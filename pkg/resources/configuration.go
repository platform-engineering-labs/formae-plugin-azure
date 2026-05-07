// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/postgresql/armpostgresqlflexibleservers/v4"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeConfiguration = "Azure::DBforPostgreSQL::Configuration"

type configurationsAPI interface {
	BeginUpdate(ctx context.Context, resourceGroupName string, serverName string, configurationName string, parameters armpostgresqlflexibleservers.ConfigurationForUpdate, options *armpostgresqlflexibleservers.ConfigurationsClientBeginUpdateOptions) (*runtime.Poller[armpostgresqlflexibleservers.ConfigurationsClientUpdateResponse], error)
	Get(ctx context.Context, resourceGroupName string, serverName string, configurationName string, options *armpostgresqlflexibleservers.ConfigurationsClientGetOptions) (armpostgresqlflexibleservers.ConfigurationsClientGetResponse, error)
	NewListByServerPager(resourceGroupName string, serverName string, options *armpostgresqlflexibleservers.ConfigurationsClientListByServerOptions) *runtime.Pager[armpostgresqlflexibleservers.ConfigurationsClientListByServerResponse]
	NewListFlexibleServersPager(options *armpostgresqlflexibleservers.ServersClientListOptions) *runtime.Pager[armpostgresqlflexibleservers.ServersClientListResponse]
}

// configurationsClientWrapper composes the SDK client with FlexibleServers discovery.
type configurationsClientWrapper struct {
	*armpostgresqlflexibleservers.ConfigurationsClient
	serversClient *armpostgresqlflexibleservers.ServersClient
}

func (w *configurationsClientWrapper) NewListFlexibleServersPager(options *armpostgresqlflexibleservers.ServersClientListOptions) *runtime.Pager[armpostgresqlflexibleservers.ServersClientListResponse] {
	return w.serversClient.NewListPager(options)
}

func init() {
	registry.Register(ResourceTypeConfiguration, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &Configuration{
			api: &configurationsClientWrapper{
				ConfigurationsClient: c.ConfigurationsClient,
				serversClient:        c.FlexibleServersClient,
			},
			config:   cfg,
			pipeline: c.Pipeline(),
		}
	})
}

// Configuration is the provisioner for Azure Database for PostgreSQL Flexible Server Configurations.
// Configurations are server parameters (e.g. azure.extensions, shared_preload_libraries).
// They always exist on the server — Create sets a value, Delete resets to default.
type Configuration struct {
	api      configurationsAPI
	config   *config.Config
	pipeline runtime.Pipeline
}

func configurationIDParts(resourceID string) (rgName, parentName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "flexibleservers", "configurations")
	if err != nil {
		return "", "", "", err
	}
	return rgName, names["flexibleservers"], names["configurations"], nil
}

func (c *Configuration) buildPropertiesFromResult(cfg *armpostgresqlflexibleservers.Configuration, rgName, serverName string) map[string]any {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	props["serverName"] = serverName

	if cfg.Name != nil {
		props["name"] = *cfg.Name
	}

	if cfg.Properties != nil {
		if cfg.Properties.Value != nil {
			props["value"] = *cfg.Properties.Value
		}
		if cfg.Properties.Source != nil {
			props["source"] = *cfg.Properties.Source
		}
	}

	if cfg.ID != nil {
		props["id"] = *cfg.ID
	}

	return props
}

func (c *Configuration) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props map[string]any
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	rgName, ok := props["resourceGroupName"].(string)
	if !ok || rgName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}

	serverName, ok := props["serverName"].(string)
	if !ok || serverName == "" {
		return nil, fmt.Errorf("serverName is required")
	}

	configName, ok := props["name"].(string)
	if !ok || configName == "" {
		return nil, fmt.Errorf("name is required")
	}

	value, ok := props["value"].(string)
	if !ok || value == "" {
		return nil, fmt.Errorf("value is required")
	}

	params := armpostgresqlflexibleservers.ConfigurationForUpdate{
		Properties: &armpostgresqlflexibleservers.ConfigurationProperties{
			Value:  to.Ptr(value),
			Source: to.Ptr("user-override"),
		},
	}

	poller, err := c.api.BeginUpdate(ctx, rgName, serverName, configName, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.DBforPostgreSQL/flexibleServers/%s/configurations/%s",
		c.config.SubscriptionId, rgName, serverName, configName)

	if poller.Done() {
		result, err := poller.Result(ctx)
		if err != nil {
			return &resource.CreateResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationCreate,
					OperationStatus: resource.OperationStatusFailure,
					ErrorCode:       operationErrorCode(err),
				},
			}, nil
		}

		responseProps := c.buildPropertiesFromResult(&result.Configuration, rgName, serverName)
		propsJSON, err := json.Marshal(responseProps)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal response properties: %w", err)
		}

		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:          resource.OperationCreate,
				OperationStatus:    resource.OperationStatusSuccess,
				NativeID:           *result.ID,
				ResourceProperties: propsJSON,
			},
		}, nil
	}

	resumeToken, err := poller.ResumeToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get resume token: %w", err)
	}

	reqIDJSON, err := encodeLROStart(lroOpCreate, resumeToken, expectedNativeID)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request ID: %w", err)
	}

	return &resource.CreateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationCreate,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       string(reqIDJSON),
			NativeID:        expectedNativeID,
		},
	}, nil
}

func (c *Configuration) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, serverName, configName, err := configurationIDParts(request.NativeID)
	if err != nil {
		return nil, fmt.Errorf("invalid NativeID: could not extract resource group, server, or configuration name from %s", request.NativeID)
	}

	result, err := c.api.Get(ctx, rgName, serverName, configName, nil)
	if err != nil {
		return &resource.ReadResult{
			ErrorCode: operationErrorCode(err),
		}, nil
	}

	responseProps := c.buildPropertiesFromResult(&result.Configuration, rgName, serverName)
	propsJSON, err := json.Marshal(responseProps)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}

	return &resource.ReadResult{
		ResourceType: ResourceTypeConfiguration,
		Properties:   string(propsJSON),
	}, nil
}

func (c *Configuration) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, serverName, configName, err := configurationIDParts(request.NativeID)
	if err != nil {
		return nil, fmt.Errorf("invalid NativeID: could not extract resource group, server, or configuration name from %s", request.NativeID)
	}

	var props map[string]any
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	value, ok := props["value"].(string)
	if !ok || value == "" {
		return nil, fmt.Errorf("value is required")
	}

	params := armpostgresqlflexibleservers.ConfigurationForUpdate{
		Properties: &armpostgresqlflexibleservers.ConfigurationProperties{
			Value:  to.Ptr(value),
			Source: to.Ptr("user-override"),
		},
	}

	poller, err := c.api.BeginUpdate(ctx, rgName, serverName, configName, params, nil)
	if err != nil {
		return &resource.UpdateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationUpdate,
				OperationStatus: resource.OperationStatusFailure,
				NativeID:        request.NativeID,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	if poller.Done() {
		result, err := poller.Result(ctx)
		if err != nil {
			return &resource.UpdateResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationUpdate,
					OperationStatus: resource.OperationStatusFailure,
					NativeID:        request.NativeID,
					ErrorCode:       operationErrorCode(err),
				},
			}, nil
		}

		responseProps := c.buildPropertiesFromResult(&result.Configuration, rgName, serverName)
		propsJSON, err := json.Marshal(responseProps)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal response properties: %w", err)
		}

		return &resource.UpdateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:          resource.OperationUpdate,
				OperationStatus:    resource.OperationStatusSuccess,
				NativeID:           *result.ID,
				ResourceProperties: propsJSON,
			},
		}, nil
	}

	resumeToken, err := poller.ResumeToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get resume token: %w", err)
	}

	reqIDJSON, err := encodeLROStart(lroOpUpdate, resumeToken, request.NativeID)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request ID: %w", err)
	}

	return &resource.UpdateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationUpdate,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       string(reqIDJSON),
			NativeID:        request.NativeID,
		},
	}, nil
}

func (c *Configuration) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	// Configurations can't be deleted — reset to default by setting source to "system-default"
	rgName, serverName, configName, err := configurationIDParts(request.NativeID)
	if err != nil {
		return nil, fmt.Errorf("invalid NativeID: could not extract resource group, server, or configuration name from %s", request.NativeID)
	}

	// Read current config to get the default value
	current, err := c.api.Get(ctx, rgName, serverName, configName, nil)
	if err != nil {
		if operationErrorCode(err) == resource.OperationErrorCodeNotFound {
			return &resource.DeleteResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationDelete,
					OperationStatus: resource.OperationStatusSuccess,
					NativeID:        request.NativeID,
				},
			}, nil
		}
		return &resource.DeleteResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationDelete,
				OperationStatus: resource.OperationStatusFailure,
				NativeID:        request.NativeID,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	// Reset to default
	defaultValue := ""
	if current.Properties != nil && current.Properties.DefaultValue != nil {
		defaultValue = *current.Properties.DefaultValue
	}

	params := armpostgresqlflexibleservers.ConfigurationForUpdate{
		Properties: &armpostgresqlflexibleservers.ConfigurationProperties{
			Value:  to.Ptr(defaultValue),
			Source: to.Ptr("system-default"),
		},
	}

	poller, err := c.api.BeginUpdate(ctx, rgName, serverName, configName, params, nil)
	if err != nil {
		return &resource.DeleteResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationDelete,
				OperationStatus: resource.OperationStatusFailure,
				NativeID:        request.NativeID,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	resumeToken, err := poller.ResumeToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get resume token: %w", err)
	}

	reqIDJSON, err := encodeLROStart(lroOpDelete, resumeToken, request.NativeID)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request ID: %w", err)
	}

	return &resource.DeleteResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationDelete,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       string(reqIDJSON),
			NativeID:        request.NativeID,
		},
	}, nil
}

func (c *Configuration) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	reqID, err := decodeLROStatus(request.RequestID)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
			},
		}, err
	}

	switch reqID.OperationType {
	case lroOpCreate:
		return c.statusCreate(ctx, request, &reqID)
	case lroOpUpdate:
		return c.statusUpdate(ctx, request, &reqID)
	case lroOpDelete:
		return c.statusDelete(ctx, request, &reqID)
	default:
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
			},
		}, fmt.Errorf("unknown LRO operation type: %s", reqID.OperationType)
	}
}

func (c *Configuration) statusCreate(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	return c.statusUpdateLRO(ctx, request, reqID, resource.OperationCreate)
}

func (c *Configuration) statusUpdate(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	return c.statusUpdateLRO(ctx, request, reqID, resource.OperationUpdate)
}

func (c *Configuration) statusUpdateLRO(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID, operation resource.Operation) (*resource.StatusResult, error) {
	return statusLRO(ctx, request, reqID, operation,
		func(token string) (*runtime.Poller[armpostgresqlflexibleservers.ConfigurationsClientUpdateResponse], error) {
			return resumePoller[armpostgresqlflexibleservers.ConfigurationsClientUpdateResponse](c.pipeline, token)
		},
		func(_ context.Context, result armpostgresqlflexibleservers.ConfigurationsClientUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
			nativeID := reqID.NativeID
			if result.ID != nil {
				nativeID = *result.ID
			}
			rgName, serverName, _, err := configurationIDParts(nativeID)
			if err != nil {
				return "", nil, err
			}
			responseProps := c.buildPropertiesFromResult(&result.Configuration, rgName, serverName)
			propsJSON, err := json.Marshal(responseProps)
			if err != nil {
				return "", nil, fmt.Errorf("failed to marshal response properties: %w", err)
			}
			return nativeID, propsJSON, nil
		})
}

func (c *Configuration) statusDelete(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	return statusDeleteLRO(ctx, request, reqID,
		func(token string) (*runtime.Poller[armpostgresqlflexibleservers.ConfigurationsClientUpdateResponse], error) {
			return resumePoller[armpostgresqlflexibleservers.ConfigurationsClientUpdateResponse](c.pipeline, token)
		}, nil)
}

func (c *Configuration) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	resourceGroupName := request.AdditionalProperties["resourceGroupName"]
	serverName := request.AdditionalProperties["serverName"]

	var nativeIDs []string

	if resourceGroupName != "" && serverName != "" {
		ids, err := c.listByServer(ctx, resourceGroupName, serverName)
		if err != nil {
			return nil, err
		}
		nativeIDs = ids
	} else {
		serverPager := c.api.NewListFlexibleServersPager(nil)
		for serverPager.More() {
			page, err := serverPager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list flexible servers for configuration discovery: %w", err)
			}
			for _, server := range page.Value {
				if server.ID == nil {
					continue
				}
				rgName, names, err := armIDParts(*server.ID, "flexibleservers")
				if err != nil {
					continue
				}
				srvName := names["flexibleservers"]
				ids, err := c.listByServer(ctx, rgName, srvName)
				if err != nil {
					return nil, err
				}
				nativeIDs = append(nativeIDs, ids...)
			}
		}
	}

	return &resource.ListResult{
		NativeIDs: nativeIDs,
	}, nil
}

func (c *Configuration) listByServer(ctx context.Context, resourceGroupName, serverName string) ([]string, error) {
	pager := c.api.NewListByServerPager(resourceGroupName, serverName, nil)

	var nativeIDs []string

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list configurations for server %s: %w", serverName, err)
		}
		for _, cfg := range page.Value {
			// Only list user-overridden configurations, not all defaults
			if cfg.Properties != nil && cfg.Properties.Source != nil && *cfg.Properties.Source == "user-override" {
				if cfg.ID != nil {
					nativeIDs = append(nativeIDs, *cfg.ID)
				}
			}
		}
	}

	return nativeIDs, nil
}
