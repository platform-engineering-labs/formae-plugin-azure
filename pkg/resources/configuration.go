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

func init() {
	registry.Register(ResourceTypeConfiguration, func(client *client.Client, cfg *config.Config) prov.Provisioner {
		return &Configuration{client, cfg}
	})
}

// Configuration is the provisioner for Azure Database for PostgreSQL Flexible Server Configurations.
// Configurations are server parameters (e.g. azure.extensions, shared_preload_libraries).
// They always exist on the server — Create sets a value, Delete resets to default.
type Configuration struct {
	Client *client.Client
	Config *config.Config
}

func (c *Configuration) buildPropertiesFromResult(cfg *armpostgresqlflexibleservers.Configuration, rgName, serverName string) map[string]interface{} {
	props := make(map[string]interface{})

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
	var props map[string]interface{}
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

	poller, err := c.Client.ConfigurationsClient.BeginUpdate(ctx, rgName, serverName, configName, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       mapAzureErrorToOperationErrorCode(err),
			},
		}, nil
	}

	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.DBforPostgreSQL/flexibleServers/%s/configurations/%s",
		c.Config.SubscriptionId, rgName, serverName, configName)

	if poller.Done() {
		result, err := poller.Result(ctx)
		if err != nil {
			return &resource.CreateResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationCreate,
					OperationStatus: resource.OperationStatusFailure,
					ErrorCode:       mapAzureErrorToOperationErrorCode(err),
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

	reqID := lroRequestID{
		OperationType: "create",
		ResumeToken:   resumeToken,
		NativeID:      expectedNativeID,
	}
	reqIDJSON, err := json.Marshal(reqID)
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
	parts := splitResourceID(request.NativeID)

	rgName := parts["resourcegroups"]
	serverName := parts["flexibleservers"]
	configName := parts["configurations"]

	if rgName == "" || serverName == "" || configName == "" {
		return nil, fmt.Errorf("invalid NativeID: could not extract resource group, server, or configuration name from %s", request.NativeID)
	}

	result, err := c.Client.ConfigurationsClient.Get(ctx, rgName, serverName, configName, nil)
	if err != nil {
		return &resource.ReadResult{
			ErrorCode: mapAzureErrorToOperationErrorCode(err),
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
	parts := splitResourceID(request.NativeID)

	rgName := parts["resourcegroups"]
	serverName := parts["flexibleservers"]
	configName := parts["configurations"]

	if rgName == "" || serverName == "" || configName == "" {
		return nil, fmt.Errorf("invalid NativeID: could not extract resource group, server, or configuration name from %s", request.NativeID)
	}

	var props map[string]interface{}
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

	poller, err := c.Client.ConfigurationsClient.BeginUpdate(ctx, rgName, serverName, configName, params, nil)
	if err != nil {
		return &resource.UpdateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationUpdate,
				OperationStatus: resource.OperationStatusFailure,
				NativeID:        request.NativeID,
				ErrorCode:       mapAzureErrorToOperationErrorCode(err),
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
					ErrorCode:       mapAzureErrorToOperationErrorCode(err),
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

	reqID := lroRequestID{
		OperationType: "update",
		ResumeToken:   resumeToken,
		NativeID:      request.NativeID,
	}
	reqIDJSON, err := json.Marshal(reqID)
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
	parts := splitResourceID(request.NativeID)

	rgName := parts["resourcegroups"]
	serverName := parts["flexibleservers"]
	configName := parts["configurations"]

	if rgName == "" || serverName == "" || configName == "" {
		return nil, fmt.Errorf("invalid NativeID: could not extract resource group, server, or configuration name from %s", request.NativeID)
	}

	// Read current config to get the default value
	current, err := c.Client.ConfigurationsClient.Get(ctx, rgName, serverName, configName, nil)
	if err != nil {
		if mapAzureErrorToOperationErrorCode(err) == resource.OperationErrorCodeNotFound {
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
				ErrorCode:       mapAzureErrorToOperationErrorCode(err),
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

	poller, err := c.Client.ConfigurationsClient.BeginUpdate(ctx, rgName, serverName, configName, params, nil)
	if err != nil {
		return &resource.DeleteResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationDelete,
				OperationStatus: resource.OperationStatusFailure,
				NativeID:        request.NativeID,
				ErrorCode:       mapAzureErrorToOperationErrorCode(err),
			},
		}, nil
	}

	resumeToken, err := poller.ResumeToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get resume token: %w", err)
	}

	reqID := lroRequestID{
		OperationType: "delete",
		ResumeToken:   resumeToken,
		NativeID:      request.NativeID,
	}
	reqIDJSON, err := json.Marshal(reqID)
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
	var reqID lroRequestID
	if err := json.Unmarshal([]byte(request.RequestID), &reqID); err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
			},
		}, fmt.Errorf("failed to parse request ID: %w", err)
	}

	// All operations (create, update, delete) use BeginUpdate, same poller type
	operation := resource.OperationCreate
	switch reqID.OperationType {
	case "update":
		operation = resource.OperationUpdate
	case "delete":
		operation = resource.OperationDelete
	}

	poller, err := c.Client.ResumeUpdateConfigurationPoller(reqID.ResumeToken)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       operation,
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
			},
		}, fmt.Errorf("failed to resume poller from token: %w", err)
	}

	if poller.Done() {
		return c.handleComplete(ctx, request, &reqID, poller, operation)
	}

	_, err = poller.Poll(ctx)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       operation,
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       mapAzureErrorToOperationErrorCode(err),
			},
		}, nil
	}

	if poller.Done() {
		return c.handleComplete(ctx, request, &reqID, poller, operation)
	}

	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       operation,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       request.RequestID,
			NativeID:        reqID.NativeID,
		},
	}, nil
}

func (c *Configuration) handleComplete(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID, poller *runtime.Poller[armpostgresqlflexibleservers.ConfigurationsClientUpdateResponse], operation resource.Operation) (*resource.StatusResult, error) {
	result, err := poller.Result(ctx)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       operation,
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       mapAzureErrorToOperationErrorCode(err),
			},
		}, nil
	}

	parts := splitResourceID(reqID.NativeID)
	rgName := parts["resourcegroups"]
	serverName := parts["flexibleservers"]

	responseProps := c.buildPropertiesFromResult(&result.Configuration, rgName, serverName)
	propsJSON, err := json.Marshal(responseProps)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}

	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			Operation:          operation,
			OperationStatus:    resource.OperationStatusSuccess,
			RequestID:          request.RequestID,
			NativeID:           *result.ID,
			ResourceProperties: propsJSON,
		},
	}, nil
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
		serverPager := c.Client.FlexibleServersClient.NewListPager(nil)
		for serverPager.More() {
			page, err := serverPager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list flexible servers for configuration discovery: %w", err)
			}
			for _, server := range page.Value {
				if server.ID == nil {
					continue
				}
				parts := splitResourceID(*server.ID)
				rgName := parts["resourcegroups"]
				srvName := parts["flexibleservers"]
				if rgName == "" || srvName == "" {
					continue
				}
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
	pager := c.Client.ConfigurationsClient.NewListByServerPager(resourceGroupName, serverName, nil)

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
