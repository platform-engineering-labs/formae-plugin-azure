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

const ResourceTypeFirewallRule = "AZURE::DBforPostgreSQL::FirewallRule"

type firewallRulesAPI interface {
	BeginCreateOrUpdate(ctx context.Context, resourceGroupName string, serverName string, firewallRuleName string, parameters armpostgresqlflexibleservers.FirewallRule, options *armpostgresqlflexibleservers.FirewallRulesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armpostgresqlflexibleservers.FirewallRulesClientCreateOrUpdateResponse], error)
	Get(ctx context.Context, resourceGroupName string, serverName string, firewallRuleName string, options *armpostgresqlflexibleservers.FirewallRulesClientGetOptions) (armpostgresqlflexibleservers.FirewallRulesClientGetResponse, error)
	BeginDelete(ctx context.Context, resourceGroupName string, serverName string, firewallRuleName string, options *armpostgresqlflexibleservers.FirewallRulesClientBeginDeleteOptions) (*runtime.Poller[armpostgresqlflexibleservers.FirewallRulesClientDeleteResponse], error)
	NewListByServerPager(resourceGroupName string, serverName string, options *armpostgresqlflexibleservers.FirewallRulesClientListByServerOptions) *runtime.Pager[armpostgresqlflexibleservers.FirewallRulesClientListByServerResponse]
	NewListFlexibleServersPager(options *armpostgresqlflexibleservers.ServersClientListOptions) *runtime.Pager[armpostgresqlflexibleservers.ServersClientListResponse]
}

// firewallRulesWrapper composes the SDK client with FlexibleServers discovery and resume-poller methods from client.Client.
type firewallRulesWrapper struct {
	*armpostgresqlflexibleservers.FirewallRulesClient
	serversClient *armpostgresqlflexibleservers.ServersClient
}

func (w *firewallRulesWrapper) NewListFlexibleServersPager(options *armpostgresqlflexibleservers.ServersClientListOptions) *runtime.Pager[armpostgresqlflexibleservers.ServersClientListResponse] {
	return w.serversClient.NewListPager(options)
}

func init() {
	registry.Register(ResourceTypeFirewallRule, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &FirewallRule{
			api: &firewallRulesWrapper{
				FirewallRulesClient: c.FirewallRulesClient,
				serversClient:       c.FlexibleServersClient,
			},
			config:   cfg,
			pipeline: c.Pipeline(),
		}
	})
}

// FirewallRule is the provisioner for Azure Database for PostgreSQL Flexible Server Firewall Rules.
type FirewallRule struct {
	api      firewallRulesAPI
	config   *config.Config
	pipeline runtime.Pipeline
}

func firewallRuleIDParts(resourceID string) (rgName, parentName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "flexibleservers", "firewallrules")
	if err != nil {
		return "", "", "", err
	}
	return rgName, names["flexibleservers"], names["firewallrules"], nil
}

// buildPropertiesFromResult extracts properties from a FirewallRule Azure response.
func (f *FirewallRule) buildPropertiesFromResult(rule *armpostgresqlflexibleservers.FirewallRule, rgName, serverName string) map[string]any {
	props := make(map[string]any)

	// createOnly properties
	props["resourceGroupName"] = rgName
	props["serverName"] = serverName

	if rule.Name != nil {
		props["name"] = *rule.Name
	}

	// Properties
	if rule.Properties != nil {
		if rule.Properties.StartIPAddress != nil {
			props["startIpAddress"] = *rule.Properties.StartIPAddress
		}
		if rule.Properties.EndIPAddress != nil {
			props["endIpAddress"] = *rule.Properties.EndIPAddress
		}
	}

	// ID
	if rule.ID != nil {
		props["id"] = *rule.ID
	}

	return props
}

func (f *FirewallRule) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	// Parse properties JSON
	var props map[string]any
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	// Extract required properties
	rgName, ok := props["resourceGroupName"].(string)
	if !ok || rgName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}

	serverName, ok := props["serverName"].(string)
	if !ok || serverName == "" {
		return nil, fmt.Errorf("serverName is required")
	}

	ruleName, ok := props["name"].(string)
	if !ok || ruleName == "" {
		ruleName = request.Label
	}

	startIP, ok := props["startIpAddress"].(string)
	if !ok || startIP == "" {
		return nil, fmt.Errorf("startIpAddress is required")
	}

	endIP, ok := props["endIpAddress"].(string)
	if !ok || endIP == "" {
		return nil, fmt.Errorf("endIpAddress is required")
	}

	// Build FirewallRule parameters
	params := armpostgresqlflexibleservers.FirewallRule{
		Properties: &armpostgresqlflexibleservers.FirewallRuleProperties{
			StartIPAddress: to.Ptr(startIP),
			EndIPAddress:   to.Ptr(endIP),
		},
	}

	// Call Azure API to create firewall rule (async/LRO operation)
	poller, err := f.api.BeginCreateOrUpdate(
		ctx,
		rgName,
		serverName,
		ruleName,
		params,
		nil,
	)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	// Build expected NativeID
	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.DBforPostgreSQL/flexibleServers/%s/firewallRules/%s",
		f.config.SubscriptionId, rgName, serverName, ruleName)

	// Check if the operation completed synchronously
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

		responseProps := f.buildPropertiesFromResult(&result.FirewallRule, rgName, serverName)
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

	// Get the ResumeToken for tracking the operation
	resumeToken, err := poller.ResumeToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get resume token: %w", err)
	}

	reqIDJSON, err := encodeLROStart(lroOpCreate, resumeToken, expectedNativeID)
	if err != nil {
		return nil, err
	}

	// Return InProgress - caller should poll Status
	return &resource.CreateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationCreate,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       string(reqIDJSON),
			NativeID:        expectedNativeID,
		},
	}, nil
}

func (f *FirewallRule) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	// Parse NativeID to extract resourceGroupName, serverName, and ruleName
	rgName, serverName, ruleName, err := firewallRuleIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	// Get firewall rule from Azure
	result, err := f.api.Get(ctx, rgName, serverName, ruleName, nil)
	if err != nil {
		return &resource.ReadResult{
			ErrorCode: operationErrorCode(err),
		}, nil
	}

	responseProps := f.buildPropertiesFromResult(&result.FirewallRule, rgName, serverName)
	propsJSON, err := json.Marshal(responseProps)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}

	return &resource.ReadResult{
		ResourceType: ResourceTypeFirewallRule,
		Properties:   string(propsJSON),
	}, nil
}

func (f *FirewallRule) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	// Parse NativeID to extract resourceGroupName, serverName, and ruleName
	rgName, serverName, ruleName, err := firewallRuleIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	// Parse properties JSON
	var props map[string]any
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	startIP, ok := props["startIpAddress"].(string)
	if !ok || startIP == "" {
		return nil, fmt.Errorf("startIpAddress is required")
	}

	endIP, ok := props["endIpAddress"].(string)
	if !ok || endIP == "" {
		return nil, fmt.Errorf("endIpAddress is required")
	}

	// Build FirewallRule parameters
	params := armpostgresqlflexibleservers.FirewallRule{
		Properties: &armpostgresqlflexibleservers.FirewallRuleProperties{
			StartIPAddress: to.Ptr(startIP),
			EndIPAddress:   to.Ptr(endIP),
		},
	}

	// Call Azure API to update firewall rule (CreateOrUpdate is idempotent)
	poller, err := f.api.BeginCreateOrUpdate(
		ctx,
		rgName,
		serverName,
		ruleName,
		params,
		nil,
	)
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

	// Check if the operation completed synchronously
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

		responseProps := f.buildPropertiesFromResult(&result.FirewallRule, rgName, serverName)
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

	// Get the ResumeToken for tracking the operation
	resumeToken, err := poller.ResumeToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get resume token: %w", err)
	}

	reqIDJSON, err := encodeLROStart(lroOpUpdate, resumeToken, request.NativeID)
	if err != nil {
		return nil, err
	}

	// Return InProgress - caller should poll Status
	return &resource.UpdateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationUpdate,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       string(reqIDJSON),
			NativeID:        request.NativeID,
		},
	}, nil
}

func (f *FirewallRule) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	// Parse NativeID to extract resourceGroupName, serverName, and ruleName
	rgName, serverName, ruleName, err := firewallRuleIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	// Start async deletion
	poller, err := f.api.BeginDelete(ctx, rgName, serverName, ruleName, nil)
	if err != nil {
		// If the resource is already gone (NotFound), treat as success
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
		}, fmt.Errorf("failed to start FirewallRule deletion: %w", err)
	}

	// Get the ResumeToken for tracking the operation
	resumeToken, err := poller.ResumeToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get resume token: %w", err)
	}

	reqIDJSON, err := encodeLROStart(lroOpDelete, resumeToken, request.NativeID)
	if err != nil {
		return nil, err
	}

	// Return InProgress - caller should poll Status
	return &resource.DeleteResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationDelete,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       string(reqIDJSON),
			NativeID:        request.NativeID,
		},
	}, nil
}

func (f *FirewallRule) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	// Parse the RequestID to determine operation type
	reqID, err := decodeLROStatus(request.RequestID)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
			},
		}, fmt.Errorf("failed to parse request ID: %w", err)
	}

	switch reqID.OperationType {
	case lroOpCreate, lroOpUpdate:
		return f.statusCreateOrUpdate(ctx, request, &reqID)
	case lroOpDelete:
		return f.statusDelete(ctx, request, &reqID)
	default:
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
			},
		}, fmt.Errorf("unknown operation type: %s", reqID.OperationType)
	}
}

func (f *FirewallRule) statusCreateOrUpdate(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	operation := resource.OperationCreate
	if reqID.OperationType == lroOpUpdate {
		operation = resource.OperationUpdate
	}

	return statusLRO(ctx, request, reqID, operation,
		func(token string) (*runtime.Poller[armpostgresqlflexibleservers.FirewallRulesClientCreateOrUpdateResponse], error) {
			return resumePoller[armpostgresqlflexibleservers.FirewallRulesClientCreateOrUpdateResponse](f.pipeline, token)
		},
		func(_ context.Context, result armpostgresqlflexibleservers.FirewallRulesClientCreateOrUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
			rgName, serverName, _, err := firewallRuleIDParts(*result.ID)
			if err != nil {
				return "", nil, err
			}
			responseProps := f.buildPropertiesFromResult(&result.FirewallRule, rgName, serverName)
			propsJSON, err := json.Marshal(responseProps)
			if err != nil {
				return "", nil, fmt.Errorf("failed to marshal response properties: %w", err)
			}
			return *result.ID, propsJSON, nil
		})
}

func (f *FirewallRule) statusDelete(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	return statusDeleteLRO(ctx, request, reqID,
		func(token string) (*runtime.Poller[armpostgresqlflexibleservers.FirewallRulesClientDeleteResponse], error) {
			return resumePoller[armpostgresqlflexibleservers.FirewallRulesClientDeleteResponse](f.pipeline, token)
		}, nil)
}

func (f *FirewallRule) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	resourceGroupName := request.AdditionalProperties["resourceGroupName"]
	serverName := request.AdditionalProperties["serverName"]

	var nativeIDs []string

	if resourceGroupName != "" && serverName != "" {
		ids, err := f.listByServer(ctx, resourceGroupName, serverName)
		if err != nil {
			return nil, err
		}
		nativeIDs = ids
	} else {
		// Discovery path: enumerate all flexible servers across the subscription
		serverPager := f.api.NewListFlexibleServersPager(nil)
		for serverPager.More() {
			page, err := serverPager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list flexible servers for firewall rule discovery: %w", err)
			}
			for _, server := range page.Value {
				if server.ID == nil {
					continue
				}
				rgName, srvName, err := flexibleServerIDParts(*server.ID)
				if err != nil {
					continue
				}
				ids, err := f.listByServer(ctx, rgName, srvName)
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

func (f *FirewallRule) listByServer(ctx context.Context, resourceGroupName, serverName string) ([]string, error) {
	pager := f.api.NewListByServerPager(resourceGroupName, serverName, nil)

	var nativeIDs []string

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list firewall rules for server %s: %w", serverName, err)
		}
		for _, rule := range page.Value {
			if rule.ID != nil {
				nativeIDs = append(nativeIDs, *rule.ID)
			}
		}
	}

	return nativeIDs, nil
}
