// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/sql/armsql"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeSQLVirtualNetworkRule = "AZURE::Sql::VirtualNetworkRule"

// sqlVirtualNetworkRulesAPI is the subset of *armsql.VirtualNetworkRulesClient used
// here. Create/delete are LROs.
type sqlVirtualNetworkRulesAPI interface {
	BeginCreateOrUpdate(ctx context.Context, resourceGroupName, serverName, virtualNetworkRuleName string, parameters armsql.VirtualNetworkRule, options *armsql.VirtualNetworkRulesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armsql.VirtualNetworkRulesClientCreateOrUpdateResponse], error)
	Get(ctx context.Context, resourceGroupName, serverName, virtualNetworkRuleName string, options *armsql.VirtualNetworkRulesClientGetOptions) (armsql.VirtualNetworkRulesClientGetResponse, error)
	BeginDelete(ctx context.Context, resourceGroupName, serverName, virtualNetworkRuleName string, options *armsql.VirtualNetworkRulesClientBeginDeleteOptions) (*runtime.Poller[armsql.VirtualNetworkRulesClientDeleteResponse], error)
	NewListByServerPager(resourceGroupName, serverName string, options *armsql.VirtualNetworkRulesClientListByServerOptions) *runtime.Pager[armsql.VirtualNetworkRulesClientListByServerResponse]
}

func init() {
	registry.Register(ResourceTypeSQLVirtualNetworkRule, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &SqlVirtualNetworkRule{
			api:      c.SQLVirtualNetworkRulesClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// SqlVirtualNetworkRule is the provisioner for Azure SQL virtual network rules
// (`Microsoft.Sql/servers/<server>/virtualNetworkRules/<name>`) — a VNet subnet
// allowed to reach the server, as an alternative to IP-range firewall rules.
//
// Normally the subnet must carry the `Microsoft.Sql` service endpoint. This plugin's
// AZURE::Network::Subnet does not model serviceEndpoints yet, so set
// `ignoreMissingVnetServiceEndpoint = true` to create the rule against a plain
// subnet; ARM accepts it and the rule activates once the endpoint exists.
type SqlVirtualNetworkRule struct {
	api      sqlVirtualNetworkRulesAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

func sqlVirtualNetworkRuleIDParts(resourceID string) (rgName, serverName, ruleName string, err error) {
	rgName, names, err := armIDParts(resourceID, "servers", "virtualnetworkrules")
	if err != nil {
		return "", "", "", err
	}
	return rgName, names["servers"], names["virtualnetworkrules"], nil
}

func sqlVirtualNetworkRuleParamsFromProperties(props map[string]any) (armsql.VirtualNetworkRule, error) {
	subnetID, _ := props["virtualNetworkSubnetId"].(string)
	if subnetID == "" {
		return armsql.VirtualNetworkRule{}, fmt.Errorf("virtualNetworkSubnetId is required")
	}
	p := &armsql.VirtualNetworkRuleProperties{VirtualNetworkSubnetID: stringPtr(subnetID)}
	if v, ok := props["ignoreMissingVnetServiceEndpoint"].(bool); ok {
		p.IgnoreMissingVnetServiceEndpoint = &v
	}
	return armsql.VirtualNetworkRule{Properties: p}, nil
}

func serializeSQLVirtualNetworkRuleProperties(result armsql.VirtualNetworkRule, rgName, serverName, ruleName string) (json.RawMessage, error) {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	props["serverName"] = serverName
	if result.Name != nil {
		props["name"] = *result.Name
	} else {
		props["name"] = ruleName
	}
	if result.ID != nil {
		props["id"] = *result.ID
	}
	if p := result.Properties; p != nil {
		if p.VirtualNetworkSubnetID != nil {
			props["virtualNetworkSubnetId"] = *p.VirtualNetworkSubnetID
		}
		if p.IgnoreMissingVnetServiceEndpoint != nil {
			props["ignoreMissingVnetServiceEndpoint"] = *p.IgnoreMissingVnetServiceEndpoint
		}
		if p.State != nil {
			props["state"] = string(*p.State)
		}
	}

	return json.Marshal(props)
}

func (a *SqlVirtualNetworkRule) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props map[string]any
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	rgName, _ := props["resourceGroupName"].(string)
	if rgName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	serverName, _ := props["serverName"].(string)
	if serverName == "" {
		return nil, fmt.Errorf("serverName is required")
	}
	ruleName, _ := props["name"].(string)
	if ruleName == "" {
		ruleName = request.Label
	}
	if ruleName == "" {
		return nil, fmt.Errorf("name is required")
	}

	params, err := sqlVirtualNetworkRuleParamsFromProperties(props)
	if err != nil {
		return nil, err
	}

	poller, err := a.api.BeginCreateOrUpdate(ctx, rgName, serverName, ruleName, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	expectedID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Sql/servers/%s/virtualNetworkRules/%s",
		a.config.SubscriptionId, rgName, serverName, ruleName)

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
		propsJSON, err := serializeSQLVirtualNetworkRuleProperties(result.VirtualNetworkRule, rgName, serverName, ruleName)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize VirtualNetworkRule properties: %w", err)
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

	token, err := poller.ResumeToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get resume token: %w", err)
	}
	reqID, err := encodeLROStart(lroOpCreate, token, expectedID)
	if err != nil {
		return nil, err
	}

	return &resource.CreateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationCreate,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       reqID,
			NativeID:        expectedID,
		},
	}, nil
}

func (a *SqlVirtualNetworkRule) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, serverName, ruleName, err := sqlVirtualNetworkRuleIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := a.api.Get(ctx, rgName, serverName, ruleName, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := serializeSQLVirtualNetworkRuleProperties(result.VirtualNetworkRule, rgName, serverName, ruleName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize VirtualNetworkRule properties: %w", err)
	}

	return &resource.ReadResult{
		ResourceType: ResourceTypeSQLVirtualNetworkRule,
		Properties:   string(propsJSON),
	}, nil
}

// Update sends a full-body PUT: virtualNetworkSubnetId and
// ignoreMissingVnetServiceEndpoint are both writable, and CreateOrUpdate is an
// idempotent upsert.
func (a *SqlVirtualNetworkRule) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, serverName, ruleName, err := sqlVirtualNetworkRuleIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props map[string]any
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse desired properties: %w", err)
	}

	params, err := sqlVirtualNetworkRuleParamsFromProperties(props)
	if err != nil {
		return nil, err
	}

	poller, err := a.api.BeginCreateOrUpdate(ctx, rgName, serverName, ruleName, params, nil)
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
		propsJSON, err := serializeSQLVirtualNetworkRuleProperties(result.VirtualNetworkRule, rgName, serverName, ruleName)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize VirtualNetworkRule properties: %w", err)
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

	token, err := poller.ResumeToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get resume token: %w", err)
	}
	reqID, err := encodeLROStart(lroOpUpdate, token, request.NativeID)
	if err != nil {
		return nil, err
	}

	return &resource.UpdateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationUpdate,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       reqID,
			NativeID:        request.NativeID,
		},
	}, nil
}

func (a *SqlVirtualNetworkRule) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, serverName, ruleName, err := sqlVirtualNetworkRuleIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, err := a.api.BeginDelete(ctx, rgName, serverName, ruleName, nil)
	if err != nil {
		if isDeleteSuccessError(err) {
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
		}, fmt.Errorf("failed to delete VirtualNetworkRule: %w", err)
	}

	if poller.Done() {
		return &resource.DeleteResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationDelete,
				OperationStatus: resource.OperationStatusSuccess,
				NativeID:        request.NativeID,
			},
		}, nil
	}

	token, err := poller.ResumeToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get resume token: %w", err)
	}
	reqID, err := encodeLROStart(lroOpDelete, token, request.NativeID)
	if err != nil {
		return nil, err
	}

	return &resource.DeleteResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationDelete,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       reqID,
			NativeID:        request.NativeID,
		},
	}, nil
}

func (a *SqlVirtualNetworkRule) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
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
	case lroOpCreate, lroOpUpdate:
		return statusLRO(ctx, request, &reqID, resource.OperationCreate,
			func(token string) (*runtime.Poller[armsql.VirtualNetworkRulesClientCreateOrUpdateResponse], error) {
				return resumePoller[armsql.VirtualNetworkRulesClientCreateOrUpdateResponse](a.pipeline, token)
			},
			func(_ context.Context, result armsql.VirtualNetworkRulesClientCreateOrUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				rgName, serverName, ruleName, err := sqlVirtualNetworkRuleIDParts(*result.ID)
				if err != nil {
					return "", nil, err
				}
				propsJSON, err := serializeSQLVirtualNetworkRuleProperties(result.VirtualNetworkRule, rgName, serverName, ruleName)
				if err != nil {
					return "", nil, fmt.Errorf("failed to serialize VirtualNetworkRule properties: %w", err)
				}
				return *result.ID, propsJSON, nil
			})
	case lroOpDelete:
		return statusDeleteLRO(ctx, request, &reqID,
			func(token string) (*runtime.Poller[armsql.VirtualNetworkRulesClientDeleteResponse], error) {
				return resumePoller[armsql.VirtualNetworkRulesClientDeleteResponse](a.pipeline, token)
			}, nil)
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

func (a *SqlVirtualNetworkRule) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	serverName := request.AdditionalProperties["serverName"]

	var nativeIDs []string
	pager := a.api.NewListByServerPager(rgName, serverName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list SQL virtual network rules for server %s: %w", serverName, err)
		}
		for _, rule := range page.Value {
			if rule.ID != nil {
				nativeIDs = append(nativeIDs, *rule.ID)
			}
		}
	}

	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
