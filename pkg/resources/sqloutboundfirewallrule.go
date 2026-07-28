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

const ResourceTypeSQLOutboundFirewallRule = "AZURE::Sql::OutboundFirewallRule"

// sqlOutboundFirewallRulesAPI is the subset of *armsql.OutboundFirewallRulesClient
// used here. Create/delete are LROs. The request body carries only a read-only
// provisioningState, so the allowed destination is conveyed entirely by the resource
// name (an FQDN).
type sqlOutboundFirewallRulesAPI interface {
	BeginCreateOrUpdate(ctx context.Context, resourceGroupName, serverName, outboundRuleFqdn string, parameters armsql.OutboundFirewallRule, options *armsql.OutboundFirewallRulesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armsql.OutboundFirewallRulesClientCreateOrUpdateResponse], error)
	Get(ctx context.Context, resourceGroupName, serverName, outboundRuleFqdn string, options *armsql.OutboundFirewallRulesClientGetOptions) (armsql.OutboundFirewallRulesClientGetResponse, error)
	BeginDelete(ctx context.Context, resourceGroupName, serverName, outboundRuleFqdn string, options *armsql.OutboundFirewallRulesClientBeginDeleteOptions) (*runtime.Poller[armsql.OutboundFirewallRulesClientDeleteResponse], error)
	NewListByServerPager(resourceGroupName, serverName string, options *armsql.OutboundFirewallRulesClientListByServerOptions) *runtime.Pager[armsql.OutboundFirewallRulesClientListByServerResponse]
}

func init() {
	registry.Register(ResourceTypeSQLOutboundFirewallRule, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &SqlOutboundFirewallRule{
			api:      c.SQLOutboundFirewallRulesClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// SqlOutboundFirewallRule is the provisioner for Azure SQL outbound firewall rules
// (`Microsoft.Sql/servers/<server>/outboundFirewallRules/<fqdn>`) — the allow-list of
// destinations a server may reach when outbound network restriction is enabled.
//
// The rule *is* its name: the resource name is the permitted FQDN and the body
// carries only a read-only provisioningState, so nothing is writable and Update is a
// re-read.
type SqlOutboundFirewallRule struct {
	api      sqlOutboundFirewallRulesAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

func sqlOutboundFirewallRuleIDParts(resourceID string) (rgName, serverName, ruleFqdn string, err error) {
	rgName, names, err := armIDParts(resourceID, "servers", "outboundfirewallrules")
	if err != nil {
		return "", "", "", err
	}
	return rgName, names["servers"], names["outboundfirewallrules"], nil
}

func serializeSQLOutboundFirewallRuleProperties(result armsql.OutboundFirewallRule, rgName, serverName, ruleFqdn string) (json.RawMessage, error) {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	props["serverName"] = serverName
	if result.Name != nil {
		props["name"] = *result.Name
	} else {
		props["name"] = ruleFqdn
	}
	if result.ID != nil {
		props["id"] = *result.ID
	}
	return json.Marshal(props)
}

func (a *SqlOutboundFirewallRule) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
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
	ruleFqdn, _ := props["name"].(string)
	if ruleFqdn == "" {
		ruleFqdn = request.Label
	}
	if ruleFqdn == "" {
		return nil, fmt.Errorf("name is required")
	}

	poller, err := a.api.BeginCreateOrUpdate(ctx, rgName, serverName, ruleFqdn, armsql.OutboundFirewallRule{}, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	expectedID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Sql/servers/%s/outboundFirewallRules/%s",
		a.config.SubscriptionId, rgName, serverName, ruleFqdn)

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
		propsJSON, err := serializeSQLOutboundFirewallRuleProperties(result.OutboundFirewallRule, rgName, serverName, ruleFqdn)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize OutboundFirewallRule properties: %w", err)
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

func (a *SqlOutboundFirewallRule) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, serverName, ruleFqdn, err := sqlOutboundFirewallRuleIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := a.api.Get(ctx, rgName, serverName, ruleFqdn, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := serializeSQLOutboundFirewallRuleProperties(result.OutboundFirewallRule, rgName, serverName, ruleFqdn)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize OutboundFirewallRule properties: %w", err)
	}

	return &resource.ReadResult{
		ResourceType: ResourceTypeSQLOutboundFirewallRule,
		Properties:   string(propsJSON),
	}, nil
}

// Update re-reads current state without writing. The rule's only field is a
// read-only provisioningState and its identity is its name, so a change of allowed
// FQDN is a replace, not an update.
func (a *SqlOutboundFirewallRule) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, serverName, ruleFqdn, err := sqlOutboundFirewallRuleIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := a.api.Get(ctx, rgName, serverName, ruleFqdn, nil)
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

	propsJSON, err := serializeSQLOutboundFirewallRuleProperties(result.OutboundFirewallRule, rgName, serverName, ruleFqdn)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize OutboundFirewallRule properties: %w", err)
	}

	return &resource.UpdateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:          resource.OperationUpdate,
			OperationStatus:    resource.OperationStatusSuccess,
			NativeID:           request.NativeID,
			ResourceProperties: propsJSON,
		},
	}, nil
}

func (a *SqlOutboundFirewallRule) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, serverName, ruleFqdn, err := sqlOutboundFirewallRuleIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, err := a.api.BeginDelete(ctx, rgName, serverName, ruleFqdn, nil)
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
		}, fmt.Errorf("failed to delete OutboundFirewallRule: %w", err)
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

func (a *SqlOutboundFirewallRule) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
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
			func(token string) (*runtime.Poller[armsql.OutboundFirewallRulesClientCreateOrUpdateResponse], error) {
				return resumePoller[armsql.OutboundFirewallRulesClientCreateOrUpdateResponse](a.pipeline, token)
			},
			func(_ context.Context, result armsql.OutboundFirewallRulesClientCreateOrUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				rgName, serverName, ruleFqdn, err := sqlOutboundFirewallRuleIDParts(*result.ID)
				if err != nil {
					return "", nil, err
				}
				propsJSON, err := serializeSQLOutboundFirewallRuleProperties(result.OutboundFirewallRule, rgName, serverName, ruleFqdn)
				if err != nil {
					return "", nil, fmt.Errorf("failed to serialize OutboundFirewallRule properties: %w", err)
				}
				return *result.ID, propsJSON, nil
			})
	case lroOpDelete:
		return statusDeleteLRO(ctx, request, &reqID,
			func(token string) (*runtime.Poller[armsql.OutboundFirewallRulesClientDeleteResponse], error) {
				return resumePoller[armsql.OutboundFirewallRulesClientDeleteResponse](a.pipeline, token)
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

func (a *SqlOutboundFirewallRule) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	serverName := request.AdditionalProperties["serverName"]

	var nativeIDs []string
	pager := a.api.NewListByServerPager(rgName, serverName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list SQL outbound firewall rules for server %s: %w", serverName, err)
		}
		for _, rule := range page.Value {
			if rule.ID != nil {
				nativeIDs = append(nativeIDs, *rule.ID)
			}
		}
	}

	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
