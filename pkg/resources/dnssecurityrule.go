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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/dnsresolver/armdnsresolver"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeDNSSecurityRule = "AZURE::Network::DnsSecurityRule"

// dnsSecurityRulesAPI is the armdnsresolver surface used here. All three mutating
// calls are LROs, and DNSSecurityRulePatch nests its properties correctly (unlike
// DNSForwardingRulesetPatch), so the action, domain lists, priority and state are
// all genuinely updatable.
type dnsSecurityRulesAPI interface {
	BeginCreateOrUpdate(ctx context.Context, resourceGroupName string, dnsResolverPolicyName string, dnsSecurityRuleName string, parameters armdnsresolver.DNSSecurityRule, options *armdnsresolver.DNSSecurityRulesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armdnsresolver.DNSSecurityRulesClientCreateOrUpdateResponse], error)
	Get(ctx context.Context, resourceGroupName string, dnsResolverPolicyName string, dnsSecurityRuleName string, options *armdnsresolver.DNSSecurityRulesClientGetOptions) (armdnsresolver.DNSSecurityRulesClientGetResponse, error)
	BeginUpdate(ctx context.Context, resourceGroupName string, dnsResolverPolicyName string, dnsSecurityRuleName string, parameters armdnsresolver.DNSSecurityRulePatch, options *armdnsresolver.DNSSecurityRulesClientBeginUpdateOptions) (*runtime.Poller[armdnsresolver.DNSSecurityRulesClientUpdateResponse], error)
	BeginDelete(ctx context.Context, resourceGroupName string, dnsResolverPolicyName string, dnsSecurityRuleName string, options *armdnsresolver.DNSSecurityRulesClientBeginDeleteOptions) (*runtime.Poller[armdnsresolver.DNSSecurityRulesClientDeleteResponse], error)
	NewListPager(resourceGroupName string, dnsResolverPolicyName string, options *armdnsresolver.DNSSecurityRulesClientListOptions) *runtime.Pager[armdnsresolver.DNSSecurityRulesClientListResponse]
}

func init() {
	registry.Register(ResourceTypeDNSSecurityRule, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &DNSSecurityRule{
			api:      c.DNSSecurityRulesClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// DNSSecurityRule is the provisioner for rules in a DNS resolver policy
// (Microsoft.Network/dnsResolverPolicies/dnsSecurityRules).
type DNSSecurityRule struct {
	api      dnsSecurityRulesAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

// dnsSecurityRuleProps mirrors
// schema/pkl/network/dnssecurityrule.pkl.
type dnsSecurityRuleProps struct {
	Name                  string                      `json:"name"`
	Location              string                      `json:"location"`
	ResourceGroupName     string                      `json:"resourceGroupName"`
	DNSResolverPolicyName string                      `json:"dnsResolverPolicyName"`
	Action                *dnsSecurityRuleActionProps `json:"action"`
	DomainListIDs         []string                    `json:"dnsResolverDomainListIds"`
	Priority              *int32                      `json:"priority"`
	DNSSecurityRuleState  string                      `json:"dnsSecurityRuleState"`
}

type dnsSecurityRuleActionProps struct {
	ActionType string `json:"actionType"`
}

// domainListSubResources wraps domain-list ARM IDs in the SubResource shape both
// the create body and the patch body expect.
func domainListSubResources(ids []string) []*armdnsresolver.SubResource {
	if len(ids) == 0 {
		return nil
	}
	out := make([]*armdnsresolver.SubResource, 0, len(ids))
	for _, id := range ids {
		if id == "" {
			continue
		}
		out = append(out, &armdnsresolver.SubResource{ID: to.Ptr(id)})
	}
	return out
}

// dnsSecurityRuleState returns nil for an unset state so ARM applies its own
// default rather than receiving an empty string.
func dnsSecurityRuleState(state string) *armdnsresolver.DNSSecurityRuleState {
	if state == "" {
		return nil
	}
	return to.Ptr(armdnsresolver.DNSSecurityRuleState(state))
}

func dnsSecurityRuleIDParts(resourceID string) (rgName, policyName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "dnsresolverpolicies", "dnssecurityrules")
	if err != nil {
		return "", "", "", err
	}
	return rgName, names["dnsresolverpolicies"], names["dnssecurityrules"], nil
}

func (d *DNSSecurityRule) buildPropertiesFromResult(rule *armdnsresolver.DNSSecurityRule, rgName, policyName string) map[string]any {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	props["dnsResolverPolicyName"] = policyName

	if rule.ID != nil {
		props["id"] = *rule.ID
	}
	if rule.Name != nil {
		props["name"] = *rule.Name
	}
	if rule.Location != nil {
		props["location"] = normalizeAzureLocation(*rule.Location)
	}

	if p := rule.Properties; p != nil {
		if p.Action != nil && p.Action.ActionType != nil {
			props["action"] = map[string]any{
				"actionType": canonicalizeEnum(string(*p.Action.ActionType), "Alert", "Allow", "Block"),
			}
		}
		if len(p.DNSResolverDomainLists) > 0 {
			// Order is echoed as sent; ARM treats the lists as a set, so there is
			// nothing meaningful to canonicalise.
			ids := make([]string, 0, len(p.DNSResolverDomainLists))
			for _, domainList := range p.DNSResolverDomainLists {
				if domainList == nil || domainList.ID == nil {
					continue
				}
				ids = append(ids, *domainList.ID)
			}
			props["dnsResolverDomainListIds"] = ids
		}
		if p.Priority != nil {
			props["priority"] = *p.Priority
		}
		if p.DNSSecurityRuleState != nil {
			props["dnsSecurityRuleState"] = canonicalizeEnum(string(*p.DNSSecurityRuleState), "Enabled", "Disabled")
		}
	}

	if tags := azureTagsToFormaeTags(rule.Tags); tags != nil {
		props["Tags"] = tags
	}

	return props
}

func (d *DNSSecurityRule) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props dnsSecurityRuleProps
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	if props.DNSResolverPolicyName == "" {
		return nil, fmt.Errorf("dnsResolverPolicyName is required")
	}
	if props.Location == "" {
		return nil, fmt.Errorf("location is required")
	}
	if props.Action == nil || props.Action.ActionType == "" {
		return nil, fmt.Errorf("action.actionType is required")
	}
	if len(props.DomainListIDs) == 0 {
		return nil, fmt.Errorf("dnsResolverDomainListIds is required")
	}
	if props.Priority == nil {
		return nil, fmt.Errorf("priority is required")
	}
	name := props.Name
	if name == "" {
		name = request.Label
	}
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}

	params := armdnsresolver.DNSSecurityRule{
		Location: to.Ptr(props.Location),
		Properties: &armdnsresolver.DNSSecurityRuleProperties{
			Action:                 &armdnsresolver.DNSSecurityRuleAction{ActionType: to.Ptr(armdnsresolver.ActionType(props.Action.ActionType))},
			DNSResolverDomainLists: domainListSubResources(props.DomainListIDs),
			Priority:               props.Priority,
			DNSSecurityRuleState:   dnsSecurityRuleState(props.DNSSecurityRuleState),
		},
	}
	if azureTags := formaeTagsToAzureTags(request.Properties); azureTags != nil {
		params.Tags = azureTags
	}

	poller, err := d.api.BeginCreateOrUpdate(ctx, props.ResourceGroupName, props.DNSResolverPolicyName, name, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/dnsResolvers/%s/dnsSecurityRules/%s",
		d.config.SubscriptionId, props.ResourceGroupName, props.DNSResolverPolicyName, name)

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
		nativeID, propsJSON, err := d.completeFromRule(&result.DNSSecurityRule)
		if err != nil {
			return nil, err
		}
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:          resource.OperationCreate,
				OperationStatus:    resource.OperationStatusSuccess,
				NativeID:           nativeID,
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
		return nil, err
	}

	return &resource.CreateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationCreate,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       reqIDJSON,
			NativeID:        expectedNativeID,
		},
	}, nil
}

func (d *DNSSecurityRule) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, policyName, name, err := dnsSecurityRuleIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := d.api.Get(ctx, rgName, policyName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(d.buildPropertiesFromResult(&result.DNSSecurityRule, rgName, policyName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeDNSSecurityRule,
		Properties:   string(propsJSON),
	}, nil
}

// Update carries everything but the parents: DNSSecurityRulePatchProperties has
// fields for the action, the domain lists, the priority and the rule state, and it
// nests them under "properties" the way ARM expects.
func (d *DNSSecurityRule) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, policyName, name, err := dnsSecurityRuleIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props dnsSecurityRuleProps
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	patchProps := &armdnsresolver.DNSSecurityRulePatchProperties{
		DNSResolverDomainLists: domainListSubResources(props.DomainListIDs),
		Priority:               props.Priority,
		DNSSecurityRuleState:   dnsSecurityRuleState(props.DNSSecurityRuleState),
	}
	if props.Action != nil && props.Action.ActionType != "" {
		patchProps.Action = &armdnsresolver.DNSSecurityRuleAction{
			ActionType: to.Ptr(armdnsresolver.ActionType(props.Action.ActionType)),
		}
	}

	params := armdnsresolver.DNSSecurityRulePatch{
		Tags:       formaeTagsToAzureTags(request.DesiredProperties),
		Properties: patchProps,
	}

	poller, err := d.api.BeginUpdate(ctx, rgName, policyName, name, params, nil)
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
		propsJSON, err := json.Marshal(d.buildPropertiesFromResult(&result.DNSSecurityRule, rgName, policyName))
		if err != nil {
			return nil, fmt.Errorf("failed to marshal response properties: %w", err)
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

	resumeToken, err := poller.ResumeToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get resume token: %w", err)
	}
	reqIDJSON, err := encodeLROStart(lroOpUpdate, resumeToken, request.NativeID)
	if err != nil {
		return nil, err
	}

	return &resource.UpdateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationUpdate,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       reqIDJSON,
			NativeID:        request.NativeID,
		},
	}, nil
}

func (d *DNSSecurityRule) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, policyName, name, err := dnsSecurityRuleIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, err := d.api.BeginDelete(ctx, rgName, policyName, name, nil)
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
		}, nil
	}

	if poller.Done() {
		if _, err := poller.Result(ctx); err != nil && !isDeleteSuccessError(err) {
			return &resource.DeleteResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationDelete,
					OperationStatus: resource.OperationStatusFailure,
					NativeID:        request.NativeID,
					ErrorCode:       operationErrorCode(err),
				},
			}, nil
		}
		return &resource.DeleteResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationDelete,
				OperationStatus: resource.OperationStatusSuccess,
				NativeID:        request.NativeID,
			},
		}, nil
	}

	resumeToken, err := poller.ResumeToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get resume token: %w", err)
	}
	reqIDJSON, err := encodeLROStart(lroOpDelete, resumeToken, request.NativeID)
	if err != nil {
		return nil, err
	}

	return &resource.DeleteResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationDelete,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       reqIDJSON,
			NativeID:        request.NativeID,
		},
	}, nil
}

func (d *DNSSecurityRule) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	reqID, err := decodeLROStatus(request.RequestID)
	if err != nil {
		return nil, err
	}

	switch reqID.OperationType {
	case lroOpCreate:
		return statusLRO(ctx, request, &reqID, resource.OperationCreate,
			func(token string) (*runtime.Poller[armdnsresolver.DNSSecurityRulesClientCreateOrUpdateResponse], error) {
				return resumePoller[armdnsresolver.DNSSecurityRulesClientCreateOrUpdateResponse](d.pipeline, token)
			},
			func(_ context.Context, result armdnsresolver.DNSSecurityRulesClientCreateOrUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				return d.completeFromRule(&result.DNSSecurityRule)
			})
	case lroOpUpdate:
		return statusLRO(ctx, request, &reqID, resource.OperationUpdate,
			func(token string) (*runtime.Poller[armdnsresolver.DNSSecurityRulesClientUpdateResponse], error) {
				return resumePoller[armdnsresolver.DNSSecurityRulesClientUpdateResponse](d.pipeline, token)
			},
			func(_ context.Context, result armdnsresolver.DNSSecurityRulesClientUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				return d.completeFromRule(&result.DNSSecurityRule)
			})
	case lroOpDelete:
		return statusDeleteLRO(ctx, request, &reqID,
			func(token string) (*runtime.Poller[armdnsresolver.DNSSecurityRulesClientDeleteResponse], error) {
				return resumePoller[armdnsresolver.DNSSecurityRulesClientDeleteResponse](d.pipeline, token)
			}, nil)
	default:
		return nil, fmt.Errorf("unknown operation type: %s", reqID.OperationType)
	}
}

func (d *DNSSecurityRule) completeFromRule(rule *armdnsresolver.DNSSecurityRule) (string, json.RawMessage, error) {
	nativeID := ""
	rgName := ""
	policyName := ""
	if rule.ID != nil {
		nativeID = *rule.ID
		if rg, resolver, _, err := dnsSecurityRuleIDParts(*rule.ID); err == nil {
			rgName = rg
			policyName = resolver
		}
	}
	propsJSON, err := json.Marshal(d.buildPropertiesFromResult(rule, rgName, policyName))
	if err != nil {
		return "", nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return nativeID, propsJSON, nil
}

// List requires both the resource group and the resolver name: ARM has no
// subscription-wide listing for inbound endpoints.
func (d *DNSSecurityRule) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	policyName := request.AdditionalProperties["dnsResolverPolicyName"]
	if rgName == "" || policyName == "" {
		return &resource.ListResult{}, nil
	}

	var nativeIDs []string
	pager := d.api.NewListPager(rgName, policyName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list dns resolver inbound endpoints: %w", err)
		}
		for _, rule := range page.Value {
			if rule.ID != nil {
				nativeIDs = append(nativeIDs, *rule.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
