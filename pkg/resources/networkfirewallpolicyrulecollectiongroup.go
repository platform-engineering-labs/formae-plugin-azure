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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v4"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeNetworkFirewallPolicyRuleCollectionGroup = "AZURE::Network::FirewallPolicyRuleCollectionGroup"

// rcgOpDeleteSettle is a second delete phase, not an Azure operation type.
//
// ARM answers DELETE on a rule collection group synchronously — the poller is done
// on the first response — but it leaves the PARENT policy in Updating for another
// ~15 seconds. Reporting the group gone at that point makes the very next command in
// a teardown fail:
//
//	FirewallPolicyDeleteNotAllowedWhenUpdatingOrDeleting: Firewall Policy <name> can
//	not be deleted because it is in Updating state from previous operation ID: ...
//
// The child's delete is what put the parent in that state, so the child waits it out
// rather than making every parent-side caller retry.
const rcgOpDeleteSettle = "delete-settle"

// networkFirewallRuleCollectionGroupsAPI is the armnetwork surface used here.
// Create and delete are LROs; there is no PATCH verb at all, so an update is
// another CreateOrUpdate.
type networkFirewallRuleCollectionGroupsAPI interface {
	BeginCreateOrUpdate(ctx context.Context, resourceGroupName string, firewallPolicyName string, ruleCollectionGroupName string, parameters armnetwork.FirewallPolicyRuleCollectionGroup, options *armnetwork.FirewallPolicyRuleCollectionGroupsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.FirewallPolicyRuleCollectionGroupsClientCreateOrUpdateResponse], error)
	Get(ctx context.Context, resourceGroupName string, firewallPolicyName string, ruleCollectionGroupName string, options *armnetwork.FirewallPolicyRuleCollectionGroupsClientGetOptions) (armnetwork.FirewallPolicyRuleCollectionGroupsClientGetResponse, error)
	BeginDelete(ctx context.Context, resourceGroupName string, firewallPolicyName string, ruleCollectionGroupName string, options *armnetwork.FirewallPolicyRuleCollectionGroupsClientBeginDeleteOptions) (*runtime.Poller[armnetwork.FirewallPolicyRuleCollectionGroupsClientDeleteResponse], error)
	NewListPager(resourceGroupName string, firewallPolicyName string, options *armnetwork.FirewallPolicyRuleCollectionGroupsClientListOptions) *runtime.Pager[armnetwork.FirewallPolicyRuleCollectionGroupsClientListResponse]
}

func init() {
	registry.Register(ResourceTypeNetworkFirewallPolicyRuleCollectionGroup, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &NetworkFirewallPolicyRuleCollectionGroup{
			api:      c.FirewallPolicyRuleCollectionGroupsClient,
			policies: c.FirewallPoliciesClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// NetworkFirewallPolicyRuleCollectionGroup is the provisioner for rule collection
// groups inside an Azure Firewall policy
// (Microsoft.Network/firewallPolicies/ruleCollectionGroups).
type NetworkFirewallPolicyRuleCollectionGroup struct {
	api      networkFirewallRuleCollectionGroupsAPI
	policies networkFirewallPoliciesAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

// networkFirewallRuleCollectionGroupProps mirrors
// schema/pkl/network/firewallpolicyrulecollectiongroup.pkl.
type networkFirewallRuleCollectionGroupProps struct {
	Name               string                               `json:"name"`
	ResourceGroupName  string                               `json:"resourceGroupName"`
	FirewallPolicyName string                               `json:"firewallPolicyName"`
	Priority           *int32                               `json:"priority"`
	RuleCollections    []networkFirewallRuleCollectionProps `json:"ruleCollections"`
}

type networkFirewallRuleCollectionProps struct {
	Name         string                            `json:"name"`
	Priority     *int32                            `json:"priority"`
	Action       string                            `json:"action"`
	NetworkRules []networkFirewallNetworkRuleProps `json:"networkRules"`
}

type networkFirewallNetworkRuleProps struct {
	Name                 string   `json:"name"`
	IPProtocols          []string `json:"ipProtocols"`
	SourceAddresses      []string `json:"sourceAddresses"`
	DestinationAddresses []string `json:"destinationAddresses"`
	DestinationPorts     []string `json:"destinationPorts"`
	Description          *string  `json:"description"`
}

func networkFirewallRuleCollectionGroupIDParts(resourceID string) (rgName, policyName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "firewallpolicies", "rulecollectiongroups")
	if err != nil {
		return "", "", "", err
	}
	return rgName, names["firewallpolicies"], names["rulecollectiongroups"], nil
}

func (r *NetworkFirewallPolicyRuleCollectionGroup) buildPropertiesFromResult(group *armnetwork.FirewallPolicyRuleCollectionGroup, rgName, policyName string) map[string]any {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	props["firewallPolicyName"] = policyName

	if group.ID != nil {
		props["id"] = *group.ID
	}
	if group.Name != nil {
		props["name"] = *group.Name
	}

	if p := group.Properties; p != nil {
		if p.Priority != nil {
			props["priority"] = *p.Priority
		}
		if collections := networkFirewallRuleCollectionsFromResult(p.RuleCollections); collections != nil {
			props["ruleCollections"] = collections
		}
		// provisioningState and size are service state.
	}

	return props
}

// networkFirewallRuleCollectionsFromResult reads back only the shape this schema can
// express: filter rule collections containing network rules.
//
// ARM's rule collections are a polymorphic union, and so are the rules inside them.
// NAT collections, and application rules within a filter collection, are skipped
// rather than half-read — surfacing something the schema cannot express would show
// as drift forever.
func networkFirewallRuleCollectionsFromResult(collections []armnetwork.FirewallPolicyRuleCollectionClassification) []map[string]any {
	out := make([]map[string]any, 0, len(collections))

	for _, raw := range collections {
		filter, ok := raw.(*armnetwork.FirewallPolicyFilterRuleCollection)
		if !ok || filter == nil {
			continue
		}

		rules := make([]map[string]any, 0, len(filter.Rules))
		for _, rawRule := range filter.Rules {
			rule, ok := rawRule.(*armnetwork.Rule)
			if !ok || rule == nil {
				continue
			}
			entry := make(map[string]any)
			if rule.Name != nil {
				entry["name"] = *rule.Name
			}
			if rule.Description != nil && *rule.Description != "" {
				entry["description"] = *rule.Description
			}
			if protocols := rule.IPProtocols; len(protocols) > 0 {
				values := make([]string, 0, len(protocols))
				for _, protocol := range protocols {
					if protocol == nil {
						continue
					}
					values = append(values, canonicalizeEnum(string(*protocol), "Any", "TCP", "UDP", "ICMP"))
				}
				entry["ipProtocols"] = values
			}
			if sources := stringsFromPointers(rule.SourceAddresses); sources != nil {
				entry["sourceAddresses"] = sources
			}
			if destinations := stringsFromPointers(rule.DestinationAddresses); destinations != nil {
				entry["destinationAddresses"] = destinations
			}
			if ports := stringsFromPointers(rule.DestinationPorts); ports != nil {
				entry["destinationPorts"] = ports
			}
			// sourceIpGroups, destinationIpGroups and destinationFqdns are not
			// modelled.
			rules = append(rules, entry)
		}

		// A filter collection whose rules are all application rules has nothing this
		// schema can represent, so it is skipped entirely rather than reported empty.
		if len(rules) == 0 {
			continue
		}

		collection := map[string]any{"networkRules": rules}
		if filter.Name != nil {
			collection["name"] = *filter.Name
		}
		if filter.Priority != nil {
			collection["priority"] = *filter.Priority
		}
		if filter.Action != nil && filter.Action.Type != nil {
			collection["action"] = canonicalizeEnum(string(*filter.Action.Type), "Allow", "Deny")
		}
		out = append(out, collection)
	}

	if len(out) == 0 {
		return nil
	}
	return out
}

// networkFirewallRuleCollectionGroupParams builds the request body shared by create
// and update.
func networkFirewallRuleCollectionGroupParams(props networkFirewallRuleCollectionGroupProps) armnetwork.FirewallPolicyRuleCollectionGroup {
	collections := make([]armnetwork.FirewallPolicyRuleCollectionClassification, 0, len(props.RuleCollections))

	for _, collection := range props.RuleCollections {
		rules := make([]armnetwork.FirewallPolicyRuleClassification, 0, len(collection.NetworkRules))
		for _, rule := range collection.NetworkRules {
			protocols := make([]*armnetwork.FirewallPolicyRuleNetworkProtocol, 0, len(rule.IPProtocols))
			for _, protocol := range rule.IPProtocols {
				protocols = append(protocols, to.Ptr(armnetwork.FirewallPolicyRuleNetworkProtocol(protocol)))
			}
			rules = append(rules, &armnetwork.Rule{
				// ARM requires the discriminator on every rule.
				RuleType:             to.Ptr(armnetwork.FirewallPolicyRuleTypeNetworkRule),
				Name:                 to.Ptr(rule.Name),
				Description:          rule.Description,
				IPProtocols:          protocols,
				SourceAddresses:      stringPointers(rule.SourceAddresses),
				DestinationAddresses: stringPointers(rule.DestinationAddresses),
				DestinationPorts:     stringPointers(rule.DestinationPorts),
			})
		}

		filter := &armnetwork.FirewallPolicyFilterRuleCollection{
			// And on every collection.
			RuleCollectionType: to.Ptr(armnetwork.FirewallPolicyRuleCollectionTypeFirewallPolicyFilterRuleCollection),
			Name:               to.Ptr(collection.Name),
			Priority:           collection.Priority,
			Rules:              rules,
		}
		if collection.Action != "" {
			filter.Action = &armnetwork.FirewallPolicyFilterRuleCollectionAction{
				Type: to.Ptr(armnetwork.FirewallPolicyFilterRuleCollectionActionType(collection.Action)),
			}
		}
		collections = append(collections, filter)
	}

	return armnetwork.FirewallPolicyRuleCollectionGroup{
		Properties: &armnetwork.FirewallPolicyRuleCollectionGroupProperties{
			Priority:        props.Priority,
			RuleCollections: collections,
		},
	}
}

// upsert backs both Create and Update: this API has no PATCH verb.
func (r *NetworkFirewallPolicyRuleCollectionGroup) upsert(ctx context.Context, payload json.RawMessage, label string) (*runtime.Poller[armnetwork.FirewallPolicyRuleCollectionGroupsClientCreateOrUpdateResponse], networkFirewallRuleCollectionGroupProps, string, error) {
	var props networkFirewallRuleCollectionGroupProps
	if err := json.Unmarshal(payload, &props); err != nil {
		return nil, props, "", fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return nil, props, "", fmt.Errorf("resourceGroupName is required")
	}
	if props.FirewallPolicyName == "" {
		return nil, props, "", fmt.Errorf("firewallPolicyName is required")
	}
	if props.Priority == nil {
		return nil, props, "", fmt.Errorf("priority is required")
	}
	if len(props.RuleCollections) == 0 {
		return nil, props, "", fmt.Errorf("ruleCollections is required")
	}
	for _, collection := range props.RuleCollections {
		if collection.Priority == nil {
			return nil, props, "", fmt.Errorf("ruleCollections[].priority is required")
		}
		if len(collection.NetworkRules) == 0 {
			return nil, props, "", fmt.Errorf("ruleCollections[].networkRules is required")
		}
	}
	name := props.Name
	if name == "" {
		name = label
	}
	if name == "" {
		return nil, props, "", fmt.Errorf("name is required")
	}

	poller, err := r.api.BeginCreateOrUpdate(ctx, props.ResourceGroupName, props.FirewallPolicyName, name,
		networkFirewallRuleCollectionGroupParams(props), nil)
	return poller, props, name, err
}

func (r *NetworkFirewallPolicyRuleCollectionGroup) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	poller, props, name, err := r.upsert(ctx, request.Properties, request.Label)
	if err != nil {
		if name == "" {
			return nil, err
		}
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/firewallPolicies/%s/ruleCollectionGroups/%s",
		r.config.SubscriptionId, props.ResourceGroupName, props.FirewallPolicyName, name)

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
		nativeID, propsJSON, err := r.completeFromGroup(&result.FirewallPolicyRuleCollectionGroup)
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

func (r *NetworkFirewallPolicyRuleCollectionGroup) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, policyName, name, err := networkFirewallRuleCollectionGroupIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := r.api.Get(ctx, rgName, policyName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(r.buildPropertiesFromResult(&result.FirewallPolicyRuleCollectionGroup, rgName, policyName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeNetworkFirewallPolicyRuleCollectionGroup,
		Properties:   string(propsJSON),
	}, nil
}

// Update re-PUTs through BeginCreateOrUpdate, replacing the group's collections
// wholesale — which is what desired-state semantics want anyway.
func (r *NetworkFirewallPolicyRuleCollectionGroup) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, policyName, _, err := networkFirewallRuleCollectionGroupIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, _, name, err := r.upsert(ctx, request.DesiredProperties, "")
	if err != nil {
		if name == "" {
			return nil, err
		}
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
		propsJSON, err := json.Marshal(r.buildPropertiesFromResult(&result.FirewallPolicyRuleCollectionGroup, rgName, policyName))
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

func (r *NetworkFirewallPolicyRuleCollectionGroup) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, policyName, name, err := networkFirewallRuleCollectionGroupIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, err := r.api.BeginDelete(ctx, rgName, policyName, name, nil)
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
		// Group gone, parent still settling.
		reqIDJSON, err := encodeLROStart(rcgOpDeleteSettle, "", request.NativeID)
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

func (r *NetworkFirewallPolicyRuleCollectionGroup) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	reqID, err := decodeLROStatus(request.RequestID)
	if err != nil {
		return nil, err
	}

	switch reqID.OperationType {
	case lroOpCreate, lroOpUpdate:
		// Both resume as CreateOrUpdate responses: this API has no PATCH verb, so
		// Update issues BeginCreateOrUpdate too.
		operation := resource.OperationCreate
		if reqID.OperationType == lroOpUpdate {
			operation = resource.OperationUpdate
		}
		return statusLRO(ctx, request, &reqID, operation,
			func(token string) (*runtime.Poller[armnetwork.FirewallPolicyRuleCollectionGroupsClientCreateOrUpdateResponse], error) {
				return resumePoller[armnetwork.FirewallPolicyRuleCollectionGroupsClientCreateOrUpdateResponse](r.pipeline, token)
			},
			func(_ context.Context, result armnetwork.FirewallPolicyRuleCollectionGroupsClientCreateOrUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				return r.completeFromGroup(&result.FirewallPolicyRuleCollectionGroup)
			})
	case lroOpDelete:
		poller, err := resumePoller[armnetwork.FirewallPolicyRuleCollectionGroupsClientDeleteResponse](r.pipeline, reqID.ResumeToken)
		if err != nil {
			return nil, fmt.Errorf("failed to resume delete poller: %w", err)
		}
		if _, err := poller.Poll(ctx); err != nil && !isDeleteSuccessError(err) {
			return lroFailure(resource.OperationDelete, request.RequestID, operationErrorCode(err), err.Error()), nil
		}
		if !poller.Done() {
			return lroInProgress(resource.OperationDelete, request.RequestID, reqID.NativeID), nil
		}
		if _, err := poller.Result(ctx); err != nil && !isDeleteSuccessError(err) {
			return lroFailure(resource.OperationDelete, request.RequestID, operationErrorCode(err), err.Error()), nil
		}
		settleID, err := encodeLROStart(rcgOpDeleteSettle, "", reqID.NativeID)
		if err != nil {
			return nil, err
		}
		return lroInProgress(resource.OperationDelete, settleID, reqID.NativeID), nil
	case rcgOpDeleteSettle:
		return r.statusDeleteSettle(ctx, request, &reqID)
	default:
		return nil, fmt.Errorf("unknown operation type: %s", reqID.OperationType)
	}
}

// statusDeleteSettle reports the delete complete once the parent policy has left
// its Updating state, so a teardown that removes the policy next is not rejected.
func (r *NetworkFirewallPolicyRuleCollectionGroup) statusDeleteSettle(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	rgName, policyName, _, err := networkFirewallRuleCollectionGroupIDParts(reqID.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := r.policies.Get(ctx, rgName, policyName, nil)
	if err != nil {
		// A policy that is already gone cannot block anything.
		return lroDeleteSuccess(request.RequestID, reqID.NativeID), nil
	}

	state := ""
	if p := result.Properties; p != nil && p.ProvisioningState != nil {
		state = string(*p.ProvisioningState)
	}
	switch armnetwork.ProvisioningState(state) {
	case armnetwork.ProvisioningStateUpdating, armnetwork.ProvisioningStateDeleting:
		return lroInProgress(resource.OperationDelete, request.RequestID, reqID.NativeID), nil
	default:
		return lroDeleteSuccess(request.RequestID, reqID.NativeID), nil
	}
}

func (r *NetworkFirewallPolicyRuleCollectionGroup) completeFromGroup(group *armnetwork.FirewallPolicyRuleCollectionGroup) (string, json.RawMessage, error) {
	nativeID := ""
	rgName := ""
	policyName := ""
	if group.ID != nil {
		nativeID = *group.ID
		if rg, policy, _, err := networkFirewallRuleCollectionGroupIDParts(*group.ID); err == nil {
			rgName = rg
			policyName = policy
		}
	}
	propsJSON, err := json.Marshal(r.buildPropertiesFromResult(group, rgName, policyName))
	if err != nil {
		return "", nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return nativeID, propsJSON, nil
}

// List requires both the resource group and the policy: ARM has no
// subscription-wide listing for rule collection groups.
func (r *NetworkFirewallPolicyRuleCollectionGroup) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	policyName := request.AdditionalProperties["firewallPolicyName"]
	if rgName == "" || policyName == "" {
		return &resource.ListResult{}, nil
	}

	var nativeIDs []string
	pager := r.api.NewListPager(rgName, policyName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list firewall policy rule collection groups: %w", err)
		}
		for _, group := range page.Value {
			if group.ID != nil {
				nativeIDs = append(nativeIDs, *group.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
