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

const ResourceTypeFirewallPolicyRuleCollectionGroup = "AZURE::Network::FirewallPolicyRuleCollectionGroup"

// lroOpDeleteSettleParent marks a delete whose ARM operation has already finished
// but whose parent firewall policy has not left `Updating` yet. It carries no
// resume token — Status polls the parent policy instead of a poller.
const lroOpDeleteSettleParent = "delete-settle-parent"

// firewallPolicyRuleCollectionGroupsAPI is the subset of
// *armnetwork.FirewallPolicyRuleCollectionGroupsClient used here. There is no
// PATCH verb at all — every change is a full-body PUT.
type firewallPolicyRuleCollectionGroupsAPI interface {
	BeginCreateOrUpdate(ctx context.Context, resourceGroupName, firewallPolicyName, ruleCollectionGroupName string, parameters armnetwork.FirewallPolicyRuleCollectionGroup, options *armnetwork.FirewallPolicyRuleCollectionGroupsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.FirewallPolicyRuleCollectionGroupsClientCreateOrUpdateResponse], error)
	Get(ctx context.Context, resourceGroupName, firewallPolicyName, ruleCollectionGroupName string, options *armnetwork.FirewallPolicyRuleCollectionGroupsClientGetOptions) (armnetwork.FirewallPolicyRuleCollectionGroupsClientGetResponse, error)
	BeginDelete(ctx context.Context, resourceGroupName, firewallPolicyName, ruleCollectionGroupName string, options *armnetwork.FirewallPolicyRuleCollectionGroupsClientBeginDeleteOptions) (*runtime.Poller[armnetwork.FirewallPolicyRuleCollectionGroupsClientDeleteResponse], error)
	NewListPager(resourceGroupName, firewallPolicyName string, options *armnetwork.FirewallPolicyRuleCollectionGroupsClientListOptions) *runtime.Pager[armnetwork.FirewallPolicyRuleCollectionGroupsClientListResponse]
	NewListAllPoliciesPager(options *armnetwork.FirewallPoliciesClientListAllOptions) *runtime.Pager[armnetwork.FirewallPoliciesClientListAllResponse]
	GetPolicy(ctx context.Context, resourceGroupName, firewallPolicyName string, options *armnetwork.FirewallPoliciesClientGetOptions) (armnetwork.FirewallPoliciesClientGetResponse, error)
}

// firewallPolicyRuleCollectionGroupsWrapper composes the rule-collection-group
// client with subscription-wide policy discovery.
type firewallPolicyRuleCollectionGroupsWrapper struct {
	*armnetwork.FirewallPolicyRuleCollectionGroupsClient
	policiesClient *armnetwork.FirewallPoliciesClient
}

func (w *firewallPolicyRuleCollectionGroupsWrapper) NewListAllPoliciesPager(options *armnetwork.FirewallPoliciesClientListAllOptions) *runtime.Pager[armnetwork.FirewallPoliciesClientListAllResponse] {
	return w.policiesClient.NewListAllPager(options)
}

func (w *firewallPolicyRuleCollectionGroupsWrapper) GetPolicy(ctx context.Context, resourceGroupName, firewallPolicyName string, options *armnetwork.FirewallPoliciesClientGetOptions) (armnetwork.FirewallPoliciesClientGetResponse, error) {
	return w.policiesClient.Get(ctx, resourceGroupName, firewallPolicyName, options)
}

func init() {
	registry.Register(ResourceTypeFirewallPolicyRuleCollectionGroup, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &FirewallPolicyRuleCollectionGroup{
			api: &firewallPolicyRuleCollectionGroupsWrapper{
				FirewallPolicyRuleCollectionGroupsClient: c.FirewallPolicyRuleCollectionGroupsClient,
				policiesClient:                           c.FirewallPoliciesClient,
			},
			config:   cfg,
			pipeline: c.Pipeline(),
		}
	})
}

// FirewallPolicyRuleCollectionGroup is the provisioner for the rule groups inside
// a firewall policy
// (`Microsoft.Network/firewallPolicies/<policy>/ruleCollectionGroups/<name>`).
//
// ARM models `ruleCollections` as a discriminated union on `ruleCollectionType`,
// whose rules are themselves a union on `ruleType`. The SDK exposes both as Go
// interfaces (`FirewallPolicyRuleCollectionClassification` /
// `FirewallPolicyRuleClassification`) and keeps its unmarshallers unexported, so
// this file does the discrimination explicitly in both directions.
//
// Supported today: `FirewallPolicyFilterRuleCollection` holding `NetworkRule` and
// `ApplicationRule` rules.
//
// ponytail: `FirewallPolicyNatRuleCollection` (DNAT) is not supported. It needs a
// firewall with a public IP to be meaningful, so it cannot be exercised without
// the AzureFirewall handler and its hourly cost — deliberately left until that
// lands rather than shipped unverified. An unsupported collection type in the
// desired state is rejected loudly rather than silently dropped.
type FirewallPolicyRuleCollectionGroup struct {
	api      firewallPolicyRuleCollectionGroupsAPI
	config   *config.Config
	pipeline runtime.Pipeline
}

func firewallPolicyRuleCollectionGroupIDParts(resourceID string) (rgName, policyName, name string, err error) {
	rgName, names, err := armExactIDParts(resourceID, "firewallpolicies", "rulecollectiongroups")
	if err != nil {
		return "", "", "", err
	}
	return rgName, names[0], names[1], nil
}

// --- serialize (ARM -> formae) -------------------------------------------------

func serializeFirewallRuleCollections(collections []armnetwork.FirewallPolicyRuleCollectionClassification) []any {
	if len(collections) == 0 {
		return nil
	}
	out := make([]any, 0, len(collections))
	for _, raw := range collections {
		filter, ok := raw.(*armnetwork.FirewallPolicyFilterRuleCollection)
		if !ok {
			// A NAT collection (or a type added by a newer API version) round-trips
			// as nothing rather than as a wrong shape; Read then reports drift,
			// which is the honest outcome for a collection this handler cannot own.
			continue
		}
		collection := map[string]any{"ruleCollectionType": "FirewallPolicyFilterRuleCollection"}
		if filter.Name != nil {
			collection["name"] = *filter.Name
		}
		if filter.Priority != nil {
			collection["priority"] = int(*filter.Priority)
		}
		if filter.Action != nil && filter.Action.Type != nil {
			collection["action"] = map[string]any{"type": string(*filter.Action.Type)}
		}
		if rules := serializeFirewallRules(filter.Rules); rules != nil {
			collection["rules"] = rules
		}
		out = append(out, collection)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func serializeFirewallRules(rules []armnetwork.FirewallPolicyRuleClassification) []any {
	if len(rules) == 0 {
		return nil
	}
	out := make([]any, 0, len(rules))
	for _, raw := range rules {
		switch rule := raw.(type) {
		case *armnetwork.Rule:
			entry := map[string]any{"ruleType": "NetworkRule"}
			if rule.Name != nil {
				entry["name"] = *rule.Name
			}
			if rule.Description != nil {
				entry["description"] = *rule.Description
			}
			if v := networkProtocolStrings(rule.IPProtocols); v != nil {
				entry["ipProtocols"] = v
			}
			if v := stringSliceFromPtrs(rule.SourceAddresses); v != nil {
				entry["sourceAddresses"] = v
			}
			if v := stringSliceFromPtrs(rule.DestinationAddresses); v != nil {
				entry["destinationAddresses"] = v
			}
			if v := stringSliceFromPtrs(rule.DestinationPorts); v != nil {
				entry["destinationPorts"] = v
			}
			if v := stringSliceFromPtrs(rule.DestinationFqdns); v != nil {
				entry["destinationFqdns"] = v
			}
			if v := stringSliceFromPtrs(rule.SourceIPGroups); v != nil {
				entry["sourceIpGroups"] = v
			}
			if v := stringSliceFromPtrs(rule.DestinationIPGroups); v != nil {
				entry["destinationIpGroups"] = v
			}
			out = append(out, entry)
		case *armnetwork.ApplicationRule:
			entry := map[string]any{"ruleType": "ApplicationRule"}
			if rule.Name != nil {
				entry["name"] = *rule.Name
			}
			if rule.Description != nil {
				entry["description"] = *rule.Description
			}
			if v := applicationProtocols(rule.Protocols); v != nil {
				entry["protocols"] = v
			}
			if v := stringSliceFromPtrs(rule.SourceAddresses); v != nil {
				entry["sourceAddresses"] = v
			}
			if v := stringSliceFromPtrs(rule.SourceIPGroups); v != nil {
				entry["sourceIpGroups"] = v
			}
			if v := stringSliceFromPtrs(rule.TargetFqdns); v != nil {
				entry["targetFqdns"] = v
			}
			if v := stringSliceFromPtrs(rule.FqdnTags); v != nil {
				entry["fqdnTags"] = v
			}
			if v := stringSliceFromPtrs(rule.WebCategories); v != nil {
				entry["webCategories"] = v
			}
			out = append(out, entry)
		default:
			continue
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func networkProtocolStrings(in []*armnetwork.FirewallPolicyRuleNetworkProtocol) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for _, p := range in {
		if p != nil {
			out = append(out, string(*p))
		}
	}
	return out
}

func applicationProtocols(in []*armnetwork.FirewallPolicyRuleApplicationProtocol) []any {
	if len(in) == 0 {
		return nil
	}
	out := make([]any, 0, len(in))
	for _, p := range in {
		if p == nil {
			continue
		}
		entry := map[string]any{}
		if p.ProtocolType != nil {
			entry["protocolType"] = string(*p.ProtocolType)
		}
		if p.Port != nil {
			entry["port"] = int(*p.Port)
		}
		out = append(out, entry)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func serializeFirewallPolicyRuleCollectionGroupProperties(result armnetwork.FirewallPolicyRuleCollectionGroup, rgName, policyName, name string) (json.RawMessage, error) {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	props["firewallPolicyName"] = policyName
	if result.Name != nil {
		props["name"] = *result.Name
	} else {
		props["name"] = name
	}
	if result.ID != nil {
		props["id"] = *result.ID
	}

	if result.Properties != nil {
		if result.Properties.Priority != nil {
			props["priority"] = int(*result.Properties.Priority)
		}
		if collections := serializeFirewallRuleCollections(result.Properties.RuleCollections); collections != nil {
			props["ruleCollections"] = collections
		}
		// provisioningState and size are read-only with no schema field.
	}

	return json.Marshal(props)
}

// --- params (formae -> ARM) ----------------------------------------------------

func firewallRuleCollectionsFromProperties(raw []any) ([]armnetwork.FirewallPolicyRuleCollectionClassification, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	out := make([]armnetwork.FirewallPolicyRuleCollectionClassification, 0, len(raw))
	for i, item := range raw {
		collectionMap, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("ruleCollections[%d] is not an object", i)
		}
		collectionType, _ := collectionMap["ruleCollectionType"].(string)
		if collectionType != string(armnetwork.FirewallPolicyRuleCollectionTypeFirewallPolicyFilterRuleCollection) {
			return nil, fmt.Errorf("ruleCollections[%d]: unsupported ruleCollectionType %q, only FirewallPolicyFilterRuleCollection is implemented", i, collectionType)
		}

		filter := &armnetwork.FirewallPolicyFilterRuleCollection{
			RuleCollectionType: to.Ptr(armnetwork.FirewallPolicyRuleCollectionTypeFirewallPolicyFilterRuleCollection),
		}
		if v, ok := collectionMap["name"].(string); ok && v != "" {
			filter.Name = to.Ptr(v)
		}
		if v, ok := collectionMap["priority"].(float64); ok {
			filter.Priority = to.Ptr(int32(v))
		}
		if actionMap, ok := collectionMap["action"].(map[string]any); ok {
			if v, ok := actionMap["type"].(string); ok && v != "" {
				filter.Action = &armnetwork.FirewallPolicyFilterRuleCollectionAction{
					Type: to.Ptr(armnetwork.FirewallPolicyFilterRuleCollectionActionType(v)),
				}
			}
		}
		if rulesRaw, ok := collectionMap["rules"].([]any); ok {
			rules, err := firewallRulesFromProperties(i, rulesRaw)
			if err != nil {
				return nil, err
			}
			filter.Rules = rules
		}
		out = append(out, filter)
	}
	return out, nil
}

func firewallRulesFromProperties(collectionIndex int, raw []any) ([]armnetwork.FirewallPolicyRuleClassification, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	out := make([]armnetwork.FirewallPolicyRuleClassification, 0, len(raw))
	for i, item := range raw {
		ruleMap, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("ruleCollections[%d].rules[%d] is not an object", collectionIndex, i)
		}
		ruleType, _ := ruleMap["ruleType"].(string)
		switch ruleType {
		case string(armnetwork.FirewallPolicyRuleTypeNetworkRule):
			rule := &armnetwork.Rule{RuleType: to.Ptr(armnetwork.FirewallPolicyRuleTypeNetworkRule)}
			if v, ok := ruleMap["name"].(string); ok && v != "" {
				rule.Name = to.Ptr(v)
			}
			if v, ok := ruleMap["description"].(string); ok && v != "" {
				rule.Description = to.Ptr(v)
			}
			if v, ok := ruleMap["ipProtocols"].([]any); ok {
				protocols := make([]*armnetwork.FirewallPolicyRuleNetworkProtocol, 0, len(v))
				for _, p := range v {
					if s, ok := p.(string); ok && s != "" {
						protocols = append(protocols, to.Ptr(armnetwork.FirewallPolicyRuleNetworkProtocol(s)))
					}
				}
				rule.IPProtocols = protocols
			}
			if v, ok := ruleMap["sourceAddresses"].([]any); ok {
				rule.SourceAddresses = stringPtrsFromAny(v)
			}
			if v, ok := ruleMap["destinationAddresses"].([]any); ok {
				rule.DestinationAddresses = stringPtrsFromAny(v)
			}
			if v, ok := ruleMap["destinationPorts"].([]any); ok {
				rule.DestinationPorts = stringPtrsFromAny(v)
			}
			if v, ok := ruleMap["destinationFqdns"].([]any); ok {
				rule.DestinationFqdns = stringPtrsFromAny(v)
			}
			if v, ok := ruleMap["sourceIpGroups"].([]any); ok {
				rule.SourceIPGroups = stringPtrsFromAny(v)
			}
			if v, ok := ruleMap["destinationIpGroups"].([]any); ok {
				rule.DestinationIPGroups = stringPtrsFromAny(v)
			}
			out = append(out, rule)
		case string(armnetwork.FirewallPolicyRuleTypeApplicationRule):
			rule := &armnetwork.ApplicationRule{RuleType: to.Ptr(armnetwork.FirewallPolicyRuleTypeApplicationRule)}
			if v, ok := ruleMap["name"].(string); ok && v != "" {
				rule.Name = to.Ptr(v)
			}
			if v, ok := ruleMap["description"].(string); ok && v != "" {
				rule.Description = to.Ptr(v)
			}
			if v, ok := ruleMap["protocols"].([]any); ok {
				protocols := make([]*armnetwork.FirewallPolicyRuleApplicationProtocol, 0, len(v))
				for _, p := range v {
					protocolMap, ok := p.(map[string]any)
					if !ok {
						continue
					}
					protocol := &armnetwork.FirewallPolicyRuleApplicationProtocol{}
					if s, ok := protocolMap["protocolType"].(string); ok && s != "" {
						protocol.ProtocolType = to.Ptr(armnetwork.FirewallPolicyRuleApplicationProtocolType(s))
					}
					if n, ok := protocolMap["port"].(float64); ok {
						protocol.Port = to.Ptr(int32(n))
					}
					protocols = append(protocols, protocol)
				}
				rule.Protocols = protocols
			}
			if v, ok := ruleMap["sourceAddresses"].([]any); ok {
				rule.SourceAddresses = stringPtrsFromAny(v)
			}
			if v, ok := ruleMap["sourceIpGroups"].([]any); ok {
				rule.SourceIPGroups = stringPtrsFromAny(v)
			}
			if v, ok := ruleMap["targetFqdns"].([]any); ok {
				rule.TargetFqdns = stringPtrsFromAny(v)
			}
			if v, ok := ruleMap["fqdnTags"].([]any); ok {
				rule.FqdnTags = stringPtrsFromAny(v)
			}
			if v, ok := ruleMap["webCategories"].([]any); ok {
				rule.WebCategories = stringPtrsFromAny(v)
			}
			out = append(out, rule)
		default:
			return nil, fmt.Errorf("ruleCollections[%d].rules[%d]: unsupported ruleType %q, only NetworkRule and ApplicationRule are implemented", collectionIndex, i, ruleType)
		}
	}
	return out, nil
}

func firewallPolicyRuleCollectionGroupParamsFromProperties(props map[string]any) (armnetwork.FirewallPolicyRuleCollectionGroup, error) {
	priority, ok := props["priority"].(float64)
	if !ok {
		return armnetwork.FirewallPolicyRuleCollectionGroup{}, fmt.Errorf("priority is required")
	}

	group := armnetwork.FirewallPolicyRuleCollectionGroup{
		Properties: &armnetwork.FirewallPolicyRuleCollectionGroupProperties{
			Priority: to.Ptr(int32(priority)),
		},
	}

	if raw, ok := props["ruleCollections"].([]any); ok {
		collections, err := firewallRuleCollectionsFromProperties(raw)
		if err != nil {
			return armnetwork.FirewallPolicyRuleCollectionGroup{}, err
		}
		group.Properties.RuleCollections = collections
	}

	return group, nil
}

// --- CRUD ---------------------------------------------------------------------

func (g *FirewallPolicyRuleCollectionGroup) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props map[string]any
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	rgName, _ := props["resourceGroupName"].(string)
	if rgName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	policyName, _ := props["firewallPolicyName"].(string)
	if policyName == "" {
		return nil, fmt.Errorf("firewallPolicyName is required")
	}
	name, _ := props["name"].(string)
	if name == "" {
		name = request.Label
	}
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}

	params, err := firewallPolicyRuleCollectionGroupParamsFromProperties(props)
	if err != nil {
		return nil, err
	}

	poller, err := g.api.BeginCreateOrUpdate(ctx, rgName, policyName, name, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	expectedID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/firewallPolicies/%s/ruleCollectionGroups/%s",
		g.config.SubscriptionId, rgName, policyName, name)

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
		propsJSON, err := serializeFirewallPolicyRuleCollectionGroupProperties(result.FirewallPolicyRuleCollectionGroup, rgName, policyName, name)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize FirewallPolicyRuleCollectionGroup properties: %w", err)
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

func (g *FirewallPolicyRuleCollectionGroup) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, policyName, name, err := firewallPolicyRuleCollectionGroupIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := g.api.Get(ctx, rgName, policyName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := serializeFirewallPolicyRuleCollectionGroupProperties(result.FirewallPolicyRuleCollectionGroup, rgName, policyName, name)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize FirewallPolicyRuleCollectionGroup properties: %w", err)
	}

	return &resource.ReadResult{
		ResourceType: ResourceTypeFirewallPolicyRuleCollectionGroup,
		Properties:   string(propsJSON),
	}, nil
}

func (g *FirewallPolicyRuleCollectionGroup) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, policyName, name, err := firewallPolicyRuleCollectionGroupIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props map[string]any
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse desired properties: %w", err)
	}

	// No PATCH verb exists; the whole rule set is replaced by the PUT.
	params, err := firewallPolicyRuleCollectionGroupParamsFromProperties(props)
	if err != nil {
		return nil, err
	}

	poller, err := g.api.BeginCreateOrUpdate(ctx, rgName, policyName, name, params, nil)
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
		propsJSON, err := serializeFirewallPolicyRuleCollectionGroupProperties(result.FirewallPolicyRuleCollectionGroup, rgName, policyName, name)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize FirewallPolicyRuleCollectionGroup properties: %w", err)
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

func (g *FirewallPolicyRuleCollectionGroup) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, policyName, name, err := firewallPolicyRuleCollectionGroupIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, err := g.api.BeginDelete(ctx, rgName, policyName, name, nil)
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
		}, fmt.Errorf("failed to delete FirewallPolicyRuleCollectionGroup: %w", err)
	}

	// A synchronous completion still has to wait for the parent policy to settle, but
	// a terminal poller cannot produce a resume token — so hand back a tokenless
	// request ID and let Status poll the parent directly.
	if poller.Done() {
		reqID, err := encodeLROStart(lroOpDeleteSettleParent, "", request.NativeID)
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

func (g *FirewallPolicyRuleCollectionGroup) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
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
		return g.statusCreateOrUpdate(ctx, request, &reqID)
	case lroOpDelete:
		return statusDeleteLRO(ctx, request, &reqID,
			func(token string) (*runtime.Poller[armnetwork.FirewallPolicyRuleCollectionGroupsClientDeleteResponse], error) {
				return resumePoller[armnetwork.FirewallPolicyRuleCollectionGroupsClientDeleteResponse](g.pipeline, token)
			}, g.verifyParentPolicySettled)
	case lroOpDeleteSettleParent:
		return g.verifyParentPolicySettled(ctx, request, &reqID), nil
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

// verifyParentPolicySettled runs once the group's own delete LRO reports done.
//
// Deleting a rule collection group drives its *parent* firewall policy into
// `Updating`, and the policy stays there for a few seconds after the child's own
// operation has completed. A policy in that state cannot be deleted: ARM answers
// `FirewallPolicyDeleteNotAllowedWhenUpdatingOrDeleting` ("can not be deleted
// because it is in Updating state from previous operation ID …"). Since formae
// starts the parent's delete as soon as the child reports success, reporting
// success early makes tearing a policy and its groups down in one apply fail.
//
// Staying InProgress until the parent is out of `Updating` keeps that teardown
// ordering correct. A policy that has already vanished, or that cannot be read,
// counts as settled — the child really is gone either way.
func (g *FirewallPolicyRuleCollectionGroup) verifyParentPolicySettled(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) *resource.StatusResult {
	rgName, policyName, _, err := firewallPolicyRuleCollectionGroupIDParts(reqID.NativeID)
	if err != nil {
		return lroDeleteSuccess(request.RequestID, reqID.NativeID)
	}

	policy, err := g.api.GetPolicy(ctx, rgName, policyName, nil)
	if err != nil {
		return lroDeleteSuccess(request.RequestID, reqID.NativeID)
	}
	if policy.Properties != nil && policy.Properties.ProvisioningState != nil &&
		*policy.Properties.ProvisioningState == armnetwork.ProvisioningStateUpdating {
		return lroInProgress(resource.OperationDelete, request.RequestID, reqID.NativeID)
	}

	return lroDeleteSuccess(request.RequestID, reqID.NativeID)
}

func (g *FirewallPolicyRuleCollectionGroup) statusCreateOrUpdate(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	operation := resource.OperationCreate
	if reqID.OperationType == lroOpUpdate {
		operation = resource.OperationUpdate
	}

	return statusLRO(ctx, request, reqID, operation,
		func(token string) (*runtime.Poller[armnetwork.FirewallPolicyRuleCollectionGroupsClientCreateOrUpdateResponse], error) {
			return resumePoller[armnetwork.FirewallPolicyRuleCollectionGroupsClientCreateOrUpdateResponse](g.pipeline, token)
		},
		func(_ context.Context, result armnetwork.FirewallPolicyRuleCollectionGroupsClientCreateOrUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
			rgName, policyName, name, err := firewallPolicyRuleCollectionGroupIDParts(*result.ID)
			if err != nil {
				return "", nil, err
			}
			propsJSON, err := serializeFirewallPolicyRuleCollectionGroupProperties(result.FirewallPolicyRuleCollectionGroup, rgName, policyName, name)
			if err != nil {
				return "", nil, fmt.Errorf("failed to serialize FirewallPolicyRuleCollectionGroup properties: %w", err)
			}
			return *result.ID, propsJSON, nil
		})
}

func (g *FirewallPolicyRuleCollectionGroup) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	policyName := request.AdditionalProperties["firewallPolicyName"]

	if rgName != "" && policyName != "" {
		ids, err := g.listByPolicy(ctx, rgName, policyName)
		if err != nil {
			return nil, err
		}
		return &resource.ListResult{NativeIDs: ids}, nil
	}

	// Discovery path: rule collection groups can only be listed per-policy.
	var nativeIDs []string
	pager := g.api.NewListAllPoliciesPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list firewall policies for rule collection group discovery: %w", err)
		}
		for _, policy := range page.Value {
			if policy.ID == nil {
				continue
			}
			policyRG, name, err := firewallPolicyIDParts(*policy.ID)
			if err != nil {
				continue
			}
			ids, err := g.listByPolicy(ctx, policyRG, name)
			if err != nil {
				return nil, err
			}
			nativeIDs = append(nativeIDs, ids...)
		}
	}

	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}

func (g *FirewallPolicyRuleCollectionGroup) listByPolicy(ctx context.Context, rgName, policyName string) ([]string, error) {
	pager := g.api.NewListPager(rgName, policyName, nil)

	var nativeIDs []string
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list rule collection groups in policy %s/%s: %w", rgName, policyName, err)
		}
		for _, group := range page.Value {
			if group.ID != nil {
				nativeIDs = append(nativeIDs, *group.ID)
			}
		}
	}

	return nativeIDs, nil
}
