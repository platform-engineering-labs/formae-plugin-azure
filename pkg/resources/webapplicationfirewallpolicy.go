// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v4"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeWAFPolicy = "AZURE::Network::ApplicationGatewayWebApplicationFirewallPolicy"

// wafPoliciesAPI is the narrow surface of the armnetwork WAF-policy client used
// here. CreateOrUpdate and Get are synchronous (they return the body directly);
// only Delete is an LRO (BeginDelete), which Delete drives to completion inline
// so the resource has no async Status handling.
type wafPoliciesAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName string, policyName string, parameters armnetwork.WebApplicationFirewallPolicy, options *armnetwork.WebApplicationFirewallPoliciesClientCreateOrUpdateOptions) (armnetwork.WebApplicationFirewallPoliciesClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName string, policyName string, options *armnetwork.WebApplicationFirewallPoliciesClientGetOptions) (armnetwork.WebApplicationFirewallPoliciesClientGetResponse, error)
	BeginDelete(ctx context.Context, resourceGroupName string, policyName string, options *armnetwork.WebApplicationFirewallPoliciesClientBeginDeleteOptions) (*runtime.Poller[armnetwork.WebApplicationFirewallPoliciesClientDeleteResponse], error)
	NewListPager(resourceGroupName string, options *armnetwork.WebApplicationFirewallPoliciesClientListOptions) *runtime.Pager[armnetwork.WebApplicationFirewallPoliciesClientListResponse]
	NewListAllPager(options *armnetwork.WebApplicationFirewallPoliciesClientListAllOptions) *runtime.Pager[armnetwork.WebApplicationFirewallPoliciesClientListAllResponse]
}

func init() {
	registry.Register(ResourceTypeWAFPolicy, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &WebApplicationFirewallPolicy{
			api:    c.WebApplicationFirewallPoliciesClient,
			config: cfg,
		}
	})
}

// WebApplicationFirewallPolicy is the provisioner for an Application Gateway WAF policy.
type WebApplicationFirewallPolicy struct {
	api    wafPoliciesAPI
	config *config.Config
}

func wafPolicyIDParts(resourceID string) (rgName, policyName string, err error) {
	rgName, names, err := armIDParts(resourceID, "applicationgatewaywebapplicationfirewallpolicies")
	if err != nil {
		return "", "", err
	}
	return rgName, names["applicationgatewaywebapplicationfirewallpolicies"], nil
}

// buildWAFPolicyParams converts the formae property map into an
// armnetwork.WebApplicationFirewallPolicy suitable for CreateOrUpdate. Shared by
// Create and Update so the body shape stays identical across operations.
func buildWAFPolicyParams(props map[string]any, location string) (armnetwork.WebApplicationFirewallPolicy, error) {
	params := armnetwork.WebApplicationFirewallPolicy{
		Location:   stringPtr(location),
		Properties: &armnetwork.WebApplicationFirewallPolicyPropertiesFormat{},
	}

	if psRaw, ok := props["policySettings"].(map[string]any); ok {
		ps := &armnetwork.PolicySettings{}
		if state, ok := psRaw["state"].(string); ok && state != "" {
			s := armnetwork.WebApplicationFirewallEnabledState(state)
			ps.State = &s
		}
		if mode, ok := psRaw["mode"].(string); ok && mode != "" {
			m := armnetwork.WebApplicationFirewallMode(mode)
			ps.Mode = &m
		}
		if rbc, ok := psRaw["requestBodyCheck"].(bool); ok {
			ps.RequestBodyCheck = &rbc
		}
		if size, ok := psRaw["maxRequestBodySizeInKb"].(float64); ok {
			ps.MaxRequestBodySizeInKb = int32Ptr(int32(size))
		}
		params.Properties.PolicySettings = ps
	}

	mrRaw, ok := props["managedRules"].(map[string]any)
	if !ok {
		return params, fmt.Errorf("managedRules is required")
	}
	setsRaw, ok := mrRaw["managedRuleSets"].([]any)
	if !ok || len(setsRaw) == 0 {
		return params, fmt.Errorf("managedRules.managedRuleSets is required")
	}
	sets := make([]*armnetwork.ManagedRuleSet, 0, len(setsRaw))
	for i, raw := range setsRaw {
		m, ok := raw.(map[string]any)
		if !ok {
			return params, fmt.Errorf("managedRuleSets[%d] must be an object", i)
		}
		ruleSetType, _ := m["ruleSetType"].(string)
		ruleSetVersion, _ := m["ruleSetVersion"].(string)
		if ruleSetType == "" || ruleSetVersion == "" {
			return params, fmt.Errorf("managedRuleSets[%d] requires ruleSetType and ruleSetVersion", i)
		}
		sets = append(sets, &armnetwork.ManagedRuleSet{
			RuleSetType:    stringPtr(ruleSetType),
			RuleSetVersion: stringPtr(ruleSetVersion),
		})
	}
	params.Properties.ManagedRules = &armnetwork.ManagedRulesDefinition{ManagedRuleSets: sets}

	if rulesRaw, ok := props["customRules"].([]any); ok && len(rulesRaw) > 0 {
		rules := make([]*armnetwork.WebApplicationFirewallCustomRule, 0, len(rulesRaw))
		for i, raw := range rulesRaw {
			m, ok := raw.(map[string]any)
			if !ok {
				return params, fmt.Errorf("customRules[%d] must be an object", i)
			}
			rule, err := buildWAFCustomRule(m, i)
			if err != nil {
				return params, err
			}
			rules = append(rules, rule)
		}
		params.Properties.CustomRules = rules
	}

	return params, nil
}

func buildWAFCustomRule(m map[string]any, idx int) (*armnetwork.WebApplicationFirewallCustomRule, error) {
	name, _ := m["name"].(string)
	ruleType, _ := m["ruleType"].(string)
	action, _ := m["action"].(string)
	priority, priorityOK := m["priority"].(float64)
	if name == "" || ruleType == "" || action == "" || !priorityOK {
		return nil, fmt.Errorf("customRules[%d] requires name, priority, ruleType, action", idx)
	}
	rt := armnetwork.WebApplicationFirewallRuleType(ruleType)
	act := armnetwork.WebApplicationFirewallAction(action)
	rule := &armnetwork.WebApplicationFirewallCustomRule{
		Name:     stringPtr(name),
		Priority: int32Ptr(int32(priority)),
		RuleType: &rt,
		Action:   &act,
	}

	conditionsRaw, ok := m["matchConditions"].([]any)
	if !ok || len(conditionsRaw) == 0 {
		return nil, fmt.Errorf("customRules[%d] requires matchConditions", idx)
	}
	conditions := make([]*armnetwork.MatchCondition, 0, len(conditionsRaw))
	for j, cRaw := range conditionsRaw {
		cm, ok := cRaw.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("customRules[%d].matchConditions[%d] must be an object", idx, j)
		}
		cond, err := buildWAFMatchCondition(cm, idx, j)
		if err != nil {
			return nil, err
		}
		conditions = append(conditions, cond)
	}
	rule.MatchConditions = conditions
	return rule, nil
}

func buildWAFMatchCondition(cm map[string]any, idx, j int) (*armnetwork.MatchCondition, error) {
	operator, _ := cm["operator"].(string)
	if operator == "" {
		return nil, fmt.Errorf("customRules[%d].matchConditions[%d] requires operator", idx, j)
	}
	op := armnetwork.WebApplicationFirewallOperator(operator)
	cond := &armnetwork.MatchCondition{Operator: &op}

	varsRaw, ok := cm["matchVariables"].([]any)
	if !ok || len(varsRaw) == 0 {
		return nil, fmt.Errorf("customRules[%d].matchConditions[%d] requires matchVariables", idx, j)
	}
	vars := make([]*armnetwork.MatchVariable, 0, len(varsRaw))
	for k, vRaw := range varsRaw {
		vm, ok := vRaw.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("customRules[%d].matchConditions[%d].matchVariables[%d] must be an object", idx, j, k)
		}
		variableName, _ := vm["variableName"].(string)
		if variableName == "" {
			return nil, fmt.Errorf("customRules[%d].matchConditions[%d].matchVariables[%d] requires variableName", idx, j, k)
		}
		mv := armnetwork.WebApplicationFirewallMatchVariable(variableName)
		matchVar := &armnetwork.MatchVariable{VariableName: &mv}
		if selector, ok := vm["selector"].(string); ok && selector != "" {
			matchVar.Selector = stringPtr(selector)
		}
		vars = append(vars, matchVar)
	}
	cond.MatchVariables = vars

	if valuesRaw, ok := cm["matchValues"].([]any); ok {
		values := make([]*string, 0, len(valuesRaw))
		for _, v := range valuesRaw {
			if s, ok := v.(string); ok {
				values = append(values, stringPtr(s))
			}
		}
		cond.MatchValues = values
	}
	if neg, ok := cm["negationConditon"].(bool); ok {
		cond.NegationConditon = &neg
	}
	return cond, nil
}

// serializeWAFPolicyProperties converts an Azure WAF policy back to Formae
// property format for round-trip-clean re-apply.
func serializeWAFPolicyProperties(result armnetwork.WebApplicationFirewallPolicy, rgName, name string) (json.RawMessage, error) {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	if result.Name != nil {
		props["name"] = *result.Name
	} else {
		props["name"] = name
	}
	if result.Location != nil {
		props["location"] = *result.Location
	}
	if result.ID != nil {
		props["id"] = *result.ID
	}

	if p := result.Properties; p != nil {
		if ps := p.PolicySettings; ps != nil {
			settings := make(map[string]any)
			if ps.State != nil {
				settings["state"] = string(*ps.State)
			}
			if ps.Mode != nil {
				settings["mode"] = string(*ps.Mode)
			}
			if ps.RequestBodyCheck != nil {
				settings["requestBodyCheck"] = *ps.RequestBodyCheck
			}
			if ps.MaxRequestBodySizeInKb != nil {
				settings["maxRequestBodySizeInKb"] = *ps.MaxRequestBodySizeInKb
			}
			if len(settings) > 0 {
				props["policySettings"] = settings
			}
		}

		if p.ManagedRules != nil && len(p.ManagedRules.ManagedRuleSets) > 0 {
			sets := make([]map[string]any, 0, len(p.ManagedRules.ManagedRuleSets))
			for _, s := range p.ManagedRules.ManagedRuleSets {
				if s == nil {
					continue
				}
				m := make(map[string]any)
				if s.RuleSetType != nil {
					m["ruleSetType"] = *s.RuleSetType
				}
				if s.RuleSetVersion != nil {
					m["ruleSetVersion"] = *s.RuleSetVersion
				}
				sets = append(sets, m)
			}
			props["managedRules"] = map[string]any{"managedRuleSets": sets}
		}

		if len(p.CustomRules) > 0 {
			rules := make([]map[string]any, 0, len(p.CustomRules))
			for _, r := range p.CustomRules {
				if r == nil {
					continue
				}
				rules = append(rules, serializeWAFCustomRule(r))
			}
			props["customRules"] = rules
		}
	}

	if tags := azureTagsToFormaeTags(result.Tags); tags != nil {
		props["Tags"] = tags
	}

	return json.Marshal(props)
}

func serializeWAFCustomRule(r *armnetwork.WebApplicationFirewallCustomRule) map[string]any {
	m := make(map[string]any)
	if r.Name != nil {
		m["name"] = *r.Name
	}
	if r.Priority != nil {
		m["priority"] = *r.Priority
	}
	if r.RuleType != nil {
		m["ruleType"] = string(*r.RuleType)
	}
	if r.Action != nil {
		m["action"] = string(*r.Action)
	}
	if len(r.MatchConditions) > 0 {
		conditions := make([]map[string]any, 0, len(r.MatchConditions))
		for _, c := range r.MatchConditions {
			if c == nil {
				continue
			}
			conditions = append(conditions, serializeWAFMatchCondition(c))
		}
		m["matchConditions"] = conditions
	}
	return m
}

func serializeWAFMatchCondition(c *armnetwork.MatchCondition) map[string]any {
	cm := make(map[string]any)
	if c.Operator != nil {
		cm["operator"] = string(*c.Operator)
	}
	if c.NegationConditon != nil {
		cm["negationConditon"] = *c.NegationConditon
	}
	if len(c.MatchVariables) > 0 {
		vars := make([]map[string]any, 0, len(c.MatchVariables))
		for _, v := range c.MatchVariables {
			if v == nil {
				continue
			}
			vm := make(map[string]any)
			if v.VariableName != nil {
				vm["variableName"] = string(*v.VariableName)
			}
			if v.Selector != nil {
				vm["selector"] = *v.Selector
			}
			vars = append(vars, vm)
		}
		cm["matchVariables"] = vars
	}
	if len(c.MatchValues) > 0 {
		values := make([]string, 0, len(c.MatchValues))
		for _, v := range c.MatchValues {
			if v != nil {
				values = append(values, *v)
			}
		}
		cm["matchValues"] = values
	}
	return cm
}

func (w *WebApplicationFirewallPolicy) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props map[string]any
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	rgName, ok := props["resourceGroupName"].(string)
	if !ok || rgName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	location, ok := props["location"].(string)
	if !ok || location == "" {
		return nil, fmt.Errorf("location is required")
	}
	name, ok := props["name"].(string)
	if !ok || name == "" {
		name = request.Label
	}

	params, err := buildWAFPolicyParams(props, location)
	if err != nil {
		return nil, err
	}
	if azureTags := formaeTagsToAzureTags(request.Properties); azureTags != nil {
		params.Tags = azureTags
	}

	result, err := w.api.CreateOrUpdate(ctx, rgName, name, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	propsJSON, err := serializeWAFPolicyProperties(result.WebApplicationFirewallPolicy, rgName, name)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize WAF policy properties: %w", err)
	}
	nativeID := ""
	if result.ID != nil {
		nativeID = *result.ID
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

func (w *WebApplicationFirewallPolicy) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, name, err := wafPolicyIDParts(request.NativeID)
	if err != nil {
		return nil, fmt.Errorf("invalid NativeID: cannot extract resourceGroup or policy name from %s: %w", request.NativeID, err)
	}

	result, err := w.api.Get(ctx, rgName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}
	propsJSON, err := serializeWAFPolicyProperties(result.WebApplicationFirewallPolicy, rgName, name)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize WAF policy properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeWAFPolicy,
		Properties:   string(propsJSON),
	}, nil
}

func (w *WebApplicationFirewallPolicy) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, name, err := wafPolicyIDParts(request.NativeID)
	if err != nil {
		return nil, fmt.Errorf("invalid NativeID: cannot extract resourceGroup or policy name from %s: %w", request.NativeID, err)
	}

	var props map[string]any
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	location, ok := props["location"].(string)
	if !ok || location == "" {
		return nil, fmt.Errorf("location is required")
	}

	params, err := buildWAFPolicyParams(props, location)
	if err != nil {
		return nil, err
	}
	if azureTags := formaeTagsToAzureTags(request.DesiredProperties); azureTags != nil {
		params.Tags = azureTags
	}

	result, err := w.api.CreateOrUpdate(ctx, rgName, name, params, nil)
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

	propsJSON, err := serializeWAFPolicyProperties(result.WebApplicationFirewallPolicy, rgName, name)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize WAF policy properties: %w", err)
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

// Delete drives the delete LRO to completion inline. WAF-policy deletes complete
// quickly, so returning a terminal Success keeps Status a no-op. A NotFound on
// the initial call means the goal is already met (idempotent delete).
func (w *WebApplicationFirewallPolicy) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, name, err := wafPolicyIDParts(request.NativeID)
	if err != nil {
		return nil, fmt.Errorf("invalid NativeID: cannot extract resourceGroup or policy name from %s: %w", request.NativeID, err)
	}

	poller, err := w.api.BeginDelete(ctx, rgName, name, nil)
	if err != nil {
		if operationErrorCode(err) == resource.OperationErrorCodeNotFound {
			return wafDeleteSuccess(request.NativeID), nil
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

	if _, err := poller.PollUntilDone(ctx, nil); err != nil {
		if operationErrorCode(err) == resource.OperationErrorCodeNotFound {
			return wafDeleteSuccess(request.NativeID), nil
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

	return wafDeleteSuccess(request.NativeID), nil
}

func wafDeleteSuccess(nativeID string) *resource.DeleteResult {
	return &resource.DeleteResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationDelete,
			OperationStatus: resource.OperationStatusSuccess,
			NativeID:        nativeID,
		},
	}
}

// WAF policy CreateOrUpdate/Get are synchronous and Delete completes inline, so
// Status is a no-op that satisfies the interface.
func (w *WebApplicationFirewallPolicy) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

func (w *WebApplicationFirewallPolicy) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	resourceGroupName := request.AdditionalProperties["resourceGroupName"]

	var nativeIDs []string
	if resourceGroupName != "" {
		pager := w.api.NewListPager(resourceGroupName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list WAF policies: %w", err)
			}
			for _, x := range page.Value {
				if x != nil && x.ID != nil {
					nativeIDs = append(nativeIDs, *x.ID)
				}
			}
		}
	} else {
		pager := w.api.NewListAllPager(nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list WAF policies: %w", err)
			}
			for _, x := range page.Value {
				if x != nil && x.ID != nil {
					nativeIDs = append(nativeIDs, *x.ID)
				}
			}
		}
	}

	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
