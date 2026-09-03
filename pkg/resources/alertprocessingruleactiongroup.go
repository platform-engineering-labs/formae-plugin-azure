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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/alertsmanagement/armalertsmanagement"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeAlertProcessingRuleActionGroup = "AZURE::AlertsManagement::AlertProcessingRuleActionGroup"

// alertProcessingRulesAPI is the armalertsmanagement surface shared by the two
// alert-processing-rule resource types. Every call is synchronous.
//
// Note the ARM type is Microsoft.AlertsManagement/actionRules — "alert processing
// rule" is the product name the API kept the old path for.
type alertProcessingRulesAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName, alertProcessingRuleName string, alertProcessingRule armalertsmanagement.AlertProcessingRule, options *armalertsmanagement.AlertProcessingRulesClientCreateOrUpdateOptions) (armalertsmanagement.AlertProcessingRulesClientCreateOrUpdateResponse, error)
	GetByName(ctx context.Context, resourceGroupName, alertProcessingRuleName string, options *armalertsmanagement.AlertProcessingRulesClientGetByNameOptions) (armalertsmanagement.AlertProcessingRulesClientGetByNameResponse, error)
	Delete(ctx context.Context, resourceGroupName, alertProcessingRuleName string, options *armalertsmanagement.AlertProcessingRulesClientDeleteOptions) (armalertsmanagement.AlertProcessingRulesClientDeleteResponse, error)
	NewListByResourceGroupPager(resourceGroupName string, options *armalertsmanagement.AlertProcessingRulesClientListByResourceGroupOptions) *runtime.Pager[armalertsmanagement.AlertProcessingRulesClientListByResourceGroupResponse]
	NewListBySubscriptionPager(options *armalertsmanagement.AlertProcessingRulesClientListBySubscriptionOptions) *runtime.Pager[armalertsmanagement.AlertProcessingRulesClientListBySubscriptionResponse]
}

func init() {
	registry.Register(ResourceTypeAlertProcessingRuleActionGroup, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &AlertProcessingRuleActionGroup{api: c.AlertProcessingRulesClient, config: cfg}
	})
}

// AlertProcessingRuleActionGroup is the provisioner for the AddActionGroups flavour
// of Microsoft.AlertsManagement/actionRules: it attaches action groups to every
// alert that matches its scopes and conditions.
type AlertProcessingRuleActionGroup struct {
	api    alertProcessingRulesAPI
	config *config.Config
}

// alertProcessingRuleProps is the union of the fields the two alert-processing-rule
// schemas declare. ActionGroupIds is only read by the AddActionGroups flavour and
// Schedule only by the suppression flavour; each provisioner ignores the other's.
type alertProcessingRuleProps struct {
	Name              string                         `json:"name"`
	ResourceGroupName string                         `json:"resourceGroupName"`
	Location          string                         `json:"location"`
	Scopes            []string                       `json:"scopes"`
	Conditions        []alertProcessingRuleCondition `json:"conditions"`
	Description       *string                        `json:"description"`
	Enabled           *bool                          `json:"enabled"`
	ActionGroupIds    []string                       `json:"actionGroupIds"`
	Schedule          *alertProcessingRuleSchedule   `json:"schedule"`
}

type alertProcessingRuleCondition struct {
	Field    string   `json:"field"`
	Operator string   `json:"operator"`
	Values   []string `json:"values"`
}

type alertProcessingRuleSchedule struct {
	EffectiveFrom  string `json:"effectiveFrom"`
	EffectiveUntil string `json:"effectiveUntil"`
	TimeZone       string `json:"timeZone"`
}

func alertProcessingRuleIDParts(resourceID string) (rgName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "actionrules")
	if err != nil {
		return "", "", err
	}
	return rgName, names["actionrules"], nil
}

// alertProcessingRuleCommonProperties reads back everything the two flavours share.
// The action list is flavour-specific and is added by the caller.
func alertProcessingRuleCommonProperties(rule *armalertsmanagement.AlertProcessingRule, rgName string) map[string]any {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName

	if rule.ID != nil {
		props["id"] = *rule.ID
	}
	if rule.Name != nil {
		props["name"] = *rule.Name
	}
	if rule.Location != nil {
		// Alert processing rules are global: the value is the literal "Global", not a
		// region, so it is passed through rather than normalised.
		props["location"] = *rule.Location
	}
	if tags := azureTagsToFormaeTags(rule.Tags); len(tags) > 0 {
		props["Tags"] = tags
	}

	p := rule.Properties
	if p == nil {
		return props
	}

	if scopes := stringsFromPointers(p.Scopes); len(scopes) > 0 {
		props["scopes"] = scopes
	}
	if p.Description != nil && *p.Description != "" {
		props["description"] = *p.Description
	}
	if p.Enabled != nil {
		props["enabled"] = *p.Enabled
	}

	conditions := make([]map[string]any, 0, len(p.Conditions))
	for _, condition := range p.Conditions {
		if condition == nil {
			continue
		}
		entry := map[string]any{}
		if condition.Field != nil {
			entry["field"] = string(*condition.Field)
		}
		if condition.Operator != nil {
			entry["operator"] = string(*condition.Operator)
		}
		if values := stringsFromPointers(condition.Values); len(values) > 0 {
			entry["values"] = values
		}
		conditions = append(conditions, entry)
	}
	if len(conditions) > 0 {
		props["conditions"] = conditions
	}

	return props
}

// alertProcessingRuleBaseProperties builds the request body members the two flavours
// share. The Actions list is flavour-specific and is set by the caller.
func alertProcessingRuleBaseProperties(props alertProcessingRuleProps) *armalertsmanagement.AlertProcessingRuleProperties {
	properties := &armalertsmanagement.AlertProcessingRuleProperties{
		Scopes: stringPointers(props.Scopes),
	}
	if props.Description != nil {
		properties.Description = props.Description
	}
	if props.Enabled != nil {
		properties.Enabled = props.Enabled
	}
	for _, condition := range props.Conditions {
		entry := &armalertsmanagement.Condition{
			Values: stringPointers(condition.Values),
		}
		if condition.Field != "" {
			entry.Field = to.Ptr(armalertsmanagement.Field(condition.Field))
		}
		if condition.Operator != "" {
			entry.Operator = to.Ptr(armalertsmanagement.Operator(condition.Operator))
		}
		properties.Conditions = append(properties.Conditions, entry)
	}
	return properties
}

// parseAlertProcessingRuleProps validates the members both flavours require.
func parseAlertProcessingRuleProps(payload json.RawMessage, label string) (alertProcessingRuleProps, string, error) {
	var props alertProcessingRuleProps
	if err := json.Unmarshal(payload, &props); err != nil {
		return props, "", fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return props, "", fmt.Errorf("resourceGroupName is required")
	}
	if props.Location == "" {
		return props, "", fmt.Errorf("location is required")
	}
	if len(props.Scopes) == 0 {
		return props, "", fmt.Errorf("at least one scope is required")
	}
	name := props.Name
	if name == "" {
		name = label
	}
	if name == "" {
		return props, "", fmt.Errorf("name is required")
	}
	return props, name, nil
}

// alertProcessingRuleHasActionType reports whether a rule carries an action of the
// given type. Both resource types live under the same ARM type, so List has to sort
// the two apart or discovery of one would hand back the other's ids.
func alertProcessingRuleHasActionType(rule *armalertsmanagement.AlertProcessingRule, want armalertsmanagement.ActionType) bool {
	if rule == nil || rule.Properties == nil {
		return false
	}
	for _, action := range rule.Properties.Actions {
		if action == nil {
			continue
		}
		base := action.GetAction()
		if base != nil && base.ActionType != nil && *base.ActionType == want {
			return true
		}
	}
	return false
}

// listAlertProcessingRules walks either the resource group or the whole subscription
// and returns the ids of the rules carrying the wanted action type.
func listAlertProcessingRules(ctx context.Context, api alertProcessingRulesAPI, rgName string, want armalertsmanagement.ActionType) ([]string, error) {
	var nativeIDs []string

	if rgName != "" {
		pager := api.NewListByResourceGroupPager(rgName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list alert processing rules: %w", err)
			}
			for _, rule := range page.Value {
				if rule != nil && rule.ID != nil && alertProcessingRuleHasActionType(rule, want) {
					nativeIDs = append(nativeIDs, *rule.ID)
				}
			}
		}
		return nativeIDs, nil
	}

	pager := api.NewListBySubscriptionPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list alert processing rules: %w", err)
		}
		for _, rule := range page.Value {
			if rule != nil && rule.ID != nil && alertProcessingRuleHasActionType(rule, want) {
				nativeIDs = append(nativeIDs, *rule.ID)
			}
		}
	}
	return nativeIDs, nil
}

func (a *AlertProcessingRuleActionGroup) buildPropertiesFromResult(rule *armalertsmanagement.AlertProcessingRule, rgName string) map[string]any {
	props := alertProcessingRuleCommonProperties(rule, rgName)

	if rule.Properties == nil {
		return props
	}
	var actionGroupIDs []string
	for _, action := range rule.Properties.Actions {
		add, ok := action.(*armalertsmanagement.AddActionGroups)
		if !ok || add == nil {
			continue
		}
		actionGroupIDs = append(actionGroupIDs, stringsFromPointers(add.ActionGroupIDs)...)
	}
	if len(actionGroupIDs) > 0 {
		props["actionGroupIds"] = actionGroupIDs
	}
	// A RemoveAllActionGroups action belongs to the suppression resource type and is
	// deliberately not read back here; the schedule block is likewise only modelled
	// there.
	return props
}

func (a *AlertProcessingRuleActionGroup) params(props alertProcessingRuleProps, payload json.RawMessage) armalertsmanagement.AlertProcessingRule {
	properties := alertProcessingRuleBaseProperties(props)
	properties.Actions = []armalertsmanagement.ActionClassification{
		&armalertsmanagement.AddActionGroups{
			ActionType:     to.Ptr(armalertsmanagement.ActionTypeAddActionGroups),
			ActionGroupIDs: stringPointers(props.ActionGroupIds),
		},
	}

	rule := armalertsmanagement.AlertProcessingRule{
		Location:   to.Ptr(props.Location),
		Properties: properties,
	}
	if tags := formaeTagsToAzureTags(payload); len(tags) > 0 {
		rule.Tags = tags
	}
	return rule
}

func (a *AlertProcessingRuleActionGroup) parseProps(payload json.RawMessage, label string) (alertProcessingRuleProps, string, error) {
	props, name, err := parseAlertProcessingRuleProps(payload, label)
	if err != nil {
		return props, "", err
	}
	if len(props.ActionGroupIds) == 0 {
		return props, "", fmt.Errorf("at least one actionGroupId is required")
	}
	return props, name, nil
}

func (a *AlertProcessingRuleActionGroup) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	props, name, err := a.parseProps(request.Properties, request.Label)
	if err != nil {
		return nil, err
	}

	result, err := a.api.CreateOrUpdate(ctx, props.ResourceGroupName, name, a.params(props, request.Properties), nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
				StatusMessage:   err.Error(),
			},
		}, nil
	}

	nativeID := ""
	if result.ID != nil {
		nativeID = *result.ID
	}
	propsJSON, err := json.Marshal(a.buildPropertiesFromResult(&result.AlertProcessingRule, props.ResourceGroupName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
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

func (a *AlertProcessingRuleActionGroup) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, name, err := alertProcessingRuleIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := a.api.GetByName(ctx, rgName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(a.buildPropertiesFromResult(&result.AlertProcessingRule, rgName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeAlertProcessingRuleActionGroup,
		Properties:   string(propsJSON),
	}, nil
}

// Update reissues CreateOrUpdate. The PATCH verb takes PatchObject, which reaches
// only tags and the enabled flag, so it cannot change scopes, conditions or the
// action groups. Location rides along because a PUT without it is rejected.
func (a *AlertProcessingRuleActionGroup) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, name, err := alertProcessingRuleIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	props, _, err := a.parseProps(request.DesiredProperties, name)
	if err != nil {
		return nil, err
	}

	result, err := a.api.CreateOrUpdate(ctx, rgName, name, a.params(props, request.DesiredProperties), nil)
	if err != nil {
		return &resource.UpdateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationUpdate,
				OperationStatus: resource.OperationStatusFailure,
				NativeID:        request.NativeID,
				ErrorCode:       operationErrorCode(err),
				StatusMessage:   err.Error(),
			},
		}, nil
	}

	propsJSON, err := json.Marshal(a.buildPropertiesFromResult(&result.AlertProcessingRule, rgName))
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

func (a *AlertProcessingRuleActionGroup) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, name, err := alertProcessingRuleIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	if _, err := a.api.Delete(ctx, rgName, name, nil); err != nil && !isDeleteSuccessError(err) {
		return &resource.DeleteResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationDelete,
				OperationStatus: resource.OperationStatusFailure,
				NativeID:        request.NativeID,
				ErrorCode:       operationErrorCode(err),
				StatusMessage:   err.Error(),
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

// Status can only ever be asked about an operation that already finished: every
// write here is synchronous.
func (a *AlertProcessingRuleActionGroup) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

// List narrows to a resource group when one is given, and otherwise walks the whole
// subscription. Rules whose action is RemoveAllActionGroups belong to
// AZURE::AlertsManagement::AlertProcessingRuleSuppression and are filtered out.
func (a *AlertProcessingRuleActionGroup) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	nativeIDs, err := listAlertProcessingRules(ctx, a.api,
		request.AdditionalProperties["resourceGroupName"], armalertsmanagement.ActionTypeAddActionGroups)
	if err != nil {
		return nil, err
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
