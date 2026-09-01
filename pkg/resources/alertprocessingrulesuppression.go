// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/alertsmanagement/armalertsmanagement"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeAlertProcessingRuleSuppression = "AZURE::AlertsManagement::AlertProcessingRuleSuppression"

func init() {
	registry.Register(ResourceTypeAlertProcessingRuleSuppression, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &AlertProcessingRuleSuppression{api: c.AlertProcessingRulesClient, config: cfg}
	})
}

// AlertProcessingRuleSuppression is the provisioner for the RemoveAllActionGroups
// flavour of Microsoft.AlertsManagement/actionRules: it silences notifications for
// every alert that matches its scopes and conditions, typically during a maintenance
// window.
//
// It shares the ARM type, the SDK client and the request/response plumbing with
// AZURE::AlertsManagement::AlertProcessingRuleActionGroup; the shared pieces live in
// alertprocessingruleactiongroup.go.
type AlertProcessingRuleSuppression struct {
	api    alertProcessingRulesAPI
	config *config.Config
}

func (a *AlertProcessingRuleSuppression) buildPropertiesFromResult(rule *armalertsmanagement.AlertProcessingRule, rgName string) map[string]any {
	props := alertProcessingRuleCommonProperties(rule, rgName)

	if rule.Properties == nil || rule.Properties.Schedule == nil {
		return props
	}
	s := rule.Properties.Schedule
	schedule := map[string]any{}
	if s.EffectiveFrom != nil {
		schedule["effectiveFrom"] = *s.EffectiveFrom
	}
	if s.EffectiveUntil != nil {
		schedule["effectiveUntil"] = *s.EffectiveUntil
	}
	if s.TimeZone != nil {
		schedule["timeZone"] = *s.TimeZone
	}
	if len(schedule) > 0 {
		props["schedule"] = schedule
	}
	// ARM's recurrences (daily/weekly/monthly) are a polymorphic union that the
	// schema does not model, so they are not read back either — surfacing a shape the
	// schema cannot express would drift forever.
	return props
}

func (a *AlertProcessingRuleSuppression) params(props alertProcessingRuleProps, payload json.RawMessage) armalertsmanagement.AlertProcessingRule {
	properties := alertProcessingRuleBaseProperties(props)
	properties.Actions = []armalertsmanagement.ActionClassification{
		&armalertsmanagement.RemoveAllActionGroups{
			ActionType: to.Ptr(armalertsmanagement.ActionTypeRemoveAllActionGroups),
		},
	}
	if s := props.Schedule; s != nil {
		schedule := &armalertsmanagement.Schedule{}
		if s.EffectiveFrom != "" {
			schedule.EffectiveFrom = to.Ptr(s.EffectiveFrom)
		}
		if s.EffectiveUntil != "" {
			schedule.EffectiveUntil = to.Ptr(s.EffectiveUntil)
		}
		if s.TimeZone != "" {
			schedule.TimeZone = to.Ptr(s.TimeZone)
		}
		properties.Schedule = schedule
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

func (a *AlertProcessingRuleSuppression) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	props, name, err := parseAlertProcessingRuleProps(request.Properties, request.Label)
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

func (a *AlertProcessingRuleSuppression) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
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
		ResourceType: ResourceTypeAlertProcessingRuleSuppression,
		Properties:   string(propsJSON),
	}, nil
}

// Update reissues CreateOrUpdate. The PATCH verb takes PatchObject, which reaches
// only tags and the enabled flag, so it cannot change scopes, conditions or the
// schedule. Location rides along because a PUT without it is rejected.
func (a *AlertProcessingRuleSuppression) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, name, err := alertProcessingRuleIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	props, _, err := parseAlertProcessingRuleProps(request.DesiredProperties, name)
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

func (a *AlertProcessingRuleSuppression) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
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
func (a *AlertProcessingRuleSuppression) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

// List narrows to a resource group when one is given, and otherwise walks the whole
// subscription. Rules whose action is AddActionGroups belong to
// AZURE::AlertsManagement::AlertProcessingRuleActionGroup and are filtered out.
func (a *AlertProcessingRuleSuppression) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	nativeIDs, err := listAlertProcessingRules(ctx, a.api,
		request.AdditionalProperties["resourceGroupName"], armalertsmanagement.ActionTypeRemoveAllActionGroups)
	if err != nil {
		return nil, err
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
