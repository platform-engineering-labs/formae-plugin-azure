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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/monitor/armmonitor"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeMonitorScheduledQueryRule = "AZURE::Insights::ScheduledQueryRule"

// monitorScheduledQueryRulesAPI is the armmonitor surface used here; all operations
// are synchronous.
//
// Note: armmonitor is still a pre-1.0 module (v0.13.0), so a future major bump may
// change these signatures. pkg/client pins this client to api-version 2021-08-01 —
// the module's default runs ahead of what the service accepts.
type monitorScheduledQueryRulesAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName string, ruleName string, parameters armmonitor.ScheduledQueryRuleResource, options *armmonitor.ScheduledQueryRulesClientCreateOrUpdateOptions) (armmonitor.ScheduledQueryRulesClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName string, ruleName string, options *armmonitor.ScheduledQueryRulesClientGetOptions) (armmonitor.ScheduledQueryRulesClientGetResponse, error)
	Delete(ctx context.Context, resourceGroupName string, ruleName string, options *armmonitor.ScheduledQueryRulesClientDeleteOptions) (armmonitor.ScheduledQueryRulesClientDeleteResponse, error)
	NewListByResourceGroupPager(resourceGroupName string, options *armmonitor.ScheduledQueryRulesClientListByResourceGroupOptions) *runtime.Pager[armmonitor.ScheduledQueryRulesClientListByResourceGroupResponse]
	NewListBySubscriptionPager(options *armmonitor.ScheduledQueryRulesClientListBySubscriptionOptions) *runtime.Pager[armmonitor.ScheduledQueryRulesClientListBySubscriptionResponse]
}

func init() {
	registry.Register(ResourceTypeMonitorScheduledQueryRule, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &MonitorScheduledQueryRule{
			api:    c.MonitorScheduledQueryRulesClient,
			config: cfg,
		}
	})
}

// MonitorScheduledQueryRule is the provisioner for Azure Monitor scheduled query
// rules, a.k.a. log alerts (Microsoft.Insights/scheduledQueryRules).
type MonitorScheduledQueryRule struct {
	api    monitorScheduledQueryRulesAPI
	config *config.Config
}

// monitorScheduledQueryRuleProps mirrors schema/pkl/insights/scheduledqueryrule.pkl.
type monitorScheduledQueryRuleProps struct {
	Name                string                     `json:"name"`
	ResourceGroupName   string                     `json:"resourceGroupName"`
	Location            string                     `json:"location"`
	Scopes              []string                   `json:"scopes"`
	Criteria            []monitorSQRConditionProps `json:"criteria"`
	Severity            *int32                     `json:"severity"`
	WindowSize          *string                    `json:"windowSize"`
	EvaluationFrequency *string                    `json:"evaluationFrequency"`
	ActionGroupIDs      []string                   `json:"actionGroupIds"`
	Description         *string                    `json:"description"`
	DisplayName         *string                    `json:"displayName"`
	SkipQueryValidation *bool                      `json:"skipQueryValidation"`
	Enabled             *bool                      `json:"enabled"`
	AutoMitigate        *bool                      `json:"autoMitigate"`
}

type monitorSQRConditionProps struct {
	Query           string                        `json:"query"`
	TimeAggregation string                        `json:"timeAggregation"`
	Operator        string                        `json:"operator"`
	Threshold       float64                       `json:"threshold"`
	FailingPeriods  *monitorSQRFailingPeriodProps `json:"failingPeriods"`
}

type monitorSQRFailingPeriodProps struct {
	MinFailingPeriodsToAlert  int64 `json:"minFailingPeriodsToAlert"`
	NumberOfEvaluationPeriods int64 `json:"numberOfEvaluationPeriods"`
}

func monitorScheduledQueryRuleIDParts(resourceID string) (rgName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "scheduledqueryrules")
	if err != nil {
		return "", "", err
	}
	return rgName, names["scheduledqueryrules"], nil
}

func (m *MonitorScheduledQueryRule) buildPropertiesFromResult(alert *armmonitor.ScheduledQueryRuleResource, rgName string) map[string]any {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName

	if alert.ID != nil {
		props["id"] = *alert.ID
	}
	if alert.Name != nil {
		props["name"] = *alert.Name
	}
	if alert.Location != nil {
		props["location"] = normalizeAzureLocation(*alert.Location)
	}

	if p := alert.Properties; p != nil {
		if p.Description != nil {
			props["description"] = *p.Description
		}
		if p.DisplayName != nil {
			props["displayName"] = *p.DisplayName
		}
		if p.SkipQueryValidation != nil {
			props["skipQueryValidation"] = *p.SkipQueryValidation
		}
		if p.Enabled != nil {
			props["enabled"] = *p.Enabled
		}
		if p.AutoMitigate != nil {
			props["autoMitigate"] = *p.AutoMitigate
		}
		if p.Severity != nil {
			props["severity"] = *p.Severity
		}
		if p.WindowSize != nil {
			props["windowSize"] = *p.WindowSize
		}
		if p.EvaluationFrequency != nil {
			props["evaluationFrequency"] = *p.EvaluationFrequency
		}
		if len(p.Scopes) > 0 {
			scopes := make([]string, 0, len(p.Scopes))
			for _, scope := range p.Scopes {
				if scope == nil {
					continue
				}
				scopes = append(scopes, *scope)
			}
			props["scopes"] = scopes
		}
		if p.Actions != nil && len(p.Actions.ActionGroups) > 0 {
			// Unlike metric alerts, this API carries action groups as bare ARM ID
			// strings rather than objects.
			ids := make([]string, 0, len(p.Actions.ActionGroups))
			for _, id := range p.Actions.ActionGroups {
				if id == nil {
					continue
				}
				ids = append(ids, *id)
			}
			props["actionGroupIds"] = ids
		}
		if criteria := monitorSQRCriteriaFromResult(p.Criteria); criteria != nil {
			props["criteria"] = criteria
		}
		// isMigrated, lastUpdatedTime, targetResourceType/Region, customProperties
		// and actionProperties are deliberately dropped: none is desired state here,
		// and lastUpdatedTime moves on its own.
	}

	if tags := azureTagsToFormaeTags(alert.Tags); tags != nil {
		props["Tags"] = tags
	}

	return props
}

// monitorSQRCriteriaFromResult reads back only the condition shape this schema can
// express: a static threshold on a KQL query.
//
// ARM also supports dynamic thresholds (alertSensitivity + ignoreDataBefore) and
// dimension splitting. Neither is modelled, so a condition using either is skipped
// rather than half-read — surfacing something the schema cannot express would show
// as drift forever.
func monitorSQRCriteriaFromResult(criteria *armmonitor.ScheduledQueryRuleCriteria) []map[string]any {
	if criteria == nil {
		return nil
	}

	out := make([]map[string]any, 0, len(criteria.AllOf))
	for _, c := range criteria.AllOf {
		if c == nil || c.Query == nil {
			continue
		}
		if c.AlertSensitivity != nil || len(c.Dimensions) > 0 {
			continue
		}
		entry := map[string]any{"query": *c.Query}
		if c.TimeAggregation != nil {
			entry["timeAggregation"] = string(*c.TimeAggregation)
		}
		if c.Operator != nil {
			entry["operator"] = string(*c.Operator)
		}
		if c.Threshold != nil {
			entry["threshold"] = *c.Threshold
		}
		if fp := c.FailingPeriods; fp != nil && fp.MinFailingPeriodsToAlert != nil && fp.NumberOfEvaluationPeriods != nil {
			entry["failingPeriods"] = map[string]any{
				"minFailingPeriodsToAlert":  *fp.MinFailingPeriodsToAlert,
				"numberOfEvaluationPeriods": *fp.NumberOfEvaluationPeriods,
			}
		}
		out = append(out, entry)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// monitorScheduledQueryRuleParams builds the request body shared by create and update.
func monitorScheduledQueryRuleParams(props monitorScheduledQueryRuleProps) armmonitor.ScheduledQueryRuleResource {
	conditions := make([]*armmonitor.Condition, 0, len(props.Criteria))
	for _, c := range props.Criteria {
		condition := &armmonitor.Condition{
			Query:           to.Ptr(c.Query),
			TimeAggregation: to.Ptr(armmonitor.TimeAggregation(c.TimeAggregation)),
			Operator:        to.Ptr(armmonitor.ConditionOperator(c.Operator)),
			Threshold:       to.Ptr(c.Threshold),
		}
		if c.FailingPeriods != nil {
			condition.FailingPeriods = &armmonitor.ConditionFailingPeriods{
				MinFailingPeriodsToAlert:  to.Ptr(c.FailingPeriods.MinFailingPeriodsToAlert),
				NumberOfEvaluationPeriods: to.Ptr(c.FailingPeriods.NumberOfEvaluationPeriods),
			}
		}
		conditions = append(conditions, condition)
	}

	scopes := make([]*string, 0, len(props.Scopes))
	for _, scope := range props.Scopes {
		scopes = append(scopes, to.Ptr(scope))
	}

	ruleProps := &armmonitor.ScheduledQueryRuleProperties{
		Scopes:              scopes,
		Criteria:            &armmonitor.ScheduledQueryRuleCriteria{AllOf: conditions},
		Enabled:             props.Enabled,
		WindowSize:          props.WindowSize,
		EvaluationFrequency: props.EvaluationFrequency,
		Description:         props.Description,
		DisplayName:         props.DisplayName,
		AutoMitigate:        props.AutoMitigate,
		SkipQueryValidation: props.SkipQueryValidation,
	}
	if props.Severity != nil {
		ruleProps.Severity = to.Ptr(armmonitor.AlertSeverity(*props.Severity))
	}
	if len(props.ActionGroupIDs) > 0 {
		ids := make([]*string, 0, len(props.ActionGroupIDs))
		for _, id := range props.ActionGroupIDs {
			ids = append(ids, to.Ptr(id))
		}
		ruleProps.Actions = &armmonitor.Actions{ActionGroups: ids}
	}

	return armmonitor.ScheduledQueryRuleResource{
		Location:   to.Ptr(props.Location),
		Properties: ruleProps,
	}
}

// upsert backs both Create and Update. The ARM PATCH
// (ScheduledQueryRuleResourcePatch) exists but takes the same full property bag, so
// every write goes through CreateOrUpdate, which replaces the rule wholesale.
func (m *MonitorScheduledQueryRule) upsert(ctx context.Context, payload json.RawMessage, label string) (armmonitor.ScheduledQueryRuleResource, string, string, error) {
	var props monitorScheduledQueryRuleProps
	if err := json.Unmarshal(payload, &props); err != nil {
		return armmonitor.ScheduledQueryRuleResource{}, "", "", fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return armmonitor.ScheduledQueryRuleResource{}, "", "", fmt.Errorf("resourceGroupName is required")
	}
	if len(props.Scopes) == 0 {
		return armmonitor.ScheduledQueryRuleResource{}, "", "", fmt.Errorf("scopes is required")
	}
	if len(props.Criteria) == 0 {
		return armmonitor.ScheduledQueryRuleResource{}, "", "", fmt.Errorf("criteria is required")
	}
	if props.Severity == nil {
		return armmonitor.ScheduledQueryRuleResource{}, "", "", fmt.Errorf("severity is required")
	}
	if props.Location == "" {
		return armmonitor.ScheduledQueryRuleResource{}, "", "", fmt.Errorf("location is required")
	}
	if props.WindowSize == nil || props.EvaluationFrequency == nil {
		return armmonitor.ScheduledQueryRuleResource{}, "", "", fmt.Errorf("windowSize and evaluationFrequency are required")
	}
	name := props.Name
	if name == "" {
		name = label
	}
	if name == "" {
		return armmonitor.ScheduledQueryRuleResource{}, "", "", fmt.Errorf("name is required")
	}

	params := monitorScheduledQueryRuleParams(props)
	if azureTags := formaeTagsToAzureTags(payload); azureTags != nil {
		params.Tags = azureTags
	}

	result, err := m.api.CreateOrUpdate(ctx, props.ResourceGroupName, name, params, nil)
	if err != nil {
		return armmonitor.ScheduledQueryRuleResource{}, props.ResourceGroupName, name, err
	}
	return result.ScheduledQueryRuleResource, props.ResourceGroupName, name, nil
}

func (m *MonitorScheduledQueryRule) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	created, rgName, _, err := m.upsert(ctx, request.Properties, request.Label)
	if err != nil {
		if rgName == "" {
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

	nativeID := ""
	if created.ID != nil {
		nativeID = *created.ID
	}
	propsJSON, err := json.Marshal(m.buildPropertiesFromResult(&created, rgName))
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

func (m *MonitorScheduledQueryRule) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, name, err := monitorScheduledQueryRuleIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := m.api.Get(ctx, rgName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(m.buildPropertiesFromResult(&result.ScheduledQueryRuleResource, rgName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeMonitorScheduledQueryRule,
		Properties:   string(propsJSON),
	}, nil
}

func (m *MonitorScheduledQueryRule) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	updated, rgName, _, err := m.upsert(ctx, request.DesiredProperties, "")
	if err != nil {
		if rgName == "" {
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

	propsJSON, err := json.Marshal(m.buildPropertiesFromResult(&updated, rgName))
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

func (m *MonitorScheduledQueryRule) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, name, err := monitorScheduledQueryRuleIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	if _, err := m.api.Delete(ctx, rgName, name, nil); err != nil && !isDeleteSuccessError(err) {
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

// Status is never reached with real work to do: every operation on a metric alert
// is synchronous, so it echoes success.
func (m *MonitorScheduledQueryRule) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

func (m *MonitorScheduledQueryRule) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]

	var nativeIDs []string

	if rgName != "" {
		pager := m.api.NewListByResourceGroupPager(rgName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list scheduled query rules: %w", err)
			}
			for _, alert := range page.Value {
				if alert.ID != nil {
					nativeIDs = append(nativeIDs, *alert.ID)
				}
			}
		}
		return &resource.ListResult{NativeIDs: nativeIDs}, nil
	}

	pager := m.api.NewListBySubscriptionPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list scheduled query rules: %w", err)
		}
		for _, alert := range page.Value {
			if alert.ID != nil {
				nativeIDs = append(nativeIDs, *alert.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
