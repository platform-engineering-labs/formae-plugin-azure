// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/monitor/armmonitor"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeMonitorMetricAlert = "AZURE::Insights::MetricAlert"

// monitorMetricAlertsAPI is the armmonitor surface used here; all operations are
// synchronous.
//
// Note: armmonitor is still a pre-1.0 module (v0.13.0), so a future major bump may
// change these signatures. It also defaults this client to an api-version ARM
// rejects for metricAlerts, so pkg/client pins 2018-03-01 explicitly — see the
// comment there.
type monitorMetricAlertsAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName string, ruleName string, parameters armmonitor.MetricAlertResource, options *armmonitor.MetricAlertsClientCreateOrUpdateOptions) (armmonitor.MetricAlertsClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName string, ruleName string, options *armmonitor.MetricAlertsClientGetOptions) (armmonitor.MetricAlertsClientGetResponse, error)
	Delete(ctx context.Context, resourceGroupName string, ruleName string, options *armmonitor.MetricAlertsClientDeleteOptions) (armmonitor.MetricAlertsClientDeleteResponse, error)
	NewListByResourceGroupPager(resourceGroupName string, options *armmonitor.MetricAlertsClientListByResourceGroupOptions) *runtime.Pager[armmonitor.MetricAlertsClientListByResourceGroupResponse]
	NewListBySubscriptionPager(options *armmonitor.MetricAlertsClientListBySubscriptionOptions) *runtime.Pager[armmonitor.MetricAlertsClientListBySubscriptionResponse]
}

func init() {
	registry.Register(ResourceTypeMonitorMetricAlert, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &MonitorMetricAlert{
			api:    c.MonitorMetricAlertsClient,
			config: cfg,
		}
	})
}

// MonitorMetricAlert is the provisioner for Azure Monitor metric alerts
// (Microsoft.Insights/metricAlerts).
type MonitorMetricAlert struct {
	api    monitorMetricAlertsAPI
	config *config.Config
}

// monitorMetricAlertProps mirrors schema/pkl/insights/metricalert.pkl.
type monitorMetricAlertProps struct {
	Name                string                        `json:"name"`
	ResourceGroupName   string                        `json:"resourceGroupName"`
	Location            string                        `json:"location"`
	Scopes              []string                      `json:"scopes"`
	Criteria            []monitorMetricCriterionProps `json:"criteria"`
	Severity            *int32                        `json:"severity"`
	WindowSize          *string                       `json:"windowSize"`
	EvaluationFrequency *string                       `json:"evaluationFrequency"`
	ActionGroupIDs      []string                      `json:"actionGroupIds"`
	Description         *string                       `json:"description"`
	Enabled             *bool                         `json:"enabled"`
	AutoMitigate        *bool                         `json:"autoMitigate"`
}

type monitorMetricCriterionProps struct {
	Name            string  `json:"name"`
	MetricName      string  `json:"metricName"`
	MetricNamespace string  `json:"metricNamespace"`
	Operator        string  `json:"operator"`
	Threshold       float64 `json:"threshold"`
	TimeAggregation string  `json:"timeAggregation"`
}

func monitorMetricAlertIDParts(resourceID string) (rgName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "metricalerts")
	if err != nil {
		return "", "", err
	}
	return rgName, names["metricalerts"], nil
}

func (m *MonitorMetricAlert) buildPropertiesFromResult(alert *armmonitor.MetricAlertResource, rgName string) map[string]any {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName

	if alert.ID != nil {
		props["id"] = *alert.ID
	}
	if alert.Name != nil {
		props["name"] = *alert.Name
	}
	// ARM echoes "global" back with varying case; normalise so a read never
	// disagrees with the schema on case alone.
	if alert.Location != nil {
		loc := *alert.Location
		if strings.EqualFold(loc, "global") {
			loc = "Global"
		}
		props["location"] = loc
	}

	if p := alert.Properties; p != nil {
		if p.Description != nil {
			props["description"] = *p.Description
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
		if len(p.Actions) > 0 {
			ids := make([]string, 0, len(p.Actions))
			for _, action := range p.Actions {
				if action == nil || action.ActionGroupID == nil {
					continue
				}
				ids = append(ids, *action.ActionGroupID)
			}
			props["actionGroupIds"] = ids
		}
		if criteria := monitorMetricCriteriaFromResult(p.Criteria); criteria != nil {
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

// monitorMetricCriteriaFromResult reads back only the criteria shape this schema
// can express: single-resource, multiple-metric, static thresholds.
//
// ARM's criteria field is a polymorphic union. Dynamic-threshold criteria and
// multi-resource criteria with dimensions are not modelled, so an alert using them
// reads with no criteria rather than with wrong ones — surfacing a criterion the
// schema cannot express would show as drift forever. Dimensions on an otherwise
// static criterion are likewise a signal to skip it.
func monitorMetricCriteriaFromResult(criteria armmonitor.MetricAlertCriteriaClassification) []map[string]any {
	single, ok := criteria.(*armmonitor.MetricAlertSingleResourceMultipleMetricCriteria)
	if !ok || single == nil {
		return nil
	}

	out := make([]map[string]any, 0, len(single.AllOf))
	for _, c := range single.AllOf {
		if c == nil || len(c.Dimensions) > 0 {
			continue
		}
		entry := make(map[string]any)
		if c.Name != nil {
			entry["name"] = *c.Name
		}
		if c.MetricName != nil {
			entry["metricName"] = *c.MetricName
		}
		if c.MetricNamespace != nil {
			entry["metricNamespace"] = *c.MetricNamespace
		}
		if c.Operator != nil {
			entry["operator"] = string(*c.Operator)
		}
		if c.Threshold != nil {
			entry["threshold"] = *c.Threshold
		}
		if c.TimeAggregation != nil {
			entry["timeAggregation"] = string(*c.TimeAggregation)
		}
		out = append(out, entry)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// monitorMetricAlertParams builds the request body shared by create and update.
func monitorMetricAlertParams(props monitorMetricAlertProps) armmonitor.MetricAlertResource {
	location := props.Location
	if location == "" {
		location = "Global"
	}

	criteria := make([]*armmonitor.MetricCriteria, 0, len(props.Criteria))
	for _, c := range props.Criteria {
		criteria = append(criteria, &armmonitor.MetricCriteria{
			// ARM requires the discriminator on every criterion.
			CriterionType:   to.Ptr(armmonitor.CriterionTypeStaticThresholdCriterion),
			Name:            to.Ptr(c.Name),
			MetricName:      to.Ptr(c.MetricName),
			MetricNamespace: to.Ptr(c.MetricNamespace),
			Operator:        to.Ptr(armmonitor.Operator(c.Operator)),
			Threshold:       to.Ptr(c.Threshold),
			TimeAggregation: to.Ptr(armmonitor.AggregationTypeEnum(c.TimeAggregation)),
		})
	}

	scopes := make([]*string, 0, len(props.Scopes))
	for _, scope := range props.Scopes {
		scopes = append(scopes, to.Ptr(scope))
	}

	alertProps := &armmonitor.MetricAlertProperties{
		Scopes:              scopes,
		Severity:            props.Severity,
		Enabled:             props.Enabled,
		WindowSize:          props.WindowSize,
		EvaluationFrequency: props.EvaluationFrequency,
		Description:         props.Description,
		AutoMitigate:        props.AutoMitigate,
		Criteria: &armmonitor.MetricAlertSingleResourceMultipleMetricCriteria{
			ODataType: to.Ptr(armmonitor.OdatatypeMicrosoftAzureMonitorSingleResourceMultipleMetricCriteria),
			AllOf:     criteria,
		},
	}

	if len(props.ActionGroupIDs) > 0 {
		actions := make([]*armmonitor.MetricAlertAction, 0, len(props.ActionGroupIDs))
		for _, id := range props.ActionGroupIDs {
			actions = append(actions, &armmonitor.MetricAlertAction{ActionGroupID: to.Ptr(id)})
		}
		alertProps.Actions = actions
	}

	return armmonitor.MetricAlertResource{
		Location:   to.Ptr(location),
		Properties: alertProps,
	}
}

// upsert backs both Create and Update. The ARM PATCH (MetricAlertResourcePatch)
// exists but takes the same full property bag, so every write goes through
// CreateOrUpdate, which replaces the rule wholesale.
func (m *MonitorMetricAlert) upsert(ctx context.Context, payload json.RawMessage, label string) (armmonitor.MetricAlertResource, string, string, error) {
	var props monitorMetricAlertProps
	if err := json.Unmarshal(payload, &props); err != nil {
		return armmonitor.MetricAlertResource{}, "", "", fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return armmonitor.MetricAlertResource{}, "", "", fmt.Errorf("resourceGroupName is required")
	}
	if len(props.Scopes) == 0 {
		return armmonitor.MetricAlertResource{}, "", "", fmt.Errorf("scopes is required")
	}
	if len(props.Criteria) == 0 {
		return armmonitor.MetricAlertResource{}, "", "", fmt.Errorf("criteria is required")
	}
	if props.Severity == nil {
		return armmonitor.MetricAlertResource{}, "", "", fmt.Errorf("severity is required")
	}
	name := props.Name
	if name == "" {
		name = label
	}
	if name == "" {
		return armmonitor.MetricAlertResource{}, "", "", fmt.Errorf("name is required")
	}

	params := monitorMetricAlertParams(props)
	if azureTags := formaeTagsToAzureTags(payload); azureTags != nil {
		params.Tags = azureTags
	}

	result, err := m.api.CreateOrUpdate(ctx, props.ResourceGroupName, name, params, nil)
	if err != nil {
		return armmonitor.MetricAlertResource{}, props.ResourceGroupName, name, err
	}
	return result.MetricAlertResource, props.ResourceGroupName, name, nil
}

func (m *MonitorMetricAlert) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
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

func (m *MonitorMetricAlert) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, name, err := monitorMetricAlertIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := m.api.Get(ctx, rgName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(m.buildPropertiesFromResult(&result.MetricAlertResource, rgName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeMonitorMetricAlert,
		Properties:   string(propsJSON),
	}, nil
}

func (m *MonitorMetricAlert) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
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

func (m *MonitorMetricAlert) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, name, err := monitorMetricAlertIDParts(request.NativeID)
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
func (m *MonitorMetricAlert) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

func (m *MonitorMetricAlert) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]

	var nativeIDs []string

	if rgName != "" {
		pager := m.api.NewListByResourceGroupPager(rgName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list metric alerts: %w", err)
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
			return nil, fmt.Errorf("failed to list metric alerts: %w", err)
		}
		for _, alert := range page.Value {
			if alert.ID != nil {
				nativeIDs = append(nativeIDs, *alert.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
