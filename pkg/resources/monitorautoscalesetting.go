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

const ResourceTypeMonitorAutoscaleSetting = "AZURE::Insights::AutoscaleSetting"

// monitorAutoscaleSettingsAPI is the subset of *armmonitor.AutoscaleSettingsClient
// used here. Every call is synchronous. The SDK's Update verb takes
// AutoscaleSettingResourcePatch, which is a full properties replacement anyway, so
// CreateOrUpdate carries both writes.
type monitorAutoscaleSettingsAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName, autoscaleSettingName string, parameters armmonitor.AutoscaleSettingResource, options *armmonitor.AutoscaleSettingsClientCreateOrUpdateOptions) (armmonitor.AutoscaleSettingsClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName, autoscaleSettingName string, options *armmonitor.AutoscaleSettingsClientGetOptions) (armmonitor.AutoscaleSettingsClientGetResponse, error)
	Delete(ctx context.Context, resourceGroupName, autoscaleSettingName string, options *armmonitor.AutoscaleSettingsClientDeleteOptions) (armmonitor.AutoscaleSettingsClientDeleteResponse, error)
	NewListByResourceGroupPager(resourceGroupName string, options *armmonitor.AutoscaleSettingsClientListByResourceGroupOptions) *runtime.Pager[armmonitor.AutoscaleSettingsClientListByResourceGroupResponse]
	NewListBySubscriptionPager(options *armmonitor.AutoscaleSettingsClientListBySubscriptionOptions) *runtime.Pager[armmonitor.AutoscaleSettingsClientListBySubscriptionResponse]
}

func init() {
	registry.Register(ResourceTypeMonitorAutoscaleSetting, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &MonitorAutoscaleSetting{api: c.MonitorAutoscaleSettingsClient, config: cfg}
	})
}

// MonitorAutoscaleSetting is the provisioner for Azure Monitor autoscale settings
// (Microsoft.Insights/autoscaleSettings).
type MonitorAutoscaleSetting struct {
	api    monitorAutoscaleSettingsAPI
	config *config.Config
}

// monitorAutoscaleSettingProps mirrors schema/pkl/insights/autoscalesetting.pkl.
type monitorAutoscaleSettingProps struct {
	Name                    string                  `json:"name"`
	ResourceGroupName       string                  `json:"resourceGroupName"`
	Location                string                  `json:"location"`
	TargetResourceURI       string                  `json:"targetResourceUri"`
	Enabled                 *bool                   `json:"enabled"`
	PredictiveAutoscaleMode string                  `json:"predictiveAutoscaleMode"`
	Profiles                []autoscaleProfileProps `json:"profiles"`
}

type autoscaleProfileProps struct {
	Name     string                 `json:"name"`
	Capacity autoscaleCapacityProps `json:"capacity"`
	Rules    []autoscaleRuleProps   `json:"rules"`
}

type autoscaleCapacityProps struct {
	Minimum string `json:"minimum"`
	Maximum string `json:"maximum"`
	Default string `json:"default"`
}

type autoscaleRuleProps struct {
	MetricTrigger autoscaleMetricTriggerProps `json:"metricTrigger"`
	ScaleAction   autoscaleScaleActionProps   `json:"scaleAction"`
}

type autoscaleMetricTriggerProps struct {
	MetricName        string  `json:"metricName"`
	MetricResourceURI string  `json:"metricResourceUri"`
	TimeGrain         string  `json:"timeGrain"`
	Statistic         string  `json:"statistic"`
	TimeWindow        string  `json:"timeWindow"`
	TimeAggregation   string  `json:"timeAggregation"`
	Operator          string  `json:"operator"`
	Threshold         float64 `json:"threshold"`
}

type autoscaleScaleActionProps struct {
	Direction string `json:"direction"`
	Type      string `json:"type"`
	Value     string `json:"value"`
	Cooldown  string `json:"cooldown"`
}

func monitorAutoscaleSettingIDParts(resourceID string) (rgName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "autoscalesettings")
	if err != nil {
		return "", "", err
	}
	return rgName, names["autoscalesettings"], nil
}

// buildPropertiesFromResult reads an autoscale setting back into desired-state shape.
//
// Only the fields the schema models are emitted. That is deliberate rather than
// lazy: `hasProviderDefault` is honoured only on TOP-LEVEL resource properties, so
// anything the service fills in inside profiles[] or rules[] — metricNamespace,
// dividePerInstance, dimensions, metricResourceLocation — would read as "not
// expected and not a provider default" against a fixture that never declared it.
// Every nested field modelled here is required, so it is always sent and always
// echoed; everything else the service adds is dropped on the way back. The two
// values the service does choose on its own, targetResourceLocation and the
// predictive autoscale mode, are surfaced as top-level properties, where
// hasProviderDefault does work.
func (m *MonitorAutoscaleSetting) buildPropertiesFromResult(setting *armmonitor.AutoscaleSettingResource, rgName string) map[string]any {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName

	if setting.ID != nil {
		props["id"] = *setting.ID
	}
	if setting.Name != nil {
		props["name"] = *setting.Name
	}
	if setting.Location != nil {
		props["location"] = normalizeAzureLocation(*setting.Location)
	}
	if tags := azureTagsToFormaeTags(setting.Tags); len(tags) > 0 {
		props["Tags"] = tags
	}

	p := setting.Properties
	if p == nil {
		return props
	}

	if p.TargetResourceURI != nil {
		props["targetResourceUri"] = *p.TargetResourceURI
	}
	if p.Enabled != nil {
		props["enabled"] = *p.Enabled
	}
	if p.TargetResourceLocation != nil {
		props["targetResourceLocation"] = normalizeAzureLocation(*p.TargetResourceLocation)
	}
	if p.PredictiveAutoscalePolicy != nil && p.PredictiveAutoscalePolicy.ScaleMode != nil {
		props["predictiveAutoscaleMode"] = canonicalizeEnum(string(*p.PredictiveAutoscalePolicy.ScaleMode),
			"Disabled", "ForecastOnly", "Enabled")
	}

	profiles := make([]map[string]any, 0, len(p.Profiles))
	for _, profile := range p.Profiles {
		if profile == nil {
			continue
		}
		entry := map[string]any{}
		if profile.Name != nil {
			entry["name"] = *profile.Name
		}
		if c := profile.Capacity; c != nil {
			capacity := map[string]any{}
			if c.Minimum != nil {
				capacity["minimum"] = *c.Minimum
			}
			if c.Maximum != nil {
				capacity["maximum"] = *c.Maximum
			}
			if c.Default != nil {
				capacity["default"] = *c.Default
			}
			entry["capacity"] = capacity
		}
		rules := make([]map[string]any, 0, len(profile.Rules))
		for _, rule := range profile.Rules {
			if rule == nil {
				continue
			}
			ruleEntry := map[string]any{}
			if t := rule.MetricTrigger; t != nil {
				trigger := map[string]any{}
				if t.MetricName != nil {
					trigger["metricName"] = *t.MetricName
				}
				if t.MetricResourceURI != nil {
					trigger["metricResourceUri"] = *t.MetricResourceURI
				}
				if t.TimeGrain != nil {
					trigger["timeGrain"] = *t.TimeGrain
				}
				if t.Statistic != nil {
					trigger["statistic"] = canonicalizeEnum(string(*t.Statistic),
						"Average", "Min", "Max", "Sum", "Count")
				}
				if t.TimeWindow != nil {
					trigger["timeWindow"] = *t.TimeWindow
				}
				if t.TimeAggregation != nil {
					trigger["timeAggregation"] = canonicalizeEnum(string(*t.TimeAggregation),
						"Average", "Minimum", "Maximum", "Total", "Count", "Last")
				}
				if t.Operator != nil {
					trigger["operator"] = canonicalizeEnum(string(*t.Operator),
						"Equals", "NotEquals", "GreaterThan", "GreaterThanOrEqual", "LessThan", "LessThanOrEqual")
				}
				if t.Threshold != nil {
					trigger["threshold"] = *t.Threshold
				}
				ruleEntry["metricTrigger"] = trigger
			}
			if a := rule.ScaleAction; a != nil {
				action := map[string]any{}
				if a.Direction != nil {
					action["direction"] = canonicalizeEnum(string(*a.Direction), "None", "Increase", "Decrease")
				}
				if a.Type != nil {
					action["type"] = canonicalizeEnum(string(*a.Type),
						"ChangeCount", "PercentChangeCount", "ExactCount", "ServiceAllowedNextValue")
				}
				if a.Value != nil {
					action["value"] = *a.Value
				}
				if a.Cooldown != nil {
					action["cooldown"] = *a.Cooldown
				}
				ruleEntry["scaleAction"] = action
			}
			rules = append(rules, ruleEntry)
		}
		entry["rules"] = rules
		profiles = append(profiles, entry)
	}
	if len(profiles) > 0 {
		props["profiles"] = profiles
	}

	// notifications, fixedDate/recurrence schedules and per-rule dimensions are not
	// modelled, so they are not read back either — surfacing state the schema cannot
	// express would drift forever.
	return props
}

// monitorAutoscaleSettingParams builds the request body shared by create and update.
//
// properties.name is deliberately not sent: ARM fills it from the resource name, and
// the body verified against the live API omitted it.
func monitorAutoscaleSettingParams(props monitorAutoscaleSettingProps, payload json.RawMessage) armmonitor.AutoscaleSettingResource {
	setting := &armmonitor.AutoscaleSetting{
		TargetResourceURI: to.Ptr(props.TargetResourceURI),
	}
	if props.Enabled != nil {
		setting.Enabled = props.Enabled
	}
	if props.PredictiveAutoscaleMode != "" {
		setting.PredictiveAutoscalePolicy = &armmonitor.PredictiveAutoscalePolicy{
			ScaleMode: to.Ptr(armmonitor.PredictiveAutoscalePolicyScaleMode(props.PredictiveAutoscaleMode)),
		}
	}

	for _, profile := range props.Profiles {
		p := &armmonitor.AutoscaleProfile{
			Name: to.Ptr(profile.Name),
			Capacity: &armmonitor.ScaleCapacity{
				Minimum: to.Ptr(profile.Capacity.Minimum),
				Maximum: to.Ptr(profile.Capacity.Maximum),
				Default: to.Ptr(profile.Capacity.Default),
			},
		}
		for _, rule := range profile.Rules {
			p.Rules = append(p.Rules, &armmonitor.ScaleRule{
				MetricTrigger: &armmonitor.MetricTrigger{
					MetricName:        to.Ptr(rule.MetricTrigger.MetricName),
					MetricResourceURI: to.Ptr(rule.MetricTrigger.MetricResourceURI),
					TimeGrain:         to.Ptr(rule.MetricTrigger.TimeGrain),
					Statistic:         to.Ptr(armmonitor.MetricStatisticType(rule.MetricTrigger.Statistic)),
					TimeWindow:        to.Ptr(rule.MetricTrigger.TimeWindow),
					TimeAggregation:   to.Ptr(armmonitor.TimeAggregationType(rule.MetricTrigger.TimeAggregation)),
					Operator:          to.Ptr(armmonitor.ComparisonOperationType(rule.MetricTrigger.Operator)),
					Threshold:         to.Ptr(rule.MetricTrigger.Threshold),
				},
				ScaleAction: &armmonitor.ScaleAction{
					Direction: to.Ptr(armmonitor.ScaleDirection(rule.ScaleAction.Direction)),
					Type:      to.Ptr(armmonitor.ScaleType(rule.ScaleAction.Type)),
					Value:     to.Ptr(rule.ScaleAction.Value),
					Cooldown:  to.Ptr(rule.ScaleAction.Cooldown),
				},
			})
		}
		setting.Profiles = append(setting.Profiles, p)
	}

	params := armmonitor.AutoscaleSettingResource{
		Location:   to.Ptr(props.Location),
		Properties: setting,
	}
	if tags := formaeTagsToAzureTags(payload); len(tags) > 0 {
		params.Tags = tags
	}
	return params
}

func (m *MonitorAutoscaleSetting) parseProps(payload json.RawMessage, label string) (monitorAutoscaleSettingProps, string, error) {
	var props monitorAutoscaleSettingProps
	if err := json.Unmarshal(payload, &props); err != nil {
		return props, "", fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return props, "", fmt.Errorf("resourceGroupName is required")
	}
	if props.Location == "" {
		return props, "", fmt.Errorf("location is required")
	}
	if props.TargetResourceURI == "" {
		return props, "", fmt.Errorf("targetResourceUri is required")
	}
	if len(props.Profiles) == 0 {
		return props, "", fmt.Errorf("at least one profile is required")
	}
	for _, profile := range props.Profiles {
		if profile.Name == "" {
			return props, "", fmt.Errorf("every profile needs a name")
		}
		if len(profile.Rules) == 0 {
			return props, "", fmt.Errorf("profile %q needs at least one rule", profile.Name)
		}
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

func (m *MonitorAutoscaleSetting) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	props, name, err := m.parseProps(request.Properties, request.Label)
	if err != nil {
		return nil, err
	}

	result, err := m.api.CreateOrUpdate(ctx, props.ResourceGroupName, name,
		monitorAutoscaleSettingParams(props, request.Properties), nil)
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
	propsJSON, err := json.Marshal(m.buildPropertiesFromResult(&result.AutoscaleSettingResource, props.ResourceGroupName))
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

func (m *MonitorAutoscaleSetting) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, name, err := monitorAutoscaleSettingIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := m.api.Get(ctx, rgName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(m.buildPropertiesFromResult(&result.AutoscaleSettingResource, rgName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeMonitorAutoscaleSetting,
		Properties:   string(propsJSON),
	}, nil
}

// Update reissues CreateOrUpdate. The PATCH verb takes AutoscaleSettingResourcePatch,
// whose properties block replaces the whole autoscale setting anyway, so a PUT is
// both simpler and consistent with the rest of the plugin. Location rides along
// because a PUT without it is rejected.
func (m *MonitorAutoscaleSetting) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, name, err := monitorAutoscaleSettingIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	props, _, err := m.parseProps(request.DesiredProperties, name)
	if err != nil {
		return nil, err
	}

	result, err := m.api.CreateOrUpdate(ctx, rgName, name,
		monitorAutoscaleSettingParams(props, request.DesiredProperties), nil)
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

	propsJSON, err := json.Marshal(m.buildPropertiesFromResult(&result.AutoscaleSettingResource, rgName))
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

func (m *MonitorAutoscaleSetting) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, name, err := monitorAutoscaleSettingIDParts(request.NativeID)
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
func (m *MonitorAutoscaleSetting) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

// List narrows to a resource group when one is given, and otherwise walks the whole
// subscription.
func (m *MonitorAutoscaleSetting) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]

	var nativeIDs []string
	if rgName != "" {
		pager := m.api.NewListByResourceGroupPager(rgName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list autoscale settings: %w", err)
			}
			for _, setting := range page.Value {
				if setting != nil && setting.ID != nil {
					nativeIDs = append(nativeIDs, *setting.ID)
				}
			}
		}
		return &resource.ListResult{NativeIDs: nativeIDs}, nil
	}

	pager := m.api.NewListBySubscriptionPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list autoscale settings: %w", err)
		}
		for _, setting := range page.Value {
			if setting != nil && setting.ID != nil {
				nativeIDs = append(nativeIDs, *setting.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
