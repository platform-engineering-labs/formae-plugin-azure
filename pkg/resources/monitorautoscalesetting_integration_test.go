// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/monitor/armmonitor"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testAutoscaleSettingNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Insights/autoscaleSettings/as1"

const testAutoscaleTargetID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.SignalRService/webPubSub/wps1"

type fakeAutoscaleSettingsAPI struct {
	createFn      func(ctx context.Context, rgName, name string, body armmonitor.AutoscaleSettingResource, options *armmonitor.AutoscaleSettingsClientCreateOrUpdateOptions) (armmonitor.AutoscaleSettingsClientCreateOrUpdateResponse, error)
	getFn         func(ctx context.Context, rgName, name string, options *armmonitor.AutoscaleSettingsClientGetOptions) (armmonitor.AutoscaleSettingsClientGetResponse, error)
	deleteFn      func(ctx context.Context, rgName, name string, options *armmonitor.AutoscaleSettingsClientDeleteOptions) (armmonitor.AutoscaleSettingsClientDeleteResponse, error)
	listByGroupFn func(rgName string, options *armmonitor.AutoscaleSettingsClientListByResourceGroupOptions) *runtime.Pager[armmonitor.AutoscaleSettingsClientListByResourceGroupResponse]
	listBySubFn   func(options *armmonitor.AutoscaleSettingsClientListBySubscriptionOptions) *runtime.Pager[armmonitor.AutoscaleSettingsClientListBySubscriptionResponse]
}

func (f *fakeAutoscaleSettingsAPI) CreateOrUpdate(ctx context.Context, rgName, name string, body armmonitor.AutoscaleSettingResource, options *armmonitor.AutoscaleSettingsClientCreateOrUpdateOptions) (armmonitor.AutoscaleSettingsClientCreateOrUpdateResponse, error) {
	return f.createFn(ctx, rgName, name, body, options)
}

func (f *fakeAutoscaleSettingsAPI) Get(ctx context.Context, rgName, name string, options *armmonitor.AutoscaleSettingsClientGetOptions) (armmonitor.AutoscaleSettingsClientGetResponse, error) {
	return f.getFn(ctx, rgName, name, options)
}

func (f *fakeAutoscaleSettingsAPI) Delete(ctx context.Context, rgName, name string, options *armmonitor.AutoscaleSettingsClientDeleteOptions) (armmonitor.AutoscaleSettingsClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, name, options)
}

func (f *fakeAutoscaleSettingsAPI) NewListByResourceGroupPager(rgName string, options *armmonitor.AutoscaleSettingsClientListByResourceGroupOptions) *runtime.Pager[armmonitor.AutoscaleSettingsClientListByResourceGroupResponse] {
	return f.listByGroupFn(rgName, options)
}

func (f *fakeAutoscaleSettingsAPI) NewListBySubscriptionPager(options *armmonitor.AutoscaleSettingsClientListBySubscriptionOptions) *runtime.Pager[armmonitor.AutoscaleSettingsClientListBySubscriptionResponse] {
	return f.listBySubFn(options)
}

func newTestAutoscaleSetting(api monitorAutoscaleSettingsAPI) *MonitorAutoscaleSetting {
	return &MonitorAutoscaleSetting{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func autoscaleSettingDesired(maximum string) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":              "as1",
		"resourceGroupName": "rg-1",
		"location":          "westeurope",
		"targetResourceUri": testAutoscaleTargetID,
		"enabled":           true,
		"profiles": []any{
			map[string]any{
				"name": "default",
				"capacity": map[string]any{
					"minimum": "1",
					"maximum": maximum,
					"default": "1",
				},
				"rules": []any{
					map[string]any{
						"metricTrigger": map[string]any{
							"metricName":        "ConnectionQuotaUtilization",
							"metricResourceUri": testAutoscaleTargetID,
							"timeGrain":         "PT1M",
							"statistic":         "Average",
							"timeWindow":        "PT5M",
							"timeAggregation":   "Average",
							"operator":          "GreaterThan",
							"threshold":         70,
						},
						"scaleAction": map[string]any{
							"direction": "Increase",
							"type":      "ChangeCount",
							"value":     "1",
							"cooldown":  "PT5M",
						},
					},
				},
			},
		},
		"Tags": []any{map[string]any{"Key": "env", "Value": "test"}},
	})
	return out
}

func TestMonitorAutoscaleSetting_CRUD(t *testing.T) {
	settingResult := armmonitor.AutoscaleSettingResource{
		ID:       to.Ptr(testAutoscaleSettingNativeID),
		Name:     to.Ptr("as1"),
		Location: to.Ptr("West Europe"),
		Properties: &armmonitor.AutoscaleSetting{
			// ARM fills in the setting name and the target's region on its own.
			Name:                   to.Ptr("as1"),
			Enabled:                to.Ptr(true),
			TargetResourceURI:      to.Ptr(testAutoscaleTargetID),
			TargetResourceLocation: to.Ptr("West Europe"),
			PredictiveAutoscalePolicy: &armmonitor.PredictiveAutoscalePolicy{
				ScaleMode: to.Ptr(armmonitor.PredictiveAutoscalePolicyScaleModeDisabled),
			},
			Profiles: []*armmonitor.AutoscaleProfile{
				{
					Name: to.Ptr("default"),
					Capacity: &armmonitor.ScaleCapacity{
						Minimum: to.Ptr("1"), Maximum: to.Ptr("2"), Default: to.Ptr("1"),
					},
					Rules: []*armmonitor.ScaleRule{
						{
							MetricTrigger: &armmonitor.MetricTrigger{
								MetricName:        to.Ptr("ConnectionQuotaUtilization"),
								MetricResourceURI: to.Ptr(testAutoscaleTargetID),
								TimeGrain:         to.Ptr("PT1M"),
								Statistic:         to.Ptr(armmonitor.MetricStatisticTypeAverage),
								TimeWindow:        to.Ptr("PT5M"),
								TimeAggregation:   to.Ptr(armmonitor.TimeAggregationTypeAverage),
								Operator:          to.Ptr(armmonitor.ComparisonOperationTypeGreaterThan),
								Threshold:         to.Ptr(float64(70)),
								// Service-filled members of a nested class. They must
								// NOT come back: hasProviderDefault is a no-op inside
								// profiles[]/rules[], so echoing them would read as
								// unexpected drift on every sync.
								MetricNamespace:        to.Ptr(""),
								MetricResourceLocation: to.Ptr("westeurope"),
								DividePerInstance:      to.Ptr(false),
								Dimensions:             []*armmonitor.ScaleRuleMetricDimension{},
							},
							ScaleAction: &armmonitor.ScaleAction{
								Direction: to.Ptr(armmonitor.ScaleDirectionIncrease),
								Type:      to.Ptr(armmonitor.ScaleTypeChangeCount),
								Value:     to.Ptr("1"),
								Cooldown:  to.Ptr("PT5M"),
							},
						},
					},
				},
			},
			Notifications: []*armmonitor.AutoscaleNotification{
				{Operation: to.Ptr("Scale")},
			},
		},
		Tags: map[string]*string{"env": to.Ptr("test")},
	}

	var sent armmonitor.AutoscaleSettingResource
	writeCalls := 0
	deleteCalls := 0
	fake := &fakeAutoscaleSettingsAPI{
		createFn: func(_ context.Context, rgName, name string, body armmonitor.AutoscaleSettingResource, _ *armmonitor.AutoscaleSettingsClientCreateOrUpdateOptions) (armmonitor.AutoscaleSettingsClientCreateOrUpdateResponse, error) {
			require.Equal(t, "rg-1", rgName)
			require.Equal(t, "as1", name)
			sent = body
			writeCalls++
			return armmonitor.AutoscaleSettingsClientCreateOrUpdateResponse{AutoscaleSettingResource: settingResult}, nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armmonitor.AutoscaleSettingsClientGetOptions) (armmonitor.AutoscaleSettingsClientGetResponse, error) {
			return armmonitor.AutoscaleSettingsClientGetResponse{AutoscaleSettingResource: settingResult}, nil
		},
		deleteFn: func(_ context.Context, _, _ string, _ *armmonitor.AutoscaleSettingsClientDeleteOptions) (armmonitor.AutoscaleSettingsClientDeleteResponse, error) {
			deleteCalls++
			return armmonitor.AutoscaleSettingsClientDeleteResponse{}, nil
		},
		listByGroupFn: func(_ string, _ *armmonitor.AutoscaleSettingsClientListByResourceGroupOptions) *runtime.Pager[armmonitor.AutoscaleSettingsClientListByResourceGroupResponse] {
			return runtime.NewPager(runtime.PagingHandler[armmonitor.AutoscaleSettingsClientListByResourceGroupResponse]{
				More: func(_ armmonitor.AutoscaleSettingsClientListByResourceGroupResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armmonitor.AutoscaleSettingsClientListByResourceGroupResponse) (armmonitor.AutoscaleSettingsClientListByResourceGroupResponse, error) {
					return armmonitor.AutoscaleSettingsClientListByResourceGroupResponse{
						AutoscaleSettingResourceCollection: armmonitor.AutoscaleSettingResourceCollection{
							Value: []*armmonitor.AutoscaleSettingResource{
								{ID: to.Ptr(testAutoscaleSettingNativeID)},
								// A nil entry must not panic the walk.
								nil,
							},
						},
					}, nil
				},
			})
		},
		listBySubFn: func(_ *armmonitor.AutoscaleSettingsClientListBySubscriptionOptions) *runtime.Pager[armmonitor.AutoscaleSettingsClientListBySubscriptionResponse] {
			return runtime.NewPager(runtime.PagingHandler[armmonitor.AutoscaleSettingsClientListBySubscriptionResponse]{
				More: func(_ armmonitor.AutoscaleSettingsClientListBySubscriptionResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armmonitor.AutoscaleSettingsClientListBySubscriptionResponse) (armmonitor.AutoscaleSettingsClientListBySubscriptionResponse, error) {
					return armmonitor.AutoscaleSettingsClientListBySubscriptionResponse{
						AutoscaleSettingResourceCollection: armmonitor.AutoscaleSettingResourceCollection{
							Value: []*armmonitor.AutoscaleSettingResource{
								{ID: to.Ptr(testAutoscaleSettingNativeID)},
								{ID: to.Ptr("/subscriptions/sub-1/resourceGroups/rg-2/providers/Microsoft.Insights/autoscaleSettings/as2")},
							},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestAutoscaleSetting(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "as1", Properties: autoscaleSettingDesired("2"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testAutoscaleSettingNativeID, got.ProgressResult.NativeID)

		require.Equal(t, "westeurope", *sent.Location)
		require.Equal(t, testAutoscaleTargetID, *sent.Properties.TargetResourceURI)
		require.True(t, *sent.Properties.Enabled)
		require.Len(t, sent.Properties.Profiles, 1)
		profile := sent.Properties.Profiles[0]
		require.Equal(t, "default", *profile.Name)
		require.Equal(t, "2", *profile.Capacity.Maximum)
		require.Len(t, profile.Rules, 1)
		trigger := profile.Rules[0].MetricTrigger
		require.Equal(t, "ConnectionQuotaUtilization", *trigger.MetricName)
		require.Equal(t, armmonitor.MetricStatisticTypeAverage, *trigger.Statistic)
		require.Equal(t, armmonitor.ComparisonOperationTypeGreaterThan, *trigger.Operator)
		require.Equal(t, float64(70), *trigger.Threshold)
		action := profile.Rules[0].ScaleAction
		require.Equal(t, armmonitor.ScaleDirectionIncrease, *action.Direction)
		require.Equal(t, "PT5M", *action.Cooldown)
		require.Equal(t, "test", *sent.Tags["env"])
		// properties.name is left for ARM to fill in - the body verified against the
		// live API omitted it.
		require.Nil(t, sent.Properties.Name)
	})

	t.Run("Create_requires_target", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "as1", "resourceGroupName": "rg-1", "location": "westeurope",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "targetResourceUri is required")
	})

	t.Run("Create_requires_a_profile", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "as1", "resourceGroupName": "rg-1", "location": "westeurope",
			"targetResourceUri": testAutoscaleTargetID,
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "at least one profile is required")
	})

	t.Run("Create_requires_a_rule_per_profile", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "as1", "resourceGroupName": "rg-1", "location": "westeurope",
			"targetResourceUri": testAutoscaleTargetID,
			"profiles": []any{map[string]any{
				"name":     "default",
				"capacity": map[string]any{"minimum": "1", "maximum": "2", "default": "1"},
			}},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "needs at least one rule")
	})

	t.Run("Create_failure_carries_the_provider_error", func(t *testing.T) {
		fake.createFn = func(_ context.Context, _, _ string, _ armmonitor.AutoscaleSettingResource, _ *armmonitor.AutoscaleSettingsClientCreateOrUpdateOptions) (armmonitor.AutoscaleSettingsClientCreateOrUpdateResponse, error) {
			return armmonitor.AutoscaleSettingsClientCreateOrUpdateResponse{}, &azcore.ResponseError{
				StatusCode: 400, ErrorCode: "InvalidArgument",
			}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "as1", Properties: autoscaleSettingDesired("2"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.Equal(t, resource.OperationErrorCodeInvalidRequest, got.ProgressResult.ErrorCode)
		// Without this the only trace of a rejected targetResourceUri is a state
		// transition to Failed with no cause.
		require.Contains(t, got.ProgressResult.StatusMessage, "InvalidArgument")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testAutoscaleSettingNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "as1", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		// ARM returns "West Europe"; read must normalise or desired state drifts.
		require.Equal(t, "westeurope", props["location"])
		require.Equal(t, testAutoscaleTargetID, props["targetResourceUri"])
		require.Equal(t, true, props["enabled"])
		require.Equal(t, "westeurope", props["targetResourceLocation"])
		require.Equal(t, "Disabled", props["predictiveAutoscaleMode"])

		profiles := props["profiles"].([]any)
		require.Len(t, profiles, 1)
		profile := profiles[0].(map[string]any)
		require.Equal(t, "default", profile["name"])
		require.Equal(t, map[string]any{"minimum": "1", "maximum": "2", "default": "1"}, profile["capacity"])

		rules := profile["rules"].([]any)
		require.Len(t, rules, 1)
		trigger := rules[0].(map[string]any)["metricTrigger"].(map[string]any)
		require.Equal(t, "ConnectionQuotaUtilization", trigger["metricName"])
		require.Equal(t, float64(70), trigger["threshold"])
		// The nested service-populated members must be dropped, or every sync
		// reports "not expected and not a provider default".
		require.NotContains(t, trigger, "metricNamespace")
		require.NotContains(t, trigger, "metricResourceLocation")
		require.NotContains(t, trigger, "dividePerInstance")
		require.NotContains(t, trigger, "dimensions")
	})

	t.Run("Read_drops_unmodelled_state", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testAutoscaleSettingNativeID})
		require.NoError(t, err)
		for _, key := range []string{"notifications", "systemData", "fixedDate", "recurrence"} {
			require.NotContains(t, got.Properties, key)
		}
	})

	t.Run("Update_reissues_create", func(t *testing.T) {
		fake.createFn = func(_ context.Context, rgName, name string, body armmonitor.AutoscaleSettingResource, _ *armmonitor.AutoscaleSettingsClientCreateOrUpdateOptions) (armmonitor.AutoscaleSettingsClientCreateOrUpdateResponse, error) {
			require.Equal(t, "rg-1", rgName)
			require.Equal(t, "as1", name)
			sent = body
			writeCalls++
			return armmonitor.AutoscaleSettingsClientCreateOrUpdateResponse{AutoscaleSettingResource: settingResult}, nil
		}
		before := writeCalls
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testAutoscaleSettingNativeID,
			DesiredProperties: autoscaleSettingDesired("3"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, writeCalls)
		require.Equal(t, "3", *sent.Properties.Profiles[0].Capacity.Maximum)
		// Location must ride along: a PUT without it is rejected.
		require.Equal(t, "westeurope", *sent.Location)
	})

	t.Run("Delete", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testAutoscaleSettingNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _ string, _ *armmonitor.AutoscaleSettingsClientDeleteOptions) (armmonitor.AutoscaleSettingsClientDeleteResponse, error) {
			return armmonitor.AutoscaleSettingsClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testAutoscaleSettingNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Status_is_always_success", func(t *testing.T) {
		got, err := prov.Status(context.Background(), &resource.StatusRequest{RequestID: "whatever"})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_resource_group", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testAutoscaleSettingNativeID}, got.NativeIDs)
	})

	t.Run("List_without_group_is_subscription_wide", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 2)
	})

	t.Run("Read_NotFound", func(t *testing.T) {
		fake.getFn = func(_ context.Context, _, _ string, _ *armmonitor.AutoscaleSettingsClientGetOptions) (armmonitor.AutoscaleSettingsClientGetResponse, error) {
			return armmonitor.AutoscaleSettingsClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testAutoscaleSettingNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
	})
}
