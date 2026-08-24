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

const (
	testMetricAlertNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Insights/metricAlerts/ma-1"
	testMetricAlertScopeID  = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Storage/storageAccounts/sa1"
	testMetricAlertAGID     = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Insights/actionGroups/ag-1"
)

func newTestMetricAlert(api monitorMetricAlertsAPI) *MonitorMetricAlert {
	return &MonitorMetricAlert{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func metricAlertDesired(severity int) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":              "ma-1",
		"resourceGroupName": "rg-1",
		"location":          "Global",
		"scopes":            []any{testMetricAlertScopeID},
		"criteria": []any{map[string]any{
			"name":            "Metric1",
			"metricName":      "Transactions",
			"metricNamespace": "Microsoft.Storage/storageAccounts",
			"operator":        "GreaterThan",
			"threshold":       100,
			"timeAggregation": "Total",
		}},
		"severity":            severity,
		"windowSize":          "PT5M",
		"evaluationFrequency": "PT1M",
		"actionGroupIds":      []any{testMetricAlertAGID},
		"description":         "too many transactions",
		"enabled":             true,
		"autoMitigate":        true,
	})
	return out
}

func TestMonitorMetricAlert_CRUD(t *testing.T) {
	var sent armmonitor.MetricAlertResource
	echo := func(params armmonitor.MetricAlertResource) armmonitor.MetricAlertResource {
		params.ID = to.Ptr(testMetricAlertNativeID)
		params.Name = to.Ptr("ma-1")
		return params
	}

	createCalls := 0
	deleteCalls := 0
	fake := &fakeMetricAlertsAPI{
		createOrUpdateFn: func(_ context.Context, _, name string, params armmonitor.MetricAlertResource, _ *armmonitor.MetricAlertsClientCreateOrUpdateOptions) (armmonitor.MetricAlertsClientCreateOrUpdateResponse, error) {
			require.Equal(t, "ma-1", name)
			sent = params
			createCalls++
			return armmonitor.MetricAlertsClientCreateOrUpdateResponse{MetricAlertResource: echo(params)}, nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armmonitor.MetricAlertsClientGetOptions) (armmonitor.MetricAlertsClientGetResponse, error) {
			return armmonitor.MetricAlertsClientGetResponse{MetricAlertResource: echo(sent)}, nil
		},
		deleteFn: func(_ context.Context, _, _ string, _ *armmonitor.MetricAlertsClientDeleteOptions) (armmonitor.MetricAlertsClientDeleteResponse, error) {
			deleteCalls++
			return armmonitor.MetricAlertsClientDeleteResponse{}, nil
		},
		newListByResourceGroupPagerFn: func(_ string, _ *armmonitor.MetricAlertsClientListByResourceGroupOptions) *runtime.Pager[armmonitor.MetricAlertsClientListByResourceGroupResponse] {
			return runtime.NewPager(runtime.PagingHandler[armmonitor.MetricAlertsClientListByResourceGroupResponse]{
				More: func(_ armmonitor.MetricAlertsClientListByResourceGroupResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armmonitor.MetricAlertsClientListByResourceGroupResponse) (armmonitor.MetricAlertsClientListByResourceGroupResponse, error) {
					return armmonitor.MetricAlertsClientListByResourceGroupResponse{
						MetricAlertResourceCollection: armmonitor.MetricAlertResourceCollection{
							Value: []*armmonitor.MetricAlertResource{{ID: to.Ptr(testMetricAlertNativeID)}},
						},
					}, nil
				},
			})
		},
		newListBySubscriptionPagerFn: func(_ *armmonitor.MetricAlertsClientListBySubscriptionOptions) *runtime.Pager[armmonitor.MetricAlertsClientListBySubscriptionResponse] {
			return runtime.NewPager(runtime.PagingHandler[armmonitor.MetricAlertsClientListBySubscriptionResponse]{
				More: func(_ armmonitor.MetricAlertsClientListBySubscriptionResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armmonitor.MetricAlertsClientListBySubscriptionResponse) (armmonitor.MetricAlertsClientListBySubscriptionResponse, error) {
					return armmonitor.MetricAlertsClientListBySubscriptionResponse{
						MetricAlertResourceCollection: armmonitor.MetricAlertResourceCollection{
							Value: []*armmonitor.MetricAlertResource{
								{ID: to.Ptr(testMetricAlertNativeID)},
								{ID: to.Ptr("/subscriptions/sub-1/resourceGroups/rg-2/providers/Microsoft.Insights/metricAlerts/ma-2")},
							},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestMetricAlert(fake)

	t.Run("Create_is_synchronous", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "ma-1", Properties: metricAlertDesired(3),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testMetricAlertNativeID, got.ProgressResult.NativeID)
		require.Empty(t, got.ProgressResult.RequestID)

		require.EqualValues(t, 3, *sent.Properties.Severity)
		require.Equal(t, "PT5M", *sent.Properties.WindowSize)
		require.Len(t, sent.Properties.Scopes, 1)
		require.Len(t, sent.Properties.Actions, 1)

		// The criteria must go out as the single-resource static-threshold union
		// member, with the discriminator ARM requires on every criterion.
		single, ok := sent.Properties.Criteria.(*armmonitor.MetricAlertSingleResourceMultipleMetricCriteria)
		require.True(t, ok)
		require.Equal(t, armmonitor.OdatatypeMicrosoftAzureMonitorSingleResourceMultipleMetricCriteria, *single.ODataType)
		require.Len(t, single.AllOf, 1)
		require.Equal(t, armmonitor.CriterionTypeStaticThresholdCriterion, *single.AllOf[0].CriterionType)
		require.Equal(t, "Transactions", *single.AllOf[0].MetricName)
		require.Equal(t, "Microsoft.Storage/storageAccounts", *single.AllOf[0].MetricNamespace)
		require.EqualValues(t, 100, *single.AllOf[0].Threshold)
	})

	t.Run("Create_requires_criteria", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "ma-1", "resourceGroupName": "rg-1", "location": "Global",
			"scopes": []any{testMetricAlertScopeID}, "severity": 3,
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "criteria is required")
	})

	t.Run("Create_requires_severity", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "ma-1", "resourceGroupName": "rg-1", "location": "Global",
			"scopes": []any{testMetricAlertScopeID},
			"criteria": []any{map[string]any{
				"name": "Metric1", "metricName": "Transactions",
				"metricNamespace": "Microsoft.Storage/storageAccounts",
				"operator":        "GreaterThan", "threshold": 100, "timeAggregation": "Total",
			}},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "severity is required")
	})

	t.Run("Create_requires_scopes", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "ma-1", "resourceGroupName": "rg-1", "location": "Global", "severity": 3,
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "scopes is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testMetricAlertNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "ma-1", props["name"])
		require.Equal(t, "Global", props["location"])
		require.EqualValues(t, 3, props["severity"])
		require.Equal(t, "PT5M", props["windowSize"])
		require.Equal(t, []any{testMetricAlertScopeID}, props["scopes"])
		require.Equal(t, []any{testMetricAlertAGID}, props["actionGroupIds"])

		criteria := props["criteria"].([]any)
		require.Len(t, criteria, 1)
		first := criteria[0].(map[string]any)
		require.Equal(t, "Transactions", first["metricName"])
		require.Equal(t, "GreaterThan", first["operator"])
		require.EqualValues(t, 100, first["threshold"])
		// criterionType is ARM's discriminator, not desired state.
		require.NotContains(t, first, "criterionType")
	})

	t.Run("Update_reissues_create_or_update", func(t *testing.T) {
		before := createCalls
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testMetricAlertNativeID,
			DesiredProperties: metricAlertDesired(1),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Empty(t, got.ProgressResult.RequestID)
		require.Equal(t, before+1, createCalls)
		require.EqualValues(t, 1, *sent.Properties.Severity)
	})

	t.Run("Delete_is_synchronous", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testMetricAlertNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _ string, _ *armmonitor.MetricAlertsClientDeleteOptions) (armmonitor.MetricAlertsClientDeleteResponse, error) {
			return armmonitor.MetricAlertsClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testMetricAlertNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_resource_group", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testMetricAlertNativeID}, got.NativeIDs)
	})

	t.Run("List_without_group_is_subscription_wide", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 2)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.createOrUpdateFn = func(_ context.Context, _, _ string, _ armmonitor.MetricAlertResource, _ *armmonitor.MetricAlertsClientCreateOrUpdateOptions) (armmonitor.MetricAlertsClientCreateOrUpdateResponse, error) {
			return armmonitor.MetricAlertsClientCreateOrUpdateResponse{}, &azcore.ResponseError{StatusCode: 409}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "ma-1", Properties: metricAlertDesired(3),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

// ARM's criteria field is a polymorphic union. A dynamic-threshold alert, or a
// static one carrying dimensions, is not expressible in this schema — read must
// omit the criteria entirely rather than surface something that would read as
// drift on every sync.
func TestMonitorMetricAlert_ReadSkipsUnmodelledCriteria(t *testing.T) {
	t.Run("dynamic_threshold_criteria", func(t *testing.T) {
		fake := &fakeMetricAlertsAPI{
			getFn: func(_ context.Context, _, _ string, _ *armmonitor.MetricAlertsClientGetOptions) (armmonitor.MetricAlertsClientGetResponse, error) {
				return armmonitor.MetricAlertsClientGetResponse{MetricAlertResource: armmonitor.MetricAlertResource{
					ID:       to.Ptr(testMetricAlertNativeID),
					Name:     to.Ptr("ma-1"),
					Location: to.Ptr("global"),
					Properties: &armmonitor.MetricAlertProperties{
						Severity: to.Ptr(int32(3)),
						Criteria: &armmonitor.MetricAlertMultipleResourceMultipleMetricCriteria{
							ODataType: to.Ptr(armmonitor.OdatatypeMicrosoftAzureMonitorMultipleResourceMultipleMetricCriteria),
						},
					},
				}}, nil
			},
		}
		got, err := newTestMetricAlert(fake).Read(context.Background(), &resource.ReadRequest{NativeID: testMetricAlertNativeID})
		require.NoError(t, err)
		require.NotContains(t, got.Properties, "criteria")
		// The rest of the alert still reads, and "global" is normalised.
		require.Contains(t, got.Properties, `"location":"Global"`)
	})

	t.Run("static_criteria_with_dimensions", func(t *testing.T) {
		fake := &fakeMetricAlertsAPI{
			getFn: func(_ context.Context, _, _ string, _ *armmonitor.MetricAlertsClientGetOptions) (armmonitor.MetricAlertsClientGetResponse, error) {
				return armmonitor.MetricAlertsClientGetResponse{MetricAlertResource: armmonitor.MetricAlertResource{
					ID:   to.Ptr(testMetricAlertNativeID),
					Name: to.Ptr("ma-1"),
					Properties: &armmonitor.MetricAlertProperties{
						Criteria: &armmonitor.MetricAlertSingleResourceMultipleMetricCriteria{
							AllOf: []*armmonitor.MetricCriteria{{
								Name:       to.Ptr("Metric1"),
								MetricName: to.Ptr("Transactions"),
								Dimensions: []*armmonitor.MetricDimension{{
									Name: to.Ptr("ApiName"), Operator: to.Ptr("Include"),
									Values: []*string{to.Ptr("PutBlob")},
								}},
							}},
						},
					},
				}}, nil
			},
		}
		got, err := newTestMetricAlert(fake).Read(context.Background(), &resource.ReadRequest{NativeID: testMetricAlertNativeID})
		require.NoError(t, err)
		require.NotContains(t, got.Properties, "criteria")
		require.NotContains(t, got.Properties, "ApiName")
	})
}

func TestMonitorMetricAlert_ReadNotFound(t *testing.T) {
	fake := &fakeMetricAlertsAPI{
		getFn: func(_ context.Context, _, _ string, _ *armmonitor.MetricAlertsClientGetOptions) (armmonitor.MetricAlertsClientGetResponse, error) {
			return armmonitor.MetricAlertsClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestMetricAlert(fake).Read(context.Background(), &resource.ReadRequest{NativeID: testMetricAlertNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeMetricAlertsAPI struct {
	createOrUpdateFn              func(ctx context.Context, rgName, name string, params armmonitor.MetricAlertResource, options *armmonitor.MetricAlertsClientCreateOrUpdateOptions) (armmonitor.MetricAlertsClientCreateOrUpdateResponse, error)
	getFn                         func(ctx context.Context, rgName, name string, options *armmonitor.MetricAlertsClientGetOptions) (armmonitor.MetricAlertsClientGetResponse, error)
	deleteFn                      func(ctx context.Context, rgName, name string, options *armmonitor.MetricAlertsClientDeleteOptions) (armmonitor.MetricAlertsClientDeleteResponse, error)
	newListByResourceGroupPagerFn func(rgName string, options *armmonitor.MetricAlertsClientListByResourceGroupOptions) *runtime.Pager[armmonitor.MetricAlertsClientListByResourceGroupResponse]
	newListBySubscriptionPagerFn  func(options *armmonitor.MetricAlertsClientListBySubscriptionOptions) *runtime.Pager[armmonitor.MetricAlertsClientListBySubscriptionResponse]
}

func (f *fakeMetricAlertsAPI) CreateOrUpdate(ctx context.Context, rgName, name string, params armmonitor.MetricAlertResource, options *armmonitor.MetricAlertsClientCreateOrUpdateOptions) (armmonitor.MetricAlertsClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, name, params, options)
}

func (f *fakeMetricAlertsAPI) Get(ctx context.Context, rgName, name string, options *armmonitor.MetricAlertsClientGetOptions) (armmonitor.MetricAlertsClientGetResponse, error) {
	return f.getFn(ctx, rgName, name, options)
}

func (f *fakeMetricAlertsAPI) Delete(ctx context.Context, rgName, name string, options *armmonitor.MetricAlertsClientDeleteOptions) (armmonitor.MetricAlertsClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, name, options)
}

func (f *fakeMetricAlertsAPI) NewListByResourceGroupPager(rgName string, options *armmonitor.MetricAlertsClientListByResourceGroupOptions) *runtime.Pager[armmonitor.MetricAlertsClientListByResourceGroupResponse] {
	return f.newListByResourceGroupPagerFn(rgName, options)
}

func (f *fakeMetricAlertsAPI) NewListBySubscriptionPager(options *armmonitor.MetricAlertsClientListBySubscriptionOptions) *runtime.Pager[armmonitor.MetricAlertsClientListBySubscriptionResponse] {
	return f.newListBySubscriptionPagerFn(options)
}
