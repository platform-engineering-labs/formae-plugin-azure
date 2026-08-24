// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/monitor/armmonitor"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const (
	testSQRNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Insights/scheduledQueryRules/sqr-1"
	testSQRScopeID  = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.OperationalInsights/workspaces/law1"
	testSQRAGID     = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Insights/actionGroups/ag-1"
	testSQRQuery    = "Heartbeat | summarize count()"
)

func newTestSQR(api monitorScheduledQueryRulesAPI) *MonitorScheduledQueryRule {
	return &MonitorScheduledQueryRule{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func sqrDesired(severity int) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":              "sqr-1",
		"resourceGroupName": "rg-1",
		"location":          "eastus",
		"scopes":            []any{testSQRScopeID},
		"criteria": []any{map[string]any{
			"query":           testSQRQuery,
			"timeAggregation": "Count",
			"operator":        "GreaterThan",
			"threshold":       10,
			"failingPeriods": map[string]any{
				"minFailingPeriodsToAlert":  1,
				"numberOfEvaluationPeriods": 1,
			},
		}},
		"severity":            severity,
		"windowSize":          "PT5M",
		"evaluationFrequency": "PT5M",
		"actionGroupIds":      []any{testSQRAGID},
		"description":         "heartbeats above threshold",
		"displayName":         "heartbeat check",
		"enabled":             true,
		"autoMitigate":        true,
		"skipQueryValidation": false,
	})
	return out
}

func TestMonitorScheduledQueryRule_CRUD(t *testing.T) {
	var sent armmonitor.ScheduledQueryRuleResource
	echo := func(params armmonitor.ScheduledQueryRuleResource) armmonitor.ScheduledQueryRuleResource {
		params.ID = to.Ptr(testSQRNativeID)
		params.Name = to.Ptr("sqr-1")
		return params
	}

	createCalls := 0
	deleteCalls := 0
	fake := &fakeSQRAPI{
		createOrUpdateFn: func(_ context.Context, _, name string, params armmonitor.ScheduledQueryRuleResource, _ *armmonitor.ScheduledQueryRulesClientCreateOrUpdateOptions) (armmonitor.ScheduledQueryRulesClientCreateOrUpdateResponse, error) {
			require.Equal(t, "sqr-1", name)
			sent = params
			createCalls++
			return armmonitor.ScheduledQueryRulesClientCreateOrUpdateResponse{ScheduledQueryRuleResource: echo(params)}, nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armmonitor.ScheduledQueryRulesClientGetOptions) (armmonitor.ScheduledQueryRulesClientGetResponse, error) {
			return armmonitor.ScheduledQueryRulesClientGetResponse{ScheduledQueryRuleResource: echo(sent)}, nil
		},
		deleteFn: func(_ context.Context, _, _ string, _ *armmonitor.ScheduledQueryRulesClientDeleteOptions) (armmonitor.ScheduledQueryRulesClientDeleteResponse, error) {
			deleteCalls++
			return armmonitor.ScheduledQueryRulesClientDeleteResponse{}, nil
		},
		newListByResourceGroupPagerFn: func(_ string, _ *armmonitor.ScheduledQueryRulesClientListByResourceGroupOptions) *runtime.Pager[armmonitor.ScheduledQueryRulesClientListByResourceGroupResponse] {
			return runtime.NewPager(runtime.PagingHandler[armmonitor.ScheduledQueryRulesClientListByResourceGroupResponse]{
				More: func(_ armmonitor.ScheduledQueryRulesClientListByResourceGroupResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armmonitor.ScheduledQueryRulesClientListByResourceGroupResponse) (armmonitor.ScheduledQueryRulesClientListByResourceGroupResponse, error) {
					return armmonitor.ScheduledQueryRulesClientListByResourceGroupResponse{
						ScheduledQueryRuleResourceCollection: armmonitor.ScheduledQueryRuleResourceCollection{
							Value: []*armmonitor.ScheduledQueryRuleResource{{ID: to.Ptr(testSQRNativeID)}},
						},
					}, nil
				},
			})
		},
		newListBySubscriptionPagerFn: func(_ *armmonitor.ScheduledQueryRulesClientListBySubscriptionOptions) *runtime.Pager[armmonitor.ScheduledQueryRulesClientListBySubscriptionResponse] {
			return runtime.NewPager(runtime.PagingHandler[armmonitor.ScheduledQueryRulesClientListBySubscriptionResponse]{
				More: func(_ armmonitor.ScheduledQueryRulesClientListBySubscriptionResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armmonitor.ScheduledQueryRulesClientListBySubscriptionResponse) (armmonitor.ScheduledQueryRulesClientListBySubscriptionResponse, error) {
					return armmonitor.ScheduledQueryRulesClientListBySubscriptionResponse{
						ScheduledQueryRuleResourceCollection: armmonitor.ScheduledQueryRuleResourceCollection{
							Value: []*armmonitor.ScheduledQueryRuleResource{
								{ID: to.Ptr(testSQRNativeID)},
								{ID: to.Ptr("/subscriptions/sub-1/resourceGroups/rg-2/providers/Microsoft.Insights/scheduledQueryRules/sqr-2")},
							},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestSQR(fake)

	t.Run("Create_is_synchronous", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "sqr-1", Properties: sqrDesired(3),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testSQRNativeID, got.ProgressResult.NativeID)
		require.Empty(t, got.ProgressResult.RequestID)

		// Log alerts are regional, unlike metric alerts.
		require.Equal(t, "eastus", *sent.Location)
		require.EqualValues(t, armmonitor.AlertSeverity(3), *sent.Properties.Severity)
		require.Equal(t, "PT5M", *sent.Properties.WindowSize)
		require.Equal(t, "PT5M", *sent.Properties.EvaluationFrequency)
		require.Equal(t, "heartbeat check", *sent.Properties.DisplayName)

		require.Len(t, sent.Properties.Criteria.AllOf, 1)
		cond := sent.Properties.Criteria.AllOf[0]
		require.Equal(t, testSQRQuery, *cond.Query)
		require.Equal(t, armmonitor.TimeAggregationCount, *cond.TimeAggregation)
		require.Equal(t, armmonitor.ConditionOperatorGreaterThan, *cond.Operator)
		require.EqualValues(t, 10, *cond.Threshold)
		require.EqualValues(t, 1, *cond.FailingPeriods.MinFailingPeriodsToAlert)
		require.EqualValues(t, 1, *cond.FailingPeriods.NumberOfEvaluationPeriods)

		// This API carries action groups as bare ID strings, not objects.
		require.Len(t, sent.Properties.Actions.ActionGroups, 1)
		require.Equal(t, testSQRAGID, *sent.Properties.Actions.ActionGroups[0])
	})

	t.Run("Create_requires_criteria", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "sqr-1", "resourceGroupName": "rg-1", "location": "eastus",
			"scopes": []any{testSQRScopeID}, "severity": 3,
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "criteria is required")
	})

	t.Run("Create_requires_window_and_frequency", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "sqr-1", "resourceGroupName": "rg-1", "location": "eastus",
			"scopes": []any{testSQRScopeID}, "severity": 3,
			"criteria": []any{map[string]any{
				"query": testSQRQuery, "timeAggregation": "Count",
				"operator": "GreaterThan", "threshold": 10,
			}},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "windowSize and evaluationFrequency are required")
	})

	t.Run("Create_requires_severity", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "sqr-1", "resourceGroupName": "rg-1", "location": "eastus",
			"scopes": []any{testSQRScopeID},
			"criteria": []any{map[string]any{
				"query": testSQRQuery, "timeAggregation": "Count",
				"operator": "GreaterThan", "threshold": 10,
			}},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "severity is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testSQRNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "sqr-1", props["name"])
		require.Equal(t, "eastus", props["location"])
		require.EqualValues(t, 3, props["severity"])
		require.Equal(t, []any{testSQRScopeID}, props["scopes"])
		require.Equal(t, []any{testSQRAGID}, props["actionGroupIds"])
		require.Equal(t, "heartbeat check", props["displayName"])

		criteria := props["criteria"].([]any)
		require.Len(t, criteria, 1)
		first := criteria[0].(map[string]any)
		require.Equal(t, testSQRQuery, first["query"])
		require.Equal(t, "Count", first["timeAggregation"])
		require.EqualValues(t, 10, first["threshold"])
		fp := first["failingPeriods"].(map[string]any)
		require.EqualValues(t, 1, fp["numberOfEvaluationPeriods"])
	})

	t.Run("Update_reissues_create_or_update", func(t *testing.T) {
		before := createCalls
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testSQRNativeID,
			DesiredProperties: sqrDesired(1),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Empty(t, got.ProgressResult.RequestID)
		require.Equal(t, before+1, createCalls)
		require.EqualValues(t, armmonitor.AlertSeverity(1), *sent.Properties.Severity)
	})

	t.Run("Delete_is_synchronous", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testSQRNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _ string, _ *armmonitor.ScheduledQueryRulesClientDeleteOptions) (armmonitor.ScheduledQueryRulesClientDeleteResponse, error) {
			return armmonitor.ScheduledQueryRulesClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testSQRNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_resource_group", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testSQRNativeID}, got.NativeIDs)
	})

	t.Run("List_without_group_is_subscription_wide", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 2)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.createOrUpdateFn = func(_ context.Context, _, _ string, _ armmonitor.ScheduledQueryRuleResource, _ *armmonitor.ScheduledQueryRulesClientCreateOrUpdateOptions) (armmonitor.ScheduledQueryRulesClientCreateOrUpdateResponse, error) {
			return armmonitor.ScheduledQueryRulesClientCreateOrUpdateResponse{}, &azcore.ResponseError{StatusCode: 409}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "sqr-1", Properties: sqrDesired(3),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

// Dynamic-threshold conditions and dimension splitting are not modelled. Read must
// omit such a condition rather than surface a half-read version of it, which would
// show as drift on every sync.
func TestMonitorScheduledQueryRule_ReadSkipsUnmodelledConditions(t *testing.T) {
	t.Run("dynamic_threshold", func(t *testing.T) {
		fake := &fakeSQRAPI{
			getFn: func(_ context.Context, _, _ string, _ *armmonitor.ScheduledQueryRulesClientGetOptions) (armmonitor.ScheduledQueryRulesClientGetResponse, error) {
				return armmonitor.ScheduledQueryRulesClientGetResponse{ScheduledQueryRuleResource: armmonitor.ScheduledQueryRuleResource{
					ID:       to.Ptr(testSQRNativeID),
					Name:     to.Ptr("sqr-1"),
					Location: to.Ptr("East US"),
					Properties: &armmonitor.ScheduledQueryRuleProperties{
						Criteria: &armmonitor.ScheduledQueryRuleCriteria{
							AllOf: []*armmonitor.Condition{{
								Query:            to.Ptr(testSQRQuery),
								AlertSensitivity: to.Ptr("Medium"),
								IgnoreDataBefore: to.Ptr(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)),
							}},
						},
					},
				}}, nil
			},
		}
		got, err := newTestSQR(fake).Read(context.Background(), &resource.ReadRequest{NativeID: testSQRNativeID})
		require.NoError(t, err)
		require.NotContains(t, got.Properties, "criteria")
		require.NotContains(t, got.Properties, "alertSensitivity")
		// The rest still reads, and ARM's "East US" is normalised.
		require.Contains(t, got.Properties, `"location":"eastus"`)
	})

	t.Run("dimension_splitting", func(t *testing.T) {
		fake := &fakeSQRAPI{
			getFn: func(_ context.Context, _, _ string, _ *armmonitor.ScheduledQueryRulesClientGetOptions) (armmonitor.ScheduledQueryRulesClientGetResponse, error) {
				return armmonitor.ScheduledQueryRulesClientGetResponse{ScheduledQueryRuleResource: armmonitor.ScheduledQueryRuleResource{
					ID:   to.Ptr(testSQRNativeID),
					Name: to.Ptr("sqr-1"),
					Properties: &armmonitor.ScheduledQueryRuleProperties{
						Criteria: &armmonitor.ScheduledQueryRuleCriteria{
							AllOf: []*armmonitor.Condition{{
								Query: to.Ptr(testSQRQuery),
								Dimensions: []*armmonitor.Dimension{{
									Name: to.Ptr("Computer"), Operator: to.Ptr(armmonitor.DimensionOperatorInclude),
									Values: []*string{to.Ptr("web1")},
								}},
							}},
						},
					},
				}}, nil
			},
		}
		got, err := newTestSQR(fake).Read(context.Background(), &resource.ReadRequest{NativeID: testSQRNativeID})
		require.NoError(t, err)
		require.NotContains(t, got.Properties, "criteria")
		require.NotContains(t, got.Properties, "Computer")
	})
}

func TestMonitorScheduledQueryRule_ReadNotFound(t *testing.T) {
	fake := &fakeSQRAPI{
		getFn: func(_ context.Context, _, _ string, _ *armmonitor.ScheduledQueryRulesClientGetOptions) (armmonitor.ScheduledQueryRulesClientGetResponse, error) {
			return armmonitor.ScheduledQueryRulesClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestSQR(fake).Read(context.Background(), &resource.ReadRequest{NativeID: testSQRNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeSQRAPI struct {
	createOrUpdateFn              func(ctx context.Context, rgName, name string, params armmonitor.ScheduledQueryRuleResource, options *armmonitor.ScheduledQueryRulesClientCreateOrUpdateOptions) (armmonitor.ScheduledQueryRulesClientCreateOrUpdateResponse, error)
	getFn                         func(ctx context.Context, rgName, name string, options *armmonitor.ScheduledQueryRulesClientGetOptions) (armmonitor.ScheduledQueryRulesClientGetResponse, error)
	deleteFn                      func(ctx context.Context, rgName, name string, options *armmonitor.ScheduledQueryRulesClientDeleteOptions) (armmonitor.ScheduledQueryRulesClientDeleteResponse, error)
	newListByResourceGroupPagerFn func(rgName string, options *armmonitor.ScheduledQueryRulesClientListByResourceGroupOptions) *runtime.Pager[armmonitor.ScheduledQueryRulesClientListByResourceGroupResponse]
	newListBySubscriptionPagerFn  func(options *armmonitor.ScheduledQueryRulesClientListBySubscriptionOptions) *runtime.Pager[armmonitor.ScheduledQueryRulesClientListBySubscriptionResponse]
}

func (f *fakeSQRAPI) CreateOrUpdate(ctx context.Context, rgName, name string, params armmonitor.ScheduledQueryRuleResource, options *armmonitor.ScheduledQueryRulesClientCreateOrUpdateOptions) (armmonitor.ScheduledQueryRulesClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, name, params, options)
}

func (f *fakeSQRAPI) Get(ctx context.Context, rgName, name string, options *armmonitor.ScheduledQueryRulesClientGetOptions) (armmonitor.ScheduledQueryRulesClientGetResponse, error) {
	return f.getFn(ctx, rgName, name, options)
}

func (f *fakeSQRAPI) Delete(ctx context.Context, rgName, name string, options *armmonitor.ScheduledQueryRulesClientDeleteOptions) (armmonitor.ScheduledQueryRulesClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, name, options)
}

func (f *fakeSQRAPI) NewListByResourceGroupPager(rgName string, options *armmonitor.ScheduledQueryRulesClientListByResourceGroupOptions) *runtime.Pager[armmonitor.ScheduledQueryRulesClientListByResourceGroupResponse] {
	return f.newListByResourceGroupPagerFn(rgName, options)
}

func (f *fakeSQRAPI) NewListBySubscriptionPager(options *armmonitor.ScheduledQueryRulesClientListBySubscriptionOptions) *runtime.Pager[armmonitor.ScheduledQueryRulesClientListBySubscriptionResponse] {
	return f.newListBySubscriptionPagerFn(options)
}
