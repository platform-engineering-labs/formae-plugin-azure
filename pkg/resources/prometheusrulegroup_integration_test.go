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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/alertsmanagement/armalertsmanagement"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testPrometheusRuleGroupNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.AlertsManagement/prometheusRuleGroups/prg1"

const testPrometheusScopeWorkspaceID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Monitor/accounts/amw1"

type fakePrometheusRuleGroupsAPI struct {
	createFn      func(ctx context.Context, rgName, name string, body armalertsmanagement.PrometheusRuleGroupResource, options *armalertsmanagement.PrometheusRuleGroupsClientCreateOrUpdateOptions) (armalertsmanagement.PrometheusRuleGroupsClientCreateOrUpdateResponse, error)
	getFn         func(ctx context.Context, rgName, name string, options *armalertsmanagement.PrometheusRuleGroupsClientGetOptions) (armalertsmanagement.PrometheusRuleGroupsClientGetResponse, error)
	deleteFn      func(ctx context.Context, rgName, name string, options *armalertsmanagement.PrometheusRuleGroupsClientDeleteOptions) (armalertsmanagement.PrometheusRuleGroupsClientDeleteResponse, error)
	listByGroupFn func(rgName string, options *armalertsmanagement.PrometheusRuleGroupsClientListByResourceGroupOptions) *runtime.Pager[armalertsmanagement.PrometheusRuleGroupsClientListByResourceGroupResponse]
	listBySubFn   func(options *armalertsmanagement.PrometheusRuleGroupsClientListBySubscriptionOptions) *runtime.Pager[armalertsmanagement.PrometheusRuleGroupsClientListBySubscriptionResponse]
}

func (f *fakePrometheusRuleGroupsAPI) CreateOrUpdate(ctx context.Context, rgName, name string, body armalertsmanagement.PrometheusRuleGroupResource, options *armalertsmanagement.PrometheusRuleGroupsClientCreateOrUpdateOptions) (armalertsmanagement.PrometheusRuleGroupsClientCreateOrUpdateResponse, error) {
	return f.createFn(ctx, rgName, name, body, options)
}

func (f *fakePrometheusRuleGroupsAPI) Get(ctx context.Context, rgName, name string, options *armalertsmanagement.PrometheusRuleGroupsClientGetOptions) (armalertsmanagement.PrometheusRuleGroupsClientGetResponse, error) {
	return f.getFn(ctx, rgName, name, options)
}

func (f *fakePrometheusRuleGroupsAPI) Delete(ctx context.Context, rgName, name string, options *armalertsmanagement.PrometheusRuleGroupsClientDeleteOptions) (armalertsmanagement.PrometheusRuleGroupsClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, name, options)
}

func (f *fakePrometheusRuleGroupsAPI) NewListByResourceGroupPager(rgName string, options *armalertsmanagement.PrometheusRuleGroupsClientListByResourceGroupOptions) *runtime.Pager[armalertsmanagement.PrometheusRuleGroupsClientListByResourceGroupResponse] {
	return f.listByGroupFn(rgName, options)
}

func (f *fakePrometheusRuleGroupsAPI) NewListBySubscriptionPager(options *armalertsmanagement.PrometheusRuleGroupsClientListBySubscriptionOptions) *runtime.Pager[armalertsmanagement.PrometheusRuleGroupsClientListBySubscriptionResponse] {
	return f.listBySubFn(options)
}

func newTestPrometheusRuleGroup(api prometheusRuleGroupsAPI) *PrometheusRuleGroup {
	return &PrometheusRuleGroup{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func prometheusRuleGroupDesired(interval string) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":              "prg1",
		"resourceGroupName": "rg-1",
		"location":          "eastus",
		"scopes":            []string{testPrometheusScopeWorkspaceID},
		"description":       "conformance test rule group",
		"enabled":           true,
		"interval":          interval,
		"rules": []any{
			map[string]any{
				"record":     "job:node_cpu_seconds:avg_rate5m",
				"expression": "avg by (job) (rate(node_cpu_seconds_total[5m]))",
				"enabled":    true,
				"labels":     map[string]string{"team": "platform"},
			},
			map[string]any{
				"alert":       "ConformanceTestNeverFires",
				"expression":  "vector(0) > 1",
				"enabled":     true,
				"for":         "PT5M",
				"severity":    4,
				"annotations": map[string]string{"summary": "never fires"},
			},
		},
		"Tags": []any{map[string]any{"Key": "env", "Value": "test"}},
	})
	return out
}

func TestPrometheusRuleGroup_CRUD(t *testing.T) {
	groupResult := armalertsmanagement.PrometheusRuleGroupResource{
		ID:       to.Ptr(testPrometheusRuleGroupNativeID),
		Name:     to.Ptr("prg1"),
		Location: to.Ptr("East US"),
		Properties: &armalertsmanagement.PrometheusRuleGroupProperties{
			Scopes:      []*string{to.Ptr(testPrometheusScopeWorkspaceID)},
			Description: to.Ptr("conformance test rule group"),
			Enabled:     to.Ptr(true),
			Interval:    to.Ptr("PT1M"),
			Rules: []*armalertsmanagement.PrometheusRule{
				{
					Record:     to.Ptr("job:node_cpu_seconds:avg_rate5m"),
					Expression: to.Ptr("avg by (job) (rate(node_cpu_seconds_total[5m]))"),
					Enabled:    to.Ptr(true),
					Labels:     map[string]*string{"team": to.Ptr("platform")},
				},
				{
					Alert:       to.Ptr("ConformanceTestNeverFires"),
					Expression:  to.Ptr("vector(0) > 1"),
					Enabled:     to.Ptr(true),
					For:         to.Ptr("PT5M"),
					Severity:    to.Ptr(int32(4)),
					Annotations: map[string]*string{"summary": to.Ptr("never fires")},
					// Service-filled members of a nested class. hasProviderDefault is a
					// no-op inside rules[], so these must not be read back.
					ResolveConfiguration: &armalertsmanagement.PrometheusRuleResolveConfiguration{
						AutoResolved:  to.Ptr(true),
						TimeToResolve: to.Ptr("PT5M"),
					},
					Actions: []*armalertsmanagement.PrometheusRuleGroupAction{},
				},
			},
		},
		Tags: map[string]*string{"env": to.Ptr("test")},
	}

	var sent armalertsmanagement.PrometheusRuleGroupResource
	writeCalls := 0
	deleteCalls := 0
	fake := &fakePrometheusRuleGroupsAPI{
		createFn: func(_ context.Context, rgName, name string, body armalertsmanagement.PrometheusRuleGroupResource, _ *armalertsmanagement.PrometheusRuleGroupsClientCreateOrUpdateOptions) (armalertsmanagement.PrometheusRuleGroupsClientCreateOrUpdateResponse, error) {
			require.Equal(t, "rg-1", rgName)
			require.Equal(t, "prg1", name)
			sent = body
			writeCalls++
			return armalertsmanagement.PrometheusRuleGroupsClientCreateOrUpdateResponse{PrometheusRuleGroupResource: groupResult}, nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armalertsmanagement.PrometheusRuleGroupsClientGetOptions) (armalertsmanagement.PrometheusRuleGroupsClientGetResponse, error) {
			return armalertsmanagement.PrometheusRuleGroupsClientGetResponse{PrometheusRuleGroupResource: groupResult}, nil
		},
		deleteFn: func(_ context.Context, _, _ string, _ *armalertsmanagement.PrometheusRuleGroupsClientDeleteOptions) (armalertsmanagement.PrometheusRuleGroupsClientDeleteResponse, error) {
			deleteCalls++
			return armalertsmanagement.PrometheusRuleGroupsClientDeleteResponse{}, nil
		},
		listByGroupFn: func(_ string, _ *armalertsmanagement.PrometheusRuleGroupsClientListByResourceGroupOptions) *runtime.Pager[armalertsmanagement.PrometheusRuleGroupsClientListByResourceGroupResponse] {
			return runtime.NewPager(runtime.PagingHandler[armalertsmanagement.PrometheusRuleGroupsClientListByResourceGroupResponse]{
				More: func(_ armalertsmanagement.PrometheusRuleGroupsClientListByResourceGroupResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armalertsmanagement.PrometheusRuleGroupsClientListByResourceGroupResponse) (armalertsmanagement.PrometheusRuleGroupsClientListByResourceGroupResponse, error) {
					return armalertsmanagement.PrometheusRuleGroupsClientListByResourceGroupResponse{
						PrometheusRuleGroupResourceCollection: armalertsmanagement.PrometheusRuleGroupResourceCollection{
							Value: []*armalertsmanagement.PrometheusRuleGroupResource{
								{ID: to.Ptr(testPrometheusRuleGroupNativeID)},
								// A nil entry must not panic the walk.
								nil,
							},
						},
					}, nil
				},
			})
		},
		listBySubFn: func(_ *armalertsmanagement.PrometheusRuleGroupsClientListBySubscriptionOptions) *runtime.Pager[armalertsmanagement.PrometheusRuleGroupsClientListBySubscriptionResponse] {
			return runtime.NewPager(runtime.PagingHandler[armalertsmanagement.PrometheusRuleGroupsClientListBySubscriptionResponse]{
				More: func(_ armalertsmanagement.PrometheusRuleGroupsClientListBySubscriptionResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armalertsmanagement.PrometheusRuleGroupsClientListBySubscriptionResponse) (armalertsmanagement.PrometheusRuleGroupsClientListBySubscriptionResponse, error) {
					return armalertsmanagement.PrometheusRuleGroupsClientListBySubscriptionResponse{
						PrometheusRuleGroupResourceCollection: armalertsmanagement.PrometheusRuleGroupResourceCollection{
							Value: []*armalertsmanagement.PrometheusRuleGroupResource{
								{ID: to.Ptr(testPrometheusRuleGroupNativeID)},
								{ID: to.Ptr("/subscriptions/sub-1/resourceGroups/rg-2/providers/Microsoft.AlertsManagement/prometheusRuleGroups/prg2")},
							},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestPrometheusRuleGroup(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "prg1", Properties: prometheusRuleGroupDesired("PT1M"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testPrometheusRuleGroupNativeID, got.ProgressResult.NativeID)

		require.Equal(t, "eastus", *sent.Location)
		require.Equal(t, testPrometheusScopeWorkspaceID, *sent.Properties.Scopes[0])
		require.Equal(t, "PT1M", *sent.Properties.Interval)
		require.Len(t, sent.Properties.Rules, 2)

		recording := sent.Properties.Rules[0]
		require.Equal(t, "job:node_cpu_seconds:avg_rate5m", *recording.Record)
		require.Nil(t, recording.Alert)
		require.True(t, *recording.Enabled)
		require.Equal(t, "platform", *recording.Labels["team"])
		// A recording rule must not carry alerting-only members.
		require.Nil(t, recording.For)
		require.Nil(t, recording.Severity)
		require.Nil(t, recording.Annotations)

		alerting := sent.Properties.Rules[1]
		require.Equal(t, "ConformanceTestNeverFires", *alerting.Alert)
		require.Nil(t, alerting.Record)
		require.Equal(t, "PT5M", *alerting.For)
		require.Equal(t, int32(4), *alerting.Severity)
		require.Equal(t, "never fires", *alerting.Annotations["summary"])
		require.Equal(t, "test", *sent.Tags["env"])
	})

	t.Run("Create_requires_a_scope", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "prg1", "resourceGroupName": "rg-1", "location": "eastus",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "at least one scope is required")
	})

	t.Run("Create_requires_a_rule", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "prg1", "resourceGroupName": "rg-1", "location": "eastus",
			"scopes": []string{testPrometheusScopeWorkspaceID},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "at least one rule is required")
	})

	t.Run("Create_rejects_a_rule_that_is_neither_record_nor_alert", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "prg1", "resourceGroupName": "rg-1", "location": "eastus",
			"scopes": []string{testPrometheusScopeWorkspaceID},
			"rules":  []any{map[string]any{"expression": "vector(0)", "enabled": true}},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "either record or alert")
	})

	t.Run("Create_rejects_a_rule_that_is_both", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "prg1", "resourceGroupName": "rg-1", "location": "eastus",
			"scopes": []string{testPrometheusScopeWorkspaceID},
			"rules": []any{map[string]any{
				"record": "r", "alert": "a", "expression": "vector(0)", "enabled": true,
			}},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "cannot set both record and alert")
	})

	t.Run("Create_failure_carries_the_provider_error", func(t *testing.T) {
		fake.createFn = func(_ context.Context, _, _ string, _ armalertsmanagement.PrometheusRuleGroupResource, _ *armalertsmanagement.PrometheusRuleGroupsClientCreateOrUpdateOptions) (armalertsmanagement.PrometheusRuleGroupsClientCreateOrUpdateResponse, error) {
			return armalertsmanagement.PrometheusRuleGroupsClientCreateOrUpdateResponse{}, &azcore.ResponseError{
				StatusCode: 400, ErrorCode: "InvalidPromQL",
			}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "prg1", Properties: prometheusRuleGroupDesired("PT1M"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.Contains(t, got.ProgressResult.StatusMessage, "InvalidPromQL")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testPrometheusRuleGroupNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "prg1", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		// ARM returns "East US"; read must normalise or desired state drifts.
		require.Equal(t, "eastus", props["location"])
		require.Equal(t, []any{testPrometheusScopeWorkspaceID}, props["scopes"])
		require.Equal(t, "PT1M", props["interval"])
		require.Equal(t, true, props["enabled"])

		rules := props["rules"].([]any)
		require.Len(t, rules, 2)
		recording := rules[0].(map[string]any)
		require.Equal(t, "job:node_cpu_seconds:avg_rate5m", recording["record"])
		require.NotContains(t, recording, "alert")
		require.Equal(t, map[string]any{"team": "platform"}, recording["labels"])

		alerting := rules[1].(map[string]any)
		require.Equal(t, "ConformanceTestNeverFires", alerting["alert"])
		require.Equal(t, "PT5M", alerting["for"])
		require.Equal(t, float64(4), alerting["severity"])
		// Neither is modelled, so neither may be read back.
		require.NotContains(t, alerting, "resolveConfiguration")
		require.NotContains(t, alerting, "actions")
	})

	t.Run("Update_reissues_create", func(t *testing.T) {
		fake.createFn = func(_ context.Context, _, _ string, body armalertsmanagement.PrometheusRuleGroupResource, _ *armalertsmanagement.PrometheusRuleGroupsClientCreateOrUpdateOptions) (armalertsmanagement.PrometheusRuleGroupsClientCreateOrUpdateResponse, error) {
			sent = body
			writeCalls++
			return armalertsmanagement.PrometheusRuleGroupsClientCreateOrUpdateResponse{PrometheusRuleGroupResource: groupResult}, nil
		}
		before := writeCalls
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testPrometheusRuleGroupNativeID,
			DesiredProperties: prometheusRuleGroupDesired("PT5M"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, writeCalls)
		require.Equal(t, "PT5M", *sent.Properties.Interval)
		// Location must ride along: a PUT without it is rejected.
		require.Equal(t, "eastus", *sent.Location)
	})

	t.Run("Delete", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testPrometheusRuleGroupNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _ string, _ *armalertsmanagement.PrometheusRuleGroupsClientDeleteOptions) (armalertsmanagement.PrometheusRuleGroupsClientDeleteResponse, error) {
			return armalertsmanagement.PrometheusRuleGroupsClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testPrometheusRuleGroupNativeID})
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
		require.Equal(t, []string{testPrometheusRuleGroupNativeID}, got.NativeIDs)
	})

	t.Run("List_without_group_is_subscription_wide", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 2)
	})

	t.Run("Read_NotFound", func(t *testing.T) {
		fake.getFn = func(_ context.Context, _, _ string, _ *armalertsmanagement.PrometheusRuleGroupsClientGetOptions) (armalertsmanagement.PrometheusRuleGroupsClientGetResponse, error) {
			return armalertsmanagement.PrometheusRuleGroupsClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testPrometheusRuleGroupNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
	})
}
