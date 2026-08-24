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

const testActivityLogAlertNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Insights/activityLogAlerts/ala-1"

func newTestMonitorActivityLogAlert(api monitorActivityLogAlertsAPI) *MonitorActivityLogAlert {
	return &MonitorActivityLogAlert{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func activityLogAlertDesired(description string, actionGroupIDs ...string) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":              "ala-1",
		"resourceGroupName": "rg-1",
		"location":          "Global",
		"scopes":            []any{"/subscriptions/sub-1"},
		"conditions": []any{
			map[string]any{"field": "category", "equals": "Administrative"},
			map[string]any{"field": "operationName", "equals": "Microsoft.Compute/virtualMachines/delete"},
		},
		"actionGroupIds": actionGroupIDs,
		"description":    description,
		"enabled":        true,
	})
	return out
}

func TestMonitorActivityLogAlert_CRUD(t *testing.T) {
	var sent armmonitor.ActivityLogAlertResource
	echo := func(params armmonitor.ActivityLogAlertResource) armmonitor.ActivityLogAlertResource {
		params.ID = to.Ptr(testActivityLogAlertNativeID)
		params.Name = to.Ptr("ala-1")
		return params
	}

	fake := &fakeActivityLogAlertsAPI{
		createOrUpdateFn: func(_ context.Context, _, name string, params armmonitor.ActivityLogAlertResource, _ *armmonitor.ActivityLogAlertsClientCreateOrUpdateOptions) (armmonitor.ActivityLogAlertsClientCreateOrUpdateResponse, error) {
			require.Equal(t, "ala-1", name)
			sent = params
			return armmonitor.ActivityLogAlertsClientCreateOrUpdateResponse{ActivityLogAlertResource: echo(params)}, nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armmonitor.ActivityLogAlertsClientGetOptions) (armmonitor.ActivityLogAlertsClientGetResponse, error) {
			return armmonitor.ActivityLogAlertsClientGetResponse{ActivityLogAlertResource: echo(sent)}, nil
		},
		deleteFn: func(_ context.Context, _, _ string, _ *armmonitor.ActivityLogAlertsClientDeleteOptions) (armmonitor.ActivityLogAlertsClientDeleteResponse, error) {
			return armmonitor.ActivityLogAlertsClientDeleteResponse{}, nil
		},
		newListByResourceGroupPagerFn: func(_ string, _ *armmonitor.ActivityLogAlertsClientListByResourceGroupOptions) *runtime.Pager[armmonitor.ActivityLogAlertsClientListByResourceGroupResponse] {
			return runtime.NewPager(runtime.PagingHandler[armmonitor.ActivityLogAlertsClientListByResourceGroupResponse]{
				More: func(_ armmonitor.ActivityLogAlertsClientListByResourceGroupResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armmonitor.ActivityLogAlertsClientListByResourceGroupResponse) (armmonitor.ActivityLogAlertsClientListByResourceGroupResponse, error) {
					return armmonitor.ActivityLogAlertsClientListByResourceGroupResponse{
						AlertRuleList: armmonitor.AlertRuleList{
							Value: []*armmonitor.ActivityLogAlertResource{{ID: to.Ptr(testActivityLogAlertNativeID)}},
						},
					}, nil
				},
			})
		},
		newListBySubscriptionIDPagerFn: func(_ *armmonitor.ActivityLogAlertsClientListBySubscriptionIDOptions) *runtime.Pager[armmonitor.ActivityLogAlertsClientListBySubscriptionIDResponse] {
			return runtime.NewPager(runtime.PagingHandler[armmonitor.ActivityLogAlertsClientListBySubscriptionIDResponse]{
				More: func(_ armmonitor.ActivityLogAlertsClientListBySubscriptionIDResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armmonitor.ActivityLogAlertsClientListBySubscriptionIDResponse) (armmonitor.ActivityLogAlertsClientListBySubscriptionIDResponse, error) {
					return armmonitor.ActivityLogAlertsClientListBySubscriptionIDResponse{
						AlertRuleList: armmonitor.AlertRuleList{
							Value: []*armmonitor.ActivityLogAlertResource{
								{ID: to.Ptr(testActivityLogAlertNativeID)},
								{ID: to.Ptr("/subscriptions/sub-1/resourceGroups/rg-2/providers/Microsoft.Insights/activityLogAlerts/ala-2")},
							},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestMonitorActivityLogAlert(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "ala-1", Properties: activityLogAlertDesired("watch deletes", "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Insights/actionGroups/ag-1")})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testActivityLogAlertNativeID, got.ProgressResult.NativeID)

		require.Equal(t, "Global", *sent.Location)
		require.Len(t, sent.Properties.Scopes, 1)
		require.Equal(t, "/subscriptions/sub-1", *sent.Properties.Scopes[0])
		require.Len(t, sent.Properties.Condition.AllOf, 2)
		require.Equal(t, "category", *sent.Properties.Condition.AllOf[0].Field)
		require.Equal(t, "Administrative", *sent.Properties.Condition.AllOf[0].Equals)
		require.Equal(t, "watch deletes", *sent.Properties.Description)
		require.True(t, *sent.Properties.Enabled)
		require.Len(t, sent.Properties.Actions.ActionGroups, 1)

		var props map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &props))
		require.Equal(t, "Global", props["location"])
		conditions := props["conditions"].([]any)
		require.Len(t, conditions, 2)
		require.Equal(t, "category", conditions[0].(map[string]any)["field"])
		require.Equal(t, []any{"/subscriptions/sub-1"}, props["scopes"])
		require.Equal(t, "watch deletes", props["description"])
	})

	// Location defaults to Global rather than a region: action groups are global
	// and ARM rejects a region here.
	t.Run("Create_defaults_location_to_Global", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "ala-1", "resourceGroupName": "rg-1",
			"scopes":     []any{"/subscriptions/sub-1"},
			"conditions": []any{map[string]any{"field": "category", "equals": "Administrative"}},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.Equal(t, "Global", *sent.Location)
	})

	t.Run("Create_requires_conditions", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "ala-1", "resourceGroupName": "rg-1"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.Error(t, err)
	})

	t.Run("Create_requires_resourceGroupName", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name":       "ala-1",
			"scopes":     []any{"/subscriptions/sub-1"},
			"conditions": []any{map[string]any{"field": "category", "equals": "Administrative"}},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.Error(t, err)
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testActivityLogAlertNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "ala-1", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, true, props["enabled"])
	})

	// The ARM PATCH can only toggle enabled/tags, so a receiver change has to go
	// through CreateOrUpdate — otherwise the new receiver would be silently dropped.
	t.Run("Update_replaces_rule_via_CreateOrUpdate", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testActivityLogAlertNativeID,
			DesiredProperties: activityLogAlertDesired("watch everything", "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Insights/actionGroups/ag-1"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testActivityLogAlertNativeID, got.ProgressResult.NativeID)
		require.Equal(t, "watch everything", *sent.Properties.Description)
	})

	t.Run("Delete", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testActivityLogAlertNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _ string, _ *armmonitor.ActivityLogAlertsClientDeleteOptions) (armmonitor.ActivityLogAlertsClientDeleteResponse, error) {
			return armmonitor.ActivityLogAlertsClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testActivityLogAlertNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_resource_group", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testActivityLogAlertNativeID}, got.NativeIDs)
	})

	t.Run("List_without_group_is_subscription_wide", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 2)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.createOrUpdateFn = func(_ context.Context, _, _ string, _ armmonitor.ActivityLogAlertResource, _ *armmonitor.ActivityLogAlertsClientCreateOrUpdateOptions) (armmonitor.ActivityLogAlertsClientCreateOrUpdateResponse, error) {
			return armmonitor.ActivityLogAlertsClientCreateOrUpdateResponse{}, &azcore.ResponseError{StatusCode: 400}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "ala-1", Properties: activityLogAlertDesired("watch deletes", "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Insights/actionGroups/ag-1")})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

func TestMonitorActivityLogAlert_ReadNotFound(t *testing.T) {
	fake := &fakeActivityLogAlertsAPI{
		getFn: func(_ context.Context, _, _ string, _ *armmonitor.ActivityLogAlertsClientGetOptions) (armmonitor.ActivityLogAlertsClientGetResponse, error) {
			return armmonitor.ActivityLogAlertsClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestMonitorActivityLogAlert(fake).Read(context.Background(), &resource.ReadRequest{NativeID: testActivityLogAlertNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeActivityLogAlertsAPI struct {
	createOrUpdateFn               func(ctx context.Context, rgName, name string, ag armmonitor.ActivityLogAlertResource, options *armmonitor.ActivityLogAlertsClientCreateOrUpdateOptions) (armmonitor.ActivityLogAlertsClientCreateOrUpdateResponse, error)
	getFn                          func(ctx context.Context, rgName, name string, options *armmonitor.ActivityLogAlertsClientGetOptions) (armmonitor.ActivityLogAlertsClientGetResponse, error)
	deleteFn                       func(ctx context.Context, rgName, name string, options *armmonitor.ActivityLogAlertsClientDeleteOptions) (armmonitor.ActivityLogAlertsClientDeleteResponse, error)
	newListByResourceGroupPagerFn  func(rgName string, options *armmonitor.ActivityLogAlertsClientListByResourceGroupOptions) *runtime.Pager[armmonitor.ActivityLogAlertsClientListByResourceGroupResponse]
	newListBySubscriptionIDPagerFn func(options *armmonitor.ActivityLogAlertsClientListBySubscriptionIDOptions) *runtime.Pager[armmonitor.ActivityLogAlertsClientListBySubscriptionIDResponse]
}

func (f *fakeActivityLogAlertsAPI) CreateOrUpdate(ctx context.Context, rgName, name string, ag armmonitor.ActivityLogAlertResource, options *armmonitor.ActivityLogAlertsClientCreateOrUpdateOptions) (armmonitor.ActivityLogAlertsClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, name, ag, options)
}

func (f *fakeActivityLogAlertsAPI) Get(ctx context.Context, rgName, name string, options *armmonitor.ActivityLogAlertsClientGetOptions) (armmonitor.ActivityLogAlertsClientGetResponse, error) {
	return f.getFn(ctx, rgName, name, options)
}

func (f *fakeActivityLogAlertsAPI) Delete(ctx context.Context, rgName, name string, options *armmonitor.ActivityLogAlertsClientDeleteOptions) (armmonitor.ActivityLogAlertsClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, name, options)
}

func (f *fakeActivityLogAlertsAPI) NewListByResourceGroupPager(rgName string, options *armmonitor.ActivityLogAlertsClientListByResourceGroupOptions) *runtime.Pager[armmonitor.ActivityLogAlertsClientListByResourceGroupResponse] {
	return f.newListByResourceGroupPagerFn(rgName, options)
}

func (f *fakeActivityLogAlertsAPI) NewListBySubscriptionIDPager(options *armmonitor.ActivityLogAlertsClientListBySubscriptionIDOptions) *runtime.Pager[armmonitor.ActivityLogAlertsClientListBySubscriptionIDResponse] {
	return f.newListBySubscriptionIDPagerFn(options)
}
