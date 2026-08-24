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

const testActionGroupNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Insights/actionGroups/ag-1"

func newTestMonitorActionGroup(api monitorActionGroupsAPI) *MonitorActionGroup {
	return &MonitorActionGroup{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func actionGroupDesired(shortName string, emails ...string) []byte {
	receivers := make([]map[string]any, 0, len(emails))
	for i, e := range emails {
		receivers = append(receivers, map[string]any{
			"name":                 "oncall-" + string(rune('a'+i)),
			"emailAddress":         e,
			"useCommonAlertSchema": true,
		})
	}
	out, _ := json.Marshal(map[string]any{
		"name":              "ag-1",
		"resourceGroupName": "rg-1",
		"location":          "Global",
		"groupShortName":    shortName,
		"enabled":           true,
		"emailReceivers":    receivers,
	})
	return out
}

func TestMonitorActionGroup_CRUD(t *testing.T) {
	var sent armmonitor.ActionGroupResource
	echo := func(params armmonitor.ActionGroupResource) armmonitor.ActionGroupResource {
		params.ID = to.Ptr(testActionGroupNativeID)
		params.Name = to.Ptr("ag-1")
		return params
	}

	fake := &fakeActionGroupsAPI{
		createOrUpdateFn: func(_ context.Context, _, name string, params armmonitor.ActionGroupResource, _ *armmonitor.ActionGroupsClientCreateOrUpdateOptions) (armmonitor.ActionGroupsClientCreateOrUpdateResponse, error) {
			require.Equal(t, "ag-1", name)
			sent = params
			return armmonitor.ActionGroupsClientCreateOrUpdateResponse{ActionGroupResource: echo(params)}, nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armmonitor.ActionGroupsClientGetOptions) (armmonitor.ActionGroupsClientGetResponse, error) {
			return armmonitor.ActionGroupsClientGetResponse{ActionGroupResource: echo(sent)}, nil
		},
		deleteFn: func(_ context.Context, _, _ string, _ *armmonitor.ActionGroupsClientDeleteOptions) (armmonitor.ActionGroupsClientDeleteResponse, error) {
			return armmonitor.ActionGroupsClientDeleteResponse{}, nil
		},
		newListByResourceGroupPagerFn: func(_ string, _ *armmonitor.ActionGroupsClientListByResourceGroupOptions) *runtime.Pager[armmonitor.ActionGroupsClientListByResourceGroupResponse] {
			return runtime.NewPager(runtime.PagingHandler[armmonitor.ActionGroupsClientListByResourceGroupResponse]{
				More: func(_ armmonitor.ActionGroupsClientListByResourceGroupResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armmonitor.ActionGroupsClientListByResourceGroupResponse) (armmonitor.ActionGroupsClientListByResourceGroupResponse, error) {
					return armmonitor.ActionGroupsClientListByResourceGroupResponse{
						ActionGroupList: armmonitor.ActionGroupList{
							Value: []*armmonitor.ActionGroupResource{{ID: to.Ptr(testActionGroupNativeID)}},
						},
					}, nil
				},
			})
		},
		newListBySubscriptionIDPagerFn: func(_ *armmonitor.ActionGroupsClientListBySubscriptionIDOptions) *runtime.Pager[armmonitor.ActionGroupsClientListBySubscriptionIDResponse] {
			return runtime.NewPager(runtime.PagingHandler[armmonitor.ActionGroupsClientListBySubscriptionIDResponse]{
				More: func(_ armmonitor.ActionGroupsClientListBySubscriptionIDResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armmonitor.ActionGroupsClientListBySubscriptionIDResponse) (armmonitor.ActionGroupsClientListBySubscriptionIDResponse, error) {
					return armmonitor.ActionGroupsClientListBySubscriptionIDResponse{
						ActionGroupList: armmonitor.ActionGroupList{
							Value: []*armmonitor.ActionGroupResource{
								{ID: to.Ptr(testActionGroupNativeID)},
								{ID: to.Ptr("/subscriptions/sub-1/resourceGroups/rg-2/providers/Microsoft.Insights/actionGroups/ag-2")},
							},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestMonitorActionGroup(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "ag-1", Properties: actionGroupDesired("fpsdtag", "oncall@example.com")})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testActionGroupNativeID, got.ProgressResult.NativeID)

		require.Equal(t, "Global", *sent.Location)
		require.Equal(t, "fpsdtag", *sent.Properties.GroupShortName)
		require.Len(t, sent.Properties.EmailReceivers, 1)
		require.Equal(t, "oncall@example.com", *sent.Properties.EmailReceivers[0].EmailAddress)

		var props map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &props))
		require.Equal(t, "Global", props["location"])
		receivers := props["emailReceivers"].([]any)
		require.Len(t, receivers, 1)
	})

	// Location defaults to Global rather than a region: action groups are global
	// and ARM rejects a region here.
	t.Run("Create_defaults_location_to_Global", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "ag-1", "resourceGroupName": "rg-1", "groupShortName": "fpsdtag",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.Equal(t, "Global", *sent.Location)
	})

	t.Run("Create_requires_groupShortName", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "ag-1", "resourceGroupName": "rg-1"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.Error(t, err)
	})

	t.Run("Create_requires_resourceGroupName", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "ag-1", "groupShortName": "fpsdtag"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.Error(t, err)
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testActionGroupNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "ag-1", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, true, props["enabled"])
	})

	// The ARM PATCH can only toggle enabled/tags, so a receiver change has to go
	// through CreateOrUpdate — otherwise the new receiver would be silently dropped.
	t.Run("Update_replaces_receivers_via_CreateOrUpdate", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testActionGroupNativeID,
			DesiredProperties: actionGroupDesired("fpsdtag", "oncall@example.com", "backup@example.com"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testActionGroupNativeID, got.ProgressResult.NativeID)
		require.Len(t, sent.Properties.EmailReceivers, 2)
	})

	t.Run("Delete", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testActionGroupNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _ string, _ *armmonitor.ActionGroupsClientDeleteOptions) (armmonitor.ActionGroupsClientDeleteResponse, error) {
			return armmonitor.ActionGroupsClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testActionGroupNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_resource_group", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testActionGroupNativeID}, got.NativeIDs)
	})

	t.Run("List_without_group_is_subscription_wide", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 2)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.createOrUpdateFn = func(_ context.Context, _, _ string, _ armmonitor.ActionGroupResource, _ *armmonitor.ActionGroupsClientCreateOrUpdateOptions) (armmonitor.ActionGroupsClientCreateOrUpdateResponse, error) {
			return armmonitor.ActionGroupsClientCreateOrUpdateResponse{}, &azcore.ResponseError{StatusCode: 400}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "ag-1", Properties: actionGroupDesired("fpsdtag", "oncall@example.com")})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

func TestMonitorActionGroup_ReadNotFound(t *testing.T) {
	fake := &fakeActionGroupsAPI{
		getFn: func(_ context.Context, _, _ string, _ *armmonitor.ActionGroupsClientGetOptions) (armmonitor.ActionGroupsClientGetResponse, error) {
			return armmonitor.ActionGroupsClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestMonitorActionGroup(fake).Read(context.Background(), &resource.ReadRequest{NativeID: testActionGroupNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeActionGroupsAPI struct {
	createOrUpdateFn               func(ctx context.Context, rgName, name string, ag armmonitor.ActionGroupResource, options *armmonitor.ActionGroupsClientCreateOrUpdateOptions) (armmonitor.ActionGroupsClientCreateOrUpdateResponse, error)
	getFn                          func(ctx context.Context, rgName, name string, options *armmonitor.ActionGroupsClientGetOptions) (armmonitor.ActionGroupsClientGetResponse, error)
	deleteFn                       func(ctx context.Context, rgName, name string, options *armmonitor.ActionGroupsClientDeleteOptions) (armmonitor.ActionGroupsClientDeleteResponse, error)
	newListByResourceGroupPagerFn  func(rgName string, options *armmonitor.ActionGroupsClientListByResourceGroupOptions) *runtime.Pager[armmonitor.ActionGroupsClientListByResourceGroupResponse]
	newListBySubscriptionIDPagerFn func(options *armmonitor.ActionGroupsClientListBySubscriptionIDOptions) *runtime.Pager[armmonitor.ActionGroupsClientListBySubscriptionIDResponse]
}

func (f *fakeActionGroupsAPI) CreateOrUpdate(ctx context.Context, rgName, name string, ag armmonitor.ActionGroupResource, options *armmonitor.ActionGroupsClientCreateOrUpdateOptions) (armmonitor.ActionGroupsClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, name, ag, options)
}

func (f *fakeActionGroupsAPI) Get(ctx context.Context, rgName, name string, options *armmonitor.ActionGroupsClientGetOptions) (armmonitor.ActionGroupsClientGetResponse, error) {
	return f.getFn(ctx, rgName, name, options)
}

func (f *fakeActionGroupsAPI) Delete(ctx context.Context, rgName, name string, options *armmonitor.ActionGroupsClientDeleteOptions) (armmonitor.ActionGroupsClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, name, options)
}

func (f *fakeActionGroupsAPI) NewListByResourceGroupPager(rgName string, options *armmonitor.ActionGroupsClientListByResourceGroupOptions) *runtime.Pager[armmonitor.ActionGroupsClientListByResourceGroupResponse] {
	return f.newListByResourceGroupPagerFn(rgName, options)
}

func (f *fakeActionGroupsAPI) NewListBySubscriptionIDPager(options *armmonitor.ActionGroupsClientListBySubscriptionIDOptions) *runtime.Pager[armmonitor.ActionGroupsClientListBySubscriptionIDResponse] {
	return f.newListBySubscriptionIDPagerFn(options)
}
