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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/desktopvirtualization/armdesktopvirtualization"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const (
	testAvdApplicationGroupNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.DesktopVirtualization/applicationGroups/ag-1"
	testAvdApplicationGroupHostPool = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.DesktopVirtualization/hostPools/hp-1"
	testAvdApplicationGroupWorkspce = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.DesktopVirtualization/workspaces/ws-1"
)

func newTestAvdApplicationGroup(api avdApplicationGroupsAPI) *AvdApplicationGroup {
	return &AvdApplicationGroup{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func avdApplicationGroupDesired(tagValue string) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":                 "ag-1",
		"location":             "eastus",
		"resourceGroupName":    "rg-1",
		"hostPoolArmPath":      testAvdApplicationGroupHostPool,
		"applicationGroupType": "RemoteApp",
		"description":          "conformance application group",
		"friendlyName":         "ag one",
		"Tags":                 []map[string]string{{"Key": "env", "Value": tagValue}},
	})
	return out
}

func TestAvdApplicationGroup_CRUD(t *testing.T) {
	// The response deliberately carries workspaceArmPath: the service writes it
	// the moment a workspace lists this group, so the read path must drop it or
	// every sync after that reports drift.
	groupResult := armdesktopvirtualization.ApplicationGroup{
		ID:       to.Ptr(testAvdApplicationGroupNativeID),
		Name:     to.Ptr("ag-1"),
		Location: to.Ptr("East US"),
		Properties: &armdesktopvirtualization.ApplicationGroupProperties{
			HostPoolArmPath:      to.Ptr(testAvdApplicationGroupHostPool),
			ApplicationGroupType: to.Ptr(armdesktopvirtualization.ApplicationGroupTypeRemoteApp),
			Description:          to.Ptr("conformance application group"),
			FriendlyName:         to.Ptr("ag one"),
			WorkspaceArmPath:     to.Ptr(testAvdApplicationGroupWorkspce),
			ObjectID:             to.Ptr("00000000-0000-0000-0000-000000000002"),
			CloudPcResource:      to.Ptr(false),
		},
		Tags: map[string]*string{"env": to.Ptr("conformance")},
	}

	var sentCreate armdesktopvirtualization.ApplicationGroup
	var sentUpdate *armdesktopvirtualization.ApplicationGroupPatch
	deleteCalls := 0
	fake := &fakeAvdApplicationGroupsAPI{
		createOrUpdateFn: func(_ context.Context, rgName, name string, params armdesktopvirtualization.ApplicationGroup, _ *armdesktopvirtualization.ApplicationGroupsClientCreateOrUpdateOptions) (armdesktopvirtualization.ApplicationGroupsClientCreateOrUpdateResponse, error) {
			require.Equal(t, "rg-1", rgName)
			require.Equal(t, "ag-1", name)
			sentCreate = params
			return armdesktopvirtualization.ApplicationGroupsClientCreateOrUpdateResponse{ApplicationGroup: groupResult}, nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armdesktopvirtualization.ApplicationGroupsClientGetOptions) (armdesktopvirtualization.ApplicationGroupsClientGetResponse, error) {
			return armdesktopvirtualization.ApplicationGroupsClientGetResponse{ApplicationGroup: groupResult}, nil
		},
		updateFn: func(_ context.Context, _, _ string, options *armdesktopvirtualization.ApplicationGroupsClientUpdateOptions) (armdesktopvirtualization.ApplicationGroupsClientUpdateResponse, error) {
			sentUpdate = options.ApplicationGroup
			return armdesktopvirtualization.ApplicationGroupsClientUpdateResponse{ApplicationGroup: groupResult}, nil
		},
		deleteFn: func(_ context.Context, _, _ string, _ *armdesktopvirtualization.ApplicationGroupsClientDeleteOptions) (armdesktopvirtualization.ApplicationGroupsClientDeleteResponse, error) {
			deleteCalls++
			return armdesktopvirtualization.ApplicationGroupsClientDeleteResponse{}, nil
		},
		newListByResourceGroupPagerFn: func(rgName string, _ *armdesktopvirtualization.ApplicationGroupsClientListByResourceGroupOptions) *runtime.Pager[armdesktopvirtualization.ApplicationGroupsClientListByResourceGroupResponse] {
			require.Equal(t, "rg-1", rgName)
			return runtime.NewPager(runtime.PagingHandler[armdesktopvirtualization.ApplicationGroupsClientListByResourceGroupResponse]{
				More: func(armdesktopvirtualization.ApplicationGroupsClientListByResourceGroupResponse) bool { return false },
				Fetcher: func(context.Context, *armdesktopvirtualization.ApplicationGroupsClientListByResourceGroupResponse) (armdesktopvirtualization.ApplicationGroupsClientListByResourceGroupResponse, error) {
					return armdesktopvirtualization.ApplicationGroupsClientListByResourceGroupResponse{
						ApplicationGroupList: armdesktopvirtualization.ApplicationGroupList{
							Value: []*armdesktopvirtualization.ApplicationGroup{{ID: to.Ptr(testAvdApplicationGroupNativeID)}},
						},
					}, nil
				},
			})
		},
		newListBySubscriptionPagerFn: func(_ *armdesktopvirtualization.ApplicationGroupsClientListBySubscriptionOptions) *runtime.Pager[armdesktopvirtualization.ApplicationGroupsClientListBySubscriptionResponse] {
			return runtime.NewPager(runtime.PagingHandler[armdesktopvirtualization.ApplicationGroupsClientListBySubscriptionResponse]{
				More: func(armdesktopvirtualization.ApplicationGroupsClientListBySubscriptionResponse) bool { return false },
				Fetcher: func(context.Context, *armdesktopvirtualization.ApplicationGroupsClientListBySubscriptionResponse) (armdesktopvirtualization.ApplicationGroupsClientListBySubscriptionResponse, error) {
					return armdesktopvirtualization.ApplicationGroupsClientListBySubscriptionResponse{
						ApplicationGroupList: armdesktopvirtualization.ApplicationGroupList{
							Value: []*armdesktopvirtualization.ApplicationGroup{{ID: to.Ptr(testAvdApplicationGroupNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestAvdApplicationGroup(fake)

	t.Run("Create_is_synchronous", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "ag-1",
			Properties: avdApplicationGroupDesired("conformance"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testAvdApplicationGroupNativeID, got.ProgressResult.NativeID)
		require.Empty(t, got.ProgressResult.RequestID)

		require.Equal(t, "eastus", *sentCreate.Location)
		// The host pool link is a field, not an association resource.
		require.Equal(t, testAvdApplicationGroupHostPool, *sentCreate.Properties.HostPoolArmPath)
		require.Equal(t, armdesktopvirtualization.ApplicationGroupTypeRemoteApp,
			*sentCreate.Properties.ApplicationGroupType)
		require.Equal(t, "conformance", *sentCreate.Tags["env"])
	})

	t.Run("Create_requires_host_pool_arm_path", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "ag-1", "resourceGroupName": "rg-1", "location": "eastus",
			"applicationGroupType": "RemoteApp",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "hostPoolArmPath is required")
	})

	t.Run("Create_requires_application_group_type", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "ag-1", "resourceGroupName": "rg-1", "location": "eastus",
			"hostPoolArmPath": testAvdApplicationGroupHostPool,
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "applicationGroupType is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testAvdApplicationGroupNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "ag-1", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "eastus", props["location"])
		require.Equal(t, testAvdApplicationGroupHostPool, props["hostPoolArmPath"])
		require.Equal(t, "RemoteApp", props["applicationGroupType"])
		require.Equal(t, []any{map[string]any{"Key": "env", "Value": "conformance"}}, props["Tags"])
	})

	// workspaceArmPath appears the moment a workspace references the group, so
	// surfacing it would report drift for something the user never declared. The
	// link is modelled from the workspace side instead.
	t.Run("Read_drops_workspace_back_reference", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testAvdApplicationGroupNativeID})
		require.NoError(t, err)
		for _, key := range []string{"workspaceArmPath", "objectId", "cloudPcResource"} {
			require.NotContains(t, got.Properties, key)
		}
	})

	// ARM's ApplicationGroupPatchProperties carries only description and
	// friendlyName, which is exactly why hostPoolArmPath and
	// applicationGroupType are createOnly.
	t.Run("Update_patches_free_text_and_tags_only", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testAvdApplicationGroupNativeID,
			DesiredProperties: avdApplicationGroupDesired("conformance-updated"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, "conformance application group", *sentUpdate.Properties.Description)
		require.Equal(t, "ag one", *sentUpdate.Properties.FriendlyName)
		require.Equal(t, "conformance-updated", *sentUpdate.Tags["env"])
	})

	t.Run("Delete_is_synchronous", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testAvdApplicationGroupNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Empty(t, got.ProgressResult.RequestID)
		require.Equal(t, before+1, deleteCalls)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(context.Context, string, string, *armdesktopvirtualization.ApplicationGroupsClientDeleteOptions) (armdesktopvirtualization.ApplicationGroupsClientDeleteResponse, error) {
			return armdesktopvirtualization.ApplicationGroupsClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testAvdApplicationGroupNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_resource_group", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testAvdApplicationGroupNativeID}, got.NativeIDs)
	})

	t.Run("List_falls_back_to_subscription_wide", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Equal(t, []string{testAvdApplicationGroupNativeID}, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure_with_cause", func(t *testing.T) {
		fake.createOrUpdateFn = func(context.Context, string, string, armdesktopvirtualization.ApplicationGroup, *armdesktopvirtualization.ApplicationGroupsClientCreateOrUpdateOptions) (armdesktopvirtualization.ApplicationGroupsClientCreateOrUpdateResponse, error) {
			return armdesktopvirtualization.ApplicationGroupsClientCreateOrUpdateResponse{},
				&azcore.ResponseError{StatusCode: 400, ErrorCode: "BadRequest"}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "ag-1", Properties: avdApplicationGroupDesired("conformance"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.Contains(t, got.ProgressResult.StatusMessage, "BadRequest")
	})
}

func TestAvdApplicationGroup_ReadNotFound(t *testing.T) {
	fake := &fakeAvdApplicationGroupsAPI{
		getFn: func(context.Context, string, string, *armdesktopvirtualization.ApplicationGroupsClientGetOptions) (armdesktopvirtualization.ApplicationGroupsClientGetResponse, error) {
			return armdesktopvirtualization.ApplicationGroupsClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestAvdApplicationGroup(fake).Read(context.Background(),
		&resource.ReadRequest{NativeID: testAvdApplicationGroupNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeAvdApplicationGroupsAPI struct {
	createOrUpdateFn              func(ctx context.Context, rgName, name string, params armdesktopvirtualization.ApplicationGroup, options *armdesktopvirtualization.ApplicationGroupsClientCreateOrUpdateOptions) (armdesktopvirtualization.ApplicationGroupsClientCreateOrUpdateResponse, error)
	getFn                         func(ctx context.Context, rgName, name string, options *armdesktopvirtualization.ApplicationGroupsClientGetOptions) (armdesktopvirtualization.ApplicationGroupsClientGetResponse, error)
	updateFn                      func(ctx context.Context, rgName, name string, options *armdesktopvirtualization.ApplicationGroupsClientUpdateOptions) (armdesktopvirtualization.ApplicationGroupsClientUpdateResponse, error)
	deleteFn                      func(ctx context.Context, rgName, name string, options *armdesktopvirtualization.ApplicationGroupsClientDeleteOptions) (armdesktopvirtualization.ApplicationGroupsClientDeleteResponse, error)
	newListByResourceGroupPagerFn func(rgName string, options *armdesktopvirtualization.ApplicationGroupsClientListByResourceGroupOptions) *runtime.Pager[armdesktopvirtualization.ApplicationGroupsClientListByResourceGroupResponse]
	newListBySubscriptionPagerFn  func(options *armdesktopvirtualization.ApplicationGroupsClientListBySubscriptionOptions) *runtime.Pager[armdesktopvirtualization.ApplicationGroupsClientListBySubscriptionResponse]
}

func (f *fakeAvdApplicationGroupsAPI) CreateOrUpdate(ctx context.Context, rgName, name string, params armdesktopvirtualization.ApplicationGroup, options *armdesktopvirtualization.ApplicationGroupsClientCreateOrUpdateOptions) (armdesktopvirtualization.ApplicationGroupsClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, name, params, options)
}

func (f *fakeAvdApplicationGroupsAPI) Get(ctx context.Context, rgName, name string, options *armdesktopvirtualization.ApplicationGroupsClientGetOptions) (armdesktopvirtualization.ApplicationGroupsClientGetResponse, error) {
	return f.getFn(ctx, rgName, name, options)
}

func (f *fakeAvdApplicationGroupsAPI) Update(ctx context.Context, rgName, name string, options *armdesktopvirtualization.ApplicationGroupsClientUpdateOptions) (armdesktopvirtualization.ApplicationGroupsClientUpdateResponse, error) {
	return f.updateFn(ctx, rgName, name, options)
}

func (f *fakeAvdApplicationGroupsAPI) Delete(ctx context.Context, rgName, name string, options *armdesktopvirtualization.ApplicationGroupsClientDeleteOptions) (armdesktopvirtualization.ApplicationGroupsClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, name, options)
}

func (f *fakeAvdApplicationGroupsAPI) NewListByResourceGroupPager(rgName string, options *armdesktopvirtualization.ApplicationGroupsClientListByResourceGroupOptions) *runtime.Pager[armdesktopvirtualization.ApplicationGroupsClientListByResourceGroupResponse] {
	return f.newListByResourceGroupPagerFn(rgName, options)
}

func (f *fakeAvdApplicationGroupsAPI) NewListBySubscriptionPager(options *armdesktopvirtualization.ApplicationGroupsClientListBySubscriptionOptions) *runtime.Pager[armdesktopvirtualization.ApplicationGroupsClientListBySubscriptionResponse] {
	return f.newListBySubscriptionPagerFn(options)
}
