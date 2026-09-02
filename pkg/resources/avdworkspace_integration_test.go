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
	testAvdWorkspaceNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.DesktopVirtualization/workspaces/ws-1"
	testAvdWorkspaceAppGroup = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.DesktopVirtualization/applicationGroups/ag-1"
)

func newTestAvdWorkspace(api avdWorkspacesAPI) *AvdWorkspace {
	return &AvdWorkspace{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func avdWorkspaceDesired(tagValue string, appGroups []string) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":                       "ws-1",
		"location":                   "eastus",
		"resourceGroupName":          "rg-1",
		"applicationGroupReferences": appGroups,
		"description":                "conformance workspace",
		"friendlyName":               "ws one",
		"Tags":                       []map[string]string{{"Key": "env", "Value": tagValue}},
	})
	return out
}

func TestAvdWorkspace_CRUD(t *testing.T) {
	wsResult := armdesktopvirtualization.Workspace{
		ID:       to.Ptr(testAvdWorkspaceNativeID),
		Name:     to.Ptr("ws-1"),
		Location: to.Ptr("East US"),
		Properties: &armdesktopvirtualization.WorkspaceProperties{
			ApplicationGroupReferences: []*string{to.Ptr(testAvdWorkspaceAppGroup)},
			Description:                to.Ptr("conformance workspace"),
			FriendlyName:               to.Ptr("ws one"),
			ObjectID:                   to.Ptr("00000000-0000-0000-0000-000000000004"),
			CloudPcResource:            to.Ptr(false),
		},
		Tags: map[string]*string{"env": to.Ptr("conformance")},
	}

	var sentCreate armdesktopvirtualization.Workspace
	var sentUpdate *armdesktopvirtualization.WorkspacePatch
	deleteCalls := 0
	fake := &fakeAvdWorkspacesAPI{
		createOrUpdateFn: func(_ context.Context, rgName, name string, params armdesktopvirtualization.Workspace, _ *armdesktopvirtualization.WorkspacesClientCreateOrUpdateOptions) (armdesktopvirtualization.WorkspacesClientCreateOrUpdateResponse, error) {
			require.Equal(t, "rg-1", rgName)
			require.Equal(t, "ws-1", name)
			sentCreate = params
			return armdesktopvirtualization.WorkspacesClientCreateOrUpdateResponse{Workspace: wsResult}, nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armdesktopvirtualization.WorkspacesClientGetOptions) (armdesktopvirtualization.WorkspacesClientGetResponse, error) {
			return armdesktopvirtualization.WorkspacesClientGetResponse{Workspace: wsResult}, nil
		},
		updateFn: func(_ context.Context, _, _ string, options *armdesktopvirtualization.WorkspacesClientUpdateOptions) (armdesktopvirtualization.WorkspacesClientUpdateResponse, error) {
			sentUpdate = options.Workspace
			return armdesktopvirtualization.WorkspacesClientUpdateResponse{Workspace: wsResult}, nil
		},
		deleteFn: func(_ context.Context, _, _ string, _ *armdesktopvirtualization.WorkspacesClientDeleteOptions) (armdesktopvirtualization.WorkspacesClientDeleteResponse, error) {
			deleteCalls++
			return armdesktopvirtualization.WorkspacesClientDeleteResponse{}, nil
		},
		newListByResourceGroupPagerFn: func(rgName string, _ *armdesktopvirtualization.WorkspacesClientListByResourceGroupOptions) *runtime.Pager[armdesktopvirtualization.WorkspacesClientListByResourceGroupResponse] {
			require.Equal(t, "rg-1", rgName)
			return runtime.NewPager(runtime.PagingHandler[armdesktopvirtualization.WorkspacesClientListByResourceGroupResponse]{
				More: func(armdesktopvirtualization.WorkspacesClientListByResourceGroupResponse) bool { return false },
				Fetcher: func(context.Context, *armdesktopvirtualization.WorkspacesClientListByResourceGroupResponse) (armdesktopvirtualization.WorkspacesClientListByResourceGroupResponse, error) {
					return armdesktopvirtualization.WorkspacesClientListByResourceGroupResponse{
						WorkspaceList: armdesktopvirtualization.WorkspaceList{
							Value: []*armdesktopvirtualization.Workspace{{ID: to.Ptr(testAvdWorkspaceNativeID)}},
						},
					}, nil
				},
			})
		},
		newListBySubscriptionPagerFn: func(_ *armdesktopvirtualization.WorkspacesClientListBySubscriptionOptions) *runtime.Pager[armdesktopvirtualization.WorkspacesClientListBySubscriptionResponse] {
			return runtime.NewPager(runtime.PagingHandler[armdesktopvirtualization.WorkspacesClientListBySubscriptionResponse]{
				More: func(armdesktopvirtualization.WorkspacesClientListBySubscriptionResponse) bool { return false },
				Fetcher: func(context.Context, *armdesktopvirtualization.WorkspacesClientListBySubscriptionResponse) (armdesktopvirtualization.WorkspacesClientListBySubscriptionResponse, error) {
					return armdesktopvirtualization.WorkspacesClientListBySubscriptionResponse{
						WorkspaceList: armdesktopvirtualization.WorkspaceList{
							Value: []*armdesktopvirtualization.Workspace{{ID: to.Ptr(testAvdWorkspaceNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestAvdWorkspace(fake)

	t.Run("Create_is_synchronous", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "ws-1",
			Properties: avdWorkspaceDesired("conformance", []string{testAvdWorkspaceAppGroup}),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testAvdWorkspaceNativeID, got.ProgressResult.NativeID)
		require.Empty(t, got.ProgressResult.RequestID)

		require.Equal(t, "eastus", *sentCreate.Location)
		// Which application groups appear in the feed is a field, not an
		// association resource.
		require.Len(t, sentCreate.Properties.ApplicationGroupReferences, 1)
		require.Equal(t, testAvdWorkspaceAppGroup, *sentCreate.Properties.ApplicationGroupReferences[0])
		require.Equal(t, "conformance", *sentCreate.Tags["env"])
	})

	// An unset list must be omitted from the body rather than sent as an empty
	// array: ARM treats an explicit [] as "detach everything".
	t.Run("Create_omits_an_unset_application_group_list", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "ws-1", "resourceGroupName": "rg-1", "location": "eastus",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.Nil(t, sentCreate.Properties.ApplicationGroupReferences)
	})

	t.Run("Create_requires_resource_group", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "ws-1", "location": "eastus"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "resourceGroupName is required")
	})

	t.Run("Create_requires_location", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "ws-1", "resourceGroupName": "rg-1"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "location is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testAvdWorkspaceNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "ws-1", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "eastus", props["location"])
		require.Equal(t, []any{testAvdWorkspaceAppGroup}, props["applicationGroupReferences"])
		require.Equal(t, []any{map[string]any{"Key": "env", "Value": "conformance"}}, props["Tags"])
	})

	t.Run("Read_drops_service_state", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testAvdWorkspaceNativeID})
		require.NoError(t, err)
		for _, key := range []string{"objectId", "cloudPcResource"} {
			require.NotContains(t, got.Properties, key)
		}
	})

	// A workspace with no application groups must read back with the field
	// absent, not as a declared-but-empty list.
	t.Run("Read_omits_an_empty_application_group_list", func(t *testing.T) {
		fake.getFn = func(context.Context, string, string, *armdesktopvirtualization.WorkspacesClientGetOptions) (armdesktopvirtualization.WorkspacesClientGetResponse, error) {
			return armdesktopvirtualization.WorkspacesClientGetResponse{Workspace: armdesktopvirtualization.Workspace{
				ID:         to.Ptr(testAvdWorkspaceNativeID),
				Name:       to.Ptr("ws-1"),
				Properties: &armdesktopvirtualization.WorkspaceProperties{Description: to.Ptr("")},
			}}, nil
		}
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testAvdWorkspaceNativeID})
		require.NoError(t, err)
		require.NotContains(t, got.Properties, "applicationGroupReferences")
		require.NotContains(t, got.Properties, "description")
		fake.getFn = func(context.Context, string, string, *armdesktopvirtualization.WorkspacesClientGetOptions) (armdesktopvirtualization.WorkspacesClientGetResponse, error) {
			return armdesktopvirtualization.WorkspacesClientGetResponse{Workspace: wsResult}, nil
		}
	})

	// The list is a set the caller owns outright, so it is PATCHed whole:
	// otherwise removing the last application group would be impossible.
	t.Run("Update_sends_the_application_group_list_whole", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testAvdWorkspaceNativeID,
			DesiredProperties: avdWorkspaceDesired("conformance-updated", nil),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.NotNil(t, sentUpdate.Properties.ApplicationGroupReferences)
		require.Empty(t, sentUpdate.Properties.ApplicationGroupReferences)
		require.Equal(t, "conformance-updated", *sentUpdate.Tags["env"])
	})

	t.Run("Delete_is_synchronous", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testAvdWorkspaceNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Empty(t, got.ProgressResult.RequestID)
		require.Equal(t, before+1, deleteCalls)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(context.Context, string, string, *armdesktopvirtualization.WorkspacesClientDeleteOptions) (armdesktopvirtualization.WorkspacesClientDeleteResponse, error) {
			return armdesktopvirtualization.WorkspacesClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testAvdWorkspaceNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_resource_group", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testAvdWorkspaceNativeID}, got.NativeIDs)
	})

	t.Run("List_falls_back_to_subscription_wide", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Equal(t, []string{testAvdWorkspaceNativeID}, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure_with_cause", func(t *testing.T) {
		fake.createOrUpdateFn = func(context.Context, string, string, armdesktopvirtualization.Workspace, *armdesktopvirtualization.WorkspacesClientCreateOrUpdateOptions) (armdesktopvirtualization.WorkspacesClientCreateOrUpdateResponse, error) {
			return armdesktopvirtualization.WorkspacesClientCreateOrUpdateResponse{},
				&azcore.ResponseError{StatusCode: 409, ErrorCode: "ApplicationGroupAlreadyInAWorkspace"}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "ws-1",
			Properties: avdWorkspaceDesired("conformance", []string{testAvdWorkspaceAppGroup}),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.Contains(t, got.ProgressResult.StatusMessage, "ApplicationGroupAlreadyInAWorkspace")
	})
}

func TestAvdWorkspace_ReadNotFound(t *testing.T) {
	fake := &fakeAvdWorkspacesAPI{
		getFn: func(context.Context, string, string, *armdesktopvirtualization.WorkspacesClientGetOptions) (armdesktopvirtualization.WorkspacesClientGetResponse, error) {
			return armdesktopvirtualization.WorkspacesClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestAvdWorkspace(fake).Read(context.Background(),
		&resource.ReadRequest{NativeID: testAvdWorkspaceNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeAvdWorkspacesAPI struct {
	createOrUpdateFn              func(ctx context.Context, rgName, name string, params armdesktopvirtualization.Workspace, options *armdesktopvirtualization.WorkspacesClientCreateOrUpdateOptions) (armdesktopvirtualization.WorkspacesClientCreateOrUpdateResponse, error)
	getFn                         func(ctx context.Context, rgName, name string, options *armdesktopvirtualization.WorkspacesClientGetOptions) (armdesktopvirtualization.WorkspacesClientGetResponse, error)
	updateFn                      func(ctx context.Context, rgName, name string, options *armdesktopvirtualization.WorkspacesClientUpdateOptions) (armdesktopvirtualization.WorkspacesClientUpdateResponse, error)
	deleteFn                      func(ctx context.Context, rgName, name string, options *armdesktopvirtualization.WorkspacesClientDeleteOptions) (armdesktopvirtualization.WorkspacesClientDeleteResponse, error)
	newListByResourceGroupPagerFn func(rgName string, options *armdesktopvirtualization.WorkspacesClientListByResourceGroupOptions) *runtime.Pager[armdesktopvirtualization.WorkspacesClientListByResourceGroupResponse]
	newListBySubscriptionPagerFn  func(options *armdesktopvirtualization.WorkspacesClientListBySubscriptionOptions) *runtime.Pager[armdesktopvirtualization.WorkspacesClientListBySubscriptionResponse]
}

func (f *fakeAvdWorkspacesAPI) CreateOrUpdate(ctx context.Context, rgName, name string, params armdesktopvirtualization.Workspace, options *armdesktopvirtualization.WorkspacesClientCreateOrUpdateOptions) (armdesktopvirtualization.WorkspacesClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, name, params, options)
}

func (f *fakeAvdWorkspacesAPI) Get(ctx context.Context, rgName, name string, options *armdesktopvirtualization.WorkspacesClientGetOptions) (armdesktopvirtualization.WorkspacesClientGetResponse, error) {
	return f.getFn(ctx, rgName, name, options)
}

func (f *fakeAvdWorkspacesAPI) Update(ctx context.Context, rgName, name string, options *armdesktopvirtualization.WorkspacesClientUpdateOptions) (armdesktopvirtualization.WorkspacesClientUpdateResponse, error) {
	return f.updateFn(ctx, rgName, name, options)
}

func (f *fakeAvdWorkspacesAPI) Delete(ctx context.Context, rgName, name string, options *armdesktopvirtualization.WorkspacesClientDeleteOptions) (armdesktopvirtualization.WorkspacesClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, name, options)
}

func (f *fakeAvdWorkspacesAPI) NewListByResourceGroupPager(rgName string, options *armdesktopvirtualization.WorkspacesClientListByResourceGroupOptions) *runtime.Pager[armdesktopvirtualization.WorkspacesClientListByResourceGroupResponse] {
	return f.newListByResourceGroupPagerFn(rgName, options)
}

func (f *fakeAvdWorkspacesAPI) NewListBySubscriptionPager(options *armdesktopvirtualization.WorkspacesClientListBySubscriptionOptions) *runtime.Pager[armdesktopvirtualization.WorkspacesClientListBySubscriptionResponse] {
	return f.newListBySubscriptionPagerFn(options)
}
