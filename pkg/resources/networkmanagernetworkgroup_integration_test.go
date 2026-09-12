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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v4"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testNetworkGroupNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/networkManagers/nm-1/networkGroups/group-1"

func newTestNetworkManagerNetworkGroup(api networkManagerGroupsAPI) *NetworkManagerNetworkGroup {
	return &NetworkManagerNetworkGroup{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

func networkGroupDesired(description string) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":               "group-1",
		"resourceGroupName":  "rg-1",
		"networkManagerName": "nm-1",
		"description":        description,
	})
	return out
}

func TestNetworkManagerNetworkGroup_CRUD(t *testing.T) {
	groupResult := armnetwork.Group{
		ID:   to.Ptr(testNetworkGroupNativeID),
		Name: to.Ptr("group-1"),
		Properties: &armnetwork.GroupProperties{
			Description:       to.Ptr("conformance"),
			ProvisioningState: to.Ptr(armnetwork.ProvisioningStateSucceeded),
			ResourceGUID:      to.Ptr("00000000-0000-0000-0000-000000000000"),
		},
	}

	var sent armnetwork.Group
	var sawManager string
	var sawForce *bool
	deleteCalls := 0
	fake := &fakeNetworkManagerGroupsAPI{
		createOrUpdateFn: func(_ context.Context, rgName, managerName, name string, params armnetwork.Group, _ *armnetwork.GroupsClientCreateOrUpdateOptions) (armnetwork.GroupsClientCreateOrUpdateResponse, error) {
			require.Equal(t, "rg-1", rgName)
			require.Equal(t, "group-1", name)
			sawManager = managerName
			sent = params
			return armnetwork.GroupsClientCreateOrUpdateResponse{Group: groupResult}, nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ *armnetwork.GroupsClientGetOptions) (armnetwork.GroupsClientGetResponse, error) {
			return armnetwork.GroupsClientGetResponse{Group: groupResult}, nil
		},
		beginDeleteFn: func(_ context.Context, _, _, _ string, options *armnetwork.GroupsClientBeginDeleteOptions) (*runtime.Poller[armnetwork.GroupsClientDeleteResponse], error) {
			deleteCalls++
			if options != nil {
				sawForce = options.Force
			}
			return newDonePoller(armnetwork.GroupsClientDeleteResponse{}), nil
		},
		newListPagerFn: func(_, _ string, _ *armnetwork.GroupsClientListOptions) *runtime.Pager[armnetwork.GroupsClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armnetwork.GroupsClientListResponse]{
				More: func(_ armnetwork.GroupsClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armnetwork.GroupsClientListResponse) (armnetwork.GroupsClientListResponse, error) {
					return armnetwork.GroupsClientListResponse{
						GroupListResult: armnetwork.GroupListResult{
							Value: []*armnetwork.Group{{ID: to.Ptr(testNetworkGroupNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestNetworkManagerNetworkGroup(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "group-1",
			Properties: networkGroupDesired("conformance"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testNetworkGroupNativeID, got.ProgressResult.NativeID)
		require.Equal(t, "nm-1", sawManager)
		require.Equal(t, "conformance", *sent.Properties.Description)
	})

	t.Run("Create_requires_manager", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "group-1", "resourceGroupName": "rg-1"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "networkManagerName is required")
	})

	t.Run("Create_requires_resource_group", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "group-1", "networkManagerName": "nm-1"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "resourceGroupName is required")
	})

	// An unset description is left out of the request entirely rather than sent
	// as an empty string.
	t.Run("Create_without_description_sends_none", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "group-1", "resourceGroupName": "rg-1", "networkManagerName": "nm-1",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.Nil(t, sent.Properties.Description)
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testNetworkGroupNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "group-1", props["name"])
		// Both parents come from the native ID, not the response body.
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "nm-1", props["networkManagerName"])
		require.Equal(t, "conformance", props["description"])
		require.NotContains(t, got.Properties, "provisioningState")
	})

	t.Run("Update", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testNetworkGroupNativeID,
			DesiredProperties: networkGroupDesired("redescribed"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, "redescribed", *sent.Properties.Description)
	})

	t.Run("Delete_sends_force", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testNetworkGroupNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
		require.NotNil(t, sawForce)
		require.True(t, *sawForce)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _, _ string, _ *armnetwork.GroupsClientBeginDeleteOptions) (*runtime.Poller[armnetwork.GroupsClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testNetworkGroupNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_manager", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "networkManagerName": "nm-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testNetworkGroupNativeID}, got.NativeIDs)
	})

	t.Run("List_without_parents_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure_with_message", func(t *testing.T) {
		fake.createOrUpdateFn = func(_ context.Context, _, _, _ string, _ armnetwork.Group, _ *armnetwork.GroupsClientCreateOrUpdateOptions) (armnetwork.GroupsClientCreateOrUpdateResponse, error) {
			return armnetwork.GroupsClientCreateOrUpdateResponse{}, &azcore.ResponseError{StatusCode: 409}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "group-1", Properties: networkGroupDesired("conformance"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.NotEmpty(t, got.ProgressResult.StatusMessage)
	})
}

func TestNetworkManagerNetworkGroup_ReadNotFound(t *testing.T) {
	fake := &fakeNetworkManagerGroupsAPI{
		getFn: func(_ context.Context, _, _, _ string, _ *armnetwork.GroupsClientGetOptions) (armnetwork.GroupsClientGetResponse, error) {
			return armnetwork.GroupsClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestNetworkManagerNetworkGroup(fake).Read(context.Background(),
		&resource.ReadRequest{NativeID: testNetworkGroupNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeNetworkManagerGroupsAPI struct {
	createOrUpdateFn func(ctx context.Context, rgName, managerName, name string, params armnetwork.Group, options *armnetwork.GroupsClientCreateOrUpdateOptions) (armnetwork.GroupsClientCreateOrUpdateResponse, error)
	getFn            func(ctx context.Context, rgName, managerName, name string, options *armnetwork.GroupsClientGetOptions) (armnetwork.GroupsClientGetResponse, error)
	beginDeleteFn    func(ctx context.Context, rgName, managerName, name string, options *armnetwork.GroupsClientBeginDeleteOptions) (*runtime.Poller[armnetwork.GroupsClientDeleteResponse], error)
	newListPagerFn   func(rgName, managerName string, options *armnetwork.GroupsClientListOptions) *runtime.Pager[armnetwork.GroupsClientListResponse]
}

func (f *fakeNetworkManagerGroupsAPI) CreateOrUpdate(ctx context.Context, rgName, managerName, name string, params armnetwork.Group, options *armnetwork.GroupsClientCreateOrUpdateOptions) (armnetwork.GroupsClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, managerName, name, params, options)
}

func (f *fakeNetworkManagerGroupsAPI) Get(ctx context.Context, rgName, managerName, name string, options *armnetwork.GroupsClientGetOptions) (armnetwork.GroupsClientGetResponse, error) {
	return f.getFn(ctx, rgName, managerName, name, options)
}

func (f *fakeNetworkManagerGroupsAPI) BeginDelete(ctx context.Context, rgName, managerName, name string, options *armnetwork.GroupsClientBeginDeleteOptions) (*runtime.Poller[armnetwork.GroupsClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, managerName, name, options)
}

func (f *fakeNetworkManagerGroupsAPI) NewListPager(rgName, managerName string, options *armnetwork.GroupsClientListOptions) *runtime.Pager[armnetwork.GroupsClientListResponse] {
	return f.newListPagerFn(rgName, managerName, options)
}
