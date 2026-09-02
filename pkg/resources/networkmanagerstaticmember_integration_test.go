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

const (
	testStaticMemberNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/networkManagers/nm-1/networkGroups/group-1/staticMembers/member-1"
	testStaticMemberVnetID   = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/virtualNetworks/vnet-1"
)

func newTestNetworkManagerStaticMember(api networkManagerStaticMembersAPI) *NetworkManagerStaticMember {
	return &NetworkManagerStaticMember{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

func staticMemberDesired(vnetID string) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":               "member-1",
		"resourceGroupName":  "rg-1",
		"networkManagerName": "nm-1",
		"networkGroupName":   "group-1",
		"resourceId":         vnetID,
	})
	return out
}

func TestNetworkManagerStaticMember_CRUD(t *testing.T) {
	memberResult := armnetwork.StaticMember{
		ID:   to.Ptr(testStaticMemberNativeID),
		Name: to.Ptr("member-1"),
		Properties: &armnetwork.StaticMemberProperties{
			ResourceID:        to.Ptr(testStaticMemberVnetID),
			Region:            to.Ptr("eastus"),
			ProvisioningState: to.Ptr(armnetwork.ProvisioningStateSucceeded),
		},
	}

	var sent armnetwork.StaticMember
	var sawManager, sawGroup string
	deleteCalls := 0
	fake := &fakeNetworkManagerStaticMembersAPI{
		createOrUpdateFn: func(_ context.Context, rgName, managerName, groupName, name string, params armnetwork.StaticMember, _ *armnetwork.StaticMembersClientCreateOrUpdateOptions) (armnetwork.StaticMembersClientCreateOrUpdateResponse, error) {
			require.Equal(t, "rg-1", rgName)
			require.Equal(t, "member-1", name)
			sawManager = managerName
			sawGroup = groupName
			sent = params
			return armnetwork.StaticMembersClientCreateOrUpdateResponse{StaticMember: memberResult}, nil
		},
		getFn: func(_ context.Context, _, _, _, _ string, _ *armnetwork.StaticMembersClientGetOptions) (armnetwork.StaticMembersClientGetResponse, error) {
			return armnetwork.StaticMembersClientGetResponse{StaticMember: memberResult}, nil
		},
		deleteFn: func(_ context.Context, _, _, _, _ string, _ *armnetwork.StaticMembersClientDeleteOptions) (armnetwork.StaticMembersClientDeleteResponse, error) {
			deleteCalls++
			return armnetwork.StaticMembersClientDeleteResponse{}, nil
		},
		newListPagerFn: func(_, _, _ string, _ *armnetwork.StaticMembersClientListOptions) *runtime.Pager[armnetwork.StaticMembersClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armnetwork.StaticMembersClientListResponse]{
				More: func(_ armnetwork.StaticMembersClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armnetwork.StaticMembersClientListResponse) (armnetwork.StaticMembersClientListResponse, error) {
					return armnetwork.StaticMembersClientListResponse{
						StaticMemberListResult: armnetwork.StaticMemberListResult{
							Value: []*armnetwork.StaticMember{{ID: to.Ptr(testStaticMemberNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestNetworkManagerStaticMember(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "member-1",
			Properties: staticMemberDesired(testStaticMemberVnetID),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testStaticMemberNativeID, got.ProgressResult.NativeID)
		require.Equal(t, "nm-1", sawManager)
		require.Equal(t, "group-1", sawGroup)
		require.Equal(t, testStaticMemberVnetID, *sent.Properties.ResourceID)
	})

	t.Run("Create_requires_group", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "member-1", "resourceGroupName": "rg-1", "networkManagerName": "nm-1",
			"resourceId": testStaticMemberVnetID,
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "networkGroupName is required")
	})

	t.Run("Create_requires_resource_id", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "member-1", "resourceGroupName": "rg-1",
			"networkManagerName": "nm-1", "networkGroupName": "group-1",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "resourceId is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testStaticMemberNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "member-1", props["name"])
		// All three parents come from the native ID, not the response body.
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "nm-1", props["networkManagerName"])
		require.Equal(t, "group-1", props["networkGroupName"])
		require.Equal(t, testStaticMemberVnetID, props["resourceId"])
	})

	// region is derived by the service from the target virtual network, so it is
	// dropped rather than surfaced as state nobody declared.
	t.Run("Read_drops_service_owned_fields", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testStaticMemberNativeID})
		require.NoError(t, err)
		require.NotContains(t, got.Properties, "region")
		require.NotContains(t, got.Properties, "provisioningState")
	})

	t.Run("Update_reissues_create_or_update", func(t *testing.T) {
		other := "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/virtualNetworks/vnet-2"
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testStaticMemberNativeID,
			DesiredProperties: staticMemberDesired(other),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, other, *sent.Properties.ResourceID)
	})

	// StaticMembersClient.Delete is synchronous — there is no BeginDelete — so no
	// poller is ever created.
	t.Run("Delete", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testStaticMemberNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _, _, _ string, _ *armnetwork.StaticMembersClientDeleteOptions) (armnetwork.StaticMembersClientDeleteResponse, error) {
			return armnetwork.StaticMembersClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testStaticMemberNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_group", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{
				"resourceGroupName": "rg-1", "networkManagerName": "nm-1", "networkGroupName": "group-1",
			},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testStaticMemberNativeID}, got.NativeIDs)
	})

	t.Run("List_without_parents_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})

	t.Run("Status_is_success_every_verb_is_synchronous", func(t *testing.T) {
		got, err := prov.Status(context.Background(), &resource.StatusRequest{RequestID: "req-1"})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Azure_error_maps_to_failure_with_message", func(t *testing.T) {
		fake.createOrUpdateFn = func(_ context.Context, _, _, _, _ string, _ armnetwork.StaticMember, _ *armnetwork.StaticMembersClientCreateOrUpdateOptions) (armnetwork.StaticMembersClientCreateOrUpdateResponse, error) {
			return armnetwork.StaticMembersClientCreateOrUpdateResponse{}, &azcore.ResponseError{StatusCode: 409}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "member-1", Properties: staticMemberDesired(testStaticMemberVnetID),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.NotEmpty(t, got.ProgressResult.StatusMessage)
	})
}

func TestNetworkManagerStaticMember_ReadNotFound(t *testing.T) {
	fake := &fakeNetworkManagerStaticMembersAPI{
		getFn: func(_ context.Context, _, _, _, _ string, _ *armnetwork.StaticMembersClientGetOptions) (armnetwork.StaticMembersClientGetResponse, error) {
			return armnetwork.StaticMembersClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestNetworkManagerStaticMember(fake).Read(context.Background(),
		&resource.ReadRequest{NativeID: testStaticMemberNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeNetworkManagerStaticMembersAPI struct {
	createOrUpdateFn func(ctx context.Context, rgName, managerName, groupName, name string, params armnetwork.StaticMember, options *armnetwork.StaticMembersClientCreateOrUpdateOptions) (armnetwork.StaticMembersClientCreateOrUpdateResponse, error)
	getFn            func(ctx context.Context, rgName, managerName, groupName, name string, options *armnetwork.StaticMembersClientGetOptions) (armnetwork.StaticMembersClientGetResponse, error)
	deleteFn         func(ctx context.Context, rgName, managerName, groupName, name string, options *armnetwork.StaticMembersClientDeleteOptions) (armnetwork.StaticMembersClientDeleteResponse, error)
	newListPagerFn   func(rgName, managerName, groupName string, options *armnetwork.StaticMembersClientListOptions) *runtime.Pager[armnetwork.StaticMembersClientListResponse]
}

func (f *fakeNetworkManagerStaticMembersAPI) CreateOrUpdate(ctx context.Context, rgName, managerName, groupName, name string, params armnetwork.StaticMember, options *armnetwork.StaticMembersClientCreateOrUpdateOptions) (armnetwork.StaticMembersClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, managerName, groupName, name, params, options)
}

func (f *fakeNetworkManagerStaticMembersAPI) Get(ctx context.Context, rgName, managerName, groupName, name string, options *armnetwork.StaticMembersClientGetOptions) (armnetwork.StaticMembersClientGetResponse, error) {
	return f.getFn(ctx, rgName, managerName, groupName, name, options)
}

func (f *fakeNetworkManagerStaticMembersAPI) Delete(ctx context.Context, rgName, managerName, groupName, name string, options *armnetwork.StaticMembersClientDeleteOptions) (armnetwork.StaticMembersClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, managerName, groupName, name, options)
}

func (f *fakeNetworkManagerStaticMembersAPI) NewListPager(rgName, managerName, groupName string, options *armnetwork.StaticMembersClientListOptions) *runtime.Pager[armnetwork.StaticMembersClientListResponse] {
	return f.newListPagerFn(rgName, managerName, groupName, options)
}
