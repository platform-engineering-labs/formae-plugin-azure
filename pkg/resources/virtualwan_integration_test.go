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

const testVirtualWanNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/virtualWans/vwan1"

type fakeVirtualWansAPI struct {
	beginCreateOrUpdateFn         func(ctx context.Context, rgName, name string, params armnetwork.VirtualWAN, options *armnetwork.VirtualWansClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.VirtualWansClientCreateOrUpdateResponse], error)
	getFn                         func(ctx context.Context, rgName, name string, options *armnetwork.VirtualWansClientGetOptions) (armnetwork.VirtualWansClientGetResponse, error)
	beginDeleteFn                 func(ctx context.Context, rgName, name string, options *armnetwork.VirtualWansClientBeginDeleteOptions) (*runtime.Poller[armnetwork.VirtualWansClientDeleteResponse], error)
	newListByResourceGroupPagerFn func(rgName string, options *armnetwork.VirtualWansClientListByResourceGroupOptions) *runtime.Pager[armnetwork.VirtualWansClientListByResourceGroupResponse]
	newListPagerFn                func(options *armnetwork.VirtualWansClientListOptions) *runtime.Pager[armnetwork.VirtualWansClientListResponse]
}

func (f *fakeVirtualWansAPI) BeginCreateOrUpdate(ctx context.Context, rgName, name string, params armnetwork.VirtualWAN, options *armnetwork.VirtualWansClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.VirtualWansClientCreateOrUpdateResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, rgName, name, params, options)
}

func (f *fakeVirtualWansAPI) Get(ctx context.Context, rgName, name string, options *armnetwork.VirtualWansClientGetOptions) (armnetwork.VirtualWansClientGetResponse, error) {
	return f.getFn(ctx, rgName, name, options)
}

func (f *fakeVirtualWansAPI) BeginDelete(ctx context.Context, rgName, name string, options *armnetwork.VirtualWansClientBeginDeleteOptions) (*runtime.Poller[armnetwork.VirtualWansClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, name, options)
}

func (f *fakeVirtualWansAPI) NewListByResourceGroupPager(rgName string, options *armnetwork.VirtualWansClientListByResourceGroupOptions) *runtime.Pager[armnetwork.VirtualWansClientListByResourceGroupResponse] {
	return f.newListByResourceGroupPagerFn(rgName, options)
}

func (f *fakeVirtualWansAPI) NewListPager(options *armnetwork.VirtualWansClientListOptions) *runtime.Pager[armnetwork.VirtualWansClientListResponse] {
	return f.newListPagerFn(options)
}

func newTestVirtualWan(api virtualWansAPI) *VirtualWan {
	return &VirtualWan{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func virtualWanDesired(branchToBranch bool) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":                       "vwan1",
		"resourceGroupName":          "rg-1",
		"location":                   "eastus",
		"virtualWanTier":             "Standard",
		"disableVpnEncryption":       false,
		"allowBranchToBranchTraffic": branchToBranch,
		"allowVnetToVnetTraffic":     false,
		"Tags":                       []any{map[string]any{"Key": "env", "Value": "test"}},
	})
	return out
}

func TestVirtualWan_CRUD(t *testing.T) {
	wanResult := armnetwork.VirtualWAN{
		ID:       to.Ptr(testVirtualWanNativeID),
		Name:     to.Ptr("vwan1"),
		Location: to.Ptr("East US"),
		Properties: &armnetwork.VirtualWanProperties{
			// ARM echoes the tier lower-cased on some API versions.
			Type:                       to.Ptr("standard"),
			DisableVPNEncryption:       to.Ptr(false),
			AllowBranchToBranchTraffic: to.Ptr(true),
			AllowVnetToVnetTraffic:     to.Ptr(false),
			ProvisioningState:          to.Ptr(armnetwork.ProvisioningStateSucceeded),
			// Back-references owned by the hub / site resources.
			VirtualHubs: []*armnetwork.SubResource{{ID: to.Ptr("/subscriptions/sub-1/hub")}},
			VPNSites:    []*armnetwork.SubResource{{ID: to.Ptr("/subscriptions/sub-1/site")}},
		},
		Tags: map[string]*string{"env": to.Ptr("test")},
		Etag: to.Ptr("W/\"etag\""),
	}

	var sent armnetwork.VirtualWAN
	createCalls := 0
	deleteCalls := 0
	fake := &fakeVirtualWansAPI{
		beginCreateOrUpdateFn: func(_ context.Context, rgName, name string, params armnetwork.VirtualWAN, _ *armnetwork.VirtualWansClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.VirtualWansClientCreateOrUpdateResponse], error) {
			require.Equal(t, "rg-1", rgName)
			require.Equal(t, "vwan1", name)
			sent = params
			createCalls++
			return newDonePoller(armnetwork.VirtualWansClientCreateOrUpdateResponse{VirtualWAN: wanResult}), nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armnetwork.VirtualWansClientGetOptions) (armnetwork.VirtualWansClientGetResponse, error) {
			return armnetwork.VirtualWansClientGetResponse{VirtualWAN: wanResult}, nil
		},
		beginDeleteFn: func(_ context.Context, _, _ string, _ *armnetwork.VirtualWansClientBeginDeleteOptions) (*runtime.Poller[armnetwork.VirtualWansClientDeleteResponse], error) {
			deleteCalls++
			return newDonePoller(armnetwork.VirtualWansClientDeleteResponse{}), nil
		},
		newListByResourceGroupPagerFn: func(_ string, _ *armnetwork.VirtualWansClientListByResourceGroupOptions) *runtime.Pager[armnetwork.VirtualWansClientListByResourceGroupResponse] {
			return runtime.NewPager(runtime.PagingHandler[armnetwork.VirtualWansClientListByResourceGroupResponse]{
				More: func(_ armnetwork.VirtualWansClientListByResourceGroupResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armnetwork.VirtualWansClientListByResourceGroupResponse) (armnetwork.VirtualWansClientListByResourceGroupResponse, error) {
					return armnetwork.VirtualWansClientListByResourceGroupResponse{
						ListVirtualWANsResult: armnetwork.ListVirtualWANsResult{
							Value: []*armnetwork.VirtualWAN{{ID: to.Ptr(testVirtualWanNativeID)}},
						},
					}, nil
				},
			})
		},
		newListPagerFn: func(_ *armnetwork.VirtualWansClientListOptions) *runtime.Pager[armnetwork.VirtualWansClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armnetwork.VirtualWansClientListResponse]{
				More: func(_ armnetwork.VirtualWansClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armnetwork.VirtualWansClientListResponse) (armnetwork.VirtualWansClientListResponse, error) {
					return armnetwork.VirtualWansClientListResponse{
						ListVirtualWANsResult: armnetwork.ListVirtualWANsResult{
							Value: []*armnetwork.VirtualWAN{{ID: to.Ptr(testVirtualWanNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestVirtualWan(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "vwan1", Properties: virtualWanDesired(true),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testVirtualWanNativeID, got.ProgressResult.NativeID)

		require.Equal(t, "eastus", *sent.Location)
		require.Equal(t, "Standard", *sent.Properties.Type)
		require.False(t, *sent.Properties.DisableVPNEncryption)
		require.True(t, *sent.Properties.AllowBranchToBranchTraffic)
		require.False(t, *sent.Properties.AllowVnetToVnetTraffic)
		require.Equal(t, "test", *sent.Tags["env"])
	})

	t.Run("Create_requires_resource_group", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "vwan1", "location": "eastus"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "resourceGroupName is required")
	})

	t.Run("Create_requires_location", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "vwan1", "resourceGroupName": "rg-1"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "location is required")
	})

	// The native ID reported while the LRO is still running must match the path ARM
	// actually assigns, or the resource is orphaned once it completes.
	t.Run("PendingCreateReportsRealNativeID", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, _ armnetwork.VirtualWAN, _ *armnetwork.VirtualWansClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.VirtualWansClientCreateOrUpdateResponse], error) {
			return newPendingPoller[armnetwork.VirtualWansClientCreateOrUpdateResponse](), nil
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "vwan1", Properties: virtualWanDesired(true),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusInProgress, got.ProgressResult.OperationStatus)
		require.Equal(t, testVirtualWanNativeID, got.ProgressResult.NativeID)
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testVirtualWanNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "vwan1", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		// ARM returns "East US"; read must normalise or desired state drifts.
		require.Equal(t, "eastus", props["location"])
		// ARM returns "standard"; the schema union is "Standard".
		require.Equal(t, "Standard", props["virtualWanTier"])
		require.Equal(t, false, props["disableVpnEncryption"])
		require.Equal(t, true, props["allowBranchToBranchTraffic"])
		require.Equal(t, false, props["allowVnetToVnetTraffic"])
	})

	// Service state and the hub/site back-references would read as drift forever.
	t.Run("Read_drops_service_state", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testVirtualWanNativeID})
		require.NoError(t, err)
		for _, key := range []string{"provisioningState", "etag", "virtualHubs", "vpnSites", "office365LocalBreakoutCategory"} {
			require.NotContains(t, got.Properties, key)
		}
	})

	t.Run("Update_reissues_create_or_update", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, params armnetwork.VirtualWAN, _ *armnetwork.VirtualWansClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.VirtualWansClientCreateOrUpdateResponse], error) {
			sent = params
			createCalls++
			return newDonePoller(armnetwork.VirtualWansClientCreateOrUpdateResponse{VirtualWAN: wanResult}), nil
		}
		before := createCalls
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testVirtualWanNativeID,
			DesiredProperties: virtualWanDesired(false),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, createCalls)
		require.False(t, *sent.Properties.AllowBranchToBranchTraffic)
		// Location must ride along: a PUT without it is rejected.
		require.Equal(t, "eastus", *sent.Location)
	})

	t.Run("Delete", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testVirtualWanNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _ string, _ *armnetwork.VirtualWansClientBeginDeleteOptions) (*runtime.Poller[armnetwork.VirtualWansClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testVirtualWanNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_resource_group", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testVirtualWanNativeID}, got.NativeIDs)
	})

	t.Run("List_by_subscription", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Equal(t, []string{testVirtualWanNativeID}, got.NativeIDs)
	})

	t.Run("Read_NotFound", func(t *testing.T) {
		fake.getFn = func(_ context.Context, _, _ string, _ *armnetwork.VirtualWansClientGetOptions) (armnetwork.VirtualWansClientGetResponse, error) {
			return armnetwork.VirtualWansClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testVirtualWanNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
	})
}
