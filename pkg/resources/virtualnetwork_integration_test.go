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

const testVNetNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/virtualNetworks/vnet-1"

func TestVirtualNetwork_CRUD(t *testing.T) {
	fake := &fakeVirtualNetworksAPI{
		beginCreateOrUpdateFn: func(_ context.Context, _, _ string, _ armnetwork.VirtualNetwork, _ *armnetwork.VirtualNetworksClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.VirtualNetworksClientCreateOrUpdateResponse], error) {
			return newDonePoller(armnetwork.VirtualNetworksClientCreateOrUpdateResponse{
				VirtualNetwork: armnetwork.VirtualNetwork{
					ID:       to.Ptr(testVNetNativeID),
					Name:     to.Ptr("vnet-1"),
					Location: to.Ptr("eastus"),
					Properties: &armnetwork.VirtualNetworkPropertiesFormat{
						AddressSpace: &armnetwork.AddressSpace{
							AddressPrefixes: []*string{to.Ptr("10.0.0.0/16")},
						},
					},
				},
			}), nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armnetwork.VirtualNetworksClientGetOptions) (armnetwork.VirtualNetworksClientGetResponse, error) {
			return armnetwork.VirtualNetworksClientGetResponse{
				VirtualNetwork: armnetwork.VirtualNetwork{
					ID:       to.Ptr(testVNetNativeID),
					Name:     to.Ptr("vnet-1"),
					Location: to.Ptr("eastus"),
					Properties: &armnetwork.VirtualNetworkPropertiesFormat{
						AddressSpace: &armnetwork.AddressSpace{
							AddressPrefixes: []*string{to.Ptr("10.0.0.0/16")},
						},
					},
				},
			}, nil
		},
		beginDeleteFn: func(_ context.Context, _, _ string, _ *armnetwork.VirtualNetworksClientBeginDeleteOptions) (*runtime.Poller[armnetwork.VirtualNetworksClientDeleteResponse], error) {
			return newInProgressPoller[armnetwork.VirtualNetworksClientDeleteResponse](), nil
		},
		newListAllPagerFn: func(_ *armnetwork.VirtualNetworksClientListAllOptions) *runtime.Pager[armnetwork.VirtualNetworksClientListAllResponse] {
			return runtime.NewPager(runtime.PagingHandler[armnetwork.VirtualNetworksClientListAllResponse]{
				More: func(_ armnetwork.VirtualNetworksClientListAllResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armnetwork.VirtualNetworksClientListAllResponse) (armnetwork.VirtualNetworksClientListAllResponse, error) {
					return armnetwork.VirtualNetworksClientListAllResponse{
						VirtualNetworkListResult: armnetwork.VirtualNetworkListResult{
							Value: []*armnetwork.VirtualNetwork{{ID: to.Ptr(testVNetNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestVirtualNetwork(fake)

	t.Run("Create", func(t *testing.T) {
		props, _ := json.Marshal(map[string]interface{}{
			"resourceGroupName": "rg-1", "name": "vnet-1", "location": "eastus",
			"addressSpace": map[string]interface{}{"addressPrefixes": []string{"10.0.0.0/16"}},
		})
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testVNetNativeID, got.ProgressResult.NativeID)
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testVNetNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
		var props map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "vnet-1", props["name"])
	})

	t.Run("Delete", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testVNetNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusInProgress, got.ProgressResult.OperationStatus)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _ string, _ *armnetwork.VirtualNetworksClientBeginDeleteOptions) (*runtime.Poller[armnetwork.VirtualNetworksClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testVNetNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{},
		})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 1)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, _ armnetwork.VirtualNetwork, _ *armnetwork.VirtualNetworksClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.VirtualNetworksClientCreateOrUpdateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 403}
		}
		props, _ := json.Marshal(map[string]interface{}{
			"resourceGroupName": "rg-1", "name": "vnet-1", "location": "eastus",
			"addressSpace": map[string]interface{}{"addressPrefixes": []string{"10.0.0.0/16"}},
		})
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

// --- Test helpers ---

func newTestVirtualNetwork(api virtualNetworksAPI) *VirtualNetwork {
	return &VirtualNetwork{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

type fakeVirtualNetworksAPI struct {
	beginCreateOrUpdateFn func(ctx context.Context, rgName, vnetName string, params armnetwork.VirtualNetwork, opts *armnetwork.VirtualNetworksClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.VirtualNetworksClientCreateOrUpdateResponse], error)
	getFn                 func(ctx context.Context, rgName, vnetName string, opts *armnetwork.VirtualNetworksClientGetOptions) (armnetwork.VirtualNetworksClientGetResponse, error)
	beginDeleteFn         func(ctx context.Context, rgName, vnetName string, opts *armnetwork.VirtualNetworksClientBeginDeleteOptions) (*runtime.Poller[armnetwork.VirtualNetworksClientDeleteResponse], error)
	newListPagerFn        func(rgName string, opts *armnetwork.VirtualNetworksClientListOptions) *runtime.Pager[armnetwork.VirtualNetworksClientListResponse]
	newListAllPagerFn     func(opts *armnetwork.VirtualNetworksClientListAllOptions) *runtime.Pager[armnetwork.VirtualNetworksClientListAllResponse]
	resumeCreatePollerFn  func(token string) (*runtime.Poller[armnetwork.VirtualNetworksClientCreateOrUpdateResponse], error)
	resumeDeletePollerFn  func(token string) (*runtime.Poller[armnetwork.VirtualNetworksClientDeleteResponse], error)
}

func (f *fakeVirtualNetworksAPI) BeginCreateOrUpdate(ctx context.Context, rgName, vnetName string, params armnetwork.VirtualNetwork, opts *armnetwork.VirtualNetworksClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.VirtualNetworksClientCreateOrUpdateResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, rgName, vnetName, params, opts)
}

func (f *fakeVirtualNetworksAPI) Get(ctx context.Context, rgName, vnetName string, opts *armnetwork.VirtualNetworksClientGetOptions) (armnetwork.VirtualNetworksClientGetResponse, error) {
	return f.getFn(ctx, rgName, vnetName, opts)
}

func (f *fakeVirtualNetworksAPI) BeginDelete(ctx context.Context, rgName, vnetName string, opts *armnetwork.VirtualNetworksClientBeginDeleteOptions) (*runtime.Poller[armnetwork.VirtualNetworksClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, vnetName, opts)
}

func (f *fakeVirtualNetworksAPI) NewListPager(rgName string, opts *armnetwork.VirtualNetworksClientListOptions) *runtime.Pager[armnetwork.VirtualNetworksClientListResponse] {
	return f.newListPagerFn(rgName, opts)
}

func (f *fakeVirtualNetworksAPI) NewListAllPager(opts *armnetwork.VirtualNetworksClientListAllOptions) *runtime.Pager[armnetwork.VirtualNetworksClientListAllResponse] {
	return f.newListAllPagerFn(opts)
}

func (f *fakeVirtualNetworksAPI) ResumeCreatePoller(token string) (*runtime.Poller[armnetwork.VirtualNetworksClientCreateOrUpdateResponse], error) {
	return f.resumeCreatePollerFn(token)
}

func (f *fakeVirtualNetworksAPI) ResumeDeletePoller(token string) (*runtime.Poller[armnetwork.VirtualNetworksClientDeleteResponse], error) {
	return f.resumeDeletePollerFn(token)
}
