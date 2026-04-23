// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v4"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testNICNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/networkInterfaces/my-nic"

func TestNetworkInterface_CRUD(t *testing.T) {
	allocMethod := armnetwork.IPAllocationMethodDynamic
	fake := &fakeNetworkInterfacesAPI{
		beginCreateOrUpdateFn: func(_ context.Context, _, _ string, _ armnetwork.Interface, _ *armnetwork.InterfacesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.InterfacesClientCreateOrUpdateResponse], error) {
			return newDoneCreateNICPoller(armnetwork.InterfacesClientCreateOrUpdateResponse{
				Interface: armnetwork.Interface{
					ID:       to.Ptr(testNICNativeID),
					Name:     to.Ptr("my-nic"),
					Location: to.Ptr("eastus"),
					Properties: &armnetwork.InterfacePropertiesFormat{
						IPConfigurations: []*armnetwork.InterfaceIPConfiguration{
							{
								Name: to.Ptr("ipconfig1"),
								Properties: &armnetwork.InterfaceIPConfigurationPropertiesFormat{
									PrivateIPAllocationMethod: &allocMethod,
									Primary:                  to.Ptr(true),
									Subnet: &armnetwork.Subnet{
										ID: to.Ptr("/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/virtualNetworks/vnet-1/subnets/default"),
									},
								},
							},
						},
						EnableAcceleratedNetworking: to.Ptr(false),
						EnableIPForwarding:          to.Ptr(false),
					},
				},
			}), nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armnetwork.InterfacesClientGetOptions) (armnetwork.InterfacesClientGetResponse, error) {
			return armnetwork.InterfacesClientGetResponse{
				Interface: armnetwork.Interface{
					ID:       to.Ptr(testNICNativeID),
					Name:     to.Ptr("my-nic"),
					Location: to.Ptr("eastus"),
					Properties: &armnetwork.InterfacePropertiesFormat{
						IPConfigurations: []*armnetwork.InterfaceIPConfiguration{
							{
								Name: to.Ptr("ipconfig1"),
								Properties: &armnetwork.InterfaceIPConfigurationPropertiesFormat{
									PrivateIPAllocationMethod: &allocMethod,
									Primary:                  to.Ptr(true),
									Subnet: &armnetwork.Subnet{
										ID: to.Ptr("/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/virtualNetworks/vnet-1/subnets/default"),
									},
								},
							},
						},
						EnableAcceleratedNetworking: to.Ptr(false),
						EnableIPForwarding:          to.Ptr(false),
					},
				},
			}, nil
		},
		beginDeleteFn: func(_ context.Context, _, _ string, _ *armnetwork.InterfacesClientBeginDeleteOptions) (*runtime.Poller[armnetwork.InterfacesClientDeleteResponse], error) {
			return newDoneDeleteNICPoller(armnetwork.InterfacesClientDeleteResponse{}), nil
		},
		newListPagerFn: func(_ string, _ *armnetwork.InterfacesClientListOptions) *runtime.Pager[armnetwork.InterfacesClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armnetwork.InterfacesClientListResponse]{
				More: func(_ armnetwork.InterfacesClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armnetwork.InterfacesClientListResponse) (armnetwork.InterfacesClientListResponse, error) {
					return armnetwork.InterfacesClientListResponse{
						InterfaceListResult: armnetwork.InterfaceListResult{
							Value: []*armnetwork.Interface{{ID: to.Ptr(testNICNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestNetworkInterface(fake)

	t.Run("Create", func(t *testing.T) {
		props, _ := json.Marshal(map[string]interface{}{
			"resourceGroupName": "rg-1", "location": "eastus", "name": "my-nic",
			"ipConfigurations": []map[string]interface{}{
				{"name": "ipconfig1", "subnet": "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/virtualNetworks/vnet-1/subnets/default"},
			},
		})
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testNICNativeID, got.ProgressResult.NativeID)
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testNICNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
		var props map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "my-nic", props["name"])
	})

	t.Run("Delete", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testNICNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _ string, _ *armnetwork.InterfacesClientBeginDeleteOptions) (*runtime.Poller[armnetwork.InterfacesClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testNICNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 1)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, _ armnetwork.Interface, _ *armnetwork.InterfacesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.InterfacesClientCreateOrUpdateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 403}
		}
		props, _ := json.Marshal(map[string]interface{}{
			"resourceGroupName": "rg-1", "location": "eastus", "name": "x",
			"ipConfigurations": []map[string]interface{}{
				{"name": "ipconfig1", "subnet": "/subs/sub-1/rg/rg-1/vnet/v/subnets/s"},
			},
		})
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

// --- Test helpers ---

func newTestNetworkInterface(api networkInterfacesAPI) *NetworkInterface {
	return &NetworkInterface{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

// nicDoneHandler is a PollingHandler that reports Done() immediately and populates
// out from the stored response on Result().
type nicDoneHandler[T any] struct {
	resp T
}

func (h *nicDoneHandler[T]) Done() bool                                     { return true }
func (h *nicDoneHandler[T]) Poll(_ context.Context) (*http.Response, error) { return nil, nil }
func (h *nicDoneHandler[T]) Result(_ context.Context, out *T) error         { *out = h.resp; return nil }

func newDoneCreateNICPoller(resp armnetwork.InterfacesClientCreateOrUpdateResponse) *runtime.Poller[armnetwork.InterfacesClientCreateOrUpdateResponse] {
	p, err := runtime.NewPoller[armnetwork.InterfacesClientCreateOrUpdateResponse](nil, runtime.Pipeline{}, &runtime.NewPollerOptions[armnetwork.InterfacesClientCreateOrUpdateResponse]{
		Handler: &nicDoneHandler[armnetwork.InterfacesClientCreateOrUpdateResponse]{resp: resp},
	})
	if err != nil {
		panic(err)
	}
	return p
}

func newDoneDeleteNICPoller(resp armnetwork.InterfacesClientDeleteResponse) *runtime.Poller[armnetwork.InterfacesClientDeleteResponse] {
	p, err := runtime.NewPoller[armnetwork.InterfacesClientDeleteResponse](nil, runtime.Pipeline{}, &runtime.NewPollerOptions[armnetwork.InterfacesClientDeleteResponse]{
		Handler: &nicDoneHandler[armnetwork.InterfacesClientDeleteResponse]{resp: resp},
	})
	if err != nil {
		panic(err)
	}
	return p
}

type fakeNetworkInterfacesAPI struct {
	beginCreateOrUpdateFn  func(ctx context.Context, resourceGroupName string, networkInterfaceName string, parameters armnetwork.Interface, options *armnetwork.InterfacesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.InterfacesClientCreateOrUpdateResponse], error)
	getFn                  func(ctx context.Context, resourceGroupName string, networkInterfaceName string, options *armnetwork.InterfacesClientGetOptions) (armnetwork.InterfacesClientGetResponse, error)
	beginDeleteFn          func(ctx context.Context, resourceGroupName string, networkInterfaceName string, options *armnetwork.InterfacesClientBeginDeleteOptions) (*runtime.Poller[armnetwork.InterfacesClientDeleteResponse], error)
	newListPagerFn         func(resourceGroupName string, options *armnetwork.InterfacesClientListOptions) *runtime.Pager[armnetwork.InterfacesClientListResponse]
	resumeCreateOrUpdateFn func(token string) (*runtime.Poller[armnetwork.InterfacesClientCreateOrUpdateResponse], error)
	resumeDeleteFn         func(token string) (*runtime.Poller[armnetwork.InterfacesClientDeleteResponse], error)
}

func (f *fakeNetworkInterfacesAPI) BeginCreateOrUpdate(ctx context.Context, resourceGroupName string, networkInterfaceName string, parameters armnetwork.Interface, options *armnetwork.InterfacesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.InterfacesClientCreateOrUpdateResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, resourceGroupName, networkInterfaceName, parameters, options)
}

func (f *fakeNetworkInterfacesAPI) Get(ctx context.Context, resourceGroupName string, networkInterfaceName string, options *armnetwork.InterfacesClientGetOptions) (armnetwork.InterfacesClientGetResponse, error) {
	return f.getFn(ctx, resourceGroupName, networkInterfaceName, options)
}

func (f *fakeNetworkInterfacesAPI) BeginDelete(ctx context.Context, resourceGroupName string, networkInterfaceName string, options *armnetwork.InterfacesClientBeginDeleteOptions) (*runtime.Poller[armnetwork.InterfacesClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, resourceGroupName, networkInterfaceName, options)
}

func (f *fakeNetworkInterfacesAPI) NewListPager(resourceGroupName string, options *armnetwork.InterfacesClientListOptions) *runtime.Pager[armnetwork.InterfacesClientListResponse] {
	return f.newListPagerFn(resourceGroupName, options)
}

func (f *fakeNetworkInterfacesAPI) ResumeCreateOrUpdatePoller(token string) (*runtime.Poller[armnetwork.InterfacesClientCreateOrUpdateResponse], error) {
	return f.resumeCreateOrUpdateFn(token)
}

func (f *fakeNetworkInterfacesAPI) ResumeDeletePoller(token string) (*runtime.Poller[armnetwork.InterfacesClientDeleteResponse], error) {
	return f.resumeDeleteFn(token)
}
