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

const testPIPNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/publicIPAddresses/pip-1"

func TestPublicIPAddress_CRUD(t *testing.T) {
	allocationMethod := armnetwork.IPAllocationMethodStatic

	fake := &fakePublicIPAddressesAPI{
		beginCreateOrUpdateFn: func(_ context.Context, _, _ string, _ armnetwork.PublicIPAddress, _ *armnetwork.PublicIPAddressesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.PublicIPAddressesClientCreateOrUpdateResponse], error) {
			return newDonePoller(armnetwork.PublicIPAddressesClientCreateOrUpdateResponse{
				PublicIPAddress: armnetwork.PublicIPAddress{
					ID:       to.Ptr(testPIPNativeID),
					Name:     to.Ptr("pip-1"),
					Location: to.Ptr("eastus"),
					Properties: &armnetwork.PublicIPAddressPropertiesFormat{
						PublicIPAllocationMethod: &allocationMethod,
						IPAddress:               to.Ptr("20.1.2.3"),
					},
				},
			}), nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armnetwork.PublicIPAddressesClientGetOptions) (armnetwork.PublicIPAddressesClientGetResponse, error) {
			return armnetwork.PublicIPAddressesClientGetResponse{
				PublicIPAddress: armnetwork.PublicIPAddress{
					ID:       to.Ptr(testPIPNativeID),
					Name:     to.Ptr("pip-1"),
					Location: to.Ptr("eastus"),
					Properties: &armnetwork.PublicIPAddressPropertiesFormat{
						PublicIPAllocationMethod: &allocationMethod,
						IPAddress:               to.Ptr("20.1.2.3"),
					},
				},
			}, nil
		},
		beginDeleteFn: func(_ context.Context, _, _ string, _ *armnetwork.PublicIPAddressesClientBeginDeleteOptions) (*runtime.Poller[armnetwork.PublicIPAddressesClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		},
		newListPagerFn: func(rgName string, _ *armnetwork.PublicIPAddressesClientListOptions) *runtime.Pager[armnetwork.PublicIPAddressesClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armnetwork.PublicIPAddressesClientListResponse]{
				More: func(_ armnetwork.PublicIPAddressesClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armnetwork.PublicIPAddressesClientListResponse) (armnetwork.PublicIPAddressesClientListResponse, error) {
					return armnetwork.PublicIPAddressesClientListResponse{
						PublicIPAddressListResult: armnetwork.PublicIPAddressListResult{
							Value: []*armnetwork.PublicIPAddress{
								{ID: to.Ptr(testPIPNativeID)},
								{ID: to.Ptr("/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/publicIPAddresses/pip-2")},
							},
						},
					}, nil
				},
			})
		},
		newListAllPagerFn: func(_ *armnetwork.PublicIPAddressesClientListAllOptions) *runtime.Pager[armnetwork.PublicIPAddressesClientListAllResponse] {
			return runtime.NewPager(runtime.PagingHandler[armnetwork.PublicIPAddressesClientListAllResponse]{
				More: func(_ armnetwork.PublicIPAddressesClientListAllResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armnetwork.PublicIPAddressesClientListAllResponse) (armnetwork.PublicIPAddressesClientListAllResponse, error) {
					return armnetwork.PublicIPAddressesClientListAllResponse{
						PublicIPAddressListResult: armnetwork.PublicIPAddressListResult{
							Value: []*armnetwork.PublicIPAddress{
								{ID: to.Ptr(testPIPNativeID)},
							},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestPublicIPAddress(fake)

	t.Run("Create", func(t *testing.T) {
		props, _ := json.Marshal(map[string]interface{}{
			"resourceGroupName": "rg-1",
			"name":              "pip-1",
			"location":          "eastus",
		})
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "pip-1", Properties: props})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testPIPNativeID, got.ProgressResult.NativeID)
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testPIPNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
		var props map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "pip-1", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testPIPNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 2)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, _ armnetwork.PublicIPAddress, _ *armnetwork.PublicIPAddressesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.PublicIPAddressesClientCreateOrUpdateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 403}
		}
		props, _ := json.Marshal(map[string]interface{}{
			"resourceGroupName": "rg-1",
			"name":              "pip-1",
			"location":          "eastus",
		})
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

// --- Test helpers ---

func newTestPublicIPAddress(api publicIPAddressesAPI) *PublicIPAddress {
	return &PublicIPAddress{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

type fakePublicIPAddressesAPI struct {
	beginCreateOrUpdateFn func(ctx context.Context, rgName, pipName string, params armnetwork.PublicIPAddress, opts *armnetwork.PublicIPAddressesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.PublicIPAddressesClientCreateOrUpdateResponse], error)
	getFn                 func(ctx context.Context, rgName, pipName string, opts *armnetwork.PublicIPAddressesClientGetOptions) (armnetwork.PublicIPAddressesClientGetResponse, error)
	beginDeleteFn         func(ctx context.Context, rgName, pipName string, opts *armnetwork.PublicIPAddressesClientBeginDeleteOptions) (*runtime.Poller[armnetwork.PublicIPAddressesClientDeleteResponse], error)
	newListPagerFn        func(rgName string, opts *armnetwork.PublicIPAddressesClientListOptions) *runtime.Pager[armnetwork.PublicIPAddressesClientListResponse]
	newListAllPagerFn     func(opts *armnetwork.PublicIPAddressesClientListAllOptions) *runtime.Pager[armnetwork.PublicIPAddressesClientListAllResponse]
	resumeCreatePollerFn  func(token string) (*runtime.Poller[armnetwork.PublicIPAddressesClientCreateOrUpdateResponse], error)
	resumeDeletePollerFn  func(token string) (*runtime.Poller[armnetwork.PublicIPAddressesClientDeleteResponse], error)
}

func (f *fakePublicIPAddressesAPI) BeginCreateOrUpdate(ctx context.Context, rgName, pipName string, params armnetwork.PublicIPAddress, opts *armnetwork.PublicIPAddressesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.PublicIPAddressesClientCreateOrUpdateResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, rgName, pipName, params, opts)
}

func (f *fakePublicIPAddressesAPI) Get(ctx context.Context, rgName, pipName string, opts *armnetwork.PublicIPAddressesClientGetOptions) (armnetwork.PublicIPAddressesClientGetResponse, error) {
	return f.getFn(ctx, rgName, pipName, opts)
}

func (f *fakePublicIPAddressesAPI) BeginDelete(ctx context.Context, rgName, pipName string, opts *armnetwork.PublicIPAddressesClientBeginDeleteOptions) (*runtime.Poller[armnetwork.PublicIPAddressesClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, pipName, opts)
}

func (f *fakePublicIPAddressesAPI) NewListPager(rgName string, opts *armnetwork.PublicIPAddressesClientListOptions) *runtime.Pager[armnetwork.PublicIPAddressesClientListResponse] {
	return f.newListPagerFn(rgName, opts)
}

func (f *fakePublicIPAddressesAPI) NewListAllPager(opts *armnetwork.PublicIPAddressesClientListAllOptions) *runtime.Pager[armnetwork.PublicIPAddressesClientListAllResponse] {
	return f.newListAllPagerFn(opts)
}

func (f *fakePublicIPAddressesAPI) ResumeCreatePoller(token string) (*runtime.Poller[armnetwork.PublicIPAddressesClientCreateOrUpdateResponse], error) {
	return f.resumeCreatePollerFn(token)
}

func (f *fakePublicIPAddressesAPI) ResumeDeletePoller(token string) (*runtime.Poller[armnetwork.PublicIPAddressesClientDeleteResponse], error) {
	return f.resumeDeletePollerFn(token)
}
