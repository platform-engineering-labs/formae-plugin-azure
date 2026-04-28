// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build integration

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
	testPENativeID      = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/privateEndpoints/pe-1"
	testPESubnetID      = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/virtualNetworks/vnet-1/subnets/snet-1"
	testPELinkServiceID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Storage/storageAccounts/stg1"
)

func TestPrivateEndpoint_CRUD(t *testing.T) {
	donePollerResult := armnetwork.PrivateEndpointsClientCreateOrUpdateResponse{
		PrivateEndpoint: armnetwork.PrivateEndpoint{
			ID:       to.Ptr(testPENativeID),
			Name:     to.Ptr("pe-1"),
			Location: to.Ptr("eastus"),
			Properties: &armnetwork.PrivateEndpointProperties{
				Subnet: &armnetwork.Subnet{ID: to.Ptr(testPESubnetID)},
				PrivateLinkServiceConnections: []*armnetwork.PrivateLinkServiceConnection{
					{
						Name: to.Ptr("conn-1"),
						Properties: &armnetwork.PrivateLinkServiceConnectionProperties{
							PrivateLinkServiceID: to.Ptr(testPELinkServiceID),
							GroupIDs:             []*string{to.Ptr("blob")},
						},
					},
				},
			},
		},
	}
	fake := &fakePrivateEndpointsAPI{
		beginCreateOrUpdateFn: func(_ context.Context, _, _ string, _ armnetwork.PrivateEndpoint, _ *armnetwork.PrivateEndpointsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.PrivateEndpointsClientCreateOrUpdateResponse], error) {
			return newDonePoller(donePollerResult), nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armnetwork.PrivateEndpointsClientGetOptions) (armnetwork.PrivateEndpointsClientGetResponse, error) {
			return armnetwork.PrivateEndpointsClientGetResponse{PrivateEndpoint: donePollerResult.PrivateEndpoint}, nil
		},
		beginDeleteFn: func(_ context.Context, _, _ string, _ *armnetwork.PrivateEndpointsClientBeginDeleteOptions) (*runtime.Poller[armnetwork.PrivateEndpointsClientDeleteResponse], error) {
			return newInProgressPoller[armnetwork.PrivateEndpointsClientDeleteResponse](), nil
		},
		newListBySubscriptionPagerFn: func(_ *armnetwork.PrivateEndpointsClientListBySubscriptionOptions) *runtime.Pager[armnetwork.PrivateEndpointsClientListBySubscriptionResponse] {
			return runtime.NewPager(runtime.PagingHandler[armnetwork.PrivateEndpointsClientListBySubscriptionResponse]{
				More: func(_ armnetwork.PrivateEndpointsClientListBySubscriptionResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armnetwork.PrivateEndpointsClientListBySubscriptionResponse) (armnetwork.PrivateEndpointsClientListBySubscriptionResponse, error) {
					return armnetwork.PrivateEndpointsClientListBySubscriptionResponse{
						PrivateEndpointListResult: armnetwork.PrivateEndpointListResult{
							Value: []*armnetwork.PrivateEndpoint{{ID: to.Ptr(testPENativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestPrivateEndpoint(fake)

	mkProps := func() json.RawMessage {
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName": "rg-1",
			"name":              "pe-1",
			"location":          "eastus",
			"subnetId":          testPESubnetID,
			"privateLinkServiceConnections": []map[string]any{
				{
					"name":                 "conn-1",
					"privateLinkServiceId": testPELinkServiceID,
					"groupIds":             []string{"blob"},
				},
			},
		})
		return props
	}

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testPENativeID, got.ProgressResult.NativeID)

		var props map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &props))
		require.Equal(t, testPESubnetID, props["subnetId"])
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testPENativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _ string, _ *armnetwork.PrivateEndpointsClientBeginDeleteOptions) (*runtime.Poller[armnetwork.PrivateEndpointsClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testPENativeID})
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
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, _ armnetwork.PrivateEndpoint, _ *armnetwork.PrivateEndpointsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.PrivateEndpointsClientCreateOrUpdateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 403}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

// --- Test helpers ---

func newTestPrivateEndpoint(api privateEndpointsAPI) *PrivateEndpoint {
	return &PrivateEndpoint{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

type fakePrivateEndpointsAPI struct {
	beginCreateOrUpdateFn        func(ctx context.Context, rgName, peName string, params armnetwork.PrivateEndpoint, opts *armnetwork.PrivateEndpointsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.PrivateEndpointsClientCreateOrUpdateResponse], error)
	getFn                        func(ctx context.Context, rgName, peName string, opts *armnetwork.PrivateEndpointsClientGetOptions) (armnetwork.PrivateEndpointsClientGetResponse, error)
	beginDeleteFn                func(ctx context.Context, rgName, peName string, opts *armnetwork.PrivateEndpointsClientBeginDeleteOptions) (*runtime.Poller[armnetwork.PrivateEndpointsClientDeleteResponse], error)
	newListPagerFn               func(rgName string, opts *armnetwork.PrivateEndpointsClientListOptions) *runtime.Pager[armnetwork.PrivateEndpointsClientListResponse]
	newListBySubscriptionPagerFn func(opts *armnetwork.PrivateEndpointsClientListBySubscriptionOptions) *runtime.Pager[armnetwork.PrivateEndpointsClientListBySubscriptionResponse]
}

func (f *fakePrivateEndpointsAPI) BeginCreateOrUpdate(ctx context.Context, rgName, peName string, params armnetwork.PrivateEndpoint, opts *armnetwork.PrivateEndpointsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.PrivateEndpointsClientCreateOrUpdateResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, rgName, peName, params, opts)
}

func (f *fakePrivateEndpointsAPI) Get(ctx context.Context, rgName, peName string, opts *armnetwork.PrivateEndpointsClientGetOptions) (armnetwork.PrivateEndpointsClientGetResponse, error) {
	return f.getFn(ctx, rgName, peName, opts)
}

func (f *fakePrivateEndpointsAPI) BeginDelete(ctx context.Context, rgName, peName string, opts *armnetwork.PrivateEndpointsClientBeginDeleteOptions) (*runtime.Poller[armnetwork.PrivateEndpointsClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, peName, opts)
}

func (f *fakePrivateEndpointsAPI) NewListPager(rgName string, opts *armnetwork.PrivateEndpointsClientListOptions) *runtime.Pager[armnetwork.PrivateEndpointsClientListResponse] {
	return f.newListPagerFn(rgName, opts)
}

func (f *fakePrivateEndpointsAPI) NewListBySubscriptionPager(opts *armnetwork.PrivateEndpointsClientListBySubscriptionOptions) *runtime.Pager[armnetwork.PrivateEndpointsClientListBySubscriptionResponse] {
	return f.newListBySubscriptionPagerFn(opts)
}
