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
	testZoneGroupNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/privateEndpoints/pe-1/privateDnsZoneGroups/zg-1"
	testZoneGroupZoneID   = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/privateDnsZones/privatelink.blob.core.windows.net"
)

func TestPrivateDnsZoneGroup_CRUD(t *testing.T) {
	donePollerResult := armnetwork.PrivateDNSZoneGroupsClientCreateOrUpdateResponse{
		PrivateDNSZoneGroup: armnetwork.PrivateDNSZoneGroup{
			ID:   to.Ptr(testZoneGroupNativeID),
			Name: to.Ptr("zg-1"),
			Properties: &armnetwork.PrivateDNSZoneGroupPropertiesFormat{
				PrivateDNSZoneConfigs: []*armnetwork.PrivateDNSZoneConfig{
					{
						Name: to.Ptr("blob-zone"),
						Properties: &armnetwork.PrivateDNSZonePropertiesFormat{
							PrivateDNSZoneID: to.Ptr(testZoneGroupZoneID),
						},
					},
				},
			},
		},
	}
	fake := &fakePrivateDnsZoneGroupsAPI{
		beginCreateOrUpdateFn: func(_ context.Context, _, _, _ string, _ armnetwork.PrivateDNSZoneGroup, _ *armnetwork.PrivateDNSZoneGroupsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.PrivateDNSZoneGroupsClientCreateOrUpdateResponse], error) {
			return newDonePoller(donePollerResult), nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ *armnetwork.PrivateDNSZoneGroupsClientGetOptions) (armnetwork.PrivateDNSZoneGroupsClientGetResponse, error) {
			return armnetwork.PrivateDNSZoneGroupsClientGetResponse{PrivateDNSZoneGroup: donePollerResult.PrivateDNSZoneGroup}, nil
		},
		beginDeleteFn: func(_ context.Context, _, _, _ string, _ *armnetwork.PrivateDNSZoneGroupsClientBeginDeleteOptions) (*runtime.Poller[armnetwork.PrivateDNSZoneGroupsClientDeleteResponse], error) {
			return newInProgressPoller[armnetwork.PrivateDNSZoneGroupsClientDeleteResponse](), nil
		},
		newListPagerFn: func(_, _ string, _ *armnetwork.PrivateDNSZoneGroupsClientListOptions) *runtime.Pager[armnetwork.PrivateDNSZoneGroupsClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armnetwork.PrivateDNSZoneGroupsClientListResponse]{
				More: func(_ armnetwork.PrivateDNSZoneGroupsClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armnetwork.PrivateDNSZoneGroupsClientListResponse) (armnetwork.PrivateDNSZoneGroupsClientListResponse, error) {
					return armnetwork.PrivateDNSZoneGroupsClientListResponse{
						PrivateDNSZoneGroupListResult: armnetwork.PrivateDNSZoneGroupListResult{
							Value: []*armnetwork.PrivateDNSZoneGroup{{ID: to.Ptr(testZoneGroupNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestPrivateDnsZoneGroup(fake)

	mkProps := func() json.RawMessage {
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName":   "rg-1",
			"privateEndpointName": "pe-1",
			"name":                "zg-1",
			"privateDnsZoneConfigs": []map[string]any{
				{
					"name":             "blob-zone",
					"privateDnsZoneId": testZoneGroupZoneID,
				},
			},
		})
		return props
	}

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testZoneGroupNativeID, got.ProgressResult.NativeID)
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testZoneGroupNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _, _ string, _ *armnetwork.PrivateDNSZoneGroupsClientBeginDeleteOptions) (*runtime.Poller[armnetwork.PrivateDNSZoneGroupsClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testZoneGroupNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{
				"resourceGroupName":   "rg-1",
				"privateEndpointName": "pe-1",
			},
		})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 1)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _, _ string, _ armnetwork.PrivateDNSZoneGroup, _ *armnetwork.PrivateDNSZoneGroupsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.PrivateDNSZoneGroupsClientCreateOrUpdateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 403}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

// --- Test helpers ---

func newTestPrivateDnsZoneGroup(api privateDnsZoneGroupsAPI) *PrivateDnsZoneGroup {
	return &PrivateDnsZoneGroup{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

type fakePrivateDnsZoneGroupsAPI struct {
	beginCreateOrUpdateFn func(ctx context.Context, rgName, peName, groupName string, params armnetwork.PrivateDNSZoneGroup, opts *armnetwork.PrivateDNSZoneGroupsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.PrivateDNSZoneGroupsClientCreateOrUpdateResponse], error)
	getFn                 func(ctx context.Context, rgName, peName, groupName string, opts *armnetwork.PrivateDNSZoneGroupsClientGetOptions) (armnetwork.PrivateDNSZoneGroupsClientGetResponse, error)
	beginDeleteFn         func(ctx context.Context, rgName, peName, groupName string, opts *armnetwork.PrivateDNSZoneGroupsClientBeginDeleteOptions) (*runtime.Poller[armnetwork.PrivateDNSZoneGroupsClientDeleteResponse], error)
	newListPagerFn        func(peName, rgName string, opts *armnetwork.PrivateDNSZoneGroupsClientListOptions) *runtime.Pager[armnetwork.PrivateDNSZoneGroupsClientListResponse]
}

func (f *fakePrivateDnsZoneGroupsAPI) BeginCreateOrUpdate(ctx context.Context, rgName, peName, groupName string, params armnetwork.PrivateDNSZoneGroup, opts *armnetwork.PrivateDNSZoneGroupsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.PrivateDNSZoneGroupsClientCreateOrUpdateResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, rgName, peName, groupName, params, opts)
}

func (f *fakePrivateDnsZoneGroupsAPI) Get(ctx context.Context, rgName, peName, groupName string, opts *armnetwork.PrivateDNSZoneGroupsClientGetOptions) (armnetwork.PrivateDNSZoneGroupsClientGetResponse, error) {
	return f.getFn(ctx, rgName, peName, groupName, opts)
}

func (f *fakePrivateDnsZoneGroupsAPI) BeginDelete(ctx context.Context, rgName, peName, groupName string, opts *armnetwork.PrivateDNSZoneGroupsClientBeginDeleteOptions) (*runtime.Poller[armnetwork.PrivateDNSZoneGroupsClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, peName, groupName, opts)
}

func (f *fakePrivateDnsZoneGroupsAPI) NewListPager(peName, rgName string, opts *armnetwork.PrivateDNSZoneGroupsClientListOptions) *runtime.Pager[armnetwork.PrivateDNSZoneGroupsClientListResponse] {
	return f.newListPagerFn(peName, rgName, opts)
}
