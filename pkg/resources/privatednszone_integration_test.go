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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/privatedns/armprivatedns"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testZoneNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/privateDnsZones/zone-1.internal"

func TestPrivateDnsZone_CRUD(t *testing.T) {
	donePollerResult := armprivatedns.PrivateZonesClientCreateOrUpdateResponse{
		PrivateZone: armprivatedns.PrivateZone{
			ID:       to.Ptr(testZoneNativeID),
			Name:     to.Ptr("zone-1.internal"),
			Location: to.Ptr("global"),
		},
	}
	fake := &fakePrivateDnsZonesAPI{
		beginCreateOrUpdateFn: func(_ context.Context, _, _ string, _ armprivatedns.PrivateZone, _ *armprivatedns.PrivateZonesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armprivatedns.PrivateZonesClientCreateOrUpdateResponse], error) {
			return newDonePoller(donePollerResult), nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armprivatedns.PrivateZonesClientGetOptions) (armprivatedns.PrivateZonesClientGetResponse, error) {
			return armprivatedns.PrivateZonesClientGetResponse{PrivateZone: donePollerResult.PrivateZone}, nil
		},
		beginDeleteFn: func(_ context.Context, _, _ string, _ *armprivatedns.PrivateZonesClientBeginDeleteOptions) (*runtime.Poller[armprivatedns.PrivateZonesClientDeleteResponse], error) {
			return newInProgressPoller[armprivatedns.PrivateZonesClientDeleteResponse](), nil
		},
		newListPagerFn: func(_ *armprivatedns.PrivateZonesClientListOptions) *runtime.Pager[armprivatedns.PrivateZonesClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armprivatedns.PrivateZonesClientListResponse]{
				More: func(_ armprivatedns.PrivateZonesClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armprivatedns.PrivateZonesClientListResponse) (armprivatedns.PrivateZonesClientListResponse, error) {
					return armprivatedns.PrivateZonesClientListResponse{
						PrivateZoneListResult: armprivatedns.PrivateZoneListResult{
							Value: []*armprivatedns.PrivateZone{{ID: to.Ptr(testZoneNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestPrivateDnsZone(fake)

	mkProps := func() json.RawMessage {
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName": "rg-1",
			"name":              "zone-1.internal",
			"location":          "global",
		})
		return props
	}

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testZoneNativeID, got.ProgressResult.NativeID)
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testZoneNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _ string, _ *armprivatedns.PrivateZonesClientBeginDeleteOptions) (*runtime.Poller[armprivatedns.PrivateZonesClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testZoneNativeID})
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
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, _ armprivatedns.PrivateZone, _ *armprivatedns.PrivateZonesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armprivatedns.PrivateZonesClientCreateOrUpdateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 403}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

// --- Test helpers ---

func newTestPrivateDnsZone(api privateDnsZonesAPI) *PrivateDnsZone {
	return &PrivateDnsZone{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

type fakePrivateDnsZonesAPI struct {
	beginCreateOrUpdateFn       func(ctx context.Context, rgName, zoneName string, params armprivatedns.PrivateZone, opts *armprivatedns.PrivateZonesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armprivatedns.PrivateZonesClientCreateOrUpdateResponse], error)
	getFn                       func(ctx context.Context, rgName, zoneName string, opts *armprivatedns.PrivateZonesClientGetOptions) (armprivatedns.PrivateZonesClientGetResponse, error)
	beginDeleteFn               func(ctx context.Context, rgName, zoneName string, opts *armprivatedns.PrivateZonesClientBeginDeleteOptions) (*runtime.Poller[armprivatedns.PrivateZonesClientDeleteResponse], error)
	newListByResourceGroupPager func(rgName string, opts *armprivatedns.PrivateZonesClientListByResourceGroupOptions) *runtime.Pager[armprivatedns.PrivateZonesClientListByResourceGroupResponse]
	newListPagerFn              func(opts *armprivatedns.PrivateZonesClientListOptions) *runtime.Pager[armprivatedns.PrivateZonesClientListResponse]
}

func (f *fakePrivateDnsZonesAPI) BeginCreateOrUpdate(ctx context.Context, rgName, zoneName string, params armprivatedns.PrivateZone, opts *armprivatedns.PrivateZonesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armprivatedns.PrivateZonesClientCreateOrUpdateResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, rgName, zoneName, params, opts)
}

func (f *fakePrivateDnsZonesAPI) Get(ctx context.Context, rgName, zoneName string, opts *armprivatedns.PrivateZonesClientGetOptions) (armprivatedns.PrivateZonesClientGetResponse, error) {
	return f.getFn(ctx, rgName, zoneName, opts)
}

func (f *fakePrivateDnsZonesAPI) BeginDelete(ctx context.Context, rgName, zoneName string, opts *armprivatedns.PrivateZonesClientBeginDeleteOptions) (*runtime.Poller[armprivatedns.PrivateZonesClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, zoneName, opts)
}

func (f *fakePrivateDnsZonesAPI) NewListByResourceGroupPager(rgName string, opts *armprivatedns.PrivateZonesClientListByResourceGroupOptions) *runtime.Pager[armprivatedns.PrivateZonesClientListByResourceGroupResponse] {
	return f.newListByResourceGroupPager(rgName, opts)
}

func (f *fakePrivateDnsZonesAPI) NewListPager(opts *armprivatedns.PrivateZonesClientListOptions) *runtime.Pager[armprivatedns.PrivateZonesClientListResponse] {
	return f.newListPagerFn(opts)
}
