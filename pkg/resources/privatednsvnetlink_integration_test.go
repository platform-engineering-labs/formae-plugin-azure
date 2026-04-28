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

const testVNetLinkNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/privateDnsZones/zone-1.internal/virtualNetworkLinks/link-1"
const testVNetLinkVNetID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/virtualNetworks/vnet-1"

func TestPrivateDnsZoneVNetLink_CRUD(t *testing.T) {
	donePollerResult := armprivatedns.VirtualNetworkLinksClientCreateOrUpdateResponse{
		VirtualNetworkLink: armprivatedns.VirtualNetworkLink{
			ID:       to.Ptr(testVNetLinkNativeID),
			Name:     to.Ptr("link-1"),
			Location: to.Ptr("global"),
			Properties: &armprivatedns.VirtualNetworkLinkProperties{
				VirtualNetwork:      &armprivatedns.SubResource{ID: to.Ptr(testVNetLinkVNetID)},
				RegistrationEnabled: to.Ptr(false),
			},
		},
	}

	fake := &fakePrivateDnsVNetLinksAPI{
		beginCreateOrUpdateFn: func(_ context.Context, _, _, _ string, _ armprivatedns.VirtualNetworkLink, _ *armprivatedns.VirtualNetworkLinksClientBeginCreateOrUpdateOptions) (*runtime.Poller[armprivatedns.VirtualNetworkLinksClientCreateOrUpdateResponse], error) {
			return newDonePoller(donePollerResult), nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ *armprivatedns.VirtualNetworkLinksClientGetOptions) (armprivatedns.VirtualNetworkLinksClientGetResponse, error) {
			return armprivatedns.VirtualNetworkLinksClientGetResponse{VirtualNetworkLink: donePollerResult.VirtualNetworkLink}, nil
		},
		beginDeleteFn: func(_ context.Context, _, _, _ string, _ *armprivatedns.VirtualNetworkLinksClientBeginDeleteOptions) (*runtime.Poller[armprivatedns.VirtualNetworkLinksClientDeleteResponse], error) {
			return newInProgressPoller[armprivatedns.VirtualNetworkLinksClientDeleteResponse](), nil
		},
		newListPagerFn: func(_, _ string, _ *armprivatedns.VirtualNetworkLinksClientListOptions) *runtime.Pager[armprivatedns.VirtualNetworkLinksClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armprivatedns.VirtualNetworkLinksClientListResponse]{
				More: func(_ armprivatedns.VirtualNetworkLinksClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armprivatedns.VirtualNetworkLinksClientListResponse) (armprivatedns.VirtualNetworkLinksClientListResponse, error) {
					return armprivatedns.VirtualNetworkLinksClientListResponse{
						VirtualNetworkLinkListResult: armprivatedns.VirtualNetworkLinkListResult{
							Value: []*armprivatedns.VirtualNetworkLink{{ID: to.Ptr(testVNetLinkNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestPrivateDnsZoneVNetLink(fake)

	mkProps := func() json.RawMessage {
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName":   "rg-1",
			"privateZoneName":     "zone-1.internal",
			"name":                "link-1",
			"location":            "global",
			"virtualNetworkId":    testVNetLinkVNetID,
			"registrationEnabled": false,
		})
		return props
	}

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testVNetLinkNativeID, got.ProgressResult.NativeID)

		var props map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &props))
		require.Equal(t, testVNetLinkVNetID, props["virtualNetworkId"])
		require.Equal(t, false, props["registrationEnabled"])
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testVNetLinkNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _, _ string, _ *armprivatedns.VirtualNetworkLinksClientBeginDeleteOptions) (*runtime.Poller[armprivatedns.VirtualNetworkLinksClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testVNetLinkNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{
				"resourceGroupName": "rg-1",
				"privateZoneName":   "zone-1.internal",
			},
		})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 1)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _, _ string, _ armprivatedns.VirtualNetworkLink, _ *armprivatedns.VirtualNetworkLinksClientBeginCreateOrUpdateOptions) (*runtime.Poller[armprivatedns.VirtualNetworkLinksClientCreateOrUpdateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 403}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

// --- Test helpers ---

func newTestPrivateDnsZoneVNetLink(api privateDnsVNetLinksAPI) *PrivateDnsZoneVNetLink {
	return &PrivateDnsZoneVNetLink{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

type fakePrivateDnsVNetLinksAPI struct {
	beginCreateOrUpdateFn func(ctx context.Context, rgName, zoneName, linkName string, params armprivatedns.VirtualNetworkLink, opts *armprivatedns.VirtualNetworkLinksClientBeginCreateOrUpdateOptions) (*runtime.Poller[armprivatedns.VirtualNetworkLinksClientCreateOrUpdateResponse], error)
	getFn                 func(ctx context.Context, rgName, zoneName, linkName string, opts *armprivatedns.VirtualNetworkLinksClientGetOptions) (armprivatedns.VirtualNetworkLinksClientGetResponse, error)
	beginDeleteFn         func(ctx context.Context, rgName, zoneName, linkName string, opts *armprivatedns.VirtualNetworkLinksClientBeginDeleteOptions) (*runtime.Poller[armprivatedns.VirtualNetworkLinksClientDeleteResponse], error)
	newListPagerFn        func(rgName, zoneName string, opts *armprivatedns.VirtualNetworkLinksClientListOptions) *runtime.Pager[armprivatedns.VirtualNetworkLinksClientListResponse]
}

func (f *fakePrivateDnsVNetLinksAPI) BeginCreateOrUpdate(ctx context.Context, rgName, zoneName, linkName string, params armprivatedns.VirtualNetworkLink, opts *armprivatedns.VirtualNetworkLinksClientBeginCreateOrUpdateOptions) (*runtime.Poller[armprivatedns.VirtualNetworkLinksClientCreateOrUpdateResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, rgName, zoneName, linkName, params, opts)
}

func (f *fakePrivateDnsVNetLinksAPI) Get(ctx context.Context, rgName, zoneName, linkName string, opts *armprivatedns.VirtualNetworkLinksClientGetOptions) (armprivatedns.VirtualNetworkLinksClientGetResponse, error) {
	return f.getFn(ctx, rgName, zoneName, linkName, opts)
}

func (f *fakePrivateDnsVNetLinksAPI) BeginDelete(ctx context.Context, rgName, zoneName, linkName string, opts *armprivatedns.VirtualNetworkLinksClientBeginDeleteOptions) (*runtime.Poller[armprivatedns.VirtualNetworkLinksClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, zoneName, linkName, opts)
}

func (f *fakePrivateDnsVNetLinksAPI) NewListPager(rgName, zoneName string, opts *armprivatedns.VirtualNetworkLinksClientListOptions) *runtime.Pager[armprivatedns.VirtualNetworkLinksClientListResponse] {
	return f.newListPagerFn(rgName, zoneName, opts)
}
