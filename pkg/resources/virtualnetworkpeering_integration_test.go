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
	testPeeringNativeID   = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/virtualNetworks/vnet-local/virtualNetworkPeerings/peer-1"
	testPeeringLocalVNet  = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/virtualNetworks/vnet-local"
	testPeeringRemoteVNet = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/virtualNetworks/vnet-remote"
)

func TestVirtualNetworkPeering_CRUD(t *testing.T) {
	model := armnetwork.VirtualNetworkPeering{
		ID:   to.Ptr(testPeeringNativeID),
		Name: to.Ptr("peer-1"),
		Properties: &armnetwork.VirtualNetworkPeeringPropertiesFormat{
			RemoteVirtualNetwork:      &armnetwork.SubResource{ID: to.Ptr(testPeeringRemoteVNet)},
			AllowVirtualNetworkAccess: to.Ptr(true),
			AllowForwardedTraffic:     to.Ptr(false),
			AllowGatewayTransit:       to.Ptr(false),
			UseRemoteGateways:         to.Ptr(false),
			PeeringState:              to.Ptr(armnetwork.VirtualNetworkPeeringStateInitiated),
		},
	}
	fake := &fakeVirtualNetworkPeeringsAPI{
		beginCreateOrUpdateFn: func(_ context.Context, _, _, _ string, _ armnetwork.VirtualNetworkPeering, _ *armnetwork.VirtualNetworkPeeringsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.VirtualNetworkPeeringsClientCreateOrUpdateResponse], error) {
			return newDonePoller(armnetwork.VirtualNetworkPeeringsClientCreateOrUpdateResponse{VirtualNetworkPeering: model}), nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ *armnetwork.VirtualNetworkPeeringsClientGetOptions) (armnetwork.VirtualNetworkPeeringsClientGetResponse, error) {
			return armnetwork.VirtualNetworkPeeringsClientGetResponse{VirtualNetworkPeering: model}, nil
		},
		beginDeleteFn: func(_ context.Context, _, _, _ string, _ *armnetwork.VirtualNetworkPeeringsClientBeginDeleteOptions) (*runtime.Poller[armnetwork.VirtualNetworkPeeringsClientDeleteResponse], error) {
			return newInProgressPoller[armnetwork.VirtualNetworkPeeringsClientDeleteResponse](), nil
		},
		newListPagerFn: func(_, _ string, _ *armnetwork.VirtualNetworkPeeringsClientListOptions) *runtime.Pager[armnetwork.VirtualNetworkPeeringsClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armnetwork.VirtualNetworkPeeringsClientListResponse]{
				More: func(_ armnetwork.VirtualNetworkPeeringsClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armnetwork.VirtualNetworkPeeringsClientListResponse) (armnetwork.VirtualNetworkPeeringsClientListResponse, error) {
					return armnetwork.VirtualNetworkPeeringsClientListResponse{
						VirtualNetworkPeeringListResult: armnetwork.VirtualNetworkPeeringListResult{
							Value: []*armnetwork.VirtualNetworkPeering{{ID: to.Ptr(testPeeringNativeID)}},
						},
					}, nil
				},
			})
		},
		newListAllVNetsPagerFn: func(_ *armnetwork.VirtualNetworksClientListAllOptions) *runtime.Pager[armnetwork.VirtualNetworksClientListAllResponse] {
			return runtime.NewPager(runtime.PagingHandler[armnetwork.VirtualNetworksClientListAllResponse]{
				More: func(_ armnetwork.VirtualNetworksClientListAllResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armnetwork.VirtualNetworksClientListAllResponse) (armnetwork.VirtualNetworksClientListAllResponse, error) {
					return armnetwork.VirtualNetworksClientListAllResponse{
						VirtualNetworkListResult: armnetwork.VirtualNetworkListResult{
							Value: []*armnetwork.VirtualNetwork{{ID: to.Ptr(testPeeringLocalVNet)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestVirtualNetworkPeering(fake)

	mkProps := func() json.RawMessage {
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName":         "rg-1",
			"virtualNetworkName":        "vnet-local",
			"name":                      "peer-1",
			"remoteVirtualNetworkId":    testPeeringRemoteVNet,
			"allowVirtualNetworkAccess": true,
			"allowForwardedTraffic":     false,
		})
		return props
	}

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testPeeringNativeID, got.ProgressResult.NativeID)

		var serialized map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &serialized))
		require.Equal(t, "peer-1", serialized["name"])
		require.Equal(t, "rg-1", serialized["resourceGroupName"])
		require.Equal(t, "vnet-local", serialized["virtualNetworkName"])
		require.Equal(t, testPeeringRemoteVNet, serialized["remoteVirtualNetworkId"])
		require.Equal(t, true, serialized["allowVirtualNetworkAccess"])
		require.Equal(t, false, serialized["allowForwardedTraffic"])
	})

	// peeringState / provisioningState are read-only ARM output with no schema field;
	// leaking them into properties fails conformance Verify.
	t.Run("Serialize_omits_unmodelled_readonly_fields", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testPeeringNativeID})
		require.NoError(t, err)
		var serialized map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &serialized))
		require.NotContains(t, serialized, "peeringState")
		require.NotContains(t, serialized, "provisioningState")
	})

	t.Run("Create_forwards_params_to_ARM", func(t *testing.T) {
		var seen armnetwork.VirtualNetworkPeering
		var seenRG, seenVNet, seenName string
		fake.beginCreateOrUpdateFn = func(_ context.Context, rg, vnet, name string, params armnetwork.VirtualNetworkPeering, _ *armnetwork.VirtualNetworkPeeringsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.VirtualNetworkPeeringsClientCreateOrUpdateResponse], error) {
			seen, seenRG, seenVNet, seenName = params, rg, vnet, name
			return newDonePoller(armnetwork.VirtualNetworkPeeringsClientCreateOrUpdateResponse{VirtualNetworkPeering: model}), nil
		}
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName":         "rg-1",
			"virtualNetworkName":        "vnet-local",
			"name":                      "peer-1",
			"remoteVirtualNetworkId":    testPeeringRemoteVNet,
			"allowVirtualNetworkAccess": true,
			"allowForwardedTraffic":     true,
			"allowGatewayTransit":       true,
			"useRemoteGateways":         false,
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.Equal(t, "rg-1", seenRG)
		require.Equal(t, "vnet-local", seenVNet)
		require.Equal(t, "peer-1", seenName)
		require.Equal(t, testPeeringRemoteVNet, *seen.Properties.RemoteVirtualNetwork.ID)
		require.True(t, *seen.Properties.AllowVirtualNetworkAccess)
		require.True(t, *seen.Properties.AllowForwardedTraffic)
		require.True(t, *seen.Properties.AllowGatewayTransit)
		require.False(t, *seen.Properties.UseRemoteGateways)

		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _, _ string, _ armnetwork.VirtualNetworkPeering, _ *armnetwork.VirtualNetworkPeeringsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.VirtualNetworkPeeringsClientCreateOrUpdateResponse], error) {
			return newDonePoller(armnetwork.VirtualNetworkPeeringsClientCreateOrUpdateResponse{VirtualNetworkPeering: model}), nil
		}
	})

	// A false flag must reach ARM as an explicit false, not be dropped as a zero value.
	t.Run("Create_sends_explicit_false_flags", func(t *testing.T) {
		var seen armnetwork.VirtualNetworkPeering
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _, _ string, params armnetwork.VirtualNetworkPeering, _ *armnetwork.VirtualNetworkPeeringsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.VirtualNetworkPeeringsClientCreateOrUpdateResponse], error) {
			seen = params
			return newDonePoller(armnetwork.VirtualNetworkPeeringsClientCreateOrUpdateResponse{VirtualNetworkPeering: model}), nil
		}
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName":         "rg-1",
			"virtualNetworkName":        "vnet-local",
			"name":                      "peer-1",
			"remoteVirtualNetworkId":    testPeeringRemoteVNet,
			"allowVirtualNetworkAccess": false,
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.NotNil(t, seen.Properties.AllowVirtualNetworkAccess)
		require.False(t, *seen.Properties.AllowVirtualNetworkAccess)
		// Flags the forma never mentions stay nil so Azure applies its own default.
		require.Nil(t, seen.Properties.AllowForwardedTraffic)

		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _, _ string, _ armnetwork.VirtualNetworkPeering, _ *armnetwork.VirtualNetworkPeeringsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.VirtualNetworkPeeringsClientCreateOrUpdateResponse], error) {
			return newDonePoller(armnetwork.VirtualNetworkPeeringsClientCreateOrUpdateResponse{VirtualNetworkPeering: model}), nil
		}
	})

	t.Run("Create_requires_remoteVirtualNetworkId", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName":  "rg-1",
			"virtualNetworkName": "vnet-local",
			"name":               "peer-1",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "remoteVirtualNetworkId is required")
	})

	t.Run("Create_requires_resourceGroupName", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"virtualNetworkName": "vnet-local", "name": "peer-1"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "resourceGroupName is required")
	})

	t.Run("Create_requires_virtualNetworkName", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"resourceGroupName": "rg-1", "name": "peer-1"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "virtualNetworkName is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testPeeringNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
		require.Equal(t, ResourceTypeVirtualNetworkPeering, got.ResourceType)
	})

	t.Run("Read_not_found", func(t *testing.T) {
		fake.getFn = func(_ context.Context, _, _, _ string, _ *armnetwork.VirtualNetworkPeeringsClientGetOptions) (armnetwork.VirtualNetworkPeeringsClientGetResponse, error) {
			return armnetwork.VirtualNetworkPeeringsClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testPeeringNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)

		fake.getFn = func(_ context.Context, _, _, _ string, _ *armnetwork.VirtualNetworkPeeringsClientGetOptions) (armnetwork.VirtualNetworkPeeringsClientGetResponse, error) {
			return armnetwork.VirtualNetworkPeeringsClientGetResponse{VirtualNetworkPeering: model}, nil
		}
	})

	// Peerings have no PATCH verb, and the parent names must come from the native ID
	// rather than the payload.
	t.Run("Update_derives_parents_from_native_id", func(t *testing.T) {
		var seenRG, seenVNet, seenName string
		var seen armnetwork.VirtualNetworkPeering
		fake.beginCreateOrUpdateFn = func(_ context.Context, rg, vnet, name string, params armnetwork.VirtualNetworkPeering, _ *armnetwork.VirtualNetworkPeeringsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.VirtualNetworkPeeringsClientCreateOrUpdateResponse], error) {
			seenRG, seenVNet, seenName, seen = rg, vnet, name, params
			return newDonePoller(armnetwork.VirtualNetworkPeeringsClientCreateOrUpdateResponse{VirtualNetworkPeering: model}), nil
		}
		desired, _ := json.Marshal(map[string]any{
			// Deliberately wrong parents in the payload — the native ID must win.
			"resourceGroupName":      "wrong-rg",
			"virtualNetworkName":     "wrong-vnet",
			"name":                   "wrong-name",
			"remoteVirtualNetworkId": testPeeringRemoteVNet,
			"allowForwardedTraffic":  true,
		})
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testPeeringNativeID,
			DesiredProperties: desired,
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, "rg-1", seenRG)
		require.Equal(t, "vnet-local", seenVNet)
		require.Equal(t, "peer-1", seenName)
		// The immutable remote reference has to be echoed back in the PUT body.
		require.Equal(t, testPeeringRemoteVNet, *seen.Properties.RemoteVirtualNetwork.ID)
		require.True(t, *seen.Properties.AllowForwardedTraffic)
	})

	t.Run("Delete_in_progress_returns_lro_request_id", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testPeeringNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusInProgress, got.ProgressResult.OperationStatus)
		reqID, err := decodeLROStatus(got.ProgressResult.RequestID)
		require.NoError(t, err)
		require.Equal(t, lroOpDelete, reqID.OperationType)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _, _ string, _ *armnetwork.VirtualNetworkPeeringsClientBeginDeleteOptions) (*runtime.Poller[armnetwork.VirtualNetworkPeeringsClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testPeeringNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Status_rejects_unknown_operation", func(t *testing.T) {
		reqID, err := encodeLROStart("bogus", "token", testPeeringNativeID)
		require.NoError(t, err)
		got, err := prov.Status(context.Background(), &resource.StatusRequest{RequestID: reqID})
		require.Error(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_vnet", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "virtualNetworkName": "vnet-local"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testPeeringNativeID}, got.NativeIDs)
	})

	// Peerings cannot be listed subscription-wide, so discovery walks every VNet.
	t.Run("List_all_walks_vnets", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Equal(t, []string{testPeeringNativeID}, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _, _ string, _ armnetwork.VirtualNetworkPeering, _ *armnetwork.VirtualNetworkPeeringsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.VirtualNetworkPeeringsClientCreateOrUpdateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 403}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

func TestVirtualNetworkPeeringIDParts(t *testing.T) {
	rg, vnet, name, err := virtualNetworkPeeringIDParts(testPeeringNativeID)
	require.NoError(t, err)
	require.Equal(t, "rg-1", rg)
	require.Equal(t, "vnet-local", vnet)
	require.Equal(t, "peer-1", name)

	// A bare VNet ID has no peering segment.
	_, _, _, err = virtualNetworkPeeringIDParts(testPeeringLocalVNet)
	require.Error(t, err)
}

// --- Test helpers ---

func newTestVirtualNetworkPeering(api virtualNetworkPeeringsAPI) *VirtualNetworkPeering {
	return &VirtualNetworkPeering{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

type fakeVirtualNetworkPeeringsAPI struct {
	beginCreateOrUpdateFn  func(ctx context.Context, rgName, vnetName, name string, params armnetwork.VirtualNetworkPeering, opts *armnetwork.VirtualNetworkPeeringsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.VirtualNetworkPeeringsClientCreateOrUpdateResponse], error)
	getFn                  func(ctx context.Context, rgName, vnetName, name string, opts *armnetwork.VirtualNetworkPeeringsClientGetOptions) (armnetwork.VirtualNetworkPeeringsClientGetResponse, error)
	beginDeleteFn          func(ctx context.Context, rgName, vnetName, name string, opts *armnetwork.VirtualNetworkPeeringsClientBeginDeleteOptions) (*runtime.Poller[armnetwork.VirtualNetworkPeeringsClientDeleteResponse], error)
	newListPagerFn         func(rgName, vnetName string, opts *armnetwork.VirtualNetworkPeeringsClientListOptions) *runtime.Pager[armnetwork.VirtualNetworkPeeringsClientListResponse]
	newListAllVNetsPagerFn func(opts *armnetwork.VirtualNetworksClientListAllOptions) *runtime.Pager[armnetwork.VirtualNetworksClientListAllResponse]
}

func (f *fakeVirtualNetworkPeeringsAPI) BeginCreateOrUpdate(ctx context.Context, rgName, vnetName, name string, params armnetwork.VirtualNetworkPeering, opts *armnetwork.VirtualNetworkPeeringsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.VirtualNetworkPeeringsClientCreateOrUpdateResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, rgName, vnetName, name, params, opts)
}

func (f *fakeVirtualNetworkPeeringsAPI) Get(ctx context.Context, rgName, vnetName, name string, opts *armnetwork.VirtualNetworkPeeringsClientGetOptions) (armnetwork.VirtualNetworkPeeringsClientGetResponse, error) {
	return f.getFn(ctx, rgName, vnetName, name, opts)
}

func (f *fakeVirtualNetworkPeeringsAPI) BeginDelete(ctx context.Context, rgName, vnetName, name string, opts *armnetwork.VirtualNetworkPeeringsClientBeginDeleteOptions) (*runtime.Poller[armnetwork.VirtualNetworkPeeringsClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, vnetName, name, opts)
}

func (f *fakeVirtualNetworkPeeringsAPI) NewListPager(rgName, vnetName string, opts *armnetwork.VirtualNetworkPeeringsClientListOptions) *runtime.Pager[armnetwork.VirtualNetworkPeeringsClientListResponse] {
	return f.newListPagerFn(rgName, vnetName, opts)
}

func (f *fakeVirtualNetworkPeeringsAPI) NewListAllVNetsPager(opts *armnetwork.VirtualNetworksClientListAllOptions) *runtime.Pager[armnetwork.VirtualNetworksClientListAllResponse] {
	return f.newListAllVNetsPagerFn(opts)
}
