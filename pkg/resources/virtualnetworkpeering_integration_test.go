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
	testPeeringNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/virtualNetworks/vnet-a/virtualNetworkPeerings/a-to-b"
	testPeeringRemoteID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/virtualNetworks/vnet-b"
)

func newTestPeering(api virtualNetworkPeeringsAPI) *VirtualNetworkPeering {
	return &VirtualNetworkPeering{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func peeringDesired(allowForwarded bool) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":                      "a-to-b",
		"resourceGroupName":         "rg-1",
		"virtualNetworkName":        "vnet-a",
		"remoteVirtualNetworkId":    testPeeringRemoteID,
		"allowVirtualNetworkAccess": true,
		"allowForwardedTraffic":     allowForwarded,
		"allowGatewayTransit":       false,
		"useRemoteGateways":         false,
	})
	return out
}

func TestVirtualNetworkPeering_CRUD(t *testing.T) {
	var sent armnetwork.VirtualNetworkPeering
	var sawPath []string
	echo := func(params armnetwork.VirtualNetworkPeering) armnetwork.VirtualNetworkPeering {
		params.ID = to.Ptr(testPeeringNativeID)
		params.Name = to.Ptr("a-to-b")
		if params.Properties != nil {
			// One-directional: ARM reports Initiated until the mirror peering exists.
			params.Properties.PeeringState = to.Ptr(armnetwork.VirtualNetworkPeeringStateInitiated)
			params.Properties.ProvisioningState = to.Ptr(armnetwork.ProvisioningStateSucceeded)
			params.Properties.RemoteAddressSpace = &armnetwork.AddressSpace{
				AddressPrefixes: []*string{to.Ptr("10.1.0.0/16")},
			}
		}
		return params
	}

	createCalls := 0
	deleteCalls := 0
	fake := &fakePeeringsAPI{
		beginCreateOrUpdateFn: func(_ context.Context, rgName, vnetName, name string, params armnetwork.VirtualNetworkPeering, _ *armnetwork.VirtualNetworkPeeringsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.VirtualNetworkPeeringsClientCreateOrUpdateResponse], error) {
			sawPath = []string{rgName, vnetName, name}
			sent = params
			createCalls++
			return newDonePoller(armnetwork.VirtualNetworkPeeringsClientCreateOrUpdateResponse{VirtualNetworkPeering: echo(params)}), nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ *armnetwork.VirtualNetworkPeeringsClientGetOptions) (armnetwork.VirtualNetworkPeeringsClientGetResponse, error) {
			return armnetwork.VirtualNetworkPeeringsClientGetResponse{VirtualNetworkPeering: echo(sent)}, nil
		},
		beginDeleteFn: func(_ context.Context, _, _, _ string, _ *armnetwork.VirtualNetworkPeeringsClientBeginDeleteOptions) (*runtime.Poller[armnetwork.VirtualNetworkPeeringsClientDeleteResponse], error) {
			deleteCalls++
			return newDonePoller(armnetwork.VirtualNetworkPeeringsClientDeleteResponse{}), nil
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
	}
	prov := newTestPeering(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "a-to-b", Properties: peeringDesired(false),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testPeeringNativeID, got.ProgressResult.NativeID)

		require.Equal(t, []string{"rg-1", "vnet-a", "a-to-b"}, sawPath)
		require.Equal(t, testPeeringRemoteID, *sent.Properties.RemoteVirtualNetwork.ID)
		require.True(t, *sent.Properties.AllowVirtualNetworkAccess)
		require.False(t, *sent.Properties.AllowForwardedTraffic)
	})

	t.Run("Create_requires_remote_vnet", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "a-to-b", "resourceGroupName": "rg-1", "virtualNetworkName": "vnet-a",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "remoteVirtualNetworkId is required")
	})

	t.Run("Create_requires_virtual_network", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "a-to-b", "resourceGroupName": "rg-1",
			"remoteVirtualNetworkId": testPeeringRemoteID,
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "virtualNetworkName is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testPeeringNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "a-to-b", props["name"])
		// Both parents come from the native ID, not the response body.
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "vnet-a", props["virtualNetworkName"])
		require.Equal(t, testPeeringRemoteID, props["remoteVirtualNetworkId"])
		require.Equal(t, true, props["allowVirtualNetworkAccess"])
		require.Equal(t, false, props["allowForwardedTraffic"])
		// A one-way peering sits in Initiated until its mirror exists; that is normal.
		require.Equal(t, "Initiated", props["peeringState"])
	})

	// ARM reports the far side's address space and its own bookkeeping. None of it
	// is desired state, and it changes whenever the remote vnet does.
	t.Run("Read_drops_remote_view_and_bookkeeping", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testPeeringNativeID})
		require.NoError(t, err)
		for _, key := range []string{
			"remoteAddressSpace", "remoteVirtualNetworkAddressSpace",
			"remoteBgpCommunities", "peeringSyncLevel", "provisioningState", "resourceGuid",
		} {
			require.NotContains(t, got.Properties, key)
		}
		require.NotContains(t, got.Properties, "10.1.0.0/16")
	})

	// No PATCH verb on this API: an update is another CreateOrUpdate.
	t.Run("Update_reissues_create_or_update", func(t *testing.T) {
		before := createCalls
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testPeeringNativeID,
			DesiredProperties: peeringDesired(true),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, createCalls)
		require.True(t, *sent.Properties.AllowForwardedTraffic)
		// The remote vnet must still be sent: a PUT without it would unset the link.
		require.Equal(t, testPeeringRemoteID, *sent.Properties.RemoteVirtualNetwork.ID)
	})

	t.Run("Delete", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testPeeringNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _, _ string, _ *armnetwork.VirtualNetworkPeeringsClientBeginDeleteOptions) (*runtime.Poller[armnetwork.VirtualNetworkPeeringsClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testPeeringNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_virtual_network", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "virtualNetworkName": "vnet-a"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testPeeringNativeID}, got.NativeIDs)
	})

	t.Run("List_without_parents_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _, _ string, _ armnetwork.VirtualNetworkPeering, _ *armnetwork.VirtualNetworkPeeringsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.VirtualNetworkPeeringsClientCreateOrUpdateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 409}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "a-to-b", Properties: peeringDesired(false),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

// The native ID reported for an in-flight create must match the path ARM will
// return. This template was inherited wrong from the resource this handler was
// derived from, and only a real apply would have noticed.
func TestVirtualNetworkPeering_PendingCreateReportsRealNativeID(t *testing.T) {
	fake := &fakePeeringsAPI{
		beginCreateOrUpdateFn: func(_ context.Context, _, _, _ string, _ armnetwork.VirtualNetworkPeering, _ *armnetwork.VirtualNetworkPeeringsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.VirtualNetworkPeeringsClientCreateOrUpdateResponse], error) {
			return newPendingPoller[armnetwork.VirtualNetworkPeeringsClientCreateOrUpdateResponse](), nil
		},
	}
	got, err := newTestPeering(fake).Create(context.Background(), &resource.CreateRequest{
		Label: "a-to-b", Properties: peeringDesired(false),
	})
	require.NoError(t, err)
	require.Equal(t, resource.OperationStatusInProgress, got.ProgressResult.OperationStatus)
	require.Equal(t, testPeeringNativeID, got.ProgressResult.NativeID)
}

func TestVirtualNetworkPeering_ReadNotFound(t *testing.T) {
	fake := &fakePeeringsAPI{
		getFn: func(_ context.Context, _, _, _ string, _ *armnetwork.VirtualNetworkPeeringsClientGetOptions) (armnetwork.VirtualNetworkPeeringsClientGetResponse, error) {
			return armnetwork.VirtualNetworkPeeringsClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestPeering(fake).Read(context.Background(), &resource.ReadRequest{NativeID: testPeeringNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakePeeringsAPI struct {
	beginCreateOrUpdateFn func(ctx context.Context, rgName, vnetName, name string, params armnetwork.VirtualNetworkPeering, options *armnetwork.VirtualNetworkPeeringsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.VirtualNetworkPeeringsClientCreateOrUpdateResponse], error)
	getFn                 func(ctx context.Context, rgName, vnetName, name string, options *armnetwork.VirtualNetworkPeeringsClientGetOptions) (armnetwork.VirtualNetworkPeeringsClientGetResponse, error)
	beginDeleteFn         func(ctx context.Context, rgName, vnetName, name string, options *armnetwork.VirtualNetworkPeeringsClientBeginDeleteOptions) (*runtime.Poller[armnetwork.VirtualNetworkPeeringsClientDeleteResponse], error)
	newListPagerFn        func(rgName, vnetName string, options *armnetwork.VirtualNetworkPeeringsClientListOptions) *runtime.Pager[armnetwork.VirtualNetworkPeeringsClientListResponse]
}

func (f *fakePeeringsAPI) BeginCreateOrUpdate(ctx context.Context, rgName, vnetName, name string, params armnetwork.VirtualNetworkPeering, options *armnetwork.VirtualNetworkPeeringsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.VirtualNetworkPeeringsClientCreateOrUpdateResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, rgName, vnetName, name, params, options)
}

func (f *fakePeeringsAPI) Get(ctx context.Context, rgName, vnetName, name string, options *armnetwork.VirtualNetworkPeeringsClientGetOptions) (armnetwork.VirtualNetworkPeeringsClientGetResponse, error) {
	return f.getFn(ctx, rgName, vnetName, name, options)
}

func (f *fakePeeringsAPI) BeginDelete(ctx context.Context, rgName, vnetName, name string, options *armnetwork.VirtualNetworkPeeringsClientBeginDeleteOptions) (*runtime.Poller[armnetwork.VirtualNetworkPeeringsClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, vnetName, name, options)
}

func (f *fakePeeringsAPI) NewListPager(rgName, vnetName string, options *armnetwork.VirtualNetworkPeeringsClientListOptions) *runtime.Pager[armnetwork.VirtualNetworkPeeringsClientListResponse] {
	return f.newListPagerFn(rgName, vnetName, options)
}
