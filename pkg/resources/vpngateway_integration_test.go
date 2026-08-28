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
	testVpnGatewayNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/vpnGateways/vpngw1"
	testVpnGatewayHubID    = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/virtualHubs/hub1"
	testVpnGatewaySiteID   = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/vpnSites/site1"
)

type fakeVpnGatewaysAPI struct {
	beginCreateOrUpdateFn         func(ctx context.Context, rgName, name string, params armnetwork.VPNGateway, options *armnetwork.VPNGatewaysClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.VPNGatewaysClientCreateOrUpdateResponse], error)
	getFn                         func(ctx context.Context, rgName, name string, options *armnetwork.VPNGatewaysClientGetOptions) (armnetwork.VPNGatewaysClientGetResponse, error)
	beginDeleteFn                 func(ctx context.Context, rgName, name string, options *armnetwork.VPNGatewaysClientBeginDeleteOptions) (*runtime.Poller[armnetwork.VPNGatewaysClientDeleteResponse], error)
	newListByResourceGroupPagerFn func(rgName string, options *armnetwork.VPNGatewaysClientListByResourceGroupOptions) *runtime.Pager[armnetwork.VPNGatewaysClientListByResourceGroupResponse]
	newListPagerFn                func(options *armnetwork.VPNGatewaysClientListOptions) *runtime.Pager[armnetwork.VPNGatewaysClientListResponse]
}

func (f *fakeVpnGatewaysAPI) BeginCreateOrUpdate(ctx context.Context, rgName, name string, params armnetwork.VPNGateway, options *armnetwork.VPNGatewaysClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.VPNGatewaysClientCreateOrUpdateResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, rgName, name, params, options)
}

func (f *fakeVpnGatewaysAPI) Get(ctx context.Context, rgName, name string, options *armnetwork.VPNGatewaysClientGetOptions) (armnetwork.VPNGatewaysClientGetResponse, error) {
	return f.getFn(ctx, rgName, name, options)
}

func (f *fakeVpnGatewaysAPI) BeginDelete(ctx context.Context, rgName, name string, options *armnetwork.VPNGatewaysClientBeginDeleteOptions) (*runtime.Poller[armnetwork.VPNGatewaysClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, name, options)
}

func (f *fakeVpnGatewaysAPI) NewListByResourceGroupPager(rgName string, options *armnetwork.VPNGatewaysClientListByResourceGroupOptions) *runtime.Pager[armnetwork.VPNGatewaysClientListByResourceGroupResponse] {
	return f.newListByResourceGroupPagerFn(rgName, options)
}

func (f *fakeVpnGatewaysAPI) NewListPager(options *armnetwork.VPNGatewaysClientListOptions) *runtime.Pager[armnetwork.VPNGatewaysClientListResponse] {
	return f.newListPagerFn(options)
}

func newTestVpnGateway(api vpnGatewaysAPI) *VpnGateway {
	return &VpnGateway{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func vpnGatewayDesired(scaleUnit, routingWeight int) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":                "vpngw1",
		"resourceGroupName":   "rg-1",
		"location":            "eastus",
		"virtualHubId":        testVpnGatewayHubID,
		"vpnGatewayScaleUnit": scaleUnit,
		"bgpSettings": map[string]any{
			"asn":        65515,
			"peerWeight": 0,
		},
		"connections": []any{map[string]any{
			"name":                      "conn0",
			"remoteVpnSiteId":           testVpnGatewaySiteID,
			"connectionBandwidth":       10,
			"enableBgp":                 false,
			"routingWeight":             routingWeight,
			"vpnConnectionProtocolType": "IKEv2",
			"sharedKey":                 "not-a-real-psk",
		}},
		"Tags": []any{map[string]any{"Key": "env", "Value": "test"}},
	})
	return out
}

func TestVpnGateway_CRUD(t *testing.T) {
	gatewayResult := armnetwork.VPNGateway{
		ID:       to.Ptr(testVpnGatewayNativeID),
		Name:     to.Ptr("vpngw1"),
		Location: to.Ptr("East US"),
		Properties: &armnetwork.VPNGatewayProperties{
			VirtualHub:          &armnetwork.SubResource{ID: to.Ptr(testVpnGatewayHubID)},
			VPNGatewayScaleUnit: to.Ptr(int32(1)),
			BgpSettings: &armnetwork.BgpSettings{
				Asn:        to.Ptr(int64(65515)),
				PeerWeight: to.Ptr(int32(0)),
				// Allocated by Azure out of the hub prefix; must not reach state.
				BgpPeeringAddress: to.Ptr("10.100.0.12"),
				BgpPeeringAddresses: []*armnetwork.IPConfigurationBgpPeeringAddress{{
					IPConfigurationID: to.Ptr("Instance0"),
				}},
			},
			Connections: []*armnetwork.VPNConnection{{
				// ARM assigns the child ID and etag; neither may reach state.
				ID:   to.Ptr(testVpnGatewayNativeID + "/vpnConnections/conn0"),
				Name: to.Ptr("conn0"),
				Etag: to.Ptr("W/\"conn-etag\""),
				Properties: &armnetwork.VPNConnectionProperties{
					RemoteVPNSite:       &armnetwork.SubResource{ID: to.Ptr(testVpnGatewaySiteID)},
					ConnectionBandwidth: to.Ptr(int32(10)),
					EnableBgp:           to.Ptr(false),
					RoutingWeight:       to.Ptr(int32(0)),
					// ARM echoes the IKE version back with its own casing.
					VPNConnectionProtocolType: to.Ptr(armnetwork.VirtualNetworkGatewayConnectionProtocol("ikev2")),
					// Azure seeds one link connection per remote link, and returns the
					// shared key. Neither is modelled.
					SharedKey: to.Ptr("not-a-real-psk"),
					VPNLinkConnections: []*armnetwork.VPNSiteLinkConnection{{
						Name: to.Ptr("conn0-link0"),
					}},
					ConnectionStatus:       to.Ptr(armnetwork.VPNConnectionStatusNotConnected),
					EgressBytesTransferred: to.Ptr(int64(0)),
					ProvisioningState:      to.Ptr(armnetwork.ProvisioningStateSucceeded),
				},
			}},
			// Service state: the gateway's instance IPs and provisioning state.
			IPConfigurations: []*armnetwork.VPNGatewayIPConfiguration{{
				ID: to.Ptr("Instance0"),
			}},
			ProvisioningState: to.Ptr(armnetwork.ProvisioningStateSucceeded),
		},
		Tags: map[string]*string{"env": to.Ptr("test")},
		Etag: to.Ptr("W/\"etag\""),
	}

	var sent armnetwork.VPNGateway
	createCalls := 0
	deleteCalls := 0
	fake := &fakeVpnGatewaysAPI{
		beginCreateOrUpdateFn: func(_ context.Context, rgName, name string, params armnetwork.VPNGateway, _ *armnetwork.VPNGatewaysClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.VPNGatewaysClientCreateOrUpdateResponse], error) {
			require.Equal(t, "rg-1", rgName)
			require.Equal(t, "vpngw1", name)
			sent = params
			createCalls++
			return newDonePoller(armnetwork.VPNGatewaysClientCreateOrUpdateResponse{VPNGateway: gatewayResult}), nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armnetwork.VPNGatewaysClientGetOptions) (armnetwork.VPNGatewaysClientGetResponse, error) {
			return armnetwork.VPNGatewaysClientGetResponse{VPNGateway: gatewayResult}, nil
		},
		beginDeleteFn: func(_ context.Context, _, _ string, _ *armnetwork.VPNGatewaysClientBeginDeleteOptions) (*runtime.Poller[armnetwork.VPNGatewaysClientDeleteResponse], error) {
			deleteCalls++
			return newDonePoller(armnetwork.VPNGatewaysClientDeleteResponse{}), nil
		},
		newListByResourceGroupPagerFn: func(_ string, _ *armnetwork.VPNGatewaysClientListByResourceGroupOptions) *runtime.Pager[armnetwork.VPNGatewaysClientListByResourceGroupResponse] {
			return runtime.NewPager(runtime.PagingHandler[armnetwork.VPNGatewaysClientListByResourceGroupResponse]{
				More: func(_ armnetwork.VPNGatewaysClientListByResourceGroupResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armnetwork.VPNGatewaysClientListByResourceGroupResponse) (armnetwork.VPNGatewaysClientListByResourceGroupResponse, error) {
					return armnetwork.VPNGatewaysClientListByResourceGroupResponse{
						ListVPNGatewaysResult: armnetwork.ListVPNGatewaysResult{
							Value: []*armnetwork.VPNGateway{{ID: to.Ptr(testVpnGatewayNativeID)}},
						},
					}, nil
				},
			})
		},
		newListPagerFn: func(_ *armnetwork.VPNGatewaysClientListOptions) *runtime.Pager[armnetwork.VPNGatewaysClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armnetwork.VPNGatewaysClientListResponse]{
				More: func(_ armnetwork.VPNGatewaysClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armnetwork.VPNGatewaysClientListResponse) (armnetwork.VPNGatewaysClientListResponse, error) {
					return armnetwork.VPNGatewaysClientListResponse{
						ListVPNGatewaysResult: armnetwork.ListVPNGatewaysResult{
							Value: []*armnetwork.VPNGateway{{ID: to.Ptr(testVpnGatewayNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestVpnGateway(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "vpngw1", Properties: vpnGatewayDesired(1, 0),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testVpnGatewayNativeID, got.ProgressResult.NativeID)

		require.Equal(t, "eastus", *sent.Location)
		require.Equal(t, testVpnGatewayHubID, *sent.Properties.VirtualHub.ID)
		require.Equal(t, int32(1), *sent.Properties.VPNGatewayScaleUnit)
		require.Equal(t, int64(65515), *sent.Properties.BgpSettings.Asn)
		require.Equal(t, int32(0), *sent.Properties.BgpSettings.PeerWeight)
		require.Len(t, sent.Properties.Connections, 1)
		conn := sent.Properties.Connections[0]
		require.Equal(t, "conn0", *conn.Name)
		require.Equal(t, testVpnGatewaySiteID, *conn.Properties.RemoteVPNSite.ID)
		require.Equal(t, int32(10), *conn.Properties.ConnectionBandwidth)
		require.Equal(t, armnetwork.VirtualNetworkGatewayConnectionProtocolIKEv2, *conn.Properties.VPNConnectionProtocolType)
		// The shared key must reach ARM even though it is never read back.
		require.Equal(t, "not-a-real-psk", *conn.Properties.SharedKey)
		require.Equal(t, "test", *sent.Tags["env"])
	})

	t.Run("Create_requires_virtual_hub", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "vpngw1", "resourceGroupName": "rg-1", "location": "eastus",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "virtualHubId is required")
	})

	t.Run("Create_requires_remote_site_on_every_connection", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "vpngw1", "resourceGroupName": "rg-1", "location": "eastus",
			"virtualHubId": testVpnGatewayHubID,
			"connections":  []any{map[string]any{"name": "conn0"}},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "needs a remoteVpnSiteId")
	})

	// The native ID reported while the LRO is still running must match the path ARM
	// actually assigns, or a 30-minute create orphans a billed gateway.
	t.Run("PendingCreateReportsRealNativeID", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, _ armnetwork.VPNGateway, _ *armnetwork.VPNGatewaysClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.VPNGatewaysClientCreateOrUpdateResponse], error) {
			return newPendingPoller[armnetwork.VPNGatewaysClientCreateOrUpdateResponse](), nil
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "vpngw1", Properties: vpnGatewayDesired(1, 0),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusInProgress, got.ProgressResult.OperationStatus)
		require.Equal(t, testVpnGatewayNativeID, got.ProgressResult.NativeID)
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testVpnGatewayNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "vpngw1", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "eastus", props["location"])
		require.Equal(t, testVpnGatewayHubID, props["virtualHubId"])
		require.EqualValues(t, 1, props["vpnGatewayScaleUnit"])

		bgp := props["bgpSettings"].(map[string]any)
		require.EqualValues(t, 65515, bgp["asn"])
		require.EqualValues(t, 0, bgp["peerWeight"])
		require.NotContains(t, bgp, "bgpPeeringAddress")

		conns := props["connections"].([]any)
		require.Len(t, conns, 1)
		conn := conns[0].(map[string]any)
		require.Equal(t, "conn0", conn["name"])
		require.Equal(t, testVpnGatewaySiteID, conn["remoteVpnSiteId"])
		require.EqualValues(t, 10, conn["connectionBandwidth"])
		// ARM returns "ikev2"; the schema union is "IKEv2".
		require.Equal(t, "IKEv2", conn["vpnConnectionProtocolType"])
	})

	// Service state, the Azure-allocated peering addresses and the write-only shared
	// key must never reach stored state.
	t.Run("Read_drops_service_state_and_secrets", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testVpnGatewayNativeID})
		require.NoError(t, err)
		for _, key := range []string{
			"provisioningState", "ipConfigurations", "etag", "bgpPeeringAddress",
			"bgpPeeringAddresses", "vpnLinkConnections", "connectionStatus",
			"egressBytesTransferred", "sharedKey", "not-a-real-psk",
		} {
			require.NotContains(t, got.Properties, key)
		}
	})

	t.Run("Update_reissues_create_or_update", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, params armnetwork.VPNGateway, _ *armnetwork.VPNGatewaysClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.VPNGatewaysClientCreateOrUpdateResponse], error) {
			sent = params
			createCalls++
			return newDonePoller(armnetwork.VPNGatewaysClientCreateOrUpdateResponse{VPNGateway: gatewayResult}), nil
		}
		before := createCalls
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testVpnGatewayNativeID,
			DesiredProperties: vpnGatewayDesired(2, 10),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, createCalls)
		require.Equal(t, int32(2), *sent.Properties.VPNGatewayScaleUnit)
		require.Equal(t, int32(10), *sent.Properties.Connections[0].Properties.RoutingWeight)
		// Location and the hub reference must ride along: a PUT without them is rejected.
		require.Equal(t, "eastus", *sent.Location)
		require.Equal(t, testVpnGatewayHubID, *sent.Properties.VirtualHub.ID)
	})

	t.Run("Delete", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testVpnGatewayNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _ string, _ *armnetwork.VPNGatewaysClientBeginDeleteOptions) (*runtime.Poller[armnetwork.VPNGatewaysClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testVpnGatewayNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_resource_group", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testVpnGatewayNativeID}, got.NativeIDs)
	})

	t.Run("List_by_subscription", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Equal(t, []string{testVpnGatewayNativeID}, got.NativeIDs)
	})

	t.Run("Read_NotFound", func(t *testing.T) {
		fake.getFn = func(_ context.Context, _, _ string, _ *armnetwork.VPNGatewaysClientGetOptions) (armnetwork.VPNGatewaysClientGetResponse, error) {
			return armnetwork.VPNGatewaysClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testVpnGatewayNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
	})
}
