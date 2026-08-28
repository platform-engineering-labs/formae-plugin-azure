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
	testConnectionNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/connections/conn1"
	testConnectionGw1ID    = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/virtualNetworkGateways/vngw1"
	testConnectionGw2ID    = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/virtualNetworkGateways/vngw2"
	testConnectionLngID    = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/localNetworkGateways/lng1"
)

type fakeVirtualNetworkGatewayConnectionsAPI struct {
	beginCreateOrUpdateFn func(ctx context.Context, rgName, name string, params armnetwork.VirtualNetworkGatewayConnection, options *armnetwork.VirtualNetworkGatewayConnectionsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.VirtualNetworkGatewayConnectionsClientCreateOrUpdateResponse], error)
	getFn                 func(ctx context.Context, rgName, name string, options *armnetwork.VirtualNetworkGatewayConnectionsClientGetOptions) (armnetwork.VirtualNetworkGatewayConnectionsClientGetResponse, error)
	beginDeleteFn         func(ctx context.Context, rgName, name string, options *armnetwork.VirtualNetworkGatewayConnectionsClientBeginDeleteOptions) (*runtime.Poller[armnetwork.VirtualNetworkGatewayConnectionsClientDeleteResponse], error)
	newListPagerFn        func(rgName string, options *armnetwork.VirtualNetworkGatewayConnectionsClientListOptions) *runtime.Pager[armnetwork.VirtualNetworkGatewayConnectionsClientListResponse]
}

func (f *fakeVirtualNetworkGatewayConnectionsAPI) BeginCreateOrUpdate(ctx context.Context, rgName, name string, params armnetwork.VirtualNetworkGatewayConnection, options *armnetwork.VirtualNetworkGatewayConnectionsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.VirtualNetworkGatewayConnectionsClientCreateOrUpdateResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, rgName, name, params, options)
}

func (f *fakeVirtualNetworkGatewayConnectionsAPI) Get(ctx context.Context, rgName, name string, options *armnetwork.VirtualNetworkGatewayConnectionsClientGetOptions) (armnetwork.VirtualNetworkGatewayConnectionsClientGetResponse, error) {
	return f.getFn(ctx, rgName, name, options)
}

func (f *fakeVirtualNetworkGatewayConnectionsAPI) BeginDelete(ctx context.Context, rgName, name string, options *armnetwork.VirtualNetworkGatewayConnectionsClientBeginDeleteOptions) (*runtime.Poller[armnetwork.VirtualNetworkGatewayConnectionsClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, name, options)
}

func (f *fakeVirtualNetworkGatewayConnectionsAPI) NewListPager(rgName string, options *armnetwork.VirtualNetworkGatewayConnectionsClientListOptions) *runtime.Pager[armnetwork.VirtualNetworkGatewayConnectionsClientListResponse] {
	return f.newListPagerFn(rgName, options)
}

func newTestVirtualNetworkGatewayConnection(api virtualNetworkGatewayConnectionsAPI) *VirtualNetworkGatewayConnection {
	return &VirtualNetworkGatewayConnection{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func connectionDesired(routingWeight int) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":                     "conn1",
		"resourceGroupName":        "rg-1",
		"location":                 "eastus",
		"connectionType":           "IPsec",
		"virtualNetworkGateway1Id": testConnectionGw1ID,
		"localNetworkGateway2Id":   testConnectionLngID,
		"sharedKey":                "not-a-real-psk",
		"enableBgp":                false,
		"connectionProtocol":       "IKEv2",
		"connectionMode":           "Default",
		"routingWeight":            routingWeight,
		"dpdTimeoutSeconds":        45,
		"ipsecPolicies": []any{map[string]any{
			"saLifeTimeSeconds":   27000,
			"saDataSizeKilobytes": 102400000,
			"ipsecEncryption":     "GCMAES256",
			"ipsecIntegrity":      "GCMAES256",
			"ikeEncryption":       "AES256",
			"ikeIntegrity":        "SHA384",
			"dhGroup":             "DHGroup24",
			"pfsGroup":            "PFS24",
		}},
		"Tags": []any{map[string]any{"Key": "env", "Value": "test"}},
	})
	return out
}

func TestVirtualNetworkGatewayConnection_CRUD(t *testing.T) {
	connResult := armnetwork.VirtualNetworkGatewayConnection{
		ID:       to.Ptr(testConnectionNativeID),
		Name:     to.Ptr("conn1"),
		Location: to.Ptr("East US"),
		Properties: &armnetwork.VirtualNetworkGatewayConnectionPropertiesFormat{
			// ARM echoes every enum back with its own casing.
			ConnectionType: to.Ptr(armnetwork.VirtualNetworkGatewayConnectionType("ipsec")),
			// ARM inflates both peers into full gateway objects; only the ID is ours.
			VirtualNetworkGateway1: &armnetwork.VirtualNetworkGateway{
				ID:         to.Ptr(testConnectionGw1ID),
				Name:       to.Ptr("vngw1"),
				Location:   to.Ptr("East US"),
				Properties: &armnetwork.VirtualNetworkGatewayPropertiesFormat{},
			},
			LocalNetworkGateway2: &armnetwork.LocalNetworkGateway{
				ID:         to.Ptr(testConnectionLngID),
				Name:       to.Ptr("lng1"),
				Location:   to.Ptr("East US"),
				Properties: &armnetwork.LocalNetworkGatewayPropertiesFormat{},
			},
			// ARM does hand the shared key back; it must never reach state.
			SharedKey:          to.Ptr("not-a-real-psk"),
			EnableBgp:          to.Ptr(false),
			ConnectionProtocol: to.Ptr(armnetwork.VirtualNetworkGatewayConnectionProtocol("ikev2")),
			ConnectionMode:     to.Ptr(armnetwork.VirtualNetworkGatewayConnectionMode("default")),
			RoutingWeight:      to.Ptr(int32(0)),
			DpdTimeoutSeconds:  to.Ptr(int32(45)),
			IPSecPolicies: []*armnetwork.IPSecPolicy{{
				SaLifeTimeSeconds:   to.Ptr(int32(27000)),
				SaDataSizeKilobytes: to.Ptr(int32(102400000)),
				IPSecEncryption:     to.Ptr(armnetwork.IPSecEncryption("gcmaes256")),
				IPSecIntegrity:      to.Ptr(armnetwork.IPSecIntegrity("gcmaes256")),
				IkeEncryption:       to.Ptr(armnetwork.IkeEncryption("aes256")),
				IkeIntegrity:        to.Ptr(armnetwork.IkeIntegrity("sha384")),
				DhGroup:             to.Ptr(armnetwork.DhGroup("dhgroup24")),
				PfsGroup:            to.Ptr(armnetwork.PfsGroup("pfs24")),
			}},
			// Service state.
			ConnectionStatus:        to.Ptr(armnetwork.VirtualNetworkGatewayConnectionStatusNotConnected),
			EgressBytesTransferred:  to.Ptr(int64(0)),
			IngressBytesTransferred: to.Ptr(int64(0)),
			ProvisioningState:       to.Ptr(armnetwork.ProvisioningStateSucceeded),
			ResourceGUID:            to.Ptr("11112222-3333-4444-5555-666677778888"),
			TunnelConnectionStatus: []*armnetwork.TunnelConnectionHealth{{
				Tunnel: to.Ptr("tunnel0"),
			}},
		},
		Tags: map[string]*string{"env": to.Ptr("test")},
		Etag: to.Ptr("W/\"etag\""),
	}

	var sent armnetwork.VirtualNetworkGatewayConnection
	createCalls := 0
	deleteCalls := 0
	fake := &fakeVirtualNetworkGatewayConnectionsAPI{
		beginCreateOrUpdateFn: func(_ context.Context, rgName, name string, params armnetwork.VirtualNetworkGatewayConnection, _ *armnetwork.VirtualNetworkGatewayConnectionsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.VirtualNetworkGatewayConnectionsClientCreateOrUpdateResponse], error) {
			require.Equal(t, "rg-1", rgName)
			require.Equal(t, "conn1", name)
			sent = params
			createCalls++
			return newDonePoller(armnetwork.VirtualNetworkGatewayConnectionsClientCreateOrUpdateResponse{VirtualNetworkGatewayConnection: connResult}), nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armnetwork.VirtualNetworkGatewayConnectionsClientGetOptions) (armnetwork.VirtualNetworkGatewayConnectionsClientGetResponse, error) {
			return armnetwork.VirtualNetworkGatewayConnectionsClientGetResponse{VirtualNetworkGatewayConnection: connResult}, nil
		},
		beginDeleteFn: func(_ context.Context, _, _ string, _ *armnetwork.VirtualNetworkGatewayConnectionsClientBeginDeleteOptions) (*runtime.Poller[armnetwork.VirtualNetworkGatewayConnectionsClientDeleteResponse], error) {
			deleteCalls++
			return newDonePoller(armnetwork.VirtualNetworkGatewayConnectionsClientDeleteResponse{}), nil
		},
		newListPagerFn: func(_ string, _ *armnetwork.VirtualNetworkGatewayConnectionsClientListOptions) *runtime.Pager[armnetwork.VirtualNetworkGatewayConnectionsClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armnetwork.VirtualNetworkGatewayConnectionsClientListResponse]{
				More: func(_ armnetwork.VirtualNetworkGatewayConnectionsClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armnetwork.VirtualNetworkGatewayConnectionsClientListResponse) (armnetwork.VirtualNetworkGatewayConnectionsClientListResponse, error) {
					return armnetwork.VirtualNetworkGatewayConnectionsClientListResponse{
						VirtualNetworkGatewayConnectionListResult: armnetwork.VirtualNetworkGatewayConnectionListResult{
							Value: []*armnetwork.VirtualNetworkGatewayConnection{{ID: to.Ptr(testConnectionNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestVirtualNetworkGatewayConnection(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "conn1", Properties: connectionDesired(0),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testConnectionNativeID, got.ProgressResult.NativeID)

		require.Equal(t, "eastus", *sent.Location)
		require.Equal(t, armnetwork.VirtualNetworkGatewayConnectionTypeIPsec, *sent.Properties.ConnectionType)
		// ARM models the peers as whole gateway objects; only the ID is sent.
		require.Equal(t, testConnectionGw1ID, *sent.Properties.VirtualNetworkGateway1.ID)
		require.Nil(t, sent.Properties.VirtualNetworkGateway1.Properties)
		require.Equal(t, testConnectionLngID, *sent.Properties.LocalNetworkGateway2.ID)
		require.Nil(t, sent.Properties.VirtualNetworkGateway2)
		require.Nil(t, sent.Properties.Peer)
		// The shared key must reach ARM even though it is never read back.
		require.Equal(t, "not-a-real-psk", *sent.Properties.SharedKey)
		require.False(t, *sent.Properties.EnableBgp)
		require.Equal(t, armnetwork.VirtualNetworkGatewayConnectionProtocolIKEv2, *sent.Properties.ConnectionProtocol)
		require.Equal(t, armnetwork.VirtualNetworkGatewayConnectionModeDefault, *sent.Properties.ConnectionMode)
		require.Equal(t, int32(45), *sent.Properties.DpdTimeoutSeconds)
		require.Len(t, sent.Properties.IPSecPolicies, 1)
		policy := sent.Properties.IPSecPolicies[0]
		require.Equal(t, int32(27000), *policy.SaLifeTimeSeconds)
		require.Equal(t, armnetwork.IPSecEncryptionGCMAES256, *policy.IPSecEncryption)
		require.Equal(t, armnetwork.IkeIntegritySHA384, *policy.IkeIntegrity)
		require.Equal(t, armnetwork.DhGroupDHGroup24, *policy.DhGroup)
		require.Equal(t, armnetwork.PfsGroupPFS24, *policy.PfsGroup)
		require.Equal(t, "test", *sent.Tags["env"])
	})

	t.Run("Create_requires_first_gateway", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "conn1", "resourceGroupName": "rg-1", "location": "eastus",
			"connectionType": "IPsec",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "virtualNetworkGateway1Id is required")
	})

	// Each connection type has exactly one peer field, and ARM's rejection for the
	// wrong one is opaque.
	t.Run("Create_ipsec_requires_local_network_gateway", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "conn1", "resourceGroupName": "rg-1", "location": "eastus",
			"connectionType": "IPsec", "virtualNetworkGateway1Id": testConnectionGw1ID,
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "localNetworkGateway2Id is required for an IPsec connection")
	})

	t.Run("Create_vnet2vnet_requires_second_gateway", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "conn1", "resourceGroupName": "rg-1", "location": "eastus",
			"connectionType": "Vnet2Vnet", "virtualNetworkGateway1Id": testConnectionGw1ID,
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "virtualNetworkGateway2Id is required for a Vnet2Vnet connection")
	})

	t.Run("Create_vnet2vnet_sends_second_gateway", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "conn1", "resourceGroupName": "rg-1", "location": "eastus",
			"connectionType":           "Vnet2Vnet",
			"virtualNetworkGateway1Id": testConnectionGw1ID,
			"virtualNetworkGateway2Id": testConnectionGw2ID,
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.Equal(t, testConnectionGw2ID, *sent.Properties.VirtualNetworkGateway2.ID)
		require.Nil(t, sent.Properties.LocalNetworkGateway2)
	})

	t.Run("Create_expressroute_requires_peer", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "conn1", "resourceGroupName": "rg-1", "location": "eastus",
			"connectionType": "ExpressRoute", "virtualNetworkGateway1Id": testConnectionGw1ID,
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "peerId is required for an ExpressRoute connection")
	})

	// Azure accepts at most one custom policy per connection.
	t.Run("Create_rejects_two_ipsec_policies", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "conn1", "resourceGroupName": "rg-1", "location": "eastus",
			"connectionType":           "IPsec",
			"virtualNetworkGateway1Id": testConnectionGw1ID,
			"localNetworkGateway2Id":   testConnectionLngID,
			"ipsecPolicies":            []any{map[string]any{}, map[string]any{}},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "ipsecPolicies accepts at most one entry")
	})

	// The native ID reported while the LRO is still running must match the path ARM
	// actually assigns, or the resource is orphaned once it completes.
	t.Run("PendingCreateReportsRealNativeID", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, _ armnetwork.VirtualNetworkGatewayConnection, _ *armnetwork.VirtualNetworkGatewayConnectionsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.VirtualNetworkGatewayConnectionsClientCreateOrUpdateResponse], error) {
			return newPendingPoller[armnetwork.VirtualNetworkGatewayConnectionsClientCreateOrUpdateResponse](), nil
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "conn1", Properties: connectionDesired(0),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusInProgress, got.ProgressResult.OperationStatus)
		require.Equal(t, testConnectionNativeID, got.ProgressResult.NativeID)
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testConnectionNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "conn1", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "eastus", props["location"])
		// Every enum comes back from ARM lower-cased and must be canonicalised.
		require.Equal(t, "IPsec", props["connectionType"])
		require.Equal(t, "IKEv2", props["connectionProtocol"])
		require.Equal(t, "Default", props["connectionMode"])
		// Only the peers' ARM IDs are read back, never their inflated bodies.
		require.Equal(t, testConnectionGw1ID, props["virtualNetworkGateway1Id"])
		require.Equal(t, testConnectionLngID, props["localNetworkGateway2Id"])
		require.Equal(t, false, props["enableBgp"])
		require.EqualValues(t, 0, props["routingWeight"])
		require.EqualValues(t, 45, props["dpdTimeoutSeconds"])

		policies := props["ipsecPolicies"].([]any)
		require.Len(t, policies, 1)
		policy := policies[0].(map[string]any)
		require.EqualValues(t, 27000, policy["saLifeTimeSeconds"])
		require.EqualValues(t, 102400000, policy["saDataSizeKilobytes"])
		require.Equal(t, "GCMAES256", policy["ipsecEncryption"])
		require.Equal(t, "GCMAES256", policy["ipsecIntegrity"])
		require.Equal(t, "AES256", policy["ikeEncryption"])
		require.Equal(t, "SHA384", policy["ikeIntegrity"])
		require.Equal(t, "DHGroup24", policy["dhGroup"])
		require.Equal(t, "PFS24", policy["pfsGroup"])
	})

	// The shared key ARM hands back must never reach stored state, and neither may
	// the inflated peer bodies or the connection's live counters.
	t.Run("Read_drops_service_state_and_secrets", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testConnectionNativeID})
		require.NoError(t, err)
		for _, key := range []string{
			"sharedKey", "not-a-real-psk", "authorizationKey",
			"provisioningState", "resourceGuid", "etag", "connectionStatus",
			"egressBytesTransferred", "ingressBytesTransferred",
			"tunnelConnectionStatus",
		} {
			require.NotContains(t, got.Properties, key)
		}
		// The peers must come back as bare ARM ID strings, not as the inflated
		// gateway objects ARM returns.
		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.IsType(t, "", props["virtualNetworkGateway1Id"])
		require.IsType(t, "", props["localNetworkGateway2Id"])
	})

	t.Run("Update_reissues_create_or_update", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, params armnetwork.VirtualNetworkGatewayConnection, _ *armnetwork.VirtualNetworkGatewayConnectionsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.VirtualNetworkGatewayConnectionsClientCreateOrUpdateResponse], error) {
			sent = params
			createCalls++
			return newDonePoller(armnetwork.VirtualNetworkGatewayConnectionsClientCreateOrUpdateResponse{VirtualNetworkGatewayConnection: connResult}), nil
		}
		before := createCalls
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testConnectionNativeID,
			DesiredProperties: connectionDesired(20),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, createCalls)
		require.Equal(t, int32(20), *sent.Properties.RoutingWeight)
		// Location, the connection type and both peers must ride along: a PUT without
		// them is rejected.
		require.Equal(t, "eastus", *sent.Location)
		require.Equal(t, armnetwork.VirtualNetworkGatewayConnectionTypeIPsec, *sent.Properties.ConnectionType)
		require.Equal(t, testConnectionGw1ID, *sent.Properties.VirtualNetworkGateway1.ID)
		require.Equal(t, testConnectionLngID, *sent.Properties.LocalNetworkGateway2.ID)
	})

	t.Run("Delete", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testConnectionNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _ string, _ *armnetwork.VirtualNetworkGatewayConnectionsClientBeginDeleteOptions) (*runtime.Poller[armnetwork.VirtualNetworkGatewayConnectionsClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testConnectionNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_resource_group", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testConnectionNativeID}, got.NativeIDs)
	})

	// ARM offers no subscription-wide listing for this type.
	t.Run("List_without_group_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})

	t.Run("Read_NotFound", func(t *testing.T) {
		fake.getFn = func(_ context.Context, _, _ string, _ *armnetwork.VirtualNetworkGatewayConnectionsClientGetOptions) (armnetwork.VirtualNetworkGatewayConnectionsClientGetResponse, error) {
			return armnetwork.VirtualNetworkGatewayConnectionsClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testConnectionNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
	})
}
