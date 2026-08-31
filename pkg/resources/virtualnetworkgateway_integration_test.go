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
	testVnetGatewayNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/virtualNetworkGateways/vngw1"
	testGatewaySubnetID     = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/virtualNetworks/vnet1/subnets/GatewaySubnet"
	testVnetGatewayPipID    = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/publicIPAddresses/pip1"
	testVnetGatewayPipID2   = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/publicIPAddresses/pip2"
)

type fakeVirtualNetworkGatewaysAPI struct {
	beginCreateOrUpdateFn func(ctx context.Context, rgName, name string, params armnetwork.VirtualNetworkGateway, options *armnetwork.VirtualNetworkGatewaysClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.VirtualNetworkGatewaysClientCreateOrUpdateResponse], error)
	getFn                 func(ctx context.Context, rgName, name string, options *armnetwork.VirtualNetworkGatewaysClientGetOptions) (armnetwork.VirtualNetworkGatewaysClientGetResponse, error)
	beginDeleteFn         func(ctx context.Context, rgName, name string, options *armnetwork.VirtualNetworkGatewaysClientBeginDeleteOptions) (*runtime.Poller[armnetwork.VirtualNetworkGatewaysClientDeleteResponse], error)
	newListPagerFn        func(rgName string, options *armnetwork.VirtualNetworkGatewaysClientListOptions) *runtime.Pager[armnetwork.VirtualNetworkGatewaysClientListResponse]
}

func (f *fakeVirtualNetworkGatewaysAPI) BeginCreateOrUpdate(ctx context.Context, rgName, name string, params armnetwork.VirtualNetworkGateway, options *armnetwork.VirtualNetworkGatewaysClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.VirtualNetworkGatewaysClientCreateOrUpdateResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, rgName, name, params, options)
}

func (f *fakeVirtualNetworkGatewaysAPI) Get(ctx context.Context, rgName, name string, options *armnetwork.VirtualNetworkGatewaysClientGetOptions) (armnetwork.VirtualNetworkGatewaysClientGetResponse, error) {
	return f.getFn(ctx, rgName, name, options)
}

func (f *fakeVirtualNetworkGatewaysAPI) BeginDelete(ctx context.Context, rgName, name string, options *armnetwork.VirtualNetworkGatewaysClientBeginDeleteOptions) (*runtime.Poller[armnetwork.VirtualNetworkGatewaysClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, name, options)
}

func (f *fakeVirtualNetworkGatewaysAPI) NewListPager(rgName string, options *armnetwork.VirtualNetworkGatewaysClientListOptions) *runtime.Pager[armnetwork.VirtualNetworkGatewaysClientListResponse] {
	return f.newListPagerFn(rgName, options)
}

func newTestVirtualNetworkGateway(api virtualNetworkGatewaysAPI) *VirtualNetworkGateway {
	return &VirtualNetworkGateway{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func vnetGatewayDesired(skuName string, peerWeight int) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":              "vngw1",
		"resourceGroupName": "rg-1",
		"location":          "eastus",
		"gatewayType":       "Vpn",
		"vpnType":           "RouteBased",
		"sku":               map[string]any{"name": skuName, "tier": skuName},
		"ipConfigurations": []any{map[string]any{
			"name":              "default",
			"subnetId":          testGatewaySubnetID,
			"publicIpAddressId": testVnetGatewayPipID,
		}},
		"activeActive":         false,
		"enableBgp":            true,
		"bgpSettings":          map[string]any{"asn": 65515, "peerWeight": peerWeight},
		"vpnGatewayGeneration": "Generation1",
		"vpnClientConfiguration": map[string]any{
			"vpnClientAddressPool":   []any{"172.16.201.0/24"},
			"vpnClientProtocols":     []any{"OpenVPN"},
			"vpnAuthenticationTypes": []any{"Certificate"},
			"vpnClientRootCertificates": []any{map[string]any{
				"name":           "root",
				"publicCertData": "MIIBase64CertBody",
			}},
		},
		"Tags": []any{map[string]any{"Key": "env", "Value": "test"}},
	})
	return out
}

func TestVirtualNetworkGateway_CRUD(t *testing.T) {
	gatewayResult := armnetwork.VirtualNetworkGateway{
		ID:       to.Ptr(testVnetGatewayNativeID),
		Name:     to.Ptr("vngw1"),
		Location: to.Ptr("East US"),
		Properties: &armnetwork.VirtualNetworkGatewayPropertiesFormat{
			// ARM echoes every enum back with its own casing.
			GatewayType: to.Ptr(armnetwork.VirtualNetworkGatewayType("vpn")),
			VPNType:     to.Ptr(armnetwork.VPNType("routebased")),
			SKU: &armnetwork.VirtualNetworkGatewaySKU{
				Name: to.Ptr(armnetwork.VirtualNetworkGatewaySKUName("vpngw1")),
				Tier: to.Ptr(armnetwork.VirtualNetworkGatewaySKUTier("vpngw1")),
				// Instance count Azure derives from the SKU; not modelled.
				Capacity: to.Ptr(int32(2)),
			},
			IPConfigurations: []*armnetwork.VirtualNetworkGatewayIPConfiguration{{
				// ARM assigns the child ID and etag; neither may reach state.
				ID:   to.Ptr(testVnetGatewayNativeID + "/ipConfigurations/default"),
				Name: to.Ptr("default"),
				Etag: to.Ptr("W/\"ipconf-etag\""),
				Properties: &armnetwork.VirtualNetworkGatewayIPConfigurationPropertiesFormat{
					Subnet:                    &armnetwork.SubResource{ID: to.Ptr(testGatewaySubnetID)},
					PublicIPAddress:           &armnetwork.SubResource{ID: to.Ptr(testVnetGatewayPipID)},
					PrivateIPAllocationMethod: to.Ptr(armnetwork.IPAllocationMethod("dynamic")),
					// Azure picks the private address out of the GatewaySubnet.
					PrivateIPAddress:  to.Ptr("10.20.0.6"),
					ProvisioningState: to.Ptr(armnetwork.ProvisioningStateSucceeded),
				},
			}},
			Active:    to.Ptr(false),
			EnableBgp: to.Ptr(true),
			BgpSettings: &armnetwork.BgpSettings{
				Asn:        to.Ptr(int64(65515)),
				PeerWeight: to.Ptr(int32(0)),
				// Allocated by Azure out of the GatewaySubnet; must not reach state.
				BgpPeeringAddress: to.Ptr("10.20.0.254"),
				BgpPeeringAddresses: []*armnetwork.IPConfigurationBgpPeeringAddress{{
					IPConfigurationID: to.Ptr(testVnetGatewayNativeID + "/ipConfigurations/default"),
				}},
			},
			VPNGatewayGeneration: to.Ptr(armnetwork.VPNGatewayGeneration("generation1")),
			VPNClientConfiguration: &armnetwork.VPNClientConfiguration{
				VPNClientAddressPool: &armnetwork.AddressSpace{
					AddressPrefixes: []*string{to.Ptr("172.16.201.0/24")},
				},
				VPNClientProtocols:     []*armnetwork.VPNClientProtocol{to.Ptr(armnetwork.VPNClientProtocol("openvpn"))},
				VPNAuthenticationTypes: []*armnetwork.VPNAuthenticationType{to.Ptr(armnetwork.VPNAuthenticationType("certificate"))},
				VPNClientRootCertificates: []*armnetwork.VPNClientRootCertificate{{
					ID:   to.Ptr(testVnetGatewayNativeID + "/vpnClientRootCertificates/root"),
					Name: to.Ptr("root"),
					Etag: to.Ptr("W/\"cert-etag\""),
					Properties: &armnetwork.VPNClientRootCertificatePropertiesFormat{
						PublicCertData:    to.Ptr("MIIBase64CertBody"),
						ProvisioningState: to.Ptr(armnetwork.ProvisioningStateSucceeded),
					},
				}},
			},
			// Service state.
			ProvisioningState: to.Ptr(armnetwork.ProvisioningStateSucceeded),
			ResourceGUID:      to.Ptr("aa11bb22-cc33-dd44-ee55-ff6677889900"),
		},
		Tags: map[string]*string{"env": to.Ptr("test")},
		Etag: to.Ptr("W/\"etag\""),
	}

	var sent armnetwork.VirtualNetworkGateway
	createCalls := 0
	deleteCalls := 0
	fake := &fakeVirtualNetworkGatewaysAPI{
		beginCreateOrUpdateFn: func(_ context.Context, rgName, name string, params armnetwork.VirtualNetworkGateway, _ *armnetwork.VirtualNetworkGatewaysClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.VirtualNetworkGatewaysClientCreateOrUpdateResponse], error) {
			require.Equal(t, "rg-1", rgName)
			require.Equal(t, "vngw1", name)
			sent = params
			createCalls++
			return newDonePoller(armnetwork.VirtualNetworkGatewaysClientCreateOrUpdateResponse{VirtualNetworkGateway: gatewayResult}), nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armnetwork.VirtualNetworkGatewaysClientGetOptions) (armnetwork.VirtualNetworkGatewaysClientGetResponse, error) {
			return armnetwork.VirtualNetworkGatewaysClientGetResponse{VirtualNetworkGateway: gatewayResult}, nil
		},
		beginDeleteFn: func(_ context.Context, _, _ string, _ *armnetwork.VirtualNetworkGatewaysClientBeginDeleteOptions) (*runtime.Poller[armnetwork.VirtualNetworkGatewaysClientDeleteResponse], error) {
			deleteCalls++
			return newDonePoller(armnetwork.VirtualNetworkGatewaysClientDeleteResponse{}), nil
		},
		newListPagerFn: func(_ string, _ *armnetwork.VirtualNetworkGatewaysClientListOptions) *runtime.Pager[armnetwork.VirtualNetworkGatewaysClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armnetwork.VirtualNetworkGatewaysClientListResponse]{
				More: func(_ armnetwork.VirtualNetworkGatewaysClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armnetwork.VirtualNetworkGatewaysClientListResponse) (armnetwork.VirtualNetworkGatewaysClientListResponse, error) {
					return armnetwork.VirtualNetworkGatewaysClientListResponse{
						VirtualNetworkGatewayListResult: armnetwork.VirtualNetworkGatewayListResult{
							Value: []*armnetwork.VirtualNetworkGateway{{ID: to.Ptr(testVnetGatewayNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestVirtualNetworkGateway(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "vngw1", Properties: vnetGatewayDesired("VpnGw1", 0),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testVnetGatewayNativeID, got.ProgressResult.NativeID)

		require.Equal(t, "eastus", *sent.Location)
		require.Equal(t, armnetwork.VirtualNetworkGatewayTypeVPN, *sent.Properties.GatewayType)
		require.Equal(t, armnetwork.VPNTypeRouteBased, *sent.Properties.VPNType)
		require.Equal(t, armnetwork.VirtualNetworkGatewaySKUNameVPNGw1, *sent.Properties.SKU.Name)
		require.Equal(t, armnetwork.VirtualNetworkGatewaySKUTierVPNGw1, *sent.Properties.SKU.Tier)
		require.Len(t, sent.Properties.IPConfigurations, 1)
		cfg := sent.Properties.IPConfigurations[0]
		require.Equal(t, testGatewaySubnetID, *cfg.Properties.Subnet.ID)
		require.Equal(t, testVnetGatewayPipID, *cfg.Properties.PublicIPAddress.ID)
		require.False(t, *sent.Properties.Active)
		require.True(t, *sent.Properties.EnableBgp)
		require.Equal(t, int64(65515), *sent.Properties.BgpSettings.Asn)
		require.Equal(t, armnetwork.VPNGatewayGenerationGeneration1, *sent.Properties.VPNGatewayGeneration)

		vpnClient := sent.Properties.VPNClientConfiguration
		require.Equal(t, "172.16.201.0/24", *vpnClient.VPNClientAddressPool.AddressPrefixes[0])
		require.Equal(t, armnetwork.VPNClientProtocolOpenVPN, *vpnClient.VPNClientProtocols[0])
		require.Equal(t, armnetwork.VPNAuthenticationTypeCertificate, *vpnClient.VPNAuthenticationTypes[0])
		require.Equal(t, "root", *vpnClient.VPNClientRootCertificates[0].Name)
		require.Equal(t, "MIIBase64CertBody", *vpnClient.VPNClientRootCertificates[0].Properties.PublicCertData)
		require.Equal(t, "test", *sent.Tags["env"])
	})

	t.Run("Create_requires_gateway_type", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "vngw1", "resourceGroupName": "rg-1", "location": "eastus",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "gatewayType is required")
	})

	t.Run("Create_requires_sku", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "vngw1", "resourceGroupName": "rg-1", "location": "eastus",
			"gatewayType": "Vpn", "vpnType": "RouteBased",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "sku is required")
	})

	// Azure accepts a gateway only in a subnet literally named GatewaySubnet, and
	// rejects anything else after tens of minutes of provisioning.
	t.Run("Create_rejects_wrong_subnet_name", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "vngw1", "resourceGroupName": "rg-1", "location": "eastus",
			"gatewayType": "Vpn", "vpnType": "RouteBased",
			"sku": map[string]any{"name": "VpnGw1", "tier": "VpnGw1"},
			"ipConfigurations": []any{map[string]any{
				"name":              "default",
				"subnetId":          "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/virtualNetworks/vnet1/subnets/default",
				"publicIpAddressId": testVnetGatewayPipID,
			}},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "requires a subnet named exactly GatewaySubnet")
	})

	t.Run("Create_active_active_requires_two_front_ends", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "vngw1", "resourceGroupName": "rg-1", "location": "eastus",
			"gatewayType": "Vpn", "vpnType": "RouteBased",
			"sku": map[string]any{"name": "VpnGw1", "tier": "VpnGw1"},
			"ipConfigurations": []any{map[string]any{
				"name": "default", "subnetId": testGatewaySubnetID,
				"publicIpAddressId": testVnetGatewayPipID,
			}},
			"activeActive": true,
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "activeActive requires two ipConfigurations entries")
	})

	t.Run("Create_active_active_accepts_two_front_ends", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "vngw1", "resourceGroupName": "rg-1", "location": "eastus",
			"gatewayType": "Vpn", "vpnType": "RouteBased",
			"sku": map[string]any{"name": "VpnGw1", "tier": "VpnGw1"},
			"ipConfigurations": []any{
				map[string]any{"name": "default", "subnetId": testGatewaySubnetID, "publicIpAddressId": testVnetGatewayPipID},
				map[string]any{"name": "activeActive", "subnetId": testGatewaySubnetID, "publicIpAddressId": testVnetGatewayPipID2},
			},
			"activeActive": true,
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.Len(t, sent.Properties.IPConfigurations, 2)
		require.True(t, *sent.Properties.Active)
	})

	// The native ID reported while the LRO is still running must match the path ARM
	// actually assigns: a create here takes 30-45 minutes, and a mismatch orphans a
	// billed gateway for that entire window.
	t.Run("PendingCreateReportsRealNativeID", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, _ armnetwork.VirtualNetworkGateway, _ *armnetwork.VirtualNetworkGatewaysClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.VirtualNetworkGatewaysClientCreateOrUpdateResponse], error) {
			return newPendingPoller[armnetwork.VirtualNetworkGatewaysClientCreateOrUpdateResponse](), nil
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "vngw1", Properties: vnetGatewayDesired("VpnGw1", 0),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusInProgress, got.ProgressResult.OperationStatus)
		require.Equal(t, testVnetGatewayNativeID, got.ProgressResult.NativeID)
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testVnetGatewayNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "vngw1", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "eastus", props["location"])
		// Every enum comes back from ARM lower-cased and must be canonicalised.
		require.Equal(t, "Vpn", props["gatewayType"])
		require.Equal(t, "RouteBased", props["vpnType"])
		require.Equal(t, "VpnGw1", props["sku"].(map[string]any)["name"])
		require.Equal(t, "VpnGw1", props["sku"].(map[string]any)["tier"])
		require.Equal(t, "Generation1", props["vpnGatewayGeneration"])
		require.Equal(t, false, props["activeActive"])
		require.Equal(t, true, props["enableBgp"])

		bgp := props["bgpSettings"].(map[string]any)
		require.EqualValues(t, 65515, bgp["asn"])
		require.EqualValues(t, 0, bgp["peerWeight"])
		require.NotContains(t, bgp, "bgpPeeringAddress")

		configs := props["ipConfigurations"].([]any)
		require.Len(t, configs, 1)
		cfg := configs[0].(map[string]any)
		require.Equal(t, "default", cfg["name"])
		require.Equal(t, testGatewaySubnetID, cfg["subnetId"])
		require.Equal(t, testVnetGatewayPipID, cfg["publicIpAddressId"])
		require.Equal(t, "Dynamic", cfg["privateIpAllocationMethod"])

		vpnClient := props["vpnClientConfiguration"].(map[string]any)
		require.Equal(t, []any{"172.16.201.0/24"}, vpnClient["vpnClientAddressPool"])
		require.Equal(t, []any{"OpenVPN"}, vpnClient["vpnClientProtocols"])
		require.Equal(t, []any{"Certificate"}, vpnClient["vpnAuthenticationTypes"])
		certs := vpnClient["vpnClientRootCertificates"].([]any)
		require.Equal(t, "root", certs[0].(map[string]any)["name"])
		require.Equal(t, "MIIBase64CertBody", certs[0].(map[string]any)["publicCertData"])
	})

	// Service state, the Azure-picked addresses and the SKU capacity would read as
	// drift forever.
	t.Run("Read_drops_service_state", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testVnetGatewayNativeID})
		require.NoError(t, err)
		for _, key := range []string{
			"provisioningState", "resourceGuid", "etag", "capacity",
			"bgpPeeringAddress", "bgpPeeringAddresses", "privateIPAddress",
			"inboundDnsForwardingEndpoint", "radiusServerSecret",
		} {
			require.NotContains(t, got.Properties, key)
		}
	})

	t.Run("Update_reissues_create_or_update", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, params armnetwork.VirtualNetworkGateway, _ *armnetwork.VirtualNetworkGatewaysClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.VirtualNetworkGatewaysClientCreateOrUpdateResponse], error) {
			sent = params
			createCalls++
			return newDonePoller(armnetwork.VirtualNetworkGatewaysClientCreateOrUpdateResponse{VirtualNetworkGateway: gatewayResult}), nil
		}
		before := createCalls
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testVnetGatewayNativeID,
			DesiredProperties: vnetGatewayDesired("VpnGw2", 10),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, createCalls)
		require.Equal(t, armnetwork.VirtualNetworkGatewaySKUNameVPNGw2, *sent.Properties.SKU.Name)
		require.Equal(t, int32(10), *sent.Properties.BgpSettings.PeerWeight)
		// Location, gateway type and the front end must ride along: a PUT without
		// them is rejected.
		require.Equal(t, "eastus", *sent.Location)
		require.Equal(t, armnetwork.VirtualNetworkGatewayTypeVPN, *sent.Properties.GatewayType)
		require.Len(t, sent.Properties.IPConfigurations, 1)
	})

	t.Run("Delete", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testVnetGatewayNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _ string, _ *armnetwork.VirtualNetworkGatewaysClientBeginDeleteOptions) (*runtime.Poller[armnetwork.VirtualNetworkGatewaysClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testVnetGatewayNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_resource_group", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testVnetGatewayNativeID}, got.NativeIDs)
	})

	// ARM offers no subscription-wide listing for this type.
	t.Run("List_without_group_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})

	t.Run("Read_NotFound", func(t *testing.T) {
		fake.getFn = func(_ context.Context, _, _ string, _ *armnetwork.VirtualNetworkGatewaysClientGetOptions) (armnetwork.VirtualNetworkGatewaysClientGetResponse, error) {
			return armnetwork.VirtualNetworkGatewaysClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testVnetGatewayNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
	})
}
