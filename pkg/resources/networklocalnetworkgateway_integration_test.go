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

const testLocalNetworkGatewayNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/localNetworkGateways/lng1"

type fakeLocalNetworkGatewaysAPI struct {
	beginCreateOrUpdateFn func(ctx context.Context, rgName, name string, params armnetwork.LocalNetworkGateway, options *armnetwork.LocalNetworkGatewaysClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.LocalNetworkGatewaysClientCreateOrUpdateResponse], error)
	getFn                 func(ctx context.Context, rgName, name string, options *armnetwork.LocalNetworkGatewaysClientGetOptions) (armnetwork.LocalNetworkGatewaysClientGetResponse, error)
	beginDeleteFn         func(ctx context.Context, rgName, name string, options *armnetwork.LocalNetworkGatewaysClientBeginDeleteOptions) (*runtime.Poller[armnetwork.LocalNetworkGatewaysClientDeleteResponse], error)
	newListPagerFn        func(rgName string, options *armnetwork.LocalNetworkGatewaysClientListOptions) *runtime.Pager[armnetwork.LocalNetworkGatewaysClientListResponse]
}

func (f *fakeLocalNetworkGatewaysAPI) BeginCreateOrUpdate(ctx context.Context, rgName, name string, params armnetwork.LocalNetworkGateway, options *armnetwork.LocalNetworkGatewaysClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.LocalNetworkGatewaysClientCreateOrUpdateResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, rgName, name, params, options)
}

func (f *fakeLocalNetworkGatewaysAPI) Get(ctx context.Context, rgName, name string, options *armnetwork.LocalNetworkGatewaysClientGetOptions) (armnetwork.LocalNetworkGatewaysClientGetResponse, error) {
	return f.getFn(ctx, rgName, name, options)
}

func (f *fakeLocalNetworkGatewaysAPI) BeginDelete(ctx context.Context, rgName, name string, options *armnetwork.LocalNetworkGatewaysClientBeginDeleteOptions) (*runtime.Poller[armnetwork.LocalNetworkGatewaysClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, name, options)
}

func (f *fakeLocalNetworkGatewaysAPI) NewListPager(rgName string, options *armnetwork.LocalNetworkGatewaysClientListOptions) *runtime.Pager[armnetwork.LocalNetworkGatewaysClientListResponse] {
	return f.newListPagerFn(rgName, options)
}

func newTestLocalNetworkGateway(api networkLocalNetworkGatewaysAPI) *NetworkLocalNetworkGateway {
	return &NetworkLocalNetworkGateway{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func localNetworkGatewayDesired(prefixes []any, peerWeight int) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":                     "lng1",
		"resourceGroupName":        "rg-1",
		"location":                 "eastus",
		"gatewayIpAddress":         "203.0.113.10",
		"localNetworkAddressSpace": prefixes,
		"bgpSettings": map[string]any{
			"asn":               65010,
			"bgpPeeringAddress": "192.168.1.1",
			"peerWeight":        peerWeight,
		},
		"Tags": []any{map[string]any{"Key": "env", "Value": "test"}},
	})
	return out
}

func TestNetworkLocalNetworkGateway_CRUD(t *testing.T) {
	gatewayResult := armnetwork.LocalNetworkGateway{
		ID:       to.Ptr(testLocalNetworkGatewayNativeID),
		Name:     to.Ptr("lng1"),
		Location: to.Ptr("East US"),
		Properties: &armnetwork.LocalNetworkGatewayPropertiesFormat{
			GatewayIPAddress: to.Ptr("203.0.113.10"),
			LocalNetworkAddressSpace: &armnetwork.AddressSpace{
				AddressPrefixes: []*string{to.Ptr("192.168.1.0/24")},
			},
			BgpSettings: &armnetwork.BgpSettings{
				Asn:               to.Ptr(int64(65010)),
				BgpPeeringAddress: to.Ptr("192.168.1.1"),
				PeerWeight:        to.Ptr(int32(10)),
				// Gateway-side view of the peering, populated once a connection
				// exists. Not modelled, so it must not reach state.
				BgpPeeringAddresses: []*armnetwork.IPConfigurationBgpPeeringAddress{{
					IPConfigurationID: to.Ptr("/subscriptions/sub-1/ipConfigurations/default"),
				}},
			},
			ProvisioningState: to.Ptr(armnetwork.ProvisioningStateSucceeded),
			ResourceGUID:      to.Ptr("2b1f5cbb-1111-2222-3333-444455556666"),
		},
		Tags: map[string]*string{"env": to.Ptr("test")},
		Etag: to.Ptr("W/\"etag\""),
	}

	var sent armnetwork.LocalNetworkGateway
	createCalls := 0
	deleteCalls := 0
	fake := &fakeLocalNetworkGatewaysAPI{
		beginCreateOrUpdateFn: func(_ context.Context, rgName, name string, params armnetwork.LocalNetworkGateway, _ *armnetwork.LocalNetworkGatewaysClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.LocalNetworkGatewaysClientCreateOrUpdateResponse], error) {
			require.Equal(t, "rg-1", rgName)
			require.Equal(t, "lng1", name)
			sent = params
			createCalls++
			return newDonePoller(armnetwork.LocalNetworkGatewaysClientCreateOrUpdateResponse{LocalNetworkGateway: gatewayResult}), nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armnetwork.LocalNetworkGatewaysClientGetOptions) (armnetwork.LocalNetworkGatewaysClientGetResponse, error) {
			return armnetwork.LocalNetworkGatewaysClientGetResponse{LocalNetworkGateway: gatewayResult}, nil
		},
		beginDeleteFn: func(_ context.Context, _, _ string, _ *armnetwork.LocalNetworkGatewaysClientBeginDeleteOptions) (*runtime.Poller[armnetwork.LocalNetworkGatewaysClientDeleteResponse], error) {
			deleteCalls++
			return newDonePoller(armnetwork.LocalNetworkGatewaysClientDeleteResponse{}), nil
		},
		newListPagerFn: func(_ string, _ *armnetwork.LocalNetworkGatewaysClientListOptions) *runtime.Pager[armnetwork.LocalNetworkGatewaysClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armnetwork.LocalNetworkGatewaysClientListResponse]{
				More: func(_ armnetwork.LocalNetworkGatewaysClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armnetwork.LocalNetworkGatewaysClientListResponse) (armnetwork.LocalNetworkGatewaysClientListResponse, error) {
					return armnetwork.LocalNetworkGatewaysClientListResponse{
						LocalNetworkGatewayListResult: armnetwork.LocalNetworkGatewayListResult{
							Value: []*armnetwork.LocalNetworkGateway{{ID: to.Ptr(testLocalNetworkGatewayNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestLocalNetworkGateway(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "lng1", Properties: localNetworkGatewayDesired([]any{"192.168.1.0/24"}, 10),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testLocalNetworkGatewayNativeID, got.ProgressResult.NativeID)

		require.Equal(t, "eastus", *sent.Location)
		require.Equal(t, "203.0.113.10", *sent.Properties.GatewayIPAddress)
		require.Nil(t, sent.Properties.Fqdn)
		require.Equal(t, "192.168.1.0/24", *sent.Properties.LocalNetworkAddressSpace.AddressPrefixes[0])
		require.Equal(t, int64(65010), *sent.Properties.BgpSettings.Asn)
		require.Equal(t, "192.168.1.1", *sent.Properties.BgpSettings.BgpPeeringAddress)
		require.Equal(t, int32(10), *sent.Properties.BgpSettings.PeerWeight)
		require.Equal(t, "test", *sent.Tags["env"])
	})

	// ARM rejects a gateway addressed by neither, and silently ignores fqdn when both
	// are set, so both cases are refused before the request goes out.
	t.Run("Create_requires_an_address", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "lng1", "resourceGroupName": "rg-1", "location": "eastus",
			"localNetworkAddressSpace": []any{"192.168.1.0/24"},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "one of gatewayIpAddress or fqdn is required")
	})

	t.Run("Create_rejects_both_addresses", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "lng1", "resourceGroupName": "rg-1", "location": "eastus",
			"gatewayIpAddress": "203.0.113.10", "fqdn": "vpn.example.com",
			"localNetworkAddressSpace": []any{"192.168.1.0/24"},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "mutually exclusive")
	})

	t.Run("Create_requires_address_space", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "lng1", "resourceGroupName": "rg-1", "location": "eastus",
			"gatewayIpAddress": "203.0.113.10",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "localNetworkAddressSpace is required")
	})

	t.Run("Create_accepts_fqdn_only", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "lng1", "resourceGroupName": "rg-1", "location": "eastus",
			"fqdn": "vpn.example.com", "localNetworkAddressSpace": []any{"192.168.1.0/24"},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.Equal(t, "vpn.example.com", *sent.Properties.Fqdn)
		require.Nil(t, sent.Properties.GatewayIPAddress)
	})

	// The native ID reported while the LRO is still running must match the path ARM
	// actually assigns, or the resource is orphaned once it completes.
	t.Run("PendingCreateReportsRealNativeID", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, _ armnetwork.LocalNetworkGateway, _ *armnetwork.LocalNetworkGatewaysClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.LocalNetworkGatewaysClientCreateOrUpdateResponse], error) {
			return newPendingPoller[armnetwork.LocalNetworkGatewaysClientCreateOrUpdateResponse](), nil
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "lng1", Properties: localNetworkGatewayDesired([]any{"192.168.1.0/24"}, 10),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusInProgress, got.ProgressResult.OperationStatus)
		require.Equal(t, testLocalNetworkGatewayNativeID, got.ProgressResult.NativeID)
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testLocalNetworkGatewayNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "lng1", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		// ARM returns "East US"; read must normalise or desired state drifts.
		require.Equal(t, "eastus", props["location"])
		require.Equal(t, "203.0.113.10", props["gatewayIpAddress"])
		require.Equal(t, []any{"192.168.1.0/24"}, props["localNetworkAddressSpace"])

		bgp := props["bgpSettings"].(map[string]any)
		require.EqualValues(t, 65010, bgp["asn"])
		require.Equal(t, "192.168.1.1", bgp["bgpPeeringAddress"])
		require.EqualValues(t, 10, bgp["peerWeight"])
	})

	// Service state and the gateway-side peering view would read as drift forever.
	t.Run("Read_drops_service_state", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testLocalNetworkGatewayNativeID})
		require.NoError(t, err)
		for _, key := range []string{"provisioningState", "resourceGuid", "etag", "bgpPeeringAddresses", "ipConfigurationId"} {
			require.NotContains(t, got.Properties, key)
		}
		// An absent fqdn must stay absent rather than appearing as "".
		require.NotContains(t, got.Properties, "fqdn")
	})

	// UpdateTags cannot change the address space or the peer address, so an update is
	// another CreateOrUpdate.
	t.Run("Update_reissues_create_or_update", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, params armnetwork.LocalNetworkGateway, _ *armnetwork.LocalNetworkGatewaysClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.LocalNetworkGatewaysClientCreateOrUpdateResponse], error) {
			sent = params
			createCalls++
			return newDonePoller(armnetwork.LocalNetworkGatewaysClientCreateOrUpdateResponse{LocalNetworkGateway: gatewayResult}), nil
		}
		before := createCalls
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testLocalNetworkGatewayNativeID,
			DesiredProperties: localNetworkGatewayDesired([]any{"192.168.1.0/24", "192.168.2.0/24"}, 20),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, createCalls)
		require.Len(t, sent.Properties.LocalNetworkAddressSpace.AddressPrefixes, 2)
		require.Equal(t, int32(20), *sent.Properties.BgpSettings.PeerWeight)
		// Location must ride along: a PUT without it is rejected.
		require.Equal(t, "eastus", *sent.Location)
	})

	t.Run("Delete", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testLocalNetworkGatewayNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _ string, _ *armnetwork.LocalNetworkGatewaysClientBeginDeleteOptions) (*runtime.Poller[armnetwork.LocalNetworkGatewaysClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testLocalNetworkGatewayNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_resource_group", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testLocalNetworkGatewayNativeID}, got.NativeIDs)
	})

	// ARM offers no subscription-wide listing for this type.
	t.Run("List_without_group_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})

	t.Run("Read_NotFound", func(t *testing.T) {
		fake.getFn = func(_ context.Context, _, _ string, _ *armnetwork.LocalNetworkGatewaysClientGetOptions) (armnetwork.LocalNetworkGatewaysClientGetResponse, error) {
			return armnetwork.LocalNetworkGatewaysClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testLocalNetworkGatewayNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
	})
}
