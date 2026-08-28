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
	testVirtualHubNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/virtualHubs/hub1"
	testVirtualHubWanID    = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/virtualWans/vwan1"
)

type fakeVirtualHubsAPI struct {
	beginCreateOrUpdateFn         func(ctx context.Context, rgName, name string, params armnetwork.VirtualHub, options *armnetwork.VirtualHubsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.VirtualHubsClientCreateOrUpdateResponse], error)
	getFn                         func(ctx context.Context, rgName, name string, options *armnetwork.VirtualHubsClientGetOptions) (armnetwork.VirtualHubsClientGetResponse, error)
	beginDeleteFn                 func(ctx context.Context, rgName, name string, options *armnetwork.VirtualHubsClientBeginDeleteOptions) (*runtime.Poller[armnetwork.VirtualHubsClientDeleteResponse], error)
	newListByResourceGroupPagerFn func(rgName string, options *armnetwork.VirtualHubsClientListByResourceGroupOptions) *runtime.Pager[armnetwork.VirtualHubsClientListByResourceGroupResponse]
	newListPagerFn                func(options *armnetwork.VirtualHubsClientListOptions) *runtime.Pager[armnetwork.VirtualHubsClientListResponse]
}

func (f *fakeVirtualHubsAPI) BeginCreateOrUpdate(ctx context.Context, rgName, name string, params armnetwork.VirtualHub, options *armnetwork.VirtualHubsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.VirtualHubsClientCreateOrUpdateResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, rgName, name, params, options)
}

func (f *fakeVirtualHubsAPI) Get(ctx context.Context, rgName, name string, options *armnetwork.VirtualHubsClientGetOptions) (armnetwork.VirtualHubsClientGetResponse, error) {
	return f.getFn(ctx, rgName, name, options)
}

func (f *fakeVirtualHubsAPI) BeginDelete(ctx context.Context, rgName, name string, options *armnetwork.VirtualHubsClientBeginDeleteOptions) (*runtime.Poller[armnetwork.VirtualHubsClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, name, options)
}

func (f *fakeVirtualHubsAPI) NewListByResourceGroupPager(rgName string, options *armnetwork.VirtualHubsClientListByResourceGroupOptions) *runtime.Pager[armnetwork.VirtualHubsClientListByResourceGroupResponse] {
	return f.newListByResourceGroupPagerFn(rgName, options)
}

func (f *fakeVirtualHubsAPI) NewListPager(options *armnetwork.VirtualHubsClientListOptions) *runtime.Pager[armnetwork.VirtualHubsClientListResponse] {
	return f.newListPagerFn(options)
}

func newTestVirtualHub(api virtualHubsAPI) *VirtualHub {
	return &VirtualHub{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func virtualHubDesired(routingPreference string) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":                       "hub1",
		"resourceGroupName":          "rg-1",
		"location":                   "eastus",
		"virtualWanId":               testVirtualHubWanID,
		"addressPrefix":              "10.100.0.0/23",
		"sku":                        "Standard",
		"hubRoutingPreference":       routingPreference,
		"allowBranchToBranchTraffic": true,
		"Tags":                       []any{map[string]any{"Key": "env", "Value": "test"}},
	})
	return out
}

func TestVirtualHub_CRUD(t *testing.T) {
	hubResult := armnetwork.VirtualHub{
		ID:       to.Ptr(testVirtualHubNativeID),
		Name:     to.Ptr("hub1"),
		Location: to.Ptr("East US"),
		Properties: &armnetwork.VirtualHubProperties{
			VirtualWan:    &armnetwork.SubResource{ID: to.Ptr(testVirtualHubWanID)},
			AddressPrefix: to.Ptr("10.100.0.0/23"),
			// ARM echoes the sku and routing preference back with its own casing.
			SKU:                        to.Ptr("standard"),
			HubRoutingPreference:       to.Ptr(armnetwork.HubRoutingPreference("aspath")),
			AllowBranchToBranchTraffic: to.Ptr(true),
			// Service state and gateway back-references: the hub never owns these.
			ProvisioningState: to.Ptr(armnetwork.ProvisioningStateSucceeded),
			RoutingState:      to.Ptr(armnetwork.RoutingStateProvisioned),
			VirtualRouterAsn:  to.Ptr(int64(65515)),
			VirtualRouterIPs:  []*string{to.Ptr("10.100.0.68")},
			VPNGateway:        &armnetwork.SubResource{ID: to.Ptr("/subscriptions/sub-1/vpngw")},
			RouteTable:        &armnetwork.VirtualHubRouteTable{},
		},
		Tags: map[string]*string{"env": to.Ptr("test")},
		Etag: to.Ptr("W/\"etag\""),
		Kind: to.Ptr("VirtualHub"),
	}

	var sent armnetwork.VirtualHub
	createCalls := 0
	deleteCalls := 0
	fake := &fakeVirtualHubsAPI{
		beginCreateOrUpdateFn: func(_ context.Context, rgName, name string, params armnetwork.VirtualHub, _ *armnetwork.VirtualHubsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.VirtualHubsClientCreateOrUpdateResponse], error) {
			require.Equal(t, "rg-1", rgName)
			require.Equal(t, "hub1", name)
			sent = params
			createCalls++
			return newDonePoller(armnetwork.VirtualHubsClientCreateOrUpdateResponse{VirtualHub: hubResult}), nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armnetwork.VirtualHubsClientGetOptions) (armnetwork.VirtualHubsClientGetResponse, error) {
			return armnetwork.VirtualHubsClientGetResponse{VirtualHub: hubResult}, nil
		},
		beginDeleteFn: func(_ context.Context, _, _ string, _ *armnetwork.VirtualHubsClientBeginDeleteOptions) (*runtime.Poller[armnetwork.VirtualHubsClientDeleteResponse], error) {
			deleteCalls++
			return newDonePoller(armnetwork.VirtualHubsClientDeleteResponse{}), nil
		},
		newListByResourceGroupPagerFn: func(_ string, _ *armnetwork.VirtualHubsClientListByResourceGroupOptions) *runtime.Pager[armnetwork.VirtualHubsClientListByResourceGroupResponse] {
			return runtime.NewPager(runtime.PagingHandler[armnetwork.VirtualHubsClientListByResourceGroupResponse]{
				More: func(_ armnetwork.VirtualHubsClientListByResourceGroupResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armnetwork.VirtualHubsClientListByResourceGroupResponse) (armnetwork.VirtualHubsClientListByResourceGroupResponse, error) {
					return armnetwork.VirtualHubsClientListByResourceGroupResponse{
						ListVirtualHubsResult: armnetwork.ListVirtualHubsResult{
							Value: []*armnetwork.VirtualHub{{ID: to.Ptr(testVirtualHubNativeID)}},
						},
					}, nil
				},
			})
		},
		newListPagerFn: func(_ *armnetwork.VirtualHubsClientListOptions) *runtime.Pager[armnetwork.VirtualHubsClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armnetwork.VirtualHubsClientListResponse]{
				More: func(_ armnetwork.VirtualHubsClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armnetwork.VirtualHubsClientListResponse) (armnetwork.VirtualHubsClientListResponse, error) {
					return armnetwork.VirtualHubsClientListResponse{
						ListVirtualHubsResult: armnetwork.ListVirtualHubsResult{
							Value: []*armnetwork.VirtualHub{{ID: to.Ptr(testVirtualHubNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestVirtualHub(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "hub1", Properties: virtualHubDesired("ASPath"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testVirtualHubNativeID, got.ProgressResult.NativeID)

		require.Equal(t, "eastus", *sent.Location)
		require.Equal(t, testVirtualHubWanID, *sent.Properties.VirtualWan.ID)
		require.Equal(t, "10.100.0.0/23", *sent.Properties.AddressPrefix)
		require.Equal(t, "Standard", *sent.Properties.SKU)
		require.Equal(t, armnetwork.HubRoutingPreferenceASPath, *sent.Properties.HubRoutingPreference)
		require.True(t, *sent.Properties.AllowBranchToBranchTraffic)
		require.Equal(t, "test", *sent.Tags["env"])
	})

	t.Run("Create_requires_virtual_wan", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "hub1", "resourceGroupName": "rg-1", "location": "eastus",
			"addressPrefix": "10.100.0.0/23",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "virtualWanId is required")
	})

	t.Run("Create_requires_address_prefix", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "hub1", "resourceGroupName": "rg-1", "location": "eastus",
			"virtualWanId": testVirtualHubWanID,
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "addressPrefix is required")
	})

	// The native ID reported while the LRO is still running must match the path ARM
	// actually assigns, or the resource is orphaned once it completes.
	t.Run("PendingCreateReportsRealNativeID", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, _ armnetwork.VirtualHub, _ *armnetwork.VirtualHubsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.VirtualHubsClientCreateOrUpdateResponse], error) {
			return newPendingPoller[armnetwork.VirtualHubsClientCreateOrUpdateResponse](), nil
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "hub1", Properties: virtualHubDesired("ASPath"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusInProgress, got.ProgressResult.OperationStatus)
		require.Equal(t, testVirtualHubNativeID, got.ProgressResult.NativeID)
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testVirtualHubNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "hub1", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "eastus", props["location"])
		require.Equal(t, testVirtualHubWanID, props["virtualWanId"])
		require.Equal(t, "10.100.0.0/23", props["addressPrefix"])
		// ARM returns "standard" / "aspath"; the schema unions are "Standard" / "ASPath".
		require.Equal(t, "Standard", props["sku"])
		require.Equal(t, "ASPath", props["hubRoutingPreference"])
		require.Equal(t, true, props["allowBranchToBranchTraffic"])
	})

	// Service state and the gateway back-references would read as drift forever.
	t.Run("Read_drops_service_state", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testVirtualHubNativeID})
		require.NoError(t, err)
		for _, key := range []string{
			"provisioningState", "routingState", "virtualRouterAsn", "virtualRouterIps",
			"vpnGateway", "routeTable", "etag", "kind",
		} {
			require.NotContains(t, got.Properties, key)
		}
	})

	t.Run("Update_reissues_create_or_update", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, params armnetwork.VirtualHub, _ *armnetwork.VirtualHubsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.VirtualHubsClientCreateOrUpdateResponse], error) {
			sent = params
			createCalls++
			return newDonePoller(armnetwork.VirtualHubsClientCreateOrUpdateResponse{VirtualHub: hubResult}), nil
		}
		before := createCalls
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testVirtualHubNativeID,
			DesiredProperties: virtualHubDesired("VpnGateway"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, createCalls)
		require.Equal(t, armnetwork.HubRoutingPreferenceVPNGateway, *sent.Properties.HubRoutingPreference)
		// Location and the WAN reference must ride along: a PUT without them is rejected.
		require.Equal(t, "eastus", *sent.Location)
		require.Equal(t, testVirtualHubWanID, *sent.Properties.VirtualWan.ID)
	})

	t.Run("Delete", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testVirtualHubNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _ string, _ *armnetwork.VirtualHubsClientBeginDeleteOptions) (*runtime.Poller[armnetwork.VirtualHubsClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testVirtualHubNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_resource_group", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testVirtualHubNativeID}, got.NativeIDs)
	})

	t.Run("List_by_subscription", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Equal(t, []string{testVirtualHubNativeID}, got.NativeIDs)
	})

	t.Run("Read_NotFound", func(t *testing.T) {
		fake.getFn = func(_ context.Context, _, _ string, _ *armnetwork.VirtualHubsClientGetOptions) (armnetwork.VirtualHubsClientGetResponse, error) {
			return armnetwork.VirtualHubsClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testVirtualHubNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
	})
}
