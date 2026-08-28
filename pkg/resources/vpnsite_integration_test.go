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
	testVpnSiteNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/vpnSites/site1"
	testVpnSiteWanID    = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/virtualWans/vwan1"
)

type fakeVpnSitesAPI struct {
	beginCreateOrUpdateFn         func(ctx context.Context, rgName, name string, params armnetwork.VPNSite, options *armnetwork.VPNSitesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.VPNSitesClientCreateOrUpdateResponse], error)
	getFn                         func(ctx context.Context, rgName, name string, options *armnetwork.VPNSitesClientGetOptions) (armnetwork.VPNSitesClientGetResponse, error)
	beginDeleteFn                 func(ctx context.Context, rgName, name string, options *armnetwork.VPNSitesClientBeginDeleteOptions) (*runtime.Poller[armnetwork.VPNSitesClientDeleteResponse], error)
	newListByResourceGroupPagerFn func(rgName string, options *armnetwork.VPNSitesClientListByResourceGroupOptions) *runtime.Pager[armnetwork.VPNSitesClientListByResourceGroupResponse]
	newListPagerFn                func(options *armnetwork.VPNSitesClientListOptions) *runtime.Pager[armnetwork.VPNSitesClientListResponse]
}

func (f *fakeVpnSitesAPI) BeginCreateOrUpdate(ctx context.Context, rgName, name string, params armnetwork.VPNSite, options *armnetwork.VPNSitesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.VPNSitesClientCreateOrUpdateResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, rgName, name, params, options)
}

func (f *fakeVpnSitesAPI) Get(ctx context.Context, rgName, name string, options *armnetwork.VPNSitesClientGetOptions) (armnetwork.VPNSitesClientGetResponse, error) {
	return f.getFn(ctx, rgName, name, options)
}

func (f *fakeVpnSitesAPI) BeginDelete(ctx context.Context, rgName, name string, options *armnetwork.VPNSitesClientBeginDeleteOptions) (*runtime.Poller[armnetwork.VPNSitesClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, name, options)
}

func (f *fakeVpnSitesAPI) NewListByResourceGroupPager(rgName string, options *armnetwork.VPNSitesClientListByResourceGroupOptions) *runtime.Pager[armnetwork.VPNSitesClientListByResourceGroupResponse] {
	return f.newListByResourceGroupPagerFn(rgName, options)
}

func (f *fakeVpnSitesAPI) NewListPager(options *armnetwork.VPNSitesClientListOptions) *runtime.Pager[armnetwork.VPNSitesClientListResponse] {
	return f.newListPagerFn(options)
}

func newTestVpnSite(api vpnSitesAPI) *VpnSite {
	return &VpnSite{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func vpnSiteDesired(prefixes []any, linkSpeed int) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":              "site1",
		"resourceGroupName": "rg-1",
		"location":          "eastus",
		"virtualWanId":      testVpnSiteWanID,
		"addressSpace":      prefixes,
		"deviceProperties": map[string]any{
			"deviceVendor":    "Contoso",
			"deviceModel":     "CX-100",
			"linkSpeedInMbps": linkSpeed,
		},
		"vpnSiteLinks": []any{map[string]any{
			"name":      "link0",
			"ipAddress": "203.0.113.30",
			"linkProperties": map[string]any{
				"linkProviderName": "Contoso Telecom",
				"linkSpeedInMbps":  linkSpeed,
			},
			"bgpProperties": map[string]any{
				"asn":               65020,
				"bgpPeeringAddress": "192.168.10.1",
			},
		}},
		"Tags": []any{map[string]any{"Key": "env", "Value": "test"}},
	})
	return out
}

func TestVpnSite_CRUD(t *testing.T) {
	siteResult := armnetwork.VPNSite{
		ID:       to.Ptr(testVpnSiteNativeID),
		Name:     to.Ptr("site1"),
		Location: to.Ptr("East US"),
		Properties: &armnetwork.VPNSiteProperties{
			VirtualWan: &armnetwork.SubResource{ID: to.Ptr(testVpnSiteWanID)},
			AddressSpace: &armnetwork.AddressSpace{
				AddressPrefixes: []*string{to.Ptr("192.168.10.0/24")},
			},
			DeviceProperties: &armnetwork.DeviceProperties{
				DeviceVendor:    to.Ptr("Contoso"),
				DeviceModel:     to.Ptr("CX-100"),
				LinkSpeedInMbps: to.Ptr(int32(100)),
			},
			VPNSiteLinks: []*armnetwork.VPNSiteLink{{
				// ARM assigns the child ID, etag and type; none may reach state.
				ID:   to.Ptr(testVpnSiteNativeID + "/vpnSiteLinks/link0"),
				Name: to.Ptr("link0"),
				Etag: to.Ptr("W/\"link-etag\""),
				Type: to.Ptr("Microsoft.Network/vpnSites/vpnSiteLinks"),
				Properties: &armnetwork.VPNSiteLinkProperties{
					IPAddress: to.Ptr("203.0.113.30"),
					LinkProperties: &armnetwork.VPNLinkProviderProperties{
						LinkProviderName: to.Ptr("Contoso Telecom"),
						LinkSpeedInMbps:  to.Ptr(int32(100)),
					},
					BgpProperties: &armnetwork.VPNLinkBgpSettings{
						Asn:               to.Ptr(int64(65020)),
						BgpPeeringAddress: to.Ptr("192.168.10.1"),
					},
					ProvisioningState: to.Ptr(armnetwork.ProvisioningStateSucceeded),
				},
			}},
			ProvisioningState: to.Ptr(armnetwork.ProvisioningStateSucceeded),
			SiteKey:           to.Ptr("service-generated-site-key"),
		},
		Tags: map[string]*string{"env": to.Ptr("test")},
		Etag: to.Ptr("W/\"etag\""),
	}

	var sent armnetwork.VPNSite
	createCalls := 0
	deleteCalls := 0
	fake := &fakeVpnSitesAPI{
		beginCreateOrUpdateFn: func(_ context.Context, rgName, name string, params armnetwork.VPNSite, _ *armnetwork.VPNSitesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.VPNSitesClientCreateOrUpdateResponse], error) {
			require.Equal(t, "rg-1", rgName)
			require.Equal(t, "site1", name)
			sent = params
			createCalls++
			return newDonePoller(armnetwork.VPNSitesClientCreateOrUpdateResponse{VPNSite: siteResult}), nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armnetwork.VPNSitesClientGetOptions) (armnetwork.VPNSitesClientGetResponse, error) {
			return armnetwork.VPNSitesClientGetResponse{VPNSite: siteResult}, nil
		},
		beginDeleteFn: func(_ context.Context, _, _ string, _ *armnetwork.VPNSitesClientBeginDeleteOptions) (*runtime.Poller[armnetwork.VPNSitesClientDeleteResponse], error) {
			deleteCalls++
			return newDonePoller(armnetwork.VPNSitesClientDeleteResponse{}), nil
		},
		newListByResourceGroupPagerFn: func(_ string, _ *armnetwork.VPNSitesClientListByResourceGroupOptions) *runtime.Pager[armnetwork.VPNSitesClientListByResourceGroupResponse] {
			return runtime.NewPager(runtime.PagingHandler[armnetwork.VPNSitesClientListByResourceGroupResponse]{
				More: func(_ armnetwork.VPNSitesClientListByResourceGroupResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armnetwork.VPNSitesClientListByResourceGroupResponse) (armnetwork.VPNSitesClientListByResourceGroupResponse, error) {
					return armnetwork.VPNSitesClientListByResourceGroupResponse{
						ListVPNSitesResult: armnetwork.ListVPNSitesResult{
							Value: []*armnetwork.VPNSite{{ID: to.Ptr(testVpnSiteNativeID)}},
						},
					}, nil
				},
			})
		},
		newListPagerFn: func(_ *armnetwork.VPNSitesClientListOptions) *runtime.Pager[armnetwork.VPNSitesClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armnetwork.VPNSitesClientListResponse]{
				More: func(_ armnetwork.VPNSitesClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armnetwork.VPNSitesClientListResponse) (armnetwork.VPNSitesClientListResponse, error) {
					return armnetwork.VPNSitesClientListResponse{
						ListVPNSitesResult: armnetwork.ListVPNSitesResult{
							Value: []*armnetwork.VPNSite{{ID: to.Ptr(testVpnSiteNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestVpnSite(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "site1", Properties: vpnSiteDesired([]any{"192.168.10.0/24"}, 100),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testVpnSiteNativeID, got.ProgressResult.NativeID)

		require.Equal(t, "eastus", *sent.Location)
		require.Equal(t, testVpnSiteWanID, *sent.Properties.VirtualWan.ID)
		require.Equal(t, "192.168.10.0/24", *sent.Properties.AddressSpace.AddressPrefixes[0])
		require.Equal(t, "Contoso", *sent.Properties.DeviceProperties.DeviceVendor)
		require.Equal(t, int32(100), *sent.Properties.DeviceProperties.LinkSpeedInMbps)
		require.Len(t, sent.Properties.VPNSiteLinks, 1)
		link := sent.Properties.VPNSiteLinks[0]
		require.Equal(t, "link0", *link.Name)
		require.Equal(t, "203.0.113.30", *link.Properties.IPAddress)
		require.Nil(t, link.Properties.Fqdn)
		require.Equal(t, "Contoso Telecom", *link.Properties.LinkProperties.LinkProviderName)
		require.Equal(t, int64(65020), *link.Properties.BgpProperties.Asn)
		require.Equal(t, "192.168.10.1", *link.Properties.BgpProperties.BgpPeeringAddress)
		require.Equal(t, "test", *sent.Tags["env"])
	})

	t.Run("Create_requires_virtual_wan", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "site1", "resourceGroupName": "rg-1", "location": "eastus",
			"ipAddress": "203.0.113.30",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "virtualWanId is required")
	})

	// A site with no endpoint at all can never be the target of a connection.
	t.Run("Create_requires_an_endpoint", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "site1", "resourceGroupName": "rg-1", "location": "eastus",
			"virtualWanId": testVpnSiteWanID,
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "one of ipAddress or vpnSiteLinks is required")
	})

	t.Run("Create_rejects_link_with_both_addresses", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "site1", "resourceGroupName": "rg-1", "location": "eastus",
			"virtualWanId": testVpnSiteWanID,
			"vpnSiteLinks": []any{map[string]any{
				"name": "link0", "ipAddress": "203.0.113.30", "fqdn": "branch.example.com",
			}},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "mutually exclusive")
	})

	t.Run("Create_rejects_link_without_an_address", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "site1", "resourceGroupName": "rg-1", "location": "eastus",
			"virtualWanId": testVpnSiteWanID,
			"vpnSiteLinks": []any{map[string]any{"name": "link0"}},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "needs one of ipAddress or fqdn")
	})

	// The native ID reported while the LRO is still running must match the path ARM
	// actually assigns, or the resource is orphaned once it completes.
	t.Run("PendingCreateReportsRealNativeID", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, _ armnetwork.VPNSite, _ *armnetwork.VPNSitesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.VPNSitesClientCreateOrUpdateResponse], error) {
			return newPendingPoller[armnetwork.VPNSitesClientCreateOrUpdateResponse](), nil
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "site1", Properties: vpnSiteDesired([]any{"192.168.10.0/24"}, 100),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusInProgress, got.ProgressResult.OperationStatus)
		require.Equal(t, testVpnSiteNativeID, got.ProgressResult.NativeID)
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testVpnSiteNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "site1", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "eastus", props["location"])
		require.Equal(t, testVpnSiteWanID, props["virtualWanId"])
		require.Equal(t, []any{"192.168.10.0/24"}, props["addressSpace"])

		device := props["deviceProperties"].(map[string]any)
		require.Equal(t, "Contoso", device["deviceVendor"])
		require.Equal(t, "CX-100", device["deviceModel"])
		require.EqualValues(t, 100, device["linkSpeedInMbps"])

		links := props["vpnSiteLinks"].([]any)
		require.Len(t, links, 1)
		link := links[0].(map[string]any)
		require.Equal(t, "link0", link["name"])
		require.Equal(t, "203.0.113.30", link["ipAddress"])
		require.Equal(t, "Contoso Telecom", link["linkProperties"].(map[string]any)["linkProviderName"])
		require.EqualValues(t, 65020, link["bgpProperties"].(map[string]any)["asn"])
	})

	// Service state and the ARM-assigned per-link identity would read as drift forever.
	t.Run("Read_drops_service_state", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testVpnSiteNativeID})
		require.NoError(t, err)
		for _, key := range []string{"provisioningState", "siteKey", "etag", "vpnSiteLinks/link0", "isSecuritySite"} {
			require.NotContains(t, got.Properties, key)
		}
		// An absent fqdn must stay absent rather than appearing as "".
		require.NotContains(t, got.Properties, "fqdn")
	})

	t.Run("Update_reissues_create_or_update", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, params armnetwork.VPNSite, _ *armnetwork.VPNSitesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.VPNSitesClientCreateOrUpdateResponse], error) {
			sent = params
			createCalls++
			return newDonePoller(armnetwork.VPNSitesClientCreateOrUpdateResponse{VPNSite: siteResult}), nil
		}
		before := createCalls
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testVpnSiteNativeID,
			DesiredProperties: vpnSiteDesired([]any{"192.168.10.0/24", "192.168.11.0/24"}, 200),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, createCalls)
		require.Len(t, sent.Properties.AddressSpace.AddressPrefixes, 2)
		require.Equal(t, int32(200), *sent.Properties.DeviceProperties.LinkSpeedInMbps)
		// Location and the WAN reference must ride along: a PUT without them is rejected.
		require.Equal(t, "eastus", *sent.Location)
		require.Equal(t, testVpnSiteWanID, *sent.Properties.VirtualWan.ID)
	})

	t.Run("Delete", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testVpnSiteNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _ string, _ *armnetwork.VPNSitesClientBeginDeleteOptions) (*runtime.Poller[armnetwork.VPNSitesClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testVpnSiteNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_resource_group", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testVpnSiteNativeID}, got.NativeIDs)
	})

	t.Run("List_by_subscription", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Equal(t, []string{testVpnSiteNativeID}, got.NativeIDs)
	})

	t.Run("Read_NotFound", func(t *testing.T) {
		fake.getFn = func(_ context.Context, _, _ string, _ *armnetwork.VPNSitesClientGetOptions) (armnetwork.VPNSitesClientGetResponse, error) {
			return armnetwork.VPNSitesClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testVpnSiteNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
	})
}
