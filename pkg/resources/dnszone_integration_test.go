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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/dns/armdns"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testDnsZoneNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/dnszones/example-1.com"

func testDnsZoneResult() armdns.Zone {
	return armdns.Zone{
		ID:       to.Ptr(testDnsZoneNativeID),
		Name:     to.Ptr("example-1.com"),
		Location: to.Ptr("global"),
		Properties: &armdns.ZoneProperties{
			ZoneType:    to.Ptr(armdns.ZoneTypePublic),
			NameServers: []*string{to.Ptr("ns1-01.azure-dns.com."), to.Ptr("ns2-01.azure-dns.net.")},
		},
	}
}

func TestDnsZone_CRUD(t *testing.T) {
	fake := &fakeDnsZonesAPI{
		createOrUpdateFn: func(_ context.Context, _, _ string, _ armdns.Zone, _ *armdns.ZonesClientCreateOrUpdateOptions) (armdns.ZonesClientCreateOrUpdateResponse, error) {
			return armdns.ZonesClientCreateOrUpdateResponse{Zone: testDnsZoneResult()}, nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armdns.ZonesClientGetOptions) (armdns.ZonesClientGetResponse, error) {
			return armdns.ZonesClientGetResponse{Zone: testDnsZoneResult()}, nil
		},
		beginDeleteFn: func(_ context.Context, _, _ string, _ *armdns.ZonesClientBeginDeleteOptions) (*runtime.Poller[armdns.ZonesClientDeleteResponse], error) {
			return newInProgressPoller[armdns.ZonesClientDeleteResponse](), nil
		},
		newListByResourceGroupPagerFn: func(_ string, _ *armdns.ZonesClientListByResourceGroupOptions) *runtime.Pager[armdns.ZonesClientListByResourceGroupResponse] {
			return runtime.NewPager(runtime.PagingHandler[armdns.ZonesClientListByResourceGroupResponse]{
				More: func(_ armdns.ZonesClientListByResourceGroupResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armdns.ZonesClientListByResourceGroupResponse) (armdns.ZonesClientListByResourceGroupResponse, error) {
					return armdns.ZonesClientListByResourceGroupResponse{
						ZoneListResult: armdns.ZoneListResult{Value: []*armdns.Zone{{ID: to.Ptr(testDnsZoneNativeID)}}},
					}, nil
				},
			})
		},
		newListPagerFn: func(_ *armdns.ZonesClientListOptions) *runtime.Pager[armdns.ZonesClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armdns.ZonesClientListResponse]{
				More: func(_ armdns.ZonesClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armdns.ZonesClientListResponse) (armdns.ZonesClientListResponse, error) {
					return armdns.ZonesClientListResponse{
						ZoneListResult: armdns.ZoneListResult{Value: []*armdns.Zone{{ID: to.Ptr(testDnsZoneNativeID)}}},
					}, nil
				},
			})
		},
	}
	prov := newTestDnsZone(fake)

	mkProps := func() json.RawMessage {
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName": "rg-1",
			"name":              "example-1.com",
			"location":          "global",
			"zoneType":          "Public",
		})
		return props
	}

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testDnsZoneNativeID, got.ProgressResult.NativeID)
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testDnsZoneNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
	})

	t.Run("Read_surfaces_nameServers", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testDnsZoneNativeID})
		require.NoError(t, err)
		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		ns, ok := props["nameServers"].([]any)
		require.True(t, ok, "nameServers must be present on read")
		require.Len(t, ns, 2)
		require.Equal(t, "ns1-01.azure-dns.com.", ns[0])
		require.Equal(t, "Public", props["zoneType"])
	})

	t.Run("Update", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName": "rg-1",
			"name":              "example-1.com",
			"location":          "global",
			"zoneType":          "Public",
			"Tags":              []map[string]string{{"Key": "Environment", "Value": "updated"}},
		})
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{NativeID: testDnsZoneNativeID, DesiredProperties: props})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testDnsZoneNativeID, got.ProgressResult.NativeID)
	})

	t.Run("Delete", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testDnsZoneNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusInProgress, got.ProgressResult.OperationStatus)
		require.NotEmpty(t, got.ProgressResult.RequestID)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _ string, _ *armdns.ZonesClientBeginDeleteOptions) (*runtime.Poller[armdns.ZonesClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testDnsZoneNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_resource_group", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 1)
	})

	t.Run("List_all", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{},
		})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 1)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.createOrUpdateFn = func(_ context.Context, _, _ string, _ armdns.Zone, _ *armdns.ZonesClientCreateOrUpdateOptions) (armdns.ZonesClientCreateOrUpdateResponse, error) {
			return armdns.ZonesClientCreateOrUpdateResponse{}, &azcore.ResponseError{StatusCode: 403}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

// --- Test helpers ---

func newTestDnsZone(api dnsZonesAPI) *DnsZone {
	return &DnsZone{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

type fakeDnsZonesAPI struct {
	createOrUpdateFn              func(ctx context.Context, rgName, zoneName string, params armdns.Zone, opts *armdns.ZonesClientCreateOrUpdateOptions) (armdns.ZonesClientCreateOrUpdateResponse, error)
	getFn                         func(ctx context.Context, rgName, zoneName string, opts *armdns.ZonesClientGetOptions) (armdns.ZonesClientGetResponse, error)
	beginDeleteFn                 func(ctx context.Context, rgName, zoneName string, opts *armdns.ZonesClientBeginDeleteOptions) (*runtime.Poller[armdns.ZonesClientDeleteResponse], error)
	newListByResourceGroupPagerFn func(rgName string, opts *armdns.ZonesClientListByResourceGroupOptions) *runtime.Pager[armdns.ZonesClientListByResourceGroupResponse]
	newListPagerFn                func(opts *armdns.ZonesClientListOptions) *runtime.Pager[armdns.ZonesClientListResponse]
}

func (f *fakeDnsZonesAPI) CreateOrUpdate(ctx context.Context, rgName, zoneName string, params armdns.Zone, opts *armdns.ZonesClientCreateOrUpdateOptions) (armdns.ZonesClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, zoneName, params, opts)
}

func (f *fakeDnsZonesAPI) Get(ctx context.Context, rgName, zoneName string, opts *armdns.ZonesClientGetOptions) (armdns.ZonesClientGetResponse, error) {
	return f.getFn(ctx, rgName, zoneName, opts)
}

func (f *fakeDnsZonesAPI) BeginDelete(ctx context.Context, rgName, zoneName string, opts *armdns.ZonesClientBeginDeleteOptions) (*runtime.Poller[armdns.ZonesClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, zoneName, opts)
}

func (f *fakeDnsZonesAPI) NewListByResourceGroupPager(rgName string, opts *armdns.ZonesClientListByResourceGroupOptions) *runtime.Pager[armdns.ZonesClientListByResourceGroupResponse] {
	return f.newListByResourceGroupPagerFn(rgName, opts)
}

func (f *fakeDnsZonesAPI) NewListPager(opts *armdns.ZonesClientListOptions) *runtime.Pager[armdns.ZonesClientListResponse] {
	return f.newListPagerFn(opts)
}
