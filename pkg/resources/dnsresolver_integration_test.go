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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/dnsresolver/armdnsresolver"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const (
	testDNSResolverNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/dnsResolvers/resolver-1"
	testDNSResolverVnetID   = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/virtualNetworks/vnet-1"
)

func newTestDNSResolver(api dnsResolversAPI) *DNSResolver {
	return &DNSResolver{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func dnsResolverDesired(tagValue string) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":              "resolver-1",
		"location":          "eastus",
		"resourceGroupName": "rg-1",
		"virtualNetworkId":  testDNSResolverVnetID,
		"Tags":              []any{map[string]any{"Key": "env", "Value": tagValue}},
	})
	return out
}

func TestDNSResolver_CRUD(t *testing.T) {
	resolverResult := armdnsresolver.DNSResolver{
		ID:       to.Ptr(testDNSResolverNativeID),
		Name:     to.Ptr("resolver-1"),
		Location: to.Ptr("East US"),
		Properties: &armdnsresolver.Properties{
			VirtualNetwork:    &armdnsresolver.SubResource{ID: to.Ptr(testDNSResolverVnetID)},
			DNSResolverState:  to.Ptr(armdnsresolver.DNSResolverStateConnected),
			ProvisioningState: to.Ptr(armdnsresolver.ProvisioningStateSucceeded),
			ResourceGUID:      to.Ptr("11111111-2222-3333-4444-555555555555"),
		},
		Tags: map[string]*string{"env": to.Ptr("test")},
	}

	var sentCreate armdnsresolver.DNSResolver
	var sentPatch armdnsresolver.Patch
	deleteCalls := 0
	fake := &fakeDNSResolversAPI{
		beginCreateOrUpdateFn: func(_ context.Context, _, name string, params armdnsresolver.DNSResolver, _ *armdnsresolver.DNSResolversClientBeginCreateOrUpdateOptions) (*runtime.Poller[armdnsresolver.DNSResolversClientCreateOrUpdateResponse], error) {
			require.Equal(t, "resolver-1", name)
			sentCreate = params
			return newDonePoller(armdnsresolver.DNSResolversClientCreateOrUpdateResponse{DNSResolver: resolverResult}), nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armdnsresolver.DNSResolversClientGetOptions) (armdnsresolver.DNSResolversClientGetResponse, error) {
			return armdnsresolver.DNSResolversClientGetResponse{DNSResolver: resolverResult}, nil
		},
		beginUpdateFn: func(_ context.Context, _, _ string, params armdnsresolver.Patch, _ *armdnsresolver.DNSResolversClientBeginUpdateOptions) (*runtime.Poller[armdnsresolver.DNSResolversClientUpdateResponse], error) {
			sentPatch = params
			return newDonePoller(armdnsresolver.DNSResolversClientUpdateResponse{DNSResolver: resolverResult}), nil
		},
		beginDeleteFn: func(_ context.Context, _, _ string, _ *armdnsresolver.DNSResolversClientBeginDeleteOptions) (*runtime.Poller[armdnsresolver.DNSResolversClientDeleteResponse], error) {
			deleteCalls++
			return newDonePoller(armdnsresolver.DNSResolversClientDeleteResponse{}), nil
		},
		newListPagerFn: func(_ *armdnsresolver.DNSResolversClientListOptions) *runtime.Pager[armdnsresolver.DNSResolversClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armdnsresolver.DNSResolversClientListResponse]{
				More: func(_ armdnsresolver.DNSResolversClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armdnsresolver.DNSResolversClientListResponse) (armdnsresolver.DNSResolversClientListResponse, error) {
					return armdnsresolver.DNSResolversClientListResponse{
						ListResult: armdnsresolver.ListResult{
							Value: []*armdnsresolver.DNSResolver{
								{ID: to.Ptr(testDNSResolverNativeID)},
								{ID: to.Ptr("/subscriptions/sub-1/resourceGroups/rg-2/providers/Microsoft.Network/dnsResolvers/resolver-2")},
							},
						},
					}, nil
				},
			})
		},
		newListByResourceGroupPagerFn: func(_ string, _ *armdnsresolver.DNSResolversClientListByResourceGroupOptions) *runtime.Pager[armdnsresolver.DNSResolversClientListByResourceGroupResponse] {
			return runtime.NewPager(runtime.PagingHandler[armdnsresolver.DNSResolversClientListByResourceGroupResponse]{
				More: func(_ armdnsresolver.DNSResolversClientListByResourceGroupResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armdnsresolver.DNSResolversClientListByResourceGroupResponse) (armdnsresolver.DNSResolversClientListByResourceGroupResponse, error) {
					return armdnsresolver.DNSResolversClientListByResourceGroupResponse{
						ListResult: armdnsresolver.ListResult{
							Value: []*armdnsresolver.DNSResolver{{ID: to.Ptr(testDNSResolverNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestDNSResolver(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "resolver-1",
			Properties: dnsResolverDesired("test"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testDNSResolverNativeID, got.ProgressResult.NativeID)
		require.Equal(t, testDNSResolverVnetID, *sentCreate.Properties.VirtualNetwork.ID)
		require.Equal(t, "test", *sentCreate.Tags["env"])
	})

	t.Run("Create_requires_virtual_network", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "resolver-1", "location": "eastus", "resourceGroupName": "rg-1",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "virtualNetworkId is required")
	})

	t.Run("Create_requires_location", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "resolver-1", "resourceGroupName": "rg-1", "virtualNetworkId": testDNSResolverVnetID,
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "location is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testDNSResolverNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "resolver-1", props["name"])
		// ARM returns "East US"; read must normalise or desired state drifts.
		require.Equal(t, "eastus", props["location"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, testDNSResolverVnetID, props["virtualNetworkId"])
		require.Equal(t, "Connected", props["dnsResolverState"])
	})

	// provisioningState and resourceGuid are service bookkeeping, not desired
	// state: surfacing them would only ever read back as noise.
	t.Run("Read_drops_service_bookkeeping", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testDNSResolverNativeID})
		require.NoError(t, err)
		require.NotContains(t, got.Properties, "provisioningState")
		require.NotContains(t, got.Properties, "resourceGuid")
		require.NotContains(t, got.Properties, "resourceGUID")
	})

	// armdnsresolver.Patch carries tags and nothing else, so a tag change is the
	// only in-place update this resource has.
	t.Run("Update_sends_tags", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testDNSResolverNativeID,
			DesiredProperties: dnsResolverDesired("updated"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, "updated", *sentPatch.Tags["env"])
	})

	t.Run("Delete", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testDNSResolverNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _ string, _ *armdnsresolver.DNSResolversClientBeginDeleteOptions) (*runtime.Poller[armdnsresolver.DNSResolversClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testDNSResolverNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_resource_group", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testDNSResolverNativeID}, got.NativeIDs)
	})

	t.Run("List_without_group_is_subscription_wide", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 2)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, _ armdnsresolver.DNSResolver, _ *armdnsresolver.DNSResolversClientBeginCreateOrUpdateOptions) (*runtime.Poller[armdnsresolver.DNSResolversClientCreateOrUpdateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 409}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "resolver-1", Properties: dnsResolverDesired("test"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

func TestDNSResolver_ReadNotFound(t *testing.T) {
	fake := &fakeDNSResolversAPI{
		getFn: func(_ context.Context, _, _ string, _ *armdnsresolver.DNSResolversClientGetOptions) (armdnsresolver.DNSResolversClientGetResponse, error) {
			return armdnsresolver.DNSResolversClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestDNSResolver(fake).Read(context.Background(), &resource.ReadRequest{NativeID: testDNSResolverNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeDNSResolversAPI struct {
	beginCreateOrUpdateFn         func(ctx context.Context, rgName, name string, params armdnsresolver.DNSResolver, options *armdnsresolver.DNSResolversClientBeginCreateOrUpdateOptions) (*runtime.Poller[armdnsresolver.DNSResolversClientCreateOrUpdateResponse], error)
	getFn                         func(ctx context.Context, rgName, name string, options *armdnsresolver.DNSResolversClientGetOptions) (armdnsresolver.DNSResolversClientGetResponse, error)
	beginUpdateFn                 func(ctx context.Context, rgName, name string, params armdnsresolver.Patch, options *armdnsresolver.DNSResolversClientBeginUpdateOptions) (*runtime.Poller[armdnsresolver.DNSResolversClientUpdateResponse], error)
	beginDeleteFn                 func(ctx context.Context, rgName, name string, options *armdnsresolver.DNSResolversClientBeginDeleteOptions) (*runtime.Poller[armdnsresolver.DNSResolversClientDeleteResponse], error)
	newListPagerFn                func(options *armdnsresolver.DNSResolversClientListOptions) *runtime.Pager[armdnsresolver.DNSResolversClientListResponse]
	newListByResourceGroupPagerFn func(rgName string, options *armdnsresolver.DNSResolversClientListByResourceGroupOptions) *runtime.Pager[armdnsresolver.DNSResolversClientListByResourceGroupResponse]
}

func (f *fakeDNSResolversAPI) BeginCreateOrUpdate(ctx context.Context, rgName, name string, params armdnsresolver.DNSResolver, options *armdnsresolver.DNSResolversClientBeginCreateOrUpdateOptions) (*runtime.Poller[armdnsresolver.DNSResolversClientCreateOrUpdateResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, rgName, name, params, options)
}

func (f *fakeDNSResolversAPI) Get(ctx context.Context, rgName, name string, options *armdnsresolver.DNSResolversClientGetOptions) (armdnsresolver.DNSResolversClientGetResponse, error) {
	return f.getFn(ctx, rgName, name, options)
}

func (f *fakeDNSResolversAPI) BeginUpdate(ctx context.Context, rgName, name string, params armdnsresolver.Patch, options *armdnsresolver.DNSResolversClientBeginUpdateOptions) (*runtime.Poller[armdnsresolver.DNSResolversClientUpdateResponse], error) {
	return f.beginUpdateFn(ctx, rgName, name, params, options)
}

func (f *fakeDNSResolversAPI) BeginDelete(ctx context.Context, rgName, name string, options *armdnsresolver.DNSResolversClientBeginDeleteOptions) (*runtime.Poller[armdnsresolver.DNSResolversClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, name, options)
}

func (f *fakeDNSResolversAPI) NewListPager(options *armdnsresolver.DNSResolversClientListOptions) *runtime.Pager[armdnsresolver.DNSResolversClientListResponse] {
	return f.newListPagerFn(options)
}

func (f *fakeDNSResolversAPI) NewListByResourceGroupPager(rgName string, options *armdnsresolver.DNSResolversClientListByResourceGroupOptions) *runtime.Pager[armdnsresolver.DNSResolversClientListByResourceGroupResponse] {
	return f.newListByResourceGroupPagerFn(rgName, options)
}
