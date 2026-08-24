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
	testDomainListNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/dnsResolverDomainLists/list-1"
)

func newTestDomainList(api dnsResolverDomainListsAPI) *DNSResolverDomainList {
	return &DNSResolverDomainList{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func domainListDesired(tagValue string) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":              "list-1",
		"location":          "eastus",
		"resourceGroupName": "rg-1",
		"domains":           []any{"malware.example.com.", "phishing.example.com."},
		"Tags":              []any{map[string]any{"Key": "env", "Value": tagValue}},
	})
	return out
}

func TestDNSResolverDomainList_CRUD(t *testing.T) {
	resolverResult := armdnsresolver.DomainList{
		ID:       to.Ptr(testDomainListNativeID),
		Name:     to.Ptr("list-1"),
		Location: to.Ptr("East US"),
		Properties: &armdnsresolver.DomainListProperties{
			Domains:      []*string{to.Ptr("malware.example.com."), to.Ptr("phishing.example.com.")},
			DomainsURL:   to.Ptr("https://example.blob.core.windows.net/lists/domains.txt"),
			ResourceGUID: to.Ptr("11111111-2222-3333-4444-555555555555"),
		},
		Tags: map[string]*string{"env": to.Ptr("test")},
	}

	var sentCreate armdnsresolver.DomainList
	var sentPatch armdnsresolver.DomainListPatch
	deleteCalls := 0
	fake := &fakeDNSResolverDomainListsAPI{
		beginCreateOrUpdateFn: func(_ context.Context, _, name string, params armdnsresolver.DomainList, _ *armdnsresolver.DomainListsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armdnsresolver.DomainListsClientCreateOrUpdateResponse], error) {
			require.Equal(t, "list-1", name)
			sentCreate = params
			return newDonePoller(armdnsresolver.DomainListsClientCreateOrUpdateResponse{DomainList: resolverResult}), nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armdnsresolver.DomainListsClientGetOptions) (armdnsresolver.DomainListsClientGetResponse, error) {
			return armdnsresolver.DomainListsClientGetResponse{DomainList: resolverResult}, nil
		},
		beginUpdateFn: func(_ context.Context, _, _ string, params armdnsresolver.DomainListPatch, _ *armdnsresolver.DomainListsClientBeginUpdateOptions) (*runtime.Poller[armdnsresolver.DomainListsClientUpdateResponse], error) {
			sentPatch = params
			return newDonePoller(armdnsresolver.DomainListsClientUpdateResponse{DomainList: resolverResult}), nil
		},
		beginDeleteFn: func(_ context.Context, _, _ string, _ *armdnsresolver.DomainListsClientBeginDeleteOptions) (*runtime.Poller[armdnsresolver.DomainListsClientDeleteResponse], error) {
			deleteCalls++
			return newDonePoller(armdnsresolver.DomainListsClientDeleteResponse{}), nil
		},
		newListPagerFn: func(_ *armdnsresolver.DomainListsClientListOptions) *runtime.Pager[armdnsresolver.DomainListsClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armdnsresolver.DomainListsClientListResponse]{
				More: func(_ armdnsresolver.DomainListsClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armdnsresolver.DomainListsClientListResponse) (armdnsresolver.DomainListsClientListResponse, error) {
					return armdnsresolver.DomainListsClientListResponse{
						DomainListResult: armdnsresolver.DomainListResult{
							Value: []*armdnsresolver.DomainList{
								{ID: to.Ptr(testDomainListNativeID)},
								{ID: to.Ptr("/subscriptions/sub-1/resourceGroups/rg-2/providers/Microsoft.Network/dnsResolverDomainLists/list-2")},
							},
						},
					}, nil
				},
			})
		},
		newListByResourceGroupPagerFn: func(_ string, _ *armdnsresolver.DomainListsClientListByResourceGroupOptions) *runtime.Pager[armdnsresolver.DomainListsClientListByResourceGroupResponse] {
			return runtime.NewPager(runtime.PagingHandler[armdnsresolver.DomainListsClientListByResourceGroupResponse]{
				More: func(_ armdnsresolver.DomainListsClientListByResourceGroupResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armdnsresolver.DomainListsClientListByResourceGroupResponse) (armdnsresolver.DomainListsClientListByResourceGroupResponse, error) {
					return armdnsresolver.DomainListsClientListByResourceGroupResponse{
						DomainListResult: armdnsresolver.DomainListResult{
							Value: []*armdnsresolver.DomainList{{ID: to.Ptr(testDomainListNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestDomainList(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "list-1",
			Properties: domainListDesired("test"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testDomainListNativeID, got.ProgressResult.NativeID)
		require.Equal(t, "test", *sentCreate.Tags["env"])
		require.Len(t, sentCreate.Properties.Domains, 2)
		require.Equal(t, "malware.example.com.", *sentCreate.Properties.Domains[0])
	})

	t.Run("Create_requires_domains", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "list-1", "location": "eastus", "resourceGroupName": "rg-1",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "domains is required")
	})

	t.Run("Create_requires_location", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "list-1", "resourceGroupName": "rg-1",
			"domains": []any{"malware.example.com."},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "location is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testDomainListNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "list-1", props["name"])
		// ARM returns "East US"; read must normalise or desired state drifts.
		require.Equal(t, "eastus", props["location"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		// Order is echoed as ARM returns it.
		require.Equal(t, []any{"malware.example.com.", "phishing.example.com."}, props["domains"])
	})

	// provisioningState and resourceGuid are service bookkeeping, not desired
	// state: surfacing them would only ever read back as noise.
	t.Run("Read_drops_service_bookkeeping", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testDomainListNativeID})
		require.NoError(t, err)
		require.NotContains(t, got.Properties, "provisioningState")
		require.NotContains(t, got.Properties, "resourceGuid")
		require.NotContains(t, got.Properties, "resourceGUID")
		// domainsUrl belongs to the bulk upload API this resource does not use.
		require.NotContains(t, got.Properties, "domainsUrl")
		require.NotContains(t, got.Properties, "domainsURL")
	})

	// armdnsresolver.DomainListPatch carries tags and nothing else, so a tag change is the
	// only in-place update this resource has.
	t.Run("Update_sends_tags", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testDomainListNativeID,
			DesiredProperties: domainListDesired("updated"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, "updated", *sentPatch.Tags["env"])
		// DomainListPatch nests the list under "properties" correctly (unlike
		// DNSForwardingRulesetPatch), so the domains can ride along on the patch.
		require.Len(t, sentPatch.Properties.Domains, 2)
	})

	t.Run("Delete", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testDomainListNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _ string, _ *armdnsresolver.DomainListsClientBeginDeleteOptions) (*runtime.Poller[armdnsresolver.DomainListsClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testDomainListNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_resource_group", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testDomainListNativeID}, got.NativeIDs)
	})

	t.Run("List_without_group_is_subscription_wide", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 2)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, _ armdnsresolver.DomainList, _ *armdnsresolver.DomainListsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armdnsresolver.DomainListsClientCreateOrUpdateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 409}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "list-1", Properties: domainListDesired("test"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

func TestDNSResolverDomainList_ReadNotFound(t *testing.T) {
	fake := &fakeDNSResolverDomainListsAPI{
		getFn: func(_ context.Context, _, _ string, _ *armdnsresolver.DomainListsClientGetOptions) (armdnsresolver.DomainListsClientGetResponse, error) {
			return armdnsresolver.DomainListsClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestDomainList(fake).Read(context.Background(), &resource.ReadRequest{NativeID: testDomainListNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeDNSResolverDomainListsAPI struct {
	beginCreateOrUpdateFn         func(ctx context.Context, rgName, name string, params armdnsresolver.DomainList, options *armdnsresolver.DomainListsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armdnsresolver.DomainListsClientCreateOrUpdateResponse], error)
	getFn                         func(ctx context.Context, rgName, name string, options *armdnsresolver.DomainListsClientGetOptions) (armdnsresolver.DomainListsClientGetResponse, error)
	beginUpdateFn                 func(ctx context.Context, rgName, name string, params armdnsresolver.DomainListPatch, options *armdnsresolver.DomainListsClientBeginUpdateOptions) (*runtime.Poller[armdnsresolver.DomainListsClientUpdateResponse], error)
	beginDeleteFn                 func(ctx context.Context, rgName, name string, options *armdnsresolver.DomainListsClientBeginDeleteOptions) (*runtime.Poller[armdnsresolver.DomainListsClientDeleteResponse], error)
	newListPagerFn                func(options *armdnsresolver.DomainListsClientListOptions) *runtime.Pager[armdnsresolver.DomainListsClientListResponse]
	newListByResourceGroupPagerFn func(rgName string, options *armdnsresolver.DomainListsClientListByResourceGroupOptions) *runtime.Pager[armdnsresolver.DomainListsClientListByResourceGroupResponse]
}

func (f *fakeDNSResolverDomainListsAPI) BeginCreateOrUpdate(ctx context.Context, rgName, name string, params armdnsresolver.DomainList, options *armdnsresolver.DomainListsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armdnsresolver.DomainListsClientCreateOrUpdateResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, rgName, name, params, options)
}

func (f *fakeDNSResolverDomainListsAPI) Get(ctx context.Context, rgName, name string, options *armdnsresolver.DomainListsClientGetOptions) (armdnsresolver.DomainListsClientGetResponse, error) {
	return f.getFn(ctx, rgName, name, options)
}

func (f *fakeDNSResolverDomainListsAPI) BeginUpdate(ctx context.Context, rgName, name string, params armdnsresolver.DomainListPatch, options *armdnsresolver.DomainListsClientBeginUpdateOptions) (*runtime.Poller[armdnsresolver.DomainListsClientUpdateResponse], error) {
	return f.beginUpdateFn(ctx, rgName, name, params, options)
}

func (f *fakeDNSResolverDomainListsAPI) BeginDelete(ctx context.Context, rgName, name string, options *armdnsresolver.DomainListsClientBeginDeleteOptions) (*runtime.Poller[armdnsresolver.DomainListsClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, name, options)
}

func (f *fakeDNSResolverDomainListsAPI) NewListPager(options *armdnsresolver.DomainListsClientListOptions) *runtime.Pager[armdnsresolver.DomainListsClientListResponse] {
	return f.newListPagerFn(options)
}

func (f *fakeDNSResolverDomainListsAPI) NewListByResourceGroupPager(rgName string, options *armdnsresolver.DomainListsClientListByResourceGroupOptions) *runtime.Pager[armdnsresolver.DomainListsClientListByResourceGroupResponse] {
	return f.newListByResourceGroupPagerFn(rgName, options)
}
