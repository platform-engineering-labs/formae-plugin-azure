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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/search/armsearch"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testSearchServiceNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Search/searchServices/search-1"

func newTestSearchService(api searchServicesAPI) *SearchService {
	return &SearchService{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func searchDesired(replicas int32) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":                "search-1",
		"location":            "eastus",
		"resourceGroupName":   "rg-1",
		"sku":                 map[string]any{"name": "basic"},
		"replicaCount":        replicas,
		"partitionCount":      1,
		"publicNetworkAccess": "enabled",
		"semanticSearch":      "disabled",
	})
	return out
}

func TestSearchService_CRUD(t *testing.T) {
	svcResult := armsearch.Service{
		ID:       to.Ptr(testSearchServiceNativeID),
		Name:     to.Ptr("search-1"),
		Location: to.Ptr("East US"),
		SKU:      &armsearch.SKU{Name: to.Ptr(armsearch.SKUNameBasic)},
		Properties: &armsearch.ServiceProperties{
			ReplicaCount:        to.Ptr(int32(1)),
			PartitionCount:      to.Ptr(int32(1)),
			HostingMode:         to.Ptr(armsearch.HostingModeDefault),
			PublicNetworkAccess: to.Ptr(armsearch.PublicNetworkAccessEnabled),
			SemanticSearch:      to.Ptr(armsearch.SearchSemanticSearchDisabled),
			Endpoint:            to.Ptr("https://search-1.search.windows.net"),
		},
	}

	var sentCreate armsearch.Service
	var sentUpdate armsearch.ServiceUpdate
	deleteCalls := 0
	fake := &fakeSearchServicesAPI{
		beginCreateOrUpdateFn: func(_ context.Context, _, name string, svc armsearch.Service, _ *armsearch.SearchManagementRequestOptions, _ *armsearch.ServicesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armsearch.ServicesClientCreateOrUpdateResponse], error) {
			require.Equal(t, "search-1", name)
			sentCreate = svc
			return newDonePoller(armsearch.ServicesClientCreateOrUpdateResponse{Service: svcResult}), nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armsearch.SearchManagementRequestOptions, _ *armsearch.ServicesClientGetOptions) (armsearch.ServicesClientGetResponse, error) {
			return armsearch.ServicesClientGetResponse{Service: svcResult}, nil
		},
		updateFn: func(_ context.Context, _, _ string, svc armsearch.ServiceUpdate, _ *armsearch.SearchManagementRequestOptions, _ *armsearch.ServicesClientUpdateOptions) (armsearch.ServicesClientUpdateResponse, error) {
			sentUpdate = svc
			return armsearch.ServicesClientUpdateResponse{Service: svcResult}, nil
		},
		deleteFn: func(_ context.Context, _, _ string, _ *armsearch.SearchManagementRequestOptions, _ *armsearch.ServicesClientDeleteOptions) (armsearch.ServicesClientDeleteResponse, error) {
			deleteCalls++
			return armsearch.ServicesClientDeleteResponse{}, nil
		},
		newListBySubscriptionPagerFn: func(_ *armsearch.SearchManagementRequestOptions, _ *armsearch.ServicesClientListBySubscriptionOptions) *runtime.Pager[armsearch.ServicesClientListBySubscriptionResponse] {
			return runtime.NewPager(runtime.PagingHandler[armsearch.ServicesClientListBySubscriptionResponse]{
				More: func(_ armsearch.ServicesClientListBySubscriptionResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armsearch.ServicesClientListBySubscriptionResponse) (armsearch.ServicesClientListBySubscriptionResponse, error) {
					return armsearch.ServicesClientListBySubscriptionResponse{
						ServiceListResult: armsearch.ServiceListResult{
							Value: []*armsearch.Service{
								{ID: to.Ptr(testSearchServiceNativeID)},
								{ID: to.Ptr("/subscriptions/sub-1/resourceGroups/rg-2/providers/Microsoft.Search/searchServices/search-2")},
							},
						},
					}, nil
				},
			})
		},
		newListByResourceGroupPagerFn: func(_ string, _ *armsearch.SearchManagementRequestOptions, _ *armsearch.ServicesClientListByResourceGroupOptions) *runtime.Pager[armsearch.ServicesClientListByResourceGroupResponse] {
			return runtime.NewPager(runtime.PagingHandler[armsearch.ServicesClientListByResourceGroupResponse]{
				More: func(_ armsearch.ServicesClientListByResourceGroupResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armsearch.ServicesClientListByResourceGroupResponse) (armsearch.ServicesClientListByResourceGroupResponse, error) {
					return armsearch.ServicesClientListByResourceGroupResponse{
						ServiceListResult: armsearch.ServiceListResult{
							Value: []*armsearch.Service{{ID: to.Ptr(testSearchServiceNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestSearchService(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "search-1", Properties: searchDesired(1)})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testSearchServiceNativeID, got.ProgressResult.NativeID)

		require.Equal(t, armsearch.SKUNameBasic, *sentCreate.SKU.Name)
		require.EqualValues(t, 1, *sentCreate.Properties.ReplicaCount)
		require.EqualValues(t, 1, *sentCreate.Properties.PartitionCount)
	})

	t.Run("Create_requires_sku", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "search-1", "location": "eastus", "resourceGroupName": "rg-1",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "sku.name is required")
	})

	t.Run("Create_requires_location", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "search-1", "resourceGroupName": "rg-1", "sku": map[string]any{"name": "basic"},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "location is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testSearchServiceNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "search-1", props["name"])
		// ARM returns "East US"; read must normalise or desired state drifts.
		require.Equal(t, "eastus", props["location"])
		require.Equal(t, "https://search-1.search.windows.net", props["endpoint"])
		require.Equal(t, "disabled", props["semanticSearch"])
		sku := props["sku"].(map[string]any)
		require.Equal(t, "basic", sku["name"])
	})

	// API keys come from separate ListAdminKeys / ListQueryKeys calls and must not
	// reach state on any path.
	t.Run("keys_never_serialized", func(t *testing.T) {
		read, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testSearchServiceNativeID})
		require.NoError(t, err)
		for _, key := range []string{"adminKey", "primaryKey", "queryKey", "apiKey"} {
			require.NotContains(t, read.Properties, key)
		}
	})

	// Update is a synchronous PATCH: it must report Success directly, never
	// InProgress with a resume token.
	t.Run("Update_is_synchronous", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testSearchServiceNativeID,
			DesiredProperties: searchDesired(2),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testSearchServiceNativeID, got.ProgressResult.NativeID)
		require.Empty(t, got.ProgressResult.RequestID)
		require.EqualValues(t, 2, *sentUpdate.Properties.ReplicaCount)
	})

	// Delete is synchronous too: terminal status, no poller.
	t.Run("Delete_is_synchronous", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testSearchServiceNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Empty(t, got.ProgressResult.RequestID)
		require.Equal(t, before+1, deleteCalls)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _ string, _ *armsearch.SearchManagementRequestOptions, _ *armsearch.ServicesClientDeleteOptions) (armsearch.ServicesClientDeleteResponse, error) {
			return armsearch.ServicesClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testSearchServiceNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_resource_group", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testSearchServiceNativeID}, got.NativeIDs)
	})

	t.Run("List_without_group_is_subscription_wide", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 2)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, _ armsearch.Service, _ *armsearch.SearchManagementRequestOptions, _ *armsearch.ServicesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armsearch.ServicesClientCreateOrUpdateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 409}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "search-1", Properties: searchDesired(1)})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

// Azure AI Search returns capitalized enum values even though the SDK constants
// and the request body are lowercase. Echoing that casing back failed conformance
// [Verify] ("expected enabled, got Enabled") AND broke `formae extract`, which
// could not render the PKL union for hostingMode. Read must canonicalize.
func TestSearchService_ReadCanonicalizesServiceCasing(t *testing.T) {
	fake := &fakeSearchServicesAPI{
		getFn: func(_ context.Context, _, _ string, _ *armsearch.SearchManagementRequestOptions, _ *armsearch.ServicesClientGetOptions) (armsearch.ServicesClientGetResponse, error) {
			return armsearch.ServicesClientGetResponse{Service: armsearch.Service{
				ID:       to.Ptr(testSearchServiceNativeID),
				Name:     to.Ptr("search-1"),
				Location: to.Ptr("East US"),
				// Service casing, not SDK-constant casing.
				SKU: &armsearch.SKU{Name: to.Ptr(armsearch.SKUName("Basic"))},
				Properties: &armsearch.ServiceProperties{
					HostingMode:         to.Ptr(armsearch.HostingMode("Default")),
					PublicNetworkAccess: to.Ptr(armsearch.PublicNetworkAccess("Enabled")),
					SemanticSearch:      to.Ptr(armsearch.SearchSemanticSearch("Disabled")),
				},
			}}, nil
		},
	}
	got, err := newTestSearchService(fake).Read(context.Background(), &resource.ReadRequest{NativeID: testSearchServiceNativeID})
	require.NoError(t, err)

	var props map[string]any
	require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
	require.Equal(t, "enabled", props["publicNetworkAccess"])
	require.Equal(t, "default", props["hostingMode"])
	require.Equal(t, "disabled", props["semanticSearch"])
	require.Equal(t, "basic", props["sku"].(map[string]any)["name"])
}

// Mixed-case values must keep their internal capitals: a blanket ToLower would
// turn highDensity into highdensity, which the PKL union also rejects.
func TestSearchService_CanonicalizeKeepsMixedCase(t *testing.T) {
	require.Equal(t, "highDensity", canonicalizeEnum("HighDensity", "default", "highDensity"))
	require.Equal(t, "highDensity", canonicalizeEnum("highdensity", "default", "highDensity"))
	require.Equal(t, "storage_optimized_l1", canonicalizeEnum("Storage_Optimized_L1", "storage_optimized_l1"))
	require.Equal(t, "securedByPerimeter", canonicalizeEnum("SecuredByPerimeter", "enabled", "disabled", "securedByPerimeter"))
	// An unknown value passes through rather than being mangled.
	require.Equal(t, "SomethingNew", canonicalizeEnum("SomethingNew", "enabled", "disabled"))
}

func TestSearchService_ReadNotFound(t *testing.T) {
	fake := &fakeSearchServicesAPI{
		getFn: func(_ context.Context, _, _ string, _ *armsearch.SearchManagementRequestOptions, _ *armsearch.ServicesClientGetOptions) (armsearch.ServicesClientGetResponse, error) {
			return armsearch.ServicesClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestSearchService(fake).Read(context.Background(), &resource.ReadRequest{NativeID: testSearchServiceNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeSearchServicesAPI struct {
	beginCreateOrUpdateFn         func(ctx context.Context, rgName, name string, svc armsearch.Service, reqOpts *armsearch.SearchManagementRequestOptions, options *armsearch.ServicesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armsearch.ServicesClientCreateOrUpdateResponse], error)
	getFn                         func(ctx context.Context, rgName, name string, reqOpts *armsearch.SearchManagementRequestOptions, options *armsearch.ServicesClientGetOptions) (armsearch.ServicesClientGetResponse, error)
	updateFn                      func(ctx context.Context, rgName, name string, svc armsearch.ServiceUpdate, reqOpts *armsearch.SearchManagementRequestOptions, options *armsearch.ServicesClientUpdateOptions) (armsearch.ServicesClientUpdateResponse, error)
	deleteFn                      func(ctx context.Context, rgName, name string, reqOpts *armsearch.SearchManagementRequestOptions, options *armsearch.ServicesClientDeleteOptions) (armsearch.ServicesClientDeleteResponse, error)
	newListBySubscriptionPagerFn  func(reqOpts *armsearch.SearchManagementRequestOptions, options *armsearch.ServicesClientListBySubscriptionOptions) *runtime.Pager[armsearch.ServicesClientListBySubscriptionResponse]
	newListByResourceGroupPagerFn func(rgName string, reqOpts *armsearch.SearchManagementRequestOptions, options *armsearch.ServicesClientListByResourceGroupOptions) *runtime.Pager[armsearch.ServicesClientListByResourceGroupResponse]
}

func (f *fakeSearchServicesAPI) BeginCreateOrUpdate(ctx context.Context, rgName, name string, svc armsearch.Service, reqOpts *armsearch.SearchManagementRequestOptions, options *armsearch.ServicesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armsearch.ServicesClientCreateOrUpdateResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, rgName, name, svc, reqOpts, options)
}

func (f *fakeSearchServicesAPI) Get(ctx context.Context, rgName, name string, reqOpts *armsearch.SearchManagementRequestOptions, options *armsearch.ServicesClientGetOptions) (armsearch.ServicesClientGetResponse, error) {
	return f.getFn(ctx, rgName, name, reqOpts, options)
}

func (f *fakeSearchServicesAPI) Update(ctx context.Context, rgName, name string, svc armsearch.ServiceUpdate, reqOpts *armsearch.SearchManagementRequestOptions, options *armsearch.ServicesClientUpdateOptions) (armsearch.ServicesClientUpdateResponse, error) {
	return f.updateFn(ctx, rgName, name, svc, reqOpts, options)
}

func (f *fakeSearchServicesAPI) Delete(ctx context.Context, rgName, name string, reqOpts *armsearch.SearchManagementRequestOptions, options *armsearch.ServicesClientDeleteOptions) (armsearch.ServicesClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, name, reqOpts, options)
}

func (f *fakeSearchServicesAPI) NewListBySubscriptionPager(reqOpts *armsearch.SearchManagementRequestOptions, options *armsearch.ServicesClientListBySubscriptionOptions) *runtime.Pager[armsearch.ServicesClientListBySubscriptionResponse] {
	return f.newListBySubscriptionPagerFn(reqOpts, options)
}

func (f *fakeSearchServicesAPI) NewListByResourceGroupPager(rgName string, reqOpts *armsearch.SearchManagementRequestOptions, options *armsearch.ServicesClientListByResourceGroupOptions) *runtime.Pager[armsearch.ServicesClientListByResourceGroupResponse] {
	return f.newListByResourceGroupPagerFn(rgName, reqOpts, options)
}
