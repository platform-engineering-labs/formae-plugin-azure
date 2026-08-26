// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerregistry/armcontainerregistry"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testScopeMapNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.ContainerRegistry/registries/acr1/scopeMaps/sm1"

type fakeScopeMapsAPI struct {
	beginCreateFn func(ctx context.Context, rgName, registryName, name string, params armcontainerregistry.ScopeMap, options *armcontainerregistry.ScopeMapsClientBeginCreateOptions) (*runtime.Poller[armcontainerregistry.ScopeMapsClientCreateResponse], error)
	getFn         func(ctx context.Context, rgName, registryName, name string, options *armcontainerregistry.ScopeMapsClientGetOptions) (armcontainerregistry.ScopeMapsClientGetResponse, error)
	beginUpdateFn func(ctx context.Context, rgName, registryName, name string, params armcontainerregistry.ScopeMapUpdateParameters, options *armcontainerregistry.ScopeMapsClientBeginUpdateOptions) (*runtime.Poller[armcontainerregistry.ScopeMapsClientUpdateResponse], error)
	beginDeleteFn func(ctx context.Context, rgName, registryName, name string, options *armcontainerregistry.ScopeMapsClientBeginDeleteOptions) (*runtime.Poller[armcontainerregistry.ScopeMapsClientDeleteResponse], error)
	listPagerFn   func(rgName, registryName string, options *armcontainerregistry.ScopeMapsClientListOptions) *runtime.Pager[armcontainerregistry.ScopeMapsClientListResponse]
}

func (f *fakeScopeMapsAPI) BeginCreate(ctx context.Context, rgName, registryName, name string, params armcontainerregistry.ScopeMap, options *armcontainerregistry.ScopeMapsClientBeginCreateOptions) (*runtime.Poller[armcontainerregistry.ScopeMapsClientCreateResponse], error) {
	return f.beginCreateFn(ctx, rgName, registryName, name, params, options)
}

func (f *fakeScopeMapsAPI) Get(ctx context.Context, rgName, registryName, name string, options *armcontainerregistry.ScopeMapsClientGetOptions) (armcontainerregistry.ScopeMapsClientGetResponse, error) {
	return f.getFn(ctx, rgName, registryName, name, options)
}

func (f *fakeScopeMapsAPI) BeginUpdate(ctx context.Context, rgName, registryName, name string, params armcontainerregistry.ScopeMapUpdateParameters, options *armcontainerregistry.ScopeMapsClientBeginUpdateOptions) (*runtime.Poller[armcontainerregistry.ScopeMapsClientUpdateResponse], error) {
	return f.beginUpdateFn(ctx, rgName, registryName, name, params, options)
}

func (f *fakeScopeMapsAPI) BeginDelete(ctx context.Context, rgName, registryName, name string, options *armcontainerregistry.ScopeMapsClientBeginDeleteOptions) (*runtime.Poller[armcontainerregistry.ScopeMapsClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, registryName, name, options)
}

func (f *fakeScopeMapsAPI) NewListPager(rgName, registryName string, options *armcontainerregistry.ScopeMapsClientListOptions) *runtime.Pager[armcontainerregistry.ScopeMapsClientListResponse] {
	return f.listPagerFn(rgName, registryName, options)
}

func newTestScopeMap(api containerRegistryScopeMapsAPI) *ContainerRegistryScopeMap {
	return &ContainerRegistryScopeMap{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func scopeMapDesired(actions []any, description string) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":              "sm1",
		"resourceGroupName": "rg-1",
		"registryName":      "acr1",
		"actions":           actions,
		"description":       description,
	})
	return out
}

func TestContainerRegistryScopeMap_CRUD(t *testing.T) {
	created := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	scopeMapResult := armcontainerregistry.ScopeMap{
		ID:   to.Ptr(testScopeMapNativeID),
		Name: to.Ptr("sm1"),
		Properties: &armcontainerregistry.ScopeMapProperties{
			Actions:     []*string{to.Ptr("repositories/samples/nginx/content/read")},
			Description: to.Ptr("pull only"),
			// Service state, including whether the registry built the map itself.
			CreationDate:      to.Ptr(created),
			ProvisioningState: to.Ptr(armcontainerregistry.ProvisioningStateSucceeded),
			Type:              to.Ptr("IsUserDefined"),
		},
	}

	var sentCreate armcontainerregistry.ScopeMap
	var sentUpdate armcontainerregistry.ScopeMapUpdateParameters
	createCalls := 0
	updateCalls := 0
	deleteCalls := 0
	fake := &fakeScopeMapsAPI{
		beginCreateFn: func(_ context.Context, rgName, registryName, name string, params armcontainerregistry.ScopeMap, _ *armcontainerregistry.ScopeMapsClientBeginCreateOptions) (*runtime.Poller[armcontainerregistry.ScopeMapsClientCreateResponse], error) {
			require.Equal(t, "rg-1", rgName)
			require.Equal(t, "acr1", registryName)
			require.Equal(t, "sm1", name)
			sentCreate = params
			createCalls++
			return newDonePoller(armcontainerregistry.ScopeMapsClientCreateResponse{ScopeMap: scopeMapResult}), nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ *armcontainerregistry.ScopeMapsClientGetOptions) (armcontainerregistry.ScopeMapsClientGetResponse, error) {
			return armcontainerregistry.ScopeMapsClientGetResponse{ScopeMap: scopeMapResult}, nil
		},
		beginUpdateFn: func(_ context.Context, _, _, _ string, params armcontainerregistry.ScopeMapUpdateParameters, _ *armcontainerregistry.ScopeMapsClientBeginUpdateOptions) (*runtime.Poller[armcontainerregistry.ScopeMapsClientUpdateResponse], error) {
			sentUpdate = params
			updateCalls++
			return newDonePoller(armcontainerregistry.ScopeMapsClientUpdateResponse{ScopeMap: scopeMapResult}), nil
		},
		beginDeleteFn: func(_ context.Context, _, _, _ string, _ *armcontainerregistry.ScopeMapsClientBeginDeleteOptions) (*runtime.Poller[armcontainerregistry.ScopeMapsClientDeleteResponse], error) {
			deleteCalls++
			return newDonePoller(armcontainerregistry.ScopeMapsClientDeleteResponse{}), nil
		},
		listPagerFn: func(_, _ string, _ *armcontainerregistry.ScopeMapsClientListOptions) *runtime.Pager[armcontainerregistry.ScopeMapsClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armcontainerregistry.ScopeMapsClientListResponse]{
				More: func(_ armcontainerregistry.ScopeMapsClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armcontainerregistry.ScopeMapsClientListResponse) (armcontainerregistry.ScopeMapsClientListResponse, error) {
					return armcontainerregistry.ScopeMapsClientListResponse{
						ScopeMapListResult: armcontainerregistry.ScopeMapListResult{
							Value: []*armcontainerregistry.ScopeMap{
								{ID: to.Ptr(testScopeMapNativeID)},
								// A nil entry must not panic the walk.
								nil,
							},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestScopeMap(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "sm1", Properties: scopeMapDesired([]any{"repositories/samples/nginx/content/read"}, "pull only"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testScopeMapNativeID, got.ProgressResult.NativeID)

		require.Equal(t, "repositories/samples/nginx/content/read", *sentCreate.Properties.Actions[0])
		require.Equal(t, "pull only", *sentCreate.Properties.Description)
	})

	t.Run("Create_requires_actions", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "sm1", "resourceGroupName": "rg-1", "registryName": "acr1",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "actions is required")
	})

	t.Run("Create_requires_registry", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "sm1", "resourceGroupName": "rg-1"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "registryName is required")
	})

	// The native ID reported while the LRO is still running must match the path ARM
	// actually assigns, or the resource is orphaned once it completes.
	t.Run("PendingCreateReportsRealNativeID", func(t *testing.T) {
		fake.beginCreateFn = func(_ context.Context, _, _, _ string, _ armcontainerregistry.ScopeMap, _ *armcontainerregistry.ScopeMapsClientBeginCreateOptions) (*runtime.Poller[armcontainerregistry.ScopeMapsClientCreateResponse], error) {
			return newPendingPoller[armcontainerregistry.ScopeMapsClientCreateResponse](), nil
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "sm1", Properties: scopeMapDesired([]any{"repositories/samples/nginx/content/read"}, "pull only"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusInProgress, got.ProgressResult.OperationStatus)
		require.Equal(t, testScopeMapNativeID, got.ProgressResult.NativeID)

		reqID, err := decodeLROStatus(got.ProgressResult.RequestID)
		require.NoError(t, err)
		require.Equal(t, lroOpCreate, reqID.OperationType)
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testScopeMapNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "sm1", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "acr1", props["registryName"])
		require.Equal(t, []any{"repositories/samples/nginx/content/read"}, props["actions"])
		require.Equal(t, "pull only", props["description"])
	})

	t.Run("Read_drops_service_state", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testScopeMapNativeID})
		require.NoError(t, err)
		for _, key := range []string{"creationDate", "provisioningState", "IsUserDefined", "systemData"} {
			require.NotContains(t, got.Properties, key)
		}
	})

	// Unlike most resources in this plugin, this API has a real update verb.
	t.Run("Update_patches_rather_than_reputs", func(t *testing.T) {
		beforeUpdate := updateCalls
		beforeCreate := createCalls
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID: testScopeMapNativeID,
			DesiredProperties: scopeMapDesired([]any{
				"repositories/samples/nginx/content/read",
				"repositories/samples/nginx/metadata/read",
			}, "pull and inspect"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, beforeUpdate+1, updateCalls)
		// No re-PUT: the create verb must not be touched.
		require.Equal(t, beforeCreate, createCalls)
		require.Len(t, sentUpdate.Properties.Actions, 2)
		require.Equal(t, "pull and inspect", *sentUpdate.Properties.Description)
	})

	// The update token belongs to a poller with the Update response type. Resuming it
	// as a Create response would kill the plugin operator mid-apply.
	t.Run("PendingUpdateResumesAsUpdate", func(t *testing.T) {
		fake.beginUpdateFn = func(_ context.Context, _, _, _ string, _ armcontainerregistry.ScopeMapUpdateParameters, _ *armcontainerregistry.ScopeMapsClientBeginUpdateOptions) (*runtime.Poller[armcontainerregistry.ScopeMapsClientUpdateResponse], error) {
			return newPendingPoller[armcontainerregistry.ScopeMapsClientUpdateResponse](), nil
		}
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testScopeMapNativeID,
			DesiredProperties: scopeMapDesired([]any{"repositories/samples/nginx/content/read"}, "pull only"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusInProgress, got.ProgressResult.OperationStatus)

		reqID, err := decodeLROStatus(got.ProgressResult.RequestID)
		require.NoError(t, err)
		require.Equal(t, lroOpUpdate, reqID.OperationType)
		require.Equal(t, testScopeMapNativeID, reqID.NativeID)
	})

	t.Run("Delete", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testScopeMapNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _, _ string, _ *armcontainerregistry.ScopeMapsClientBeginDeleteOptions) (*runtime.Poller[armcontainerregistry.ScopeMapsClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testScopeMapNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "registryName": "acr1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testScopeMapNativeID}, got.NativeIDs)
	})

	t.Run("List_without_registry_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})

	t.Run("Read_NotFound", func(t *testing.T) {
		fake.getFn = func(_ context.Context, _, _, _ string, _ *armcontainerregistry.ScopeMapsClientGetOptions) (armcontainerregistry.ScopeMapsClientGetResponse, error) {
			return armcontainerregistry.ScopeMapsClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testScopeMapNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
	})
}
