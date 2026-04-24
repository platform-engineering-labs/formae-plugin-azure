// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerregistry/armcontainerregistry"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testCRNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.ContainerRegistry/registries/myregistry"

func TestContainerRegistry_CRUD(t *testing.T) {
	skuBasic := armcontainerregistry.SKUNameBasic
	skuStandard := armcontainerregistry.SKUNameStandard

	fake := &fakeContainerRegistryAPI{
		beginCreateFn: func(_ context.Context, _, _ string, _ armcontainerregistry.Registry, _ *armcontainerregistry.RegistriesClientBeginCreateOptions) (*runtime.Poller[armcontainerregistry.RegistriesClientCreateResponse], error) {
			return newDonePoller(armcontainerregistry.RegistriesClientCreateResponse{
				Registry: armcontainerregistry.Registry{
					ID:       to.Ptr(testCRNativeID),
					Name:     to.Ptr("myregistry"),
					Location: to.Ptr("eastus"),
					SKU:      &armcontainerregistry.SKU{Name: &skuBasic},
					Properties: &armcontainerregistry.RegistryProperties{
						LoginServer: to.Ptr("myregistry.azurecr.io"),
					},
				},
			}), nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armcontainerregistry.RegistriesClientGetOptions) (armcontainerregistry.RegistriesClientGetResponse, error) {
			return armcontainerregistry.RegistriesClientGetResponse{
				Registry: armcontainerregistry.Registry{
					ID:       to.Ptr(testCRNativeID),
					Name:     to.Ptr("myregistry"),
					Location: to.Ptr("eastus"),
					SKU:      &armcontainerregistry.SKU{Name: &skuBasic},
					Properties: &armcontainerregistry.RegistryProperties{
						LoginServer:      to.Ptr("myregistry.azurecr.io"),
						AdminUserEnabled: to.Ptr(false),
					},
				},
			}, nil
		},
		beginUpdateFn: func(_ context.Context, _, _ string, _ armcontainerregistry.RegistryUpdateParameters, _ *armcontainerregistry.RegistriesClientBeginUpdateOptions) (*runtime.Poller[armcontainerregistry.RegistriesClientUpdateResponse], error) {
			return newDonePoller(armcontainerregistry.RegistriesClientUpdateResponse{
				Registry: armcontainerregistry.Registry{
					ID:       to.Ptr(testCRNativeID),
					Name:     to.Ptr("myregistry"),
					Location: to.Ptr("eastus"),
					SKU:      &armcontainerregistry.SKU{Name: &skuStandard},
					Properties: &armcontainerregistry.RegistryProperties{
						LoginServer: to.Ptr("myregistry.azurecr.io"),
					},
				},
			}), nil
		},
		beginDeleteFn: func(_ context.Context, _, _ string, _ *armcontainerregistry.RegistriesClientBeginDeleteOptions) (*runtime.Poller[armcontainerregistry.RegistriesClientDeleteResponse], error) {
			return newDonePoller(armcontainerregistry.RegistriesClientDeleteResponse{}), nil
		},
		newListPagerFn: func(_ *armcontainerregistry.RegistriesClientListOptions) *runtime.Pager[armcontainerregistry.RegistriesClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armcontainerregistry.RegistriesClientListResponse]{
				More: func(_ armcontainerregistry.RegistriesClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armcontainerregistry.RegistriesClientListResponse) (armcontainerregistry.RegistriesClientListResponse, error) {
					return armcontainerregistry.RegistriesClientListResponse{
						RegistryListResult: armcontainerregistry.RegistryListResult{
							Value: []*armcontainerregistry.Registry{{ID: to.Ptr(testCRNativeID)}},
						},
					}, nil
				},
			})
		},
		newListByResourceGroupPagerFn: func(_ string, _ *armcontainerregistry.RegistriesClientListByResourceGroupOptions) *runtime.Pager[armcontainerregistry.RegistriesClientListByResourceGroupResponse] {
			return runtime.NewPager(runtime.PagingHandler[armcontainerregistry.RegistriesClientListByResourceGroupResponse]{
				More: func(_ armcontainerregistry.RegistriesClientListByResourceGroupResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armcontainerregistry.RegistriesClientListByResourceGroupResponse) (armcontainerregistry.RegistriesClientListByResourceGroupResponse, error) {
					return armcontainerregistry.RegistriesClientListByResourceGroupResponse{
						RegistryListResult: armcontainerregistry.RegistryListResult{
							Value: []*armcontainerregistry.Registry{
								{ID: to.Ptr(testCRNativeID)},
								{ID: to.Ptr("/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.ContainerRegistry/registries/other")},
							},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestContainerRegistry(fake)

	t.Run("Create", func(t *testing.T) {
		props, _ := json.Marshal(map[string]interface{}{
			"resourceGroupName": "rg-1", "name": "myregistry",
			"location": "eastus", "sku": map[string]interface{}{"name": "Basic"},
		})
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "myregistry", Properties: props})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testCRNativeID, got.ProgressResult.NativeID)
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testCRNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "myregistry", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "eastus", props["location"])
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _ string, _ *armcontainerregistry.RegistriesClientBeginDeleteOptions) (*runtime.Poller[armcontainerregistry.RegistriesClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testCRNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 2)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.beginCreateFn = func(_ context.Context, _, _ string, _ armcontainerregistry.Registry, _ *armcontainerregistry.RegistriesClientBeginCreateOptions) (*runtime.Poller[armcontainerregistry.RegistriesClientCreateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 409}
		}
		props, _ := json.Marshal(map[string]interface{}{
			"resourceGroupName": "rg-1", "name": "myregistry",
			"location": "eastus", "sku": map[string]interface{}{"name": "Basic"},
		})
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

// --- Test helpers ---

func newTestContainerRegistry(api containerRegistryAPI) *ContainerRegistry {
	return &ContainerRegistry{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

// newDonePoller creates a Poller that is immediately done with the given result.
// Used by multiple resource test files (e.g. keyvault).
func newDonePoller[T any](result T) *runtime.Poller[T] {
	p, _ := runtime.NewPoller[T](nil, runtime.Pipeline{}, &runtime.NewPollerOptions[T]{
		Handler: &donePollerHandler[T]{result: result},
	})
	return p
}

type donePollerHandler[T any] struct {
	result T
}

func (h *donePollerHandler[T]) Done() bool { return true }

func (h *donePollerHandler[T]) Poll(_ context.Context) (*http.Response, error) {
	return &http.Response{StatusCode: http.StatusOK}, nil
}

func (h *donePollerHandler[T]) Result(_ context.Context, out *T) error {
	*out = h.result
	return nil
}

// newInProgressPoller creates a Poller that is not yet done and yields a resume token.
func newInProgressPoller[T any]() *runtime.Poller[T] {
	p, _ := runtime.NewPoller[T](nil, runtime.Pipeline{}, &runtime.NewPollerOptions[T]{
		Handler: &inProgressPollerHandler[T]{},
	})
	return p
}

type inProgressPollerHandler[T any] struct{}

func (h *inProgressPollerHandler[T]) Done() bool { return false }

func (h *inProgressPollerHandler[T]) Poll(_ context.Context) (*http.Response, error) {
	return &http.Response{StatusCode: http.StatusAccepted}, nil
}

func (h *inProgressPollerHandler[T]) Result(_ context.Context, _ *T) error {
	return fmt.Errorf("operation not complete")
}

type fakeContainerRegistryAPI struct {
	beginCreateFn                 func(ctx context.Context, resourceGroupName string, registryName string, registry armcontainerregistry.Registry, options *armcontainerregistry.RegistriesClientBeginCreateOptions) (*runtime.Poller[armcontainerregistry.RegistriesClientCreateResponse], error)
	getFn                         func(ctx context.Context, resourceGroupName string, registryName string, options *armcontainerregistry.RegistriesClientGetOptions) (armcontainerregistry.RegistriesClientGetResponse, error)
	beginUpdateFn                 func(ctx context.Context, resourceGroupName string, registryName string, registryUpdateParameters armcontainerregistry.RegistryUpdateParameters, options *armcontainerregistry.RegistriesClientBeginUpdateOptions) (*runtime.Poller[armcontainerregistry.RegistriesClientUpdateResponse], error)
	beginDeleteFn                 func(ctx context.Context, resourceGroupName string, registryName string, options *armcontainerregistry.RegistriesClientBeginDeleteOptions) (*runtime.Poller[armcontainerregistry.RegistriesClientDeleteResponse], error)
	newListPagerFn                func(options *armcontainerregistry.RegistriesClientListOptions) *runtime.Pager[armcontainerregistry.RegistriesClientListResponse]
	newListByResourceGroupPagerFn func(resourceGroupName string, options *armcontainerregistry.RegistriesClientListByResourceGroupOptions) *runtime.Pager[armcontainerregistry.RegistriesClientListByResourceGroupResponse]
	resumeCreateFn                func(token string) (*runtime.Poller[armcontainerregistry.RegistriesClientCreateResponse], error)
	resumeUpdateFn                func(token string) (*runtime.Poller[armcontainerregistry.RegistriesClientUpdateResponse], error)
	resumeDeleteFn                func(token string) (*runtime.Poller[armcontainerregistry.RegistriesClientDeleteResponse], error)
}

func (f *fakeContainerRegistryAPI) BeginCreate(ctx context.Context, resourceGroupName string, registryName string, registry armcontainerregistry.Registry, options *armcontainerregistry.RegistriesClientBeginCreateOptions) (*runtime.Poller[armcontainerregistry.RegistriesClientCreateResponse], error) {
	return f.beginCreateFn(ctx, resourceGroupName, registryName, registry, options)
}

func (f *fakeContainerRegistryAPI) Get(ctx context.Context, resourceGroupName string, registryName string, options *armcontainerregistry.RegistriesClientGetOptions) (armcontainerregistry.RegistriesClientGetResponse, error) {
	return f.getFn(ctx, resourceGroupName, registryName, options)
}

func (f *fakeContainerRegistryAPI) BeginUpdate(ctx context.Context, resourceGroupName string, registryName string, registryUpdateParameters armcontainerregistry.RegistryUpdateParameters, options *armcontainerregistry.RegistriesClientBeginUpdateOptions) (*runtime.Poller[armcontainerregistry.RegistriesClientUpdateResponse], error) {
	return f.beginUpdateFn(ctx, resourceGroupName, registryName, registryUpdateParameters, options)
}

func (f *fakeContainerRegistryAPI) BeginDelete(ctx context.Context, resourceGroupName string, registryName string, options *armcontainerregistry.RegistriesClientBeginDeleteOptions) (*runtime.Poller[armcontainerregistry.RegistriesClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, resourceGroupName, registryName, options)
}

func (f *fakeContainerRegistryAPI) NewListPager(options *armcontainerregistry.RegistriesClientListOptions) *runtime.Pager[armcontainerregistry.RegistriesClientListResponse] {
	return f.newListPagerFn(options)
}

func (f *fakeContainerRegistryAPI) NewListByResourceGroupPager(resourceGroupName string, options *armcontainerregistry.RegistriesClientListByResourceGroupOptions) *runtime.Pager[armcontainerregistry.RegistriesClientListByResourceGroupResponse] {
	return f.newListByResourceGroupPagerFn(resourceGroupName, options)
}

func (f *fakeContainerRegistryAPI) ResumeCreatePoller(token string) (*runtime.Poller[armcontainerregistry.RegistriesClientCreateResponse], error) {
	return f.resumeCreateFn(token)
}

func (f *fakeContainerRegistryAPI) ResumeUpdatePoller(token string) (*runtime.Poller[armcontainerregistry.RegistriesClientUpdateResponse], error) {
	return f.resumeUpdateFn(token)
}

func (f *fakeContainerRegistryAPI) ResumeDeletePoller(token string) (*runtime.Poller[armcontainerregistry.RegistriesClientDeleteResponse], error) {
	return f.resumeDeleteFn(token)
}
