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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/servicebus/armservicebus"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testSBNamespaceNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.ServiceBus/namespaces/mynamespace"

func TestServiceBusNamespace_CRUD(t *testing.T) {
	skuStandard := armservicebus.SKUNameStandard
	skuPremium := armservicebus.SKUNamePremium
	tierStandard := armservicebus.SKUTierStandard

	fake := &fakeServiceBusNamespaceAPI{
		beginCreateOrUpdateFn: func(_ context.Context, _, _ string, _ armservicebus.SBNamespace, _ *armservicebus.NamespacesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armservicebus.NamespacesClientCreateOrUpdateResponse], error) {
			return newDonePoller(armservicebus.NamespacesClientCreateOrUpdateResponse{
				SBNamespace: armservicebus.SBNamespace{
					ID:       to.Ptr(testSBNamespaceNativeID),
					Name:     to.Ptr("mynamespace"),
					Location: to.Ptr("eastus"),
					SKU:      &armservicebus.SBSKU{Name: &skuStandard, Tier: &tierStandard},
				},
			}), nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armservicebus.NamespacesClientGetOptions) (armservicebus.NamespacesClientGetResponse, error) {
			return armservicebus.NamespacesClientGetResponse{
				SBNamespace: armservicebus.SBNamespace{
					ID:       to.Ptr(testSBNamespaceNativeID),
					Name:     to.Ptr("mynamespace"),
					Location: to.Ptr("eastus"),
					SKU:      &armservicebus.SBSKU{Name: &skuStandard, Tier: &tierStandard},
				},
			}, nil
		},
		updateFn: func(_ context.Context, _, _ string, _ armservicebus.SBNamespaceUpdateParameters, _ *armservicebus.NamespacesClientUpdateOptions) (armservicebus.NamespacesClientUpdateResponse, error) {
			return armservicebus.NamespacesClientUpdateResponse{
				SBNamespace: armservicebus.SBNamespace{
					ID:       to.Ptr(testSBNamespaceNativeID),
					Name:     to.Ptr("mynamespace"),
					Location: to.Ptr("eastus"),
					SKU:      &armservicebus.SBSKU{Name: &skuPremium},
				},
			}, nil
		},
		beginDeleteFn: func(_ context.Context, _, _ string, _ *armservicebus.NamespacesClientBeginDeleteOptions) (*runtime.Poller[armservicebus.NamespacesClientDeleteResponse], error) {
			return newDonePoller(armservicebus.NamespacesClientDeleteResponse{}), nil
		},
		newListByResourceGroupPagerFn: func(_ string, _ *armservicebus.NamespacesClientListByResourceGroupOptions) *runtime.Pager[armservicebus.NamespacesClientListByResourceGroupResponse] {
			return runtime.NewPager(runtime.PagingHandler[armservicebus.NamespacesClientListByResourceGroupResponse]{
				More: func(_ armservicebus.NamespacesClientListByResourceGroupResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armservicebus.NamespacesClientListByResourceGroupResponse) (armservicebus.NamespacesClientListByResourceGroupResponse, error) {
					return armservicebus.NamespacesClientListByResourceGroupResponse{
						SBNamespaceListResult: armservicebus.SBNamespaceListResult{
							Value: []*armservicebus.SBNamespace{
								{ID: to.Ptr(testSBNamespaceNativeID)},
								{ID: to.Ptr("/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.ServiceBus/namespaces/other")},
							},
						},
					}, nil
				},
			})
		},
		newListPagerFn: func(_ *armservicebus.NamespacesClientListOptions) *runtime.Pager[armservicebus.NamespacesClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armservicebus.NamespacesClientListResponse]{
				More: func(_ armservicebus.NamespacesClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armservicebus.NamespacesClientListResponse) (armservicebus.NamespacesClientListResponse, error) {
					return armservicebus.NamespacesClientListResponse{
						SBNamespaceListResult: armservicebus.SBNamespaceListResult{
							Value: []*armservicebus.SBNamespace{{ID: to.Ptr(testSBNamespaceNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestServiceBusNamespace(fake)

	t.Run("Create", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName": "rg-1", "name": "mynamespace",
			"location": "eastus", "sku": map[string]any{"name": "Standard"},
		})
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "mynamespace", Properties: props})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testSBNamespaceNativeID, got.ProgressResult.NativeID)
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testSBNamespaceNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "mynamespace", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "eastus", props["location"])
	})

	t.Run("Update_keeps_native_id", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName": "rg-1", "name": "mynamespace",
			"location": "eastus", "sku": map[string]any{"name": "Premium", "capacity": 1},
		})
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{NativeID: testSBNamespaceNativeID, DesiredProperties: props})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testSBNamespaceNativeID, got.ProgressResult.NativeID)
	})

	t.Run("Delete", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testSBNamespaceNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _ string, _ *armservicebus.NamespacesClientBeginDeleteOptions) (*runtime.Poller[armservicebus.NamespacesClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testSBNamespaceNativeID})
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
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, _ armservicebus.SBNamespace, _ *armservicebus.NamespacesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armservicebus.NamespacesClientCreateOrUpdateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 409}
		}
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName": "rg-1", "name": "mynamespace",
			"location": "eastus", "sku": map[string]any{"name": "Standard"},
		})
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

func newTestServiceBusNamespace(api serviceBusNamespacesAPI) *ServiceBusNamespace {
	return &ServiceBusNamespace{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

type fakeServiceBusNamespaceAPI struct {
	beginCreateOrUpdateFn         func(ctx context.Context, resourceGroupName string, namespaceName string, parameters armservicebus.SBNamespace, options *armservicebus.NamespacesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armservicebus.NamespacesClientCreateOrUpdateResponse], error)
	getFn                         func(ctx context.Context, resourceGroupName string, namespaceName string, options *armservicebus.NamespacesClientGetOptions) (armservicebus.NamespacesClientGetResponse, error)
	updateFn                      func(ctx context.Context, resourceGroupName string, namespaceName string, parameters armservicebus.SBNamespaceUpdateParameters, options *armservicebus.NamespacesClientUpdateOptions) (armservicebus.NamespacesClientUpdateResponse, error)
	beginDeleteFn                 func(ctx context.Context, resourceGroupName string, namespaceName string, options *armservicebus.NamespacesClientBeginDeleteOptions) (*runtime.Poller[armservicebus.NamespacesClientDeleteResponse], error)
	newListByResourceGroupPagerFn func(resourceGroupName string, options *armservicebus.NamespacesClientListByResourceGroupOptions) *runtime.Pager[armservicebus.NamespacesClientListByResourceGroupResponse]
	newListPagerFn                func(options *armservicebus.NamespacesClientListOptions) *runtime.Pager[armservicebus.NamespacesClientListResponse]
}

func (f *fakeServiceBusNamespaceAPI) BeginCreateOrUpdate(ctx context.Context, resourceGroupName string, namespaceName string, parameters armservicebus.SBNamespace, options *armservicebus.NamespacesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armservicebus.NamespacesClientCreateOrUpdateResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, resourceGroupName, namespaceName, parameters, options)
}

func (f *fakeServiceBusNamespaceAPI) Get(ctx context.Context, resourceGroupName string, namespaceName string, options *armservicebus.NamespacesClientGetOptions) (armservicebus.NamespacesClientGetResponse, error) {
	return f.getFn(ctx, resourceGroupName, namespaceName, options)
}

func (f *fakeServiceBusNamespaceAPI) Update(ctx context.Context, resourceGroupName string, namespaceName string, parameters armservicebus.SBNamespaceUpdateParameters, options *armservicebus.NamespacesClientUpdateOptions) (armservicebus.NamespacesClientUpdateResponse, error) {
	return f.updateFn(ctx, resourceGroupName, namespaceName, parameters, options)
}

func (f *fakeServiceBusNamespaceAPI) BeginDelete(ctx context.Context, resourceGroupName string, namespaceName string, options *armservicebus.NamespacesClientBeginDeleteOptions) (*runtime.Poller[armservicebus.NamespacesClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, resourceGroupName, namespaceName, options)
}

func (f *fakeServiceBusNamespaceAPI) NewListByResourceGroupPager(resourceGroupName string, options *armservicebus.NamespacesClientListByResourceGroupOptions) *runtime.Pager[armservicebus.NamespacesClientListByResourceGroupResponse] {
	return f.newListByResourceGroupPagerFn(resourceGroupName, options)
}

func (f *fakeServiceBusNamespaceAPI) NewListPager(options *armservicebus.NamespacesClientListOptions) *runtime.Pager[armservicebus.NamespacesClientListResponse] {
	return f.newListPagerFn(options)
}
