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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testSANativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Storage/storageAccounts/myaccount"

func TestStorageAccount_CRUD(t *testing.T) {
	skuName := armstorage.SKUNameStandardLRS
	kind := armstorage.KindStorageV2
	fake := &fakeStorageAccountsAPI{
		beginCreateFn: func(_ context.Context, _, _ string, _ armstorage.AccountCreateParameters, _ *armstorage.AccountsClientBeginCreateOptions) (*runtime.Poller[armstorage.AccountsClientCreateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 200, ErrorCode: "FakePollerNotNeeded"}
		},
		getPropertiesFn: func(_ context.Context, _, _ string, _ *armstorage.AccountsClientGetPropertiesOptions) (armstorage.AccountsClientGetPropertiesResponse, error) {
			return armstorage.AccountsClientGetPropertiesResponse{
				Account: armstorage.Account{
					ID:       to.Ptr(testSANativeID),
					Name:     to.Ptr("myaccount"),
					Location: to.Ptr("eastus"),
					Kind:     &kind,
					SKU:      &armstorage.SKU{Name: &skuName},
					Properties: &armstorage.AccountProperties{
						EnableHTTPSTrafficOnly: to.Ptr(true),
					},
				},
			}, nil
		},
		updateFn: func(_ context.Context, _, _ string, _ armstorage.AccountUpdateParameters, _ *armstorage.AccountsClientUpdateOptions) (armstorage.AccountsClientUpdateResponse, error) {
			return armstorage.AccountsClientUpdateResponse{
				Account: armstorage.Account{
					ID:       to.Ptr(testSANativeID),
					Name:     to.Ptr("myaccount"),
					Location: to.Ptr("eastus"),
					Properties: &armstorage.AccountProperties{
						EnableHTTPSTrafficOnly: to.Ptr(true),
					},
				},
			}, nil
		},
		deleteFn: func(_ context.Context, _, _ string, _ *armstorage.AccountsClientDeleteOptions) (armstorage.AccountsClientDeleteResponse, error) {
			return armstorage.AccountsClientDeleteResponse{}, nil
		},
		newListByResourceGroupPagerFn: func(_ string, _ *armstorage.AccountsClientListByResourceGroupOptions) *runtime.Pager[armstorage.AccountsClientListByResourceGroupResponse] {
			return runtime.NewPager(runtime.PagingHandler[armstorage.AccountsClientListByResourceGroupResponse]{
				More: func(_ armstorage.AccountsClientListByResourceGroupResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armstorage.AccountsClientListByResourceGroupResponse) (armstorage.AccountsClientListByResourceGroupResponse, error) {
					return armstorage.AccountsClientListByResourceGroupResponse{
						AccountListResult: armstorage.AccountListResult{
							Value: []*armstorage.Account{
								{ID: to.Ptr(testSANativeID)},
								{ID: to.Ptr("/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Storage/storageAccounts/otheraccount")},
							},
						},
					}, nil
				},
			})
		},
		newListPagerFn: func(_ *armstorage.AccountsClientListOptions) *runtime.Pager[armstorage.AccountsClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armstorage.AccountsClientListResponse]{
				More: func(_ armstorage.AccountsClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armstorage.AccountsClientListResponse) (armstorage.AccountsClientListResponse, error) {
					return armstorage.AccountsClientListResponse{
						AccountListResult: armstorage.AccountListResult{
							Value: []*armstorage.Account{
								{ID: to.Ptr(testSANativeID)},
							},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestStorageAccount(fake)

	t.Run("Create", func(t *testing.T) {
		props, _ := json.Marshal(map[string]interface{}{
			"resourceGroupName": "rg-1",
			"location":          "eastus",
			"name":              "myaccount",
			"sku":               map[string]interface{}{"name": "Standard_LRS"},
			"kind":              "StorageV2",
		})
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "test-sa", Properties: props})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testSANativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
		var props map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "myaccount", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "eastus", props["location"])
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _ string, _ *armstorage.AccountsClientDeleteOptions) (armstorage.AccountsClientDeleteResponse, error) {
			return armstorage.AccountsClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testSANativeID})
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
		fake.beginCreateFn = func(_ context.Context, _, _ string, _ armstorage.AccountCreateParameters, _ *armstorage.AccountsClientBeginCreateOptions) (*runtime.Poller[armstorage.AccountsClientCreateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		props, _ := json.Marshal(map[string]interface{}{
			"resourceGroupName": "rg-1",
			"location":          "eastus",
			"name":              "myaccount",
			"sku":               map[string]interface{}{"name": "Standard_LRS"},
			"kind":              "StorageV2",
		})
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "test-sa",
			Properties: props,
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

// --- Test helpers ---

func newTestStorageAccount(api storageAccountsAPI) *StorageAccount {
	return &StorageAccount{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

type fakeStorageAccountsAPI struct {
	beginCreateFn                 func(ctx context.Context, resourceGroupName string, accountName string, parameters armstorage.AccountCreateParameters, options *armstorage.AccountsClientBeginCreateOptions) (*runtime.Poller[armstorage.AccountsClientCreateResponse], error)
	getPropertiesFn               func(ctx context.Context, resourceGroupName string, accountName string, options *armstorage.AccountsClientGetPropertiesOptions) (armstorage.AccountsClientGetPropertiesResponse, error)
	updateFn                      func(ctx context.Context, resourceGroupName string, accountName string, parameters armstorage.AccountUpdateParameters, options *armstorage.AccountsClientUpdateOptions) (armstorage.AccountsClientUpdateResponse, error)
	deleteFn                      func(ctx context.Context, resourceGroupName string, accountName string, options *armstorage.AccountsClientDeleteOptions) (armstorage.AccountsClientDeleteResponse, error)
	newListByResourceGroupPagerFn func(resourceGroupName string, options *armstorage.AccountsClientListByResourceGroupOptions) *runtime.Pager[armstorage.AccountsClientListByResourceGroupResponse]
	newListPagerFn                func(options *armstorage.AccountsClientListOptions) *runtime.Pager[armstorage.AccountsClientListResponse]
	resumeCreatePollerFn          func(token string) (*runtime.Poller[armstorage.AccountsClientCreateResponse], error)
}

func (f *fakeStorageAccountsAPI) BeginCreate(ctx context.Context, resourceGroupName string, accountName string, parameters armstorage.AccountCreateParameters, options *armstorage.AccountsClientBeginCreateOptions) (*runtime.Poller[armstorage.AccountsClientCreateResponse], error) {
	return f.beginCreateFn(ctx, resourceGroupName, accountName, parameters, options)
}

func (f *fakeStorageAccountsAPI) GetProperties(ctx context.Context, resourceGroupName string, accountName string, options *armstorage.AccountsClientGetPropertiesOptions) (armstorage.AccountsClientGetPropertiesResponse, error) {
	return f.getPropertiesFn(ctx, resourceGroupName, accountName, options)
}

func (f *fakeStorageAccountsAPI) Update(ctx context.Context, resourceGroupName string, accountName string, parameters armstorage.AccountUpdateParameters, options *armstorage.AccountsClientUpdateOptions) (armstorage.AccountsClientUpdateResponse, error) {
	return f.updateFn(ctx, resourceGroupName, accountName, parameters, options)
}

func (f *fakeStorageAccountsAPI) Delete(ctx context.Context, resourceGroupName string, accountName string, options *armstorage.AccountsClientDeleteOptions) (armstorage.AccountsClientDeleteResponse, error) {
	return f.deleteFn(ctx, resourceGroupName, accountName, options)
}

func (f *fakeStorageAccountsAPI) NewListByResourceGroupPager(resourceGroupName string, options *armstorage.AccountsClientListByResourceGroupOptions) *runtime.Pager[armstorage.AccountsClientListByResourceGroupResponse] {
	return f.newListByResourceGroupPagerFn(resourceGroupName, options)
}

func (f *fakeStorageAccountsAPI) NewListPager(options *armstorage.AccountsClientListOptions) *runtime.Pager[armstorage.AccountsClientListResponse] {
	return f.newListPagerFn(options)
}

func (f *fakeStorageAccountsAPI) ResumeCreatePoller(token string) (*runtime.Poller[armstorage.AccountsClientCreateResponse], error) {
	return f.resumeCreatePollerFn(token)
}
