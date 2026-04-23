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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/keyvault/armkeyvault"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testKVNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.KeyVault/vaults/my-vault"

func TestKeyVault_CRUD(t *testing.T) {
	fake := &fakeVaultsAPI{
		beginCreateOrUpdateFn: func(_ context.Context, rgName, vaultName string, params armkeyvault.VaultCreateOrUpdateParameters, _ *armkeyvault.VaultsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armkeyvault.VaultsClientCreateOrUpdateResponse], error) {
			return newDonePoller(armkeyvault.VaultsClientCreateOrUpdateResponse{
				Vault: armkeyvault.Vault{
					ID:       to.Ptr(testKVNativeID),
					Name:     to.Ptr(vaultName),
					Location: params.Location,
					Properties: &armkeyvault.VaultProperties{
						TenantID: params.Properties.TenantID,
						SKU:      params.Properties.SKU,
						VaultURI: to.Ptr("https://my-vault.vault.azure.net/"),
						EnableRbacAuthorization: params.Properties.EnableRbacAuthorization,
						AccessPolicies:          params.Properties.AccessPolicies,
					},
				},
			}), nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armkeyvault.VaultsClientGetOptions) (armkeyvault.VaultsClientGetResponse, error) {
			return armkeyvault.VaultsClientGetResponse{
				Vault: armkeyvault.Vault{
					ID:       to.Ptr(testKVNativeID),
					Name:     to.Ptr("my-vault"),
					Location: to.Ptr("eastus"),
					Properties: &armkeyvault.VaultProperties{
						TenantID:               to.Ptr("tenant-1"),
						EnableRbacAuthorization: to.Ptr(true),
						EnableSoftDelete:        to.Ptr(true),
						SoftDeleteRetentionInDays: to.Ptr(int32(90)),
						SKU: &armkeyvault.SKU{
							Family: to.Ptr(armkeyvault.SKUFamilyA),
							Name:   to.Ptr(armkeyvault.SKUNameStandard),
						},
						VaultURI: to.Ptr("https://my-vault.vault.azure.net/"),
					},
				},
			}, nil
		},
		deleteFn: func(_ context.Context, _, _ string, _ *armkeyvault.VaultsClientDeleteOptions) (armkeyvault.VaultsClientDeleteResponse, error) {
			return armkeyvault.VaultsClientDeleteResponse{}, nil
		},
		listByResourceGroupFn: func(rgName string, _ *armkeyvault.VaultsClientListByResourceGroupOptions) *runtime.Pager[armkeyvault.VaultsClientListByResourceGroupResponse] {
			return runtime.NewPager(runtime.PagingHandler[armkeyvault.VaultsClientListByResourceGroupResponse]{
				More: func(_ armkeyvault.VaultsClientListByResourceGroupResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armkeyvault.VaultsClientListByResourceGroupResponse) (armkeyvault.VaultsClientListByResourceGroupResponse, error) {
					return armkeyvault.VaultsClientListByResourceGroupResponse{
						VaultListResult: armkeyvault.VaultListResult{
							Value: []*armkeyvault.Vault{
								{ID: to.Ptr(testKVNativeID)},
								{ID: to.Ptr("/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.KeyVault/vaults/other-vault")},
							},
						},
					}, nil
				},
			})
		},
		listBySubscriptionFn: func(_ *armkeyvault.VaultsClientListBySubscriptionOptions) *runtime.Pager[armkeyvault.VaultsClientListBySubscriptionResponse] {
			return runtime.NewPager(runtime.PagingHandler[armkeyvault.VaultsClientListBySubscriptionResponse]{
				More: func(_ armkeyvault.VaultsClientListBySubscriptionResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armkeyvault.VaultsClientListBySubscriptionResponse) (armkeyvault.VaultsClientListBySubscriptionResponse, error) {
					return armkeyvault.VaultsClientListBySubscriptionResponse{
						VaultListResult: armkeyvault.VaultListResult{
							Value: []*armkeyvault.Vault{{ID: to.Ptr(testKVNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestKeyVault(fake)

	t.Run("Create", func(t *testing.T) {
		props, _ := json.Marshal(map[string]interface{}{
			"resourceGroupName": "rg-1",
			"location":          "eastus",
			"name":              "my-vault",
			"tenantId":          "tenant-1",
			"sku":               map[string]interface{}{"name": "standard"},
		})
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "my-vault", Properties: props})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testKVNativeID, got.ProgressResult.NativeID)
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testKVNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var serialized map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &serialized))
		require.Equal(t, "my-vault", serialized["name"])
		require.Equal(t, "rg-1", serialized["resourceGroupName"])
		require.Equal(t, "eastus", serialized["location"])
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _ string, _ *armkeyvault.VaultsClientDeleteOptions) (armkeyvault.VaultsClientDeleteResponse, error) {
			return armkeyvault.VaultsClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testKVNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 2)
		require.Equal(t, testKVNativeID, got.NativeIDs[0])
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, _ armkeyvault.VaultCreateOrUpdateParameters, _ *armkeyvault.VaultsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armkeyvault.VaultsClientCreateOrUpdateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 403}
		}
		props, _ := json.Marshal(map[string]interface{}{
			"resourceGroupName": "rg-1",
			"location":          "eastus",
			"name":              "my-vault",
			"tenantId":          "tenant-1",
			"sku":               map[string]interface{}{"name": "standard"},
		})
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

// --- Test helpers ---

func newTestKeyVault(api vaultsAPI) *KeyVault {
	return &KeyVault{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

type fakeVaultsAPI struct {
	beginCreateOrUpdateFn func(ctx context.Context, resourceGroupName string, vaultName string, parameters armkeyvault.VaultCreateOrUpdateParameters, options *armkeyvault.VaultsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armkeyvault.VaultsClientCreateOrUpdateResponse], error)
	getFn                 func(ctx context.Context, resourceGroupName string, vaultName string, options *armkeyvault.VaultsClientGetOptions) (armkeyvault.VaultsClientGetResponse, error)
	deleteFn              func(ctx context.Context, resourceGroupName string, vaultName string, options *armkeyvault.VaultsClientDeleteOptions) (armkeyvault.VaultsClientDeleteResponse, error)
	listByResourceGroupFn func(resourceGroupName string, options *armkeyvault.VaultsClientListByResourceGroupOptions) *runtime.Pager[armkeyvault.VaultsClientListByResourceGroupResponse]
	listBySubscriptionFn  func(options *armkeyvault.VaultsClientListBySubscriptionOptions) *runtime.Pager[armkeyvault.VaultsClientListBySubscriptionResponse]
	resumeCreateFn        func(token string) (*runtime.Poller[armkeyvault.VaultsClientCreateOrUpdateResponse], error)
	resumeDeleteFn        func(token string) (*runtime.Poller[armkeyvault.VaultsClientPurgeDeletedResponse], error)
}

func (f *fakeVaultsAPI) BeginCreateOrUpdate(ctx context.Context, resourceGroupName string, vaultName string, parameters armkeyvault.VaultCreateOrUpdateParameters, options *armkeyvault.VaultsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armkeyvault.VaultsClientCreateOrUpdateResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, resourceGroupName, vaultName, parameters, options)
}

func (f *fakeVaultsAPI) Get(ctx context.Context, resourceGroupName string, vaultName string, options *armkeyvault.VaultsClientGetOptions) (armkeyvault.VaultsClientGetResponse, error) {
	return f.getFn(ctx, resourceGroupName, vaultName, options)
}

func (f *fakeVaultsAPI) Delete(ctx context.Context, resourceGroupName string, vaultName string, options *armkeyvault.VaultsClientDeleteOptions) (armkeyvault.VaultsClientDeleteResponse, error) {
	return f.deleteFn(ctx, resourceGroupName, vaultName, options)
}

func (f *fakeVaultsAPI) NewListByResourceGroupPager(resourceGroupName string, options *armkeyvault.VaultsClientListByResourceGroupOptions) *runtime.Pager[armkeyvault.VaultsClientListByResourceGroupResponse] {
	return f.listByResourceGroupFn(resourceGroupName, options)
}

func (f *fakeVaultsAPI) NewListBySubscriptionPager(options *armkeyvault.VaultsClientListBySubscriptionOptions) *runtime.Pager[armkeyvault.VaultsClientListBySubscriptionResponse] {
	return f.listBySubscriptionFn(options)
}

func (f *fakeVaultsAPI) ResumeCreatePoller(token string) (*runtime.Poller[armkeyvault.VaultsClientCreateOrUpdateResponse], error) {
	return f.resumeCreateFn(token)
}

func (f *fakeVaultsAPI) ResumeDeletePoller(token string) (*runtime.Poller[armkeyvault.VaultsClientPurgeDeletedResponse], error) {
	return f.resumeDeleteFn(token)
}
