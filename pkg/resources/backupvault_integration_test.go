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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/dataprotection/armdataprotection/v3"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testBackupVaultNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.DataProtection/backupVaults/bv-1"

func newTestBackupVault(api backupVaultsAPI) *BackupVault {
	return &BackupVault{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func backupVaultDesired(redundancy string, retentionDays float64) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":              "bv-1",
		"location":          "eastus",
		"resourceGroupName": "rg-1",
		"storageSettings": []map[string]any{
			{"datastoreType": "VaultStore", "type": redundancy},
		},
		"softDeleteState":         "Off",
		"softDeleteRetentionDays": retentionDays,
	})
	return out
}

func TestBackupVault_CRUD(t *testing.T) {
	vaultResult := armdataprotection.BackupVaultResource{
		ID:       to.Ptr(testBackupVaultNativeID),
		Name:     to.Ptr("bv-1"),
		Location: to.Ptr("East US"),
		Properties: &armdataprotection.BackupVault{
			StorageSettings: []*armdataprotection.StorageSetting{{
				DatastoreType: to.Ptr(armdataprotection.StorageSettingStoreTypesVaultStore),
				Type:          to.Ptr(armdataprotection.StorageSettingTypesLocallyRedundant),
			}},
			SecuritySettings: &armdataprotection.SecuritySettings{
				SoftDeleteSettings: &armdataprotection.SoftDeleteSettings{
					State:                   to.Ptr(armdataprotection.SoftDeleteStateOff),
					RetentionDurationInDays: to.Ptr(float64(14)),
				},
			},
		},
	}

	var sentCreate armdataprotection.BackupVaultResource
	var sentPatch armdataprotection.PatchResourceRequestInput
	fake := &fakeBackupVaultsAPI{
		beginCreateOrUpdateFn: func(_ context.Context, _, name string, params armdataprotection.BackupVaultResource, _ *armdataprotection.BackupVaultsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armdataprotection.BackupVaultsClientCreateOrUpdateResponse], error) {
			require.Equal(t, "bv-1", name)
			sentCreate = params
			return newDonePoller(armdataprotection.BackupVaultsClientCreateOrUpdateResponse{BackupVaultResource: vaultResult}), nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armdataprotection.BackupVaultsClientGetOptions) (armdataprotection.BackupVaultsClientGetResponse, error) {
			return armdataprotection.BackupVaultsClientGetResponse{BackupVaultResource: vaultResult}, nil
		},
		beginUpdateFn: func(_ context.Context, _, _ string, params armdataprotection.PatchResourceRequestInput, _ *armdataprotection.BackupVaultsClientBeginUpdateOptions) (*runtime.Poller[armdataprotection.BackupVaultsClientUpdateResponse], error) {
			sentPatch = params
			return newDonePoller(armdataprotection.BackupVaultsClientUpdateResponse{BackupVaultResource: vaultResult}), nil
		},
		beginDeleteFn: func(_ context.Context, _, _ string, _ *armdataprotection.BackupVaultsClientBeginDeleteOptions) (*runtime.Poller[armdataprotection.BackupVaultsClientDeleteResponse], error) {
			return newDonePoller(armdataprotection.BackupVaultsClientDeleteResponse{}), nil
		},
		newGetInSubscriptionPagerFn: func(_ *armdataprotection.BackupVaultsClientGetInSubscriptionOptions) *runtime.Pager[armdataprotection.BackupVaultsClientGetInSubscriptionResponse] {
			return runtime.NewPager(runtime.PagingHandler[armdataprotection.BackupVaultsClientGetInSubscriptionResponse]{
				More: func(_ armdataprotection.BackupVaultsClientGetInSubscriptionResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armdataprotection.BackupVaultsClientGetInSubscriptionResponse) (armdataprotection.BackupVaultsClientGetInSubscriptionResponse, error) {
					return armdataprotection.BackupVaultsClientGetInSubscriptionResponse{
						BackupVaultResourceList: armdataprotection.BackupVaultResourceList{
							Value: []*armdataprotection.BackupVaultResource{
								{ID: to.Ptr(testBackupVaultNativeID)},
								{ID: to.Ptr("/subscriptions/sub-1/resourceGroups/rg-2/providers/Microsoft.DataProtection/backupVaults/bv-2")},
							},
						},
					}, nil
				},
			})
		},
		newGetInResourceGroupPagerFn: func(_ string, _ *armdataprotection.BackupVaultsClientGetInResourceGroupOptions) *runtime.Pager[armdataprotection.BackupVaultsClientGetInResourceGroupResponse] {
			return runtime.NewPager(runtime.PagingHandler[armdataprotection.BackupVaultsClientGetInResourceGroupResponse]{
				More: func(_ armdataprotection.BackupVaultsClientGetInResourceGroupResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armdataprotection.BackupVaultsClientGetInResourceGroupResponse) (armdataprotection.BackupVaultsClientGetInResourceGroupResponse, error) {
					return armdataprotection.BackupVaultsClientGetInResourceGroupResponse{
						BackupVaultResourceList: armdataprotection.BackupVaultResourceList{
							Value: []*armdataprotection.BackupVaultResource{{ID: to.Ptr(testBackupVaultNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestBackupVault(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "bv-1", Properties: backupVaultDesired("LocallyRedundant", 14)})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testBackupVaultNativeID, got.ProgressResult.NativeID)

		require.Len(t, sentCreate.Properties.StorageSettings, 1)
		require.Equal(t, armdataprotection.StorageSettingStoreTypesVaultStore, *sentCreate.Properties.StorageSettings[0].DatastoreType)
		require.Equal(t, armdataprotection.StorageSettingTypesLocallyRedundant, *sentCreate.Properties.StorageSettings[0].Type)
		require.Equal(t, armdataprotection.SoftDeleteStateOff, *sentCreate.Properties.SecuritySettings.SoftDeleteSettings.State)
	})

	t.Run("Create_requires_a_storageSetting", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "bv-1", "location": "eastus", "resourceGroupName": "rg-1",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "at least one storageSetting")
	})

	t.Run("Create_requires_location", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "bv-1", "resourceGroupName": "rg-1",
			"storageSettings": []map[string]any{{"datastoreType": "VaultStore", "type": "LocallyRedundant"}},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "location is required")
	})

	// Omitting soft-delete entirely must leave securitySettings nil rather than
	// sending an empty block ARM would reject.
	t.Run("Create_omits_empty_security_settings", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "bv-1", "location": "eastus", "resourceGroupName": "rg-1",
			"storageSettings": []map[string]any{{"datastoreType": "VaultStore", "type": "LocallyRedundant"}},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "bv-1", Properties: props})
		require.NoError(t, err)
		require.Nil(t, sentCreate.Properties.SecuritySettings)
		require.Nil(t, sentCreate.Properties.FeatureSettings)
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testBackupVaultNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "bv-1", props["name"])
		require.Equal(t, "eastus", props["location"])
		require.Equal(t, "Off", props["softDeleteState"])
		require.EqualValues(t, 14, props["softDeleteRetentionDays"])
		settings := props["storageSettings"].([]any)
		require.Len(t, settings, 1)
		require.Equal(t, "VaultStore", settings[0].(map[string]any)["datastoreType"])
	})

	// ARM's PatchBackupVaultInput cannot carry storageSettings, so the update body
	// must not attempt to send it.
	t.Run("Update_patches_only_settings", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testBackupVaultNativeID,
			DesiredProperties: backupVaultDesired("LocallyRedundant", 30),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testBackupVaultNativeID, got.ProgressResult.NativeID)
		require.EqualValues(t, 30, *sentPatch.Properties.SecuritySettings.SoftDeleteSettings.RetentionDurationInDays)
	})

	t.Run("Delete", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testBackupVaultNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _ string, _ *armdataprotection.BackupVaultsClientBeginDeleteOptions) (*runtime.Poller[armdataprotection.BackupVaultsClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testBackupVaultNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_resource_group", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testBackupVaultNativeID}, got.NativeIDs)
	})

	t.Run("List_without_group_is_subscription_wide", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 2)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, _ armdataprotection.BackupVaultResource, _ *armdataprotection.BackupVaultsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armdataprotection.BackupVaultsClientCreateOrUpdateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 409}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "bv-1", Properties: backupVaultDesired("LocallyRedundant", 14)})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

func TestBackupVault_ReadNotFound(t *testing.T) {
	fake := &fakeBackupVaultsAPI{
		getFn: func(_ context.Context, _, _ string, _ *armdataprotection.BackupVaultsClientGetOptions) (armdataprotection.BackupVaultsClientGetResponse, error) {
			return armdataprotection.BackupVaultsClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestBackupVault(fake).Read(context.Background(), &resource.ReadRequest{NativeID: testBackupVaultNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeBackupVaultsAPI struct {
	beginCreateOrUpdateFn        func(ctx context.Context, rgName, name string, params armdataprotection.BackupVaultResource, options *armdataprotection.BackupVaultsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armdataprotection.BackupVaultsClientCreateOrUpdateResponse], error)
	getFn                        func(ctx context.Context, rgName, name string, options *armdataprotection.BackupVaultsClientGetOptions) (armdataprotection.BackupVaultsClientGetResponse, error)
	beginUpdateFn                func(ctx context.Context, rgName, name string, params armdataprotection.PatchResourceRequestInput, options *armdataprotection.BackupVaultsClientBeginUpdateOptions) (*runtime.Poller[armdataprotection.BackupVaultsClientUpdateResponse], error)
	beginDeleteFn                func(ctx context.Context, rgName, name string, options *armdataprotection.BackupVaultsClientBeginDeleteOptions) (*runtime.Poller[armdataprotection.BackupVaultsClientDeleteResponse], error)
	newGetInSubscriptionPagerFn  func(options *armdataprotection.BackupVaultsClientGetInSubscriptionOptions) *runtime.Pager[armdataprotection.BackupVaultsClientGetInSubscriptionResponse]
	newGetInResourceGroupPagerFn func(rgName string, options *armdataprotection.BackupVaultsClientGetInResourceGroupOptions) *runtime.Pager[armdataprotection.BackupVaultsClientGetInResourceGroupResponse]
}

func (f *fakeBackupVaultsAPI) BeginCreateOrUpdate(ctx context.Context, rgName, name string, params armdataprotection.BackupVaultResource, options *armdataprotection.BackupVaultsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armdataprotection.BackupVaultsClientCreateOrUpdateResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, rgName, name, params, options)
}

func (f *fakeBackupVaultsAPI) Get(ctx context.Context, rgName, name string, options *armdataprotection.BackupVaultsClientGetOptions) (armdataprotection.BackupVaultsClientGetResponse, error) {
	return f.getFn(ctx, rgName, name, options)
}

func (f *fakeBackupVaultsAPI) BeginUpdate(ctx context.Context, rgName, name string, params armdataprotection.PatchResourceRequestInput, options *armdataprotection.BackupVaultsClientBeginUpdateOptions) (*runtime.Poller[armdataprotection.BackupVaultsClientUpdateResponse], error) {
	return f.beginUpdateFn(ctx, rgName, name, params, options)
}

func (f *fakeBackupVaultsAPI) BeginDelete(ctx context.Context, rgName, name string, options *armdataprotection.BackupVaultsClientBeginDeleteOptions) (*runtime.Poller[armdataprotection.BackupVaultsClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, name, options)
}

func (f *fakeBackupVaultsAPI) NewGetInSubscriptionPager(options *armdataprotection.BackupVaultsClientGetInSubscriptionOptions) *runtime.Pager[armdataprotection.BackupVaultsClientGetInSubscriptionResponse] {
	return f.newGetInSubscriptionPagerFn(options)
}

func (f *fakeBackupVaultsAPI) NewGetInResourceGroupPager(rgName string, options *armdataprotection.BackupVaultsClientGetInResourceGroupOptions) *runtime.Pager[armdataprotection.BackupVaultsClientGetInResourceGroupResponse] {
	return f.newGetInResourceGroupPagerFn(rgName, options)
}
