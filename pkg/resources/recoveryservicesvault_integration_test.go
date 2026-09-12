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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/recoveryservices/armrecoveryservices"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testRecoveryServicesVaultNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.RecoveryServices/vaults/rsv-1"

func newTestRecoveryServicesVault(api recoveryServicesVaultsAPI) *RecoveryServicesVault {
	return &RecoveryServicesVault{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func recoveryServicesVaultDesired(alerts string) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":                    "rsv-1",
		"location":                "eastus",
		"resourceGroupName":       "rg-1",
		"skuName":                 "Standard",
		"softDeleteState":         "Disabled",
		"alertsForAllJobFailures": alerts,
	})
	return out
}

func TestRecoveryServicesVault_CRUD(t *testing.T) {
	vaultResult := armrecoveryservices.Vault{
		ID:       to.Ptr(testRecoveryServicesVaultNativeID),
		Name:     to.Ptr("rsv-1"),
		Location: to.Ptr("East US"),
		SKU:      &armrecoveryservices.SKU{Name: to.Ptr(armrecoveryservices.SKUNameStandard)},
		Properties: &armrecoveryservices.VaultProperties{
			ProvisioningState: to.Ptr("Succeeded"),
			SecuritySettings: &armrecoveryservices.SecuritySettings{
				SoftDeleteSettings: &armrecoveryservices.SoftDeleteSettings{
					SoftDeleteState: to.Ptr(armrecoveryservices.SoftDeleteStateDisabled),
				},
			},
			MonitoringSettings: &armrecoveryservices.MonitoringSettings{
				AzureMonitorAlertSettings: &armrecoveryservices.AzureMonitorAlertSettings{
					AlertsForAllJobFailures: to.Ptr(armrecoveryservices.AlertsStateEnabled),
				},
			},
			// Read-only on the ARM contract: reported, never sent.
			RedundancySettings: &armrecoveryservices.VaultPropertiesRedundancySettings{
				StandardTierStorageRedundancy: to.Ptr(armrecoveryservices.StandardTierStorageRedundancyGeoRedundant),
				CrossRegionRestore:            to.Ptr(armrecoveryservices.CrossRegionRestoreDisabled),
			},
		},
	}

	var sent armrecoveryservices.Vault
	fake := &fakeRecoveryServicesVaultsAPI{
		beginCreateOrUpdateFn: func(_ context.Context, rgName, name string, vault armrecoveryservices.Vault, _ *armrecoveryservices.VaultsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armrecoveryservices.VaultsClientCreateOrUpdateResponse], error) {
			require.Equal(t, "rg-1", rgName)
			require.Equal(t, "rsv-1", name)
			sent = vault
			return newDonePoller(armrecoveryservices.VaultsClientCreateOrUpdateResponse{Vault: vaultResult}), nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armrecoveryservices.VaultsClientGetOptions) (armrecoveryservices.VaultsClientGetResponse, error) {
			return armrecoveryservices.VaultsClientGetResponse{Vault: vaultResult}, nil
		},
		deleteFn: func(_ context.Context, _, _ string, _ *armrecoveryservices.VaultsClientDeleteOptions) (armrecoveryservices.VaultsClientDeleteResponse, error) {
			return armrecoveryservices.VaultsClientDeleteResponse{}, nil
		},
		newListBySubscriptionIDPagerFn: func(_ *armrecoveryservices.VaultsClientListBySubscriptionIDOptions) *runtime.Pager[armrecoveryservices.VaultsClientListBySubscriptionIDResponse] {
			return runtime.NewPager(runtime.PagingHandler[armrecoveryservices.VaultsClientListBySubscriptionIDResponse]{
				More: func(_ armrecoveryservices.VaultsClientListBySubscriptionIDResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armrecoveryservices.VaultsClientListBySubscriptionIDResponse) (armrecoveryservices.VaultsClientListBySubscriptionIDResponse, error) {
					return armrecoveryservices.VaultsClientListBySubscriptionIDResponse{
						VaultList: armrecoveryservices.VaultList{
							Value: []*armrecoveryservices.Vault{
								{ID: to.Ptr(testRecoveryServicesVaultNativeID)},
								{ID: to.Ptr("/subscriptions/sub-1/resourceGroups/rg-2/providers/Microsoft.RecoveryServices/vaults/rsv-2")},
							},
						},
					}, nil
				},
			})
		},
		newListByResourceGroupPagerFn: func(_ string, _ *armrecoveryservices.VaultsClientListByResourceGroupOptions) *runtime.Pager[armrecoveryservices.VaultsClientListByResourceGroupResponse] {
			return runtime.NewPager(runtime.PagingHandler[armrecoveryservices.VaultsClientListByResourceGroupResponse]{
				More: func(_ armrecoveryservices.VaultsClientListByResourceGroupResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armrecoveryservices.VaultsClientListByResourceGroupResponse) (armrecoveryservices.VaultsClientListByResourceGroupResponse, error) {
					return armrecoveryservices.VaultsClientListByResourceGroupResponse{
						VaultList: armrecoveryservices.VaultList{
							Value: []*armrecoveryservices.Vault{{ID: to.Ptr(testRecoveryServicesVaultNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestRecoveryServicesVault(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "rsv-1",
			Properties: recoveryServicesVaultDesired("Enabled"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testRecoveryServicesVaultNativeID, got.ProgressResult.NativeID)

		require.Equal(t, armrecoveryservices.SKUNameStandard, *sent.SKU.Name)
		require.Equal(t, armrecoveryservices.SoftDeleteStateDisabled, *sent.Properties.SecuritySettings.SoftDeleteSettings.SoftDeleteState)
		require.Equal(t, armrecoveryservices.AlertsStateEnabled, *sent.Properties.MonitoringSettings.AzureMonitorAlertSettings.AlertsForAllJobFailures)
		// redundancySettings is read-only; the request must never carry it.
		require.Nil(t, sent.Properties.RedundancySettings)
	})

	t.Run("Create_requires_sku", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "rsv-1", "location": "eastus", "resourceGroupName": "rg-1"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "skuName is required")
	})

	t.Run("Create_requires_location", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "rsv-1", "resourceGroupName": "rg-1", "skuName": "Standard"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "location is required")
	})

	t.Run("Create_omits_untouched_settings", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "rsv-1", "location": "eastus", "resourceGroupName": "rg-1", "skuName": "Standard",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "rsv-1", Properties: props})
		require.NoError(t, err)
		require.Nil(t, sent.Properties.SecuritySettings)
		require.Nil(t, sent.Properties.MonitoringSettings)
		require.Nil(t, sent.Properties.RestoreSettings)
		require.Nil(t, sent.SKU.Tier)
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testRecoveryServicesVaultNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "rsv-1", props["name"])
		// ARM answers "East US"; desired state spells it "eastus".
		require.Equal(t, "eastus", props["location"])
		require.Equal(t, "Standard", props["skuName"])
		require.Equal(t, "Disabled", props["softDeleteState"])
		require.Equal(t, "Enabled", props["alertsForAllJobFailures"])
		require.Equal(t, "GeoRedundant", props["standardTierStorageRedundancy"])
		require.Equal(t, "Succeeded", props["provisioningState"])
		require.NotContains(t, props, "skuTier")
	})

	// Update goes back through PUT, not PATCH, so the whole desired vault is sent.
	t.Run("Update_uses_create_or_update", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testRecoveryServicesVaultNativeID,
			DesiredProperties: recoveryServicesVaultDesired("Disabled"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testRecoveryServicesVaultNativeID, got.ProgressResult.NativeID)
		require.Equal(t, armrecoveryservices.AlertsStateDisabled, *sent.Properties.MonitoringSettings.AzureMonitorAlertSettings.AlertsForAllJobFailures)
	})

	t.Run("Delete", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testRecoveryServicesVaultNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _ string, _ *armrecoveryservices.VaultsClientDeleteOptions) (armrecoveryservices.VaultsClientDeleteResponse, error) {
			return armrecoveryservices.VaultsClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testRecoveryServicesVaultNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	// A vault with a registered container cannot be deleted; the reason has to
	// reach StatusMessage or it is lost.
	t.Run("Delete_conflict_reports_reason", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _ string, _ *armrecoveryservices.VaultsClientDeleteOptions) (armrecoveryservices.VaultsClientDeleteResponse, error) {
			return armrecoveryservices.VaultsClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 409, ErrorCode: "VaultCannotBeDeletedAsThereAreBackupItemsFoundInVault"}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testRecoveryServicesVaultNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.Contains(t, got.ProgressResult.StatusMessage, "VaultCannotBeDeletedAsThereAreBackupItemsFoundInVault")
	})

	t.Run("List_by_resource_group", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testRecoveryServicesVaultNativeID}, got.NativeIDs)
	})

	t.Run("List_without_group_is_subscription_wide", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 2)
	})

	t.Run("Azure_error_maps_to_failure_with_message", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, _ armrecoveryservices.Vault, _ *armrecoveryservices.VaultsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armrecoveryservices.VaultsClientCreateOrUpdateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 409, ErrorCode: "VaultAlreadyExists"}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "rsv-1", Properties: recoveryServicesVaultDesired("Enabled")})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.Equal(t, resource.OperationErrorCodeResourceConflict, got.ProgressResult.ErrorCode)
		require.Contains(t, got.ProgressResult.StatusMessage, "VaultAlreadyExists")
	})
}

func TestRecoveryServicesVault_ReadNotFound(t *testing.T) {
	fake := &fakeRecoveryServicesVaultsAPI{
		getFn: func(_ context.Context, _, _ string, _ *armrecoveryservices.VaultsClientGetOptions) (armrecoveryservices.VaultsClientGetResponse, error) {
			return armrecoveryservices.VaultsClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestRecoveryServicesVault(fake).Read(context.Background(), &resource.ReadRequest{NativeID: testRecoveryServicesVaultNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

func TestRecoveryServicesVault_CreateInProgress(t *testing.T) {
	fake := &fakeRecoveryServicesVaultsAPI{
		beginCreateOrUpdateFn: func(_ context.Context, _, _ string, _ armrecoveryservices.Vault, _ *armrecoveryservices.VaultsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armrecoveryservices.VaultsClientCreateOrUpdateResponse], error) {
			return newInProgressPoller[armrecoveryservices.VaultsClientCreateOrUpdateResponse](), nil
		},
	}
	got, err := newTestRecoveryServicesVault(fake).Create(context.Background(), &resource.CreateRequest{
		Label:      "rsv-1",
		Properties: recoveryServicesVaultDesired("Enabled"),
	})
	require.NoError(t, err)
	require.Equal(t, resource.OperationStatusInProgress, got.ProgressResult.OperationStatus)
	require.Equal(t, testRecoveryServicesVaultNativeID, got.ProgressResult.NativeID)

	reqID, err := decodeLROStatus(got.ProgressResult.RequestID)
	require.NoError(t, err)
	require.Equal(t, lroOpCreate, reqID.OperationType)
	require.NotEmpty(t, reqID.ResumeToken)
}

// --- Test helpers ---

type fakeRecoveryServicesVaultsAPI struct {
	beginCreateOrUpdateFn          func(ctx context.Context, rgName, name string, vault armrecoveryservices.Vault, options *armrecoveryservices.VaultsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armrecoveryservices.VaultsClientCreateOrUpdateResponse], error)
	getFn                          func(ctx context.Context, rgName, name string, options *armrecoveryservices.VaultsClientGetOptions) (armrecoveryservices.VaultsClientGetResponse, error)
	deleteFn                       func(ctx context.Context, rgName, name string, options *armrecoveryservices.VaultsClientDeleteOptions) (armrecoveryservices.VaultsClientDeleteResponse, error)
	newListBySubscriptionIDPagerFn func(options *armrecoveryservices.VaultsClientListBySubscriptionIDOptions) *runtime.Pager[armrecoveryservices.VaultsClientListBySubscriptionIDResponse]
	newListByResourceGroupPagerFn  func(rgName string, options *armrecoveryservices.VaultsClientListByResourceGroupOptions) *runtime.Pager[armrecoveryservices.VaultsClientListByResourceGroupResponse]
}

func (f *fakeRecoveryServicesVaultsAPI) BeginCreateOrUpdate(ctx context.Context, rgName, name string, vault armrecoveryservices.Vault, options *armrecoveryservices.VaultsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armrecoveryservices.VaultsClientCreateOrUpdateResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, rgName, name, vault, options)
}

func (f *fakeRecoveryServicesVaultsAPI) Get(ctx context.Context, rgName, name string, options *armrecoveryservices.VaultsClientGetOptions) (armrecoveryservices.VaultsClientGetResponse, error) {
	return f.getFn(ctx, rgName, name, options)
}

func (f *fakeRecoveryServicesVaultsAPI) Delete(ctx context.Context, rgName, name string, options *armrecoveryservices.VaultsClientDeleteOptions) (armrecoveryservices.VaultsClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, name, options)
}

func (f *fakeRecoveryServicesVaultsAPI) NewListBySubscriptionIDPager(options *armrecoveryservices.VaultsClientListBySubscriptionIDOptions) *runtime.Pager[armrecoveryservices.VaultsClientListBySubscriptionIDResponse] {
	return f.newListBySubscriptionIDPagerFn(options)
}

func (f *fakeRecoveryServicesVaultsAPI) NewListByResourceGroupPager(rgName string, options *armrecoveryservices.VaultsClientListByResourceGroupOptions) *runtime.Pager[armrecoveryservices.VaultsClientListByResourceGroupResponse] {
	return f.newListByResourceGroupPagerFn(rgName, options)
}
