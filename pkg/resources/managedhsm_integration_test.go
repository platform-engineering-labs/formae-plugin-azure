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

const (
	testManagedHsmNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.KeyVault/managedHSMs/hsm-1"
	testManagedHsmTenantID = "35412a0c-6726-4fc9-98ef-6e91adcb8d0e"
	testManagedHsmAdminID  = "11111111-2222-3333-4444-555555555555"
)

func newTestManagedHsm(api managedHsmsAPI) *ManagedHsm {
	return &ManagedHsm{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

func managedHsmModel(tags map[string]*string) armkeyvault.ManagedHsm {
	return armkeyvault.ManagedHsm{
		ID:   to.Ptr(testManagedHsmNativeID),
		Name: to.Ptr("hsm-1"),
		// ARM echoes the display form of the region; the plugin folds it back.
		Location: to.Ptr("East US"),
		SKU: &armkeyvault.ManagedHsmSKU{
			Family: to.Ptr(armkeyvault.ManagedHsmSKUFamilyB),
			Name:   to.Ptr(armkeyvault.ManagedHsmSKUNameStandardB1),
		},
		Properties: &armkeyvault.ManagedHsmProperties{
			TenantID:                  to.Ptr(testManagedHsmTenantID),
			InitialAdminObjectIDs:     []*string{to.Ptr(testManagedHsmAdminID)},
			EnableSoftDelete:          to.Ptr(true),
			SoftDeleteRetentionInDays: to.Ptr(int32(7)),
			EnablePurgeProtection:     to.Ptr(false),
			PublicNetworkAccess:       to.Ptr(armkeyvault.PublicNetworkAccessEnabled),
			HsmURI:                    to.Ptr("https://hsm-1.managedhsm.azure.net/"),
		},
		Tags: tags,
	}
}

func TestManagedHsm_CRUD(t *testing.T) {
	model := managedHsmModel(map[string]*string{"Environment": to.Ptr("test")})

	fake := &fakeManagedHsmsAPI{
		beginCreateOrUpdateFn: func(_ context.Context, _, _ string, _ armkeyvault.ManagedHsm, _ *armkeyvault.ManagedHsmsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armkeyvault.ManagedHsmsClientCreateOrUpdateResponse], error) {
			return newDonePoller(armkeyvault.ManagedHsmsClientCreateOrUpdateResponse{ManagedHsm: model}), nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armkeyvault.ManagedHsmsClientGetOptions) (armkeyvault.ManagedHsmsClientGetResponse, error) {
			return armkeyvault.ManagedHsmsClientGetResponse{ManagedHsm: model}, nil
		},
		beginDeleteFn: func(_ context.Context, _, _ string, _ *armkeyvault.ManagedHsmsClientBeginDeleteOptions) (*runtime.Poller[armkeyvault.ManagedHsmsClientDeleteResponse], error) {
			return newInProgressPoller[armkeyvault.ManagedHsmsClientDeleteResponse](), nil
		},
		newListByResourceGroupPagerFn: func(_ string, _ *armkeyvault.ManagedHsmsClientListByResourceGroupOptions) *runtime.Pager[armkeyvault.ManagedHsmsClientListByResourceGroupResponse] {
			return runtime.NewPager(runtime.PagingHandler[armkeyvault.ManagedHsmsClientListByResourceGroupResponse]{
				More: func(_ armkeyvault.ManagedHsmsClientListByResourceGroupResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armkeyvault.ManagedHsmsClientListByResourceGroupResponse) (armkeyvault.ManagedHsmsClientListByResourceGroupResponse, error) {
					return armkeyvault.ManagedHsmsClientListByResourceGroupResponse{ManagedHsmListResult: armkeyvault.ManagedHsmListResult{
						Value: []*armkeyvault.ManagedHsm{{ID: to.Ptr(testManagedHsmNativeID)}},
					}}, nil
				},
			})
		},
		newListBySubscriptionPagerFn: func(_ *armkeyvault.ManagedHsmsClientListBySubscriptionOptions) *runtime.Pager[armkeyvault.ManagedHsmsClientListBySubscriptionResponse] {
			return runtime.NewPager(runtime.PagingHandler[armkeyvault.ManagedHsmsClientListBySubscriptionResponse]{
				More: func(_ armkeyvault.ManagedHsmsClientListBySubscriptionResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armkeyvault.ManagedHsmsClientListBySubscriptionResponse) (armkeyvault.ManagedHsmsClientListBySubscriptionResponse, error) {
					return armkeyvault.ManagedHsmsClientListBySubscriptionResponse{ManagedHsmListResult: armkeyvault.ManagedHsmListResult{
						Value: []*armkeyvault.ManagedHsm{{ID: to.Ptr(testManagedHsmNativeID)}},
					}}, nil
				},
			})
		},
	}
	prov := newTestManagedHsm(fake)

	mkProps := func() json.RawMessage {
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName":     "rg-1",
			"name":                  "hsm-1",
			"location":              "eastus",
			"tenantId":              testManagedHsmTenantID,
			"sku":                   map[string]any{"family": "B", "name": "Standard_B1"},
			"initialAdminObjectIds": []string{testManagedHsmAdminID},
			"enableSoftDelete":      true,
			"Tags":                  []map[string]string{{"Key": "Environment", "Value": "test"}},
		})
		return props
	}

	t.Run("Create", func(t *testing.T) {
		var seen armkeyvault.ManagedHsm
		fake.beginCreateOrUpdateFn = func(_ context.Context, rg, name string, params armkeyvault.ManagedHsm, _ *armkeyvault.ManagedHsmsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armkeyvault.ManagedHsmsClientCreateOrUpdateResponse], error) {
			seen = params
			require.Equal(t, "rg-1", rg)
			require.Equal(t, "hsm-1", name)
			return newDonePoller(armkeyvault.ManagedHsmsClientCreateOrUpdateResponse{ManagedHsm: model}), nil
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testManagedHsmNativeID, got.ProgressResult.NativeID)

		require.Equal(t, armkeyvault.ManagedHsmSKUNameStandardB1, *seen.SKU.Name)
		require.Equal(t, armkeyvault.ManagedHsmSKUFamilyB, *seen.SKU.Family)
		require.Equal(t, testManagedHsmAdminID, *seen.Properties.InitialAdminObjectIDs[0])
		require.Equal(t, "test", *seen.Tags["Environment"])

		var serialized map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &serialized))
		require.Equal(t, "hsm-1", serialized["name"])
		require.Equal(t, "eastus", serialized["location"], "the ARM display form must be folded back")
		require.Equal(t, "https://hsm-1.managedhsm.azure.net/", serialized["hsmUri"])
		require.Equal(t, []any{testManagedHsmAdminID}, serialized["initialAdminObjectIds"])
	})

	t.Run("Create_requires_an_administrator", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName": "rg-1", "name": "hsm-1", "location": "eastus",
			"tenantId": testManagedHsmTenantID,
			"sku":      map[string]any{"family": "B", "name": "Standard_B1"},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "initialAdminObjectIds")
	})

	t.Run("Create_requires_sku_and_tenant", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName": "rg-1", "name": "hsm-1", "location": "eastus",
			"initialAdminObjectIds": []string{testManagedHsmAdminID},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "tenantId")
	})

	t.Run("Create_in_progress_returns_lro_request_id", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, _ armkeyvault.ManagedHsm, _ *armkeyvault.ManagedHsmsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armkeyvault.ManagedHsmsClientCreateOrUpdateResponse], error) {
			return newInProgressPoller[armkeyvault.ManagedHsmsClientCreateOrUpdateResponse](), nil
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusInProgress, got.ProgressResult.OperationStatus)
		require.Equal(t, testManagedHsmNativeID, got.ProgressResult.NativeID)

		reqID, err := decodeLROStatus(got.ProgressResult.RequestID)
		require.NoError(t, err)
		require.Equal(t, lroOpCreate, reqID.OperationType)
		require.Equal(t, testManagedHsmNativeID, reqID.NativeID)

		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, _ armkeyvault.ManagedHsm, _ *armkeyvault.ManagedHsmsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armkeyvault.ManagedHsmsClientCreateOrUpdateResponse], error) {
			return newDonePoller(armkeyvault.ManagedHsmsClientCreateOrUpdateResponse{ManagedHsm: model}), nil
		}
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testManagedHsmNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
		require.Equal(t, ResourceTypeManagedHsm, got.ResourceType)

		var serialized map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &serialized))
		require.Equal(t, "rg-1", serialized["resourceGroupName"])
		require.Equal(t, true, serialized["enableSoftDelete"])
		require.Equal(t, "Enabled", serialized["publicNetworkAccess"])
		require.Equal(t, map[string]any{"family": "B", "name": "Standard_B1"}, serialized["sku"])
	})

	t.Run("Read_not_found", func(t *testing.T) {
		fake.getFn = func(_ context.Context, _, _ string, _ *armkeyvault.ManagedHsmsClientGetOptions) (armkeyvault.ManagedHsmsClientGetResponse, error) {
			return armkeyvault.ManagedHsmsClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testManagedHsmNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)

		fake.getFn = func(_ context.Context, _, _ string, _ *armkeyvault.ManagedHsmsClientGetOptions) (armkeyvault.ManagedHsmsClientGetResponse, error) {
			return armkeyvault.ManagedHsmsClientGetResponse{ManagedHsm: model}, nil
		}
	})

	t.Run("Update_keeps_native_id", func(t *testing.T) {
		var seen armkeyvault.ManagedHsm
		updated := managedHsmModel(map[string]*string{"Environment": to.Ptr("updated")})
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, params armkeyvault.ManagedHsm, _ *armkeyvault.ManagedHsmsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armkeyvault.ManagedHsmsClientCreateOrUpdateResponse], error) {
			seen = params
			return newDonePoller(armkeyvault.ManagedHsmsClientCreateOrUpdateResponse{ManagedHsm: updated}), nil
		}
		desired, _ := json.Marshal(map[string]any{
			"resourceGroupName":     "rg-1",
			"name":                  "hsm-1",
			"location":              "eastus",
			"tenantId":              testManagedHsmTenantID,
			"sku":                   map[string]any{"family": "B", "name": "Standard_B1"},
			"initialAdminObjectIds": []string{testManagedHsmAdminID},
			"publicNetworkAccess":   "Disabled",
			"Tags":                  []map[string]string{{"Key": "Environment", "Value": "updated"}},
		})
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{NativeID: testManagedHsmNativeID, DesiredProperties: desired})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testManagedHsmNativeID, got.ProgressResult.NativeID)
		require.Equal(t, armkeyvault.PublicNetworkAccessDisabled, *seen.Properties.PublicNetworkAccess)
		require.Equal(t, "updated", *seen.Tags["Environment"])

		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, _ armkeyvault.ManagedHsm, _ *armkeyvault.ManagedHsmsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armkeyvault.ManagedHsmsClientCreateOrUpdateResponse], error) {
			return newDonePoller(armkeyvault.ManagedHsmsClientCreateOrUpdateResponse{ManagedHsm: model}), nil
		}
	})

	t.Run("Delete_in_progress_returns_lro_request_id", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testManagedHsmNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusInProgress, got.ProgressResult.OperationStatus)
		reqID, err := decodeLROStatus(got.ProgressResult.RequestID)
		require.NoError(t, err)
		require.Equal(t, lroOpDelete, reqID.OperationType)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _ string, _ *armkeyvault.ManagedHsmsClientBeginDeleteOptions) (*runtime.Poller[armkeyvault.ManagedHsmsClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testManagedHsmNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Status_rejects_unknown_operation", func(t *testing.T) {
		reqID, err := encodeLROStart("bogus", "token", testManagedHsmNativeID)
		require.NoError(t, err)
		got, err := prov.Status(context.Background(), &resource.StatusRequest{RequestID: reqID})
		require.Error(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.Contains(t, got.ProgressResult.StatusMessage, "bogus")
	})

	t.Run("List_by_resource_group", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testManagedHsmNativeID}, got.NativeIDs)
	})

	t.Run("List_all", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Equal(t, []string{testManagedHsmNativeID}, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure_with_a_message", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, _ armkeyvault.ManagedHsm, _ *armkeyvault.ManagedHsmsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armkeyvault.ManagedHsmsClientCreateOrUpdateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 409, ErrorCode: "ConflictError"}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.Contains(t, got.ProgressResult.StatusMessage, "ConflictError")
	})
}

func TestManagedHsmIDParts(t *testing.T) {
	rg, name, err := managedHsmIDParts(testManagedHsmNativeID)
	require.NoError(t, err)
	require.Equal(t, "rg-1", rg)
	require.Equal(t, "hsm-1", name)

	_, _, err = managedHsmIDParts("/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.KeyVault/vaults/kv-1")
	require.Error(t, err)
}

// --- Test helpers ---

type fakeManagedHsmsAPI struct {
	beginCreateOrUpdateFn         func(ctx context.Context, rgName, name string, params armkeyvault.ManagedHsm, opts *armkeyvault.ManagedHsmsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armkeyvault.ManagedHsmsClientCreateOrUpdateResponse], error)
	getFn                         func(ctx context.Context, rgName, name string, opts *armkeyvault.ManagedHsmsClientGetOptions) (armkeyvault.ManagedHsmsClientGetResponse, error)
	beginDeleteFn                 func(ctx context.Context, rgName, name string, opts *armkeyvault.ManagedHsmsClientBeginDeleteOptions) (*runtime.Poller[armkeyvault.ManagedHsmsClientDeleteResponse], error)
	newListByResourceGroupPagerFn func(rgName string, opts *armkeyvault.ManagedHsmsClientListByResourceGroupOptions) *runtime.Pager[armkeyvault.ManagedHsmsClientListByResourceGroupResponse]
	newListBySubscriptionPagerFn  func(opts *armkeyvault.ManagedHsmsClientListBySubscriptionOptions) *runtime.Pager[armkeyvault.ManagedHsmsClientListBySubscriptionResponse]
}

func (f *fakeManagedHsmsAPI) BeginCreateOrUpdate(ctx context.Context, rgName, name string, params armkeyvault.ManagedHsm, opts *armkeyvault.ManagedHsmsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armkeyvault.ManagedHsmsClientCreateOrUpdateResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, rgName, name, params, opts)
}

func (f *fakeManagedHsmsAPI) Get(ctx context.Context, rgName, name string, opts *armkeyvault.ManagedHsmsClientGetOptions) (armkeyvault.ManagedHsmsClientGetResponse, error) {
	return f.getFn(ctx, rgName, name, opts)
}

func (f *fakeManagedHsmsAPI) BeginDelete(ctx context.Context, rgName, name string, opts *armkeyvault.ManagedHsmsClientBeginDeleteOptions) (*runtime.Poller[armkeyvault.ManagedHsmsClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, name, opts)
}

func (f *fakeManagedHsmsAPI) NewListByResourceGroupPager(rgName string, opts *armkeyvault.ManagedHsmsClientListByResourceGroupOptions) *runtime.Pager[armkeyvault.ManagedHsmsClientListByResourceGroupResponse] {
	return f.newListByResourceGroupPagerFn(rgName, opts)
}

func (f *fakeManagedHsmsAPI) NewListBySubscriptionPager(opts *armkeyvault.ManagedHsmsClientListBySubscriptionOptions) *runtime.Pager[armkeyvault.ManagedHsmsClientListBySubscriptionResponse] {
	return f.newListBySubscriptionPagerFn(opts)
}
