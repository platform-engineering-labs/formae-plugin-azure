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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appconfiguration/armappconfiguration"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testAppConfigStoreNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.AppConfiguration/configurationStores/store-1"

func newTestAppConfigurationStore(api appConfigurationStoresAPI) *AppConfigurationStore {
	return &AppConfigurationStore{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func appConfigStoreDesired(sku string, disableLocalAuth bool) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":                      "store-1",
		"location":                  "eastus",
		"resourceGroupName":         "rg-1",
		"sku":                       map[string]any{"name": sku},
		"publicNetworkAccess":       "Enabled",
		"disableLocalAuth":          disableLocalAuth,
		"softDeleteRetentionInDays": 1,
	})
	return out
}

func TestAppConfigurationStore_CRUD(t *testing.T) {
	storeResult := armappconfiguration.ConfigurationStore{
		ID:       to.Ptr(testAppConfigStoreNativeID),
		Name:     to.Ptr("store-1"),
		Location: to.Ptr("East US"),
		SKU:      &armappconfiguration.SKU{Name: to.Ptr("standard")},
		Properties: &armappconfiguration.ConfigurationStoreProperties{
			Endpoint:                  to.Ptr("https://store-1.azconfig.io"),
			PublicNetworkAccess:       to.Ptr(armappconfiguration.PublicNetworkAccessEnabled),
			DisableLocalAuth:          to.Ptr(false),
			SoftDeleteRetentionInDays: to.Ptr(int32(1)),
			EnablePurgeProtection:     to.Ptr(false),
		},
	}

	var sentCreate armappconfiguration.ConfigurationStore
	var sentUpdate armappconfiguration.ConfigurationStoreUpdateParameters
	fake := &fakeAppConfigStoresAPI{
		beginCreateFn: func(_ context.Context, _, _ string, params armappconfiguration.ConfigurationStore, _ *armappconfiguration.ConfigurationStoresClientBeginCreateOptions) (*runtime.Poller[armappconfiguration.ConfigurationStoresClientCreateResponse], error) {
			sentCreate = params
			return newDonePoller(armappconfiguration.ConfigurationStoresClientCreateResponse{ConfigurationStore: storeResult}), nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armappconfiguration.ConfigurationStoresClientGetOptions) (armappconfiguration.ConfigurationStoresClientGetResponse, error) {
			return armappconfiguration.ConfigurationStoresClientGetResponse{ConfigurationStore: storeResult}, nil
		},
		beginUpdateFn: func(_ context.Context, _, _ string, params armappconfiguration.ConfigurationStoreUpdateParameters, _ *armappconfiguration.ConfigurationStoresClientBeginUpdateOptions) (*runtime.Poller[armappconfiguration.ConfigurationStoresClientUpdateResponse], error) {
			sentUpdate = params
			return newDonePoller(armappconfiguration.ConfigurationStoresClientUpdateResponse{ConfigurationStore: storeResult}), nil
		},
		beginDeleteFn: func(_ context.Context, _, _ string, _ *armappconfiguration.ConfigurationStoresClientBeginDeleteOptions) (*runtime.Poller[armappconfiguration.ConfigurationStoresClientDeleteResponse], error) {
			return newDonePoller(armappconfiguration.ConfigurationStoresClientDeleteResponse{}), nil
		},
		newListPagerFn: func(_ *armappconfiguration.ConfigurationStoresClientListOptions) *runtime.Pager[armappconfiguration.ConfigurationStoresClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armappconfiguration.ConfigurationStoresClientListResponse]{
				More: func(_ armappconfiguration.ConfigurationStoresClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armappconfiguration.ConfigurationStoresClientListResponse) (armappconfiguration.ConfigurationStoresClientListResponse, error) {
					return armappconfiguration.ConfigurationStoresClientListResponse{
						ConfigurationStoreListResult: armappconfiguration.ConfigurationStoreListResult{
							Value: []*armappconfiguration.ConfigurationStore{
								{ID: to.Ptr(testAppConfigStoreNativeID)},
								{ID: to.Ptr("/subscriptions/sub-1/resourceGroups/rg-2/providers/Microsoft.AppConfiguration/configurationStores/store-2")},
							},
						},
					}, nil
				},
			})
		},
		newListByResourceGroupPagerFn: func(_ string, _ *armappconfiguration.ConfigurationStoresClientListByResourceGroupOptions) *runtime.Pager[armappconfiguration.ConfigurationStoresClientListByResourceGroupResponse] {
			return runtime.NewPager(runtime.PagingHandler[armappconfiguration.ConfigurationStoresClientListByResourceGroupResponse]{
				More: func(_ armappconfiguration.ConfigurationStoresClientListByResourceGroupResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armappconfiguration.ConfigurationStoresClientListByResourceGroupResponse) (armappconfiguration.ConfigurationStoresClientListByResourceGroupResponse, error) {
					return armappconfiguration.ConfigurationStoresClientListByResourceGroupResponse{
						ConfigurationStoreListResult: armappconfiguration.ConfigurationStoreListResult{
							Value: []*armappconfiguration.ConfigurationStore{
								{ID: to.Ptr(testAppConfigStoreNativeID)},
							},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestAppConfigurationStore(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "store-1", Properties: appConfigStoreDesired("standard", false)})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testAppConfigStoreNativeID, got.ProgressResult.NativeID)

		require.Equal(t, "standard", *sentCreate.SKU.Name)
		require.EqualValues(t, 1, *sentCreate.Properties.SoftDeleteRetentionInDays)

		var props map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &props))
		require.Equal(t, "eastus", props["location"])
		require.Equal(t, "https://store-1.azconfig.io", props["endpoint"])
		// Keys come from a separate ListKeys call and must never reach state.
		require.NotContains(t, props, "primaryKey")
		require.NotContains(t, props, "connectionString")
	})

	t.Run("Create_requires_sku", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "store-1", "location": "eastus", "resourceGroupName": "rg-1",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.Error(t, err)
	})

	t.Run("Create_requires_location", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "store-1", "resourceGroupName": "rg-1", "sku": map[string]any{"name": "standard"},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.Error(t, err)
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testAppConfigStoreNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "store-1", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "eastus", props["location"])
		require.Equal(t, "Enabled", props["publicNetworkAccess"])
		require.Equal(t, false, props["disableLocalAuth"])
		sku := props["sku"].(map[string]any)
		require.Equal(t, "standard", sku["name"])
	})

	// softDeleteRetentionInDays is createOnly: ARM rejects changing it, so it must
	// never appear on the update body even though the desired props carry it.
	t.Run("Update_omits_createOnly_retention", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testAppConfigStoreNativeID,
			DesiredProperties: appConfigStoreDesired("standard", true),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testAppConfigStoreNativeID, got.ProgressResult.NativeID)
		require.Equal(t, true, *sentUpdate.Properties.DisableLocalAuth)
		require.Equal(t, "standard", *sentUpdate.SKU.Name)
	})

	t.Run("Delete", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testAppConfigStoreNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _ string, _ *armappconfiguration.ConfigurationStoresClientBeginDeleteOptions) (*runtime.Poller[armappconfiguration.ConfigurationStoresClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testAppConfigStoreNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_resource_group", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testAppConfigStoreNativeID}, got.NativeIDs)
	})

	t.Run("List_without_group_is_subscription_wide", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 2)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.beginCreateFn = func(_ context.Context, _, _ string, _ armappconfiguration.ConfigurationStore, _ *armappconfiguration.ConfigurationStoresClientBeginCreateOptions) (*runtime.Poller[armappconfiguration.ConfigurationStoresClientCreateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 409}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "store-1", Properties: appConfigStoreDesired("standard", false)})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

func TestAppConfigurationStore_ReadNotFound(t *testing.T) {
	fake := &fakeAppConfigStoresAPI{
		getFn: func(_ context.Context, _, _ string, _ *armappconfiguration.ConfigurationStoresClientGetOptions) (armappconfiguration.ConfigurationStoresClientGetResponse, error) {
			return armappconfiguration.ConfigurationStoresClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestAppConfigurationStore(fake).Read(context.Background(), &resource.ReadRequest{NativeID: testAppConfigStoreNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeAppConfigStoresAPI struct {
	beginCreateFn                 func(ctx context.Context, rgName, storeName string, parameters armappconfiguration.ConfigurationStore, options *armappconfiguration.ConfigurationStoresClientBeginCreateOptions) (*runtime.Poller[armappconfiguration.ConfigurationStoresClientCreateResponse], error)
	getFn                         func(ctx context.Context, rgName, storeName string, options *armappconfiguration.ConfigurationStoresClientGetOptions) (armappconfiguration.ConfigurationStoresClientGetResponse, error)
	beginUpdateFn                 func(ctx context.Context, rgName, storeName string, parameters armappconfiguration.ConfigurationStoreUpdateParameters, options *armappconfiguration.ConfigurationStoresClientBeginUpdateOptions) (*runtime.Poller[armappconfiguration.ConfigurationStoresClientUpdateResponse], error)
	beginDeleteFn                 func(ctx context.Context, rgName, storeName string, options *armappconfiguration.ConfigurationStoresClientBeginDeleteOptions) (*runtime.Poller[armappconfiguration.ConfigurationStoresClientDeleteResponse], error)
	newListPagerFn                func(options *armappconfiguration.ConfigurationStoresClientListOptions) *runtime.Pager[armappconfiguration.ConfigurationStoresClientListResponse]
	newListByResourceGroupPagerFn func(rgName string, options *armappconfiguration.ConfigurationStoresClientListByResourceGroupOptions) *runtime.Pager[armappconfiguration.ConfigurationStoresClientListByResourceGroupResponse]
}

func (f *fakeAppConfigStoresAPI) BeginCreate(ctx context.Context, rgName, storeName string, parameters armappconfiguration.ConfigurationStore, options *armappconfiguration.ConfigurationStoresClientBeginCreateOptions) (*runtime.Poller[armappconfiguration.ConfigurationStoresClientCreateResponse], error) {
	return f.beginCreateFn(ctx, rgName, storeName, parameters, options)
}

func (f *fakeAppConfigStoresAPI) Get(ctx context.Context, rgName, storeName string, options *armappconfiguration.ConfigurationStoresClientGetOptions) (armappconfiguration.ConfigurationStoresClientGetResponse, error) {
	return f.getFn(ctx, rgName, storeName, options)
}

func (f *fakeAppConfigStoresAPI) BeginUpdate(ctx context.Context, rgName, storeName string, parameters armappconfiguration.ConfigurationStoreUpdateParameters, options *armappconfiguration.ConfigurationStoresClientBeginUpdateOptions) (*runtime.Poller[armappconfiguration.ConfigurationStoresClientUpdateResponse], error) {
	return f.beginUpdateFn(ctx, rgName, storeName, parameters, options)
}

func (f *fakeAppConfigStoresAPI) BeginDelete(ctx context.Context, rgName, storeName string, options *armappconfiguration.ConfigurationStoresClientBeginDeleteOptions) (*runtime.Poller[armappconfiguration.ConfigurationStoresClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, storeName, options)
}

func (f *fakeAppConfigStoresAPI) NewListPager(options *armappconfiguration.ConfigurationStoresClientListOptions) *runtime.Pager[armappconfiguration.ConfigurationStoresClientListResponse] {
	return f.newListPagerFn(options)
}

func (f *fakeAppConfigStoresAPI) NewListByResourceGroupPager(rgName string, options *armappconfiguration.ConfigurationStoresClientListByResourceGroupOptions) *runtime.Pager[armappconfiguration.ConfigurationStoresClientListByResourceGroupResponse] {
	return f.newListByResourceGroupPagerFn(rgName, options)
}
