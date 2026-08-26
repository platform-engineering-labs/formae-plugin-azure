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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/batch/armbatch/v3"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testBatchAccountNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Batch/batchAccounts/batch1"

func newTestBatchAccount(api batchAccountAPI) *BatchAccount {
	return &BatchAccount{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func batchDesired(modes []string) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":                       "batch1",
		"location":                   "eastus",
		"resourceGroupName":          "rg-1",
		"poolAllocationMode":         "BatchService",
		"allowedAuthenticationModes": modes,
		"publicNetworkAccess":        "Enabled",
	})
	return out
}

func TestBatchAccount_CRUD(t *testing.T) {
	acctResult := armbatch.Account{
		ID:       to.Ptr(testBatchAccountNativeID),
		Name:     to.Ptr("batch1"),
		Location: to.Ptr("East US"),
		Properties: &armbatch.AccountProperties{
			AccountEndpoint:    to.Ptr("batch1.eastus.batch.azure.com"),
			PoolAllocationMode: to.Ptr(armbatch.PoolAllocationModeBatchService),
			AllowedAuthenticationModes: []*armbatch.AuthenticationMode{
				to.Ptr(armbatch.AuthenticationModeAAD),
				to.Ptr(armbatch.AuthenticationModeSharedKey),
			},
			PublicNetworkAccess: to.Ptr(armbatch.PublicNetworkAccessTypeEnabled),
		},
	}

	var sentCreate armbatch.AccountCreateParameters
	var sentUpdate armbatch.AccountUpdateParameters
	deleteCalls := 0
	fake := &fakeBatchAccountAPI{
		beginCreateFn: func(_ context.Context, _, name string, params armbatch.AccountCreateParameters, _ *armbatch.AccountClientBeginCreateOptions) (*runtime.Poller[armbatch.AccountClientCreateResponse], error) {
			require.Equal(t, "batch1", name)
			sentCreate = params
			return newDonePoller(armbatch.AccountClientCreateResponse{Account: acctResult}), nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armbatch.AccountClientGetOptions) (armbatch.AccountClientGetResponse, error) {
			return armbatch.AccountClientGetResponse{Account: acctResult}, nil
		},
		updateFn: func(_ context.Context, _, _ string, params armbatch.AccountUpdateParameters, _ *armbatch.AccountClientUpdateOptions) (armbatch.AccountClientUpdateResponse, error) {
			sentUpdate = params
			return armbatch.AccountClientUpdateResponse{Account: acctResult}, nil
		},
		beginDeleteFn: func(_ context.Context, _, _ string, _ *armbatch.AccountClientBeginDeleteOptions) (*runtime.Poller[armbatch.AccountClientDeleteResponse], error) {
			deleteCalls++
			return newDonePoller(armbatch.AccountClientDeleteResponse{}), nil
		},
		newListPagerFn: func(_ *armbatch.AccountClientListOptions) *runtime.Pager[armbatch.AccountClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armbatch.AccountClientListResponse]{
				More: func(_ armbatch.AccountClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armbatch.AccountClientListResponse) (armbatch.AccountClientListResponse, error) {
					return armbatch.AccountClientListResponse{
						AccountListResult: armbatch.AccountListResult{
							Value: []*armbatch.Account{
								{ID: to.Ptr(testBatchAccountNativeID)},
								{ID: to.Ptr("/subscriptions/sub-1/resourceGroups/rg-2/providers/Microsoft.Batch/batchAccounts/batch2")},
							},
						},
					}, nil
				},
			})
		},
		newListByResourceGroupPagerFn: func(_ string, _ *armbatch.AccountClientListByResourceGroupOptions) *runtime.Pager[armbatch.AccountClientListByResourceGroupResponse] {
			return runtime.NewPager(runtime.PagingHandler[armbatch.AccountClientListByResourceGroupResponse]{
				More: func(_ armbatch.AccountClientListByResourceGroupResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armbatch.AccountClientListByResourceGroupResponse) (armbatch.AccountClientListByResourceGroupResponse, error) {
					return armbatch.AccountClientListByResourceGroupResponse{
						AccountListResult: armbatch.AccountListResult{
							Value: []*armbatch.Account{{ID: to.Ptr(testBatchAccountNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestBatchAccount(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "batch1",
			Properties: batchDesired([]string{"AAD", "SharedKey"}),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testBatchAccountNativeID, got.ProgressResult.NativeID)

		require.Equal(t, armbatch.PoolAllocationModeBatchService, *sentCreate.Properties.PoolAllocationMode)
		require.Equal(t, armbatch.PublicNetworkAccessTypeEnabled, *sentCreate.Properties.PublicNetworkAccess)
		require.Len(t, sentCreate.Properties.AllowedAuthenticationModes, 2)
		require.Equal(t, armbatch.AuthenticationModeAAD, *sentCreate.Properties.AllowedAuthenticationModes[0])
	})

	t.Run("Create_requires_location", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "batch1", "resourceGroupName": "rg-1"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "location is required")
	})

	t.Run("Create_requires_resource_group", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "batch1", "location": "eastus"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "resourceGroupName is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testBatchAccountNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "batch1", props["name"])
		// ARM returns "East US"; read must normalise or desired state drifts.
		require.Equal(t, "eastus", props["location"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "batch1.eastus.batch.azure.com", props["accountEndpoint"])
		require.Equal(t, "BatchService", props["poolAllocationMode"])
		require.Equal(t, []any{"AAD", "SharedKey"}, props["allowedAuthenticationModes"])
	})

	// Shared keys come from a separate GetKeys call and must not reach state on any
	// path.
	t.Run("keys_never_serialized", func(t *testing.T) {
		read, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testBatchAccountNativeID})
		require.NoError(t, err)
		for _, key := range []string{"primary", "secondary", "accountKey", "keyName"} {
			require.NotContains(t, read.Properties, key)
		}
	})

	// Update is a synchronous PATCH: it must report Success directly, never
	// InProgress with a resume token.
	t.Run("Update_is_synchronous", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testBatchAccountNativeID,
			DesiredProperties: batchDesired([]string{"AAD"}),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testBatchAccountNativeID, got.ProgressResult.NativeID)
		require.Empty(t, got.ProgressResult.RequestID)
		require.Len(t, sentUpdate.Properties.AllowedAuthenticationModes, 1)
		require.Equal(t, armbatch.AuthenticationModeAAD, *sentUpdate.Properties.AllowedAuthenticationModes[0])
	})

	t.Run("Delete", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testBatchAccountNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _ string, _ *armbatch.AccountClientBeginDeleteOptions) (*runtime.Poller[armbatch.AccountClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testBatchAccountNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_resource_group", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testBatchAccountNativeID}, got.NativeIDs)
	})

	t.Run("List_without_group_is_subscription_wide", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 2)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.beginCreateFn = func(_ context.Context, _, _ string, _ armbatch.AccountCreateParameters, _ *armbatch.AccountClientBeginCreateOptions) (*runtime.Poller[armbatch.AccountClientCreateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 409}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "batch1", Properties: batchDesired([]string{"AAD"}),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

// autoStorage is a nested block whose storageAccountId may arrive as a resolved
// ARM ID. It must round-trip through both the create body and read.
func TestBatchAccount_AutoStorageRoundTrip(t *testing.T) {
	const storageID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Storage/storageAccounts/sa1"

	var sentCreate armbatch.AccountCreateParameters
	fake := &fakeBatchAccountAPI{
		beginCreateFn: func(_ context.Context, _, _ string, params armbatch.AccountCreateParameters, _ *armbatch.AccountClientBeginCreateOptions) (*runtime.Poller[armbatch.AccountClientCreateResponse], error) {
			sentCreate = params
			return newDonePoller(armbatch.AccountClientCreateResponse{Account: armbatch.Account{
				ID:   to.Ptr(testBatchAccountNativeID),
				Name: to.Ptr("batch1"),
				Properties: &armbatch.AccountProperties{
					AutoStorage: &armbatch.AutoStorageProperties{
						StorageAccountID:   to.Ptr(storageID),
						AuthenticationMode: to.Ptr(armbatch.AutoStorageAuthenticationModeStorageKeys),
					},
				},
			}}), nil
		},
	}

	props, _ := json.Marshal(map[string]any{
		"name":              "batch1",
		"location":          "eastus",
		"resourceGroupName": "rg-1",
		"autoStorage": map[string]any{
			"storageAccountId":   storageID,
			"authenticationMode": "StorageKeys",
		},
	})
	got, err := newTestBatchAccount(fake).Create(context.Background(), &resource.CreateRequest{Properties: props})
	require.NoError(t, err)
	require.Equal(t, storageID, *sentCreate.Properties.AutoStorage.StorageAccountID)
	require.Equal(t, armbatch.AutoStorageAuthenticationModeStorageKeys, *sentCreate.Properties.AutoStorage.AuthenticationMode)

	var out map[string]any
	require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &out))
	autoStorage := out["autoStorage"].(map[string]any)
	require.Equal(t, storageID, autoStorage["storageAccountId"])
	require.Equal(t, "StorageKeys", autoStorage["authenticationMode"])
}

// lastKeySync is a timestamp the Batch service bumps on its own. Surfacing it
// would read back as permanent drift on every sync, so read must drop it.
func TestBatchAccount_ReadDropsLastKeySync(t *testing.T) {
	fake := &fakeBatchAccountAPI{
		getFn: func(_ context.Context, _, _ string, _ *armbatch.AccountClientGetOptions) (armbatch.AccountClientGetResponse, error) {
			return armbatch.AccountClientGetResponse{Account: armbatch.Account{
				ID:   to.Ptr(testBatchAccountNativeID),
				Name: to.Ptr("batch1"),
				Properties: &armbatch.AccountProperties{
					AutoStorage: &armbatch.AutoStorageProperties{
						StorageAccountID: to.Ptr("/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Storage/storageAccounts/sa1"),
						LastKeySync:      to.Ptr(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)),
					},
				},
			}}, nil
		},
	}
	got, err := newTestBatchAccount(fake).Read(context.Background(), &resource.ReadRequest{NativeID: testBatchAccountNativeID})
	require.NoError(t, err)
	require.NotContains(t, got.Properties, "lastKeySync")
	require.NotContains(t, got.Properties, "LastKeySync")
}

func TestBatchAccount_ReadNotFound(t *testing.T) {
	fake := &fakeBatchAccountAPI{
		getFn: func(_ context.Context, _, _ string, _ *armbatch.AccountClientGetOptions) (armbatch.AccountClientGetResponse, error) {
			return armbatch.AccountClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestBatchAccount(fake).Read(context.Background(), &resource.ReadRequest{NativeID: testBatchAccountNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeBatchAccountAPI struct {
	beginCreateFn                 func(ctx context.Context, rgName, name string, params armbatch.AccountCreateParameters, options *armbatch.AccountClientBeginCreateOptions) (*runtime.Poller[armbatch.AccountClientCreateResponse], error)
	getFn                         func(ctx context.Context, rgName, name string, options *armbatch.AccountClientGetOptions) (armbatch.AccountClientGetResponse, error)
	updateFn                      func(ctx context.Context, rgName, name string, params armbatch.AccountUpdateParameters, options *armbatch.AccountClientUpdateOptions) (armbatch.AccountClientUpdateResponse, error)
	beginDeleteFn                 func(ctx context.Context, rgName, name string, options *armbatch.AccountClientBeginDeleteOptions) (*runtime.Poller[armbatch.AccountClientDeleteResponse], error)
	newListPagerFn                func(options *armbatch.AccountClientListOptions) *runtime.Pager[armbatch.AccountClientListResponse]
	newListByResourceGroupPagerFn func(rgName string, options *armbatch.AccountClientListByResourceGroupOptions) *runtime.Pager[armbatch.AccountClientListByResourceGroupResponse]
}

func (f *fakeBatchAccountAPI) BeginCreate(ctx context.Context, rgName, name string, params armbatch.AccountCreateParameters, options *armbatch.AccountClientBeginCreateOptions) (*runtime.Poller[armbatch.AccountClientCreateResponse], error) {
	return f.beginCreateFn(ctx, rgName, name, params, options)
}

func (f *fakeBatchAccountAPI) Get(ctx context.Context, rgName, name string, options *armbatch.AccountClientGetOptions) (armbatch.AccountClientGetResponse, error) {
	return f.getFn(ctx, rgName, name, options)
}

func (f *fakeBatchAccountAPI) Update(ctx context.Context, rgName, name string, params armbatch.AccountUpdateParameters, options *armbatch.AccountClientUpdateOptions) (armbatch.AccountClientUpdateResponse, error) {
	return f.updateFn(ctx, rgName, name, params, options)
}

func (f *fakeBatchAccountAPI) BeginDelete(ctx context.Context, rgName, name string, options *armbatch.AccountClientBeginDeleteOptions) (*runtime.Poller[armbatch.AccountClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, name, options)
}

func (f *fakeBatchAccountAPI) NewListPager(options *armbatch.AccountClientListOptions) *runtime.Pager[armbatch.AccountClientListResponse] {
	return f.newListPagerFn(options)
}

func (f *fakeBatchAccountAPI) NewListByResourceGroupPager(rgName string, options *armbatch.AccountClientListByResourceGroupOptions) *runtime.Pager[armbatch.AccountClientListByResourceGroupResponse] {
	return f.newListByResourceGroupPagerFn(rgName, options)
}

// ARM echoes allowedAuthenticationModes in its own order, not the order they were
// sent in, so read sorts them. Without this the list flaps between syncs.
func TestBatchAccount_ReadSortsAuthModes(t *testing.T) {
	fake := &fakeBatchAccountAPI{
		getFn: func(_ context.Context, _, _ string, _ *armbatch.AccountClientGetOptions) (armbatch.AccountClientGetResponse, error) {
			return armbatch.AccountClientGetResponse{Account: armbatch.Account{
				ID:   to.Ptr(testBatchAccountNativeID),
				Name: to.Ptr("batch1"),
				Properties: &armbatch.AccountProperties{
					AllowedAuthenticationModes: []*armbatch.AuthenticationMode{
						to.Ptr(armbatch.AuthenticationModeSharedKey),
						to.Ptr(armbatch.AuthenticationModeTaskAuthenticationToken),
						to.Ptr(armbatch.AuthenticationModeAAD),
					},
				},
			}}, nil
		},
	}
	got, err := newTestBatchAccount(fake).Read(context.Background(), &resource.ReadRequest{NativeID: testBatchAccountNativeID})
	require.NoError(t, err)

	var props map[string]any
	require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
	require.Equal(t, []any{"AAD", "SharedKey", "TaskAuthenticationToken"}, props["allowedAuthenticationModes"])
}
