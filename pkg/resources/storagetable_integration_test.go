// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build integration

package resources

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testStorageTableNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Storage/storageAccounts/acct1/tableServices/default/tables/table1"

func TestStorageTable_CRUD(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	expiry := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	// Azure echoes stored access policies in its own order; listed reversed here to
	// prove serialize sorts by id.
	model := armstorage.Table{
		ID:   to.Ptr(testStorageTableNativeID),
		Name: to.Ptr("table1"),
		TableProperties: &armstorage.TableProperties{
			SignedIdentifiers: []*armstorage.TableSignedIdentifier{
				{
					ID: to.Ptr("policy-b"),
					AccessPolicy: &armstorage.TableAccessPolicy{
						Permission: to.Ptr("r"),
						StartTime:  &start,
						ExpiryTime: &expiry,
					},
				},
				{
					ID: to.Ptr("policy-a"),
					AccessPolicy: &armstorage.TableAccessPolicy{
						Permission: to.Ptr("ra"),
						StartTime:  &start,
						ExpiryTime: &expiry,
					},
				},
			},
		},
	}
	fake := &fakeStorageTablesAPI{
		createFn: func(_ context.Context, _, _, _ string, _ *armstorage.TableClientCreateOptions) (armstorage.TableClientCreateResponse, error) {
			return armstorage.TableClientCreateResponse{Table: model}, nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ *armstorage.TableClientGetOptions) (armstorage.TableClientGetResponse, error) {
			return armstorage.TableClientGetResponse{Table: model}, nil
		},
		updateFn: func(_ context.Context, _, _, _ string, _ *armstorage.TableClientUpdateOptions) (armstorage.TableClientUpdateResponse, error) {
			return armstorage.TableClientUpdateResponse{Table: model}, nil
		},
		deleteFn: func(_ context.Context, _, _, _ string, _ *armstorage.TableClientDeleteOptions) (armstorage.TableClientDeleteResponse, error) {
			return armstorage.TableClientDeleteResponse{}, nil
		},
		newListPagerFn: func(_, _ string, _ *armstorage.TableClientListOptions) *runtime.Pager[armstorage.TableClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armstorage.TableClientListResponse]{
				More: func(_ armstorage.TableClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armstorage.TableClientListResponse) (armstorage.TableClientListResponse, error) {
					return armstorage.TableClientListResponse{
						ListTableResource: armstorage.ListTableResource{
							Value: []*armstorage.Table{{ID: to.Ptr(testStorageTableNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestStorageTable(fake)

	mkProps := func() json.RawMessage {
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName":  "rg-1",
			"storageAccountName": "acct1",
			"name":               "table1",
			"signedIdentifiers": []map[string]any{
				{"id": "policy-a", "accessPolicy": map[string]any{
					"permission": "ra", "startTime": "2026-01-01T00:00:00Z", "expiryTime": "2027-01-01T00:00:00Z",
				}},
			},
		})
		return props
	}

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testStorageTableNativeID, got.ProgressResult.NativeID)

		var serialized map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &serialized))
		require.Equal(t, "table1", serialized["name"])
		require.Equal(t, "acct1", serialized["storageAccountName"])
		require.Equal(t, "rg-1", serialized["resourceGroupName"])
	})

	// ARM does not promise to echo stored access policies in submitted order.
	t.Run("Serialize_sorts_signedIdentifiers_and_formats_times", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testStorageTableNativeID})
		require.NoError(t, err)
		var serialized map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &serialized))

		ids := serialized["signedIdentifiers"].([]any)
		require.Len(t, ids, 2)
		require.Equal(t, "policy-a", ids[0].(map[string]any)["id"])
		require.Equal(t, "policy-b", ids[1].(map[string]any)["id"])

		policy := ids[0].(map[string]any)["accessPolicy"].(map[string]any)
		require.Equal(t, "ra", policy["permission"])
		require.Equal(t, "2026-01-01T00:00:00Z", policy["startTime"])
		require.Equal(t, "2027-01-01T00:00:00Z", policy["expiryTime"])
	})

	// Create/Update pass the body inside the options struct, not positionally.
	t.Run("Create_forwards_body_in_options", func(t *testing.T) {
		var seen *armstorage.TableClientCreateOptions
		var seenRG, seenAcct, seenTable string
		fake.createFn = func(_ context.Context, rg, acct, table string, opts *armstorage.TableClientCreateOptions) (armstorage.TableClientCreateResponse, error) {
			seen, seenRG, seenAcct, seenTable = opts, rg, acct, table
			return armstorage.TableClientCreateResponse{Table: model}, nil
		}
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, "rg-1", seenRG)
		require.Equal(t, "acct1", seenAcct)
		require.Equal(t, "table1", seenTable)
		require.NotNil(t, seen)
		require.NotNil(t, seen.Parameters)
		require.Len(t, seen.Parameters.TableProperties.SignedIdentifiers, 1)
		si := seen.Parameters.TableProperties.SignedIdentifiers[0]
		require.Equal(t, "policy-a", *si.ID)
		require.Equal(t, "ra", *si.AccessPolicy.Permission)
		require.Equal(t, start, si.AccessPolicy.StartTime.UTC())
		require.Equal(t, expiry, si.AccessPolicy.ExpiryTime.UTC())

		fake.createFn = func(_ context.Context, _, _, _ string, _ *armstorage.TableClientCreateOptions) (armstorage.TableClientCreateResponse, error) {
			return armstorage.TableClientCreateResponse{Table: model}, nil
		}
	})

	t.Run("Create_requires_storageAccountName", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"resourceGroupName": "rg-1", "name": "table1"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "storageAccountName is required")
	})

	t.Run("Create_rejects_signedIdentifier_without_id", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName": "rg-1", "storageAccountName": "acct1", "name": "table1",
			"signedIdentifiers": []map[string]any{{"accessPolicy": map[string]any{"permission": "r"}}},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "signedIdentifiers[0].id is required")
	})

	t.Run("Create_rejects_accessPolicy_without_permission", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName": "rg-1", "storageAccountName": "acct1", "name": "table1",
			"signedIdentifiers": []map[string]any{{"id": "p", "accessPolicy": map[string]any{}}},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "permission is required")
	})

	t.Run("Create_rejects_unparseable_time", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName": "rg-1", "storageAccountName": "acct1", "name": "table1",
			"signedIdentifiers": []map[string]any{{"id": "p", "accessPolicy": map[string]any{
				"permission": "r", "expiryTime": "not-a-time",
			}}},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "expiryTime")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testStorageTableNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
		require.Equal(t, ResourceTypeStorageTable, got.ResourceType)
	})

	t.Run("Read_not_found", func(t *testing.T) {
		fake.getFn = func(_ context.Context, _, _, _ string, _ *armstorage.TableClientGetOptions) (armstorage.TableClientGetResponse, error) {
			return armstorage.TableClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testStorageTableNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)

		fake.getFn = func(_ context.Context, _, _, _ string, _ *armstorage.TableClientGetOptions) (armstorage.TableClientGetResponse, error) {
			return armstorage.TableClientGetResponse{Table: model}, nil
		}
	})

	t.Run("Update_derives_names_from_native_id", func(t *testing.T) {
		var seenRG, seenAcct, seenTable string
		var seen *armstorage.TableClientUpdateOptions
		fake.updateFn = func(_ context.Context, rg, acct, table string, opts *armstorage.TableClientUpdateOptions) (armstorage.TableClientUpdateResponse, error) {
			seen, seenRG, seenAcct, seenTable = opts, rg, acct, table
			return armstorage.TableClientUpdateResponse{Table: model}, nil
		}
		desired, _ := json.Marshal(map[string]any{
			"signedIdentifiers": []map[string]any{
				{"id": "policy-a", "accessPolicy": map[string]any{"permission": "rau"}},
			},
		})
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testStorageTableNativeID,
			DesiredProperties: desired,
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, "rg-1", seenRG)
		require.Equal(t, "acct1", seenAcct)
		require.Equal(t, "table1", seenTable)
		require.Equal(t, "rau", *seen.Parameters.TableProperties.SignedIdentifiers[0].AccessPolicy.Permission)
	})

	t.Run("Delete", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testStorageTableNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _, _ string, _ *armstorage.TableClientDeleteOptions) (armstorage.TableClientDeleteResponse, error) {
			return armstorage.TableClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testStorageTableNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Status_is_sync_success", func(t *testing.T) {
		got, err := prov.Status(context.Background(), &resource.StatusRequest{RequestID: "anything"})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_account", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "storageAccountName": "acct1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testStorageTableNativeID}, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.createFn = func(_ context.Context, _, _, _ string, _ *armstorage.TableClientCreateOptions) (armstorage.TableClientCreateResponse, error) {
			return armstorage.TableClientCreateResponse{}, &azcore.ResponseError{StatusCode: 403}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

func TestStorageTableIDParts(t *testing.T) {
	rg, acct, table, err := storageTableIDParts(testStorageTableNativeID)
	require.NoError(t, err)
	require.Equal(t, "rg-1", rg)
	require.Equal(t, "acct1", acct)
	require.Equal(t, "table1", table)

	_, _, _, err = storageTableIDParts("/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Storage/storageAccounts/acct1")
	require.Error(t, err)
}

// --- Test helpers ---

func newTestStorageTable(api storageTablesAPI) *StorageTable {
	return &StorageTable{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

type fakeStorageTablesAPI struct {
	createFn       func(ctx context.Context, rgName, accountName, tableName string, opts *armstorage.TableClientCreateOptions) (armstorage.TableClientCreateResponse, error)
	getFn          func(ctx context.Context, rgName, accountName, tableName string, opts *armstorage.TableClientGetOptions) (armstorage.TableClientGetResponse, error)
	updateFn       func(ctx context.Context, rgName, accountName, tableName string, opts *armstorage.TableClientUpdateOptions) (armstorage.TableClientUpdateResponse, error)
	deleteFn       func(ctx context.Context, rgName, accountName, tableName string, opts *armstorage.TableClientDeleteOptions) (armstorage.TableClientDeleteResponse, error)
	newListPagerFn func(rgName, accountName string, opts *armstorage.TableClientListOptions) *runtime.Pager[armstorage.TableClientListResponse]
}

func (f *fakeStorageTablesAPI) Create(ctx context.Context, rgName, accountName, tableName string, opts *armstorage.TableClientCreateOptions) (armstorage.TableClientCreateResponse, error) {
	return f.createFn(ctx, rgName, accountName, tableName, opts)
}

func (f *fakeStorageTablesAPI) Get(ctx context.Context, rgName, accountName, tableName string, opts *armstorage.TableClientGetOptions) (armstorage.TableClientGetResponse, error) {
	return f.getFn(ctx, rgName, accountName, tableName, opts)
}

func (f *fakeStorageTablesAPI) Update(ctx context.Context, rgName, accountName, tableName string, opts *armstorage.TableClientUpdateOptions) (armstorage.TableClientUpdateResponse, error) {
	return f.updateFn(ctx, rgName, accountName, tableName, opts)
}

func (f *fakeStorageTablesAPI) Delete(ctx context.Context, rgName, accountName, tableName string, opts *armstorage.TableClientDeleteOptions) (armstorage.TableClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, accountName, tableName, opts)
}

func (f *fakeStorageTablesAPI) NewListPager(rgName, accountName string, opts *armstorage.TableClientListOptions) *runtime.Pager[armstorage.TableClientListResponse] {
	return f.newListPagerFn(rgName, accountName, opts)
}
