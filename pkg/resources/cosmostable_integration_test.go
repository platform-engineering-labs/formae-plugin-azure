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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/cosmos/armcosmos/v3"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testCosmosTableNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.DocumentDB/databaseAccounts/table-1/tables/orders"

func TestCosmosTable_CRUD(t *testing.T) {
	tableResult := armcosmos.TableGetResults{
		ID:   to.Ptr(testCosmosTableNativeID),
		Name: to.Ptr("orders"),
		Properties: &armcosmos.TableGetProperties{
			Resource: &armcosmos.TableGetPropertiesResource{ID: to.Ptr("orders")},
		},
	}

	var sent armcosmos.TableCreateUpdateParameters
	fake := &fakeCosmosTableAPI{
		createFn: func(_ context.Context, rgName, accountName, tableName string, params armcosmos.TableCreateUpdateParameters) (*runtime.Poller[armcosmos.TableResourcesClientCreateUpdateTableResponse], error) {
			require.Equal(t, []string{"rg-1", "table-1", "orders"}, []string{rgName, accountName, tableName})
			sent = params
			return newDonePoller(armcosmos.TableResourcesClientCreateUpdateTableResponse{TableGetResults: tableResult}), nil
		},
		getFn: func(_ context.Context, _, _, _ string) (armcosmos.TableResourcesClientGetTableResponse, error) {
			return armcosmos.TableResourcesClientGetTableResponse{TableGetResults: tableResult}, nil
		},
		throughputFn: func(_ context.Context, _, _, _ string) (armcosmos.TableResourcesClientGetTableThroughputResponse, error) {
			return armcosmos.TableResourcesClientGetTableThroughputResponse{
				ThroughputSettingsGetResults: armcosmos.ThroughputSettingsGetResults{
					Properties: &armcosmos.ThroughputSettingsGetProperties{
						Resource: &armcosmos.ThroughputSettingsGetPropertiesResource{Throughput: to.Ptr(int32(400))},
					},
				},
			}, nil
		},
		deleteFn: func(_ context.Context, _, _, _ string) (*runtime.Poller[armcosmos.TableResourcesClientDeleteTableResponse], error) {
			return newDonePoller(armcosmos.TableResourcesClientDeleteTableResponse{}), nil
		},
		listFn: func(_, _ string) *runtime.Pager[armcosmos.TableResourcesClientListTablesResponse] {
			return runtime.NewPager(runtime.PagingHandler[armcosmos.TableResourcesClientListTablesResponse]{
				More: func(armcosmos.TableResourcesClientListTablesResponse) bool { return false },
				Fetcher: func(context.Context, *armcosmos.TableResourcesClientListTablesResponse) (armcosmos.TableResourcesClientListTablesResponse, error) {
					return armcosmos.TableResourcesClientListTablesResponse{
						TableListResult: armcosmos.TableListResult{
							Value: []*armcosmos.TableGetResults{{ID: to.Ptr(testCosmosTableNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := &CosmosTable{api: fake, config: &config.Config{SubscriptionId: "sub-1"}}

	desired, _ := json.Marshal(map[string]any{
		"name": "orders", "resourceGroupName": "rg-1", "accountName": "table-1", "throughput": 400,
	})

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "orders", Properties: desired})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testCosmosTableNativeID, got.ProgressResult.NativeID)
		require.Equal(t, "orders", *sent.Properties.Resource.ID)
		require.EqualValues(t, 400, *sent.Properties.Options.Throughput)
	})

	t.Run("Create_requires_accountName", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "orders", "resourceGroupName": "rg-1"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "accountName is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testCosmosTableNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "orders", props["name"])
		require.Equal(t, "table-1", props["accountName"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.EqualValues(t, 400, props["throughput"])
	})

	// A Cassandra table ARM ID has an extra keyspace segment and must not parse here.
	t.Run("Read_rejects_a_foreign_ARM_ID", func(t *testing.T) {
		_, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testCosmosCassandraTableNativeID})
		require.ErrorContains(t, err, "is not a databaseAccounts/tables")
	})

	t.Run("Update_sends_no_throughput_options", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID: testCosmosTableNativeID, DesiredProperties: desired,
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Nil(t, sent.Properties.Options)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _, _ string) (*runtime.Poller[armcosmos.TableResourcesClientDeleteTableResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testCosmosTableNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "accountName": "table-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testCosmosTableNativeID}, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.createFn = func(_ context.Context, _, _, _ string, _ armcosmos.TableCreateUpdateParameters) (*runtime.Poller[armcosmos.TableResourcesClientCreateUpdateTableResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 409}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "orders", Properties: desired})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

func TestCosmosTable_ReadNotFound(t *testing.T) {
	fake := &fakeCosmosTableAPI{
		getFn: func(_ context.Context, _, _, _ string) (armcosmos.TableResourcesClientGetTableResponse, error) {
			return armcosmos.TableResourcesClientGetTableResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	prov := &CosmosTable{api: fake, config: &config.Config{SubscriptionId: "sub-1"}}
	got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testCosmosTableNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeCosmosTableAPI struct {
	createFn     func(ctx context.Context, rgName, accountName, tableName string, params armcosmos.TableCreateUpdateParameters) (*runtime.Poller[armcosmos.TableResourcesClientCreateUpdateTableResponse], error)
	getFn        func(ctx context.Context, rgName, accountName, tableName string) (armcosmos.TableResourcesClientGetTableResponse, error)
	throughputFn func(ctx context.Context, rgName, accountName, tableName string) (armcosmos.TableResourcesClientGetTableThroughputResponse, error)
	deleteFn     func(ctx context.Context, rgName, accountName, tableName string) (*runtime.Poller[armcosmos.TableResourcesClientDeleteTableResponse], error)
	listFn       func(rgName, accountName string) *runtime.Pager[armcosmos.TableResourcesClientListTablesResponse]
}

func (f *fakeCosmosTableAPI) BeginCreateUpdateTable(ctx context.Context, rgName, accountName, tableName string, params armcosmos.TableCreateUpdateParameters, _ *armcosmos.TableResourcesClientBeginCreateUpdateTableOptions) (*runtime.Poller[armcosmos.TableResourcesClientCreateUpdateTableResponse], error) {
	return f.createFn(ctx, rgName, accountName, tableName, params)
}

func (f *fakeCosmosTableAPI) GetTable(ctx context.Context, rgName, accountName, tableName string, _ *armcosmos.TableResourcesClientGetTableOptions) (armcosmos.TableResourcesClientGetTableResponse, error) {
	return f.getFn(ctx, rgName, accountName, tableName)
}

func (f *fakeCosmosTableAPI) GetTableThroughput(ctx context.Context, rgName, accountName, tableName string, _ *armcosmos.TableResourcesClientGetTableThroughputOptions) (armcosmos.TableResourcesClientGetTableThroughputResponse, error) {
	if f.throughputFn == nil {
		return armcosmos.TableResourcesClientGetTableThroughputResponse{}, &azcore.ResponseError{StatusCode: 404}
	}
	return f.throughputFn(ctx, rgName, accountName, tableName)
}

func (f *fakeCosmosTableAPI) BeginDeleteTable(ctx context.Context, rgName, accountName, tableName string, _ *armcosmos.TableResourcesClientBeginDeleteTableOptions) (*runtime.Poller[armcosmos.TableResourcesClientDeleteTableResponse], error) {
	return f.deleteFn(ctx, rgName, accountName, tableName)
}

func (f *fakeCosmosTableAPI) NewListTablesPager(rgName, accountName string, _ *armcosmos.TableResourcesClientListTablesOptions) *runtime.Pager[armcosmos.TableResourcesClientListTablesResponse] {
	return f.listFn(rgName, accountName)
}
