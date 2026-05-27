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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/sql/armsql"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testSQLDatabaseNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Sql/servers/sql-1/databases/db-1"

func TestSqlDatabase_CRUD(t *testing.T) {
	dbResult := armsql.Database{
		ID:       to.Ptr(testSQLDatabaseNativeID),
		Name:     to.Ptr("db-1"),
		Location: to.Ptr("West US 2"),
		SKU: &armsql.SKU{
			Name:     to.Ptr("S0"),
			Tier:     to.Ptr("Standard"),
			Capacity: to.Ptr(int32(10)),
		},
		Properties: &armsql.DatabaseProperties{
			Collation:    to.Ptr("SQL_Latin1_General_CP1_CI_AS"),
			MaxSizeBytes: to.Ptr(int64(268435456000)),
			Status:       to.Ptr(armsql.DatabaseStatusOnline),
		},
	}

	fake := &fakeSQLDatabasesAPI{
		beginCreateOrUpdateFn: func(_ context.Context, _, _, _ string, _ armsql.Database, _ *armsql.DatabasesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armsql.DatabasesClientCreateOrUpdateResponse], error) {
			return newDonePoller(armsql.DatabasesClientCreateOrUpdateResponse{Database: dbResult}), nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ *armsql.DatabasesClientGetOptions) (armsql.DatabasesClientGetResponse, error) {
			return armsql.DatabasesClientGetResponse{Database: dbResult}, nil
		},
		beginUpdateFn: func(_ context.Context, _, _, _ string, _ armsql.DatabaseUpdate, _ *armsql.DatabasesClientBeginUpdateOptions) (*runtime.Poller[armsql.DatabasesClientUpdateResponse], error) {
			return newDonePoller(armsql.DatabasesClientUpdateResponse{Database: dbResult}), nil
		},
		newListByServerPagerFn: func(_, _ string, _ *armsql.DatabasesClientListByServerOptions) *runtime.Pager[armsql.DatabasesClientListByServerResponse] {
			return runtime.NewPager(runtime.PagingHandler[armsql.DatabasesClientListByServerResponse]{
				More: func(_ armsql.DatabasesClientListByServerResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armsql.DatabasesClientListByServerResponse) (armsql.DatabasesClientListByServerResponse, error) {
					return armsql.DatabasesClientListByServerResponse{
						DatabaseListResult: armsql.DatabaseListResult{
							Value: []*armsql.Database{
								{ID: to.Ptr(testSQLDatabaseNativeID)},
								{ID: to.Ptr("/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Sql/servers/sql-1/databases/db-2")},
							},
						},
					}, nil
				},
			})
		},
		newListServersPagerFn: func(_ *armsql.ServersClientListOptions) *runtime.Pager[armsql.ServersClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armsql.ServersClientListResponse]{
				More: func(_ armsql.ServersClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armsql.ServersClientListResponse) (armsql.ServersClientListResponse, error) {
					return armsql.ServersClientListResponse{
						ServerListResult: armsql.ServerListResult{
							Value: []*armsql.Server{
								{ID: to.Ptr("/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Sql/servers/sql-1")},
							},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestSqlDatabase(fake)

	t.Run("Create", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName": "rg-1",
			"serverName":        "sql-1",
			"name":              "db-1",
			"location":          "westus2",
			"collation":         "SQL_Latin1_General_CP1_CI_AS",
			"maxSizeBytes":      268435456000,
			"sku": map[string]any{
				"name":     "S0",
				"tier":     "Standard",
				"capacity": 10,
			},
		})
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "db-1", Properties: props})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testSQLDatabaseNativeID, got.ProgressResult.NativeID)
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testSQLDatabaseNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "db-1", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "sql-1", props["serverName"])
		require.Equal(t, "westus2", props["location"])
		sku, ok := props["sku"].(map[string]any)
		require.True(t, ok)
		require.Equal(t, "S0", sku["name"])
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _, _ string, _ *armsql.DatabasesClientBeginDeleteOptions) (*runtime.Poller[armsql.DatabasesClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testSQLDatabaseNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "serverName": "sql-1"},
		})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 2)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _, _ string, _ armsql.Database, _ *armsql.DatabasesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armsql.DatabasesClientCreateOrUpdateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 403}
		}
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName": "rg-1",
			"serverName":        "sql-1",
			"name":              "db-1",
			"location":          "westus2",
		})
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "db-1", Properties: props})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

// --- Test helpers ---

func newTestSqlDatabase(api sqlDatabasesAPI) *SqlDatabase {
	return &SqlDatabase{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

type fakeSQLDatabasesAPI struct {
	beginCreateOrUpdateFn  func(ctx context.Context, resourceGroupName, serverName, databaseName string, parameters armsql.Database, options *armsql.DatabasesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armsql.DatabasesClientCreateOrUpdateResponse], error)
	getFn                  func(ctx context.Context, resourceGroupName, serverName, databaseName string, options *armsql.DatabasesClientGetOptions) (armsql.DatabasesClientGetResponse, error)
	beginUpdateFn          func(ctx context.Context, resourceGroupName, serverName, databaseName string, parameters armsql.DatabaseUpdate, options *armsql.DatabasesClientBeginUpdateOptions) (*runtime.Poller[armsql.DatabasesClientUpdateResponse], error)
	beginDeleteFn          func(ctx context.Context, resourceGroupName, serverName, databaseName string, options *armsql.DatabasesClientBeginDeleteOptions) (*runtime.Poller[armsql.DatabasesClientDeleteResponse], error)
	newListByServerPagerFn func(resourceGroupName, serverName string, options *armsql.DatabasesClientListByServerOptions) *runtime.Pager[armsql.DatabasesClientListByServerResponse]
	newListServersPagerFn  func(options *armsql.ServersClientListOptions) *runtime.Pager[armsql.ServersClientListResponse]
}

func (f *fakeSQLDatabasesAPI) BeginCreateOrUpdate(ctx context.Context, resourceGroupName, serverName, databaseName string, parameters armsql.Database, options *armsql.DatabasesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armsql.DatabasesClientCreateOrUpdateResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, resourceGroupName, serverName, databaseName, parameters, options)
}

func (f *fakeSQLDatabasesAPI) Get(ctx context.Context, resourceGroupName, serverName, databaseName string, options *armsql.DatabasesClientGetOptions) (armsql.DatabasesClientGetResponse, error) {
	return f.getFn(ctx, resourceGroupName, serverName, databaseName, options)
}

func (f *fakeSQLDatabasesAPI) BeginUpdate(ctx context.Context, resourceGroupName, serverName, databaseName string, parameters armsql.DatabaseUpdate, options *armsql.DatabasesClientBeginUpdateOptions) (*runtime.Poller[armsql.DatabasesClientUpdateResponse], error) {
	return f.beginUpdateFn(ctx, resourceGroupName, serverName, databaseName, parameters, options)
}

func (f *fakeSQLDatabasesAPI) BeginDelete(ctx context.Context, resourceGroupName, serverName, databaseName string, options *armsql.DatabasesClientBeginDeleteOptions) (*runtime.Poller[armsql.DatabasesClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, resourceGroupName, serverName, databaseName, options)
}

func (f *fakeSQLDatabasesAPI) NewListByServerPager(resourceGroupName, serverName string, options *armsql.DatabasesClientListByServerOptions) *runtime.Pager[armsql.DatabasesClientListByServerResponse] {
	return f.newListByServerPagerFn(resourceGroupName, serverName, options)
}

func (f *fakeSQLDatabasesAPI) NewListServersPager(options *armsql.ServersClientListOptions) *runtime.Pager[armsql.ServersClientListResponse] {
	return f.newListServersPagerFn(options)
}
