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

const testSQLElasticPoolNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Sql/servers/sql-1/elasticPools/pool-1"

func newTestSqlElasticPool(api sqlElasticPoolsAPI) *SqlElasticPool {
	return &SqlElasticPool{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func TestSqlElasticPool_CRUD(t *testing.T) {
	poolResult := armsql.ElasticPool{
		ID:       to.Ptr(testSQLElasticPoolNativeID),
		Name:     to.Ptr("pool-1"),
		Location: to.Ptr("West US 2"),
		SKU: &armsql.SKU{
			Name:     to.Ptr("StandardPool"),
			Tier:     to.Ptr("Standard"),
			Capacity: to.Ptr(int32(50)),
		},
		Properties: &armsql.ElasticPoolProperties{
			MaxSizeBytes:  to.Ptr(int64(53687091200)),
			ZoneRedundant: to.Ptr(false),
			State:         to.Ptr(armsql.ElasticPoolStateReady),
			PerDatabaseSettings: &armsql.ElasticPoolPerDatabaseSettings{
				MinCapacity: to.Ptr(float64(0)),
				MaxCapacity: to.Ptr(float64(20)),
			},
		},
	}

	var sentUpdate armsql.ElasticPoolUpdate
	fake := &fakeSQLElasticPoolsAPI{
		beginCreateOrUpdateFn: func(_ context.Context, _, _, _ string, _ armsql.ElasticPool, _ *armsql.ElasticPoolsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armsql.ElasticPoolsClientCreateOrUpdateResponse], error) {
			return newDonePoller(armsql.ElasticPoolsClientCreateOrUpdateResponse{ElasticPool: poolResult}), nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ *armsql.ElasticPoolsClientGetOptions) (armsql.ElasticPoolsClientGetResponse, error) {
			return armsql.ElasticPoolsClientGetResponse{ElasticPool: poolResult}, nil
		},
		beginUpdateFn: func(_ context.Context, _, _, _ string, params armsql.ElasticPoolUpdate, _ *armsql.ElasticPoolsClientBeginUpdateOptions) (*runtime.Poller[armsql.ElasticPoolsClientUpdateResponse], error) {
			sentUpdate = params
			return newDonePoller(armsql.ElasticPoolsClientUpdateResponse{ElasticPool: poolResult}), nil
		},
		beginDeleteFn: func(_ context.Context, _, _, _ string, _ *armsql.ElasticPoolsClientBeginDeleteOptions) (*runtime.Poller[armsql.ElasticPoolsClientDeleteResponse], error) {
			return newDonePoller(armsql.ElasticPoolsClientDeleteResponse{}), nil
		},
		newListByServerPagerFn: func(_, _ string, _ *armsql.ElasticPoolsClientListByServerOptions) *runtime.Pager[armsql.ElasticPoolsClientListByServerResponse] {
			return runtime.NewPager(runtime.PagingHandler[armsql.ElasticPoolsClientListByServerResponse]{
				More: func(_ armsql.ElasticPoolsClientListByServerResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armsql.ElasticPoolsClientListByServerResponse) (armsql.ElasticPoolsClientListByServerResponse, error) {
					return armsql.ElasticPoolsClientListByServerResponse{
						ElasticPoolListResult: armsql.ElasticPoolListResult{
							Value: []*armsql.ElasticPool{
								{ID: to.Ptr(testSQLElasticPoolNativeID)},
								{ID: to.Ptr("/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Sql/servers/sql-1/elasticPools/pool-2")},
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
	prov := newTestSqlElasticPool(fake)

	desired := func(poolCapacity int, maxPerDB float64) []byte {
		out, _ := json.Marshal(map[string]any{
			"resourceGroupName": "rg-1",
			"serverName":        "sql-1",
			"name":              "pool-1",
			"location":          "westus2",
			"maxSizeBytes":      53687091200,
			"sku": map[string]any{
				"name":     "StandardPool",
				"tier":     "Standard",
				"capacity": poolCapacity,
			},
			"perDatabaseSettings": map[string]any{
				"minCapacity": 0,
				"maxCapacity": maxPerDB,
			},
		})
		return out
	}

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "pool-1", Properties: desired(50, 20)})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testSQLElasticPoolNativeID, got.ProgressResult.NativeID)

		var props map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &props))
		require.Equal(t, "westus2", props["location"])
		pds := props["perDatabaseSettings"].(map[string]any)
		require.EqualValues(t, 20, pds["maxCapacity"])
	})

	t.Run("Create_requires_location", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"resourceGroupName": "rg-1", "serverName": "sql-1", "name": "pool-1"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.Error(t, err)
	})

	t.Run("Create_requires_serverName", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"resourceGroupName": "rg-1", "name": "pool-1", "location": "westus2"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.Error(t, err)
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testSQLElasticPoolNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "pool-1", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "sql-1", props["serverName"])
		require.Equal(t, "westus2", props["location"])
		require.Equal(t, "Ready", props["state"])
		sku := props["sku"].(map[string]any)
		require.Equal(t, "StandardPool", sku["name"])
		require.EqualValues(t, 50, sku["capacity"])
	})

	// A capacity change is an in-place resize; ARM must receive it on the update
	// body and the NativeID must not change (a replace would drop member databases).
	t.Run("Update_resizes_in_place", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testSQLElasticPoolNativeID,
			DesiredProperties: desired(100, 50),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testSQLElasticPoolNativeID, got.ProgressResult.NativeID)
		require.EqualValues(t, 100, *sentUpdate.SKU.Capacity)
		require.EqualValues(t, 50, *sentUpdate.Properties.PerDatabaseSettings.MaxCapacity)
	})

	t.Run("Delete", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testSQLElasticPoolNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _, _ string, _ *armsql.ElasticPoolsClientBeginDeleteOptions) (*runtime.Poller[armsql.ElasticPoolsClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testSQLElasticPoolNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_server", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "serverName": "sql-1"},
		})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 2)
		require.Equal(t, testSQLElasticPoolNativeID, got.NativeIDs[0])
	})

	// Without a parent server, discovery must fall back to enumerating servers.
	t.Run("List_without_parent_enumerates_servers", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 2)
	})

	t.Run("Read_rejects_non_pool_id", func(t *testing.T) {
		_, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testSQLDatabaseNativeID})
		require.Error(t, err)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _, _ string, _ armsql.ElasticPool, _ *armsql.ElasticPoolsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armsql.ElasticPoolsClientCreateOrUpdateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 403}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "pool-1", Properties: desired(50, 20)})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

func TestSqlElasticPool_ReadNotFound(t *testing.T) {
	fake := &fakeSQLElasticPoolsAPI{
		getFn: func(_ context.Context, _, _, _ string, _ *armsql.ElasticPoolsClientGetOptions) (armsql.ElasticPoolsClientGetResponse, error) {
			return armsql.ElasticPoolsClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestSqlElasticPool(fake).Read(context.Background(), &resource.ReadRequest{NativeID: testSQLElasticPoolNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeSQLElasticPoolsAPI struct {
	beginCreateOrUpdateFn  func(ctx context.Context, resourceGroupName, serverName, poolName string, parameters armsql.ElasticPool, options *armsql.ElasticPoolsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armsql.ElasticPoolsClientCreateOrUpdateResponse], error)
	getFn                  func(ctx context.Context, resourceGroupName, serverName, poolName string, options *armsql.ElasticPoolsClientGetOptions) (armsql.ElasticPoolsClientGetResponse, error)
	beginUpdateFn          func(ctx context.Context, resourceGroupName, serverName, poolName string, parameters armsql.ElasticPoolUpdate, options *armsql.ElasticPoolsClientBeginUpdateOptions) (*runtime.Poller[armsql.ElasticPoolsClientUpdateResponse], error)
	beginDeleteFn          func(ctx context.Context, resourceGroupName, serverName, poolName string, options *armsql.ElasticPoolsClientBeginDeleteOptions) (*runtime.Poller[armsql.ElasticPoolsClientDeleteResponse], error)
	newListByServerPagerFn func(resourceGroupName, serverName string, options *armsql.ElasticPoolsClientListByServerOptions) *runtime.Pager[armsql.ElasticPoolsClientListByServerResponse]
	newListServersPagerFn  func(options *armsql.ServersClientListOptions) *runtime.Pager[armsql.ServersClientListResponse]
}

func (f *fakeSQLElasticPoolsAPI) BeginCreateOrUpdate(ctx context.Context, resourceGroupName, serverName, poolName string, parameters armsql.ElasticPool, options *armsql.ElasticPoolsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armsql.ElasticPoolsClientCreateOrUpdateResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, resourceGroupName, serverName, poolName, parameters, options)
}

func (f *fakeSQLElasticPoolsAPI) Get(ctx context.Context, resourceGroupName, serverName, poolName string, options *armsql.ElasticPoolsClientGetOptions) (armsql.ElasticPoolsClientGetResponse, error) {
	return f.getFn(ctx, resourceGroupName, serverName, poolName, options)
}

func (f *fakeSQLElasticPoolsAPI) BeginUpdate(ctx context.Context, resourceGroupName, serverName, poolName string, parameters armsql.ElasticPoolUpdate, options *armsql.ElasticPoolsClientBeginUpdateOptions) (*runtime.Poller[armsql.ElasticPoolsClientUpdateResponse], error) {
	return f.beginUpdateFn(ctx, resourceGroupName, serverName, poolName, parameters, options)
}

func (f *fakeSQLElasticPoolsAPI) BeginDelete(ctx context.Context, resourceGroupName, serverName, poolName string, options *armsql.ElasticPoolsClientBeginDeleteOptions) (*runtime.Poller[armsql.ElasticPoolsClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, resourceGroupName, serverName, poolName, options)
}

func (f *fakeSQLElasticPoolsAPI) NewListByServerPager(resourceGroupName, serverName string, options *armsql.ElasticPoolsClientListByServerOptions) *runtime.Pager[armsql.ElasticPoolsClientListByServerResponse] {
	return f.newListByServerPagerFn(resourceGroupName, serverName, options)
}

func (f *fakeSQLElasticPoolsAPI) NewListServersPager(options *armsql.ServersClientListOptions) *runtime.Pager[armsql.ServersClientListResponse] {
	return f.newListServersPagerFn(options)
}
