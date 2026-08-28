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

const (
	testCosmosCassandraKeyspaceNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.DocumentDB/databaseAccounts/cassandra-1/cassandraKeyspaces/telemetry"
	testCosmosCassandraTableNativeID    = testCosmosCassandraKeyspaceNativeID + "/tables/readings"
)

// --- Keyspace ---

func TestCosmosCassandraKeyspace_CRUD(t *testing.T) {
	keyspaceResult := armcosmos.CassandraKeyspaceGetResults{
		ID:   to.Ptr(testCosmosCassandraKeyspaceNativeID),
		Name: to.Ptr("telemetry"),
		Properties: &armcosmos.CassandraKeyspaceGetProperties{
			Resource: &armcosmos.CassandraKeyspaceGetPropertiesResource{ID: to.Ptr("telemetry")},
		},
	}

	var sent armcosmos.CassandraKeyspaceCreateUpdateParameters
	fake := &fakeCosmosCassandraKeyspaceAPI{
		createFn: func(_ context.Context, rgName, accountName, keyspaceName string, params armcosmos.CassandraKeyspaceCreateUpdateParameters) (*runtime.Poller[armcosmos.CassandraResourcesClientCreateUpdateCassandraKeyspaceResponse], error) {
			require.Equal(t, []string{"rg-1", "cassandra-1", "telemetry"}, []string{rgName, accountName, keyspaceName})
			sent = params
			return newDonePoller(armcosmos.CassandraResourcesClientCreateUpdateCassandraKeyspaceResponse{CassandraKeyspaceGetResults: keyspaceResult}), nil
		},
		getFn: func(_ context.Context, _, _, _ string) (armcosmos.CassandraResourcesClientGetCassandraKeyspaceResponse, error) {
			return armcosmos.CassandraResourcesClientGetCassandraKeyspaceResponse{CassandraKeyspaceGetResults: keyspaceResult}, nil
		},
		throughputFn: func(_ context.Context, _, _, _ string) (armcosmos.CassandraResourcesClientGetCassandraKeyspaceThroughputResponse, error) {
			return armcosmos.CassandraResourcesClientGetCassandraKeyspaceThroughputResponse{
				ThroughputSettingsGetResults: armcosmos.ThroughputSettingsGetResults{
					Properties: &armcosmos.ThroughputSettingsGetProperties{
						Resource: &armcosmos.ThroughputSettingsGetPropertiesResource{Throughput: to.Ptr(int32(400))},
					},
				},
			}, nil
		},
		deleteFn: func(_ context.Context, _, _, _ string) (*runtime.Poller[armcosmos.CassandraResourcesClientDeleteCassandraKeyspaceResponse], error) {
			return newDonePoller(armcosmos.CassandraResourcesClientDeleteCassandraKeyspaceResponse{}), nil
		},
		listFn: func(_, _ string) *runtime.Pager[armcosmos.CassandraResourcesClientListCassandraKeyspacesResponse] {
			return runtime.NewPager(runtime.PagingHandler[armcosmos.CassandraResourcesClientListCassandraKeyspacesResponse]{
				More: func(armcosmos.CassandraResourcesClientListCassandraKeyspacesResponse) bool { return false },
				Fetcher: func(context.Context, *armcosmos.CassandraResourcesClientListCassandraKeyspacesResponse) (armcosmos.CassandraResourcesClientListCassandraKeyspacesResponse, error) {
					return armcosmos.CassandraResourcesClientListCassandraKeyspacesResponse{
						CassandraKeyspaceListResult: armcosmos.CassandraKeyspaceListResult{
							Value: []*armcosmos.CassandraKeyspaceGetResults{{ID: to.Ptr(testCosmosCassandraKeyspaceNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := &CosmosCassandraKeyspace{api: fake, config: &config.Config{SubscriptionId: "sub-1"}}

	desired, _ := json.Marshal(map[string]any{
		"name": "telemetry", "resourceGroupName": "rg-1", "accountName": "cassandra-1", "throughput": 400,
	})

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "telemetry", Properties: desired})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testCosmosCassandraKeyspaceNativeID, got.ProgressResult.NativeID)
		require.Equal(t, "telemetry", *sent.Properties.Resource.ID)
		require.EqualValues(t, 400, *sent.Properties.Options.Throughput)
	})

	t.Run("Create_requires_accountName", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "telemetry", "resourceGroupName": "rg-1"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "accountName is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testCosmosCassandraKeyspaceNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "telemetry", props["name"])
		require.Equal(t, "cassandra-1", props["accountName"])
		require.EqualValues(t, 400, props["throughput"])
	})

	t.Run("Update_sends_no_throughput_options", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID: testCosmosCassandraKeyspaceNativeID, DesiredProperties: desired,
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Nil(t, sent.Properties.Options)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _, _ string) (*runtime.Poller[armcosmos.CassandraResourcesClientDeleteCassandraKeyspaceResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testCosmosCassandraKeyspaceNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "accountName": "cassandra-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testCosmosCassandraKeyspaceNativeID}, got.NativeIDs)
	})
}

func TestCosmosCassandraKeyspace_ReadNotFound(t *testing.T) {
	fake := &fakeCosmosCassandraKeyspaceAPI{
		getFn: func(_ context.Context, _, _, _ string) (armcosmos.CassandraResourcesClientGetCassandraKeyspaceResponse, error) {
			return armcosmos.CassandraResourcesClientGetCassandraKeyspaceResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	prov := &CosmosCassandraKeyspace{api: fake, config: &config.Config{SubscriptionId: "sub-1"}}
	got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testCosmosCassandraKeyspaceNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Table ---

func cosmosCassandraTableDesired(extra map[string]any) []byte {
	props := map[string]any{
		"name":              "readings",
		"resourceGroupName": "rg-1",
		"accountName":       "cassandra-1",
		"keyspaceName":      "telemetry",
		"schema": map[string]any{
			"columns": []map[string]any{
				{"name": "device_id", "type": "uuid"},
				{"name": "recorded_at", "type": "timestamp"},
				{"name": "value", "type": "double"},
			},
			"partitionKeys": []map[string]any{{"name": "device_id"}},
			"clusterKeys":   []map[string]any{{"name": "recorded_at", "orderBy": "Desc"}},
		},
		"defaultTtl": 86400,
	}
	for k, v := range extra {
		props[k] = v
	}
	out, _ := json.Marshal(props)
	return out
}

func TestCosmosCassandraTable_CRUD(t *testing.T) {
	tableResult := armcosmos.CassandraTableGetResults{
		ID:   to.Ptr(testCosmosCassandraTableNativeID),
		Name: to.Ptr("readings"),
		Properties: &armcosmos.CassandraTableGetProperties{
			Resource: &armcosmos.CassandraTableGetPropertiesResource{
				ID:         to.Ptr("readings"),
				DefaultTTL: to.Ptr(int32(86400)),
				Schema: &armcosmos.CassandraSchema{
					Columns: []*armcosmos.Column{
						{Name: to.Ptr("device_id"), Type: to.Ptr("uuid")},
						{Name: to.Ptr("recorded_at"), Type: to.Ptr("timestamp")},
						{Name: to.Ptr("value"), Type: to.Ptr("double")},
					},
					PartitionKeys: []*armcosmos.CassandraPartitionKey{{Name: to.Ptr("device_id")}},
					ClusterKeys:   []*armcosmos.ClusterKey{{Name: to.Ptr("recorded_at"), OrderBy: to.Ptr("Desc")}},
				},
			},
		},
	}

	var sent armcosmos.CassandraTableCreateUpdateParameters
	fake := &fakeCosmosCassandraTableAPI{
		createFn: func(_ context.Context, rgName, accountName, keyspaceName, tableName string, params armcosmos.CassandraTableCreateUpdateParameters) (*runtime.Poller[armcosmos.CassandraResourcesClientCreateUpdateCassandraTableResponse], error) {
			require.Equal(t, []string{"rg-1", "cassandra-1", "telemetry", "readings"},
				[]string{rgName, accountName, keyspaceName, tableName})
			sent = params
			return newDonePoller(armcosmos.CassandraResourcesClientCreateUpdateCassandraTableResponse{CassandraTableGetResults: tableResult}), nil
		},
		getFn: func(_ context.Context, _, _, _, _ string) (armcosmos.CassandraResourcesClientGetCassandraTableResponse, error) {
			return armcosmos.CassandraResourcesClientGetCassandraTableResponse{CassandraTableGetResults: tableResult}, nil
		},
		deleteFn: func(_ context.Context, _, _, _, _ string) (*runtime.Poller[armcosmos.CassandraResourcesClientDeleteCassandraTableResponse], error) {
			return newDonePoller(armcosmos.CassandraResourcesClientDeleteCassandraTableResponse{}), nil
		},
		listFn: func(_, _, _ string) *runtime.Pager[armcosmos.CassandraResourcesClientListCassandraTablesResponse] {
			return runtime.NewPager(runtime.PagingHandler[armcosmos.CassandraResourcesClientListCassandraTablesResponse]{
				More: func(armcosmos.CassandraResourcesClientListCassandraTablesResponse) bool { return false },
				Fetcher: func(context.Context, *armcosmos.CassandraResourcesClientListCassandraTablesResponse) (armcosmos.CassandraResourcesClientListCassandraTablesResponse, error) {
					return armcosmos.CassandraResourcesClientListCassandraTablesResponse{
						CassandraTableListResult: armcosmos.CassandraTableListResult{
							Value: []*armcosmos.CassandraTableGetResults{{ID: to.Ptr(testCosmosCassandraTableNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := &CosmosCassandraTable{api: fake, config: &config.Config{SubscriptionId: "sub-1"}}

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "readings", Properties: cosmosCassandraTableDesired(map[string]any{"throughput": 400}),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testCosmosCassandraTableNativeID, got.ProgressResult.NativeID)

		schema := sent.Properties.Resource.Schema
		require.Len(t, schema.Columns, 3)
		require.Equal(t, "uuid", *schema.Columns[0].Type)
		require.Equal(t, "device_id", *schema.PartitionKeys[0].Name)
		require.Equal(t, "Desc", *schema.ClusterKeys[0].OrderBy)
		require.EqualValues(t, 86400, *sent.Properties.Resource.DefaultTTL)
		require.EqualValues(t, 400, *sent.Properties.Options.Throughput)
	})

	t.Run("Create_requires_a_schema", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "readings", "resourceGroupName": "rg-1", "accountName": "cassandra-1", "keyspaceName": "telemetry",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "schema with at least one column and one partitionKey is required")
	})

	t.Run("Create_requires_keyspaceName", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "readings", "resourceGroupName": "rg-1", "accountName": "cassandra-1",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "keyspaceName is required")
	})

	t.Run("Read_round_trips_the_schema", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testCosmosCassandraTableNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "readings", props["name"])
		require.Equal(t, "telemetry", props["keyspaceName"])
		require.EqualValues(t, 86400, props["defaultTtl"])

		schema := props["schema"].(map[string]any)
		require.Len(t, schema["columns"].([]any), 3)
		require.Equal(t, []any{map[string]any{"name": "device_id"}}, schema["partitionKeys"])
		require.Equal(t, []any{map[string]any{"name": "recorded_at", "orderBy": "Desc"}}, schema["clusterKeys"])
	})

	// ARM has been observed echoing "desc"; the read path must fold it onto the
	// schema's spelling.
	t.Run("Read_canonicalizes_cluster_key_order", func(t *testing.T) {
		odd := tableResult
		odd.Properties = &armcosmos.CassandraTableGetProperties{
			Resource: &armcosmos.CassandraTableGetPropertiesResource{
				ID: to.Ptr("readings"),
				Schema: &armcosmos.CassandraSchema{
					ClusterKeys: []*armcosmos.ClusterKey{{Name: to.Ptr("recorded_at"), OrderBy: to.Ptr("desc")}},
				},
			},
		}
		fake.getFn = func(_ context.Context, _, _, _, _ string) (armcosmos.CassandraResourcesClientGetCassandraTableResponse, error) {
			return armcosmos.CassandraResourcesClientGetCassandraTableResponse{CassandraTableGetResults: odd}, nil
		}
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testCosmosCassandraTableNativeID})
		require.NoError(t, err)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		clusterKeys := props["schema"].(map[string]any)["clusterKeys"].([]any)
		require.Equal(t, "Desc", clusterKeys[0].(map[string]any)["orderBy"])
	})

	t.Run("Update_changes_defaultTtl_without_options", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testCosmosCassandraTableNativeID,
			DesiredProperties: cosmosCassandraTableDesired(map[string]any{"defaultTtl": 3600}),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Nil(t, sent.Properties.Options)
		require.EqualValues(t, 3600, *sent.Properties.Resource.DefaultTTL)
		require.Len(t, sent.Properties.Resource.Schema.Columns, 3)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _, _, _ string) (*runtime.Poller[armcosmos.CassandraResourcesClientDeleteCassandraTableResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testCosmosCassandraTableNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{
				"resourceGroupName": "rg-1", "accountName": "cassandra-1", "keyspaceName": "telemetry",
			},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testCosmosCassandraTableNativeID}, got.NativeIDs)
	})
}

func TestCosmosCassandraTable_ReadNotFound(t *testing.T) {
	fake := &fakeCosmosCassandraTableAPI{
		getFn: func(_ context.Context, _, _, _, _ string) (armcosmos.CassandraResourcesClientGetCassandraTableResponse, error) {
			return armcosmos.CassandraResourcesClientGetCassandraTableResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	prov := &CosmosCassandraTable{api: fake, config: &config.Config{SubscriptionId: "sub-1"}}
	got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testCosmosCassandraTableNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeCosmosCassandraKeyspaceAPI struct {
	createFn     func(ctx context.Context, rgName, accountName, keyspaceName string, params armcosmos.CassandraKeyspaceCreateUpdateParameters) (*runtime.Poller[armcosmos.CassandraResourcesClientCreateUpdateCassandraKeyspaceResponse], error)
	getFn        func(ctx context.Context, rgName, accountName, keyspaceName string) (armcosmos.CassandraResourcesClientGetCassandraKeyspaceResponse, error)
	throughputFn func(ctx context.Context, rgName, accountName, keyspaceName string) (armcosmos.CassandraResourcesClientGetCassandraKeyspaceThroughputResponse, error)
	deleteFn     func(ctx context.Context, rgName, accountName, keyspaceName string) (*runtime.Poller[armcosmos.CassandraResourcesClientDeleteCassandraKeyspaceResponse], error)
	listFn       func(rgName, accountName string) *runtime.Pager[armcosmos.CassandraResourcesClientListCassandraKeyspacesResponse]
}

func (f *fakeCosmosCassandraKeyspaceAPI) BeginCreateUpdateCassandraKeyspace(ctx context.Context, rgName, accountName, keyspaceName string, params armcosmos.CassandraKeyspaceCreateUpdateParameters, _ *armcosmos.CassandraResourcesClientBeginCreateUpdateCassandraKeyspaceOptions) (*runtime.Poller[armcosmos.CassandraResourcesClientCreateUpdateCassandraKeyspaceResponse], error) {
	return f.createFn(ctx, rgName, accountName, keyspaceName, params)
}

func (f *fakeCosmosCassandraKeyspaceAPI) GetCassandraKeyspace(ctx context.Context, rgName, accountName, keyspaceName string, _ *armcosmos.CassandraResourcesClientGetCassandraKeyspaceOptions) (armcosmos.CassandraResourcesClientGetCassandraKeyspaceResponse, error) {
	return f.getFn(ctx, rgName, accountName, keyspaceName)
}

func (f *fakeCosmosCassandraKeyspaceAPI) GetCassandraKeyspaceThroughput(ctx context.Context, rgName, accountName, keyspaceName string, _ *armcosmos.CassandraResourcesClientGetCassandraKeyspaceThroughputOptions) (armcosmos.CassandraResourcesClientGetCassandraKeyspaceThroughputResponse, error) {
	if f.throughputFn == nil {
		return armcosmos.CassandraResourcesClientGetCassandraKeyspaceThroughputResponse{}, &azcore.ResponseError{StatusCode: 404}
	}
	return f.throughputFn(ctx, rgName, accountName, keyspaceName)
}

func (f *fakeCosmosCassandraKeyspaceAPI) BeginDeleteCassandraKeyspace(ctx context.Context, rgName, accountName, keyspaceName string, _ *armcosmos.CassandraResourcesClientBeginDeleteCassandraKeyspaceOptions) (*runtime.Poller[armcosmos.CassandraResourcesClientDeleteCassandraKeyspaceResponse], error) {
	return f.deleteFn(ctx, rgName, accountName, keyspaceName)
}

func (f *fakeCosmosCassandraKeyspaceAPI) NewListCassandraKeyspacesPager(rgName, accountName string, _ *armcosmos.CassandraResourcesClientListCassandraKeyspacesOptions) *runtime.Pager[armcosmos.CassandraResourcesClientListCassandraKeyspacesResponse] {
	return f.listFn(rgName, accountName)
}

type fakeCosmosCassandraTableAPI struct {
	createFn     func(ctx context.Context, rgName, accountName, keyspaceName, tableName string, params armcosmos.CassandraTableCreateUpdateParameters) (*runtime.Poller[armcosmos.CassandraResourcesClientCreateUpdateCassandraTableResponse], error)
	getFn        func(ctx context.Context, rgName, accountName, keyspaceName, tableName string) (armcosmos.CassandraResourcesClientGetCassandraTableResponse, error)
	throughputFn func(ctx context.Context, rgName, accountName, keyspaceName, tableName string) (armcosmos.CassandraResourcesClientGetCassandraTableThroughputResponse, error)
	deleteFn     func(ctx context.Context, rgName, accountName, keyspaceName, tableName string) (*runtime.Poller[armcosmos.CassandraResourcesClientDeleteCassandraTableResponse], error)
	listFn       func(rgName, accountName, keyspaceName string) *runtime.Pager[armcosmos.CassandraResourcesClientListCassandraTablesResponse]
}

func (f *fakeCosmosCassandraTableAPI) BeginCreateUpdateCassandraTable(ctx context.Context, rgName, accountName, keyspaceName, tableName string, params armcosmos.CassandraTableCreateUpdateParameters, _ *armcosmos.CassandraResourcesClientBeginCreateUpdateCassandraTableOptions) (*runtime.Poller[armcosmos.CassandraResourcesClientCreateUpdateCassandraTableResponse], error) {
	return f.createFn(ctx, rgName, accountName, keyspaceName, tableName, params)
}

func (f *fakeCosmosCassandraTableAPI) GetCassandraTable(ctx context.Context, rgName, accountName, keyspaceName, tableName string, _ *armcosmos.CassandraResourcesClientGetCassandraTableOptions) (armcosmos.CassandraResourcesClientGetCassandraTableResponse, error) {
	return f.getFn(ctx, rgName, accountName, keyspaceName, tableName)
}

func (f *fakeCosmosCassandraTableAPI) GetCassandraTableThroughput(ctx context.Context, rgName, accountName, keyspaceName, tableName string, _ *armcosmos.CassandraResourcesClientGetCassandraTableThroughputOptions) (armcosmos.CassandraResourcesClientGetCassandraTableThroughputResponse, error) {
	if f.throughputFn == nil {
		return armcosmos.CassandraResourcesClientGetCassandraTableThroughputResponse{}, &azcore.ResponseError{StatusCode: 404}
	}
	return f.throughputFn(ctx, rgName, accountName, keyspaceName, tableName)
}

func (f *fakeCosmosCassandraTableAPI) BeginDeleteCassandraTable(ctx context.Context, rgName, accountName, keyspaceName, tableName string, _ *armcosmos.CassandraResourcesClientBeginDeleteCassandraTableOptions) (*runtime.Poller[armcosmos.CassandraResourcesClientDeleteCassandraTableResponse], error) {
	return f.deleteFn(ctx, rgName, accountName, keyspaceName, tableName)
}

func (f *fakeCosmosCassandraTableAPI) NewListCassandraTablesPager(rgName, accountName, keyspaceName string, _ *armcosmos.CassandraResourcesClientListCassandraTablesOptions) *runtime.Pager[armcosmos.CassandraResourcesClientListCassandraTablesResponse] {
	return f.listFn(rgName, accountName, keyspaceName)
}
