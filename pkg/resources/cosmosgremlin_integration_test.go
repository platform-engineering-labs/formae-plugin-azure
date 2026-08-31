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
	testCosmosGremlinDatabaseNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.DocumentDB/databaseAccounts/gremlin-1/gremlinDatabases/social"
	testCosmosGremlinGraphNativeID    = testCosmosGremlinDatabaseNativeID + "/graphs/people"
)

// --- Database ---

func TestCosmosGremlinDatabase_CRUD(t *testing.T) {
	dbResult := armcosmos.GremlinDatabaseGetResults{
		ID:   to.Ptr(testCosmosGremlinDatabaseNativeID),
		Name: to.Ptr("social"),
		Properties: &armcosmos.GremlinDatabaseGetProperties{
			Resource: &armcosmos.GremlinDatabaseGetPropertiesResource{ID: to.Ptr("social")},
		},
	}

	var sent armcosmos.GremlinDatabaseCreateUpdateParameters
	fake := &fakeCosmosGremlinDatabaseAPI{
		createFn: func(_ context.Context, rgName, accountName, dbName string, params armcosmos.GremlinDatabaseCreateUpdateParameters) (*runtime.Poller[armcosmos.GremlinResourcesClientCreateUpdateGremlinDatabaseResponse], error) {
			require.Equal(t, []string{"rg-1", "gremlin-1", "social"}, []string{rgName, accountName, dbName})
			sent = params
			return newDonePoller(armcosmos.GremlinResourcesClientCreateUpdateGremlinDatabaseResponse{GremlinDatabaseGetResults: dbResult}), nil
		},
		getFn: func(_ context.Context, _, _, _ string) (armcosmos.GremlinResourcesClientGetGremlinDatabaseResponse, error) {
			return armcosmos.GremlinResourcesClientGetGremlinDatabaseResponse{GremlinDatabaseGetResults: dbResult}, nil
		},
		throughputFn: func(_ context.Context, _, _, _ string) (armcosmos.GremlinResourcesClientGetGremlinDatabaseThroughputResponse, error) {
			return armcosmos.GremlinResourcesClientGetGremlinDatabaseThroughputResponse{
				ThroughputSettingsGetResults: armcosmos.ThroughputSettingsGetResults{
					Properties: &armcosmos.ThroughputSettingsGetProperties{
						Resource: &armcosmos.ThroughputSettingsGetPropertiesResource{Throughput: to.Ptr(int32(400))},
					},
				},
			}, nil
		},
		deleteFn: func(_ context.Context, _, _, _ string) (*runtime.Poller[armcosmos.GremlinResourcesClientDeleteGremlinDatabaseResponse], error) {
			return newDonePoller(armcosmos.GremlinResourcesClientDeleteGremlinDatabaseResponse{}), nil
		},
		listFn: func(_, _ string) *runtime.Pager[armcosmos.GremlinResourcesClientListGremlinDatabasesResponse] {
			return runtime.NewPager(runtime.PagingHandler[armcosmos.GremlinResourcesClientListGremlinDatabasesResponse]{
				More: func(armcosmos.GremlinResourcesClientListGremlinDatabasesResponse) bool { return false },
				Fetcher: func(context.Context, *armcosmos.GremlinResourcesClientListGremlinDatabasesResponse) (armcosmos.GremlinResourcesClientListGremlinDatabasesResponse, error) {
					return armcosmos.GremlinResourcesClientListGremlinDatabasesResponse{
						GremlinDatabaseListResult: armcosmos.GremlinDatabaseListResult{
							Value: []*armcosmos.GremlinDatabaseGetResults{{ID: to.Ptr(testCosmosGremlinDatabaseNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := &CosmosGremlinDatabase{api: fake, config: &config.Config{SubscriptionId: "sub-1"}}

	desired, _ := json.Marshal(map[string]any{
		"name": "social", "resourceGroupName": "rg-1", "accountName": "gremlin-1", "throughput": 400,
	})

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "social", Properties: desired})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testCosmosGremlinDatabaseNativeID, got.ProgressResult.NativeID)
		require.Equal(t, "social", *sent.Properties.Resource.ID)
		require.EqualValues(t, 400, *sent.Properties.Options.Throughput)
	})

	t.Run("Create_requires_accountName", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "social", "resourceGroupName": "rg-1"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "accountName is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testCosmosGremlinDatabaseNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "social", props["name"])
		require.Equal(t, "gremlin-1", props["accountName"])
		require.EqualValues(t, 400, props["throughput"])
	})

	t.Run("Update_sends_no_throughput_options", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID: testCosmosGremlinDatabaseNativeID, DesiredProperties: desired,
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Nil(t, sent.Properties.Options)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _, _ string) (*runtime.Poller[armcosmos.GremlinResourcesClientDeleteGremlinDatabaseResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testCosmosGremlinDatabaseNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "accountName": "gremlin-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testCosmosGremlinDatabaseNativeID}, got.NativeIDs)
	})
}

func TestCosmosGremlinDatabase_ReadNotFound(t *testing.T) {
	fake := &fakeCosmosGremlinDatabaseAPI{
		getFn: func(_ context.Context, _, _, _ string) (armcosmos.GremlinResourcesClientGetGremlinDatabaseResponse, error) {
			return armcosmos.GremlinResourcesClientGetGremlinDatabaseResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	prov := &CosmosGremlinDatabase{api: fake, config: &config.Config{SubscriptionId: "sub-1"}}
	got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testCosmosGremlinDatabaseNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Graph ---

func cosmosGremlinGraphDesired(extra map[string]any) []byte {
	props := map[string]any{
		"name":              "people",
		"resourceGroupName": "rg-1",
		"accountName":       "gremlin-1",
		"databaseName":      "social",
		"partitionKey": map[string]any{
			"paths": []string{"/region"}, "kind": "Hash", "version": 2,
		},
		"indexingPolicy": map[string]any{
			"automatic":     true,
			"indexingMode":  "consistent",
			"includedPaths": []map[string]any{{"path": "/*"}},
			"excludedPaths": []map[string]any{{"path": `/"_etag"/?`}},
		},
		"conflictResolutionPolicy": map[string]any{
			"mode": "LastWriterWins", "conflictResolutionPath": "/_ts",
		},
		"defaultTtl": 86400,
	}
	for k, v := range extra {
		props[k] = v
	}
	out, _ := json.Marshal(props)
	return out
}

func TestCosmosGremlinGraph_CRUD(t *testing.T) {
	graphResult := armcosmos.GremlinGraphGetResults{
		ID:   to.Ptr(testCosmosGremlinGraphNativeID),
		Name: to.Ptr("people"),
		Properties: &armcosmos.GremlinGraphGetProperties{
			Resource: &armcosmos.GremlinGraphGetPropertiesResource{
				ID:         to.Ptr("people"),
				DefaultTTL: to.Ptr(int32(86400)),
				PartitionKey: &armcosmos.ContainerPartitionKey{
					Paths:     []*string{to.Ptr("/region")},
					Kind:      to.Ptr(armcosmos.PartitionKindHash),
					Version:   to.Ptr(int32(2)),
					SystemKey: to.Ptr(false),
				},
				IndexingPolicy: &armcosmos.IndexingPolicy{
					Automatic:     to.Ptr(true),
					IndexingMode:  to.Ptr(armcosmos.IndexingModeConsistent),
					IncludedPaths: []*armcosmos.IncludedPath{{Path: to.Ptr("/*")}},
					ExcludedPaths: []*armcosmos.ExcludedPath{{Path: to.Ptr(`/"_etag"/?`)}},
				},
				ConflictResolutionPolicy: &armcosmos.ConflictResolutionPolicy{
					Mode:                   to.Ptr(armcosmos.ConflictResolutionModeLastWriterWins),
					ConflictResolutionPath: to.Ptr("/_ts"),
				},
			},
		},
	}

	var sent armcosmos.GremlinGraphCreateUpdateParameters
	fake := &fakeCosmosGremlinGraphAPI{
		createFn: func(_ context.Context, rgName, accountName, dbName, graphName string, params armcosmos.GremlinGraphCreateUpdateParameters) (*runtime.Poller[armcosmos.GremlinResourcesClientCreateUpdateGremlinGraphResponse], error) {
			require.Equal(t, []string{"rg-1", "gremlin-1", "social", "people"},
				[]string{rgName, accountName, dbName, graphName})
			sent = params
			return newDonePoller(armcosmos.GremlinResourcesClientCreateUpdateGremlinGraphResponse{GremlinGraphGetResults: graphResult}), nil
		},
		getFn: func(_ context.Context, _, _, _, _ string) (armcosmos.GremlinResourcesClientGetGremlinGraphResponse, error) {
			return armcosmos.GremlinResourcesClientGetGremlinGraphResponse{GremlinGraphGetResults: graphResult}, nil
		},
		deleteFn: func(_ context.Context, _, _, _, _ string) (*runtime.Poller[armcosmos.GremlinResourcesClientDeleteGremlinGraphResponse], error) {
			return newDonePoller(armcosmos.GremlinResourcesClientDeleteGremlinGraphResponse{}), nil
		},
		listFn: func(_, _, _ string) *runtime.Pager[armcosmos.GremlinResourcesClientListGremlinGraphsResponse] {
			return runtime.NewPager(runtime.PagingHandler[armcosmos.GremlinResourcesClientListGremlinGraphsResponse]{
				More: func(armcosmos.GremlinResourcesClientListGremlinGraphsResponse) bool { return false },
				Fetcher: func(context.Context, *armcosmos.GremlinResourcesClientListGremlinGraphsResponse) (armcosmos.GremlinResourcesClientListGremlinGraphsResponse, error) {
					return armcosmos.GremlinResourcesClientListGremlinGraphsResponse{
						GremlinGraphListResult: armcosmos.GremlinGraphListResult{
							Value: []*armcosmos.GremlinGraphGetResults{{ID: to.Ptr(testCosmosGremlinGraphNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := &CosmosGremlinGraph{api: fake, config: &config.Config{SubscriptionId: "sub-1"}}

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "people", Properties: cosmosGremlinGraphDesired(map[string]any{"throughput": 400}),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testCosmosGremlinGraphNativeID, got.ProgressResult.NativeID)

		res := sent.Properties.Resource
		require.Equal(t, []string{"/region"}, stringsFromPointers(res.PartitionKey.Paths))
		require.Equal(t, armcosmos.IndexingModeConsistent, *res.IndexingPolicy.IndexingMode)
		require.Equal(t, "/_ts", *res.ConflictResolutionPolicy.ConflictResolutionPath)
		require.EqualValues(t, 86400, *res.DefaultTTL)
		require.EqualValues(t, 400, *sent.Properties.Options.Throughput)
	})

	t.Run("Create_requires_a_partitionKey", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "people", "resourceGroupName": "rg-1", "accountName": "gremlin-1", "databaseName": "social",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "partitionKey with at least one path is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testCosmosGremlinGraphNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "people", props["name"])
		require.Equal(t, "social", props["databaseName"])
		require.EqualValues(t, 86400, props["defaultTtl"])

		pk := props["partitionKey"].(map[string]any)
		require.NotContains(t, pk, "systemKey")
		require.Equal(t, "Hash", pk["kind"])

		policy := props["indexingPolicy"].(map[string]any)
		require.Equal(t, "consistent", policy["indexingMode"])
		require.Equal(t, []any{map[string]any{"path": `/"_etag"/?`}}, policy["excludedPaths"])
	})

	t.Run("Update_echoes_the_whole_body_without_options", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testCosmosGremlinGraphNativeID,
			DesiredProperties: cosmosGremlinGraphDesired(map[string]any{"defaultTtl": 3600}),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Nil(t, sent.Properties.Options)
		require.NotNil(t, sent.Properties.Resource.PartitionKey)
		require.NotNil(t, sent.Properties.Resource.IndexingPolicy)
		require.EqualValues(t, 3600, *sent.Properties.Resource.DefaultTTL)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _, _, _ string) (*runtime.Poller[armcosmos.GremlinResourcesClientDeleteGremlinGraphResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testCosmosGremlinGraphNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{
				"resourceGroupName": "rg-1", "accountName": "gremlin-1", "databaseName": "social",
			},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testCosmosGremlinGraphNativeID}, got.NativeIDs)
	})
}

func TestCosmosGremlinGraph_ReadNotFound(t *testing.T) {
	fake := &fakeCosmosGremlinGraphAPI{
		getFn: func(_ context.Context, _, _, _, _ string) (armcosmos.GremlinResourcesClientGetGremlinGraphResponse, error) {
			return armcosmos.GremlinResourcesClientGetGremlinGraphResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	prov := &CosmosGremlinGraph{api: fake, config: &config.Config{SubscriptionId: "sub-1"}}
	got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testCosmosGremlinGraphNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeCosmosGremlinDatabaseAPI struct {
	createFn     func(ctx context.Context, rgName, accountName, dbName string, params armcosmos.GremlinDatabaseCreateUpdateParameters) (*runtime.Poller[armcosmos.GremlinResourcesClientCreateUpdateGremlinDatabaseResponse], error)
	getFn        func(ctx context.Context, rgName, accountName, dbName string) (armcosmos.GremlinResourcesClientGetGremlinDatabaseResponse, error)
	throughputFn func(ctx context.Context, rgName, accountName, dbName string) (armcosmos.GremlinResourcesClientGetGremlinDatabaseThroughputResponse, error)
	deleteFn     func(ctx context.Context, rgName, accountName, dbName string) (*runtime.Poller[armcosmos.GremlinResourcesClientDeleteGremlinDatabaseResponse], error)
	listFn       func(rgName, accountName string) *runtime.Pager[armcosmos.GremlinResourcesClientListGremlinDatabasesResponse]
}

func (f *fakeCosmosGremlinDatabaseAPI) BeginCreateUpdateGremlinDatabase(ctx context.Context, rgName, accountName, dbName string, params armcosmos.GremlinDatabaseCreateUpdateParameters, _ *armcosmos.GremlinResourcesClientBeginCreateUpdateGremlinDatabaseOptions) (*runtime.Poller[armcosmos.GremlinResourcesClientCreateUpdateGremlinDatabaseResponse], error) {
	return f.createFn(ctx, rgName, accountName, dbName, params)
}

func (f *fakeCosmosGremlinDatabaseAPI) GetGremlinDatabase(ctx context.Context, rgName, accountName, dbName string, _ *armcosmos.GremlinResourcesClientGetGremlinDatabaseOptions) (armcosmos.GremlinResourcesClientGetGremlinDatabaseResponse, error) {
	return f.getFn(ctx, rgName, accountName, dbName)
}

func (f *fakeCosmosGremlinDatabaseAPI) GetGremlinDatabaseThroughput(ctx context.Context, rgName, accountName, dbName string, _ *armcosmos.GremlinResourcesClientGetGremlinDatabaseThroughputOptions) (armcosmos.GremlinResourcesClientGetGremlinDatabaseThroughputResponse, error) {
	if f.throughputFn == nil {
		return armcosmos.GremlinResourcesClientGetGremlinDatabaseThroughputResponse{}, &azcore.ResponseError{StatusCode: 404}
	}
	return f.throughputFn(ctx, rgName, accountName, dbName)
}

func (f *fakeCosmosGremlinDatabaseAPI) BeginDeleteGremlinDatabase(ctx context.Context, rgName, accountName, dbName string, _ *armcosmos.GremlinResourcesClientBeginDeleteGremlinDatabaseOptions) (*runtime.Poller[armcosmos.GremlinResourcesClientDeleteGremlinDatabaseResponse], error) {
	return f.deleteFn(ctx, rgName, accountName, dbName)
}

func (f *fakeCosmosGremlinDatabaseAPI) NewListGremlinDatabasesPager(rgName, accountName string, _ *armcosmos.GremlinResourcesClientListGremlinDatabasesOptions) *runtime.Pager[armcosmos.GremlinResourcesClientListGremlinDatabasesResponse] {
	return f.listFn(rgName, accountName)
}

type fakeCosmosGremlinGraphAPI struct {
	createFn     func(ctx context.Context, rgName, accountName, dbName, graphName string, params armcosmos.GremlinGraphCreateUpdateParameters) (*runtime.Poller[armcosmos.GremlinResourcesClientCreateUpdateGremlinGraphResponse], error)
	getFn        func(ctx context.Context, rgName, accountName, dbName, graphName string) (armcosmos.GremlinResourcesClientGetGremlinGraphResponse, error)
	throughputFn func(ctx context.Context, rgName, accountName, dbName, graphName string) (armcosmos.GremlinResourcesClientGetGremlinGraphThroughputResponse, error)
	deleteFn     func(ctx context.Context, rgName, accountName, dbName, graphName string) (*runtime.Poller[armcosmos.GremlinResourcesClientDeleteGremlinGraphResponse], error)
	listFn       func(rgName, accountName, dbName string) *runtime.Pager[armcosmos.GremlinResourcesClientListGremlinGraphsResponse]
}

func (f *fakeCosmosGremlinGraphAPI) BeginCreateUpdateGremlinGraph(ctx context.Context, rgName, accountName, dbName, graphName string, params armcosmos.GremlinGraphCreateUpdateParameters, _ *armcosmos.GremlinResourcesClientBeginCreateUpdateGremlinGraphOptions) (*runtime.Poller[armcosmos.GremlinResourcesClientCreateUpdateGremlinGraphResponse], error) {
	return f.createFn(ctx, rgName, accountName, dbName, graphName, params)
}

func (f *fakeCosmosGremlinGraphAPI) GetGremlinGraph(ctx context.Context, rgName, accountName, dbName, graphName string, _ *armcosmos.GremlinResourcesClientGetGremlinGraphOptions) (armcosmos.GremlinResourcesClientGetGremlinGraphResponse, error) {
	return f.getFn(ctx, rgName, accountName, dbName, graphName)
}

func (f *fakeCosmosGremlinGraphAPI) GetGremlinGraphThroughput(ctx context.Context, rgName, accountName, dbName, graphName string, _ *armcosmos.GremlinResourcesClientGetGremlinGraphThroughputOptions) (armcosmos.GremlinResourcesClientGetGremlinGraphThroughputResponse, error) {
	if f.throughputFn == nil {
		return armcosmos.GremlinResourcesClientGetGremlinGraphThroughputResponse{}, &azcore.ResponseError{StatusCode: 404}
	}
	return f.throughputFn(ctx, rgName, accountName, dbName, graphName)
}

func (f *fakeCosmosGremlinGraphAPI) BeginDeleteGremlinGraph(ctx context.Context, rgName, accountName, dbName, graphName string, _ *armcosmos.GremlinResourcesClientBeginDeleteGremlinGraphOptions) (*runtime.Poller[armcosmos.GremlinResourcesClientDeleteGremlinGraphResponse], error) {
	return f.deleteFn(ctx, rgName, accountName, dbName, graphName)
}

func (f *fakeCosmosGremlinGraphAPI) NewListGremlinGraphsPager(rgName, accountName, dbName string, _ *armcosmos.GremlinResourcesClientListGremlinGraphsOptions) *runtime.Pager[armcosmos.GremlinResourcesClientListGremlinGraphsResponse] {
	return f.listFn(rgName, accountName, dbName)
}
