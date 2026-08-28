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

const testCosmosMongoCollectionNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.DocumentDB/databaseAccounts/mongo-1/mongodbDatabases/catalog/collections/products"

func newTestCosmosMongoCollection(api cosmosMongoCollectionAPI) *CosmosMongoCollection {
	return &CosmosMongoCollection{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

func cosmosMongoCollectionDesired(extra map[string]any) []byte {
	props := map[string]any{
		"name":              "products",
		"resourceGroupName": "rg-1",
		"accountName":       "mongo-1",
		"databaseName":      "catalog",
		// Entity-set rendering of ARM's shardKey map.
		"shardKey": []map[string]string{{"Key": "/sku", "Value": "Hash"}},
		"indexes": []map[string]any{
			{"keys": []string{"_id"}},
			{"keys": []string{"sku"}, "unique": true},
		},
	}
	for k, v := range extra {
		props[k] = v
	}
	out, _ := json.Marshal(props)
	return out
}

func TestCosmosMongoCollection_CRUD(t *testing.T) {
	collectionResult := armcosmos.MongoDBCollectionGetResults{
		ID:   to.Ptr(testCosmosMongoCollectionNativeID),
		Name: to.Ptr("products"),
		Properties: &armcosmos.MongoDBCollectionGetProperties{
			Resource: &armcosmos.MongoDBCollectionGetPropertiesResource{
				ID:       to.Ptr("products"),
				ShardKey: map[string]*string{"/sku": to.Ptr("Hash")},
				Indexes: []*armcosmos.MongoIndex{
					{Key: &armcosmos.MongoIndexKeys{Keys: []*string{to.Ptr("_id")}}},
					{
						Key:     &armcosmos.MongoIndexKeys{Keys: []*string{to.Ptr("sku")}},
						Options: &armcosmos.MongoIndexOptions{Unique: to.Ptr(true)},
					},
				},
			},
		},
	}

	var sent armcosmos.MongoDBCollectionCreateUpdateParameters
	fake := &fakeCosmosMongoCollectionAPI{
		createFn: func(_ context.Context, rgName, accountName, dbName, collectionName string, params armcosmos.MongoDBCollectionCreateUpdateParameters) (*runtime.Poller[armcosmos.MongoDBResourcesClientCreateUpdateMongoDBCollectionResponse], error) {
			require.Equal(t, []string{"rg-1", "mongo-1", "catalog", "products"},
				[]string{rgName, accountName, dbName, collectionName})
			sent = params
			return newDonePoller(armcosmos.MongoDBResourcesClientCreateUpdateMongoDBCollectionResponse{MongoDBCollectionGetResults: collectionResult}), nil
		},
		getFn: func(_ context.Context, _, _, _, _ string) (armcosmos.MongoDBResourcesClientGetMongoDBCollectionResponse, error) {
			return armcosmos.MongoDBResourcesClientGetMongoDBCollectionResponse{MongoDBCollectionGetResults: collectionResult}, nil
		},
		deleteFn: func(_ context.Context, _, _, _, _ string) (*runtime.Poller[armcosmos.MongoDBResourcesClientDeleteMongoDBCollectionResponse], error) {
			return newDonePoller(armcosmos.MongoDBResourcesClientDeleteMongoDBCollectionResponse{}), nil
		},
		listFn: func(_, _, _ string) *runtime.Pager[armcosmos.MongoDBResourcesClientListMongoDBCollectionsResponse] {
			return runtime.NewPager(runtime.PagingHandler[armcosmos.MongoDBResourcesClientListMongoDBCollectionsResponse]{
				More: func(armcosmos.MongoDBResourcesClientListMongoDBCollectionsResponse) bool { return false },
				Fetcher: func(context.Context, *armcosmos.MongoDBResourcesClientListMongoDBCollectionsResponse) (armcosmos.MongoDBResourcesClientListMongoDBCollectionsResponse, error) {
					return armcosmos.MongoDBResourcesClientListMongoDBCollectionsResponse{
						MongoDBCollectionListResult: armcosmos.MongoDBCollectionListResult{
							Value: []*armcosmos.MongoDBCollectionGetResults{{ID: to.Ptr(testCosmosMongoCollectionNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestCosmosMongoCollection(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "products", Properties: cosmosMongoCollectionDesired(map[string]any{"throughput": 400}),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testCosmosMongoCollectionNativeID, got.ProgressResult.NativeID)

		res := sent.Properties.Resource
		require.Equal(t, "products", *res.ID)
		require.Equal(t, "Hash", *res.ShardKey["/sku"])
		require.Len(t, res.Indexes, 2)
		require.Equal(t, []string{"_id"}, stringsFromPointers(res.Indexes[0].Key.Keys))
		require.Nil(t, res.Indexes[0].Options)
		require.True(t, *res.Indexes[1].Options.Unique)
		require.EqualValues(t, 400, *sent.Properties.Options.Throughput)
	})

	// ARM only accepts "Hash" for a shard-key value, so a caller may write just the
	// path and get it defaulted.
	t.Run("Create_defaults_the_shard_key_value", func(t *testing.T) {
		_, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "products",
			Properties: cosmosMongoCollectionDesired(map[string]any{"shardKey": []map[string]string{{"Key": "/sku"}}}),
		})
		require.NoError(t, err)
		require.Equal(t, "Hash", *sent.Properties.Resource.ShardKey["/sku"])
	})

	t.Run("Create_requires_databaseName", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "products", "resourceGroupName": "rg-1", "accountName": "mongo-1",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "databaseName is required")
	})

	t.Run("Read_round_trips_shardKey_and_indexes", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testCosmosMongoCollectionNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "products", props["name"])
		require.Equal(t, "catalog", props["databaseName"])
		require.Equal(t, []any{map[string]any{"Key": "/sku", "Value": "Hash"}}, props["shardKey"])

		indexes := props["indexes"].([]any)
		require.Len(t, indexes, 2)
		require.Equal(t, []any{"_id"}, indexes[0].(map[string]any)["keys"])
		require.NotContains(t, indexes[0].(map[string]any), "unique")
		require.Equal(t, true, indexes[1].(map[string]any)["unique"])
	})

	// The shard key has to be echoed on update: a PUT that omits it asks ARM to
	// unshard the collection.
	t.Run("Update_echoes_the_shard_key_and_sends_no_options", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID: testCosmosMongoCollectionNativeID,
			DesiredProperties: cosmosMongoCollectionDesired(map[string]any{
				"indexes": []map[string]any{{"keys": []string{"_id"}}},
			}),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Nil(t, sent.Properties.Options)
		require.Equal(t, "Hash", *sent.Properties.Resource.ShardKey["/sku"])
		require.Len(t, sent.Properties.Resource.Indexes, 1)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _, _, _ string) (*runtime.Poller[armcosmos.MongoDBResourcesClientDeleteMongoDBCollectionResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testCosmosMongoCollectionNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{
				"resourceGroupName": "rg-1", "accountName": "mongo-1", "databaseName": "catalog",
			},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testCosmosMongoCollectionNativeID}, got.NativeIDs)
	})
}

func TestCosmosMongoCollection_ReadNotFound(t *testing.T) {
	fake := &fakeCosmosMongoCollectionAPI{
		getFn: func(_ context.Context, _, _, _, _ string) (armcosmos.MongoDBResourcesClientGetMongoDBCollectionResponse, error) {
			return armcosmos.MongoDBResourcesClientGetMongoDBCollectionResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestCosmosMongoCollection(fake).Read(context.Background(),
		&resource.ReadRequest{NativeID: testCosmosMongoCollectionNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeCosmosMongoCollectionAPI struct {
	createFn     func(ctx context.Context, rgName, accountName, dbName, collectionName string, params armcosmos.MongoDBCollectionCreateUpdateParameters) (*runtime.Poller[armcosmos.MongoDBResourcesClientCreateUpdateMongoDBCollectionResponse], error)
	getFn        func(ctx context.Context, rgName, accountName, dbName, collectionName string) (armcosmos.MongoDBResourcesClientGetMongoDBCollectionResponse, error)
	throughputFn func(ctx context.Context, rgName, accountName, dbName, collectionName string) (armcosmos.MongoDBResourcesClientGetMongoDBCollectionThroughputResponse, error)
	deleteFn     func(ctx context.Context, rgName, accountName, dbName, collectionName string) (*runtime.Poller[armcosmos.MongoDBResourcesClientDeleteMongoDBCollectionResponse], error)
	listFn       func(rgName, accountName, dbName string) *runtime.Pager[armcosmos.MongoDBResourcesClientListMongoDBCollectionsResponse]
}

func (f *fakeCosmosMongoCollectionAPI) BeginCreateUpdateMongoDBCollection(ctx context.Context, rgName, accountName, dbName, collectionName string, params armcosmos.MongoDBCollectionCreateUpdateParameters, _ *armcosmos.MongoDBResourcesClientBeginCreateUpdateMongoDBCollectionOptions) (*runtime.Poller[armcosmos.MongoDBResourcesClientCreateUpdateMongoDBCollectionResponse], error) {
	return f.createFn(ctx, rgName, accountName, dbName, collectionName, params)
}

func (f *fakeCosmosMongoCollectionAPI) GetMongoDBCollection(ctx context.Context, rgName, accountName, dbName, collectionName string, _ *armcosmos.MongoDBResourcesClientGetMongoDBCollectionOptions) (armcosmos.MongoDBResourcesClientGetMongoDBCollectionResponse, error) {
	return f.getFn(ctx, rgName, accountName, dbName, collectionName)
}

func (f *fakeCosmosMongoCollectionAPI) GetMongoDBCollectionThroughput(ctx context.Context, rgName, accountName, dbName, collectionName string, _ *armcosmos.MongoDBResourcesClientGetMongoDBCollectionThroughputOptions) (armcosmos.MongoDBResourcesClientGetMongoDBCollectionThroughputResponse, error) {
	if f.throughputFn == nil {
		return armcosmos.MongoDBResourcesClientGetMongoDBCollectionThroughputResponse{}, &azcore.ResponseError{StatusCode: 404}
	}
	return f.throughputFn(ctx, rgName, accountName, dbName, collectionName)
}

func (f *fakeCosmosMongoCollectionAPI) BeginDeleteMongoDBCollection(ctx context.Context, rgName, accountName, dbName, collectionName string, _ *armcosmos.MongoDBResourcesClientBeginDeleteMongoDBCollectionOptions) (*runtime.Poller[armcosmos.MongoDBResourcesClientDeleteMongoDBCollectionResponse], error) {
	return f.deleteFn(ctx, rgName, accountName, dbName, collectionName)
}

func (f *fakeCosmosMongoCollectionAPI) NewListMongoDBCollectionsPager(rgName, accountName, dbName string, _ *armcosmos.MongoDBResourcesClientListMongoDBCollectionsOptions) *runtime.Pager[armcosmos.MongoDBResourcesClientListMongoDBCollectionsResponse] {
	return f.listFn(rgName, accountName, dbName)
}
