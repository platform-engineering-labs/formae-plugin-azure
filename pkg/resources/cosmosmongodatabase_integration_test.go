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

const testCosmosMongoDatabaseNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.DocumentDB/databaseAccounts/mongo-1/mongodbDatabases/catalog"

func newTestCosmosMongoDatabase(api cosmosMongoDatabaseAPI) *CosmosMongoDatabase {
	return &CosmosMongoDatabase{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

func TestCosmosMongoDatabase_CRUD(t *testing.T) {
	dbResult := armcosmos.MongoDBDatabaseGetResults{
		ID:   to.Ptr(testCosmosMongoDatabaseNativeID),
		Name: to.Ptr("catalog"),
		Properties: &armcosmos.MongoDBDatabaseGetProperties{
			Resource: &armcosmos.MongoDBDatabaseGetPropertiesResource{ID: to.Ptr("catalog")},
		},
	}

	var sent armcosmos.MongoDBDatabaseCreateUpdateParameters
	fake := &fakeCosmosMongoDatabaseAPI{
		createFn: func(_ context.Context, rgName, accountName, dbName string, params armcosmos.MongoDBDatabaseCreateUpdateParameters) (*runtime.Poller[armcosmos.MongoDBResourcesClientCreateUpdateMongoDBDatabaseResponse], error) {
			require.Equal(t, []string{"rg-1", "mongo-1", "catalog"}, []string{rgName, accountName, dbName})
			sent = params
			return newDonePoller(armcosmos.MongoDBResourcesClientCreateUpdateMongoDBDatabaseResponse{MongoDBDatabaseGetResults: dbResult}), nil
		},
		getFn: func(_ context.Context, _, _, _ string) (armcosmos.MongoDBResourcesClientGetMongoDBDatabaseResponse, error) {
			return armcosmos.MongoDBResourcesClientGetMongoDBDatabaseResponse{MongoDBDatabaseGetResults: dbResult}, nil
		},
		throughputFn: func(_ context.Context, _, _, _ string) (armcosmos.MongoDBResourcesClientGetMongoDBDatabaseThroughputResponse, error) {
			return armcosmos.MongoDBResourcesClientGetMongoDBDatabaseThroughputResponse{
				ThroughputSettingsGetResults: armcosmos.ThroughputSettingsGetResults{
					Properties: &armcosmos.ThroughputSettingsGetProperties{
						Resource: &armcosmos.ThroughputSettingsGetPropertiesResource{
							AutoscaleSettings: &armcosmos.AutoscaleSettingsResource{MaxThroughput: to.Ptr(int32(1000))},
						},
					},
				},
			}, nil
		},
		deleteFn: func(_ context.Context, _, _, _ string) (*runtime.Poller[armcosmos.MongoDBResourcesClientDeleteMongoDBDatabaseResponse], error) {
			return newDonePoller(armcosmos.MongoDBResourcesClientDeleteMongoDBDatabaseResponse{}), nil
		},
		listFn: func(_, _ string) *runtime.Pager[armcosmos.MongoDBResourcesClientListMongoDBDatabasesResponse] {
			return runtime.NewPager(runtime.PagingHandler[armcosmos.MongoDBResourcesClientListMongoDBDatabasesResponse]{
				More: func(armcosmos.MongoDBResourcesClientListMongoDBDatabasesResponse) bool { return false },
				Fetcher: func(context.Context, *armcosmos.MongoDBResourcesClientListMongoDBDatabasesResponse) (armcosmos.MongoDBResourcesClientListMongoDBDatabasesResponse, error) {
					return armcosmos.MongoDBResourcesClientListMongoDBDatabasesResponse{
						MongoDBDatabaseListResult: armcosmos.MongoDBDatabaseListResult{
							Value: []*armcosmos.MongoDBDatabaseGetResults{{ID: to.Ptr(testCosmosMongoDatabaseNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestCosmosMongoDatabase(fake)

	desired := func(extra map[string]any) []byte {
		props := map[string]any{"name": "catalog", "resourceGroupName": "rg-1", "accountName": "mongo-1"}
		for k, v := range extra {
			props[k] = v
		}
		out, _ := json.Marshal(props)
		return out
	}

	t.Run("Create_with_autoscale", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "catalog", Properties: desired(map[string]any{"autoscaleMaxThroughput": 1000}),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testCosmosMongoDatabaseNativeID, got.ProgressResult.NativeID)
		require.Equal(t, "catalog", *sent.Properties.Resource.ID)
		require.EqualValues(t, 1000, *sent.Properties.Options.AutoscaleSettings.MaxThroughput)

		var props map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &props))
		require.EqualValues(t, 1000, props["autoscaleMaxThroughput"])
		require.NotContains(t, props, "throughput")
	})

	t.Run("Create_requires_accountName", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "catalog", "resourceGroupName": "rg-1"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "accountName is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testCosmosMongoDatabaseNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "catalog", props["name"])
		require.Equal(t, "mongo-1", props["accountName"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
	})

	// A SQL-database ARM ID must not parse as a Mongo database.
	t.Run("Read_rejects_a_foreign_ARM_ID", func(t *testing.T) {
		_, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testCosmosSqlDatabaseNativeID})
		require.ErrorContains(t, err, "is not a databaseAccounts/mongodbDatabases")
	})

	t.Run("Update_sends_no_throughput_options", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testCosmosMongoDatabaseNativeID,
			DesiredProperties: desired(map[string]any{"autoscaleMaxThroughput": 4000}),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Nil(t, sent.Properties.Options)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _, _ string) (*runtime.Poller[armcosmos.MongoDBResourcesClientDeleteMongoDBDatabaseResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testCosmosMongoDatabaseNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "accountName": "mongo-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testCosmosMongoDatabaseNativeID}, got.NativeIDs)
	})
}

func TestCosmosMongoDatabase_ReadNotFound(t *testing.T) {
	fake := &fakeCosmosMongoDatabaseAPI{
		getFn: func(_ context.Context, _, _, _ string) (armcosmos.MongoDBResourcesClientGetMongoDBDatabaseResponse, error) {
			return armcosmos.MongoDBResourcesClientGetMongoDBDatabaseResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestCosmosMongoDatabase(fake).Read(context.Background(),
		&resource.ReadRequest{NativeID: testCosmosMongoDatabaseNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeCosmosMongoDatabaseAPI struct {
	createFn     func(ctx context.Context, rgName, accountName, dbName string, params armcosmos.MongoDBDatabaseCreateUpdateParameters) (*runtime.Poller[armcosmos.MongoDBResourcesClientCreateUpdateMongoDBDatabaseResponse], error)
	getFn        func(ctx context.Context, rgName, accountName, dbName string) (armcosmos.MongoDBResourcesClientGetMongoDBDatabaseResponse, error)
	throughputFn func(ctx context.Context, rgName, accountName, dbName string) (armcosmos.MongoDBResourcesClientGetMongoDBDatabaseThroughputResponse, error)
	deleteFn     func(ctx context.Context, rgName, accountName, dbName string) (*runtime.Poller[armcosmos.MongoDBResourcesClientDeleteMongoDBDatabaseResponse], error)
	listFn       func(rgName, accountName string) *runtime.Pager[armcosmos.MongoDBResourcesClientListMongoDBDatabasesResponse]
}

func (f *fakeCosmosMongoDatabaseAPI) BeginCreateUpdateMongoDBDatabase(ctx context.Context, rgName, accountName, dbName string, params armcosmos.MongoDBDatabaseCreateUpdateParameters, _ *armcosmos.MongoDBResourcesClientBeginCreateUpdateMongoDBDatabaseOptions) (*runtime.Poller[armcosmos.MongoDBResourcesClientCreateUpdateMongoDBDatabaseResponse], error) {
	return f.createFn(ctx, rgName, accountName, dbName, params)
}

func (f *fakeCosmosMongoDatabaseAPI) GetMongoDBDatabase(ctx context.Context, rgName, accountName, dbName string, _ *armcosmos.MongoDBResourcesClientGetMongoDBDatabaseOptions) (armcosmos.MongoDBResourcesClientGetMongoDBDatabaseResponse, error) {
	return f.getFn(ctx, rgName, accountName, dbName)
}

func (f *fakeCosmosMongoDatabaseAPI) GetMongoDBDatabaseThroughput(ctx context.Context, rgName, accountName, dbName string, _ *armcosmos.MongoDBResourcesClientGetMongoDBDatabaseThroughputOptions) (armcosmos.MongoDBResourcesClientGetMongoDBDatabaseThroughputResponse, error) {
	if f.throughputFn == nil {
		return armcosmos.MongoDBResourcesClientGetMongoDBDatabaseThroughputResponse{}, &azcore.ResponseError{StatusCode: 404}
	}
	return f.throughputFn(ctx, rgName, accountName, dbName)
}

func (f *fakeCosmosMongoDatabaseAPI) BeginDeleteMongoDBDatabase(ctx context.Context, rgName, accountName, dbName string, _ *armcosmos.MongoDBResourcesClientBeginDeleteMongoDBDatabaseOptions) (*runtime.Poller[armcosmos.MongoDBResourcesClientDeleteMongoDBDatabaseResponse], error) {
	return f.deleteFn(ctx, rgName, accountName, dbName)
}

func (f *fakeCosmosMongoDatabaseAPI) NewListMongoDBDatabasesPager(rgName, accountName string, _ *armcosmos.MongoDBResourcesClientListMongoDBDatabasesOptions) *runtime.Pager[armcosmos.MongoDBResourcesClientListMongoDBDatabasesResponse] {
	return f.listFn(rgName, accountName)
}
