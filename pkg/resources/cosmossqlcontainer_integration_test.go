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

const testCosmosSqlContainerNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.DocumentDB/databaseAccounts/cosmos-1/sqlDatabases/inventory/containers/items"

func newTestCosmosSqlContainer(api cosmosSQLContainerAPI) *CosmosSqlContainer {
	return &CosmosSqlContainer{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

// cosmosSqlContainerDesired mirrors the shape a fixture produces: a full indexing
// policy including the `/"_etag"/?` exclusion ARM always adds.
func cosmosSqlContainerDesired(extra map[string]any) []byte {
	props := map[string]any{
		"name":              "items",
		"resourceGroupName": "rg-1",
		"accountName":       "cosmos-1",
		"databaseName":      "inventory",
		"partitionKey": map[string]any{
			"paths":   []string{"/customerId"},
			"kind":    "Hash",
			"version": 2,
		},
		"indexingPolicy": map[string]any{
			"automatic":     true,
			"indexingMode":  "consistent",
			"includedPaths": []map[string]any{{"path": "/*"}},
			"excludedPaths": []map[string]any{{"path": `/"_etag"/?`}},
			"compositeIndexes": [][]map[string]any{
				{{"path": "/name", "order": "ascending"}, {"path": "/age", "order": "descending"}},
			},
		},
		"uniqueKeyPolicy": map[string]any{
			"uniqueKeys": []map[string]any{{"paths": []string{"/email"}}},
		},
		"conflictResolutionPolicy": map[string]any{
			"mode":                   "LastWriterWins",
			"conflictResolutionPath": "/_ts",
		},
		"defaultTtl": 86400,
	}
	for k, v := range extra {
		props[k] = v
	}
	out, _ := json.Marshal(props)
	return out
}

func TestCosmosSqlContainer_CRUD(t *testing.T) {
	containerResult := armcosmos.SQLContainerGetResults{
		ID:   to.Ptr(testCosmosSqlContainerNativeID),
		Name: to.Ptr("items"),
		Properties: &armcosmos.SQLContainerGetProperties{
			Resource: &armcosmos.SQLContainerGetPropertiesResource{
				ID:         to.Ptr("items"),
				DefaultTTL: to.Ptr(int32(86400)),
				PartitionKey: &armcosmos.ContainerPartitionKey{
					Paths:   []*string{to.Ptr("/customerId")},
					Kind:    to.Ptr(armcosmos.PartitionKindHash),
					Version: to.Ptr(int32(2)),
					// Service-assigned and nested: must not surface as a property.
					SystemKey: to.Ptr(false),
				},
				IndexingPolicy: &armcosmos.IndexingPolicy{
					Automatic:     to.Ptr(true),
					IndexingMode:  to.Ptr(armcosmos.IndexingModeConsistent),
					IncludedPaths: []*armcosmos.IncludedPath{{Path: to.Ptr("/*")}},
					ExcludedPaths: []*armcosmos.ExcludedPath{{Path: to.Ptr(`/"_etag"/?`)}},
					CompositeIndexes: [][]*armcosmos.CompositePath{{
						{Path: to.Ptr("/name"), Order: to.Ptr(armcosmos.CompositePathSortOrderAscending)},
						{Path: to.Ptr("/age"), Order: to.Ptr(armcosmos.CompositePathSortOrderDescending)},
					}},
				},
				UniqueKeyPolicy: &armcosmos.UniqueKeyPolicy{
					UniqueKeys: []*armcosmos.UniqueKey{{Paths: []*string{to.Ptr("/email")}}},
				},
				ConflictResolutionPolicy: &armcosmos.ConflictResolutionPolicy{
					Mode:                        to.Ptr(armcosmos.ConflictResolutionModeLastWriterWins),
					ConflictResolutionPath:      to.Ptr("/_ts"),
					ConflictResolutionProcedure: to.Ptr(""),
				},
			},
		},
	}

	var sent armcosmos.SQLContainerCreateUpdateParameters
	fake := &fakeCosmosSQLContainerAPI{
		createFn: func(_ context.Context, rgName, accountName, dbName, containerName string, params armcosmos.SQLContainerCreateUpdateParameters) (*runtime.Poller[armcosmos.SQLResourcesClientCreateUpdateSQLContainerResponse], error) {
			require.Equal(t, []string{"rg-1", "cosmos-1", "inventory", "items"},
				[]string{rgName, accountName, dbName, containerName})
			sent = params
			return newDonePoller(armcosmos.SQLResourcesClientCreateUpdateSQLContainerResponse{SQLContainerGetResults: containerResult}), nil
		},
		getFn: func(_ context.Context, _, _, _, _ string) (armcosmos.SQLResourcesClientGetSQLContainerResponse, error) {
			return armcosmos.SQLResourcesClientGetSQLContainerResponse{SQLContainerGetResults: containerResult}, nil
		},
		throughputFn: func(_ context.Context, _, _, _, _ string) (armcosmos.SQLResourcesClientGetSQLContainerThroughputResponse, error) {
			return armcosmos.SQLResourcesClientGetSQLContainerThroughputResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
		deleteFn: func(_ context.Context, _, _, _, _ string) (*runtime.Poller[armcosmos.SQLResourcesClientDeleteSQLContainerResponse], error) {
			return newDonePoller(armcosmos.SQLResourcesClientDeleteSQLContainerResponse{}), nil
		},
		listFn: func(_, _, _ string) *runtime.Pager[armcosmos.SQLResourcesClientListSQLContainersResponse] {
			return runtime.NewPager(runtime.PagingHandler[armcosmos.SQLResourcesClientListSQLContainersResponse]{
				More: func(armcosmos.SQLResourcesClientListSQLContainersResponse) bool { return false },
				Fetcher: func(context.Context, *armcosmos.SQLResourcesClientListSQLContainersResponse) (armcosmos.SQLResourcesClientListSQLContainersResponse, error) {
					return armcosmos.SQLResourcesClientListSQLContainersResponse{
						SQLContainerListResult: armcosmos.SQLContainerListResult{
							Value: []*armcosmos.SQLContainerGetResults{{ID: to.Ptr(testCosmosSqlContainerNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestCosmosSqlContainer(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "items", Properties: cosmosSqlContainerDesired(map[string]any{"throughput": 400}),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testCosmosSqlContainerNativeID, got.ProgressResult.NativeID)

		res := sent.Properties.Resource
		require.Equal(t, "items", *res.ID)
		require.Equal(t, []string{"/customerId"}, stringsFromPointers(res.PartitionKey.Paths))
		require.Equal(t, armcosmos.PartitionKindHash, *res.PartitionKey.Kind)
		require.EqualValues(t, 2, *res.PartitionKey.Version)
		require.Equal(t, armcosmos.IndexingModeConsistent, *res.IndexingPolicy.IndexingMode)
		require.Len(t, res.IndexingPolicy.CompositeIndexes, 1)
		require.Len(t, res.IndexingPolicy.CompositeIndexes[0], 2)
		require.Equal(t, armcosmos.CompositePathSortOrderDescending, *res.IndexingPolicy.CompositeIndexes[0][1].Order)
		require.Equal(t, []string{"/email"}, stringsFromPointers(res.UniqueKeyPolicy.UniqueKeys[0].Paths))
		require.Equal(t, "/_ts", *res.ConflictResolutionPolicy.ConflictResolutionPath)
		require.EqualValues(t, 86400, *res.DefaultTTL)
		require.EqualValues(t, 400, *sent.Properties.Options.Throughput)
	})

	t.Run("Create_requires_a_partitionKey", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "items", "resourceGroupName": "rg-1", "accountName": "cosmos-1", "databaseName": "inventory",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "partitionKey with at least one path is required")
	})

	t.Run("Create_requires_databaseName", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "items", "resourceGroupName": "rg-1", "accountName": "cosmos-1",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "databaseName is required")
	})

	t.Run("Read_round_trips_every_policy", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testCosmosSqlContainerNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "items", props["name"])
		require.Equal(t, "inventory", props["databaseName"])
		require.Equal(t, "cosmos-1", props["accountName"])
		require.EqualValues(t, 86400, props["defaultTtl"])

		// SystemKey is service-assigned and nested: emitting it would read as
		// permanent drift, because hasProviderDefault only covers top-level fields.
		pk := props["partitionKey"].(map[string]any)
		require.NotContains(t, pk, "systemKey")
		require.Equal(t, []any{"/customerId"}, pk["paths"])
		require.Equal(t, "Hash", pk["kind"])

		policy := props["indexingPolicy"].(map[string]any)
		require.Equal(t, "consistent", policy["indexingMode"])
		require.Equal(t, []any{map[string]any{"path": "/*"}}, policy["includedPaths"])
		require.Equal(t, []any{map[string]any{"path": `/"_etag"/?`}}, policy["excludedPaths"])
		composites := policy["compositeIndexes"].([]any)
		require.Len(t, composites, 1)
		require.Len(t, composites[0].([]any), 2)

		// ARM echoes conflictResolutionProcedure as "" for LastWriterWins; that must
		// not surface as a declared-but-empty field.
		conflict := props["conflictResolutionPolicy"].(map[string]any)
		require.Equal(t, "LastWriterWins", conflict["mode"])
		require.Equal(t, "/_ts", conflict["conflictResolutionPath"])
		require.NotContains(t, conflict, "conflictResolutionProcedure")

		unique := props["uniqueKeyPolicy"].(map[string]any)
		require.Equal(t, []any{map[string]any{"paths": []any{"/email"}}}, unique["uniqueKeys"])
	})

	// ARM returns enum casings inconsistently; the read path must fold them onto the
	// schema's spelling or [Verify] compares "Consistent" against "consistent".
	t.Run("Read_canonicalizes_enum_casing", func(t *testing.T) {
		odd := containerResult
		odd.Properties = &armcosmos.SQLContainerGetProperties{
			Resource: &armcosmos.SQLContainerGetPropertiesResource{
				ID:             to.Ptr("items"),
				PartitionKey:   &armcosmos.ContainerPartitionKey{Kind: to.Ptr(armcosmos.PartitionKind("hash"))},
				IndexingPolicy: &armcosmos.IndexingPolicy{IndexingMode: to.Ptr(armcosmos.IndexingMode("Consistent"))},
			},
		}
		fake.getFn = func(_ context.Context, _, _, _, _ string) (armcosmos.SQLResourcesClientGetSQLContainerResponse, error) {
			return armcosmos.SQLResourcesClientGetSQLContainerResponse{SQLContainerGetResults: odd}, nil
		}
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testCosmosSqlContainerNativeID})
		require.NoError(t, err)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "Hash", props["partitionKey"].(map[string]any)["kind"])
		require.Equal(t, "consistent", props["indexingPolicy"].(map[string]any)["indexingMode"])

		fake.getFn = func(_ context.Context, _, _, _, _ string) (armcosmos.SQLResourcesClientGetSQLContainerResponse, error) {
			return armcosmos.SQLResourcesClientGetSQLContainerResponse{SQLContainerGetResults: containerResult}, nil
		}
	})

	// A PUT that omits a policy resets it to the service default, so the whole body
	// has to be echoed on update — but never the throughput options.
	t.Run("Update_echoes_the_whole_body_without_options", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testCosmosSqlContainerNativeID,
			DesiredProperties: cosmosSqlContainerDesired(map[string]any{"defaultTtl": 3600, "throughput": 400}),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Nil(t, sent.Properties.Options)
		require.NotNil(t, sent.Properties.Resource.PartitionKey)
		require.NotNil(t, sent.Properties.Resource.IndexingPolicy)
		require.EqualValues(t, 3600, *sent.Properties.Resource.DefaultTTL)
	})

	t.Run("Delete", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testCosmosSqlContainerNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _, _, _ string) (*runtime.Poller[armcosmos.SQLResourcesClientDeleteSQLContainerResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testCosmosSqlContainerNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{
				"resourceGroupName": "rg-1", "accountName": "cosmos-1", "databaseName": "inventory",
			},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testCosmosSqlContainerNativeID}, got.NativeIDs)
	})
}

func TestCosmosSqlContainer_ReadNotFound(t *testing.T) {
	fake := &fakeCosmosSQLContainerAPI{
		getFn: func(_ context.Context, _, _, _, _ string) (armcosmos.SQLResourcesClientGetSQLContainerResponse, error) {
			return armcosmos.SQLResourcesClientGetSQLContainerResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestCosmosSqlContainer(fake).Read(context.Background(), &resource.ReadRequest{NativeID: testCosmosSqlContainerNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeCosmosSQLContainerAPI struct {
	createFn     func(ctx context.Context, rgName, accountName, dbName, containerName string, params armcosmos.SQLContainerCreateUpdateParameters) (*runtime.Poller[armcosmos.SQLResourcesClientCreateUpdateSQLContainerResponse], error)
	getFn        func(ctx context.Context, rgName, accountName, dbName, containerName string) (armcosmos.SQLResourcesClientGetSQLContainerResponse, error)
	throughputFn func(ctx context.Context, rgName, accountName, dbName, containerName string) (armcosmos.SQLResourcesClientGetSQLContainerThroughputResponse, error)
	deleteFn     func(ctx context.Context, rgName, accountName, dbName, containerName string) (*runtime.Poller[armcosmos.SQLResourcesClientDeleteSQLContainerResponse], error)
	listFn       func(rgName, accountName, dbName string) *runtime.Pager[armcosmos.SQLResourcesClientListSQLContainersResponse]
}

func (f *fakeCosmosSQLContainerAPI) BeginCreateUpdateSQLContainer(ctx context.Context, rgName, accountName, dbName, containerName string, params armcosmos.SQLContainerCreateUpdateParameters, _ *armcosmos.SQLResourcesClientBeginCreateUpdateSQLContainerOptions) (*runtime.Poller[armcosmos.SQLResourcesClientCreateUpdateSQLContainerResponse], error) {
	return f.createFn(ctx, rgName, accountName, dbName, containerName, params)
}

func (f *fakeCosmosSQLContainerAPI) GetSQLContainer(ctx context.Context, rgName, accountName, dbName, containerName string, _ *armcosmos.SQLResourcesClientGetSQLContainerOptions) (armcosmos.SQLResourcesClientGetSQLContainerResponse, error) {
	return f.getFn(ctx, rgName, accountName, dbName, containerName)
}

func (f *fakeCosmosSQLContainerAPI) GetSQLContainerThroughput(ctx context.Context, rgName, accountName, dbName, containerName string, _ *armcosmos.SQLResourcesClientGetSQLContainerThroughputOptions) (armcosmos.SQLResourcesClientGetSQLContainerThroughputResponse, error) {
	if f.throughputFn == nil {
		return armcosmos.SQLResourcesClientGetSQLContainerThroughputResponse{}, &azcore.ResponseError{StatusCode: 404}
	}
	return f.throughputFn(ctx, rgName, accountName, dbName, containerName)
}

func (f *fakeCosmosSQLContainerAPI) BeginDeleteSQLContainer(ctx context.Context, rgName, accountName, dbName, containerName string, _ *armcosmos.SQLResourcesClientBeginDeleteSQLContainerOptions) (*runtime.Poller[armcosmos.SQLResourcesClientDeleteSQLContainerResponse], error) {
	return f.deleteFn(ctx, rgName, accountName, dbName, containerName)
}

func (f *fakeCosmosSQLContainerAPI) NewListSQLContainersPager(rgName, accountName, dbName string, _ *armcosmos.SQLResourcesClientListSQLContainersOptions) *runtime.Pager[armcosmos.SQLResourcesClientListSQLContainersResponse] {
	return f.listFn(rgName, accountName, dbName)
}
