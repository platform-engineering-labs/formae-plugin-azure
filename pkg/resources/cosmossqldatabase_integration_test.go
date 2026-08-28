// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/cosmos/armcosmos/v3"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testCosmosSqlDatabaseNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.DocumentDB/databaseAccounts/cosmos-1/sqlDatabases/inventory"

func newTestCosmosSqlDatabase(api cosmosSQLDatabaseAPI) *CosmosSqlDatabase {
	return &CosmosSqlDatabase{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

func TestCosmosSqlDatabase_CRUD(t *testing.T) {
	dbResult := armcosmos.SQLDatabaseGetResults{
		ID:   to.Ptr(testCosmosSqlDatabaseNativeID),
		Name: to.Ptr("inventory"),
		Properties: &armcosmos.SQLDatabaseGetProperties{
			Resource: &armcosmos.SQLDatabaseGetPropertiesResource{ID: to.Ptr("inventory")},
		},
	}

	var sent armcosmos.SQLDatabaseCreateUpdateParameters
	fake := &fakeCosmosSQLDatabaseAPI{
		createFn: func(_ context.Context, rgName, accountName, dbName string, params armcosmos.SQLDatabaseCreateUpdateParameters) (*runtime.Poller[armcosmos.SQLResourcesClientCreateUpdateSQLDatabaseResponse], error) {
			require.Equal(t, "rg-1", rgName)
			require.Equal(t, "cosmos-1", accountName)
			require.Equal(t, "inventory", dbName)
			sent = params
			return newDonePoller(armcosmos.SQLResourcesClientCreateUpdateSQLDatabaseResponse{SQLDatabaseGetResults: dbResult}), nil
		},
		getFn: func(_ context.Context, _, _, _ string) (armcosmos.SQLResourcesClientGetSQLDatabaseResponse, error) {
			return armcosmos.SQLResourcesClientGetSQLDatabaseResponse{SQLDatabaseGetResults: dbResult}, nil
		},
		throughputFn: func(_ context.Context, _, _, _ string) (armcosmos.SQLResourcesClientGetSQLDatabaseThroughputResponse, error) {
			return armcosmos.SQLResourcesClientGetSQLDatabaseThroughputResponse{
				ThroughputSettingsGetResults: armcosmos.ThroughputSettingsGetResults{
					Properties: &armcosmos.ThroughputSettingsGetProperties{
						Resource: &armcosmos.ThroughputSettingsGetPropertiesResource{Throughput: to.Ptr(int32(400))},
					},
				},
			}, nil
		},
		deleteFn: func(_ context.Context, _, _, _ string) (*runtime.Poller[armcosmos.SQLResourcesClientDeleteSQLDatabaseResponse], error) {
			return newDonePoller(armcosmos.SQLResourcesClientDeleteSQLDatabaseResponse{}), nil
		},
		listFn: func(_, _ string) *runtime.Pager[armcosmos.SQLResourcesClientListSQLDatabasesResponse] {
			return newCosmosSQLDatabasePager(testCosmosSqlDatabaseNativeID)
		},
	}
	prov := newTestCosmosSqlDatabase(fake)

	desired := func(extra map[string]any) []byte {
		props := map[string]any{
			"name":              "inventory",
			"resourceGroupName": "rg-1",
			"accountName":       "cosmos-1",
		}
		for k, v := range extra {
			props[k] = v
		}
		out, _ := json.Marshal(props)
		return out
	}

	t.Run("Create_with_manual_throughput", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "inventory", Properties: desired(map[string]any{"throughput": 400}),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testCosmosSqlDatabaseNativeID, got.ProgressResult.NativeID)

		require.Equal(t, "inventory", *sent.Properties.Resource.ID)
		require.EqualValues(t, 400, *sent.Properties.Options.Throughput)
		require.Nil(t, sent.Properties.Options.AutoscaleSettings)

		var props map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &props))
		require.EqualValues(t, 400, props["throughput"])
		require.Equal(t, "cosmos-1", props["accountName"])
	})

	// ARM takes throughput or autoscaleSettings, never both.
	t.Run("Create_with_autoscale", func(t *testing.T) {
		_, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "inventory", Properties: desired(map[string]any{"autoscaleMaxThroughput": 1000}),
		})
		require.NoError(t, err)
		require.Nil(t, sent.Properties.Options.Throughput)
		require.EqualValues(t, 1000, *sent.Properties.Options.AutoscaleSettings.MaxThroughput)
	})

	t.Run("Create_rejects_both_throughput_modes", func(t *testing.T) {
		_, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "inventory",
			Properties: desired(map[string]any{
				"throughput": 400, "autoscaleMaxThroughput": 1000,
			}),
		})
		require.ErrorContains(t, err, "mutually exclusive")
	})

	// A serverless account or a container inside a shared-throughput database has
	// no options block at all.
	t.Run("Create_without_throughput_sends_no_options", func(t *testing.T) {
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "inventory", Properties: desired(nil)})
		require.NoError(t, err)
		require.Nil(t, sent.Properties.Options)
	})

	t.Run("Create_requires_accountName", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "inventory", "resourceGroupName": "rg-1"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "accountName is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testCosmosSqlDatabaseNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "inventory", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "cosmos-1", props["accountName"])
		require.EqualValues(t, 400, props["throughput"])
	})

	// An autoscale resource reports both the ceiling and the current RU/s; only the
	// ceiling round-trips against desired state.
	t.Run("Read_autoscale_omits_current_throughput", func(t *testing.T) {
		fake.throughputFn = func(_ context.Context, _, _, _ string) (armcosmos.SQLResourcesClientGetSQLDatabaseThroughputResponse, error) {
			return armcosmos.SQLResourcesClientGetSQLDatabaseThroughputResponse{
				ThroughputSettingsGetResults: armcosmos.ThroughputSettingsGetResults{
					Properties: &armcosmos.ThroughputSettingsGetProperties{
						Resource: &armcosmos.ThroughputSettingsGetPropertiesResource{
							Throughput:        to.Ptr(int32(100)),
							AutoscaleSettings: &armcosmos.AutoscaleSettingsResource{MaxThroughput: to.Ptr(int32(1000))},
						},
					},
				},
			}, nil
		}
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testCosmosSqlDatabaseNativeID})
		require.NoError(t, err)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.EqualValues(t, 1000, props["autoscaleMaxThroughput"])
		require.NotContains(t, props, "throughput")
	})

	// Serverless accounts answer 400 and a shared-throughput database answers 404;
	// neither is a read failure.
	t.Run("Read_tolerates_missing_throughput", func(t *testing.T) {
		fake.throughputFn = func(_ context.Context, _, _, _ string) (armcosmos.SQLResourcesClientGetSQLDatabaseThroughputResponse, error) {
			return armcosmos.SQLResourcesClientGetSQLDatabaseThroughputResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testCosmosSqlDatabaseNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.NotContains(t, props, "throughput")
		require.NotContains(t, props, "autoscaleMaxThroughput")
	})

	t.Run("Read_rejects_a_foreign_ARM_ID", func(t *testing.T) {
		_, err := prov.Read(context.Background(), &resource.ReadRequest{
			NativeID: "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.DocumentDB/databaseAccounts/cosmos-1/mongodbDatabases/inventory",
		})
		require.ErrorContains(t, err, "is not a databaseAccounts/sqlDatabases")
	})

	// throughput is createOnly, so an update must not carry an options block: ARM
	// only honours it at create time and sending it would silently do nothing.
	t.Run("Update_sends_no_throughput_options", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testCosmosSqlDatabaseNativeID,
			DesiredProperties: desired(map[string]any{"throughput": 800}),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testCosmosSqlDatabaseNativeID, got.ProgressResult.NativeID)
		require.Nil(t, sent.Properties.Options)
		require.Equal(t, "inventory", *sent.Properties.Resource.ID)
	})

	t.Run("Delete", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testCosmosSqlDatabaseNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _, _ string) (*runtime.Poller[armcosmos.SQLResourcesClientDeleteSQLDatabaseResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testCosmosSqlDatabaseNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "accountName": "cosmos-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testCosmosSqlDatabaseNativeID}, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.createFn = func(_ context.Context, _, _, _ string, _ armcosmos.SQLDatabaseCreateUpdateParameters) (*runtime.Poller[armcosmos.SQLResourcesClientCreateUpdateSQLDatabaseResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 409}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "inventory", Properties: desired(nil)})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

func TestCosmosSqlDatabase_ReadNotFound(t *testing.T) {
	fake := &fakeCosmosSQLDatabaseAPI{
		getFn: func(_ context.Context, _, _, _ string) (armcosmos.SQLResourcesClientGetSQLDatabaseResponse, error) {
			return armcosmos.SQLResourcesClientGetSQLDatabaseResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestCosmosSqlDatabase(fake).Read(context.Background(), &resource.ReadRequest{NativeID: testCosmosSqlDatabaseNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

func newCosmosSQLDatabasePager(ids ...string) *runtime.Pager[armcosmos.SQLResourcesClientListSQLDatabasesResponse] {
	values := make([]*armcosmos.SQLDatabaseGetResults, 0, len(ids))
	for _, id := range ids {
		values = append(values, &armcosmos.SQLDatabaseGetResults{ID: to.Ptr(id)})
	}
	return runtime.NewPager(runtime.PagingHandler[armcosmos.SQLResourcesClientListSQLDatabasesResponse]{
		More: func(armcosmos.SQLResourcesClientListSQLDatabasesResponse) bool { return false },
		Fetcher: func(context.Context, *armcosmos.SQLResourcesClientListSQLDatabasesResponse) (armcosmos.SQLResourcesClientListSQLDatabasesResponse, error) {
			return armcosmos.SQLResourcesClientListSQLDatabasesResponse{
				SQLDatabaseListResult: armcosmos.SQLDatabaseListResult{Value: values},
			}, nil
		},
	})
}

type fakeCosmosSQLDatabaseAPI struct {
	createFn     func(ctx context.Context, rgName, accountName, dbName string, params armcosmos.SQLDatabaseCreateUpdateParameters) (*runtime.Poller[armcosmos.SQLResourcesClientCreateUpdateSQLDatabaseResponse], error)
	getFn        func(ctx context.Context, rgName, accountName, dbName string) (armcosmos.SQLResourcesClientGetSQLDatabaseResponse, error)
	throughputFn func(ctx context.Context, rgName, accountName, dbName string) (armcosmos.SQLResourcesClientGetSQLDatabaseThroughputResponse, error)
	deleteFn     func(ctx context.Context, rgName, accountName, dbName string) (*runtime.Poller[armcosmos.SQLResourcesClientDeleteSQLDatabaseResponse], error)
	listFn       func(rgName, accountName string) *runtime.Pager[armcosmos.SQLResourcesClientListSQLDatabasesResponse]
}

func (f *fakeCosmosSQLDatabaseAPI) BeginCreateUpdateSQLDatabase(ctx context.Context, rgName, accountName, dbName string, params armcosmos.SQLDatabaseCreateUpdateParameters, _ *armcosmos.SQLResourcesClientBeginCreateUpdateSQLDatabaseOptions) (*runtime.Poller[armcosmos.SQLResourcesClientCreateUpdateSQLDatabaseResponse], error) {
	return f.createFn(ctx, rgName, accountName, dbName, params)
}

func (f *fakeCosmosSQLDatabaseAPI) GetSQLDatabase(ctx context.Context, rgName, accountName, dbName string, _ *armcosmos.SQLResourcesClientGetSQLDatabaseOptions) (armcosmos.SQLResourcesClientGetSQLDatabaseResponse, error) {
	return f.getFn(ctx, rgName, accountName, dbName)
}

func (f *fakeCosmosSQLDatabaseAPI) GetSQLDatabaseThroughput(ctx context.Context, rgName, accountName, dbName string, _ *armcosmos.SQLResourcesClientGetSQLDatabaseThroughputOptions) (armcosmos.SQLResourcesClientGetSQLDatabaseThroughputResponse, error) {
	if f.throughputFn == nil {
		return armcosmos.SQLResourcesClientGetSQLDatabaseThroughputResponse{}, fmt.Errorf("no throughput")
	}
	return f.throughputFn(ctx, rgName, accountName, dbName)
}

func (f *fakeCosmosSQLDatabaseAPI) BeginDeleteSQLDatabase(ctx context.Context, rgName, accountName, dbName string, _ *armcosmos.SQLResourcesClientBeginDeleteSQLDatabaseOptions) (*runtime.Poller[armcosmos.SQLResourcesClientDeleteSQLDatabaseResponse], error) {
	return f.deleteFn(ctx, rgName, accountName, dbName)
}

func (f *fakeCosmosSQLDatabaseAPI) NewListSQLDatabasesPager(rgName, accountName string, _ *armcosmos.SQLResourcesClientListSQLDatabasesOptions) *runtime.Pager[armcosmos.SQLResourcesClientListSQLDatabasesResponse] {
	return f.listFn(rgName, accountName)
}
