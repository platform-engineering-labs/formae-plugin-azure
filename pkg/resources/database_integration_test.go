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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/postgresql/armpostgresqlflexibleservers/v4"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testDBNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.DBforPostgreSQL/flexibleServers/pg-srv-1/databases/mydb"

func TestDatabase_CRUD(t *testing.T) {
	fake := &fakeDatabasesAPI{
		beginCreateFn: func(_ context.Context, _, _, _ string, _ armpostgresqlflexibleservers.Database, _ *armpostgresqlflexibleservers.DatabasesClientBeginCreateOptions) (*runtime.Poller[armpostgresqlflexibleservers.DatabasesClientCreateResponse], error) {
			return newDonePoller(armpostgresqlflexibleservers.DatabasesClientCreateResponse{
				Database: armpostgresqlflexibleservers.Database{
					ID:   to.Ptr(testDBNativeID),
					Name: to.Ptr("mydb"),
					Properties: &armpostgresqlflexibleservers.DatabaseProperties{
						Charset:   to.Ptr("UTF8"),
						Collation: to.Ptr("en_US.utf8"),
					},
				},
			}), nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ *armpostgresqlflexibleservers.DatabasesClientGetOptions) (armpostgresqlflexibleservers.DatabasesClientGetResponse, error) {
			return armpostgresqlflexibleservers.DatabasesClientGetResponse{
				Database: armpostgresqlflexibleservers.Database{
					ID:   to.Ptr(testDBNativeID),
					Name: to.Ptr("mydb"),
					Properties: &armpostgresqlflexibleservers.DatabaseProperties{
						Charset:   to.Ptr("UTF8"),
						Collation: to.Ptr("en_US.utf8"),
					},
				},
			}, nil
		},
		beginDeleteFn: func(_ context.Context, _, _, _ string, _ *armpostgresqlflexibleservers.DatabasesClientBeginDeleteOptions) (*runtime.Poller[armpostgresqlflexibleservers.DatabasesClientDeleteResponse], error) {
			return newDonePoller(armpostgresqlflexibleservers.DatabasesClientDeleteResponse{}), nil
		},
		newListByServerPagerFn: func(_, _ string, _ *armpostgresqlflexibleservers.DatabasesClientListByServerOptions) *runtime.Pager[armpostgresqlflexibleservers.DatabasesClientListByServerResponse] {
			return runtime.NewPager(runtime.PagingHandler[armpostgresqlflexibleservers.DatabasesClientListByServerResponse]{
				More: func(_ armpostgresqlflexibleservers.DatabasesClientListByServerResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armpostgresqlflexibleservers.DatabasesClientListByServerResponse) (armpostgresqlflexibleservers.DatabasesClientListByServerResponse, error) {
					return armpostgresqlflexibleservers.DatabasesClientListByServerResponse{
						DatabaseListResult: armpostgresqlflexibleservers.DatabaseListResult{
							Value: []*armpostgresqlflexibleservers.Database{{ID: to.Ptr(testDBNativeID)}},
						},
					}, nil
				},
			})
		},
		newListServersPagerFn: func(_ *armpostgresqlflexibleservers.ServersClientListOptions) *runtime.Pager[armpostgresqlflexibleservers.ServersClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armpostgresqlflexibleservers.ServersClientListResponse]{
				More: func(_ armpostgresqlflexibleservers.ServersClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armpostgresqlflexibleservers.ServersClientListResponse) (armpostgresqlflexibleservers.ServersClientListResponse, error) {
					return armpostgresqlflexibleservers.ServersClientListResponse{
						ServerListResult: armpostgresqlflexibleservers.ServerListResult{
							Value: []*armpostgresqlflexibleservers.Server{
								{ID: to.Ptr("/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.DBforPostgreSQL/flexibleServers/pg-srv-1")},
							},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestDatabase(fake)

	t.Run("Create", func(t *testing.T) {
		props, _ := json.Marshal(map[string]interface{}{
			"resourceGroupName": "rg-1", "serverName": "pg-srv-1", "name": "mydb",
			"charset": "UTF8", "collation": "en_US.utf8",
		})
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "mydb", Properties: props})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testDBNativeID, got.ProgressResult.NativeID)
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testDBNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "mydb", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "pg-srv-1", props["serverName"])
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _, _ string, _ *armpostgresqlflexibleservers.DatabasesClientBeginDeleteOptions) (*runtime.Poller[armpostgresqlflexibleservers.DatabasesClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testDBNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "serverName": "pg-srv-1"},
		})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 1)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.beginCreateFn = func(_ context.Context, _, _, _ string, _ armpostgresqlflexibleservers.Database, _ *armpostgresqlflexibleservers.DatabasesClientBeginCreateOptions) (*runtime.Poller[armpostgresqlflexibleservers.DatabasesClientCreateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 403}
		}
		props, _ := json.Marshal(map[string]interface{}{
			"resourceGroupName": "rg-1", "serverName": "pg-srv-1", "name": "mydb",
		})
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "mydb", Properties: props})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

// --- Test helpers ---

func newTestDatabase(api databasesAPI) *Database {
	return &Database{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

type fakeDatabasesAPI struct {
	beginCreateFn          func(ctx context.Context, resourceGroupName string, serverName string, databaseName string, parameters armpostgresqlflexibleservers.Database, options *armpostgresqlflexibleservers.DatabasesClientBeginCreateOptions) (*runtime.Poller[armpostgresqlflexibleservers.DatabasesClientCreateResponse], error)
	getFn                  func(ctx context.Context, resourceGroupName string, serverName string, databaseName string, options *armpostgresqlflexibleservers.DatabasesClientGetOptions) (armpostgresqlflexibleservers.DatabasesClientGetResponse, error)
	beginDeleteFn          func(ctx context.Context, resourceGroupName string, serverName string, databaseName string, options *armpostgresqlflexibleservers.DatabasesClientBeginDeleteOptions) (*runtime.Poller[armpostgresqlflexibleservers.DatabasesClientDeleteResponse], error)
	newListByServerPagerFn func(resourceGroupName string, serverName string, options *armpostgresqlflexibleservers.DatabasesClientListByServerOptions) *runtime.Pager[armpostgresqlflexibleservers.DatabasesClientListByServerResponse]
	newListServersPagerFn  func(options *armpostgresqlflexibleservers.ServersClientListOptions) *runtime.Pager[armpostgresqlflexibleservers.ServersClientListResponse]
	resumeCreateFn         func(token string) (*runtime.Poller[armpostgresqlflexibleservers.DatabasesClientCreateResponse], error)
	resumeDeleteFn         func(token string) (*runtime.Poller[armpostgresqlflexibleservers.DatabasesClientDeleteResponse], error)
}

func (f *fakeDatabasesAPI) BeginCreate(ctx context.Context, resourceGroupName string, serverName string, databaseName string, parameters armpostgresqlflexibleservers.Database, options *armpostgresqlflexibleservers.DatabasesClientBeginCreateOptions) (*runtime.Poller[armpostgresqlflexibleservers.DatabasesClientCreateResponse], error) {
	return f.beginCreateFn(ctx, resourceGroupName, serverName, databaseName, parameters, options)
}

func (f *fakeDatabasesAPI) Get(ctx context.Context, resourceGroupName string, serverName string, databaseName string, options *armpostgresqlflexibleservers.DatabasesClientGetOptions) (armpostgresqlflexibleservers.DatabasesClientGetResponse, error) {
	return f.getFn(ctx, resourceGroupName, serverName, databaseName, options)
}

func (f *fakeDatabasesAPI) BeginDelete(ctx context.Context, resourceGroupName string, serverName string, databaseName string, options *armpostgresqlflexibleservers.DatabasesClientBeginDeleteOptions) (*runtime.Poller[armpostgresqlflexibleservers.DatabasesClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, resourceGroupName, serverName, databaseName, options)
}

func (f *fakeDatabasesAPI) NewListByServerPager(resourceGroupName string, serverName string, options *armpostgresqlflexibleservers.DatabasesClientListByServerOptions) *runtime.Pager[armpostgresqlflexibleservers.DatabasesClientListByServerResponse] {
	return f.newListByServerPagerFn(resourceGroupName, serverName, options)
}

func (f *fakeDatabasesAPI) NewListServersPager(options *armpostgresqlflexibleservers.ServersClientListOptions) *runtime.Pager[armpostgresqlflexibleservers.ServersClientListResponse] {
	return f.newListServersPagerFn(options)
}

func (f *fakeDatabasesAPI) ResumeCreatePoller(token string) (*runtime.Poller[armpostgresqlflexibleservers.DatabasesClientCreateResponse], error) {
	return f.resumeCreateFn(token)
}

func (f *fakeDatabasesAPI) ResumeDeletePoller(token string) (*runtime.Poller[armpostgresqlflexibleservers.DatabasesClientDeleteResponse], error) {
	return f.resumeDeleteFn(token)
}
