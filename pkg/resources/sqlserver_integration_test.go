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

const testSQLServerNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Sql/servers/sql-1"

func TestSqlServer_CRUD(t *testing.T) {
	fqdn := "sql-1.database.windows.net"

	serverResult := armsql.Server{
		ID:       to.Ptr(testSQLServerNativeID),
		Name:     to.Ptr("sql-1"),
		Location: to.Ptr("East US"),
		Properties: &armsql.ServerProperties{
			Version:                  to.Ptr("12.0"),
			AdministratorLogin:       to.Ptr("sqladmin"),
			FullyQualifiedDomainName: to.Ptr(fqdn),
			MinimalTLSVersion:        to.Ptr("1.2"),
		},
	}

	fake := &fakeSQLServersAPI{
		beginCreateOrUpdateFn: func(_ context.Context, _, _ string, _ armsql.Server, _ *armsql.ServersClientBeginCreateOrUpdateOptions) (*runtime.Poller[armsql.ServersClientCreateOrUpdateResponse], error) {
			return newDonePoller(armsql.ServersClientCreateOrUpdateResponse{Server: serverResult}), nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armsql.ServersClientGetOptions) (armsql.ServersClientGetResponse, error) {
			return armsql.ServersClientGetResponse{Server: serverResult}, nil
		},
		beginUpdateFn: func(_ context.Context, _, _ string, _ armsql.ServerUpdate, _ *armsql.ServersClientBeginUpdateOptions) (*runtime.Poller[armsql.ServersClientUpdateResponse], error) {
			return newDonePoller(armsql.ServersClientUpdateResponse{Server: serverResult}), nil
		},
		newListByResourceGroupPagerFn: func(_ string, _ *armsql.ServersClientListByResourceGroupOptions) *runtime.Pager[armsql.ServersClientListByResourceGroupResponse] {
			return runtime.NewPager(runtime.PagingHandler[armsql.ServersClientListByResourceGroupResponse]{
				More: func(_ armsql.ServersClientListByResourceGroupResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armsql.ServersClientListByResourceGroupResponse) (armsql.ServersClientListByResourceGroupResponse, error) {
					return armsql.ServersClientListByResourceGroupResponse{
						ServerListResult: armsql.ServerListResult{
							Value: []*armsql.Server{
								{ID: to.Ptr(testSQLServerNativeID)},
								{ID: to.Ptr("/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Sql/servers/sql-2")},
							},
						},
					}, nil
				},
			})
		},
		newListPagerFn: func(_ *armsql.ServersClientListOptions) *runtime.Pager[armsql.ServersClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armsql.ServersClientListResponse]{
				More: func(_ armsql.ServersClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armsql.ServersClientListResponse) (armsql.ServersClientListResponse, error) {
					return armsql.ServersClientListResponse{
						ServerListResult: armsql.ServerListResult{
							Value: []*armsql.Server{{ID: to.Ptr(testSQLServerNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestSqlServer(fake)

	t.Run("Create", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName":          "rg-1",
			"name":                       "sql-1",
			"location":                   "eastus",
			"administratorLogin":         "sqladmin",
			"administratorLoginPassword": "secret123!",
			"version":                    "12.0",
		})
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "sql-1", Properties: props})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testSQLServerNativeID, got.ProgressResult.NativeID)
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testSQLServerNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "sql-1", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "eastus", props["location"])
		require.Equal(t, fqdn, props["fullyQualifiedDomainName"])
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _ string, _ *armsql.ServersClientBeginDeleteOptions) (*runtime.Poller[armsql.ServersClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testSQLServerNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 2)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, _ armsql.Server, _ *armsql.ServersClientBeginCreateOrUpdateOptions) (*runtime.Poller[armsql.ServersClientCreateOrUpdateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 403}
		}
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName":          "rg-1",
			"name":                       "sql-1",
			"location":                   "eastus",
			"administratorLogin":         "sqladmin",
			"administratorLoginPassword": "secret123!",
			"version":                    "12.0",
		})
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "sql-1", Properties: props})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

// --- Test helpers ---

func newTestSqlServer(api sqlServersAPI) *SqlServer {
	return &SqlServer{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

type fakeSQLServersAPI struct {
	beginCreateOrUpdateFn         func(ctx context.Context, resourceGroupName, serverName string, parameters armsql.Server, options *armsql.ServersClientBeginCreateOrUpdateOptions) (*runtime.Poller[armsql.ServersClientCreateOrUpdateResponse], error)
	getFn                         func(ctx context.Context, resourceGroupName, serverName string, options *armsql.ServersClientGetOptions) (armsql.ServersClientGetResponse, error)
	beginUpdateFn                 func(ctx context.Context, resourceGroupName, serverName string, parameters armsql.ServerUpdate, options *armsql.ServersClientBeginUpdateOptions) (*runtime.Poller[armsql.ServersClientUpdateResponse], error)
	beginDeleteFn                 func(ctx context.Context, resourceGroupName, serverName string, options *armsql.ServersClientBeginDeleteOptions) (*runtime.Poller[armsql.ServersClientDeleteResponse], error)
	newListByResourceGroupPagerFn func(resourceGroupName string, options *armsql.ServersClientListByResourceGroupOptions) *runtime.Pager[armsql.ServersClientListByResourceGroupResponse]
	newListPagerFn                func(options *armsql.ServersClientListOptions) *runtime.Pager[armsql.ServersClientListResponse]
}

func (f *fakeSQLServersAPI) BeginCreateOrUpdate(ctx context.Context, resourceGroupName, serverName string, parameters armsql.Server, options *armsql.ServersClientBeginCreateOrUpdateOptions) (*runtime.Poller[armsql.ServersClientCreateOrUpdateResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, resourceGroupName, serverName, parameters, options)
}

func (f *fakeSQLServersAPI) Get(ctx context.Context, resourceGroupName, serverName string, options *armsql.ServersClientGetOptions) (armsql.ServersClientGetResponse, error) {
	return f.getFn(ctx, resourceGroupName, serverName, options)
}

func (f *fakeSQLServersAPI) BeginUpdate(ctx context.Context, resourceGroupName, serverName string, parameters armsql.ServerUpdate, options *armsql.ServersClientBeginUpdateOptions) (*runtime.Poller[armsql.ServersClientUpdateResponse], error) {
	return f.beginUpdateFn(ctx, resourceGroupName, serverName, parameters, options)
}

func (f *fakeSQLServersAPI) BeginDelete(ctx context.Context, resourceGroupName, serverName string, options *armsql.ServersClientBeginDeleteOptions) (*runtime.Poller[armsql.ServersClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, resourceGroupName, serverName, options)
}

func (f *fakeSQLServersAPI) NewListByResourceGroupPager(resourceGroupName string, options *armsql.ServersClientListByResourceGroupOptions) *runtime.Pager[armsql.ServersClientListByResourceGroupResponse] {
	return f.newListByResourceGroupPagerFn(resourceGroupName, options)
}

func (f *fakeSQLServersAPI) NewListPager(options *armsql.ServersClientListOptions) *runtime.Pager[armsql.ServersClientListResponse] {
	return f.newListPagerFn(options)
}
