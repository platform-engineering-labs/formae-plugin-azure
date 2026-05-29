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

const testSQLADAdminNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Sql/servers/sql-1/administrators/ActiveDirectory"

func TestSqlADAdministrator_CRUD(t *testing.T) {
	adminResult := armsql.ServerAzureADAdministrator{
		ID:   to.Ptr(testSQLADAdminNativeID),
		Name: to.Ptr("ActiveDirectory"),
		Properties: &armsql.AdministratorProperties{
			AdministratorType: to.Ptr(armsql.AdministratorTypeActiveDirectory),
			Login:             to.Ptr("dba-group"),
			Sid:               to.Ptr("00000000-0000-0000-0000-000000000001"),
			TenantID:          to.Ptr("11111111-1111-1111-1111-111111111111"),
		},
	}

	fake := &fakeSQLADAdministratorsAPI{
		beginCreateOrUpdateFn: func(_ context.Context, _, _ string, name armsql.AdministratorName, _ armsql.ServerAzureADAdministrator, _ *armsql.ServerAzureADAdministratorsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armsql.ServerAzureADAdministratorsClientCreateOrUpdateResponse], error) {
			require.Equal(t, armsql.AdministratorNameActiveDirectory, name)
			return newDonePoller(armsql.ServerAzureADAdministratorsClientCreateOrUpdateResponse{ServerAzureADAdministrator: adminResult}), nil
		},
		getFn: func(_ context.Context, _, _ string, name armsql.AdministratorName, _ *armsql.ServerAzureADAdministratorsClientGetOptions) (armsql.ServerAzureADAdministratorsClientGetResponse, error) {
			require.Equal(t, armsql.AdministratorNameActiveDirectory, name)
			return armsql.ServerAzureADAdministratorsClientGetResponse{ServerAzureADAdministrator: adminResult}, nil
		},
		newListByServerPagerFn: func(_, _ string, _ *armsql.ServerAzureADAdministratorsClientListByServerOptions) *runtime.Pager[armsql.ServerAzureADAdministratorsClientListByServerResponse] {
			return runtime.NewPager(runtime.PagingHandler[armsql.ServerAzureADAdministratorsClientListByServerResponse]{
				More: func(_ armsql.ServerAzureADAdministratorsClientListByServerResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armsql.ServerAzureADAdministratorsClientListByServerResponse) (armsql.ServerAzureADAdministratorsClientListByServerResponse, error) {
					return armsql.ServerAzureADAdministratorsClientListByServerResponse{
						AdministratorListResult: armsql.AdministratorListResult{
							Value: []*armsql.ServerAzureADAdministrator{
								{ID: to.Ptr(testSQLADAdminNativeID)},
							},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestSqlADAdministrator(fake)

	t.Run("Create", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName": "rg-1",
			"serverName":        "sql-1",
			"login":             "dba-group",
			"sid":               "00000000-0000-0000-0000-000000000001",
			"tenantId":          "11111111-1111-1111-1111-111111111111",
		})
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "aad-admin", Properties: props})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testSQLADAdminNativeID, got.ProgressResult.NativeID)
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testSQLADAdminNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "sql-1", props["serverName"])
		require.Equal(t, "dba-group", props["login"])
		require.Equal(t, "ActiveDirectory", props["administratorType"])
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _ string, _ armsql.AdministratorName, _ *armsql.ServerAzureADAdministratorsClientBeginDeleteOptions) (*runtime.Poller[armsql.ServerAzureADAdministratorsClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testSQLADAdminNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "serverName": "sql-1"},
		})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 1)
		require.Equal(t, testSQLADAdminNativeID, got.NativeIDs[0])
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, _ armsql.AdministratorName, _ armsql.ServerAzureADAdministrator, _ *armsql.ServerAzureADAdministratorsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armsql.ServerAzureADAdministratorsClientCreateOrUpdateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 403}
		}
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName": "rg-1",
			"serverName":        "sql-1",
			"login":             "dba-group",
			"sid":               "00000000-0000-0000-0000-000000000001",
			"tenantId":          "11111111-1111-1111-1111-111111111111",
		})
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "aad-admin", Properties: props})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

// --- Test helpers ---

func newTestSqlADAdministrator(api sqlADAdministratorsAPI) *SqlADAdministrator {
	return &SqlADAdministrator{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

type fakeSQLADAdministratorsAPI struct {
	beginCreateOrUpdateFn  func(ctx context.Context, resourceGroupName, serverName string, administratorName armsql.AdministratorName, parameters armsql.ServerAzureADAdministrator, options *armsql.ServerAzureADAdministratorsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armsql.ServerAzureADAdministratorsClientCreateOrUpdateResponse], error)
	getFn                  func(ctx context.Context, resourceGroupName, serverName string, administratorName armsql.AdministratorName, options *armsql.ServerAzureADAdministratorsClientGetOptions) (armsql.ServerAzureADAdministratorsClientGetResponse, error)
	beginDeleteFn          func(ctx context.Context, resourceGroupName, serverName string, administratorName armsql.AdministratorName, options *armsql.ServerAzureADAdministratorsClientBeginDeleteOptions) (*runtime.Poller[armsql.ServerAzureADAdministratorsClientDeleteResponse], error)
	newListByServerPagerFn func(resourceGroupName, serverName string, options *armsql.ServerAzureADAdministratorsClientListByServerOptions) *runtime.Pager[armsql.ServerAzureADAdministratorsClientListByServerResponse]
}

func (f *fakeSQLADAdministratorsAPI) BeginCreateOrUpdate(ctx context.Context, resourceGroupName, serverName string, administratorName armsql.AdministratorName, parameters armsql.ServerAzureADAdministrator, options *armsql.ServerAzureADAdministratorsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armsql.ServerAzureADAdministratorsClientCreateOrUpdateResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, resourceGroupName, serverName, administratorName, parameters, options)
}

func (f *fakeSQLADAdministratorsAPI) Get(ctx context.Context, resourceGroupName, serverName string, administratorName armsql.AdministratorName, options *armsql.ServerAzureADAdministratorsClientGetOptions) (armsql.ServerAzureADAdministratorsClientGetResponse, error) {
	return f.getFn(ctx, resourceGroupName, serverName, administratorName, options)
}

func (f *fakeSQLADAdministratorsAPI) BeginDelete(ctx context.Context, resourceGroupName, serverName string, administratorName armsql.AdministratorName, options *armsql.ServerAzureADAdministratorsClientBeginDeleteOptions) (*runtime.Poller[armsql.ServerAzureADAdministratorsClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, resourceGroupName, serverName, administratorName, options)
}

func (f *fakeSQLADAdministratorsAPI) NewListByServerPager(resourceGroupName, serverName string, options *armsql.ServerAzureADAdministratorsClientListByServerOptions) *runtime.Pager[armsql.ServerAzureADAdministratorsClientListByServerResponse] {
	return f.newListByServerPagerFn(resourceGroupName, serverName, options)
}
