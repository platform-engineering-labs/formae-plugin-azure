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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/mysql/armmysqlflexibleservers/v2"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testMySQLServerNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.DBforMySQL/flexibleServers/mysql-1"

func newTestMySQLFlexibleServer(api mySQLFlexibleServersAPI) *MySQLFlexibleServer {
	return &MySQLFlexibleServer{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func mysqlDesired(storageGB, retentionDays int) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":                       "mysql-1",
		"location":                   "eastus",
		"resourceGroupName":          "rg-1",
		"version":                    "8.0.21",
		"administratorLogin":         "mysqladmin",
		"administratorLoginPassword": "T3stP@ssw0rd!",
		"sku":                        map[string]any{"name": "Standard_B1ms", "tier": "Burstable"},
		"storage":                    map[string]any{"storageSizeGB": storageGB, "autoGrow": "Enabled"},
		"backup":                     map[string]any{"backupRetentionDays": retentionDays, "geoRedundantBackup": "Disabled"},
		"network":                    map[string]any{"publicNetworkAccess": "Enabled"},
	})
	return out
}

func TestMySQLFlexibleServer_CRUD(t *testing.T) {
	serverResult := armmysqlflexibleservers.Server{
		ID:       to.Ptr(testMySQLServerNativeID),
		Name:     to.Ptr("mysql-1"),
		Location: to.Ptr("East US"),
		SKU: &armmysqlflexibleservers.MySQLServerSKU{
			Name: to.Ptr("Standard_B1ms"),
			Tier: to.Ptr(armmysqlflexibleservers.ServerSKUTierBurstable),
		},
		Properties: &armmysqlflexibleservers.ServerProperties{
			AdministratorLogin:       to.Ptr("mysqladmin"),
			Version:                  to.Ptr(armmysqlflexibleservers.ServerVersionEight021),
			FullyQualifiedDomainName: to.Ptr("mysql-1.mysql.database.azure.com"),
			State:                    to.Ptr(armmysqlflexibleservers.ServerStateReady),
			Storage: &armmysqlflexibleservers.Storage{
				StorageSizeGB: to.Ptr(int32(20)),
				AutoGrow:      to.Ptr(armmysqlflexibleservers.EnableStatusEnumEnabled),
			},
			Backup: &armmysqlflexibleservers.Backup{
				BackupRetentionDays: to.Ptr(int32(7)),
				GeoRedundantBackup:  to.Ptr(armmysqlflexibleservers.EnableStatusEnumDisabled),
			},
			Network: &armmysqlflexibleservers.Network{
				PublicNetworkAccess: to.Ptr(armmysqlflexibleservers.EnableStatusEnumEnabled),
			},
		},
	}

	var sentCreate armmysqlflexibleservers.Server
	var sentUpdate armmysqlflexibleservers.ServerForUpdate
	fake := &fakeMySQLServersAPI{
		beginCreateFn: func(_ context.Context, _, name string, params armmysqlflexibleservers.Server, _ *armmysqlflexibleservers.ServersClientBeginCreateOptions) (*runtime.Poller[armmysqlflexibleservers.ServersClientCreateResponse], error) {
			require.Equal(t, "mysql-1", name)
			sentCreate = params
			return newDonePoller(armmysqlflexibleservers.ServersClientCreateResponse{Server: serverResult}), nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armmysqlflexibleservers.ServersClientGetOptions) (armmysqlflexibleservers.ServersClientGetResponse, error) {
			return armmysqlflexibleservers.ServersClientGetResponse{Server: serverResult}, nil
		},
		beginUpdateFn: func(_ context.Context, _, _ string, params armmysqlflexibleservers.ServerForUpdate, _ *armmysqlflexibleservers.ServersClientBeginUpdateOptions) (*runtime.Poller[armmysqlflexibleservers.ServersClientUpdateResponse], error) {
			sentUpdate = params
			return newDonePoller(armmysqlflexibleservers.ServersClientUpdateResponse{Server: serverResult}), nil
		},
		beginDeleteFn: func(_ context.Context, _, _ string, _ *armmysqlflexibleservers.ServersClientBeginDeleteOptions) (*runtime.Poller[armmysqlflexibleservers.ServersClientDeleteResponse], error) {
			return newDonePoller(armmysqlflexibleservers.ServersClientDeleteResponse{}), nil
		},
		newListPagerFn: func(_ *armmysqlflexibleservers.ServersClientListOptions) *runtime.Pager[armmysqlflexibleservers.ServersClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armmysqlflexibleservers.ServersClientListResponse]{
				More: func(_ armmysqlflexibleservers.ServersClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armmysqlflexibleservers.ServersClientListResponse) (armmysqlflexibleservers.ServersClientListResponse, error) {
					return armmysqlflexibleservers.ServersClientListResponse{
						ServerListResult: armmysqlflexibleservers.ServerListResult{
							Value: []*armmysqlflexibleservers.Server{
								{ID: to.Ptr(testMySQLServerNativeID)},
								{ID: to.Ptr("/subscriptions/sub-1/resourceGroups/rg-2/providers/Microsoft.DBforMySQL/flexibleServers/mysql-2")},
							},
						},
					}, nil
				},
			})
		},
		newListByResourceGroupPagerFn: func(_ string, _ *armmysqlflexibleservers.ServersClientListByResourceGroupOptions) *runtime.Pager[armmysqlflexibleservers.ServersClientListByResourceGroupResponse] {
			return runtime.NewPager(runtime.PagingHandler[armmysqlflexibleservers.ServersClientListByResourceGroupResponse]{
				More: func(_ armmysqlflexibleservers.ServersClientListByResourceGroupResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armmysqlflexibleservers.ServersClientListByResourceGroupResponse) (armmysqlflexibleservers.ServersClientListByResourceGroupResponse, error) {
					return armmysqlflexibleservers.ServersClientListByResourceGroupResponse{
						ServerListResult: armmysqlflexibleservers.ServerListResult{
							Value: []*armmysqlflexibleservers.Server{{ID: to.Ptr(testMySQLServerNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestMySQLFlexibleServer(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "mysql-1", Properties: mysqlDesired(20, 7)})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testMySQLServerNativeID, got.ProgressResult.NativeID)

		require.Equal(t, "mysqladmin", *sentCreate.Properties.AdministratorLogin)
		require.Equal(t, "T3stP@ssw0rd!", *sentCreate.Properties.AdministratorLoginPassword)
		require.Equal(t, armmysqlflexibleservers.ServerSKUTierBurstable, *sentCreate.SKU.Tier)
		require.EqualValues(t, 20, *sentCreate.Properties.Storage.StorageSizeGB)
	})

	t.Run("Create_requires_password", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "mysql-1", "location": "eastus", "resourceGroupName": "rg-1",
			"version": "8.0.21", "administratorLogin": "mysqladmin",
			"sku": map[string]any{"name": "Standard_B1ms", "tier": "Burstable"},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "administratorLoginPassword is required")
	})

	t.Run("Create_requires_sku_tier", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "mysql-1", "location": "eastus", "resourceGroupName": "rg-1",
			"version": "8.0.21", "administratorLogin": "a", "administratorLoginPassword": "T3stP@ssw0rd!",
			"sku": map[string]any{"name": "Standard_B1ms"},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "sku.name and sku.tier are required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testMySQLServerNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "mysql-1", props["name"])
		require.Equal(t, "eastus", props["location"])
		require.Equal(t, "8.0.21", props["version"])
		require.Equal(t, "mysqladmin", props["administratorLogin"])
		require.Equal(t, "mysql-1.mysql.database.azure.com", props["fullyQualifiedDomainName"])
		require.Equal(t, "Ready", props["state"])
	})

	// ARM never returns the admin password; it must not appear on any path.
	t.Run("password_never_serialized", func(t *testing.T) {
		read, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testMySQLServerNativeID})
		require.NoError(t, err)
		created, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "mysql-1", Properties: mysqlDesired(20, 7)})
		require.NoError(t, err)
		for _, payload := range []string{read.Properties, string(created.ProgressResult.ResourceProperties)} {
			require.NotContains(t, payload, "T3stP@ssw0rd!")
			require.NotContains(t, payload, "administratorLoginPassword")
		}
	})

	// The update body must never carry createOnly fields: ARM rejects a version or
	// login change on PATCH.
	t.Run("Update_omits_createOnly_fields", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testMySQLServerNativeID,
			DesiredProperties: mysqlDesired(40, 14),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testMySQLServerNativeID, got.ProgressResult.NativeID)
		require.EqualValues(t, 40, *sentUpdate.Properties.Storage.StorageSizeGB)
		require.EqualValues(t, 14, *sentUpdate.Properties.Backup.BackupRetentionDays)
		require.Nil(t, sentUpdate.Properties.Version)
		require.Nil(t, sentUpdate.Properties.AdministratorLoginPassword)
	})

	t.Run("Delete", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testMySQLServerNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _ string, _ *armmysqlflexibleservers.ServersClientBeginDeleteOptions) (*runtime.Poller[armmysqlflexibleservers.ServersClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testMySQLServerNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_resource_group", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testMySQLServerNativeID}, got.NativeIDs)
	})

	t.Run("List_without_group_is_subscription_wide", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 2)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.beginCreateFn = func(_ context.Context, _, _ string, _ armmysqlflexibleservers.Server, _ *armmysqlflexibleservers.ServersClientBeginCreateOptions) (*runtime.Poller[armmysqlflexibleservers.ServersClientCreateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 409}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "mysql-1", Properties: mysqlDesired(20, 7)})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

func TestMySQLFlexibleServer_ReadNotFound(t *testing.T) {
	fake := &fakeMySQLServersAPI{
		getFn: func(_ context.Context, _, _ string, _ *armmysqlflexibleservers.ServersClientGetOptions) (armmysqlflexibleservers.ServersClientGetResponse, error) {
			return armmysqlflexibleservers.ServersClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestMySQLFlexibleServer(fake).Read(context.Background(), &resource.ReadRequest{NativeID: testMySQLServerNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeMySQLServersAPI struct {
	beginCreateFn                 func(ctx context.Context, rgName, name string, params armmysqlflexibleservers.Server, options *armmysqlflexibleservers.ServersClientBeginCreateOptions) (*runtime.Poller[armmysqlflexibleservers.ServersClientCreateResponse], error)
	getFn                         func(ctx context.Context, rgName, name string, options *armmysqlflexibleservers.ServersClientGetOptions) (armmysqlflexibleservers.ServersClientGetResponse, error)
	beginUpdateFn                 func(ctx context.Context, rgName, name string, params armmysqlflexibleservers.ServerForUpdate, options *armmysqlflexibleservers.ServersClientBeginUpdateOptions) (*runtime.Poller[armmysqlflexibleservers.ServersClientUpdateResponse], error)
	beginDeleteFn                 func(ctx context.Context, rgName, name string, options *armmysqlflexibleservers.ServersClientBeginDeleteOptions) (*runtime.Poller[armmysqlflexibleservers.ServersClientDeleteResponse], error)
	newListPagerFn                func(options *armmysqlflexibleservers.ServersClientListOptions) *runtime.Pager[armmysqlflexibleservers.ServersClientListResponse]
	newListByResourceGroupPagerFn func(rgName string, options *armmysqlflexibleservers.ServersClientListByResourceGroupOptions) *runtime.Pager[armmysqlflexibleservers.ServersClientListByResourceGroupResponse]
}

func (f *fakeMySQLServersAPI) BeginCreate(ctx context.Context, rgName, name string, params armmysqlflexibleservers.Server, options *armmysqlflexibleservers.ServersClientBeginCreateOptions) (*runtime.Poller[armmysqlflexibleservers.ServersClientCreateResponse], error) {
	return f.beginCreateFn(ctx, rgName, name, params, options)
}

func (f *fakeMySQLServersAPI) Get(ctx context.Context, rgName, name string, options *armmysqlflexibleservers.ServersClientGetOptions) (armmysqlflexibleservers.ServersClientGetResponse, error) {
	return f.getFn(ctx, rgName, name, options)
}

func (f *fakeMySQLServersAPI) BeginUpdate(ctx context.Context, rgName, name string, params armmysqlflexibleservers.ServerForUpdate, options *armmysqlflexibleservers.ServersClientBeginUpdateOptions) (*runtime.Poller[armmysqlflexibleservers.ServersClientUpdateResponse], error) {
	return f.beginUpdateFn(ctx, rgName, name, params, options)
}

func (f *fakeMySQLServersAPI) BeginDelete(ctx context.Context, rgName, name string, options *armmysqlflexibleservers.ServersClientBeginDeleteOptions) (*runtime.Poller[armmysqlflexibleservers.ServersClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, name, options)
}

func (f *fakeMySQLServersAPI) NewListPager(options *armmysqlflexibleservers.ServersClientListOptions) *runtime.Pager[armmysqlflexibleservers.ServersClientListResponse] {
	return f.newListPagerFn(options)
}

func (f *fakeMySQLServersAPI) NewListByResourceGroupPager(rgName string, options *armmysqlflexibleservers.ServersClientListByResourceGroupOptions) *runtime.Pager[armmysqlflexibleservers.ServersClientListByResourceGroupResponse] {
	return f.newListByResourceGroupPagerFn(rgName, options)
}
