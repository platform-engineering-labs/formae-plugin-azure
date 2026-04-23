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

const testFSNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.DBforPostgreSQL/flexibleServers/pg-1"

func TestFlexibleServer_CRUD(t *testing.T) {
	version := armpostgresqlflexibleservers.ServerVersion("16")
	skuTier := armpostgresqlflexibleservers.SKUTierGeneralPurpose

	fake := &fakeFlexibleServersAPI{
		beginCreateFn: func(_ context.Context, _, _ string, _ armpostgresqlflexibleservers.Server, _ *armpostgresqlflexibleservers.ServersClientBeginCreateOptions) (*runtime.Poller[armpostgresqlflexibleservers.ServersClientCreateResponse], error) {
			return newDonePoller(armpostgresqlflexibleservers.ServersClientCreateResponse{
				Server: armpostgresqlflexibleservers.Server{
					ID:       to.Ptr(testFSNativeID),
					Name:     to.Ptr("pg-1"),
					Location: to.Ptr("East US"),
					SKU: &armpostgresqlflexibleservers.SKU{
						Name: to.Ptr("Standard_D2s_v3"),
						Tier: &skuTier,
					},
					Properties: &armpostgresqlflexibleservers.ServerProperties{
						Version:                  &version,
						AdministratorLogin:       to.Ptr("pgadmin"),
						FullyQualifiedDomainName: to.Ptr("pg-1.postgres.database.azure.com"),
						State:                    to.Ptr(armpostgresqlflexibleservers.ServerStateReady),
					},
				},
			}), nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armpostgresqlflexibleservers.ServersClientGetOptions) (armpostgresqlflexibleservers.ServersClientGetResponse, error) {
			return armpostgresqlflexibleservers.ServersClientGetResponse{
				Server: armpostgresqlflexibleservers.Server{
					ID:       to.Ptr(testFSNativeID),
					Name:     to.Ptr("pg-1"),
					Location: to.Ptr("East US"),
					SKU: &armpostgresqlflexibleservers.SKU{
						Name: to.Ptr("Standard_D2s_v3"),
						Tier: &skuTier,
					},
					Properties: &armpostgresqlflexibleservers.ServerProperties{
						Version:                  &version,
						AdministratorLogin:       to.Ptr("pgadmin"),
						FullyQualifiedDomainName: to.Ptr("pg-1.postgres.database.azure.com"),
						State:                    to.Ptr(armpostgresqlflexibleservers.ServerStateReady),
					},
				},
			}, nil
		},
		beginUpdateFn: func(_ context.Context, _, _ string, _ armpostgresqlflexibleservers.ServerForUpdate, _ *armpostgresqlflexibleservers.ServersClientBeginUpdateOptions) (*runtime.Poller[armpostgresqlflexibleservers.ServersClientUpdateResponse], error) {
			return newDonePoller(armpostgresqlflexibleservers.ServersClientUpdateResponse{
				Server: armpostgresqlflexibleservers.Server{
					ID:       to.Ptr(testFSNativeID),
					Name:     to.Ptr("pg-1"),
					Location: to.Ptr("East US"),
					SKU: &armpostgresqlflexibleservers.SKU{
						Name: to.Ptr("Standard_D4s_v3"),
						Tier: &skuTier,
					},
					Properties: &armpostgresqlflexibleservers.ServerProperties{
						Version:            &version,
						AdministratorLogin: to.Ptr("pgadmin"),
					},
				},
			}), nil
		},
		newListByResourceGroupPagerFn: func(_ string, _ *armpostgresqlflexibleservers.ServersClientListByResourceGroupOptions) *runtime.Pager[armpostgresqlflexibleservers.ServersClientListByResourceGroupResponse] {
			return runtime.NewPager(runtime.PagingHandler[armpostgresqlflexibleservers.ServersClientListByResourceGroupResponse]{
				More: func(_ armpostgresqlflexibleservers.ServersClientListByResourceGroupResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armpostgresqlflexibleservers.ServersClientListByResourceGroupResponse) (armpostgresqlflexibleservers.ServersClientListByResourceGroupResponse, error) {
					return armpostgresqlflexibleservers.ServersClientListByResourceGroupResponse{
						ServerListResult: armpostgresqlflexibleservers.ServerListResult{
							Value: []*armpostgresqlflexibleservers.Server{
								{ID: to.Ptr(testFSNativeID)},
								{ID: to.Ptr("/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.DBforPostgreSQL/flexibleServers/pg-2")},
							},
						},
					}, nil
				},
			})
		},
		newListPagerFn: func(_ *armpostgresqlflexibleservers.ServersClientListOptions) *runtime.Pager[armpostgresqlflexibleservers.ServersClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armpostgresqlflexibleservers.ServersClientListResponse]{
				More: func(_ armpostgresqlflexibleservers.ServersClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armpostgresqlflexibleservers.ServersClientListResponse) (armpostgresqlflexibleservers.ServersClientListResponse, error) {
					return armpostgresqlflexibleservers.ServersClientListResponse{
						ServerListResult: armpostgresqlflexibleservers.ServerListResult{
							Value: []*armpostgresqlflexibleservers.Server{
								{ID: to.Ptr(testFSNativeID)},
							},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestFlexibleServer(fake)

	t.Run("Create", func(t *testing.T) {
		props, _ := json.Marshal(map[string]interface{}{
			"resourceGroupName":          "rg-1",
			"name":                       "pg-1",
			"location":                   "eastus",
			"version":                    "16",
			"administratorLogin":         "pgadmin",
			"administratorLoginPassword": "secret123!",
			"sku": map[string]interface{}{
				"name": "Standard_D2s_v3",
				"tier": "GeneralPurpose",
			},
		})
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "pg-1", Properties: props})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testFSNativeID, got.ProgressResult.NativeID)
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testFSNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
		var props map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "pg-1", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "eastus", props["location"])
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _ string, _ *armpostgresqlflexibleservers.ServersClientBeginDeleteOptions) (*runtime.Poller[armpostgresqlflexibleservers.ServersClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testFSNativeID})
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
		fake.beginCreateFn = func(_ context.Context, _, _ string, _ armpostgresqlflexibleservers.Server, _ *armpostgresqlflexibleservers.ServersClientBeginCreateOptions) (*runtime.Poller[armpostgresqlflexibleservers.ServersClientCreateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 403}
		}
		props, _ := json.Marshal(map[string]interface{}{
			"resourceGroupName":          "rg-1",
			"name":                       "pg-1",
			"location":                   "eastus",
			"version":                    "16",
			"administratorLogin":         "pgadmin",
			"administratorLoginPassword": "secret123!",
			"sku":                        map[string]interface{}{"name": "Standard_D2s_v3", "tier": "GeneralPurpose"},
		})
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "pg-1", Properties: props})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

// --- Test helpers ---

func newTestFlexibleServer(api flexibleServersAPI) *FlexibleServer {
	return &FlexibleServer{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

type fakeFlexibleServersAPI struct {
	beginCreateFn                 func(ctx context.Context, resourceGroupName, serverName string, parameters armpostgresqlflexibleservers.Server, options *armpostgresqlflexibleservers.ServersClientBeginCreateOptions) (*runtime.Poller[armpostgresqlflexibleservers.ServersClientCreateResponse], error)
	getFn                         func(ctx context.Context, resourceGroupName, serverName string, options *armpostgresqlflexibleservers.ServersClientGetOptions) (armpostgresqlflexibleservers.ServersClientGetResponse, error)
	beginUpdateFn                 func(ctx context.Context, resourceGroupName, serverName string, parameters armpostgresqlflexibleservers.ServerForUpdate, options *armpostgresqlflexibleservers.ServersClientBeginUpdateOptions) (*runtime.Poller[armpostgresqlflexibleservers.ServersClientUpdateResponse], error)
	beginDeleteFn                 func(ctx context.Context, resourceGroupName, serverName string, options *armpostgresqlflexibleservers.ServersClientBeginDeleteOptions) (*runtime.Poller[armpostgresqlflexibleservers.ServersClientDeleteResponse], error)
	newListByResourceGroupPagerFn func(resourceGroupName string, options *armpostgresqlflexibleservers.ServersClientListByResourceGroupOptions) *runtime.Pager[armpostgresqlflexibleservers.ServersClientListByResourceGroupResponse]
	newListPagerFn                func(options *armpostgresqlflexibleservers.ServersClientListOptions) *runtime.Pager[armpostgresqlflexibleservers.ServersClientListResponse]
	resumeCreatePollerFn          func(token string) (*runtime.Poller[armpostgresqlflexibleservers.ServersClientCreateResponse], error)
	resumeUpdatePollerFn          func(token string) (*runtime.Poller[armpostgresqlflexibleservers.ServersClientUpdateResponse], error)
	resumeDeletePollerFn          func(token string) (*runtime.Poller[armpostgresqlflexibleservers.ServersClientDeleteResponse], error)
}

func (f *fakeFlexibleServersAPI) BeginCreate(ctx context.Context, resourceGroupName, serverName string, parameters armpostgresqlflexibleservers.Server, options *armpostgresqlflexibleservers.ServersClientBeginCreateOptions) (*runtime.Poller[armpostgresqlflexibleservers.ServersClientCreateResponse], error) {
	return f.beginCreateFn(ctx, resourceGroupName, serverName, parameters, options)
}

func (f *fakeFlexibleServersAPI) Get(ctx context.Context, resourceGroupName, serverName string, options *armpostgresqlflexibleservers.ServersClientGetOptions) (armpostgresqlflexibleservers.ServersClientGetResponse, error) {
	return f.getFn(ctx, resourceGroupName, serverName, options)
}

func (f *fakeFlexibleServersAPI) BeginUpdate(ctx context.Context, resourceGroupName, serverName string, parameters armpostgresqlflexibleservers.ServerForUpdate, options *armpostgresqlflexibleservers.ServersClientBeginUpdateOptions) (*runtime.Poller[armpostgresqlflexibleservers.ServersClientUpdateResponse], error) {
	return f.beginUpdateFn(ctx, resourceGroupName, serverName, parameters, options)
}

func (f *fakeFlexibleServersAPI) BeginDelete(ctx context.Context, resourceGroupName, serverName string, options *armpostgresqlflexibleservers.ServersClientBeginDeleteOptions) (*runtime.Poller[armpostgresqlflexibleservers.ServersClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, resourceGroupName, serverName, options)
}

func (f *fakeFlexibleServersAPI) NewListByResourceGroupPager(resourceGroupName string, options *armpostgresqlflexibleservers.ServersClientListByResourceGroupOptions) *runtime.Pager[armpostgresqlflexibleservers.ServersClientListByResourceGroupResponse] {
	return f.newListByResourceGroupPagerFn(resourceGroupName, options)
}

func (f *fakeFlexibleServersAPI) NewListPager(options *armpostgresqlflexibleservers.ServersClientListOptions) *runtime.Pager[armpostgresqlflexibleservers.ServersClientListResponse] {
	return f.newListPagerFn(options)
}

func (f *fakeFlexibleServersAPI) ResumeCreatePoller(token string) (*runtime.Poller[armpostgresqlflexibleservers.ServersClientCreateResponse], error) {
	return f.resumeCreatePollerFn(token)
}

func (f *fakeFlexibleServersAPI) ResumeUpdatePoller(token string) (*runtime.Poller[armpostgresqlflexibleservers.ServersClientUpdateResponse], error) {
	return f.resumeUpdatePollerFn(token)
}

func (f *fakeFlexibleServersAPI) ResumeDeletePoller(token string) (*runtime.Poller[armpostgresqlflexibleservers.ServersClientDeleteResponse], error) {
	return f.resumeDeletePollerFn(token)
}
