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
	testCosmosAccountScope           = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.DocumentDB/databaseAccounts/cosmos-1"
	testCosmosRoleDefinitionGUID     = "6a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d"
	testCosmosRoleDefinitionNativeID = testCosmosAccountScope + "/sqlRoleDefinitions/" + testCosmosRoleDefinitionGUID
	testCosmosBuiltInRoleNativeID    = testCosmosAccountScope + "/sqlRoleDefinitions/00000000-0000-0000-0000-000000000001"
	testCosmosDataReadAction         = "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/items/read"
)

func newTestCosmosSqlRoleDefinition(api cosmosSQLRoleDefinitionAPI) *CosmosSqlRoleDefinition {
	return &CosmosSqlRoleDefinition{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

func cosmosRoleDefinitionDesired(roleName string) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":              testCosmosRoleDefinitionGUID,
		"resourceGroupName": "rg-1",
		"accountName":       "cosmos-1",
		"roleName":          roleName,
		"type":              "CustomRole",
		"assignableScopes":  []string{testCosmosAccountScope},
		"permissions": []map[string]any{
			{"dataActions": []string{testCosmosDataReadAction}},
		},
	})
	return out
}

func TestCosmosSqlRoleDefinition_CRUD(t *testing.T) {
	result := armcosmos.SQLRoleDefinitionGetResults{
		ID:   to.Ptr(testCosmosRoleDefinitionNativeID),
		Name: to.Ptr(testCosmosRoleDefinitionGUID),
		Properties: &armcosmos.SQLRoleDefinitionResource{
			RoleName:         to.Ptr("conformance-reader"),
			Type:             to.Ptr(armcosmos.RoleDefinitionTypeCustomRole),
			AssignableScopes: []*string{to.Ptr(testCosmosAccountScope)},
			Permissions: []*armcosmos.Permission{
				{DataActions: []*string{to.Ptr(testCosmosDataReadAction)}},
			},
		},
	}

	var sentID string
	var sent armcosmos.SQLRoleDefinitionCreateUpdateParameters
	fake := &fakeCosmosSQLRoleDefinitionAPI{
		createFn: func(_ context.Context, roleDefinitionID, rgName, accountName string, params armcosmos.SQLRoleDefinitionCreateUpdateParameters) (*runtime.Poller[armcosmos.SQLResourcesClientCreateUpdateSQLRoleDefinitionResponse], error) {
			require.Equal(t, "rg-1", rgName)
			require.Equal(t, "cosmos-1", accountName)
			sentID = roleDefinitionID
			sent = params
			return newDonePoller(armcosmos.SQLResourcesClientCreateUpdateSQLRoleDefinitionResponse{SQLRoleDefinitionGetResults: result}), nil
		},
		getFn: func(_ context.Context, _, _, _ string) (armcosmos.SQLResourcesClientGetSQLRoleDefinitionResponse, error) {
			return armcosmos.SQLResourcesClientGetSQLRoleDefinitionResponse{SQLRoleDefinitionGetResults: result}, nil
		},
		deleteFn: func(_ context.Context, _, _, _ string) (*runtime.Poller[armcosmos.SQLResourcesClientDeleteSQLRoleDefinitionResponse], error) {
			return newDonePoller(armcosmos.SQLResourcesClientDeleteSQLRoleDefinitionResponse{}), nil
		},
		listFn: func(_, _ string) *runtime.Pager[armcosmos.SQLResourcesClientListSQLRoleDefinitionsResponse] {
			return runtime.NewPager(runtime.PagingHandler[armcosmos.SQLResourcesClientListSQLRoleDefinitionsResponse]{
				More: func(armcosmos.SQLResourcesClientListSQLRoleDefinitionsResponse) bool { return false },
				Fetcher: func(context.Context, *armcosmos.SQLResourcesClientListSQLRoleDefinitionsResponse) (armcosmos.SQLResourcesClientListSQLRoleDefinitionsResponse, error) {
					return armcosmos.SQLResourcesClientListSQLRoleDefinitionsResponse{
						SQLRoleDefinitionListResult: armcosmos.SQLRoleDefinitionListResult{
							Value: []*armcosmos.SQLRoleDefinitionGetResults{
								&result,
								{
									ID:         to.Ptr(testCosmosBuiltInRoleNativeID),
									Properties: &armcosmos.SQLRoleDefinitionResource{Type: to.Ptr(armcosmos.RoleDefinitionTypeBuiltInRole)},
								},
							},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestCosmosSqlRoleDefinition(fake)

	// The GUID in `name` is the ARM path segment, and the SDK takes it as the FIRST
	// argument — ahead of the resource group.
	t.Run("Create_passes_the_guid_as_the_path_segment", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "reader", Properties: cosmosRoleDefinitionDesired("conformance-reader"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testCosmosRoleDefinitionNativeID, got.ProgressResult.NativeID)
		require.Equal(t, testCosmosRoleDefinitionGUID, sentID)

		require.Equal(t, "conformance-reader", *sent.Properties.RoleName)
		require.Equal(t, armcosmos.RoleDefinitionTypeCustomRole, *sent.Properties.Type)
		require.Equal(t, []string{testCosmosAccountScope}, stringsFromPointers(sent.Properties.AssignableScopes))
		require.Len(t, sent.Properties.Permissions, 1)
		require.Equal(t, []string{testCosmosDataReadAction}, stringsFromPointers(sent.Properties.Permissions[0].DataActions))
	})

	t.Run("Create_requires_assignableScopes", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": testCosmosRoleDefinitionGUID, "resourceGroupName": "rg-1", "accountName": "cosmos-1",
			"roleName": "r", "permissions": []map[string]any{{"dataActions": []string{testCosmosDataReadAction}}},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "at least one assignableScope is required")
	})

	t.Run("Create_requires_permissions", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": testCosmosRoleDefinitionGUID, "resourceGroupName": "rg-1", "accountName": "cosmos-1",
			"roleName": "r", "assignableScopes": []string{testCosmosAccountScope},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "at least one permission is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testCosmosRoleDefinitionNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, testCosmosRoleDefinitionGUID, props["name"])
		require.Equal(t, "conformance-reader", props["roleName"])
		require.Equal(t, "CustomRole", props["type"])
		require.Equal(t, []any{testCosmosAccountScope}, props["assignableScopes"])
		permissions := props["permissions"].([]any)
		require.Len(t, permissions, 1)
		require.Equal(t, []any{testCosmosDataReadAction}, permissions[0].(map[string]any)["dataActions"])
	})

	t.Run("Update_changes_roleName", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testCosmosRoleDefinitionNativeID,
			DesiredProperties: cosmosRoleDefinitionDesired("conformance-reader-renamed"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testCosmosRoleDefinitionGUID, sentID)
		require.Equal(t, "conformance-reader-renamed", *sent.Properties.RoleName)
	})

	t.Run("Delete", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testCosmosRoleDefinitionNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _, _ string) (*runtime.Poller[armcosmos.SQLResourcesClientDeleteSQLRoleDefinitionResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testCosmosRoleDefinitionNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	// Every account exposes the two built-in data-plane roles and ARM refuses to
	// delete them, so discovery must not hand them to formae.
	t.Run("List_skips_built_in_roles", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "accountName": "cosmos-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testCosmosRoleDefinitionNativeID}, got.NativeIDs)
	})
}

func TestCosmosSqlRoleDefinition_ReadNotFound(t *testing.T) {
	fake := &fakeCosmosSQLRoleDefinitionAPI{
		getFn: func(_ context.Context, _, _, _ string) (armcosmos.SQLResourcesClientGetSQLRoleDefinitionResponse, error) {
			return armcosmos.SQLResourcesClientGetSQLRoleDefinitionResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestCosmosSqlRoleDefinition(fake).Read(context.Background(),
		&resource.ReadRequest{NativeID: testCosmosRoleDefinitionNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeCosmosSQLRoleDefinitionAPI struct {
	createFn func(ctx context.Context, roleDefinitionID, rgName, accountName string, params armcosmos.SQLRoleDefinitionCreateUpdateParameters) (*runtime.Poller[armcosmos.SQLResourcesClientCreateUpdateSQLRoleDefinitionResponse], error)
	getFn    func(ctx context.Context, roleDefinitionID, rgName, accountName string) (armcosmos.SQLResourcesClientGetSQLRoleDefinitionResponse, error)
	deleteFn func(ctx context.Context, roleDefinitionID, rgName, accountName string) (*runtime.Poller[armcosmos.SQLResourcesClientDeleteSQLRoleDefinitionResponse], error)
	listFn   func(rgName, accountName string) *runtime.Pager[armcosmos.SQLResourcesClientListSQLRoleDefinitionsResponse]
}

func (f *fakeCosmosSQLRoleDefinitionAPI) BeginCreateUpdateSQLRoleDefinition(ctx context.Context, roleDefinitionID, rgName, accountName string, params armcosmos.SQLRoleDefinitionCreateUpdateParameters, _ *armcosmos.SQLResourcesClientBeginCreateUpdateSQLRoleDefinitionOptions) (*runtime.Poller[armcosmos.SQLResourcesClientCreateUpdateSQLRoleDefinitionResponse], error) {
	return f.createFn(ctx, roleDefinitionID, rgName, accountName, params)
}

func (f *fakeCosmosSQLRoleDefinitionAPI) GetSQLRoleDefinition(ctx context.Context, roleDefinitionID, rgName, accountName string, _ *armcosmos.SQLResourcesClientGetSQLRoleDefinitionOptions) (armcosmos.SQLResourcesClientGetSQLRoleDefinitionResponse, error) {
	return f.getFn(ctx, roleDefinitionID, rgName, accountName)
}

func (f *fakeCosmosSQLRoleDefinitionAPI) BeginDeleteSQLRoleDefinition(ctx context.Context, roleDefinitionID, rgName, accountName string, _ *armcosmos.SQLResourcesClientBeginDeleteSQLRoleDefinitionOptions) (*runtime.Poller[armcosmos.SQLResourcesClientDeleteSQLRoleDefinitionResponse], error) {
	return f.deleteFn(ctx, roleDefinitionID, rgName, accountName)
}

func (f *fakeCosmosSQLRoleDefinitionAPI) NewListSQLRoleDefinitionsPager(rgName, accountName string, _ *armcosmos.SQLResourcesClientListSQLRoleDefinitionsOptions) *runtime.Pager[armcosmos.SQLResourcesClientListSQLRoleDefinitionsResponse] {
	return f.listFn(rgName, accountName)
}
