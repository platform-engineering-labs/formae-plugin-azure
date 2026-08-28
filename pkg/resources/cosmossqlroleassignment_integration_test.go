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
	testCosmosRoleAssignmentGUID     = "7b2c3d4e-5f6a-4b7c-8d9e-0f1a2b3c4d5e"
	testCosmosRoleAssignmentNativeID = testCosmosAccountScope + "/sqlRoleAssignments/" + testCosmosRoleAssignmentGUID
	testCosmosDataReaderRoleID       = testCosmosAccountScope + "/sqlRoleDefinitions/00000000-0000-0000-0000-000000000001"
	testCosmosDataContributorRoleID  = testCosmosAccountScope + "/sqlRoleDefinitions/00000000-0000-0000-0000-000000000002"
	testCosmosPrincipalID            = "11111111-2222-3333-4444-555555555555"
)

func newTestCosmosSqlRoleAssignment(api cosmosSQLRoleAssignmentAPI) *CosmosSqlRoleAssignment {
	return &CosmosSqlRoleAssignment{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

func cosmosRoleAssignmentDesired(roleDefinitionID string) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":              testCosmosRoleAssignmentGUID,
		"resourceGroupName": "rg-1",
		"accountName":       "cosmos-1",
		"roleDefinitionId":  roleDefinitionID,
		"principalId":       testCosmosPrincipalID,
		"scope":             testCosmosAccountScope,
	})
	return out
}

func TestCosmosSqlRoleAssignment_CRUD(t *testing.T) {
	result := armcosmos.SQLRoleAssignmentGetResults{
		ID:   to.Ptr(testCosmosRoleAssignmentNativeID),
		Name: to.Ptr(testCosmosRoleAssignmentGUID),
		Properties: &armcosmos.SQLRoleAssignmentResource{
			RoleDefinitionID: to.Ptr(testCosmosDataReaderRoleID),
			PrincipalID:      to.Ptr(testCosmosPrincipalID),
			Scope:            to.Ptr(testCosmosAccountScope),
		},
	}

	var sentID string
	var sent armcosmos.SQLRoleAssignmentCreateUpdateParameters
	fake := &fakeCosmosSQLRoleAssignmentAPI{
		createFn: func(_ context.Context, roleAssignmentID, rgName, accountName string, params armcosmos.SQLRoleAssignmentCreateUpdateParameters) (*runtime.Poller[armcosmos.SQLResourcesClientCreateUpdateSQLRoleAssignmentResponse], error) {
			require.Equal(t, "rg-1", rgName)
			require.Equal(t, "cosmos-1", accountName)
			sentID = roleAssignmentID
			sent = params
			return newDonePoller(armcosmos.SQLResourcesClientCreateUpdateSQLRoleAssignmentResponse{SQLRoleAssignmentGetResults: result}), nil
		},
		getFn: func(_ context.Context, _, _, _ string) (armcosmos.SQLResourcesClientGetSQLRoleAssignmentResponse, error) {
			return armcosmos.SQLResourcesClientGetSQLRoleAssignmentResponse{SQLRoleAssignmentGetResults: result}, nil
		},
		deleteFn: func(_ context.Context, _, _, _ string) (*runtime.Poller[armcosmos.SQLResourcesClientDeleteSQLRoleAssignmentResponse], error) {
			return newDonePoller(armcosmos.SQLResourcesClientDeleteSQLRoleAssignmentResponse{}), nil
		},
		listFn: func(_, _ string) *runtime.Pager[armcosmos.SQLResourcesClientListSQLRoleAssignmentsResponse] {
			return runtime.NewPager(runtime.PagingHandler[armcosmos.SQLResourcesClientListSQLRoleAssignmentsResponse]{
				More: func(armcosmos.SQLResourcesClientListSQLRoleAssignmentsResponse) bool { return false },
				Fetcher: func(context.Context, *armcosmos.SQLResourcesClientListSQLRoleAssignmentsResponse) (armcosmos.SQLResourcesClientListSQLRoleAssignmentsResponse, error) {
					return armcosmos.SQLResourcesClientListSQLRoleAssignmentsResponse{
						SQLRoleAssignmentListResult: armcosmos.SQLRoleAssignmentListResult{
							Value: []*armcosmos.SQLRoleAssignmentGetResults{{ID: to.Ptr(testCosmosRoleAssignmentNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestCosmosSqlRoleAssignment(fake)

	t.Run("Create_passes_the_guid_as_the_path_segment", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "reader-grant", Properties: cosmosRoleAssignmentDesired(testCosmosDataReaderRoleID),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testCosmosRoleAssignmentNativeID, got.ProgressResult.NativeID)
		require.Equal(t, testCosmosRoleAssignmentGUID, sentID)

		require.Equal(t, testCosmosDataReaderRoleID, *sent.Properties.RoleDefinitionID)
		require.Equal(t, testCosmosPrincipalID, *sent.Properties.PrincipalID)
		require.Equal(t, testCosmosAccountScope, *sent.Properties.Scope)
	})

	t.Run("Create_requires_principalId", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": testCosmosRoleAssignmentGUID, "resourceGroupName": "rg-1", "accountName": "cosmos-1",
			"roleDefinitionId": testCosmosDataReaderRoleID, "scope": testCosmosAccountScope,
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "principalId is required")
	})

	t.Run("Create_requires_roleDefinitionId", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": testCosmosRoleAssignmentGUID, "resourceGroupName": "rg-1", "accountName": "cosmos-1",
			"principalId": testCosmosPrincipalID, "scope": testCosmosAccountScope,
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "roleDefinitionId is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testCosmosRoleAssignmentNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, testCosmosRoleAssignmentGUID, props["name"])
		require.Equal(t, testCosmosDataReaderRoleID, props["roleDefinitionId"])
		require.Equal(t, testCosmosPrincipalID, props["principalId"])
		require.Equal(t, testCosmosAccountScope, props["scope"])
		require.Equal(t, "cosmos-1", props["accountName"])
	})

	// roleDefinitionId is the one mutable field: re-PUTting the same GUID swaps the
	// role rather than creating a second assignment.
	t.Run("Update_swaps_the_role", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testCosmosRoleAssignmentNativeID,
			DesiredProperties: cosmosRoleAssignmentDesired(testCosmosDataContributorRoleID),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testCosmosRoleAssignmentGUID, sentID)
		require.Equal(t, testCosmosDataContributorRoleID, *sent.Properties.RoleDefinitionID)
	})

	t.Run("Delete", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testCosmosRoleAssignmentNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _, _ string) (*runtime.Poller[armcosmos.SQLResourcesClientDeleteSQLRoleAssignmentResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testCosmosRoleAssignmentNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "accountName": "cosmos-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testCosmosRoleAssignmentNativeID}, got.NativeIDs)
	})
}

func TestCosmosSqlRoleAssignment_ReadNotFound(t *testing.T) {
	fake := &fakeCosmosSQLRoleAssignmentAPI{
		getFn: func(_ context.Context, _, _, _ string) (armcosmos.SQLResourcesClientGetSQLRoleAssignmentResponse, error) {
			return armcosmos.SQLResourcesClientGetSQLRoleAssignmentResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestCosmosSqlRoleAssignment(fake).Read(context.Background(),
		&resource.ReadRequest{NativeID: testCosmosRoleAssignmentNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeCosmosSQLRoleAssignmentAPI struct {
	createFn func(ctx context.Context, roleAssignmentID, rgName, accountName string, params armcosmos.SQLRoleAssignmentCreateUpdateParameters) (*runtime.Poller[armcosmos.SQLResourcesClientCreateUpdateSQLRoleAssignmentResponse], error)
	getFn    func(ctx context.Context, roleAssignmentID, rgName, accountName string) (armcosmos.SQLResourcesClientGetSQLRoleAssignmentResponse, error)
	deleteFn func(ctx context.Context, roleAssignmentID, rgName, accountName string) (*runtime.Poller[armcosmos.SQLResourcesClientDeleteSQLRoleAssignmentResponse], error)
	listFn   func(rgName, accountName string) *runtime.Pager[armcosmos.SQLResourcesClientListSQLRoleAssignmentsResponse]
}

func (f *fakeCosmosSQLRoleAssignmentAPI) BeginCreateUpdateSQLRoleAssignment(ctx context.Context, roleAssignmentID, rgName, accountName string, params armcosmos.SQLRoleAssignmentCreateUpdateParameters, _ *armcosmos.SQLResourcesClientBeginCreateUpdateSQLRoleAssignmentOptions) (*runtime.Poller[armcosmos.SQLResourcesClientCreateUpdateSQLRoleAssignmentResponse], error) {
	return f.createFn(ctx, roleAssignmentID, rgName, accountName, params)
}

func (f *fakeCosmosSQLRoleAssignmentAPI) GetSQLRoleAssignment(ctx context.Context, roleAssignmentID, rgName, accountName string, _ *armcosmos.SQLResourcesClientGetSQLRoleAssignmentOptions) (armcosmos.SQLResourcesClientGetSQLRoleAssignmentResponse, error) {
	return f.getFn(ctx, roleAssignmentID, rgName, accountName)
}

func (f *fakeCosmosSQLRoleAssignmentAPI) BeginDeleteSQLRoleAssignment(ctx context.Context, roleAssignmentID, rgName, accountName string, _ *armcosmos.SQLResourcesClientBeginDeleteSQLRoleAssignmentOptions) (*runtime.Poller[armcosmos.SQLResourcesClientDeleteSQLRoleAssignmentResponse], error) {
	return f.deleteFn(ctx, roleAssignmentID, rgName, accountName)
}

func (f *fakeCosmosSQLRoleAssignmentAPI) NewListSQLRoleAssignmentsPager(rgName, accountName string, _ *armcosmos.SQLResourcesClientListSQLRoleAssignmentsOptions) *runtime.Pager[armcosmos.SQLResourcesClientListSQLRoleAssignmentsResponse] {
	return f.listFn(rgName, accountName)
}
