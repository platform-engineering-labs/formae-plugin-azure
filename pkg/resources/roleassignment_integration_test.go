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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testRANativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Authorization/roleAssignments/00000000-0000-0000-0000-000000000001"

func TestRoleAssignment_CRUD(t *testing.T) {
	pt := armauthorization.PrincipalTypeServicePrincipal
	id2 := "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Authorization/roleAssignments/00000000-0000-0000-0000-000000000002"

	fake := &fakeRoleAssignmentsAPI{
		createFn: func(_ context.Context, scope, raName string, params armauthorization.RoleAssignmentCreateParameters, _ *armauthorization.RoleAssignmentsClientCreateOptions) (armauthorization.RoleAssignmentsClientCreateResponse, error) {
			require.Equal(t, "/subscriptions/sub-1", scope)
			require.Equal(t, "00000000-0000-0000-0000-000000000001", raName)
			require.NotNil(t, params.Properties)
			require.Equal(t, "principal-1", *params.Properties.PrincipalID)
			require.Equal(t, "/subscriptions/sub-1/providers/Microsoft.Authorization/roleDefinitions/role-1", *params.Properties.RoleDefinitionID)
			require.Equal(t, &pt, params.Properties.PrincipalType)

			return armauthorization.RoleAssignmentsClientCreateResponse{
				RoleAssignment: armauthorization.RoleAssignment{
					ID:   to.Ptr(testRANativeID),
					Name: to.Ptr("00000000-0000-0000-0000-000000000001"),
					Properties: &armauthorization.RoleAssignmentProperties{
						Scope:            to.Ptr("/subscriptions/sub-1"),
						PrincipalID:      to.Ptr("principal-1"),
						RoleDefinitionID: to.Ptr("/subscriptions/sub-1/providers/Microsoft.Authorization/roleDefinitions/role-1"),
						PrincipalType:    &pt,
					},
				},
			}, nil
		},
		getByIDFn: func(_ context.Context, roleAssignmentID string, _ *armauthorization.RoleAssignmentsClientGetByIDOptions) (armauthorization.RoleAssignmentsClientGetByIDResponse, error) {
			require.Equal(t, testRANativeID, roleAssignmentID)
			return armauthorization.RoleAssignmentsClientGetByIDResponse{
				RoleAssignment: armauthorization.RoleAssignment{
					ID:   to.Ptr(testRANativeID),
					Name: to.Ptr("00000000-0000-0000-0000-000000000001"),
					Properties: &armauthorization.RoleAssignmentProperties{
						Scope:            to.Ptr("/subscriptions/sub-1"),
						PrincipalID:      to.Ptr("principal-1"),
						RoleDefinitionID: to.Ptr("/subscriptions/sub-1/providers/Microsoft.Authorization/roleDefinitions/role-1"),
					},
				},
			}, nil
		},
		deleteByIDFn: func(_ context.Context, roleAssignmentID string, _ *armauthorization.RoleAssignmentsClientDeleteByIDOptions) (armauthorization.RoleAssignmentsClientDeleteByIDResponse, error) {
			require.Equal(t, testRANativeID, roleAssignmentID)
			return armauthorization.RoleAssignmentsClientDeleteByIDResponse{}, nil
		},
		listForScopeFn: func(scope string, _ *armauthorization.RoleAssignmentsClientListForScopeOptions) *runtime.Pager[armauthorization.RoleAssignmentsClientListForScopeResponse] {
			require.Equal(t, "/subscriptions/sub-1", scope)
			return runtime.NewPager(runtime.PagingHandler[armauthorization.RoleAssignmentsClientListForScopeResponse]{
				More: func(_ armauthorization.RoleAssignmentsClientListForScopeResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armauthorization.RoleAssignmentsClientListForScopeResponse) (armauthorization.RoleAssignmentsClientListForScopeResponse, error) {
					return armauthorization.RoleAssignmentsClientListForScopeResponse{
						RoleAssignmentListResult: armauthorization.RoleAssignmentListResult{
							Value: []*armauthorization.RoleAssignment{
								{ID: to.Ptr(testRANativeID)},
								{ID: to.Ptr(id2)},
							},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestRoleAssignment(fake, nil)

	t.Run("Create", func(t *testing.T) {
		props, _ := json.Marshal(map[string]interface{}{
			"scope":            "/subscriptions/sub-1",
			"name":             "00000000-0000-0000-0000-000000000001",
			"principalId":      "principal-1",
			"roleDefinitionId": "/subscriptions/sub-1/providers/Microsoft.Authorization/roleDefinitions/role-1",
			"principalType":    "ServicePrincipal",
		})
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "test-ra", Properties: props})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testRANativeID, got.ProgressResult.NativeID)
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testRANativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
		var props map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "00000000-0000-0000-0000-000000000001", props["name"])
		require.Equal(t, "/subscriptions/sub-1", props["scope"])
		require.Equal(t, "principal-1", props["principalId"])
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteByIDFn = func(_ context.Context, _ string, _ *armauthorization.RoleAssignmentsClientDeleteByIDOptions) (armauthorization.RoleAssignmentsClientDeleteByIDResponse, error) {
			return armauthorization.RoleAssignmentsClientDeleteByIDResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testRANativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"scope": "/subscriptions/sub-1"},
		})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 2)
		require.Equal(t, testRANativeID, got.NativeIDs[0])
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.createFn = func(_ context.Context, _, _ string, _ armauthorization.RoleAssignmentCreateParameters, _ *armauthorization.RoleAssignmentsClientCreateOptions) (armauthorization.RoleAssignmentsClientCreateResponse, error) {
			return armauthorization.RoleAssignmentsClientCreateResponse{}, &azcore.ResponseError{StatusCode: 409}
		}
		props, _ := json.Marshal(map[string]interface{}{
			"scope":            "/subscriptions/sub-1",
			"name":             "00000000-0000-0000-0000-000000000001",
			"principalId":      "principal-1",
			"roleDefinitionId": "/subscriptions/sub-1/providers/Microsoft.Authorization/roleDefinitions/role-1",
		})
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

// --- Test helpers ---

func newTestRoleAssignment(api roleAssignmentsAPI, cfg *config.Config) *RoleAssignment {
	return &RoleAssignment{api: api, config: cfg}
}

type fakeRoleAssignmentsAPI struct {
	createFn       func(ctx context.Context, scope, roleAssignmentName string, parameters armauthorization.RoleAssignmentCreateParameters, options *armauthorization.RoleAssignmentsClientCreateOptions) (armauthorization.RoleAssignmentsClientCreateResponse, error)
	getByIDFn      func(ctx context.Context, roleAssignmentID string, options *armauthorization.RoleAssignmentsClientGetByIDOptions) (armauthorization.RoleAssignmentsClientGetByIDResponse, error)
	deleteByIDFn   func(ctx context.Context, roleAssignmentID string, options *armauthorization.RoleAssignmentsClientDeleteByIDOptions) (armauthorization.RoleAssignmentsClientDeleteByIDResponse, error)
	listForScopeFn func(scope string, options *armauthorization.RoleAssignmentsClientListForScopeOptions) *runtime.Pager[armauthorization.RoleAssignmentsClientListForScopeResponse]
}

func (f *fakeRoleAssignmentsAPI) Create(ctx context.Context, scope, roleAssignmentName string, parameters armauthorization.RoleAssignmentCreateParameters, options *armauthorization.RoleAssignmentsClientCreateOptions) (armauthorization.RoleAssignmentsClientCreateResponse, error) {
	return f.createFn(ctx, scope, roleAssignmentName, parameters, options)
}

func (f *fakeRoleAssignmentsAPI) GetByID(ctx context.Context, roleAssignmentID string, options *armauthorization.RoleAssignmentsClientGetByIDOptions) (armauthorization.RoleAssignmentsClientGetByIDResponse, error) {
	return f.getByIDFn(ctx, roleAssignmentID, options)
}

func (f *fakeRoleAssignmentsAPI) DeleteByID(ctx context.Context, roleAssignmentID string, options *armauthorization.RoleAssignmentsClientDeleteByIDOptions) (armauthorization.RoleAssignmentsClientDeleteByIDResponse, error) {
	return f.deleteByIDFn(ctx, roleAssignmentID, options)
}

func (f *fakeRoleAssignmentsAPI) NewListForScopePager(scope string, options *armauthorization.RoleAssignmentsClientListForScopeOptions) *runtime.Pager[armauthorization.RoleAssignmentsClientListForScopeResponse] {
	return f.listForScopeFn(scope, options)
}
