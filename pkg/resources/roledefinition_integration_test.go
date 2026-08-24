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

const (
	testRoleDefinitionScope    = "/subscriptions/sub-1"
	testRoleDefinitionGUID     = "8f1c2b3a-4d5e-4f60-9a7b-1c2d3e4f5a6b"
	testRoleDefinitionNativeID = testRoleDefinitionScope + "/providers/Microsoft.Authorization/roleDefinitions/" + testRoleDefinitionGUID
)

type fakeRoleDefinitionsAPI struct {
	createOrUpdateFn func(ctx context.Context, scope, id string, definition armauthorization.RoleDefinition, options *armauthorization.RoleDefinitionsClientCreateOrUpdateOptions) (armauthorization.RoleDefinitionsClientCreateOrUpdateResponse, error)
	getFn            func(ctx context.Context, scope, id string, options *armauthorization.RoleDefinitionsClientGetOptions) (armauthorization.RoleDefinitionsClientGetResponse, error)
	deleteFn         func(ctx context.Context, scope, id string, options *armauthorization.RoleDefinitionsClientDeleteOptions) (armauthorization.RoleDefinitionsClientDeleteResponse, error)
	listPagerFn      func(scope string, options *armauthorization.RoleDefinitionsClientListOptions) *runtime.Pager[armauthorization.RoleDefinitionsClientListResponse]
}

func (f *fakeRoleDefinitionsAPI) CreateOrUpdate(ctx context.Context, scope, id string, definition armauthorization.RoleDefinition, options *armauthorization.RoleDefinitionsClientCreateOrUpdateOptions) (armauthorization.RoleDefinitionsClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, scope, id, definition, options)
}

func (f *fakeRoleDefinitionsAPI) Get(ctx context.Context, scope, id string, options *armauthorization.RoleDefinitionsClientGetOptions) (armauthorization.RoleDefinitionsClientGetResponse, error) {
	return f.getFn(ctx, scope, id, options)
}

func (f *fakeRoleDefinitionsAPI) Delete(ctx context.Context, scope, id string, options *armauthorization.RoleDefinitionsClientDeleteOptions) (armauthorization.RoleDefinitionsClientDeleteResponse, error) {
	return f.deleteFn(ctx, scope, id, options)
}

func (f *fakeRoleDefinitionsAPI) NewListPager(scope string, options *armauthorization.RoleDefinitionsClientListOptions) *runtime.Pager[armauthorization.RoleDefinitionsClientListResponse] {
	return f.listPagerFn(scope, options)
}

func newTestRoleDefinition(api roleDefinitionsAPI) *RoleDefinition {
	return &RoleDefinition{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func roleDefinitionDesired(roleName string, actions []any) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":             testRoleDefinitionGUID,
		"scope":            testRoleDefinitionScope,
		"roleName":         roleName,
		"description":      "conformance test role",
		"assignableScopes": []any{testRoleDefinitionScope},
		"permissions": []any{map[string]any{
			"actions":    actions,
			"notActions": []any{"Microsoft.Storage/storageAccounts/delete"},
		}},
	})
	return out
}

func TestRoleDefinition_CRUD(t *testing.T) {
	definitionResult := armauthorization.RoleDefinition{
		ID:   to.Ptr(testRoleDefinitionNativeID),
		Name: to.Ptr(testRoleDefinitionGUID),
		Properties: &armauthorization.RoleDefinitionProperties{
			RoleName:         to.Ptr("formae conformance reader"),
			Description:      to.Ptr("conformance test role"),
			RoleType:         to.Ptr("CustomRole"),
			AssignableScopes: []*string{to.Ptr(testRoleDefinitionScope)},
			Permissions: []*armauthorization.Permission{{
				Actions:    []*string{to.Ptr("Microsoft.Storage/storageAccounts/read")},
				NotActions: []*string{to.Ptr("Microsoft.Storage/storageAccounts/delete")},
				// ARM echoes the data-plane lists as empty arrays for a role that
				// never declared them.
				DataActions:    []*string{},
				NotDataActions: []*string{},
			}},
		},
	}

	var sentScope, sentID string
	var sent armauthorization.RoleDefinition
	writeCalls := 0
	deleteCalls := 0
	fake := &fakeRoleDefinitionsAPI{
		createOrUpdateFn: func(_ context.Context, scope, id string, definition armauthorization.RoleDefinition, _ *armauthorization.RoleDefinitionsClientCreateOrUpdateOptions) (armauthorization.RoleDefinitionsClientCreateOrUpdateResponse, error) {
			sentScope, sentID, sent = scope, id, definition
			writeCalls++
			return armauthorization.RoleDefinitionsClientCreateOrUpdateResponse{RoleDefinition: definitionResult}, nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armauthorization.RoleDefinitionsClientGetOptions) (armauthorization.RoleDefinitionsClientGetResponse, error) {
			return armauthorization.RoleDefinitionsClientGetResponse{RoleDefinition: definitionResult}, nil
		},
		deleteFn: func(_ context.Context, scope, id string, _ *armauthorization.RoleDefinitionsClientDeleteOptions) (armauthorization.RoleDefinitionsClientDeleteResponse, error) {
			sentScope, sentID = scope, id
			deleteCalls++
			return armauthorization.RoleDefinitionsClientDeleteResponse{}, nil
		},
		listPagerFn: func(_ string, _ *armauthorization.RoleDefinitionsClientListOptions) *runtime.Pager[armauthorization.RoleDefinitionsClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armauthorization.RoleDefinitionsClientListResponse]{
				More: func(_ armauthorization.RoleDefinitionsClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armauthorization.RoleDefinitionsClientListResponse) (armauthorization.RoleDefinitionsClientListResponse, error) {
					return armauthorization.RoleDefinitionsClientListResponse{
						RoleDefinitionListResult: armauthorization.RoleDefinitionListResult{
							Value: []*armauthorization.RoleDefinition{
								{
									ID:         to.Ptr(testRoleDefinitionNativeID),
									Properties: &armauthorization.RoleDefinitionProperties{RoleType: to.Ptr("CustomRole")},
								},
								// Built-in roles are read-only and cannot be managed.
								{
									ID:         to.Ptr(testRoleDefinitionScope + "/providers/Microsoft.Authorization/roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7"),
									Properties: &armauthorization.RoleDefinitionProperties{RoleType: to.Ptr("BuiltInRole")},
								},
								// A nil entry must not panic the walk.
								nil,
							},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestRoleDefinition(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: testRoleDefinitionGUID,
			Properties: roleDefinitionDesired("formae conformance reader",
				[]any{"Microsoft.Storage/storageAccounts/read"}),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testRoleDefinitionNativeID, got.ProgressResult.NativeID)

		// Scope and GUID address the resource; neither is part of the body.
		require.Equal(t, testRoleDefinitionScope, sentScope)
		require.Equal(t, testRoleDefinitionGUID, sentID)
		require.Equal(t, "formae conformance reader", *sent.Properties.RoleName)
		require.Equal(t, "Microsoft.Storage/storageAccounts/read", *sent.Properties.Permissions[0].Actions[0])
		require.Equal(t, "Microsoft.Storage/storageAccounts/delete", *sent.Properties.Permissions[0].NotActions[0])
		require.Equal(t, testRoleDefinitionScope, *sent.Properties.AssignableScopes[0])
		// ARM only accepts CustomRole: built-in roles are read-only.
		require.Equal(t, "CustomRole", *sent.Properties.RoleType)
	})

	t.Run("Create_requires_scope", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": testRoleDefinitionGUID, "roleName": "x"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "scope is required")
	})

	t.Run("Create_requires_permissions", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": testRoleDefinitionGUID, "scope": testRoleDefinitionScope,
			"roleName": "x", "assignableScopes": []any{testRoleDefinitionScope},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "permissions is required")
	})

	t.Run("Create_requires_assignable_scopes", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": testRoleDefinitionGUID, "scope": testRoleDefinitionScope, "roleName": "x",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "assignableScopes is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testRoleDefinitionNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, testRoleDefinitionGUID, props["name"])
		// The scope comes off the native ID: it is not in the response body.
		require.Equal(t, testRoleDefinitionScope, props["scope"])
		require.Equal(t, "formae conformance reader", props["roleName"])
		require.Equal(t, "conformance test role", props["description"])
		require.Equal(t, "CustomRole", props["roleType"])
		require.Equal(t, []any{testRoleDefinitionScope}, props["assignableScopes"])

		permissions := props["permissions"].([]any)
		permission := permissions[0].(map[string]any)
		require.Equal(t, []any{"Microsoft.Storage/storageAccounts/read"}, permission["actions"])
		require.Equal(t, []any{"Microsoft.Storage/storageAccounts/delete"}, permission["notActions"])
		// ARM's empty data-plane arrays must not appear as declared lists.
		require.NotContains(t, permission, "dataActions")
		require.NotContains(t, permission, "notDataActions")
	})

	// A management-group or resource-group scoped definition has a different path
	// shape, and the provider segment's casing varies by caller.
	t.Run("IDParts_handles_any_scope_and_casing", func(t *testing.T) {
		scope, name, err := roleDefinitionIDParts("/providers/Microsoft.Management/managementGroups/mg-1/providers/microsoft.authorization/roleDefinitions/" + testRoleDefinitionGUID)
		require.NoError(t, err)
		require.Equal(t, "/providers/Microsoft.Management/managementGroups/mg-1", scope)
		require.Equal(t, testRoleDefinitionGUID, name)

		scope, name, err = roleDefinitionIDParts("/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Authorization/roleDefinitions/" + testRoleDefinitionGUID)
		require.NoError(t, err)
		require.Equal(t, "/subscriptions/sub-1/resourceGroups/rg-1", scope)
		require.Equal(t, testRoleDefinitionGUID, name)

		_, _, err = roleDefinitionIDParts("/subscriptions/sub-1/resourceGroups/rg-1")
		require.ErrorContains(t, err, "not a role definition resource ID")
	})

	// CreateOrUpdate is the only write verb this API has.
	t.Run("Update_reissues_create_or_update", func(t *testing.T) {
		before := writeCalls
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID: testRoleDefinitionNativeID,
			DesiredProperties: roleDefinitionDesired("formae conformance reader, revised",
				[]any{"Microsoft.Storage/storageAccounts/read", "Microsoft.Storage/storageAccounts/listKeys/action"}),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, writeCalls)
		require.Equal(t, "formae conformance reader, revised", *sent.Properties.RoleName)
		require.Len(t, sent.Properties.Permissions[0].Actions, 2)
		require.Equal(t, testRoleDefinitionScope, sentScope)
	})

	// There is no DeleteByID on this client: both halves come off the native ID.
	t.Run("Delete", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testRoleDefinitionNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
		require.Equal(t, testRoleDefinitionScope, sentScope)
		require.Equal(t, testRoleDefinitionGUID, sentID)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _ string, _ *armauthorization.RoleDefinitionsClientDeleteOptions) (armauthorization.RoleDefinitionsClientDeleteResponse, error) {
			return armauthorization.RoleDefinitionsClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testRoleDefinitionNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Status_is_always_success", func(t *testing.T) {
		got, err := prov.Status(context.Background(), &resource.StatusRequest{RequestID: "whatever"})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	// The scope lists built-in roles too; this provider can only manage custom ones.
	t.Run("List_returns_only_custom_roles", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"scope": testRoleDefinitionScope},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testRoleDefinitionNativeID}, got.NativeIDs)
	})

	t.Run("List_without_scope_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})

	t.Run("Read_NotFound", func(t *testing.T) {
		fake.getFn = func(_ context.Context, _, _ string, _ *armauthorization.RoleDefinitionsClientGetOptions) (armauthorization.RoleDefinitionsClientGetResponse, error) {
			return armauthorization.RoleDefinitionsClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testRoleDefinitionNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
	})
}
