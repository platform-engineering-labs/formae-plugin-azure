// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/keyvault/armkeyvault"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const (
	testAccessPolicyTenantID = "35412a0c-6726-4fc9-98ef-6e91adcb8d0e"
	testAccessPolicyObjectID = "11111111-2222-3333-4444-555555555555"
	testAccessPolicyVaultID  = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.KeyVault/vaults/kv-1"
	testAccessPolicyNativeID = testAccessPolicyVaultID + "/accessPolicies/" + testAccessPolicyObjectID
)

func newTestKeyVaultAccessPolicy(api vaultAccessPolicyAPI) *KeyVaultAccessPolicy {
	return &KeyVaultAccessPolicy{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

// vaultWithPolicies builds the parent vault as ARM would return it.
func vaultWithPolicies(entries ...*armkeyvault.AccessPolicyEntry) armkeyvault.Vault {
	return armkeyvault.Vault{
		ID:   to.Ptr(testAccessPolicyVaultID),
		Name: to.Ptr("kv-1"),
		Properties: &armkeyvault.VaultProperties{
			TenantID:       to.Ptr(testAccessPolicyTenantID),
			AccessPolicies: entries,
		},
	}
}

func policyEntry(objectID string, keys, secrets []string) *armkeyvault.AccessPolicyEntry {
	return &armkeyvault.AccessPolicyEntry{
		TenantID: to.Ptr(testAccessPolicyTenantID),
		ObjectID: to.Ptr(objectID),
		Permissions: &armkeyvault.Permissions{
			Keys:    keyVaultPermPtrs[armkeyvault.KeyPermissions](keys),
			Secrets: keyVaultPermPtrs[armkeyvault.SecretPermissions](secrets),
		},
	}
}

func TestKeyVaultAccessPolicy_CRUD(t *testing.T) {
	type call struct {
		kind armkeyvault.AccessPolicyUpdateKind
		rg   string
		name string
		body armkeyvault.VaultAccessPolicyParameters
	}
	var calls []call

	fake := &fakeVaultAccessPolicyAPI{
		getFn: func(_ context.Context, _, _ string, _ *armkeyvault.VaultsClientGetOptions) (armkeyvault.VaultsClientGetResponse, error) {
			return armkeyvault.VaultsClientGetResponse{Vault: vaultWithPolicies(
				policyEntry(testAccessPolicyObjectID, []string{"get", "list"}, []string{"get"}),
				policyEntry("99999999-9999-9999-9999-999999999999", []string{"all"}, nil),
			)}, nil
		},
		updateAccessPolicyFn: func(_ context.Context, rg, name string, kind armkeyvault.AccessPolicyUpdateKind, params armkeyvault.VaultAccessPolicyParameters, _ *armkeyvault.VaultsClientUpdateAccessPolicyOptions) (armkeyvault.VaultsClientUpdateAccessPolicyResponse, error) {
			calls = append(calls, call{kind: kind, rg: rg, name: name, body: params})
			return armkeyvault.VaultsClientUpdateAccessPolicyResponse{VaultAccessPolicyParameters: params}, nil
		},
	}
	prov := newTestKeyVaultAccessPolicy(fake)

	mkProps := func() json.RawMessage {
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName": "rg-1",
			"vaultName":         "kv-1",
			"tenantId":          testAccessPolicyTenantID,
			"objectId":          testAccessPolicyObjectID,
			"permissions": map[string]any{
				"keys":    []string{"get", "list"},
				"secrets": []string{"get"},
			},
		})
		return props
	}

	t.Run("Create_adds_one_entry", func(t *testing.T) {
		calls = nil
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testAccessPolicyNativeID, got.ProgressResult.NativeID)

		require.Len(t, calls, 1)
		require.Equal(t, armkeyvault.AccessPolicyUpdateKindAdd, calls[0].kind,
			"replace would overwrite every other policy on the vault")
		require.Equal(t, "rg-1", calls[0].rg)
		require.Equal(t, "kv-1", calls[0].name)
		sent := calls[0].body.Properties.AccessPolicies
		require.Len(t, sent, 1, "only this resource's own entry may be sent")
		require.Equal(t, testAccessPolicyObjectID, *sent[0].ObjectID)

		var serialized map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &serialized))
		require.Equal(t, "kv-1", serialized["vaultName"])
		require.Equal(t, testAccessPolicyObjectID, serialized["objectId"])
		require.Equal(t, map[string]any{
			"keys":    []any{"get", "list"},
			"secrets": []any{"get"},
		}, serialized["permissions"])
	})

	t.Run("Create_requires_objectId_and_permissions", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName": "rg-1", "vaultName": "kv-1", "tenantId": testAccessPolicyTenantID,
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "objectId")

		props, _ = json.Marshal(map[string]any{
			"resourceGroupName": "rg-1", "vaultName": "kv-1", "tenantId": testAccessPolicyTenantID,
			"objectId": testAccessPolicyObjectID,
		})
		_, err = prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "permissions")
	})

	t.Run("Read_returns_only_this_identitys_entry", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testAccessPolicyNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
		require.Equal(t, ResourceTypeKeyVaultAccessPolicy, got.ResourceType)

		var serialized map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &serialized))
		require.Equal(t, testAccessPolicyObjectID, serialized["objectId"])
		require.Equal(t, map[string]any{
			"keys":    []any{"get", "list"},
			"secrets": []any{"get"},
		}, serialized["permissions"])
	})

	t.Run("Read_omits_categories_the_vault_does_not_carry", func(t *testing.T) {
		fake.getFn = func(_ context.Context, _, _ string, _ *armkeyvault.VaultsClientGetOptions) (armkeyvault.VaultsClientGetResponse, error) {
			return armkeyvault.VaultsClientGetResponse{Vault: vaultWithPolicies(
				policyEntry(testAccessPolicyObjectID, []string{"get"}, nil),
			)}, nil
		}
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testAccessPolicyNativeID})
		require.NoError(t, err)

		var serialized map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &serialized))
		// An empty category must not read back as [] - that would be drift against
		// a desired state that never declared it.
		require.Equal(t, map[string]any{"keys": []any{"get"}}, serialized["permissions"])
	})

	t.Run("Read_missing_entry_on_a_live_vault_is_NotFound", func(t *testing.T) {
		fake.getFn = func(_ context.Context, _, _ string, _ *armkeyvault.VaultsClientGetOptions) (armkeyvault.VaultsClientGetResponse, error) {
			return armkeyvault.VaultsClientGetResponse{Vault: vaultWithPolicies()}, nil
		}
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testAccessPolicyNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
	})

	t.Run("Read_missing_vault_is_NotFound", func(t *testing.T) {
		fake.getFn = func(_ context.Context, _, _ string, _ *armkeyvault.VaultsClientGetOptions) (armkeyvault.VaultsClientGetResponse, error) {
			return armkeyvault.VaultsClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testAccessPolicyNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
	})

	t.Run("Update_removes_before_adding", func(t *testing.T) {
		fake.getFn = func(_ context.Context, _, _ string, _ *armkeyvault.VaultsClientGetOptions) (armkeyvault.VaultsClientGetResponse, error) {
			return armkeyvault.VaultsClientGetResponse{Vault: vaultWithPolicies(
				policyEntry(testAccessPolicyObjectID, []string{"get", "list"}, []string{"get"}),
			)}, nil
		}
		calls = nil
		desired, _ := json.Marshal(map[string]any{
			"resourceGroupName": "rg-1",
			"vaultName":         "kv-1",
			"tenantId":          testAccessPolicyTenantID,
			"objectId":          testAccessPolicyObjectID,
			"permissions":       map[string]any{"keys": []string{"get"}},
		})
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testAccessPolicyNativeID,
			DesiredProperties: desired,
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testAccessPolicyNativeID, got.ProgressResult.NativeID)

		require.Len(t, calls, 2, "a bare add would merge the old permissions back in")
		require.Equal(t, armkeyvault.AccessPolicyUpdateKindRemove, calls[0].kind)
		require.Equal(t, armkeyvault.AccessPolicyUpdateKindAdd, calls[1].kind)

		// The remove must carry the entry as the vault currently holds it, not the
		// desired one, so it clears the old permissions under either reading of
		// what ARM's remove does.
		removed := calls[0].body.Properties.AccessPolicies[0]
		require.Equal(t, []string{"get", "list"}, permissionStrings(removed.Permissions.Keys))
		require.Equal(t, []string{"get"}, permissionStrings(removed.Permissions.Secrets))
		added := calls[1].body.Properties.AccessPolicies[0]
		require.Equal(t, []string{"get"}, permissionStrings(added.Permissions.Keys))
		require.Nil(t, permissionStrings(added.Permissions.Secrets))

		var serialized map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &serialized))
		require.Equal(t, map[string]any{"keys": []any{"get"}}, serialized["permissions"])
	})

	t.Run("Update_reports_the_add_failure", func(t *testing.T) {
		fake.updateAccessPolicyFn = func(_ context.Context, _, _ string, kind armkeyvault.AccessPolicyUpdateKind, params armkeyvault.VaultAccessPolicyParameters, _ *armkeyvault.VaultsClientUpdateAccessPolicyOptions) (armkeyvault.VaultsClientUpdateAccessPolicyResponse, error) {
			if kind == armkeyvault.AccessPolicyUpdateKindAdd {
				return armkeyvault.VaultsClientUpdateAccessPolicyResponse{}, &azcore.ResponseError{StatusCode: 403, ErrorCode: "AuthorizationFailed"}
			}
			return armkeyvault.VaultsClientUpdateAccessPolicyResponse{VaultAccessPolicyParameters: params}, nil
		}
		desired, _ := json.Marshal(map[string]any{
			"resourceGroupName": "rg-1", "vaultName": "kv-1", "tenantId": testAccessPolicyTenantID,
			"objectId": testAccessPolicyObjectID, "permissions": map[string]any{"keys": []string{"get"}},
		})
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{NativeID: testAccessPolicyNativeID, DesiredProperties: desired})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.Contains(t, got.ProgressResult.StatusMessage, "AuthorizationFailed")

		fake.updateAccessPolicyFn = func(_ context.Context, rg, name string, kind armkeyvault.AccessPolicyUpdateKind, params armkeyvault.VaultAccessPolicyParameters, _ *armkeyvault.VaultsClientUpdateAccessPolicyOptions) (armkeyvault.VaultsClientUpdateAccessPolicyResponse, error) {
			calls = append(calls, call{kind: kind, rg: rg, name: name, body: params})
			return armkeyvault.VaultsClientUpdateAccessPolicyResponse{VaultAccessPolicyParameters: params}, nil
		}
	})

	t.Run("Delete_removes_the_entry", func(t *testing.T) {
		calls = nil
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testAccessPolicyNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Len(t, calls, 1)
		require.Equal(t, armkeyvault.AccessPolicyUpdateKindRemove, calls[0].kind)
		removed := calls[0].body.Properties.AccessPolicies[0]
		require.Equal(t, testAccessPolicyObjectID, *removed.ObjectID)
		require.Equal(t, []string{"get", "list"}, permissionStrings(removed.Permissions.Keys),
			"the stored entry is sent verbatim so the remove lands under either ARM semantics")
	})

	t.Run("Delete_of_an_absent_entry_is_success_without_a_call", func(t *testing.T) {
		fake.getFn = func(_ context.Context, _, _ string, _ *armkeyvault.VaultsClientGetOptions) (armkeyvault.VaultsClientGetResponse, error) {
			return armkeyvault.VaultsClientGetResponse{Vault: vaultWithPolicies()}, nil
		}
		calls = nil
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testAccessPolicyNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Empty(t, calls)
	})

	t.Run("Delete_of_a_vault_that_is_gone_is_success", func(t *testing.T) {
		fake.getFn = func(_ context.Context, _, _ string, _ *armkeyvault.VaultsClientGetOptions) (armkeyvault.VaultsClientGetResponse, error) {
			return armkeyvault.VaultsClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testAccessPolicyNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_reports_one_id_per_entry", func(t *testing.T) {
		fake.getFn = func(_ context.Context, _, _ string, _ *armkeyvault.VaultsClientGetOptions) (armkeyvault.VaultsClientGetResponse, error) {
			return armkeyvault.VaultsClientGetResponse{Vault: vaultWithPolicies(
				policyEntry(testAccessPolicyObjectID, []string{"get"}, nil),
				policyEntry("99999999-9999-9999-9999-999999999999", []string{"all"}, nil),
			)}, nil
		}
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "vaultName": "kv-1"},
		})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 2)
		require.Equal(t, testAccessPolicyNativeID, got.NativeIDs[0])
	})

	t.Run("List_without_a_parent_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})

	t.Run("List_of_a_vault_that_is_gone_is_empty", func(t *testing.T) {
		fake.getFn = func(_ context.Context, _, _ string, _ *armkeyvault.VaultsClientGetOptions) (armkeyvault.VaultsClientGetResponse, error) {
			return armkeyvault.VaultsClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "vaultName": "kv-1"},
		})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure_with_a_message", func(t *testing.T) {
		fake.updateAccessPolicyFn = func(_ context.Context, _, _ string, _ armkeyvault.AccessPolicyUpdateKind, _ armkeyvault.VaultAccessPolicyParameters, _ *armkeyvault.VaultsClientUpdateAccessPolicyOptions) (armkeyvault.VaultsClientUpdateAccessPolicyResponse, error) {
			return armkeyvault.VaultsClientUpdateAccessPolicyResponse{}, &azcore.ResponseError{StatusCode: 403, ErrorCode: "AuthorizationFailed"}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.Contains(t, got.ProgressResult.StatusMessage, "AuthorizationFailed")
	})
}

func TestAccessPolicyIDParts(t *testing.T) {
	rg, vaultName, objectID, err := accessPolicyIDParts(testAccessPolicyNativeID)
	require.NoError(t, err)
	require.Equal(t, "rg-1", rg)
	require.Equal(t, "kv-1", vaultName)
	require.Equal(t, testAccessPolicyObjectID, objectID)

	// The bare vault id carries no access policy segment.
	_, _, _, err = accessPolicyIDParts(testAccessPolicyVaultID)
	require.Error(t, err)
}

// --- Test helpers ---

type fakeVaultAccessPolicyAPI struct {
	getFn                func(ctx context.Context, rgName, vaultName string, opts *armkeyvault.VaultsClientGetOptions) (armkeyvault.VaultsClientGetResponse, error)
	updateAccessPolicyFn func(ctx context.Context, rgName, vaultName string, kind armkeyvault.AccessPolicyUpdateKind, params armkeyvault.VaultAccessPolicyParameters, opts *armkeyvault.VaultsClientUpdateAccessPolicyOptions) (armkeyvault.VaultsClientUpdateAccessPolicyResponse, error)
}

func (f *fakeVaultAccessPolicyAPI) Get(ctx context.Context, rgName, vaultName string, opts *armkeyvault.VaultsClientGetOptions) (armkeyvault.VaultsClientGetResponse, error) {
	return f.getFn(ctx, rgName, vaultName, opts)
}

func (f *fakeVaultAccessPolicyAPI) UpdateAccessPolicy(ctx context.Context, rgName, vaultName string, kind armkeyvault.AccessPolicyUpdateKind, params armkeyvault.VaultAccessPolicyParameters, opts *armkeyvault.VaultsClientUpdateAccessPolicyOptions) (armkeyvault.VaultsClientUpdateAccessPolicyResponse, error) {
	return f.updateAccessPolicyFn(ctx, rgName, vaultName, kind, params, opts)
}
