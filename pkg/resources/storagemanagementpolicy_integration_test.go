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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const (
	testMgmtPolicyRG      = "test-rg"
	testMgmtPolicyAccount = "teststorageacct"
	testMgmtPolicyID      = "/subscriptions/sub-1/resourceGroups/test-rg/providers/Microsoft.Storage/storageAccounts/teststorageacct/managementPolicies/default"
)

func newTestStorageManagementPolicy(api managementPoliciesAPI) *StorageManagementPolicy {
	return &StorageManagementPolicy{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

// echoPolicy returns what ARM would return for the fixture rule set.
func echoPolicy(props armstorage.ManagementPolicy) armstorage.ManagementPolicy {
	props.ID = to.Ptr(testMgmtPolicyID)
	props.Name = to.Ptr("DefaultManagementPolicy")
	return props
}

func mgmtPolicyDesired(deleteDays int, prefix string) []byte {
	rule := map[string]any{
		"name":    "expire-logs",
		"enabled": true,
		"definition": map[string]any{
			"actions": map[string]any{
				"baseBlob": map[string]any{
					"tierToCool":  map[string]any{"daysAfterModificationGreaterThan": 30},
					"deleteAfter": map[string]any{"daysAfterModificationGreaterThan": deleteDays},
				},
			},
			"filters": map[string]any{
				"blobTypes":   []string{"blockBlob"},
				"prefixMatch": []string{prefix},
			},
		},
	}
	out, _ := json.Marshal(map[string]any{
		"resourceGroupName":  testMgmtPolicyRG,
		"storageAccountName": testMgmtPolicyAccount,
		"rules":              []any{rule},
	})
	return out
}

func TestStorageManagementPolicy_CRUD(t *testing.T) {
	var lastSent armstorage.ManagementPolicy
	fake := &fakeManagementPoliciesAPI{
		createOrUpdateFn: func(_ context.Context, _, _ string, name armstorage.ManagementPolicyName, props armstorage.ManagementPolicy, _ *armstorage.ManagementPoliciesClientCreateOrUpdateOptions) (armstorage.ManagementPoliciesClientCreateOrUpdateResponse, error) {
			require.Equal(t, armstorage.ManagementPolicyNameDefault, name)
			lastSent = props
			return armstorage.ManagementPoliciesClientCreateOrUpdateResponse{ManagementPolicy: echoPolicy(props)}, nil
		},
		getFn: func(_ context.Context, _, _ string, _ armstorage.ManagementPolicyName, _ *armstorage.ManagementPoliciesClientGetOptions) (armstorage.ManagementPoliciesClientGetResponse, error) {
			return armstorage.ManagementPoliciesClientGetResponse{ManagementPolicy: echoPolicy(lastSent)}, nil
		},
		deleteFn: func(_ context.Context, _, _ string, _ armstorage.ManagementPolicyName, _ *armstorage.ManagementPoliciesClientDeleteOptions) (armstorage.ManagementPoliciesClientDeleteResponse, error) {
			return armstorage.ManagementPoliciesClientDeleteResponse{}, nil
		},
	}
	prov := newTestStorageManagementPolicy(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mgmtPolicyDesired(365, "logs/")})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testMgmtPolicyID, got.ProgressResult.NativeID)

		// Every rule must go out as type Lifecycle — ARM rejects anything else.
		require.Len(t, lastSent.Properties.Policy.Rules, 1)
		require.Equal(t, armstorage.RuleTypeLifecycle, *lastSent.Properties.Policy.Rules[0].Type)
		require.EqualValues(t, 365, *lastSent.Properties.Policy.Rules[0].Definition.Actions.BaseBlob.Delete.DaysAfterModificationGreaterThan)
		require.Nil(t, lastSent.Properties.Policy.Rules[0].Definition.Actions.BaseBlob.TierToArchive)

		// Read-back shape must match the desired shape or reconcile never converges.
		var serialized map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &serialized))
		rules := serialized["rules"].([]any)
		require.Len(t, rules, 1)
		rule := rules[0].(map[string]any)
		require.Equal(t, "expire-logs", rule["name"])
		require.Equal(t, true, rule["enabled"])
		def := rule["definition"].(map[string]any)
		bb := def["actions"].(map[string]any)["baseBlob"].(map[string]any)
		require.EqualValues(t, 30, bb["tierToCool"].(map[string]any)["daysAfterModificationGreaterThan"])
		require.EqualValues(t, 365, bb["deleteAfter"].(map[string]any)["daysAfterModificationGreaterThan"])
		require.NotContains(t, bb, "tierToArchive")
		filters := def["filters"].(map[string]any)
		require.Equal(t, []any{"blockBlob"}, filters["blobTypes"])
		require.Equal(t, []any{"logs/"}, filters["prefixMatch"])
	})

	t.Run("Create_requires_account", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"resourceGroupName": testMgmtPolicyRG, "rules": []any{}})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.Error(t, err)
	})

	t.Run("Create_requires_a_rule", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName":  testMgmtPolicyRG,
			"storageAccountName": testMgmtPolicyAccount,
			"rules":              []any{},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.Error(t, err)
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testMgmtPolicyID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var serialized map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &serialized))
		require.Equal(t, testMgmtPolicyRG, serialized["resourceGroupName"])
		require.Equal(t, testMgmtPolicyAccount, serialized["storageAccountName"])
		// The singleton ARM name is never surfaced as a property.
		require.NotContains(t, serialized, "name")
	})

	t.Run("Update_replaces_rule_set_and_keeps_native_id", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testMgmtPolicyID,
			DesiredProperties: mgmtPolicyDesired(90, "archive/"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testMgmtPolicyID, got.ProgressResult.NativeID)
		require.EqualValues(t, 90, *lastSent.Properties.Policy.Rules[0].Definition.Actions.BaseBlob.Delete.DaysAfterModificationGreaterThan)
	})

	t.Run("Delete", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testMgmtPolicyID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _ string, _ armstorage.ManagementPolicyName, _ *armstorage.ManagementPoliciesClientDeleteOptions) (armstorage.ManagementPoliciesClientDeleteResponse, error) {
			return armstorage.ManagementPoliciesClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testMgmtPolicyID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_probes_the_singleton", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{
				"resourceGroupName":  testMgmtPolicyRG,
				"storageAccountName": testMgmtPolicyAccount,
			},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testMgmtPolicyID}, got.NativeIDs)
	})

	t.Run("List_without_parent_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.createOrUpdateFn = func(_ context.Context, _, _ string, _ armstorage.ManagementPolicyName, _ armstorage.ManagementPolicy, _ *armstorage.ManagementPoliciesClientCreateOrUpdateOptions) (armstorage.ManagementPoliciesClientCreateOrUpdateResponse, error) {
			return armstorage.ManagementPoliciesClientCreateOrUpdateResponse{}, &azcore.ResponseError{StatusCode: 403}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mgmtPolicyDesired(365, "logs/")})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

func TestStorageManagementPolicy_NotFound(t *testing.T) {
	fake := &fakeManagementPoliciesAPI{
		getFn: func(_ context.Context, _, _ string, _ armstorage.ManagementPolicyName, _ *armstorage.ManagementPoliciesClientGetOptions) (armstorage.ManagementPoliciesClientGetResponse, error) {
			return armstorage.ManagementPoliciesClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	prov := newTestStorageManagementPolicy(fake)

	t.Run("Read_maps_404", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testMgmtPolicyID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
	})

	// An account with no policy must list as empty, not error — otherwise discovery
	// of every account without a lifecycle policy fails.
	t.Run("List_maps_404_to_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{
				"resourceGroupName":  testMgmtPolicyRG,
				"storageAccountName": testMgmtPolicyAccount,
			},
		})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})
}

// --- Test helpers ---

type fakeManagementPoliciesAPI struct {
	createOrUpdateFn func(ctx context.Context, resourceGroupName, accountName string, name armstorage.ManagementPolicyName, properties armstorage.ManagementPolicy, options *armstorage.ManagementPoliciesClientCreateOrUpdateOptions) (armstorage.ManagementPoliciesClientCreateOrUpdateResponse, error)
	getFn            func(ctx context.Context, resourceGroupName, accountName string, name armstorage.ManagementPolicyName, options *armstorage.ManagementPoliciesClientGetOptions) (armstorage.ManagementPoliciesClientGetResponse, error)
	deleteFn         func(ctx context.Context, resourceGroupName, accountName string, name armstorage.ManagementPolicyName, options *armstorage.ManagementPoliciesClientDeleteOptions) (armstorage.ManagementPoliciesClientDeleteResponse, error)
}

func (f *fakeManagementPoliciesAPI) CreateOrUpdate(ctx context.Context, resourceGroupName, accountName string, name armstorage.ManagementPolicyName, properties armstorage.ManagementPolicy, options *armstorage.ManagementPoliciesClientCreateOrUpdateOptions) (armstorage.ManagementPoliciesClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, resourceGroupName, accountName, name, properties, options)
}

func (f *fakeManagementPoliciesAPI) Get(ctx context.Context, resourceGroupName, accountName string, name armstorage.ManagementPolicyName, options *armstorage.ManagementPoliciesClientGetOptions) (armstorage.ManagementPoliciesClientGetResponse, error) {
	return f.getFn(ctx, resourceGroupName, accountName, name, options)
}

func (f *fakeManagementPoliciesAPI) Delete(ctx context.Context, resourceGroupName, accountName string, name armstorage.ManagementPolicyName, options *armstorage.ManagementPoliciesClientDeleteOptions) (armstorage.ManagementPoliciesClientDeleteResponse, error) {
	return f.deleteFn(ctx, resourceGroupName, accountName, name, options)
}
