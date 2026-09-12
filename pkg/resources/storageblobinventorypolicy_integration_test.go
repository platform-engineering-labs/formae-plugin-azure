// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build integration

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

const testBlobInventoryPolicyNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Storage/storageAccounts/acct1/inventoryPolicies/default"

func blobInventoryDesired(destination string, schedule string) json.RawMessage {
	props, _ := json.Marshal(map[string]any{
		"resourceGroupName":  "rg-1",
		"storageAccountName": "acct1",
		"enabled":            true,
		"rules": []map[string]any{{
			"name":        "daily-blob-report",
			"destination": destination,
			"enabled":     true,
			"definition": map[string]any{
				"format":       "Csv",
				"objectType":   "Blob",
				"schedule":     schedule,
				"schemaFields": []string{"Name", "Creation-Time", "Content-Length"},
				"filters": map[string]any{
					"blobTypes":   []string{"blockBlob"},
					"prefixMatch": []string{"data/"},
				},
			},
		}},
	})
	return props
}

func echoBlobInventoryPolicy(sent armstorage.BlobInventoryPolicy) armstorage.BlobInventoryPolicy {
	sent.ID = to.Ptr(testBlobInventoryPolicyNativeID)
	sent.Name = to.Ptr("default")
	return sent
}

func TestStorageBlobInventoryPolicy_CRUD(t *testing.T) {
	var lastSent armstorage.BlobInventoryPolicy
	var lastName armstorage.BlobInventoryPolicyName
	fake := &fakeBlobInventoryPoliciesAPI{
		createOrUpdateFn: func(_ context.Context, _, _ string, name armstorage.BlobInventoryPolicyName, props armstorage.BlobInventoryPolicy, _ *armstorage.BlobInventoryPoliciesClientCreateOrUpdateOptions) (armstorage.BlobInventoryPoliciesClientCreateOrUpdateResponse, error) {
			lastSent, lastName = props, name
			return armstorage.BlobInventoryPoliciesClientCreateOrUpdateResponse{BlobInventoryPolicy: echoBlobInventoryPolicy(props)}, nil
		},
		getFn: func(_ context.Context, _, _ string, _ armstorage.BlobInventoryPolicyName, _ *armstorage.BlobInventoryPoliciesClientGetOptions) (armstorage.BlobInventoryPoliciesClientGetResponse, error) {
			return armstorage.BlobInventoryPoliciesClientGetResponse{BlobInventoryPolicy: echoBlobInventoryPolicy(lastSent)}, nil
		},
		deleteFn: func(_ context.Context, _, _ string, _ armstorage.BlobInventoryPolicyName, _ *armstorage.BlobInventoryPoliciesClientDeleteOptions) (armstorage.BlobInventoryPoliciesClientDeleteResponse, error) {
			return armstorage.BlobInventoryPoliciesClientDeleteResponse{}, nil
		},
	}
	prov := newTestStorageBlobInventoryPolicy(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: blobInventoryDesired("reports", "Daily")})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testBlobInventoryPolicyNativeID, got.ProgressResult.NativeID)

		// The singleton name and the policy type are both provider-fixed.
		require.Equal(t, armstorage.BlobInventoryPolicyNameDefault, lastName)
		require.Equal(t, armstorage.InventoryRuleTypeInventory, *lastSent.Properties.Policy.Type)
		require.True(t, *lastSent.Properties.Policy.Enabled)
		require.Len(t, lastSent.Properties.Policy.Rules, 1)
		rule := lastSent.Properties.Policy.Rules[0]
		require.Equal(t, "reports", *rule.Destination)
		require.Equal(t, armstorage.FormatCSV, *rule.Definition.Format)
		require.Equal(t, armstorage.ObjectTypeBlob, *rule.Definition.ObjectType)
		require.Equal(t, armstorage.ScheduleDaily, *rule.Definition.Schedule)
		require.Len(t, rule.Definition.SchemaFields, 3)

		var serialized map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &serialized))
		require.Equal(t, "rg-1", serialized["resourceGroupName"])
		require.Equal(t, "acct1", serialized["storageAccountName"])
		require.Equal(t, true, serialized["enabled"])
		// The singleton ARM name is never surfaced as a property.
		require.NotContains(t, serialized, "name")
		rules := serialized["rules"].([]any)
		require.Len(t, rules, 1)
		readRule := rules[0].(map[string]any)
		require.Equal(t, "daily-blob-report", readRule["name"])
		require.Equal(t, "reports", readRule["destination"])
		def := readRule["definition"].(map[string]any)
		require.Equal(t, "Csv", def["format"])
		require.Equal(t, "Blob", def["objectType"])
		require.Equal(t, "Daily", def["schedule"])
		filters := def["filters"].(map[string]any)
		require.Equal(t, []any{"blockBlob"}, filters["blobTypes"])
		require.Equal(t, []any{"data/"}, filters["prefixMatch"])
		// Unset include-flags must stay absent, not read back as false.
		require.NotContains(t, filters, "includeBlobVersions")
		require.NotContains(t, filters, "includeSnapshots")
		require.NotContains(t, filters, "includeDeleted")
	})

	t.Run("Create_requires_storageAccountName", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"resourceGroupName": "rg-1", "rules": []any{}})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "storageAccountName is required")
	})

	t.Run("Create_requires_a_rule", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName":  "rg-1",
			"storageAccountName": "acct1",
			"rules":              []any{},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "at least one rule is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testBlobInventoryPolicyNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
		require.Equal(t, ResourceTypeStorageBlobInventoryPolicy, got.ResourceType)
	})

	t.Run("Update_replaces_the_rule_set_and_keeps_the_native_id", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testBlobInventoryPolicyNativeID,
			DesiredProperties: blobInventoryDesired("archive", "Weekly"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testBlobInventoryPolicyNativeID, got.ProgressResult.NativeID)
		require.Equal(t, "archive", *lastSent.Properties.Policy.Rules[0].Destination)
		require.Equal(t, armstorage.ScheduleWeekly, *lastSent.Properties.Policy.Rules[0].Definition.Schedule)
	})

	t.Run("Delete", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testBlobInventoryPolicyNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _ string, _ armstorage.BlobInventoryPolicyName, _ *armstorage.BlobInventoryPoliciesClientDeleteOptions) (armstorage.BlobInventoryPoliciesClientDeleteResponse, error) {
			return armstorage.BlobInventoryPoliciesClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testBlobInventoryPolicyNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Status_rereads", func(t *testing.T) {
		got, err := prov.Status(context.Background(), &resource.StatusRequest{
			RequestID: "req-1",
			NativeID:  testBlobInventoryPolicyNativeID,
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testBlobInventoryPolicyNativeID, got.ProgressResult.NativeID)
	})

	t.Run("List_probes_the_singleton", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "storageAccountName": "acct1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testBlobInventoryPolicyNativeID}, got.NativeIDs)
	})

	t.Run("List_without_parent_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})
}

func TestStorageBlobInventoryPolicy_Failures(t *testing.T) {
	fake := &fakeBlobInventoryPoliciesAPI{
		createOrUpdateFn: func(_ context.Context, _, _ string, _ armstorage.BlobInventoryPolicyName, _ armstorage.BlobInventoryPolicy, _ *armstorage.BlobInventoryPoliciesClientCreateOrUpdateOptions) (armstorage.BlobInventoryPoliciesClientCreateOrUpdateResponse, error) {
			return armstorage.BlobInventoryPoliciesClientCreateOrUpdateResponse{}, &azcore.ResponseError{StatusCode: 400, ErrorCode: "InvalidBlobInventoryPolicy"}
		},
		getFn: func(_ context.Context, _, _ string, _ armstorage.BlobInventoryPolicyName, _ *armstorage.BlobInventoryPoliciesClientGetOptions) (armstorage.BlobInventoryPoliciesClientGetResponse, error) {
			return armstorage.BlobInventoryPoliciesClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	prov := newTestStorageBlobInventoryPolicy(fake)

	t.Run("Create_failure_reports_the_provider_error", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: blobInventoryDesired("reports", "Daily")})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.Equal(t, resource.OperationErrorCodeInvalidRequest, got.ProgressResult.ErrorCode)
		require.Contains(t, got.ProgressResult.StatusMessage, "InvalidBlobInventoryPolicy")
	})

	t.Run("Read_maps_404", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testBlobInventoryPolicyNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
	})

	// An account with no inventory policy must list as empty, not error, or
	// discovery of every such account fails.
	t.Run("List_maps_404_to_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "storageAccountName": "acct1"},
		})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})
}

// --- Test helpers ---

func newTestStorageBlobInventoryPolicy(api storageBlobInventoryPoliciesAPI) *StorageBlobInventoryPolicy {
	return &StorageBlobInventoryPolicy{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

type fakeBlobInventoryPoliciesAPI struct {
	createOrUpdateFn func(ctx context.Context, rgName, accountName string, name armstorage.BlobInventoryPolicyName, properties armstorage.BlobInventoryPolicy, opts *armstorage.BlobInventoryPoliciesClientCreateOrUpdateOptions) (armstorage.BlobInventoryPoliciesClientCreateOrUpdateResponse, error)
	getFn            func(ctx context.Context, rgName, accountName string, name armstorage.BlobInventoryPolicyName, opts *armstorage.BlobInventoryPoliciesClientGetOptions) (armstorage.BlobInventoryPoliciesClientGetResponse, error)
	deleteFn         func(ctx context.Context, rgName, accountName string, name armstorage.BlobInventoryPolicyName, opts *armstorage.BlobInventoryPoliciesClientDeleteOptions) (armstorage.BlobInventoryPoliciesClientDeleteResponse, error)
}

func (f *fakeBlobInventoryPoliciesAPI) CreateOrUpdate(ctx context.Context, rgName, accountName string, name armstorage.BlobInventoryPolicyName, properties armstorage.BlobInventoryPolicy, opts *armstorage.BlobInventoryPoliciesClientCreateOrUpdateOptions) (armstorage.BlobInventoryPoliciesClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, accountName, name, properties, opts)
}

func (f *fakeBlobInventoryPoliciesAPI) Get(ctx context.Context, rgName, accountName string, name armstorage.BlobInventoryPolicyName, opts *armstorage.BlobInventoryPoliciesClientGetOptions) (armstorage.BlobInventoryPoliciesClientGetResponse, error) {
	return f.getFn(ctx, rgName, accountName, name, opts)
}

func (f *fakeBlobInventoryPoliciesAPI) Delete(ctx context.Context, rgName, accountName string, name armstorage.BlobInventoryPolicyName, opts *armstorage.BlobInventoryPoliciesClientDeleteOptions) (armstorage.BlobInventoryPoliciesClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, accountName, name, opts)
}
