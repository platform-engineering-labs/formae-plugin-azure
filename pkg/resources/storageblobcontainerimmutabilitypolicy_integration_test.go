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

const (
	testImmutabilityPolicyNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Storage/storageAccounts/acct1/blobServices/default/containers/cont1/immutabilityPolicies/default"
	testImmutabilityPolicyETag     = "\"8d59f7f5e0e0c1a\""
)

func immutabilityDesired(days int, appendWrites bool) json.RawMessage {
	props, _ := json.Marshal(map[string]any{
		"resourceGroupName":                     "rg-1",
		"storageAccountName":                    "acct1",
		"containerName":                         "cont1",
		"immutabilityPeriodSinceCreationInDays": days,
		"allowProtectedAppendWrites":            appendWrites,
	})
	return props
}

// echoImmutabilityPolicy answers the way ARM does: the sent properties come back
// with the ETag and the Unlocked state ARM assigns to a new policy.
func echoImmutabilityPolicy(sent *armstorage.ImmutabilityPolicy) armstorage.ImmutabilityPolicy {
	out := armstorage.ImmutabilityPolicy{
		ID:   to.Ptr(testImmutabilityPolicyNativeID),
		Name: to.Ptr("default"),
		Etag: to.Ptr(testImmutabilityPolicyETag),
	}
	if sent != nil && sent.Properties != nil {
		props := *sent.Properties
		props.State = to.Ptr(armstorage.ImmutabilityPolicyStateUnlocked)
		out.Properties = &props
	}
	return out
}

func TestStorageBlobContainerImmutabilityPolicy_CRUD(t *testing.T) {
	var current armstorage.ImmutabilityPolicy
	var lastOptions *armstorage.BlobContainersClientCreateOrUpdateImmutabilityPolicyOptions
	fake := &fakeBlobContainerImmutabilityPolicyAPI{
		createOrUpdateFn: func(_ context.Context, _, _, _ string, opts *armstorage.BlobContainersClientCreateOrUpdateImmutabilityPolicyOptions) (armstorage.BlobContainersClientCreateOrUpdateImmutabilityPolicyResponse, error) {
			lastOptions = opts
			var sent *armstorage.ImmutabilityPolicy
			if opts != nil {
				sent = opts.Parameters
			}
			current = echoImmutabilityPolicy(sent)
			return armstorage.BlobContainersClientCreateOrUpdateImmutabilityPolicyResponse{ImmutabilityPolicy: current}, nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ *armstorage.BlobContainersClientGetImmutabilityPolicyOptions) (armstorage.BlobContainersClientGetImmutabilityPolicyResponse, error) {
			return armstorage.BlobContainersClientGetImmutabilityPolicyResponse{ImmutabilityPolicy: current}, nil
		},
		deleteFn: func(_ context.Context, _, _, _, _ string, _ *armstorage.BlobContainersClientDeleteImmutabilityPolicyOptions) (armstorage.BlobContainersClientDeleteImmutabilityPolicyResponse, error) {
			return armstorage.BlobContainersClientDeleteImmutabilityPolicyResponse{}, nil
		},
	}
	prov := newTestStorageBlobContainerImmutabilityPolicy(fake)

	t.Run("Create_sends_no_if_match", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: immutabilityDesired(7, false)})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testImmutabilityPolicyNativeID, got.ProgressResult.NativeID)

		// There is nothing to conflict with on a create.
		require.Nil(t, lastOptions.IfMatch)
		require.EqualValues(t, 7, *lastOptions.Parameters.Properties.ImmutabilityPeriodSinceCreationInDays)
		require.False(t, *lastOptions.Parameters.Properties.AllowProtectedAppendWrites)
		require.Nil(t, lastOptions.Parameters.Properties.AllowProtectedAppendWritesAll)

		var serialized map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &serialized))
		require.Equal(t, "rg-1", serialized["resourceGroupName"])
		require.Equal(t, "acct1", serialized["storageAccountName"])
		require.Equal(t, "cont1", serialized["containerName"])
		require.EqualValues(t, 7, serialized["immutabilityPeriodSinceCreationInDays"])
		require.Equal(t, false, serialized["allowProtectedAppendWrites"])
		// A new policy is Unlocked, and the state is reported as an output only.
		require.Equal(t, "Unlocked", serialized["state"])
		// Unset, so it must stay absent rather than read back as false.
		require.NotContains(t, serialized, "allowProtectedAppendWritesAll")
		// The ETag is fetched on demand, never carried on the resource.
		require.NotContains(t, serialized, "etag")
	})

	t.Run("allowProtectedAppendWritesAll_replaces_the_narrower_flag", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName":                     "rg-1",
			"storageAccountName":                    "acct1",
			"containerName":                         "cont1",
			"immutabilityPeriodSinceCreationInDays": 7,
			"allowProtectedAppendWritesAll":         true,
		})
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		// The two flags are mutually exclusive when true, so only one goes out.
		require.Nil(t, lastOptions.Parameters.Properties.AllowProtectedAppendWrites)
		require.True(t, *lastOptions.Parameters.Properties.AllowProtectedAppendWritesAll)

		var serialized map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &serialized))
		require.Equal(t, true, serialized["allowProtectedAppendWritesAll"])
		// The narrower flag carries a schema default, so it is always reported.
		require.Equal(t, false, serialized["allowProtectedAppendWrites"])
	})

	t.Run("Create_requires_containerName", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName":                     "rg-1",
			"storageAccountName":                    "acct1",
			"immutabilityPeriodSinceCreationInDays": 7,
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "containerName is required")
	})

	t.Run("Create_requires_the_retention_period", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName":  "rg-1",
			"storageAccountName": "acct1",
			"containerName":      "cont1",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "immutabilityPeriodSinceCreationInDays is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testImmutabilityPolicyNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
		require.Equal(t, ResourceTypeStorageBlobContainerImmutabilityPolicy, got.ResourceType)
	})

	t.Run("Update_sends_the_current_etag_as_if_match", func(t *testing.T) {
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: immutabilityDesired(7, false)})
		require.NoError(t, err)

		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testImmutabilityPolicyNativeID,
			DesiredProperties: immutabilityDesired(30, true),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testImmutabilityPolicyNativeID, got.ProgressResult.NativeID)

		// ARM rejects a modification without If-Match.
		require.NotNil(t, lastOptions.IfMatch)
		require.Equal(t, testImmutabilityPolicyETag, *lastOptions.IfMatch)
		require.EqualValues(t, 30, *lastOptions.Parameters.Properties.ImmutabilityPeriodSinceCreationInDays)
		require.True(t, *lastOptions.Parameters.Properties.AllowProtectedAppendWrites)
	})

	t.Run("Update_derives_the_container_from_the_native_id", func(t *testing.T) {
		var seenRG, seenAcct, seenCont string
		fake.createOrUpdateFn = func(_ context.Context, rg, acct, cont string, opts *armstorage.BlobContainersClientCreateOrUpdateImmutabilityPolicyOptions) (armstorage.BlobContainersClientCreateOrUpdateImmutabilityPolicyResponse, error) {
			seenRG, seenAcct, seenCont, lastOptions = rg, acct, cont, opts
			return armstorage.BlobContainersClientCreateOrUpdateImmutabilityPolicyResponse{ImmutabilityPolicy: current}, nil
		}
		desired, _ := json.Marshal(map[string]any{"immutabilityPeriodSinceCreationInDays": 14})
		_, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testImmutabilityPolicyNativeID,
			DesiredProperties: desired,
		})
		require.NoError(t, err)
		require.Equal(t, "rg-1", seenRG)
		require.Equal(t, "acct1", seenAcct)
		require.Equal(t, "cont1", seenCont)
	})

	t.Run("Delete_sends_the_etag", func(t *testing.T) {
		var seenIfMatch string
		fake.deleteFn = func(_ context.Context, _, _, _, ifMatch string, _ *armstorage.BlobContainersClientDeleteImmutabilityPolicyOptions) (armstorage.BlobContainersClientDeleteImmutabilityPolicyResponse, error) {
			seenIfMatch = ifMatch
			return armstorage.BlobContainersClientDeleteImmutabilityPolicyResponse{}, nil
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testImmutabilityPolicyNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testImmutabilityPolicyETag, seenIfMatch)
	})

	t.Run("Status_rereads", func(t *testing.T) {
		got, err := prov.Status(context.Background(), &resource.StatusRequest{
			RequestID: "req-1",
			NativeID:  testImmutabilityPolicyNativeID,
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testImmutabilityPolicyNativeID, got.ProgressResult.NativeID)
	})

	t.Run("List_probes_the_container", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{
				"resourceGroupName":  "rg-1",
				"storageAccountName": "acct1",
				"containerName":      "cont1",
			},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testImmutabilityPolicyNativeID}, got.NativeIDs)
	})

	t.Run("List_without_the_container_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "storageAccountName": "acct1"},
		})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})
}

func TestStorageBlobContainerImmutabilityPolicy_Failures(t *testing.T) {
	t.Run("Create_failure_reports_the_provider_error", func(t *testing.T) {
		fake := &fakeBlobContainerImmutabilityPolicyAPI{
			createOrUpdateFn: func(_ context.Context, _, _, _ string, _ *armstorage.BlobContainersClientCreateOrUpdateImmutabilityPolicyOptions) (armstorage.BlobContainersClientCreateOrUpdateImmutabilityPolicyResponse, error) {
				return armstorage.BlobContainersClientCreateOrUpdateImmutabilityPolicyResponse{},
					&azcore.ResponseError{StatusCode: 409, ErrorCode: "ImmutabilityPolicyLocked"}
			},
		}
		prov := newTestStorageBlobContainerImmutabilityPolicy(fake)

		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: immutabilityDesired(7, false)})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.Equal(t, resource.OperationErrorCodeResourceConflict, got.ProgressResult.ErrorCode)
		require.Contains(t, got.ProgressResult.StatusMessage, "ImmutabilityPolicyLocked")
	})

	t.Run("a_locked_policy_delete_surfaces_the_conflict", func(t *testing.T) {
		fake := &fakeBlobContainerImmutabilityPolicyAPI{
			getFn: func(_ context.Context, _, _, _ string, _ *armstorage.BlobContainersClientGetImmutabilityPolicyOptions) (armstorage.BlobContainersClientGetImmutabilityPolicyResponse, error) {
				return armstorage.BlobContainersClientGetImmutabilityPolicyResponse{
					ImmutabilityPolicy: armstorage.ImmutabilityPolicy{Etag: to.Ptr(testImmutabilityPolicyETag)},
				}, nil
			},
			deleteFn: func(_ context.Context, _, _, _, _ string, _ *armstorage.BlobContainersClientDeleteImmutabilityPolicyOptions) (armstorage.BlobContainersClientDeleteImmutabilityPolicyResponse, error) {
				return armstorage.BlobContainersClientDeleteImmutabilityPolicyResponse{},
					&azcore.ResponseError{StatusCode: 409, ErrorCode: "ImmutabilityPolicyDeleteNotAllowed"}
			},
		}
		prov := newTestStorageBlobContainerImmutabilityPolicy(fake)

		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testImmutabilityPolicyNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.Contains(t, got.ProgressResult.StatusMessage, "ImmutabilityPolicyDeleteNotAllowed")
	})

	t.Run("Read_maps_404", func(t *testing.T) {
		fake := &fakeBlobContainerImmutabilityPolicyAPI{
			getFn: func(_ context.Context, _, _, _ string, _ *armstorage.BlobContainersClientGetImmutabilityPolicyOptions) (armstorage.BlobContainersClientGetImmutabilityPolicyResponse, error) {
				return armstorage.BlobContainersClientGetImmutabilityPolicyResponse{}, &azcore.ResponseError{StatusCode: 404}
			},
		}
		prov := newTestStorageBlobContainerImmutabilityPolicy(fake)

		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testImmutabilityPolicyNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
	})

	t.Run("Delete_of_an_absent_policy_is_success", func(t *testing.T) {
		fake := &fakeBlobContainerImmutabilityPolicyAPI{
			getFn: func(_ context.Context, _, _, _ string, _ *armstorage.BlobContainersClientGetImmutabilityPolicyOptions) (armstorage.BlobContainersClientGetImmutabilityPolicyResponse, error) {
				return armstorage.BlobContainersClientGetImmutabilityPolicyResponse{}, &azcore.ResponseError{StatusCode: 404}
			},
		}
		prov := newTestStorageBlobContainerImmutabilityPolicy(fake)

		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testImmutabilityPolicyNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	// ARM answers 200 with an empty body for a container that never had a policy.
	t.Run("List_treats_an_empty_body_as_no_policy", func(t *testing.T) {
		fake := &fakeBlobContainerImmutabilityPolicyAPI{
			getFn: func(_ context.Context, _, _, _ string, _ *armstorage.BlobContainersClientGetImmutabilityPolicyOptions) (armstorage.BlobContainersClientGetImmutabilityPolicyResponse, error) {
				return armstorage.BlobContainersClientGetImmutabilityPolicyResponse{
					ImmutabilityPolicy: armstorage.ImmutabilityPolicy{ID: to.Ptr(testImmutabilityPolicyNativeID)},
				}, nil
			},
		}
		prov := newTestStorageBlobContainerImmutabilityPolicy(fake)

		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{
				"resourceGroupName":  "rg-1",
				"storageAccountName": "acct1",
				"containerName":      "cont1",
			},
		})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})
}

func TestStorageBlobContainerImmutabilityPolicyIDParts(t *testing.T) {
	rg, acct, cont, err := storageBlobContainerImmutabilityPolicyIDParts(testImmutabilityPolicyNativeID)
	require.NoError(t, err)
	require.Equal(t, "rg-1", rg)
	require.Equal(t, "acct1", acct)
	require.Equal(t, "cont1", cont)

	_, _, _, err = storageBlobContainerImmutabilityPolicyIDParts("/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Storage/storageAccounts/acct1")
	require.Error(t, err)
}

// --- Test helpers ---

func newTestStorageBlobContainerImmutabilityPolicy(api blobContainerImmutabilityPolicyAPI) *StorageBlobContainerImmutabilityPolicy {
	return &StorageBlobContainerImmutabilityPolicy{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

type fakeBlobContainerImmutabilityPolicyAPI struct {
	createOrUpdateFn func(ctx context.Context, rgName, accountName, containerName string, opts *armstorage.BlobContainersClientCreateOrUpdateImmutabilityPolicyOptions) (armstorage.BlobContainersClientCreateOrUpdateImmutabilityPolicyResponse, error)
	getFn            func(ctx context.Context, rgName, accountName, containerName string, opts *armstorage.BlobContainersClientGetImmutabilityPolicyOptions) (armstorage.BlobContainersClientGetImmutabilityPolicyResponse, error)
	deleteFn         func(ctx context.Context, rgName, accountName, containerName, ifMatch string, opts *armstorage.BlobContainersClientDeleteImmutabilityPolicyOptions) (armstorage.BlobContainersClientDeleteImmutabilityPolicyResponse, error)
}

func (f *fakeBlobContainerImmutabilityPolicyAPI) CreateOrUpdateImmutabilityPolicy(ctx context.Context, rgName, accountName, containerName string, opts *armstorage.BlobContainersClientCreateOrUpdateImmutabilityPolicyOptions) (armstorage.BlobContainersClientCreateOrUpdateImmutabilityPolicyResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, accountName, containerName, opts)
}

func (f *fakeBlobContainerImmutabilityPolicyAPI) GetImmutabilityPolicy(ctx context.Context, rgName, accountName, containerName string, opts *armstorage.BlobContainersClientGetImmutabilityPolicyOptions) (armstorage.BlobContainersClientGetImmutabilityPolicyResponse, error) {
	return f.getFn(ctx, rgName, accountName, containerName, opts)
}

func (f *fakeBlobContainerImmutabilityPolicyAPI) DeleteImmutabilityPolicy(ctx context.Context, rgName, accountName, containerName, ifMatch string, opts *armstorage.BlobContainersClientDeleteImmutabilityPolicyOptions) (armstorage.BlobContainersClientDeleteImmutabilityPolicyResponse, error) {
	return f.deleteFn(ctx, rgName, accountName, containerName, ifMatch, opts)
}
