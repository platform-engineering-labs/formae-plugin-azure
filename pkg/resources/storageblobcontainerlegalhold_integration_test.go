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

const testLegalHoldNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Storage/storageAccounts/acct1/blobServices/default/containers/cont1/legalHolds/default"

func legalHoldDesired(tags ...string) json.RawMessage {
	props, _ := json.Marshal(map[string]any{
		"resourceGroupName":  "rg-1",
		"storageAccountName": "acct1",
		"containerName":      "cont1",
		"legalHoldTags":      tags,
	})
	return props
}

// containerWithTags builds the container Get response the provisioner reads the
// tag set out of: the legal hold has no Get of its own.
func containerWithTags(tags ...string) armstorage.BlobContainersClientGetResponse {
	props := &armstorage.ContainerProperties{HasLegalHold: to.Ptr(len(tags) > 0)}
	if len(tags) > 0 {
		hold := &armstorage.LegalHoldProperties{HasLegalHold: to.Ptr(true)}
		for _, tag := range tags {
			hold.Tags = append(hold.Tags, &armstorage.TagProperty{Tag: to.Ptr(tag)})
		}
		props.LegalHold = hold
	}
	return armstorage.BlobContainersClientGetResponse{
		BlobContainer: armstorage.BlobContainer{
			ID:                  to.Ptr("/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Storage/storageAccounts/acct1/blobServices/default/containers/cont1"),
			Name:                to.Ptr("cont1"),
			ContainerProperties: props,
		},
	}
}

func TestStorageBlobContainerLegalHold_CRUD(t *testing.T) {
	// held is the container's tag set, the way ARM keeps it: additive through
	// setLegalHold, subtractive through clearLegalHold.
	held := map[string]bool{}
	var setCalls, clearCalls []armstorage.LegalHold

	fake := &fakeBlobContainerLegalHoldAPI{
		setFn: func(_ context.Context, _, _, _ string, hold armstorage.LegalHold, _ *armstorage.BlobContainersClientSetLegalHoldOptions) (armstorage.BlobContainersClientSetLegalHoldResponse, error) {
			setCalls = append(setCalls, hold)
			for _, tag := range hold.Tags {
				held[*tag] = true
			}
			return armstorage.BlobContainersClientSetLegalHoldResponse{LegalHold: armstorage.LegalHold{
				Tags:         hold.Tags,
				HasLegalHold: to.Ptr(len(held) > 0),
			}}, nil
		},
		clearFn: func(_ context.Context, _, _, _ string, hold armstorage.LegalHold, _ *armstorage.BlobContainersClientClearLegalHoldOptions) (armstorage.BlobContainersClientClearLegalHoldResponse, error) {
			clearCalls = append(clearCalls, hold)
			for _, tag := range hold.Tags {
				delete(held, *tag)
			}
			return armstorage.BlobContainersClientClearLegalHoldResponse{LegalHold: armstorage.LegalHold{
				HasLegalHold: to.Ptr(len(held) > 0),
			}}, nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ *armstorage.BlobContainersClientGetOptions) (armstorage.BlobContainersClientGetResponse, error) {
			tags := make([]string, 0, len(held))
			for tag := range held {
				tags = append(tags, tag)
			}
			return containerWithTags(tags...), nil
		},
	}
	prov := newTestStorageBlobContainerLegalHold(fake)

	t.Run("Create_synthesises_the_native_id", func(t *testing.T) {
		setCalls, clearCalls = nil, nil
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: legalHoldDesired("case1", "audit")})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		// ARM has no resource for a legal hold, so the identifier is built from the
		// container's ARM ID.
		require.Equal(t, testLegalHoldNativeID, got.ProgressResult.NativeID)

		require.Len(t, setCalls, 1)
		require.Empty(t, clearCalls)
		require.Equal(t, []string{"audit", "case1"}, stringsFromPointers(setCalls[0].Tags))

		var serialized map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &serialized))
		require.Equal(t, "rg-1", serialized["resourceGroupName"])
		require.Equal(t, "acct1", serialized["storageAccountName"])
		require.Equal(t, "cont1", serialized["containerName"])
		require.Equal(t, testLegalHoldNativeID, serialized["id"])
		require.Equal(t, []any{"audit", "case1"}, serialized["legalHoldTags"])
		require.Equal(t, true, serialized["hasLegalHold"])
		require.NotContains(t, serialized, "allowProtectedAppendWritesAll")
	})

	t.Run("tags_are_lower_cased_and_sorted_before_they_are_sent", func(t *testing.T) {
		setCalls = nil
		held = map[string]bool{}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: legalHoldDesired("Zeta", "ALPHA", "alpha")})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		// ARM lower-cases every tag, so comparing raw values would report drift on a
		// set that actually matches; the duplicate collapses too.
		require.Equal(t, []string{"alpha", "zeta"}, stringsFromPointers(setCalls[0].Tags))
	})

	t.Run("Create_requires_at_least_one_tag", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName":  "rg-1",
			"storageAccountName": "acct1",
			"containerName":      "cont1",
			"legalHoldTags":      []string{},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "at least one legal hold tag is required")
	})

	t.Run("Read_reads_the_tags_off_the_container", func(t *testing.T) {
		held = map[string]bool{"case1": true}
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testLegalHoldNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
		require.Equal(t, ResourceTypeStorageBlobContainerLegalHold, got.ResourceType)

		var serialized map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &serialized))
		require.Equal(t, []any{"case1"}, serialized["legalHoldTags"])
	})

	t.Run("Read_of_a_container_with_no_tags_is_not_found", func(t *testing.T) {
		held = map[string]bool{}
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testLegalHoldNativeID})
		require.NoError(t, err)
		// No tags means no hold: reporting an empty tag list would be a document the
		// schema forbids.
		require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
	})

	t.Run("Update_sets_the_wanted_tags_and_clears_the_stale_ones", func(t *testing.T) {
		held = map[string]bool{"case1": true, "audit": true}
		setCalls, clearCalls = nil, nil

		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testLegalHoldNativeID,
			DesiredProperties: legalHoldDesired("case1", "case2"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testLegalHoldNativeID, got.ProgressResult.NativeID)

		require.Len(t, setCalls, 1)
		require.Equal(t, []string{"case1", "case2"}, stringsFromPointers(setCalls[0].Tags))
		require.Len(t, clearCalls, 1)
		require.Equal(t, []string{"audit"}, stringsFromPointers(clearCalls[0].Tags))
		require.Equal(t, map[string]bool{"case1": true, "case2": true}, held)
	})

	t.Run("Update_with_nothing_to_clear_makes_no_clear_call", func(t *testing.T) {
		held = map[string]bool{"case1": true}
		setCalls, clearCalls = nil, nil
		_, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testLegalHoldNativeID,
			DesiredProperties: legalHoldDesired("case1", "case2"),
		})
		require.NoError(t, err)
		require.Len(t, setCalls, 1)
		require.Empty(t, clearCalls)
	})

	t.Run("Delete_clears_every_tag_the_container_carries", func(t *testing.T) {
		held = map[string]bool{"case1": true, "case2": true}
		setCalls, clearCalls = nil, nil
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testLegalHoldNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Len(t, clearCalls, 1)
		require.Equal(t, []string{"case1", "case2"}, stringsFromPointers(clearCalls[0].Tags))
		require.Empty(t, held)
	})

	t.Run("Delete_of_an_untagged_container_makes_no_call", func(t *testing.T) {
		held = map[string]bool{}
		clearCalls = nil
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testLegalHoldNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Empty(t, clearCalls)
	})

	t.Run("Status_rereads", func(t *testing.T) {
		held = map[string]bool{"case1": true}
		got, err := prov.Status(context.Background(), &resource.StatusRequest{
			RequestID: "req-1",
			NativeID:  testLegalHoldNativeID,
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testLegalHoldNativeID, got.ProgressResult.NativeID)
	})

	t.Run("List_reports_the_hold_only_while_tags_exist", func(t *testing.T) {
		scope := map[string]string{
			"resourceGroupName":  "rg-1",
			"storageAccountName": "acct1",
			"containerName":      "cont1",
		}

		held = map[string]bool{"case1": true}
		got, err := prov.List(context.Background(), &resource.ListRequest{AdditionalProperties: scope})
		require.NoError(t, err)
		require.Equal(t, []string{testLegalHoldNativeID}, got.NativeIDs)

		held = map[string]bool{}
		got, err = prov.List(context.Background(), &resource.ListRequest{AdditionalProperties: scope})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})

	t.Run("List_without_the_container_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "storageAccountName": "acct1"},
		})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})
}

func TestStorageBlobContainerLegalHold_AllowProtectedAppendWritesAll(t *testing.T) {
	var lastSet armstorage.LegalHold
	fake := &fakeBlobContainerLegalHoldAPI{
		setFn: func(_ context.Context, _, _, _ string, hold armstorage.LegalHold, _ *armstorage.BlobContainersClientSetLegalHoldOptions) (armstorage.BlobContainersClientSetLegalHoldResponse, error) {
			lastSet = hold
			return armstorage.BlobContainersClientSetLegalHoldResponse{LegalHold: armstorage.LegalHold{Tags: hold.Tags}}, nil
		},
	}
	prov := newTestStorageBlobContainerLegalHold(fake)

	props, _ := json.Marshal(map[string]any{
		"resourceGroupName":             "rg-1",
		"storageAccountName":            "acct1",
		"containerName":                 "cont1",
		"legalHoldTags":                 []string{"case1"},
		"allowProtectedAppendWritesAll": true,
	})
	got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
	require.NoError(t, err)
	require.True(t, *lastSet.AllowProtectedAppendWritesAll)

	var serialized map[string]any
	require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &serialized))
	require.Equal(t, true, serialized["allowProtectedAppendWritesAll"])
}

func TestStorageBlobContainerLegalHold_Failures(t *testing.T) {
	t.Run("Create_failure_reports_the_provider_error", func(t *testing.T) {
		fake := &fakeBlobContainerLegalHoldAPI{
			setFn: func(_ context.Context, _, _, _ string, _ armstorage.LegalHold, _ *armstorage.BlobContainersClientSetLegalHoldOptions) (armstorage.BlobContainersClientSetLegalHoldResponse, error) {
				return armstorage.BlobContainersClientSetLegalHoldResponse{},
					&azcore.ResponseError{StatusCode: 400, ErrorCode: "InvalidLegalHoldTag"}
			},
		}
		prov := newTestStorageBlobContainerLegalHold(fake)

		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: legalHoldDesired("case1")})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.Equal(t, resource.OperationErrorCodeInvalidRequest, got.ProgressResult.ErrorCode)
		require.Contains(t, got.ProgressResult.StatusMessage, "InvalidLegalHoldTag")
	})

	t.Run("a_missing_container_reads_as_not_found_and_deletes_as_success", func(t *testing.T) {
		fake := &fakeBlobContainerLegalHoldAPI{
			getFn: func(_ context.Context, _, _, _ string, _ *armstorage.BlobContainersClientGetOptions) (armstorage.BlobContainersClientGetResponse, error) {
				return armstorage.BlobContainersClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
			},
		}
		prov := newTestStorageBlobContainerLegalHold(fake)

		read, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testLegalHoldNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationErrorCodeNotFound, read.ErrorCode)

		del, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testLegalHoldNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, del.ProgressResult.OperationStatus)
	})
}

func TestLegalHoldNativeIDRoundTrip(t *testing.T) {
	id := legalHoldNativeID("sub-1", "rg-1", "acct1", "cont1")
	require.Equal(t, testLegalHoldNativeID, id)

	// The synthesised ID must parse as an ARM ID, or Read, Update and Delete can
	// never recover their scope from it.
	rg, acct, cont, err := storageBlobContainerLegalHoldIDParts(id)
	require.NoError(t, err)
	require.Equal(t, "rg-1", rg)
	require.Equal(t, "acct1", acct)
	require.Equal(t, "cont1", cont)
}

func TestNormalizeLegalHoldTags(t *testing.T) {
	require.Equal(t, []string{"a", "b"}, normalizeLegalHoldTags([]string{"B", " a ", "a", ""}))
	require.Empty(t, normalizeLegalHoldTags(nil))
}

func TestLegalHoldTagsToClear(t *testing.T) {
	require.Equal(t, []string{"gone"}, legalHoldTagsToClear([]string{"kept", "gone"}, []string{"kept", "new"}))
	require.Empty(t, legalHoldTagsToClear([]string{"kept"}, []string{"kept", "new"}))
}

// --- Test helpers ---

func newTestStorageBlobContainerLegalHold(api blobContainerLegalHoldAPI) *StorageBlobContainerLegalHold {
	return &StorageBlobContainerLegalHold{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

type fakeBlobContainerLegalHoldAPI struct {
	setFn   func(ctx context.Context, rgName, accountName, containerName string, hold armstorage.LegalHold, opts *armstorage.BlobContainersClientSetLegalHoldOptions) (armstorage.BlobContainersClientSetLegalHoldResponse, error)
	clearFn func(ctx context.Context, rgName, accountName, containerName string, hold armstorage.LegalHold, opts *armstorage.BlobContainersClientClearLegalHoldOptions) (armstorage.BlobContainersClientClearLegalHoldResponse, error)
	getFn   func(ctx context.Context, rgName, accountName, containerName string, opts *armstorage.BlobContainersClientGetOptions) (armstorage.BlobContainersClientGetResponse, error)
}

func (f *fakeBlobContainerLegalHoldAPI) SetLegalHold(ctx context.Context, rgName, accountName, containerName string, hold armstorage.LegalHold, opts *armstorage.BlobContainersClientSetLegalHoldOptions) (armstorage.BlobContainersClientSetLegalHoldResponse, error) {
	return f.setFn(ctx, rgName, accountName, containerName, hold, opts)
}

func (f *fakeBlobContainerLegalHoldAPI) ClearLegalHold(ctx context.Context, rgName, accountName, containerName string, hold armstorage.LegalHold, opts *armstorage.BlobContainersClientClearLegalHoldOptions) (armstorage.BlobContainersClientClearLegalHoldResponse, error) {
	return f.clearFn(ctx, rgName, accountName, containerName, hold, opts)
}

func (f *fakeBlobContainerLegalHoldAPI) Get(ctx context.Context, rgName, accountName, containerName string, opts *armstorage.BlobContainersClientGetOptions) (armstorage.BlobContainersClientGetResponse, error) {
	return f.getFn(ctx, rgName, accountName, containerName, opts)
}
