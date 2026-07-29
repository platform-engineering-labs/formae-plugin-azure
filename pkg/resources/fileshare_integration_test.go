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
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testFileShareNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Storage/storageAccounts/acct1/fileServices/default/shares/share-1"

func TestFileShare_CRUD(t *testing.T) {
	model := armstorage.FileShare{
		ID:   to.Ptr(testFileShareNativeID),
		Name: to.Ptr("share-1"),
		FileShareProperties: &armstorage.FileShareProperties{
			ShareQuota:       to.Ptr(int32(100)),
			AccessTier:       to.Ptr(armstorage.ShareAccessTierTransactionOptimized),
			EnabledProtocols: to.Ptr(armstorage.EnabledProtocolsSMB),
			Metadata:         map[string]*string{"purpose": to.Ptr("conformance")},
		},
	}
	fake := &fakeFileSharesAPI{
		createFn: func(_ context.Context, _, _, _ string, _ armstorage.FileShare, _ *armstorage.FileSharesClientCreateOptions) (armstorage.FileSharesClientCreateResponse, error) {
			return armstorage.FileSharesClientCreateResponse{FileShare: model}, nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ *armstorage.FileSharesClientGetOptions) (armstorage.FileSharesClientGetResponse, error) {
			return armstorage.FileSharesClientGetResponse{FileShare: model}, nil
		},
		updateFn: func(_ context.Context, _, _, _ string, _ armstorage.FileShare, _ *armstorage.FileSharesClientUpdateOptions) (armstorage.FileSharesClientUpdateResponse, error) {
			return armstorage.FileSharesClientUpdateResponse{FileShare: model}, nil
		},
		deleteFn: func(_ context.Context, _, _, _ string, _ *armstorage.FileSharesClientDeleteOptions) (armstorage.FileSharesClientDeleteResponse, error) {
			return armstorage.FileSharesClientDeleteResponse{}, nil
		},
		newListPagerFn: func(_, _ string, _ *armstorage.FileSharesClientListOptions) *runtime.Pager[armstorage.FileSharesClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armstorage.FileSharesClientListResponse]{
				More: func(_ armstorage.FileSharesClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armstorage.FileSharesClientListResponse) (armstorage.FileSharesClientListResponse, error) {
					return armstorage.FileSharesClientListResponse{
						FileShareItems: armstorage.FileShareItems{
							Value: []*armstorage.FileShareItem{{ID: to.Ptr(testFileShareNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestFileShare(fake)

	mkProps := func() json.RawMessage {
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName":  "rg-1",
			"storageAccountName": "acct1",
			"name":               "share-1",
			"shareQuota":         100,
			"accessTier":         "TransactionOptimized",
			"enabledProtocols":   "SMB",
			"metadata":           []map[string]string{{"Key": "purpose", "Value": "conformance"}},
		})
		return props
	}

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testFileShareNativeID, got.ProgressResult.NativeID)

		var serialized map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &serialized))
		require.Equal(t, "share-1", serialized["name"])
		require.Equal(t, "acct1", serialized["storageAccountName"])
		require.Equal(t, "rg-1", serialized["resourceGroupName"])
		require.Equal(t, float64(100), serialized["shareQuota"])
		require.Equal(t, "TransactionOptimized", serialized["accessTier"])
		require.Equal(t, "SMB", serialized["enabledProtocols"])
		require.Equal(t, []any{map[string]any{"Key": "purpose", "Value": "conformance"}}, serialized["metadata"])
	})

	t.Run("Create_forwards_params_to_ARM", func(t *testing.T) {
		var seen armstorage.FileShare
		var seenRG, seenAcct, seenShare string
		fake.createFn = func(_ context.Context, rg, acct, share string, params armstorage.FileShare, _ *armstorage.FileSharesClientCreateOptions) (armstorage.FileSharesClientCreateResponse, error) {
			seen, seenRG, seenAcct, seenShare = params, rg, acct, share
			return armstorage.FileSharesClientCreateResponse{FileShare: model}, nil
		}
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, "rg-1", seenRG)
		require.Equal(t, "acct1", seenAcct)
		require.Equal(t, "share-1", seenShare)
		require.Equal(t, int32(100), *seen.FileShareProperties.ShareQuota)
		require.Equal(t, armstorage.ShareAccessTierTransactionOptimized, *seen.FileShareProperties.AccessTier)
		require.Equal(t, armstorage.EnabledProtocolsSMB, *seen.FileShareProperties.EnabledProtocols)
		require.Equal(t, "conformance", *seen.FileShareProperties.Metadata["purpose"])

		fake.createFn = func(_ context.Context, _, _, _ string, _ armstorage.FileShare, _ *armstorage.FileSharesClientCreateOptions) (armstorage.FileSharesClientCreateResponse, error) {
			return armstorage.FileSharesClientCreateResponse{FileShare: model}, nil
		}
	})

	t.Run("Create_requires_storageAccountName", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"resourceGroupName": "rg-1", "name": "share-1"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "storageAccountName is required")
	})

	t.Run("Create_requires_resourceGroupName", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"storageAccountName": "acct1", "name": "share-1"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "resourceGroupName is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testFileShareNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
		require.Equal(t, ResourceTypeFileShare, got.ResourceType)
	})

	t.Run("Read_not_found", func(t *testing.T) {
		fake.getFn = func(_ context.Context, _, _, _ string, _ *armstorage.FileSharesClientGetOptions) (armstorage.FileSharesClientGetResponse, error) {
			return armstorage.FileSharesClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testFileShareNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)

		fake.getFn = func(_ context.Context, _, _, _ string, _ *armstorage.FileSharesClientGetOptions) (armstorage.FileSharesClientGetResponse, error) {
			return armstorage.FileSharesClientGetResponse{FileShare: model}, nil
		}
	})

	// enabledProtocols is create-only in ARM; sending it in a PATCH is rejected, so
	// Update must strip it even when the desired state still declares it.
	t.Run("Update_strips_enabledProtocols", func(t *testing.T) {
		var seen armstorage.FileShare
		var seenRG, seenAcct, seenShare string
		fake.updateFn = func(_ context.Context, rg, acct, share string, params armstorage.FileShare, _ *armstorage.FileSharesClientUpdateOptions) (armstorage.FileSharesClientUpdateResponse, error) {
			seen, seenRG, seenAcct, seenShare = params, rg, acct, share
			return armstorage.FileSharesClientUpdateResponse{FileShare: model}, nil
		}
		desired, _ := json.Marshal(map[string]any{
			"shareQuota":       200,
			"accessTier":       "Hot",
			"enabledProtocols": "SMB",
			"metadata":         []map[string]string{{"Key": "purpose", "Value": "updated"}},
		})
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testFileShareNativeID,
			DesiredProperties: desired,
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, "rg-1", seenRG)
		require.Equal(t, "acct1", seenAcct)
		require.Equal(t, "share-1", seenShare)
		require.Nil(t, seen.FileShareProperties.EnabledProtocols)
		require.Equal(t, int32(200), *seen.FileShareProperties.ShareQuota)
		require.Equal(t, armstorage.ShareAccessTierHot, *seen.FileShareProperties.AccessTier)
		require.Equal(t, "updated", *seen.FileShareProperties.Metadata["purpose"])
	})

	// The share must be deleted together with its snapshots, otherwise Azure refuses.
	t.Run("Delete_includes_snapshots", func(t *testing.T) {
		var seen *armstorage.FileSharesClientDeleteOptions
		fake.deleteFn = func(_ context.Context, _, _, _ string, opts *armstorage.FileSharesClientDeleteOptions) (armstorage.FileSharesClientDeleteResponse, error) {
			seen = opts
			return armstorage.FileSharesClientDeleteResponse{}, nil
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testFileShareNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.NotNil(t, seen)
		require.Equal(t, "snapshots", *seen.Include)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _, _ string, _ *armstorage.FileSharesClientDeleteOptions) (armstorage.FileSharesClientDeleteResponse, error) {
			return armstorage.FileSharesClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testFileShareNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Status_is_sync_success", func(t *testing.T) {
		got, err := prov.Status(context.Background(), &resource.StatusRequest{RequestID: "anything"})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_account", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "storageAccountName": "acct1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testFileShareNativeID}, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.createFn = func(_ context.Context, _, _, _ string, _ armstorage.FileShare, _ *armstorage.FileSharesClientCreateOptions) (armstorage.FileSharesClientCreateResponse, error) {
			return armstorage.FileSharesClientCreateResponse{}, &azcore.ResponseError{StatusCode: 403}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

func TestFileShareIDParts(t *testing.T) {
	rg, acct, share, err := fileShareIDParts(testFileShareNativeID)
	require.NoError(t, err)
	require.Equal(t, "rg-1", rg)
	require.Equal(t, "acct1", acct)
	require.Equal(t, "share-1", share)

	_, _, _, err = fileShareIDParts("/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Storage/storageAccounts/acct1")
	require.Error(t, err)
}

// --- Test helpers ---

func newTestFileShare(api fileSharesAPI) *FileShare {
	return &FileShare{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

type fakeFileSharesAPI struct {
	createFn       func(ctx context.Context, rgName, accountName, shareName string, share armstorage.FileShare, opts *armstorage.FileSharesClientCreateOptions) (armstorage.FileSharesClientCreateResponse, error)
	getFn          func(ctx context.Context, rgName, accountName, shareName string, opts *armstorage.FileSharesClientGetOptions) (armstorage.FileSharesClientGetResponse, error)
	updateFn       func(ctx context.Context, rgName, accountName, shareName string, share armstorage.FileShare, opts *armstorage.FileSharesClientUpdateOptions) (armstorage.FileSharesClientUpdateResponse, error)
	deleteFn       func(ctx context.Context, rgName, accountName, shareName string, opts *armstorage.FileSharesClientDeleteOptions) (armstorage.FileSharesClientDeleteResponse, error)
	newListPagerFn func(rgName, accountName string, opts *armstorage.FileSharesClientListOptions) *runtime.Pager[armstorage.FileSharesClientListResponse]
}

func (f *fakeFileSharesAPI) Create(ctx context.Context, rgName, accountName, shareName string, share armstorage.FileShare, opts *armstorage.FileSharesClientCreateOptions) (armstorage.FileSharesClientCreateResponse, error) {
	return f.createFn(ctx, rgName, accountName, shareName, share, opts)
}

func (f *fakeFileSharesAPI) Get(ctx context.Context, rgName, accountName, shareName string, opts *armstorage.FileSharesClientGetOptions) (armstorage.FileSharesClientGetResponse, error) {
	return f.getFn(ctx, rgName, accountName, shareName, opts)
}

func (f *fakeFileSharesAPI) Update(ctx context.Context, rgName, accountName, shareName string, share armstorage.FileShare, opts *armstorage.FileSharesClientUpdateOptions) (armstorage.FileSharesClientUpdateResponse, error) {
	return f.updateFn(ctx, rgName, accountName, shareName, share, opts)
}

func (f *fakeFileSharesAPI) Delete(ctx context.Context, rgName, accountName, shareName string, opts *armstorage.FileSharesClientDeleteOptions) (armstorage.FileSharesClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, accountName, shareName, opts)
}

func (f *fakeFileSharesAPI) NewListPager(rgName, accountName string, opts *armstorage.FileSharesClientListOptions) *runtime.Pager[armstorage.FileSharesClientListResponse] {
	return f.newListPagerFn(rgName, accountName, opts)
}
