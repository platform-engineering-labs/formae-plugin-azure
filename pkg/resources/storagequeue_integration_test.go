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

const testStorageQueueNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Storage/storageAccounts/acct1/queueServices/default/queues/queue-1"

func TestStorageQueue_CRUD(t *testing.T) {
	model := armstorage.Queue{
		ID:   to.Ptr(testStorageQueueNativeID),
		Name: to.Ptr("queue-1"),
		QueueProperties: &armstorage.QueueProperties{
			Metadata: map[string]*string{"purpose": to.Ptr("conformance")},
		},
	}
	fake := &fakeStorageQueuesAPI{
		createFn: func(_ context.Context, _, _, _ string, _ armstorage.Queue, _ *armstorage.QueueClientCreateOptions) (armstorage.QueueClientCreateResponse, error) {
			return armstorage.QueueClientCreateResponse{Queue: model}, nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ *armstorage.QueueClientGetOptions) (armstorage.QueueClientGetResponse, error) {
			return armstorage.QueueClientGetResponse{Queue: model}, nil
		},
		updateFn: func(_ context.Context, _, _, _ string, _ armstorage.Queue, _ *armstorage.QueueClientUpdateOptions) (armstorage.QueueClientUpdateResponse, error) {
			return armstorage.QueueClientUpdateResponse{Queue: model}, nil
		},
		deleteFn: func(_ context.Context, _, _, _ string, _ *armstorage.QueueClientDeleteOptions) (armstorage.QueueClientDeleteResponse, error) {
			return armstorage.QueueClientDeleteResponse{}, nil
		},
		newListPagerFn: func(_, _ string, _ *armstorage.QueueClientListOptions) *runtime.Pager[armstorage.QueueClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armstorage.QueueClientListResponse]{
				More: func(_ armstorage.QueueClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armstorage.QueueClientListResponse) (armstorage.QueueClientListResponse, error) {
					return armstorage.QueueClientListResponse{
						ListQueueResource: armstorage.ListQueueResource{
							Value: []*armstorage.ListQueue{{ID: to.Ptr(testStorageQueueNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestStorageQueue(fake)

	mkProps := func() json.RawMessage {
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName":  "rg-1",
			"storageAccountName": "acct1",
			"name":               "queue-1",
			"metadata":           []map[string]string{{"Key": "purpose", "Value": "conformance"}},
		})
		return props
	}

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testStorageQueueNativeID, got.ProgressResult.NativeID)

		var serialized map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &serialized))
		require.Equal(t, "queue-1", serialized["name"])
		require.Equal(t, "acct1", serialized["storageAccountName"])
		require.Equal(t, "rg-1", serialized["resourceGroupName"])
		require.Equal(t, []any{map[string]any{"Key": "purpose", "Value": "conformance"}}, serialized["metadata"])
	})

	t.Run("Create_forwards_metadata_to_ARM", func(t *testing.T) {
		var seen armstorage.Queue
		var seenRG, seenAcct, seenQueue string
		fake.createFn = func(_ context.Context, rg, acct, queue string, params armstorage.Queue, _ *armstorage.QueueClientCreateOptions) (armstorage.QueueClientCreateResponse, error) {
			seen, seenRG, seenAcct, seenQueue = params, rg, acct, queue
			return armstorage.QueueClientCreateResponse{Queue: model}, nil
		}
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, "rg-1", seenRG)
		require.Equal(t, "acct1", seenAcct)
		require.Equal(t, "queue-1", seenQueue)
		require.Equal(t, "conformance", *seen.QueueProperties.Metadata["purpose"])

		fake.createFn = func(_ context.Context, _, _, _ string, _ armstorage.Queue, _ *armstorage.QueueClientCreateOptions) (armstorage.QueueClientCreateResponse, error) {
			return armstorage.QueueClientCreateResponse{Queue: model}, nil
		}
	})

	t.Run("Create_requires_storageAccountName", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"resourceGroupName": "rg-1", "name": "queue-1"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "storageAccountName is required")
	})

	t.Run("Create_requires_resourceGroupName", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"storageAccountName": "acct1", "name": "queue-1"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "resourceGroupName is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testStorageQueueNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
		require.Equal(t, ResourceTypeStorageQueue, got.ResourceType)
	})

	t.Run("Read_not_found", func(t *testing.T) {
		fake.getFn = func(_ context.Context, _, _, _ string, _ *armstorage.QueueClientGetOptions) (armstorage.QueueClientGetResponse, error) {
			return armstorage.QueueClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testStorageQueueNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)

		fake.getFn = func(_ context.Context, _, _, _ string, _ *armstorage.QueueClientGetOptions) (armstorage.QueueClientGetResponse, error) {
			return armstorage.QueueClientGetResponse{Queue: model}, nil
		}
	})

	t.Run("Update_derives_names_from_native_id", func(t *testing.T) {
		var seen armstorage.Queue
		var seenRG, seenAcct, seenQueue string
		fake.updateFn = func(_ context.Context, rg, acct, queue string, params armstorage.Queue, _ *armstorage.QueueClientUpdateOptions) (armstorage.QueueClientUpdateResponse, error) {
			seen, seenRG, seenAcct, seenQueue = params, rg, acct, queue
			return armstorage.QueueClientUpdateResponse{Queue: model}, nil
		}
		desired, _ := json.Marshal(map[string]any{
			"metadata": []map[string]string{{"Key": "purpose", "Value": "updated"}},
		})
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testStorageQueueNativeID,
			DesiredProperties: desired,
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, "rg-1", seenRG)
		require.Equal(t, "acct1", seenAcct)
		require.Equal(t, "queue-1", seenQueue)
		require.Equal(t, "updated", *seen.QueueProperties.Metadata["purpose"])
	})

	t.Run("Delete", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testStorageQueueNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _, _ string, _ *armstorage.QueueClientDeleteOptions) (armstorage.QueueClientDeleteResponse, error) {
			return armstorage.QueueClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testStorageQueueNativeID})
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
		require.Equal(t, []string{testStorageQueueNativeID}, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.createFn = func(_ context.Context, _, _, _ string, _ armstorage.Queue, _ *armstorage.QueueClientCreateOptions) (armstorage.QueueClientCreateResponse, error) {
			return armstorage.QueueClientCreateResponse{}, &azcore.ResponseError{StatusCode: 403}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

func TestStorageQueueIDParts(t *testing.T) {
	rg, acct, queue, err := storageQueueIDParts(testStorageQueueNativeID)
	require.NoError(t, err)
	require.Equal(t, "rg-1", rg)
	require.Equal(t, "acct1", acct)
	require.Equal(t, "queue-1", queue)

	_, _, _, err = storageQueueIDParts("/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Storage/storageAccounts/acct1")
	require.Error(t, err)
}

func TestMetadataFromProperties(t *testing.T) {
	t.Run("maps entity set to ARM map", func(t *testing.T) {
		out := metadataFromProperties(map[string]any{
			"metadata": []any{
				map[string]any{"Key": "a", "Value": "1"},
				map[string]any{"Key": "b", "Value": "2"},
			},
		})
		require.Len(t, out, 2)
		require.Equal(t, "1", *out["a"])
		require.Equal(t, "2", *out["b"])
	})

	t.Run("nil when absent or empty", func(t *testing.T) {
		require.Nil(t, metadataFromProperties(map[string]any{}))
		require.Nil(t, metadataFromProperties(map[string]any{"metadata": []any{}}))
	})

	t.Run("skips entries without a key", func(t *testing.T) {
		require.Nil(t, metadataFromProperties(map[string]any{
			"metadata": []any{map[string]any{"Value": "orphan"}},
		}))
	})
}

// --- Test helpers ---

func newTestStorageQueue(api storageQueuesAPI) *StorageQueue {
	return &StorageQueue{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

type fakeStorageQueuesAPI struct {
	createFn       func(ctx context.Context, rgName, accountName, queueName string, queue armstorage.Queue, opts *armstorage.QueueClientCreateOptions) (armstorage.QueueClientCreateResponse, error)
	getFn          func(ctx context.Context, rgName, accountName, queueName string, opts *armstorage.QueueClientGetOptions) (armstorage.QueueClientGetResponse, error)
	updateFn       func(ctx context.Context, rgName, accountName, queueName string, queue armstorage.Queue, opts *armstorage.QueueClientUpdateOptions) (armstorage.QueueClientUpdateResponse, error)
	deleteFn       func(ctx context.Context, rgName, accountName, queueName string, opts *armstorage.QueueClientDeleteOptions) (armstorage.QueueClientDeleteResponse, error)
	newListPagerFn func(rgName, accountName string, opts *armstorage.QueueClientListOptions) *runtime.Pager[armstorage.QueueClientListResponse]
}

func (f *fakeStorageQueuesAPI) Create(ctx context.Context, rgName, accountName, queueName string, queue armstorage.Queue, opts *armstorage.QueueClientCreateOptions) (armstorage.QueueClientCreateResponse, error) {
	return f.createFn(ctx, rgName, accountName, queueName, queue, opts)
}

func (f *fakeStorageQueuesAPI) Get(ctx context.Context, rgName, accountName, queueName string, opts *armstorage.QueueClientGetOptions) (armstorage.QueueClientGetResponse, error) {
	return f.getFn(ctx, rgName, accountName, queueName, opts)
}

func (f *fakeStorageQueuesAPI) Update(ctx context.Context, rgName, accountName, queueName string, queue armstorage.Queue, opts *armstorage.QueueClientUpdateOptions) (armstorage.QueueClientUpdateResponse, error) {
	return f.updateFn(ctx, rgName, accountName, queueName, queue, opts)
}

func (f *fakeStorageQueuesAPI) Delete(ctx context.Context, rgName, accountName, queueName string, opts *armstorage.QueueClientDeleteOptions) (armstorage.QueueClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, accountName, queueName, opts)
}

func (f *fakeStorageQueuesAPI) NewListPager(rgName, accountName string, opts *armstorage.QueueClientListOptions) *runtime.Pager[armstorage.QueueClientListResponse] {
	return f.newListPagerFn(rgName, accountName, opts)
}
