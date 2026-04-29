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

const testBlobContainerNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Storage/storageAccounts/stg1/blobServices/default/containers/c-1"

func TestBlobContainer_CRUD(t *testing.T) {
	upstream := armstorage.BlobContainer{
		ID:   to.Ptr(testBlobContainerNativeID),
		Name: to.Ptr("c-1"),
		ContainerProperties: &armstorage.ContainerProperties{
			PublicAccess: to.Ptr(armstorage.PublicAccessNone),
		},
	}
	fake := &fakeBlobContainersAPI{
		createFn: func(_ context.Context, _, _, _ string, _ armstorage.BlobContainer, _ *armstorage.BlobContainersClientCreateOptions) (armstorage.BlobContainersClientCreateResponse, error) {
			return armstorage.BlobContainersClientCreateResponse{BlobContainer: upstream}, nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ *armstorage.BlobContainersClientGetOptions) (armstorage.BlobContainersClientGetResponse, error) {
			return armstorage.BlobContainersClientGetResponse{BlobContainer: upstream}, nil
		},
		updateFn: func(_ context.Context, _, _, _ string, _ armstorage.BlobContainer, _ *armstorage.BlobContainersClientUpdateOptions) (armstorage.BlobContainersClientUpdateResponse, error) {
			return armstorage.BlobContainersClientUpdateResponse{BlobContainer: upstream}, nil
		},
		deleteFn: func(_ context.Context, _, _, _ string, _ *armstorage.BlobContainersClientDeleteOptions) (armstorage.BlobContainersClientDeleteResponse, error) {
			return armstorage.BlobContainersClientDeleteResponse{}, nil
		},
		newListPagerFn: func(_, _ string, _ *armstorage.BlobContainersClientListOptions) *runtime.Pager[armstorage.BlobContainersClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armstorage.BlobContainersClientListResponse]{
				More: func(_ armstorage.BlobContainersClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armstorage.BlobContainersClientListResponse) (armstorage.BlobContainersClientListResponse, error) {
					return armstorage.BlobContainersClientListResponse{
						ListContainerItems: armstorage.ListContainerItems{
							Value: []*armstorage.ListContainerItem{{ID: to.Ptr(testBlobContainerNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestBlobContainer(fake)

	mkProps := func() json.RawMessage {
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName":  "rg-1",
			"storageAccountName": "stg1",
			"name":               "c-1",
			"publicAccess":       "None",
		})
		return props
	}

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testBlobContainerNativeID, got.ProgressResult.NativeID)
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testBlobContainerNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _, _ string, _ *armstorage.BlobContainersClientDeleteOptions) (armstorage.BlobContainersClientDeleteResponse, error) {
			return armstorage.BlobContainersClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testBlobContainerNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{
				"resourceGroupName":  "rg-1",
				"storageAccountName": "stg1",
			},
		})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 1)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.createFn = func(_ context.Context, _, _, _ string, _ armstorage.BlobContainer, _ *armstorage.BlobContainersClientCreateOptions) (armstorage.BlobContainersClientCreateResponse, error) {
			return armstorage.BlobContainersClientCreateResponse{}, &azcore.ResponseError{StatusCode: 403}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

// --- Test helpers ---

func newTestBlobContainer(api blobContainersAPI) *BlobContainer {
	return &BlobContainer{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

type fakeBlobContainersAPI struct {
	createFn       func(ctx context.Context, rgName, accountName, containerName string, params armstorage.BlobContainer, opts *armstorage.BlobContainersClientCreateOptions) (armstorage.BlobContainersClientCreateResponse, error)
	getFn          func(ctx context.Context, rgName, accountName, containerName string, opts *armstorage.BlobContainersClientGetOptions) (armstorage.BlobContainersClientGetResponse, error)
	updateFn       func(ctx context.Context, rgName, accountName, containerName string, params armstorage.BlobContainer, opts *armstorage.BlobContainersClientUpdateOptions) (armstorage.BlobContainersClientUpdateResponse, error)
	deleteFn       func(ctx context.Context, rgName, accountName, containerName string, opts *armstorage.BlobContainersClientDeleteOptions) (armstorage.BlobContainersClientDeleteResponse, error)
	newListPagerFn func(rgName, accountName string, opts *armstorage.BlobContainersClientListOptions) *runtime.Pager[armstorage.BlobContainersClientListResponse]
}

func (f *fakeBlobContainersAPI) Create(ctx context.Context, rgName, accountName, containerName string, params armstorage.BlobContainer, opts *armstorage.BlobContainersClientCreateOptions) (armstorage.BlobContainersClientCreateResponse, error) {
	return f.createFn(ctx, rgName, accountName, containerName, params, opts)
}

func (f *fakeBlobContainersAPI) Get(ctx context.Context, rgName, accountName, containerName string, opts *armstorage.BlobContainersClientGetOptions) (armstorage.BlobContainersClientGetResponse, error) {
	return f.getFn(ctx, rgName, accountName, containerName, opts)
}

func (f *fakeBlobContainersAPI) Update(ctx context.Context, rgName, accountName, containerName string, params armstorage.BlobContainer, opts *armstorage.BlobContainersClientUpdateOptions) (armstorage.BlobContainersClientUpdateResponse, error) {
	return f.updateFn(ctx, rgName, accountName, containerName, params, opts)
}

func (f *fakeBlobContainersAPI) Delete(ctx context.Context, rgName, accountName, containerName string, opts *armstorage.BlobContainersClientDeleteOptions) (armstorage.BlobContainersClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, accountName, containerName, opts)
}

func (f *fakeBlobContainersAPI) NewListPager(rgName, accountName string, opts *armstorage.BlobContainersClientListOptions) *runtime.Pager[armstorage.BlobContainersClientListResponse] {
	return f.newListPagerFn(rgName, accountName, opts)
}
