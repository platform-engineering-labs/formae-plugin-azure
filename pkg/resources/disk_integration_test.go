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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v5"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testDiskNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Compute/disks/disk-1"

func TestDisk_CRUD(t *testing.T) {
	donePoller := armcompute.DisksClientCreateOrUpdateResponse{
		Disk: armcompute.Disk{
			ID:       to.Ptr(testDiskNativeID),
			Name:     to.Ptr("disk-1"),
			Location: to.Ptr("eastus"),
			SKU: &armcompute.DiskSKU{
				Name: to.Ptr(armcompute.DiskStorageAccountTypesStandardLRS),
			},
			Properties: &armcompute.DiskProperties{
				CreationData: &armcompute.CreationData{
					CreateOption: to.Ptr(armcompute.DiskCreateOptionEmpty),
				},
				DiskSizeGB: to.Ptr(int32(32)),
			},
		},
	}
	fake := &fakeDisksAPI{
		beginCreateOrUpdateFn: func(_ context.Context, _, _ string, _ armcompute.Disk, _ *armcompute.DisksClientBeginCreateOrUpdateOptions) (*runtime.Poller[armcompute.DisksClientCreateOrUpdateResponse], error) {
			return newDonePoller(donePoller), nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armcompute.DisksClientGetOptions) (armcompute.DisksClientGetResponse, error) {
			return armcompute.DisksClientGetResponse{Disk: donePoller.Disk}, nil
		},
		beginUpdateFn: func(_ context.Context, _, _ string, _ armcompute.DiskUpdate, _ *armcompute.DisksClientBeginUpdateOptions) (*runtime.Poller[armcompute.DisksClientUpdateResponse], error) {
			return newDonePoller(armcompute.DisksClientUpdateResponse{Disk: donePoller.Disk}), nil
		},
		beginDeleteFn: func(_ context.Context, _, _ string, _ *armcompute.DisksClientBeginDeleteOptions) (*runtime.Poller[armcompute.DisksClientDeleteResponse], error) {
			return newInProgressPoller[armcompute.DisksClientDeleteResponse](), nil
		},
		newListByResourceGroupPagerFn: func(_ string, _ *armcompute.DisksClientListByResourceGroupOptions) *runtime.Pager[armcompute.DisksClientListByResourceGroupResponse] {
			return runtime.NewPager(runtime.PagingHandler[armcompute.DisksClientListByResourceGroupResponse]{
				More: func(_ armcompute.DisksClientListByResourceGroupResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armcompute.DisksClientListByResourceGroupResponse) (armcompute.DisksClientListByResourceGroupResponse, error) {
					return armcompute.DisksClientListByResourceGroupResponse{
						DiskList: armcompute.DiskList{
							Value: []*armcompute.Disk{{ID: to.Ptr(testDiskNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestDisk(fake)

	mkProps := func() json.RawMessage {
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName": "rg-1",
			"name":              "disk-1",
			"location":          "eastus",
			"creationData": map[string]any{
				"createOption": "Empty",
			},
			"diskSizeGB": 32,
			"sku": map[string]any{
				"name": "Standard_LRS",
			},
		})
		return props
	}

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testDiskNativeID, got.ProgressResult.NativeID)

		var serialized map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &serialized))
		require.Equal(t, "disk-1", serialized["name"])
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testDiskNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _ string, _ *armcompute.DisksClientBeginDeleteOptions) (*runtime.Poller[armcompute.DisksClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testDiskNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 1)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, _ armcompute.Disk, _ *armcompute.DisksClientBeginCreateOrUpdateOptions) (*runtime.Poller[armcompute.DisksClientCreateOrUpdateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 403}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

// --- Test helpers ---

func newTestDisk(api disksAPI) *Disk {
	return &Disk{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

type fakeDisksAPI struct {
	beginCreateOrUpdateFn         func(ctx context.Context, rgName, diskName string, params armcompute.Disk, opts *armcompute.DisksClientBeginCreateOrUpdateOptions) (*runtime.Poller[armcompute.DisksClientCreateOrUpdateResponse], error)
	getFn                         func(ctx context.Context, rgName, diskName string, opts *armcompute.DisksClientGetOptions) (armcompute.DisksClientGetResponse, error)
	beginUpdateFn                 func(ctx context.Context, rgName, diskName string, params armcompute.DiskUpdate, opts *armcompute.DisksClientBeginUpdateOptions) (*runtime.Poller[armcompute.DisksClientUpdateResponse], error)
	beginDeleteFn                 func(ctx context.Context, rgName, diskName string, opts *armcompute.DisksClientBeginDeleteOptions) (*runtime.Poller[armcompute.DisksClientDeleteResponse], error)
	newListByResourceGroupPagerFn func(rgName string, opts *armcompute.DisksClientListByResourceGroupOptions) *runtime.Pager[armcompute.DisksClientListByResourceGroupResponse]
	newListPagerFn                func(opts *armcompute.DisksClientListOptions) *runtime.Pager[armcompute.DisksClientListResponse]
}

func (f *fakeDisksAPI) BeginCreateOrUpdate(ctx context.Context, rgName, diskName string, params armcompute.Disk, opts *armcompute.DisksClientBeginCreateOrUpdateOptions) (*runtime.Poller[armcompute.DisksClientCreateOrUpdateResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, rgName, diskName, params, opts)
}

func (f *fakeDisksAPI) Get(ctx context.Context, rgName, diskName string, opts *armcompute.DisksClientGetOptions) (armcompute.DisksClientGetResponse, error) {
	return f.getFn(ctx, rgName, diskName, opts)
}

func (f *fakeDisksAPI) BeginUpdate(ctx context.Context, rgName, diskName string, params armcompute.DiskUpdate, opts *armcompute.DisksClientBeginUpdateOptions) (*runtime.Poller[armcompute.DisksClientUpdateResponse], error) {
	return f.beginUpdateFn(ctx, rgName, diskName, params, opts)
}

func (f *fakeDisksAPI) BeginDelete(ctx context.Context, rgName, diskName string, opts *armcompute.DisksClientBeginDeleteOptions) (*runtime.Poller[armcompute.DisksClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, diskName, opts)
}

func (f *fakeDisksAPI) NewListByResourceGroupPager(rgName string, opts *armcompute.DisksClientListByResourceGroupOptions) *runtime.Pager[armcompute.DisksClientListByResourceGroupResponse] {
	return f.newListByResourceGroupPagerFn(rgName, opts)
}

func (f *fakeDisksAPI) NewListPager(opts *armcompute.DisksClientListOptions) *runtime.Pager[armcompute.DisksClientListResponse] {
	return f.newListPagerFn(opts)
}
