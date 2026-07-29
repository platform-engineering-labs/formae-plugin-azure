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

const (
	testImageNativeID   = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Compute/images/img-1"
	testImageSnapshotID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Compute/snapshots/snap-1"
	testImageDiskID     = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Compute/disks/disk-1"
)

func TestImage_CRUD(t *testing.T) {
	model := armcompute.Image{
		ID:       to.Ptr(testImageNativeID),
		Name:     to.Ptr("img-1"),
		Location: to.Ptr("eastus"),
		Properties: &armcompute.ImageProperties{
			HyperVGeneration: to.Ptr(armcompute.HyperVGenerationTypesV1),
			StorageProfile: &armcompute.ImageStorageProfile{
				OSDisk: &armcompute.ImageOSDisk{
					OSType:   to.Ptr(armcompute.OperatingSystemTypesLinux),
					OSState:  to.Ptr(armcompute.OperatingSystemStateTypesGeneralized),
					Snapshot: &armcompute.SubResource{ID: to.Ptr(testImageSnapshotID)},
					// ARM fills these in on the nested disk; they are deliberately
					// not modelled, because provider defaults are only honoured on
					// top-level resource fields.
					Caching:            to.Ptr(armcompute.CachingTypesReadWrite),
					StorageAccountType: to.Ptr(armcompute.StorageAccountTypesStandardLRS),
					DiskSizeGB:         to.Ptr(int32(4)),
				},
				ZoneResilient: to.Ptr(false),
			},
			ProvisioningState: to.Ptr("Succeeded"),
		},
		Tags: map[string]*string{"Environment": to.Ptr("test")},
	}
	fake := &fakeImagesAPI{
		beginCreateOrUpdateFn: func(_ context.Context, _, _ string, _ armcompute.Image, _ *armcompute.ImagesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armcompute.ImagesClientCreateOrUpdateResponse], error) {
			return newDonePoller(armcompute.ImagesClientCreateOrUpdateResponse{Image: model}), nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armcompute.ImagesClientGetOptions) (armcompute.ImagesClientGetResponse, error) {
			return armcompute.ImagesClientGetResponse{Image: model}, nil
		},
		beginUpdateFn: func(_ context.Context, _, _ string, _ armcompute.ImageUpdate, _ *armcompute.ImagesClientBeginUpdateOptions) (*runtime.Poller[armcompute.ImagesClientUpdateResponse], error) {
			return newDonePoller(armcompute.ImagesClientUpdateResponse{Image: model}), nil
		},
		beginDeleteFn: func(_ context.Context, _, _ string, _ *armcompute.ImagesClientBeginDeleteOptions) (*runtime.Poller[armcompute.ImagesClientDeleteResponse], error) {
			return newInProgressPoller[armcompute.ImagesClientDeleteResponse](), nil
		},
		newListByResourceGroupPagerFn: func(_ string, _ *armcompute.ImagesClientListByResourceGroupOptions) *runtime.Pager[armcompute.ImagesClientListByResourceGroupResponse] {
			return runtime.NewPager(runtime.PagingHandler[armcompute.ImagesClientListByResourceGroupResponse]{
				More: func(_ armcompute.ImagesClientListByResourceGroupResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armcompute.ImagesClientListByResourceGroupResponse) (armcompute.ImagesClientListByResourceGroupResponse, error) {
					return armcompute.ImagesClientListByResourceGroupResponse{
						ImageListResult: armcompute.ImageListResult{
							Value: []*armcompute.Image{{ID: to.Ptr(testImageNativeID)}},
						},
					}, nil
				},
			})
		},
		newListPagerFn: func(_ *armcompute.ImagesClientListOptions) *runtime.Pager[armcompute.ImagesClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armcompute.ImagesClientListResponse]{
				More: func(_ armcompute.ImagesClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armcompute.ImagesClientListResponse) (armcompute.ImagesClientListResponse, error) {
					return armcompute.ImagesClientListResponse{
						ImageListResult: armcompute.ImageListResult{
							Value: []*armcompute.Image{{ID: to.Ptr(testImageNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestImage(fake)

	mkProps := func() json.RawMessage {
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName": "rg-1",
			"name":              "img-1",
			"location":          "eastus",
			"hyperVGeneration":  "V1",
			"storageProfile": map[string]any{
				"osDisk": map[string]any{
					"osType":     "Linux",
					"osState":    "Generalized",
					"snapshotId": testImageSnapshotID,
				},
			},
			"Tags": []map[string]string{{"Key": "Environment", "Value": "test"}},
		})
		return props
	}

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testImageNativeID, got.ProgressResult.NativeID)

		var serialized map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &serialized))
		require.Equal(t, "img-1", serialized["name"])
		require.Equal(t, "V1", serialized["hyperVGeneration"])
	})

	// ARM defaults caching / storageAccountType / diskSizeGB on the nested OS disk,
	// and hasProviderDefault is not honoured below the top level — surfacing them
	// would be permanent drift, so serialize must drop them.
	t.Run("Serialize_omits_arm_defaulted_nested_fields", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testImageNativeID})
		require.NoError(t, err)
		var serialized map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &serialized))
		sp := serialized["storageProfile"].(map[string]any)
		require.NotContains(t, sp, "zoneResilient")
		osDisk := sp["osDisk"].(map[string]any)
		require.Equal(t, map[string]any{
			"osType":     "Linux",
			"osState":    "Generalized",
			"snapshotId": testImageSnapshotID,
		}, osDisk)
		require.NotContains(t, serialized, "provisioningState")
	})

	t.Run("Create_forwards_params_to_ARM", func(t *testing.T) {
		var seen armcompute.Image
		var seenRG, seenName string
		fake.beginCreateOrUpdateFn = func(_ context.Context, rg, name string, params armcompute.Image, _ *armcompute.ImagesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armcompute.ImagesClientCreateOrUpdateResponse], error) {
			seen, seenRG, seenName = params, rg, name
			return newDonePoller(armcompute.ImagesClientCreateOrUpdateResponse{Image: model}), nil
		}
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, "rg-1", seenRG)
		require.Equal(t, "img-1", seenName)
		require.Equal(t, "eastus", *seen.Location)
		require.Equal(t, armcompute.HyperVGenerationTypesV1, *seen.Properties.HyperVGeneration)
		osDisk := seen.Properties.StorageProfile.OSDisk
		require.Equal(t, armcompute.OperatingSystemTypesLinux, *osDisk.OSType)
		require.Equal(t, armcompute.OperatingSystemStateTypesGeneralized, *osDisk.OSState)
		require.Equal(t, testImageSnapshotID, *osDisk.Snapshot.ID)
		require.Nil(t, osDisk.ManagedDisk)

		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, _ armcompute.Image, _ *armcompute.ImagesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armcompute.ImagesClientCreateOrUpdateResponse], error) {
			return newDonePoller(armcompute.ImagesClientCreateOrUpdateResponse{Image: model}), nil
		}
	})

	t.Run("Create_accepts_managed_disk_source", func(t *testing.T) {
		var seen armcompute.Image
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, params armcompute.Image, _ *armcompute.ImagesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armcompute.ImagesClientCreateOrUpdateResponse], error) {
			seen = params
			return newDonePoller(armcompute.ImagesClientCreateOrUpdateResponse{Image: model}), nil
		}
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName": "rg-1",
			"name":              "img-1",
			"location":          "eastus",
			"storageProfile": map[string]any{
				"osDisk": map[string]any{
					"osType":        "Linux",
					"osState":       "Generalized",
					"managedDiskId": testImageDiskID,
				},
			},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.Equal(t, testImageDiskID, *seen.Properties.StorageProfile.OSDisk.ManagedDisk.ID)
		require.Nil(t, seen.Properties.StorageProfile.OSDisk.Snapshot)

		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, _ armcompute.Image, _ *armcompute.ImagesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armcompute.ImagesClientCreateOrUpdateResponse], error) {
			return newDonePoller(armcompute.ImagesClientCreateOrUpdateResponse{Image: model}), nil
		}
	})

	t.Run("Create_requires_a_source", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName": "rg-1",
			"name":              "img-1",
			"location":          "eastus",
			"storageProfile": map[string]any{
				"osDisk": map[string]any{"osType": "Linux", "osState": "Generalized"},
			},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "either snapshotId or managedDiskId")
	})

	t.Run("Create_requires_storageProfile", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"resourceGroupName": "rg-1", "name": "img-1", "location": "eastus"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "storageProfile is required")
	})

	t.Run("Create_requires_location", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"resourceGroupName": "rg-1", "name": "img-1"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "location is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testImageNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
		require.Equal(t, ResourceTypeImage, got.ResourceType)
	})

	t.Run("Read_not_found", func(t *testing.T) {
		fake.getFn = func(_ context.Context, _, _ string, _ *armcompute.ImagesClientGetOptions) (armcompute.ImagesClientGetResponse, error) {
			return armcompute.ImagesClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testImageNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)

		fake.getFn = func(_ context.Context, _, _ string, _ *armcompute.ImagesClientGetOptions) (armcompute.ImagesClientGetResponse, error) {
			return armcompute.ImagesClientGetResponse{Image: model}, nil
		}
	})

	// The storage profile is createOnly, so the PATCH must not re-declare it.
	t.Run("Update_patch_carries_tags_only", func(t *testing.T) {
		var seen armcompute.ImageUpdate
		var seenRG, seenName string
		fake.beginUpdateFn = func(_ context.Context, rg, name string, params armcompute.ImageUpdate, _ *armcompute.ImagesClientBeginUpdateOptions) (*runtime.Poller[armcompute.ImagesClientUpdateResponse], error) {
			seen, seenRG, seenName = params, rg, name
			return newDonePoller(armcompute.ImagesClientUpdateResponse{Image: model}), nil
		}
		desired, _ := json.Marshal(map[string]any{
			"resourceGroupName": "wrong-rg",
			"name":              "wrong-name",
			"location":          "eastus",
			"storageProfile": map[string]any{
				"osDisk": map[string]any{
					"osType":     "Linux",
					"osState":    "Generalized",
					"snapshotId": testImageSnapshotID,
				},
			},
			"Tags": []map[string]string{{"Key": "Environment", "Value": "updated"}},
		})
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testImageNativeID,
			DesiredProperties: desired,
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, "rg-1", seenRG)
		require.Equal(t, "img-1", seenName)
		require.Nil(t, seen.Properties)
		require.Equal(t, "updated", *seen.Tags["Environment"])
	})

	t.Run("Delete_in_progress_returns_lro_request_id", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testImageNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusInProgress, got.ProgressResult.OperationStatus)
		reqID, err := decodeLROStatus(got.ProgressResult.RequestID)
		require.NoError(t, err)
		require.Equal(t, lroOpDelete, reqID.OperationType)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _ string, _ *armcompute.ImagesClientBeginDeleteOptions) (*runtime.Poller[armcompute.ImagesClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testImageNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Status_rejects_unknown_operation", func(t *testing.T) {
		reqID, err := encodeLROStart("bogus", "token", testImageNativeID)
		require.NoError(t, err)
		got, err := prov.Status(context.Background(), &resource.StatusRequest{RequestID: reqID})
		require.Error(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_resource_group", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testImageNativeID}, got.NativeIDs)
	})

	t.Run("List_all", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Equal(t, []string{testImageNativeID}, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, _ armcompute.Image, _ *armcompute.ImagesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armcompute.ImagesClientCreateOrUpdateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 403}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

func TestImageIDParts(t *testing.T) {
	rg, name, err := imageIDParts(testImageNativeID)
	require.NoError(t, err)
	require.Equal(t, "rg-1", rg)
	require.Equal(t, "img-1", name)

	_, _, err = imageIDParts(testImageSnapshotID)
	require.Error(t, err)
}

// --- Test helpers ---

func newTestImage(api imagesAPI) *Image {
	return &Image{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

type fakeImagesAPI struct {
	beginCreateOrUpdateFn         func(ctx context.Context, rgName, name string, params armcompute.Image, opts *armcompute.ImagesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armcompute.ImagesClientCreateOrUpdateResponse], error)
	getFn                         func(ctx context.Context, rgName, name string, opts *armcompute.ImagesClientGetOptions) (armcompute.ImagesClientGetResponse, error)
	beginUpdateFn                 func(ctx context.Context, rgName, name string, params armcompute.ImageUpdate, opts *armcompute.ImagesClientBeginUpdateOptions) (*runtime.Poller[armcompute.ImagesClientUpdateResponse], error)
	beginDeleteFn                 func(ctx context.Context, rgName, name string, opts *armcompute.ImagesClientBeginDeleteOptions) (*runtime.Poller[armcompute.ImagesClientDeleteResponse], error)
	newListByResourceGroupPagerFn func(rgName string, opts *armcompute.ImagesClientListByResourceGroupOptions) *runtime.Pager[armcompute.ImagesClientListByResourceGroupResponse]
	newListPagerFn                func(opts *armcompute.ImagesClientListOptions) *runtime.Pager[armcompute.ImagesClientListResponse]
}

func (f *fakeImagesAPI) BeginCreateOrUpdate(ctx context.Context, rgName, name string, params armcompute.Image, opts *armcompute.ImagesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armcompute.ImagesClientCreateOrUpdateResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, rgName, name, params, opts)
}

func (f *fakeImagesAPI) Get(ctx context.Context, rgName, name string, opts *armcompute.ImagesClientGetOptions) (armcompute.ImagesClientGetResponse, error) {
	return f.getFn(ctx, rgName, name, opts)
}

func (f *fakeImagesAPI) BeginUpdate(ctx context.Context, rgName, name string, params armcompute.ImageUpdate, opts *armcompute.ImagesClientBeginUpdateOptions) (*runtime.Poller[armcompute.ImagesClientUpdateResponse], error) {
	return f.beginUpdateFn(ctx, rgName, name, params, opts)
}

func (f *fakeImagesAPI) BeginDelete(ctx context.Context, rgName, name string, opts *armcompute.ImagesClientBeginDeleteOptions) (*runtime.Poller[armcompute.ImagesClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, name, opts)
}

func (f *fakeImagesAPI) NewListByResourceGroupPager(rgName string, opts *armcompute.ImagesClientListByResourceGroupOptions) *runtime.Pager[armcompute.ImagesClientListByResourceGroupResponse] {
	return f.newListByResourceGroupPagerFn(rgName, opts)
}

func (f *fakeImagesAPI) NewListPager(opts *armcompute.ImagesClientListOptions) *runtime.Pager[armcompute.ImagesClientListResponse] {
	return f.newListPagerFn(opts)
}
