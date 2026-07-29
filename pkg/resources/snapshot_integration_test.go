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
	testSnapshotNativeID  = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Compute/snapshots/snap-1"
	testSnapshotSourceDsk = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Compute/disks/disk-1"
)

func TestSnapshot_CRUD(t *testing.T) {
	model := armcompute.Snapshot{
		ID:       to.Ptr(testSnapshotNativeID),
		Name:     to.Ptr("snap-1"),
		Location: to.Ptr("eastus"),
		SKU: &armcompute.SnapshotSKU{
			Name: to.Ptr(armcompute.SnapshotStorageAccountTypesStandardLRS),
			// Tier is read-only ARM output with no schema field.
			Tier: to.Ptr("Standard"),
		},
		Properties: &armcompute.SnapshotProperties{
			CreationData: &armcompute.CreationData{
				CreateOption:     to.Ptr(armcompute.DiskCreateOptionCopy),
				SourceResourceID: to.Ptr(testSnapshotSourceDsk),
			},
			DiskSizeGB:  to.Ptr(int32(4)),
			Incremental: to.Ptr(false),
			// Read-only ARM output that must not leak into properties.
			ProvisioningState: to.Ptr("Succeeded"),
			DiskState:         to.Ptr(armcompute.DiskStateUnattached),
		},
		Tags: map[string]*string{"Environment": to.Ptr("test")},
	}
	fake := &fakeSnapshotsAPI{
		beginCreateOrUpdateFn: func(_ context.Context, _, _ string, _ armcompute.Snapshot, _ *armcompute.SnapshotsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armcompute.SnapshotsClientCreateOrUpdateResponse], error) {
			return newDonePoller(armcompute.SnapshotsClientCreateOrUpdateResponse{Snapshot: model}), nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armcompute.SnapshotsClientGetOptions) (armcompute.SnapshotsClientGetResponse, error) {
			return armcompute.SnapshotsClientGetResponse{Snapshot: model}, nil
		},
		beginUpdateFn: func(_ context.Context, _, _ string, _ armcompute.SnapshotUpdate, _ *armcompute.SnapshotsClientBeginUpdateOptions) (*runtime.Poller[armcompute.SnapshotsClientUpdateResponse], error) {
			return newDonePoller(armcompute.SnapshotsClientUpdateResponse{Snapshot: model}), nil
		},
		beginDeleteFn: func(_ context.Context, _, _ string, _ *armcompute.SnapshotsClientBeginDeleteOptions) (*runtime.Poller[armcompute.SnapshotsClientDeleteResponse], error) {
			return newInProgressPoller[armcompute.SnapshotsClientDeleteResponse](), nil
		},
		newListByResourceGroupPagerFn: func(_ string, _ *armcompute.SnapshotsClientListByResourceGroupOptions) *runtime.Pager[armcompute.SnapshotsClientListByResourceGroupResponse] {
			return runtime.NewPager(runtime.PagingHandler[armcompute.SnapshotsClientListByResourceGroupResponse]{
				More: func(_ armcompute.SnapshotsClientListByResourceGroupResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armcompute.SnapshotsClientListByResourceGroupResponse) (armcompute.SnapshotsClientListByResourceGroupResponse, error) {
					return armcompute.SnapshotsClientListByResourceGroupResponse{
						SnapshotList: armcompute.SnapshotList{
							Value: []*armcompute.Snapshot{{ID: to.Ptr(testSnapshotNativeID)}},
						},
					}, nil
				},
			})
		},
		newListPagerFn: func(_ *armcompute.SnapshotsClientListOptions) *runtime.Pager[armcompute.SnapshotsClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armcompute.SnapshotsClientListResponse]{
				More: func(_ armcompute.SnapshotsClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armcompute.SnapshotsClientListResponse) (armcompute.SnapshotsClientListResponse, error) {
					return armcompute.SnapshotsClientListResponse{
						SnapshotList: armcompute.SnapshotList{
							Value: []*armcompute.Snapshot{{ID: to.Ptr(testSnapshotNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestSnapshot(fake)

	mkProps := func() json.RawMessage {
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName": "rg-1",
			"name":              "snap-1",
			"location":          "eastus",
			"creationData": map[string]any{
				"createOption":     "Copy",
				"sourceResourceId": testSnapshotSourceDsk,
			},
			"sku":         map[string]any{"name": "Standard_LRS"},
			"incremental": false,
			"Tags":        []map[string]string{{"Key": "Environment", "Value": "test"}},
		})
		return props
	}

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testSnapshotNativeID, got.ProgressResult.NativeID)

		var serialized map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &serialized))
		require.Equal(t, "snap-1", serialized["name"])
		require.Equal(t, "rg-1", serialized["resourceGroupName"])
		require.Equal(t, float64(4), serialized["diskSizeGB"])
		require.Equal(t, false, serialized["incremental"])
		require.Equal(t, map[string]any{
			"createOption":     "Copy",
			"sourceResourceId": testSnapshotSourceDsk,
		}, serialized["creationData"])
	})

	// sku.tier / provisioningState / diskState have no schema field, and conformance
	// Verify rejects any property it did not ask for.
	t.Run("Serialize_omits_unmodelled_readonly_fields", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testSnapshotNativeID})
		require.NoError(t, err)
		var serialized map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &serialized))
		require.Equal(t, map[string]any{"name": "Standard_LRS"}, serialized["sku"])
		require.NotContains(t, serialized, "provisioningState")
		require.NotContains(t, serialized, "diskState")
	})

	t.Run("Create_forwards_params_to_ARM", func(t *testing.T) {
		var seen armcompute.Snapshot
		var seenRG, seenName string
		fake.beginCreateOrUpdateFn = func(_ context.Context, rg, name string, params armcompute.Snapshot, _ *armcompute.SnapshotsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armcompute.SnapshotsClientCreateOrUpdateResponse], error) {
			seen, seenRG, seenName = params, rg, name
			return newDonePoller(armcompute.SnapshotsClientCreateOrUpdateResponse{Snapshot: model}), nil
		}
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, "rg-1", seenRG)
		require.Equal(t, "snap-1", seenName)
		require.Equal(t, "eastus", *seen.Location)
		require.Equal(t, armcompute.SnapshotStorageAccountTypesStandardLRS, *seen.SKU.Name)
		require.Equal(t, armcompute.DiskCreateOptionCopy, *seen.Properties.CreationData.CreateOption)
		require.Equal(t, testSnapshotSourceDsk, *seen.Properties.CreationData.SourceResourceID)
		require.False(t, *seen.Properties.Incremental)
		require.Equal(t, "test", *seen.Tags["Environment"])
		// Azure derives the size from the source; sending it would read as a resize.
		require.Nil(t, seen.Properties.DiskSizeGB)

		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, _ armcompute.Snapshot, _ *armcompute.SnapshotsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armcompute.SnapshotsClientCreateOrUpdateResponse], error) {
			return newDonePoller(armcompute.SnapshotsClientCreateOrUpdateResponse{Snapshot: model}), nil
		}
	})

	t.Run("Create_requires_location", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"resourceGroupName": "rg-1", "name": "snap-1"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "location is required")
	})

	t.Run("Create_requires_creationData", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"resourceGroupName": "rg-1", "name": "snap-1", "location": "eastus"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "creationData is required")
	})

	t.Run("Create_requires_resourceGroupName", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "snap-1", "location": "eastus"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "resourceGroupName is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testSnapshotNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
		require.Equal(t, ResourceTypeSnapshot, got.ResourceType)
	})

	t.Run("Read_not_found", func(t *testing.T) {
		fake.getFn = func(_ context.Context, _, _ string, _ *armcompute.SnapshotsClientGetOptions) (armcompute.SnapshotsClientGetResponse, error) {
			return armcompute.SnapshotsClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testSnapshotNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)

		fake.getFn = func(_ context.Context, _, _ string, _ *armcompute.SnapshotsClientGetOptions) (armcompute.SnapshotsClientGetResponse, error) {
			return armcompute.SnapshotsClientGetResponse{Snapshot: model}, nil
		}
	})

	// creationData is immutable; a PATCH that carries it is rejected by ARM, so the
	// update body must only ever hold tags, sku and size.
	t.Run("Update_patch_omits_creationData", func(t *testing.T) {
		var seen armcompute.SnapshotUpdate
		var seenRG, seenName string
		fake.beginUpdateFn = func(_ context.Context, rg, name string, params armcompute.SnapshotUpdate, _ *armcompute.SnapshotsClientBeginUpdateOptions) (*runtime.Poller[armcompute.SnapshotsClientUpdateResponse], error) {
			seen, seenRG, seenName = params, rg, name
			return newDonePoller(armcompute.SnapshotsClientUpdateResponse{Snapshot: model}), nil
		}
		desired, _ := json.Marshal(map[string]any{
			// Wrong parents in the payload — the native ID must win.
			"resourceGroupName": "wrong-rg",
			"name":              "wrong-name",
			"location":          "eastus",
			"creationData": map[string]any{
				"createOption":     "Copy",
				"sourceResourceId": testSnapshotSourceDsk,
			},
			"sku":  map[string]any{"name": "Standard_ZRS"},
			"Tags": []map[string]string{{"Key": "Environment", "Value": "updated"}},
		})
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testSnapshotNativeID,
			DesiredProperties: desired,
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, "rg-1", seenRG)
		require.Equal(t, "snap-1", seenName)
		require.Equal(t, armcompute.SnapshotStorageAccountTypesStandardZRS, *seen.SKU.Name)
		require.Equal(t, "updated", *seen.Tags["Environment"])
	})

	t.Run("Delete_in_progress_returns_lro_request_id", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testSnapshotNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusInProgress, got.ProgressResult.OperationStatus)
		reqID, err := decodeLROStatus(got.ProgressResult.RequestID)
		require.NoError(t, err)
		require.Equal(t, lroOpDelete, reqID.OperationType)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _ string, _ *armcompute.SnapshotsClientBeginDeleteOptions) (*runtime.Poller[armcompute.SnapshotsClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testSnapshotNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Status_rejects_unknown_operation", func(t *testing.T) {
		reqID, err := encodeLROStart("bogus", "token", testSnapshotNativeID)
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
		require.Equal(t, []string{testSnapshotNativeID}, got.NativeIDs)
	})

	t.Run("List_all", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Equal(t, []string{testSnapshotNativeID}, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, _ armcompute.Snapshot, _ *armcompute.SnapshotsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armcompute.SnapshotsClientCreateOrUpdateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 403}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

func TestSnapshotIDParts(t *testing.T) {
	rg, name, err := snapshotIDParts(testSnapshotNativeID)
	require.NoError(t, err)
	require.Equal(t, "rg-1", rg)
	require.Equal(t, "snap-1", name)

	// A disk ID has no snapshots segment.
	_, _, err = snapshotIDParts(testSnapshotSourceDsk)
	require.Error(t, err)
}

// --- Test helpers ---

func newTestSnapshot(api snapshotsAPI) *Snapshot {
	return &Snapshot{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

type fakeSnapshotsAPI struct {
	beginCreateOrUpdateFn         func(ctx context.Context, rgName, name string, params armcompute.Snapshot, opts *armcompute.SnapshotsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armcompute.SnapshotsClientCreateOrUpdateResponse], error)
	getFn                         func(ctx context.Context, rgName, name string, opts *armcompute.SnapshotsClientGetOptions) (armcompute.SnapshotsClientGetResponse, error)
	beginUpdateFn                 func(ctx context.Context, rgName, name string, params armcompute.SnapshotUpdate, opts *armcompute.SnapshotsClientBeginUpdateOptions) (*runtime.Poller[armcompute.SnapshotsClientUpdateResponse], error)
	beginDeleteFn                 func(ctx context.Context, rgName, name string, opts *armcompute.SnapshotsClientBeginDeleteOptions) (*runtime.Poller[armcompute.SnapshotsClientDeleteResponse], error)
	newListByResourceGroupPagerFn func(rgName string, opts *armcompute.SnapshotsClientListByResourceGroupOptions) *runtime.Pager[armcompute.SnapshotsClientListByResourceGroupResponse]
	newListPagerFn                func(opts *armcompute.SnapshotsClientListOptions) *runtime.Pager[armcompute.SnapshotsClientListResponse]
}

func (f *fakeSnapshotsAPI) BeginCreateOrUpdate(ctx context.Context, rgName, name string, params armcompute.Snapshot, opts *armcompute.SnapshotsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armcompute.SnapshotsClientCreateOrUpdateResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, rgName, name, params, opts)
}

func (f *fakeSnapshotsAPI) Get(ctx context.Context, rgName, name string, opts *armcompute.SnapshotsClientGetOptions) (armcompute.SnapshotsClientGetResponse, error) {
	return f.getFn(ctx, rgName, name, opts)
}

func (f *fakeSnapshotsAPI) BeginUpdate(ctx context.Context, rgName, name string, params armcompute.SnapshotUpdate, opts *armcompute.SnapshotsClientBeginUpdateOptions) (*runtime.Poller[armcompute.SnapshotsClientUpdateResponse], error) {
	return f.beginUpdateFn(ctx, rgName, name, params, opts)
}

func (f *fakeSnapshotsAPI) BeginDelete(ctx context.Context, rgName, name string, opts *armcompute.SnapshotsClientBeginDeleteOptions) (*runtime.Poller[armcompute.SnapshotsClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, name, opts)
}

func (f *fakeSnapshotsAPI) NewListByResourceGroupPager(rgName string, opts *armcompute.SnapshotsClientListByResourceGroupOptions) *runtime.Pager[armcompute.SnapshotsClientListByResourceGroupResponse] {
	return f.newListByResourceGroupPagerFn(rgName, opts)
}

func (f *fakeSnapshotsAPI) NewListPager(opts *armcompute.SnapshotsClientListOptions) *runtime.Pager[armcompute.SnapshotsClientListResponse] {
	return f.newListPagerFn(opts)
}
