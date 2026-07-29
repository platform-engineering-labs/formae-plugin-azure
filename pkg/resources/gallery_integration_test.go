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

const testGalleryNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Compute/galleries/gal_1"

func TestGallery_CRUD(t *testing.T) {
	model := armcompute.Gallery{
		ID:       to.Ptr(testGalleryNativeID),
		Name:     to.Ptr("gal_1"),
		Location: to.Ptr("eastus"),
		Properties: &armcompute.GalleryProperties{
			Description: to.Ptr("test gallery"),
			// Read-only ARM output with no schema field.
			Identifier:        &armcompute.GalleryIdentifier{UniqueName: to.Ptr("sub-1-GAL_1")},
			ProvisioningState: to.Ptr(armcompute.GalleryProvisioningStateSucceeded),
		},
		Tags: map[string]*string{"Environment": to.Ptr("test")},
	}
	fake := &fakeGalleriesAPI{
		beginCreateOrUpdateFn: func(_ context.Context, _, _ string, _ armcompute.Gallery, _ *armcompute.GalleriesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armcompute.GalleriesClientCreateOrUpdateResponse], error) {
			return newDonePoller(armcompute.GalleriesClientCreateOrUpdateResponse{Gallery: model}), nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armcompute.GalleriesClientGetOptions) (armcompute.GalleriesClientGetResponse, error) {
			return armcompute.GalleriesClientGetResponse{Gallery: model}, nil
		},
		beginUpdateFn: func(_ context.Context, _, _ string, _ armcompute.GalleryUpdate, _ *armcompute.GalleriesClientBeginUpdateOptions) (*runtime.Poller[armcompute.GalleriesClientUpdateResponse], error) {
			return newDonePoller(armcompute.GalleriesClientUpdateResponse{Gallery: model}), nil
		},
		beginDeleteFn: func(_ context.Context, _, _ string, _ *armcompute.GalleriesClientBeginDeleteOptions) (*runtime.Poller[armcompute.GalleriesClientDeleteResponse], error) {
			return newInProgressPoller[armcompute.GalleriesClientDeleteResponse](), nil
		},
		newListByResourceGroupPagerFn: func(_ string, _ *armcompute.GalleriesClientListByResourceGroupOptions) *runtime.Pager[armcompute.GalleriesClientListByResourceGroupResponse] {
			return runtime.NewPager(runtime.PagingHandler[armcompute.GalleriesClientListByResourceGroupResponse]{
				More: func(_ armcompute.GalleriesClientListByResourceGroupResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armcompute.GalleriesClientListByResourceGroupResponse) (armcompute.GalleriesClientListByResourceGroupResponse, error) {
					return armcompute.GalleriesClientListByResourceGroupResponse{
						GalleryList: armcompute.GalleryList{Value: []*armcompute.Gallery{{ID: to.Ptr(testGalleryNativeID)}}},
					}, nil
				},
			})
		},
		newListPagerFn: func(_ *armcompute.GalleriesClientListOptions) *runtime.Pager[armcompute.GalleriesClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armcompute.GalleriesClientListResponse]{
				More: func(_ armcompute.GalleriesClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armcompute.GalleriesClientListResponse) (armcompute.GalleriesClientListResponse, error) {
					return armcompute.GalleriesClientListResponse{
						GalleryList: armcompute.GalleryList{Value: []*armcompute.Gallery{{ID: to.Ptr(testGalleryNativeID)}}},
					}, nil
				},
			})
		},
	}
	prov := newTestGallery(fake)

	mkProps := func() json.RawMessage {
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName": "rg-1",
			"name":              "gal_1",
			"location":          "eastus",
			"description":       "test gallery",
			"Tags":              []map[string]string{{"Key": "Environment", "Value": "test"}},
		})
		return props
	}

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testGalleryNativeID, got.ProgressResult.NativeID)

		var serialized map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &serialized))
		require.Equal(t, "gal_1", serialized["name"])
		require.Equal(t, "test gallery", serialized["description"])
	})

	// identifier.uniqueName and provisioningState are read-only ARM output with no
	// schema field; conformance Verify rejects properties it did not ask for.
	t.Run("Serialize_omits_unmodelled_readonly_fields", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testGalleryNativeID})
		require.NoError(t, err)
		var serialized map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &serialized))
		require.NotContains(t, serialized, "identifier")
		require.NotContains(t, serialized, "provisioningState")
	})

	t.Run("Create_forwards_params_to_ARM", func(t *testing.T) {
		var seen armcompute.Gallery
		var seenRG, seenName string
		fake.beginCreateOrUpdateFn = func(_ context.Context, rg, name string, params armcompute.Gallery, _ *armcompute.GalleriesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armcompute.GalleriesClientCreateOrUpdateResponse], error) {
			seen, seenRG, seenName = params, rg, name
			return newDonePoller(armcompute.GalleriesClientCreateOrUpdateResponse{Gallery: model}), nil
		}
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, "rg-1", seenRG)
		require.Equal(t, "gal_1", seenName)
		require.Equal(t, "eastus", *seen.Location)
		require.Equal(t, "test gallery", *seen.Properties.Description)
		require.Equal(t, "test", *seen.Tags["Environment"])

		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, _ armcompute.Gallery, _ *armcompute.GalleriesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armcompute.GalleriesClientCreateOrUpdateResponse], error) {
			return newDonePoller(armcompute.GalleriesClientCreateOrUpdateResponse{Gallery: model}), nil
		}
	})

	t.Run("Create_requires_location", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"resourceGroupName": "rg-1", "name": "gal_1"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "location is required")
	})

	t.Run("Create_requires_resourceGroupName", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "gal_1", "location": "eastus"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "resourceGroupName is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testGalleryNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
		require.Equal(t, ResourceTypeGallery, got.ResourceType)
	})

	t.Run("Read_not_found", func(t *testing.T) {
		fake.getFn = func(_ context.Context, _, _ string, _ *armcompute.GalleriesClientGetOptions) (armcompute.GalleriesClientGetResponse, error) {
			return armcompute.GalleriesClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testGalleryNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)

		fake.getFn = func(_ context.Context, _, _ string, _ *armcompute.GalleriesClientGetOptions) (armcompute.GalleriesClientGetResponse, error) {
			return armcompute.GalleriesClientGetResponse{Gallery: model}, nil
		}
	})

	t.Run("Update_derives_parents_from_native_id", func(t *testing.T) {
		var seen armcompute.GalleryUpdate
		var seenRG, seenName string
		fake.beginUpdateFn = func(_ context.Context, rg, name string, params armcompute.GalleryUpdate, _ *armcompute.GalleriesClientBeginUpdateOptions) (*runtime.Poller[armcompute.GalleriesClientUpdateResponse], error) {
			seen, seenRG, seenName = params, rg, name
			return newDonePoller(armcompute.GalleriesClientUpdateResponse{Gallery: model}), nil
		}
		desired, _ := json.Marshal(map[string]any{
			"resourceGroupName": "wrong-rg",
			"name":              "wrong-name",
			"location":          "eastus",
			"description":       "updated gallery",
			"Tags":              []map[string]string{{"Key": "Environment", "Value": "updated"}},
		})
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testGalleryNativeID,
			DesiredProperties: desired,
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, "rg-1", seenRG)
		require.Equal(t, "gal_1", seenName)
		require.Equal(t, "updated gallery", *seen.Properties.Description)
		require.Equal(t, "updated", *seen.Tags["Environment"])
	})

	t.Run("Delete_in_progress_returns_lro_request_id", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testGalleryNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusInProgress, got.ProgressResult.OperationStatus)
		reqID, err := decodeLROStatus(got.ProgressResult.RequestID)
		require.NoError(t, err)
		require.Equal(t, lroOpDelete, reqID.OperationType)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _ string, _ *armcompute.GalleriesClientBeginDeleteOptions) (*runtime.Poller[armcompute.GalleriesClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testGalleryNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Status_rejects_unknown_operation", func(t *testing.T) {
		reqID, err := encodeLROStart("bogus", "token", testGalleryNativeID)
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
		require.Equal(t, []string{testGalleryNativeID}, got.NativeIDs)
	})

	t.Run("List_all", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Equal(t, []string{testGalleryNativeID}, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, _ armcompute.Gallery, _ *armcompute.GalleriesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armcompute.GalleriesClientCreateOrUpdateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 403}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

func TestGalleryIDParts(t *testing.T) {
	rg, name, err := galleryIDParts(testGalleryNativeID)
	require.NoError(t, err)
	require.Equal(t, "rg-1", rg)
	require.Equal(t, "gal_1", name)

	// An image definition ID nests under a gallery, so the exact chain check
	// rejects it here.
	_, _, err = galleryIDParts(testGalleryNativeID + "/images/def-1")
	require.Error(t, err)
}

// --- Test helpers ---

func newTestGallery(api galleriesAPI) *Gallery {
	return &Gallery{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

type fakeGalleriesAPI struct {
	beginCreateOrUpdateFn         func(ctx context.Context, rgName, name string, params armcompute.Gallery, opts *armcompute.GalleriesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armcompute.GalleriesClientCreateOrUpdateResponse], error)
	getFn                         func(ctx context.Context, rgName, name string, opts *armcompute.GalleriesClientGetOptions) (armcompute.GalleriesClientGetResponse, error)
	beginUpdateFn                 func(ctx context.Context, rgName, name string, params armcompute.GalleryUpdate, opts *armcompute.GalleriesClientBeginUpdateOptions) (*runtime.Poller[armcompute.GalleriesClientUpdateResponse], error)
	beginDeleteFn                 func(ctx context.Context, rgName, name string, opts *armcompute.GalleriesClientBeginDeleteOptions) (*runtime.Poller[armcompute.GalleriesClientDeleteResponse], error)
	newListByResourceGroupPagerFn func(rgName string, opts *armcompute.GalleriesClientListByResourceGroupOptions) *runtime.Pager[armcompute.GalleriesClientListByResourceGroupResponse]
	newListPagerFn                func(opts *armcompute.GalleriesClientListOptions) *runtime.Pager[armcompute.GalleriesClientListResponse]
}

func (f *fakeGalleriesAPI) BeginCreateOrUpdate(ctx context.Context, rgName, name string, params armcompute.Gallery, opts *armcompute.GalleriesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armcompute.GalleriesClientCreateOrUpdateResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, rgName, name, params, opts)
}

func (f *fakeGalleriesAPI) Get(ctx context.Context, rgName, name string, opts *armcompute.GalleriesClientGetOptions) (armcompute.GalleriesClientGetResponse, error) {
	return f.getFn(ctx, rgName, name, opts)
}

func (f *fakeGalleriesAPI) BeginUpdate(ctx context.Context, rgName, name string, params armcompute.GalleryUpdate, opts *armcompute.GalleriesClientBeginUpdateOptions) (*runtime.Poller[armcompute.GalleriesClientUpdateResponse], error) {
	return f.beginUpdateFn(ctx, rgName, name, params, opts)
}

func (f *fakeGalleriesAPI) BeginDelete(ctx context.Context, rgName, name string, opts *armcompute.GalleriesClientBeginDeleteOptions) (*runtime.Poller[armcompute.GalleriesClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, name, opts)
}

func (f *fakeGalleriesAPI) NewListByResourceGroupPager(rgName string, opts *armcompute.GalleriesClientListByResourceGroupOptions) *runtime.Pager[armcompute.GalleriesClientListByResourceGroupResponse] {
	return f.newListByResourceGroupPagerFn(rgName, opts)
}

func (f *fakeGalleriesAPI) NewListPager(opts *armcompute.GalleriesClientListOptions) *runtime.Pager[armcompute.GalleriesClientListResponse] {
	return f.newListPagerFn(opts)
}
