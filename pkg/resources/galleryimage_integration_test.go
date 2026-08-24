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
	testGalleryImageNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Compute/galleries/gal_1/images/def-1"
	// A standalone managed image ID: same leaf segment word, different type.
	testManagedImageID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Compute/images/img-1"
)

func TestGalleryImage_CRUD(t *testing.T) {
	model := armcompute.GalleryImage{
		ID:       to.Ptr(testGalleryImageNativeID),
		Name:     to.Ptr("def-1"),
		Location: to.Ptr("eastus"),
		Properties: &armcompute.GalleryImageProperties{
			Identifier: &armcompute.GalleryImageIdentifier{
				Publisher: to.Ptr("formae"),
				Offer:     to.Ptr("conformance"),
				SKU:       to.Ptr("linux-gen2"),
			},
			OSType:            to.Ptr(armcompute.OperatingSystemTypesLinux),
			OSState:           to.Ptr(armcompute.OperatingSystemStateTypesGeneralized),
			HyperVGeneration:  to.Ptr(armcompute.HyperVGenerationV2),
			Architecture:      to.Ptr(armcompute.ArchitectureX64),
			Description:       to.Ptr("test definition"),
			ProvisioningState: to.Ptr(armcompute.GalleryProvisioningStateSucceeded),
		},
		Tags: map[string]*string{"Environment": to.Ptr("test")},
	}
	fake := &fakeGalleryImagesAPI{
		beginCreateOrUpdateFn: func(_ context.Context, _, _, _ string, _ armcompute.GalleryImage, _ *armcompute.GalleryImagesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armcompute.GalleryImagesClientCreateOrUpdateResponse], error) {
			return newDonePoller(armcompute.GalleryImagesClientCreateOrUpdateResponse{GalleryImage: model}), nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ *armcompute.GalleryImagesClientGetOptions) (armcompute.GalleryImagesClientGetResponse, error) {
			return armcompute.GalleryImagesClientGetResponse{GalleryImage: model}, nil
		},
		beginUpdateFn: func(_ context.Context, _, _, _ string, _ armcompute.GalleryImageUpdate, _ *armcompute.GalleryImagesClientBeginUpdateOptions) (*runtime.Poller[armcompute.GalleryImagesClientUpdateResponse], error) {
			return newDonePoller(armcompute.GalleryImagesClientUpdateResponse{GalleryImage: model}), nil
		},
		beginDeleteFn: func(_ context.Context, _, _, _ string, _ *armcompute.GalleryImagesClientBeginDeleteOptions) (*runtime.Poller[armcompute.GalleryImagesClientDeleteResponse], error) {
			return newInProgressPoller[armcompute.GalleryImagesClientDeleteResponse](), nil
		},
		newListByGalleryPagerFn: func(_, _ string, _ *armcompute.GalleryImagesClientListByGalleryOptions) *runtime.Pager[armcompute.GalleryImagesClientListByGalleryResponse] {
			return runtime.NewPager(runtime.PagingHandler[armcompute.GalleryImagesClientListByGalleryResponse]{
				More: func(_ armcompute.GalleryImagesClientListByGalleryResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armcompute.GalleryImagesClientListByGalleryResponse) (armcompute.GalleryImagesClientListByGalleryResponse, error) {
					return armcompute.GalleryImagesClientListByGalleryResponse{
						GalleryImageList: armcompute.GalleryImageList{
							Value: []*armcompute.GalleryImage{{ID: to.Ptr(testGalleryImageNativeID)}},
						},
					}, nil
				},
			})
		},
		newListGalleriesPagerFn: func(_ *armcompute.GalleriesClientListOptions) *runtime.Pager[armcompute.GalleriesClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armcompute.GalleriesClientListResponse]{
				More: func(_ armcompute.GalleriesClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armcompute.GalleriesClientListResponse) (armcompute.GalleriesClientListResponse, error) {
					return armcompute.GalleriesClientListResponse{
						GalleryList: armcompute.GalleryList{
							Value: []*armcompute.Gallery{{ID: to.Ptr(testGalleryNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestGalleryImage(fake)

	mkProps := func() json.RawMessage {
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName": "rg-1",
			"galleryName":       "gal_1",
			"name":              "def-1",
			"location":          "eastus",
			"identifier": map[string]any{
				"publisher": "formae",
				"offer":     "conformance",
				"sku":       "linux-gen2",
			},
			"osType":           "Linux",
			"osState":          "Generalized",
			"hyperVGeneration": "V2",
			"architecture":     "x64",
			"description":      "test definition",
			"Tags":             []map[string]string{{"Key": "Environment", "Value": "test"}},
		})
		return props
	}

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testGalleryImageNativeID, got.ProgressResult.NativeID)

		var serialized map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &serialized))
		require.Equal(t, "def-1", serialized["name"])
		require.Equal(t, "gal_1", serialized["galleryName"])
		require.Equal(t, map[string]any{
			"publisher": "formae",
			"offer":     "conformance",
			"sku":       "linux-gen2",
		}, serialized["identifier"])
		require.Equal(t, "V2", serialized["hyperVGeneration"])
		require.Equal(t, "x64", serialized["architecture"])
		require.NotContains(t, serialized, "provisioningState")
	})

	t.Run("Create_forwards_params_to_ARM", func(t *testing.T) {
		var seen armcompute.GalleryImage
		var seenRG, seenGallery, seenName string
		fake.beginCreateOrUpdateFn = func(_ context.Context, rg, gallery, name string, params armcompute.GalleryImage, _ *armcompute.GalleryImagesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armcompute.GalleryImagesClientCreateOrUpdateResponse], error) {
			seen, seenRG, seenGallery, seenName = params, rg, gallery, name
			return newDonePoller(armcompute.GalleryImagesClientCreateOrUpdateResponse{GalleryImage: model}), nil
		}
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, "rg-1", seenRG)
		require.Equal(t, "gal_1", seenGallery)
		require.Equal(t, "def-1", seenName)
		require.Equal(t, "formae", *seen.Properties.Identifier.Publisher)
		require.Equal(t, "conformance", *seen.Properties.Identifier.Offer)
		require.Equal(t, "linux-gen2", *seen.Properties.Identifier.SKU)
		require.Equal(t, armcompute.OperatingSystemTypesLinux, *seen.Properties.OSType)
		require.Equal(t, armcompute.OperatingSystemStateTypesGeneralized, *seen.Properties.OSState)
		require.Equal(t, armcompute.HyperVGenerationV2, *seen.Properties.HyperVGeneration)

		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _, _ string, _ armcompute.GalleryImage, _ *armcompute.GalleryImagesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armcompute.GalleryImagesClientCreateOrUpdateResponse], error) {
			return newDonePoller(armcompute.GalleryImagesClientCreateOrUpdateResponse{GalleryImage: model}), nil
		}
	})

	t.Run("Create_requires_identifier", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName": "rg-1", "galleryName": "gal_1", "name": "def-1", "location": "eastus",
			"osType": "Linux", "osState": "Generalized",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "identifier is required")
	})

	t.Run("Create_requires_full_identifier_triple", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName": "rg-1", "galleryName": "gal_1", "name": "def-1", "location": "eastus",
			"identifier": map[string]any{"publisher": "formae", "offer": "conformance"},
			"osType":     "Linux", "osState": "Generalized",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "identifier.publisher, identifier.offer and identifier.sku")
	})

	t.Run("Create_requires_galleryName", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"resourceGroupName": "rg-1", "name": "def-1", "location": "eastus"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "galleryName is required")
	})

	t.Run("Create_requires_location", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"resourceGroupName": "rg-1", "galleryName": "gal_1", "name": "def-1"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "location is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testGalleryImageNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
		require.Equal(t, ResourceTypeGalleryImage, got.ResourceType)
	})

	t.Run("Read_not_found", func(t *testing.T) {
		fake.getFn = func(_ context.Context, _, _, _ string, _ *armcompute.GalleryImagesClientGetOptions) (armcompute.GalleryImagesClientGetResponse, error) {
			return armcompute.GalleryImagesClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testGalleryImageNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)

		fake.getFn = func(_ context.Context, _, _, _ string, _ *armcompute.GalleryImagesClientGetOptions) (armcompute.GalleryImagesClientGetResponse, error) {
			return armcompute.GalleryImagesClientGetResponse{GalleryImage: model}, nil
		}
	})

	// ARM marks identifier/osType/osState required on the PATCH too, even though all
	// three are immutable, so the update body has to echo them back.
	t.Run("Update_echoes_immutable_identifier", func(t *testing.T) {
		var seen armcompute.GalleryImageUpdate
		var seenRG, seenGallery, seenName string
		fake.beginUpdateFn = func(_ context.Context, rg, gallery, name string, params armcompute.GalleryImageUpdate, _ *armcompute.GalleryImagesClientBeginUpdateOptions) (*runtime.Poller[armcompute.GalleryImagesClientUpdateResponse], error) {
			seen, seenRG, seenGallery, seenName = params, rg, gallery, name
			return newDonePoller(armcompute.GalleryImagesClientUpdateResponse{GalleryImage: model}), nil
		}
		desired, _ := json.Marshal(map[string]any{
			// Wrong parents in the payload — the native ID must win.
			"resourceGroupName": "wrong-rg",
			"galleryName":       "wrong-gallery",
			"name":              "wrong-name",
			"location":          "eastus",
			"identifier": map[string]any{
				"publisher": "formae",
				"offer":     "conformance",
				"sku":       "linux-gen2",
			},
			"osType":      "Linux",
			"osState":     "Generalized",
			"description": "updated definition",
			"Tags":        []map[string]string{{"Key": "Environment", "Value": "updated"}},
		})
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testGalleryImageNativeID,
			DesiredProperties: desired,
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, "rg-1", seenRG)
		require.Equal(t, "gal_1", seenGallery)
		require.Equal(t, "def-1", seenName)
		require.Equal(t, "formae", *seen.Properties.Identifier.Publisher)
		require.Equal(t, armcompute.OperatingSystemTypesLinux, *seen.Properties.OSType)
		require.Equal(t, "updated definition", *seen.Properties.Description)
		require.Equal(t, "updated", *seen.Tags["Environment"])
	})

	t.Run("Delete_in_progress_returns_lro_request_id", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testGalleryImageNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusInProgress, got.ProgressResult.OperationStatus)
		reqID, err := decodeLROStatus(got.ProgressResult.RequestID)
		require.NoError(t, err)
		require.Equal(t, lroOpDelete, reqID.OperationType)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _, _ string, _ *armcompute.GalleryImagesClientBeginDeleteOptions) (*runtime.Poller[armcompute.GalleryImagesClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testGalleryImageNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Status_rejects_unknown_operation", func(t *testing.T) {
		reqID, err := encodeLROStart("bogus", "token", testGalleryImageNativeID)
		require.NoError(t, err)
		got, err := prov.Status(context.Background(), &resource.StatusRequest{RequestID: reqID})
		require.Error(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_gallery", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "galleryName": "gal_1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testGalleryImageNativeID}, got.NativeIDs)
	})

	// Image definitions cannot be listed subscription-wide, so discovery walks
	// every gallery.
	t.Run("List_all_walks_galleries", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Equal(t, []string{testGalleryImageNativeID}, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _, _ string, _ armcompute.GalleryImage, _ *armcompute.GalleryImagesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armcompute.GalleryImagesClientCreateOrUpdateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 403}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

func TestGalleryImageIDParts(t *testing.T) {
	rg, gallery, name, err := galleryImageIDParts(testGalleryImageNativeID)
	require.NoError(t, err)
	require.Equal(t, "rg-1", rg)
	require.Equal(t, "gal_1", gallery)
	require.Equal(t, "def-1", name)

	// A standalone managed image ID also ends in an "images" segment. Name-based
	// matching would accept it; the exact galleries/images chain check must not.
	_, _, _, err = galleryImageIDParts(testManagedImageID)
	require.Error(t, err)

	// A bare gallery ID has no image segment.
	_, _, _, err = galleryImageIDParts(testGalleryNativeID)
	require.Error(t, err)
}

// --- Test helpers ---

func newTestGalleryImage(api galleryImagesAPI) *GalleryImage {
	return &GalleryImage{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

type fakeGalleryImagesAPI struct {
	beginCreateOrUpdateFn   func(ctx context.Context, rgName, galleryName, name string, params armcompute.GalleryImage, opts *armcompute.GalleryImagesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armcompute.GalleryImagesClientCreateOrUpdateResponse], error)
	getFn                   func(ctx context.Context, rgName, galleryName, name string, opts *armcompute.GalleryImagesClientGetOptions) (armcompute.GalleryImagesClientGetResponse, error)
	beginUpdateFn           func(ctx context.Context, rgName, galleryName, name string, params armcompute.GalleryImageUpdate, opts *armcompute.GalleryImagesClientBeginUpdateOptions) (*runtime.Poller[armcompute.GalleryImagesClientUpdateResponse], error)
	beginDeleteFn           func(ctx context.Context, rgName, galleryName, name string, opts *armcompute.GalleryImagesClientBeginDeleteOptions) (*runtime.Poller[armcompute.GalleryImagesClientDeleteResponse], error)
	newListByGalleryPagerFn func(rgName, galleryName string, opts *armcompute.GalleryImagesClientListByGalleryOptions) *runtime.Pager[armcompute.GalleryImagesClientListByGalleryResponse]
	newListGalleriesPagerFn func(opts *armcompute.GalleriesClientListOptions) *runtime.Pager[armcompute.GalleriesClientListResponse]
}

func (f *fakeGalleryImagesAPI) BeginCreateOrUpdate(ctx context.Context, rgName, galleryName, name string, params armcompute.GalleryImage, opts *armcompute.GalleryImagesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armcompute.GalleryImagesClientCreateOrUpdateResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, rgName, galleryName, name, params, opts)
}

func (f *fakeGalleryImagesAPI) Get(ctx context.Context, rgName, galleryName, name string, opts *armcompute.GalleryImagesClientGetOptions) (armcompute.GalleryImagesClientGetResponse, error) {
	return f.getFn(ctx, rgName, galleryName, name, opts)
}

func (f *fakeGalleryImagesAPI) BeginUpdate(ctx context.Context, rgName, galleryName, name string, params armcompute.GalleryImageUpdate, opts *armcompute.GalleryImagesClientBeginUpdateOptions) (*runtime.Poller[armcompute.GalleryImagesClientUpdateResponse], error) {
	return f.beginUpdateFn(ctx, rgName, galleryName, name, params, opts)
}

func (f *fakeGalleryImagesAPI) BeginDelete(ctx context.Context, rgName, galleryName, name string, opts *armcompute.GalleryImagesClientBeginDeleteOptions) (*runtime.Poller[armcompute.GalleryImagesClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, galleryName, name, opts)
}

func (f *fakeGalleryImagesAPI) NewListByGalleryPager(rgName, galleryName string, opts *armcompute.GalleryImagesClientListByGalleryOptions) *runtime.Pager[armcompute.GalleryImagesClientListByGalleryResponse] {
	return f.newListByGalleryPagerFn(rgName, galleryName, opts)
}

func (f *fakeGalleryImagesAPI) NewListGalleriesPager(opts *armcompute.GalleriesClientListOptions) *runtime.Pager[armcompute.GalleriesClientListResponse] {
	return f.newListGalleriesPagerFn(opts)
}
