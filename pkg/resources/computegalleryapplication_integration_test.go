// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v5"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testGalleryAppNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Compute/galleries/gal1/applications/app1"

func newTestGalleryApp(api computeGalleryApplicationsAPI) *ComputeGalleryApplication {
	return &ComputeGalleryApplication{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func galleryAppDesired(description string) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":              "app1",
		"location":          "eastus",
		"resourceGroupName": "rg-1",
		"galleryName":       "gal1",
		"supportedOSType":   "Linux",
		"description":       description,
		"Tags":              []any{map[string]any{"Key": "env", "Value": "test"}},
	})
	return out
}

func TestComputeGalleryApplication_CRUD(t *testing.T) {
	appResult := armcompute.GalleryApplication{
		ID:       to.Ptr(testGalleryAppNativeID),
		Name:     to.Ptr("app1"),
		Location: to.Ptr("East US"),
		Properties: &armcompute.GalleryApplicationProperties{
			SupportedOSType: to.Ptr(armcompute.OperatingSystemTypesLinux),
			Description:     to.Ptr("node agent"),
			// Fields the schema does not model.
			Eula:          to.Ptr("https://example.invalid/eula"),
			EndOfLifeDate: to.Ptr(time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)),
			CustomActions: []*armcompute.GalleryApplicationCustomAction{{
				Name:   to.Ptr("restart"),
				Script: to.Ptr("systemctl restart agent"),
			}},
		},
		Tags: map[string]*string{"env": to.Ptr("test")},
	}

	var sentCreate armcompute.GalleryApplication
	var sentUpdate armcompute.GalleryApplicationUpdate
	var sawPath []string
	deleteCalls := 0
	fake := &fakeGalleryAppsAPI{
		beginCreateOrUpdateFn: func(_ context.Context, rgName, galleryName, name string, app armcompute.GalleryApplication, _ *armcompute.GalleryApplicationsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armcompute.GalleryApplicationsClientCreateOrUpdateResponse], error) {
			sawPath = []string{rgName, galleryName, name}
			sentCreate = app
			return newDonePoller(armcompute.GalleryApplicationsClientCreateOrUpdateResponse{GalleryApplication: appResult}), nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ *armcompute.GalleryApplicationsClientGetOptions) (armcompute.GalleryApplicationsClientGetResponse, error) {
			return armcompute.GalleryApplicationsClientGetResponse{GalleryApplication: appResult}, nil
		},
		beginUpdateFn: func(_ context.Context, _, _, _ string, app armcompute.GalleryApplicationUpdate, _ *armcompute.GalleryApplicationsClientBeginUpdateOptions) (*runtime.Poller[armcompute.GalleryApplicationsClientUpdateResponse], error) {
			sentUpdate = app
			return newDonePoller(armcompute.GalleryApplicationsClientUpdateResponse{GalleryApplication: appResult}), nil
		},
		beginDeleteFn: func(_ context.Context, _, _, _ string, _ *armcompute.GalleryApplicationsClientBeginDeleteOptions) (*runtime.Poller[armcompute.GalleryApplicationsClientDeleteResponse], error) {
			deleteCalls++
			return newDonePoller(armcompute.GalleryApplicationsClientDeleteResponse{}), nil
		},
		newListByGalleryPagerFn: func(_, _ string, _ *armcompute.GalleryApplicationsClientListByGalleryOptions) *runtime.Pager[armcompute.GalleryApplicationsClientListByGalleryResponse] {
			return runtime.NewPager(runtime.PagingHandler[armcompute.GalleryApplicationsClientListByGalleryResponse]{
				More: func(_ armcompute.GalleryApplicationsClientListByGalleryResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armcompute.GalleryApplicationsClientListByGalleryResponse) (armcompute.GalleryApplicationsClientListByGalleryResponse, error) {
					return armcompute.GalleryApplicationsClientListByGalleryResponse{
						GalleryApplicationList: armcompute.GalleryApplicationList{
							Value: []*armcompute.GalleryApplication{{ID: to.Ptr(testGalleryAppNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestGalleryApp(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "app1", Properties: galleryAppDesired("node agent"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testGalleryAppNativeID, got.ProgressResult.NativeID)

		require.Equal(t, []string{"rg-1", "gal1", "app1"}, sawPath)
		require.Equal(t, "eastus", *sentCreate.Location)
		require.Equal(t, armcompute.OperatingSystemTypesLinux, *sentCreate.Properties.SupportedOSType)
		require.Equal(t, "node agent", *sentCreate.Properties.Description)
		require.Equal(t, "test", *sentCreate.Tags["env"])
		// Custom actions are not modelled, so none are ever sent.
		require.Nil(t, sentCreate.Properties.CustomActions)
	})

	t.Run("Create_requires_supported_os_type", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "app1", "location": "eastus", "resourceGroupName": "rg-1", "galleryName": "gal1",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "supportedOSType is required")
	})

	t.Run("Create_requires_gallery", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "app1", "location": "eastus", "resourceGroupName": "rg-1",
			"supportedOSType": "Linux",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "galleryName is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testGalleryAppNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "app1", props["name"])
		// ARM returns "East US"; read must normalise or desired state drifts.
		require.Equal(t, "eastus", props["location"])
		// Both parents come from the native ID, not the response body.
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "gal1", props["galleryName"])
		require.Equal(t, "Linux", props["supportedOSType"])
		require.Equal(t, "node agent", props["description"])
	})

	t.Run("Read_drops_unmodelled_fields", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testGalleryAppNativeID})
		require.NoError(t, err)
		for _, key := range []string{
			"customActions", "eula", "endOfLifeDate",
			"privacyStatementUri", "releaseNoteUri",
		} {
			require.NotContains(t, got.Properties, key)
		}
		require.NotContains(t, got.Properties, "systemctl restart agent")
	})

	t.Run("Update_sends_update_parameters", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testGalleryAppNativeID,
			DesiredProperties: galleryAppDesired("node agent v2"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, "node agent v2", *sentUpdate.Properties.Description)
		require.Equal(t, "test", *sentUpdate.Tags["env"])
	})

	t.Run("Delete", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testGalleryAppNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _, _ string, _ *armcompute.GalleryApplicationsClientBeginDeleteOptions) (*runtime.Poller[armcompute.GalleryApplicationsClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testGalleryAppNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_gallery", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "galleryName": "gal1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testGalleryAppNativeID}, got.NativeIDs)
	})

	t.Run("List_without_parents_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _, _ string, _ armcompute.GalleryApplication, _ *armcompute.GalleryApplicationsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armcompute.GalleryApplicationsClientCreateOrUpdateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 409}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "app1", Properties: galleryAppDesired("node agent"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

// The native ID reported for an in-flight create must match the path ARM returns —
// the child segment is "applications", not "galleryApplications".
func TestComputeGalleryApplication_PendingCreateReportsRealNativeID(t *testing.T) {
	fake := &fakeGalleryAppsAPI{
		beginCreateOrUpdateFn: func(_ context.Context, _, _, _ string, _ armcompute.GalleryApplication, _ *armcompute.GalleryApplicationsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armcompute.GalleryApplicationsClientCreateOrUpdateResponse], error) {
			return newPendingPoller[armcompute.GalleryApplicationsClientCreateOrUpdateResponse](), nil
		},
	}
	got, err := newTestGalleryApp(fake).Create(context.Background(), &resource.CreateRequest{
		Label: "app1", Properties: galleryAppDesired("node agent"),
	})
	require.NoError(t, err)
	require.Equal(t, resource.OperationStatusInProgress, got.ProgressResult.OperationStatus)
	require.Equal(t, testGalleryAppNativeID, got.ProgressResult.NativeID)
}

func TestComputeGalleryApplication_ReadNotFound(t *testing.T) {
	fake := &fakeGalleryAppsAPI{
		getFn: func(_ context.Context, _, _, _ string, _ *armcompute.GalleryApplicationsClientGetOptions) (armcompute.GalleryApplicationsClientGetResponse, error) {
			return armcompute.GalleryApplicationsClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestGalleryApp(fake).Read(context.Background(), &resource.ReadRequest{NativeID: testGalleryAppNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeGalleryAppsAPI struct {
	beginCreateOrUpdateFn   func(ctx context.Context, rgName, galleryName, name string, app armcompute.GalleryApplication, options *armcompute.GalleryApplicationsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armcompute.GalleryApplicationsClientCreateOrUpdateResponse], error)
	getFn                   func(ctx context.Context, rgName, galleryName, name string, options *armcompute.GalleryApplicationsClientGetOptions) (armcompute.GalleryApplicationsClientGetResponse, error)
	beginUpdateFn           func(ctx context.Context, rgName, galleryName, name string, app armcompute.GalleryApplicationUpdate, options *armcompute.GalleryApplicationsClientBeginUpdateOptions) (*runtime.Poller[armcompute.GalleryApplicationsClientUpdateResponse], error)
	beginDeleteFn           func(ctx context.Context, rgName, galleryName, name string, options *armcompute.GalleryApplicationsClientBeginDeleteOptions) (*runtime.Poller[armcompute.GalleryApplicationsClientDeleteResponse], error)
	newListByGalleryPagerFn func(rgName, galleryName string, options *armcompute.GalleryApplicationsClientListByGalleryOptions) *runtime.Pager[armcompute.GalleryApplicationsClientListByGalleryResponse]
}

func (f *fakeGalleryAppsAPI) BeginCreateOrUpdate(ctx context.Context, rgName, galleryName, name string, app armcompute.GalleryApplication, options *armcompute.GalleryApplicationsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armcompute.GalleryApplicationsClientCreateOrUpdateResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, rgName, galleryName, name, app, options)
}

func (f *fakeGalleryAppsAPI) Get(ctx context.Context, rgName, galleryName, name string, options *armcompute.GalleryApplicationsClientGetOptions) (armcompute.GalleryApplicationsClientGetResponse, error) {
	return f.getFn(ctx, rgName, galleryName, name, options)
}

func (f *fakeGalleryAppsAPI) BeginUpdate(ctx context.Context, rgName, galleryName, name string, app armcompute.GalleryApplicationUpdate, options *armcompute.GalleryApplicationsClientBeginUpdateOptions) (*runtime.Poller[armcompute.GalleryApplicationsClientUpdateResponse], error) {
	return f.beginUpdateFn(ctx, rgName, galleryName, name, app, options)
}

func (f *fakeGalleryAppsAPI) BeginDelete(ctx context.Context, rgName, galleryName, name string, options *armcompute.GalleryApplicationsClientBeginDeleteOptions) (*runtime.Poller[armcompute.GalleryApplicationsClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, galleryName, name, options)
}

func (f *fakeGalleryAppsAPI) NewListByGalleryPager(rgName, galleryName string, options *armcompute.GalleryApplicationsClientListByGalleryOptions) *runtime.Pager[armcompute.GalleryApplicationsClientListByGalleryResponse] {
	return f.newListByGalleryPagerFn(rgName, galleryName, options)
}
