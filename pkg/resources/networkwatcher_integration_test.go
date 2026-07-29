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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v4"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testNetworkWatcherNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/networkWatchers/nw-1"

func TestNetworkWatcher_CRUD(t *testing.T) {
	model := armnetwork.Watcher{
		ID:       to.Ptr(testNetworkWatcherNativeID),
		Name:     to.Ptr("nw-1"),
		Location: to.Ptr("canadacentral"),
		Etag:     to.Ptr("W/\"etag-1\""),
		Properties: &armnetwork.WatcherPropertiesFormat{
			ProvisioningState: to.Ptr(armnetwork.ProvisioningStateSucceeded),
		},
		Tags: map[string]*string{"Environment": to.Ptr("test")},
	}
	fake := &fakeNetworkWatchersAPI{
		createOrUpdateFn: func(_ context.Context, _, _ string, _ armnetwork.Watcher, _ *armnetwork.WatchersClientCreateOrUpdateOptions) (armnetwork.WatchersClientCreateOrUpdateResponse, error) {
			return armnetwork.WatchersClientCreateOrUpdateResponse{Watcher: model}, nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armnetwork.WatchersClientGetOptions) (armnetwork.WatchersClientGetResponse, error) {
			return armnetwork.WatchersClientGetResponse{Watcher: model}, nil
		},
		updateTagsFn: func(_ context.Context, _, _ string, _ armnetwork.TagsObject, _ *armnetwork.WatchersClientUpdateTagsOptions) (armnetwork.WatchersClientUpdateTagsResponse, error) {
			return armnetwork.WatchersClientUpdateTagsResponse{Watcher: model}, nil
		},
		beginDeleteFn: func(_ context.Context, _, _ string, _ *armnetwork.WatchersClientBeginDeleteOptions) (*runtime.Poller[armnetwork.WatchersClientDeleteResponse], error) {
			return newInProgressPoller[armnetwork.WatchersClientDeleteResponse](), nil
		},
		newListPagerFn: func(_ string, _ *armnetwork.WatchersClientListOptions) *runtime.Pager[armnetwork.WatchersClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armnetwork.WatchersClientListResponse]{
				More: func(_ armnetwork.WatchersClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armnetwork.WatchersClientListResponse) (armnetwork.WatchersClientListResponse, error) {
					return armnetwork.WatchersClientListResponse{
						WatcherListResult: armnetwork.WatcherListResult{
							Value: []*armnetwork.Watcher{{ID: to.Ptr(testNetworkWatcherNativeID)}},
						},
					}, nil
				},
			})
		},
		newListAllPagerFn: func(_ *armnetwork.WatchersClientListAllOptions) *runtime.Pager[armnetwork.WatchersClientListAllResponse] {
			return runtime.NewPager(runtime.PagingHandler[armnetwork.WatchersClientListAllResponse]{
				More: func(_ armnetwork.WatchersClientListAllResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armnetwork.WatchersClientListAllResponse) (armnetwork.WatchersClientListAllResponse, error) {
					return armnetwork.WatchersClientListAllResponse{
						WatcherListResult: armnetwork.WatcherListResult{
							Value: []*armnetwork.Watcher{{ID: to.Ptr(testNetworkWatcherNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestNetworkWatcher(fake)

	mkProps := func() json.RawMessage {
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName": "rg-1",
			"name":              "nw-1",
			"location":          "canadacentral",
			"Tags":              []map[string]string{{"Key": "Environment", "Value": "test"}},
		})
		return props
	}

	// CreateOrUpdate is synchronous, so Create finishes in one call and never hands
	// back a RequestID.
	t.Run("Create_is_synchronous", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testNetworkWatcherNativeID, got.ProgressResult.NativeID)
		require.Empty(t, got.ProgressResult.RequestID)

		var serialized map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &serialized))
		require.Equal(t, "nw-1", serialized["name"])
		require.Equal(t, "canadacentral", serialized["location"])
	})

	// etag and provisioningState are read-only with no schema field.
	t.Run("Serialize_omits_unmodelled_readonly_fields", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testNetworkWatcherNativeID})
		require.NoError(t, err)
		var serialized map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &serialized))
		require.NotContains(t, serialized, "etag")
		require.NotContains(t, serialized, "provisioningState")
	})

	t.Run("Create_forwards_params_to_ARM", func(t *testing.T) {
		var seen armnetwork.Watcher
		var seenRG, seenName string
		fake.createOrUpdateFn = func(_ context.Context, rg, name string, params armnetwork.Watcher, _ *armnetwork.WatchersClientCreateOrUpdateOptions) (armnetwork.WatchersClientCreateOrUpdateResponse, error) {
			seen, seenRG, seenName = params, rg, name
			return armnetwork.WatchersClientCreateOrUpdateResponse{Watcher: model}, nil
		}
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, "rg-1", seenRG)
		require.Equal(t, "nw-1", seenName)
		require.Equal(t, "canadacentral", *seen.Location)
		require.Equal(t, "test", *seen.Tags["Environment"])

		fake.createOrUpdateFn = func(_ context.Context, _, _ string, _ armnetwork.Watcher, _ *armnetwork.WatchersClientCreateOrUpdateOptions) (armnetwork.WatchersClientCreateOrUpdateResponse, error) {
			return armnetwork.WatchersClientCreateOrUpdateResponse{Watcher: model}, nil
		}
	})

	t.Run("Create_requires_location", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"resourceGroupName": "rg-1", "name": "nw-1"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "location is required")
	})

	t.Run("Create_requires_resourceGroupName", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "nw-1", "location": "canadacentral"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "resourceGroupName is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testNetworkWatcherNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
		require.Equal(t, ResourceTypeNetworkWatcher, got.ResourceType)
	})

	t.Run("Read_not_found", func(t *testing.T) {
		fake.getFn = func(_ context.Context, _, _ string, _ *armnetwork.WatchersClientGetOptions) (armnetwork.WatchersClientGetResponse, error) {
			return armnetwork.WatchersClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testNetworkWatcherNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)

		fake.getFn = func(_ context.Context, _, _ string, _ *armnetwork.WatchersClientGetOptions) (armnetwork.WatchersClientGetResponse, error) {
			return armnetwork.WatchersClientGetResponse{Watcher: model}, nil
		}
	})

	// Location is immutable and nothing else is writable, so Update is UpdateTags —
	// also synchronous.
	t.Run("Update_is_tags_only_and_synchronous", func(t *testing.T) {
		var seen armnetwork.TagsObject
		var seenRG, seenName string
		fake.updateTagsFn = func(_ context.Context, rg, name string, params armnetwork.TagsObject, _ *armnetwork.WatchersClientUpdateTagsOptions) (armnetwork.WatchersClientUpdateTagsResponse, error) {
			seen, seenRG, seenName = params, rg, name
			return armnetwork.WatchersClientUpdateTagsResponse{Watcher: model}, nil
		}
		desired, _ := json.Marshal(map[string]any{
			// Wrong parents in the payload — the native ID must win.
			"resourceGroupName": "wrong-rg",
			"name":              "wrong-name",
			"location":          "canadacentral",
			"Tags":              []map[string]string{{"Key": "Environment", "Value": "updated"}},
		})
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testNetworkWatcherNativeID,
			DesiredProperties: desired,
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Empty(t, got.ProgressResult.RequestID)
		require.Equal(t, "rg-1", seenRG)
		require.Equal(t, "nw-1", seenName)
		require.Equal(t, "updated", *seen.Tags["Environment"])
	})

	// Delete is the only LRO verb on this client.
	t.Run("Delete_in_progress_returns_lro_request_id", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testNetworkWatcherNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusInProgress, got.ProgressResult.OperationStatus)
		reqID, err := decodeLROStatus(got.ProgressResult.RequestID)
		require.NoError(t, err)
		require.Equal(t, lroOpDelete, reqID.OperationType)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _ string, _ *armnetwork.WatchersClientBeginDeleteOptions) (*runtime.Poller[armnetwork.WatchersClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testNetworkWatcherNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	// Only delete is async here, so a create/update RequestID is not a thing Status
	// should accept.
	t.Run("Status_rejects_non_delete_operations", func(t *testing.T) {
		reqID, err := encodeLROStart(lroOpCreate, "token", testNetworkWatcherNativeID)
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
		require.Equal(t, []string{testNetworkWatcherNativeID}, got.NativeIDs)
	})

	t.Run("List_all", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Equal(t, []string{testNetworkWatcherNativeID}, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.createOrUpdateFn = func(_ context.Context, _, _ string, _ armnetwork.Watcher, _ *armnetwork.WatchersClientCreateOrUpdateOptions) (armnetwork.WatchersClientCreateOrUpdateResponse, error) {
			return armnetwork.WatchersClientCreateOrUpdateResponse{}, &azcore.ResponseError{StatusCode: 409}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

func TestNetworkWatcherIDParts(t *testing.T) {
	rg, name, err := networkWatcherIDParts(testNetworkWatcherNativeID)
	require.NoError(t, err)
	require.Equal(t, "rg-1", rg)
	require.Equal(t, "nw-1", name)

	// A flow log nests under a watcher, so the exact chain check rejects it here.
	_, _, err = networkWatcherIDParts(testNetworkWatcherNativeID + "/flowLogs/fl-1")
	require.Error(t, err)
}

// --- Test helpers ---

func newTestNetworkWatcher(api networkWatchersAPI) *NetworkWatcher {
	return &NetworkWatcher{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

type fakeNetworkWatchersAPI struct {
	createOrUpdateFn  func(ctx context.Context, rgName, name string, params armnetwork.Watcher, opts *armnetwork.WatchersClientCreateOrUpdateOptions) (armnetwork.WatchersClientCreateOrUpdateResponse, error)
	getFn             func(ctx context.Context, rgName, name string, opts *armnetwork.WatchersClientGetOptions) (armnetwork.WatchersClientGetResponse, error)
	updateTagsFn      func(ctx context.Context, rgName, name string, params armnetwork.TagsObject, opts *armnetwork.WatchersClientUpdateTagsOptions) (armnetwork.WatchersClientUpdateTagsResponse, error)
	beginDeleteFn     func(ctx context.Context, rgName, name string, opts *armnetwork.WatchersClientBeginDeleteOptions) (*runtime.Poller[armnetwork.WatchersClientDeleteResponse], error)
	newListPagerFn    func(rgName string, opts *armnetwork.WatchersClientListOptions) *runtime.Pager[armnetwork.WatchersClientListResponse]
	newListAllPagerFn func(opts *armnetwork.WatchersClientListAllOptions) *runtime.Pager[armnetwork.WatchersClientListAllResponse]
}

func (f *fakeNetworkWatchersAPI) CreateOrUpdate(ctx context.Context, rgName, name string, params armnetwork.Watcher, opts *armnetwork.WatchersClientCreateOrUpdateOptions) (armnetwork.WatchersClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, name, params, opts)
}

func (f *fakeNetworkWatchersAPI) Get(ctx context.Context, rgName, name string, opts *armnetwork.WatchersClientGetOptions) (armnetwork.WatchersClientGetResponse, error) {
	return f.getFn(ctx, rgName, name, opts)
}

func (f *fakeNetworkWatchersAPI) UpdateTags(ctx context.Context, rgName, name string, params armnetwork.TagsObject, opts *armnetwork.WatchersClientUpdateTagsOptions) (armnetwork.WatchersClientUpdateTagsResponse, error) {
	return f.updateTagsFn(ctx, rgName, name, params, opts)
}

func (f *fakeNetworkWatchersAPI) BeginDelete(ctx context.Context, rgName, name string, opts *armnetwork.WatchersClientBeginDeleteOptions) (*runtime.Poller[armnetwork.WatchersClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, name, opts)
}

func (f *fakeNetworkWatchersAPI) NewListPager(rgName string, opts *armnetwork.WatchersClientListOptions) *runtime.Pager[armnetwork.WatchersClientListResponse] {
	return f.newListPagerFn(rgName, opts)
}

func (f *fakeNetworkWatchersAPI) NewListAllPager(opts *armnetwork.WatchersClientListAllOptions) *runtime.Pager[armnetwork.WatchersClientListAllResponse] {
	return f.newListAllPagerFn(opts)
}
