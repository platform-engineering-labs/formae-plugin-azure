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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/eventhub/armeventhub"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const (
	testConsumerGroupNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.EventHub/namespaces/ns-1/eventhubs/hub-1/consumergroups/cg-1"
	testDefaultCGNativeID     = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.EventHub/namespaces/ns-1/eventhubs/hub-1/consumergroups/$Default"
)

func TestEventHubConsumerGroup_CRUD(t *testing.T) {
	model := armeventhub.ConsumerGroup{
		ID:   to.Ptr(testConsumerGroupNativeID),
		Name: to.Ptr("cg-1"),
		Properties: &armeventhub.ConsumerGroupProperties{
			UserMetadata: to.Ptr("conformance"),
		},
	}
	fake := &fakeEventHubConsumerGroupsAPI{
		createOrUpdateFn: func(_ context.Context, _, _, _, _ string, _ armeventhub.ConsumerGroup, _ *armeventhub.ConsumerGroupsClientCreateOrUpdateOptions) (armeventhub.ConsumerGroupsClientCreateOrUpdateResponse, error) {
			return armeventhub.ConsumerGroupsClientCreateOrUpdateResponse{ConsumerGroup: model}, nil
		},
		getFn: func(_ context.Context, _, _, _, _ string, _ *armeventhub.ConsumerGroupsClientGetOptions) (armeventhub.ConsumerGroupsClientGetResponse, error) {
			return armeventhub.ConsumerGroupsClientGetResponse{ConsumerGroup: model}, nil
		},
		deleteFn: func(_ context.Context, _, _, _, _ string, _ *armeventhub.ConsumerGroupsClientDeleteOptions) (armeventhub.ConsumerGroupsClientDeleteResponse, error) {
			return armeventhub.ConsumerGroupsClientDeleteResponse{}, nil
		},
		newListByEventHubPagerFn: func(_, _, _ string, _ *armeventhub.ConsumerGroupsClientListByEventHubOptions) *runtime.Pager[armeventhub.ConsumerGroupsClientListByEventHubResponse] {
			return runtime.NewPager(runtime.PagingHandler[armeventhub.ConsumerGroupsClientListByEventHubResponse]{
				More: func(_ armeventhub.ConsumerGroupsClientListByEventHubResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armeventhub.ConsumerGroupsClientListByEventHubResponse) (armeventhub.ConsumerGroupsClientListByEventHubResponse, error) {
					return armeventhub.ConsumerGroupsClientListByEventHubResponse{
						ConsumerGroupListResult: armeventhub.ConsumerGroupListResult{
							Value: []*armeventhub.ConsumerGroup{
								{ID: to.Ptr(testDefaultCGNativeID), Name: to.Ptr("$Default")},
								{ID: to.Ptr(testConsumerGroupNativeID), Name: to.Ptr("cg-1")},
							},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestEventHubConsumerGroup(fake)

	mkProps := func() json.RawMessage {
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName": "rg-1",
			"namespaceName":     "ns-1",
			"eventHubName":      "hub-1",
			"name":              "cg-1",
			"userMetadata":      "conformance",
		})
		return props
	}

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testConsumerGroupNativeID, got.ProgressResult.NativeID)

		var serialized map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &serialized))
		require.Equal(t, "cg-1", serialized["name"])
		require.Equal(t, "hub-1", serialized["eventHubName"])
		require.Equal(t, "ns-1", serialized["namespaceName"])
		require.Equal(t, "rg-1", serialized["resourceGroupName"])
		require.Equal(t, "conformance", serialized["userMetadata"])
	})

	t.Run("Create_forwards_params_to_ARM", func(t *testing.T) {
		var seen armeventhub.ConsumerGroup
		var seenRG, seenNS, seenHub, seenCG string
		fake.createOrUpdateFn = func(_ context.Context, rg, ns, hub, cg string, params armeventhub.ConsumerGroup, _ *armeventhub.ConsumerGroupsClientCreateOrUpdateOptions) (armeventhub.ConsumerGroupsClientCreateOrUpdateResponse, error) {
			seen, seenRG, seenNS, seenHub, seenCG = params, rg, ns, hub, cg
			return armeventhub.ConsumerGroupsClientCreateOrUpdateResponse{ConsumerGroup: model}, nil
		}
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, "rg-1", seenRG)
		require.Equal(t, "ns-1", seenNS)
		require.Equal(t, "hub-1", seenHub)
		require.Equal(t, "cg-1", seenCG)
		require.Equal(t, "conformance", *seen.Properties.UserMetadata)

		fake.createOrUpdateFn = func(_ context.Context, _, _, _, _ string, _ armeventhub.ConsumerGroup, _ *armeventhub.ConsumerGroupsClientCreateOrUpdateOptions) (armeventhub.ConsumerGroupsClientCreateOrUpdateResponse, error) {
			return armeventhub.ConsumerGroupsClientCreateOrUpdateResponse{ConsumerGroup: model}, nil
		}
	})

	t.Run("Create_requires_eventHubName", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"resourceGroupName": "rg-1", "namespaceName": "ns-1", "name": "cg-1"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "eventHubName is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testConsumerGroupNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
		require.Equal(t, ResourceTypeEventHubConsumerGroup, got.ResourceType)
	})

	t.Run("Read_not_found", func(t *testing.T) {
		fake.getFn = func(_ context.Context, _, _, _, _ string, _ *armeventhub.ConsumerGroupsClientGetOptions) (armeventhub.ConsumerGroupsClientGetResponse, error) {
			return armeventhub.ConsumerGroupsClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testConsumerGroupNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)

		fake.getFn = func(_ context.Context, _, _, _, _ string, _ *armeventhub.ConsumerGroupsClientGetOptions) (armeventhub.ConsumerGroupsClientGetResponse, error) {
			return armeventhub.ConsumerGroupsClientGetResponse{ConsumerGroup: model}, nil
		}
	})

	t.Run("Update_derives_names_from_native_id", func(t *testing.T) {
		var seenRG, seenNS, seenHub, seenCG string
		var seen armeventhub.ConsumerGroup
		fake.createOrUpdateFn = func(_ context.Context, rg, ns, hub, cg string, params armeventhub.ConsumerGroup, _ *armeventhub.ConsumerGroupsClientCreateOrUpdateOptions) (armeventhub.ConsumerGroupsClientCreateOrUpdateResponse, error) {
			seen, seenRG, seenNS, seenHub, seenCG = params, rg, ns, hub, cg
			return armeventhub.ConsumerGroupsClientCreateOrUpdateResponse{ConsumerGroup: model}, nil
		}
		desired, _ := json.Marshal(map[string]any{"userMetadata": "updated"})
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testConsumerGroupNativeID,
			DesiredProperties: desired,
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, "rg-1", seenRG)
		require.Equal(t, "ns-1", seenNS)
		require.Equal(t, "hub-1", seenHub)
		require.Equal(t, "cg-1", seenCG)
		require.Equal(t, "updated", *seen.Properties.UserMetadata)
	})

	t.Run("Delete", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testConsumerGroupNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _, _, _ string, _ *armeventhub.ConsumerGroupsClientDeleteOptions) (armeventhub.ConsumerGroupsClientDeleteResponse, error) {
			return armeventhub.ConsumerGroupsClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testConsumerGroupNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Status_is_sync_success", func(t *testing.T) {
		got, err := prov.Status(context.Background(), &resource.StatusRequest{RequestID: "anything"})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	// $Default is created by Azure and cannot be deleted, so discovery must not
	// surface it as a manageable resource.
	t.Run("List_filters_default_consumer_group", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{
				"resourceGroupName": "rg-1", "namespaceName": "ns-1", "eventHubName": "hub-1",
			},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testConsumerGroupNativeID}, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.createOrUpdateFn = func(_ context.Context, _, _, _, _ string, _ armeventhub.ConsumerGroup, _ *armeventhub.ConsumerGroupsClientCreateOrUpdateOptions) (armeventhub.ConsumerGroupsClientCreateOrUpdateResponse, error) {
			return armeventhub.ConsumerGroupsClientCreateOrUpdateResponse{}, &azcore.ResponseError{StatusCode: 403}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

func TestEventHubConsumerGroupIDParts(t *testing.T) {
	rg, ns, hub, cg, err := eventHubConsumerGroupIDParts(testConsumerGroupNativeID)
	require.NoError(t, err)
	require.Equal(t, "rg-1", rg)
	require.Equal(t, "ns-1", ns)
	require.Equal(t, "hub-1", hub)
	require.Equal(t, "cg-1", cg)

	_, _, _, _, err = eventHubConsumerGroupIDParts(testEventHubNativeID)
	require.Error(t, err)
}

// --- Test helpers ---

func newTestEventHubConsumerGroup(api eventHubConsumerGroupsAPI) *EventHubConsumerGroup {
	return &EventHubConsumerGroup{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

type fakeEventHubConsumerGroupsAPI struct {
	createOrUpdateFn         func(ctx context.Context, rgName, nsName, hubName, cgName string, params armeventhub.ConsumerGroup, opts *armeventhub.ConsumerGroupsClientCreateOrUpdateOptions) (armeventhub.ConsumerGroupsClientCreateOrUpdateResponse, error)
	getFn                    func(ctx context.Context, rgName, nsName, hubName, cgName string, opts *armeventhub.ConsumerGroupsClientGetOptions) (armeventhub.ConsumerGroupsClientGetResponse, error)
	deleteFn                 func(ctx context.Context, rgName, nsName, hubName, cgName string, opts *armeventhub.ConsumerGroupsClientDeleteOptions) (armeventhub.ConsumerGroupsClientDeleteResponse, error)
	newListByEventHubPagerFn func(rgName, nsName, hubName string, opts *armeventhub.ConsumerGroupsClientListByEventHubOptions) *runtime.Pager[armeventhub.ConsumerGroupsClientListByEventHubResponse]
}

func (f *fakeEventHubConsumerGroupsAPI) CreateOrUpdate(ctx context.Context, rgName, nsName, hubName, cgName string, params armeventhub.ConsumerGroup, opts *armeventhub.ConsumerGroupsClientCreateOrUpdateOptions) (armeventhub.ConsumerGroupsClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, nsName, hubName, cgName, params, opts)
}

func (f *fakeEventHubConsumerGroupsAPI) Get(ctx context.Context, rgName, nsName, hubName, cgName string, opts *armeventhub.ConsumerGroupsClientGetOptions) (armeventhub.ConsumerGroupsClientGetResponse, error) {
	return f.getFn(ctx, rgName, nsName, hubName, cgName, opts)
}

func (f *fakeEventHubConsumerGroupsAPI) Delete(ctx context.Context, rgName, nsName, hubName, cgName string, opts *armeventhub.ConsumerGroupsClientDeleteOptions) (armeventhub.ConsumerGroupsClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, nsName, hubName, cgName, opts)
}

func (f *fakeEventHubConsumerGroupsAPI) NewListByEventHubPager(rgName, nsName, hubName string, opts *armeventhub.ConsumerGroupsClientListByEventHubOptions) *runtime.Pager[armeventhub.ConsumerGroupsClientListByEventHubResponse] {
	return f.newListByEventHubPagerFn(rgName, nsName, hubName, opts)
}
