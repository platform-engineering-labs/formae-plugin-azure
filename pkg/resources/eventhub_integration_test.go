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

const testEventHubNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.EventHub/namespaces/ns-1/eventhubs/hub-1"

func TestEventHub_CRUD(t *testing.T) {
	model := armeventhub.Eventhub{
		ID:   to.Ptr(testEventHubNativeID),
		Name: to.Ptr("hub-1"),
		Properties: &armeventhub.Properties{
			PartitionCount:         to.Ptr(int64(2)),
			MessageRetentionInDays: to.Ptr(int64(1)),
			Status:                 to.Ptr(armeventhub.EntityStatusActive),
			UserMetadata:           to.Ptr("conformance"),
		},
	}
	fake := &fakeEventHubsAPI{
		createOrUpdateFn: func(_ context.Context, _, _, _ string, _ armeventhub.Eventhub, _ *armeventhub.EventHubsClientCreateOrUpdateOptions) (armeventhub.EventHubsClientCreateOrUpdateResponse, error) {
			return armeventhub.EventHubsClientCreateOrUpdateResponse{Eventhub: model}, nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ *armeventhub.EventHubsClientGetOptions) (armeventhub.EventHubsClientGetResponse, error) {
			return armeventhub.EventHubsClientGetResponse{Eventhub: model}, nil
		},
		deleteFn: func(_ context.Context, _, _, _ string, _ *armeventhub.EventHubsClientDeleteOptions) (armeventhub.EventHubsClientDeleteResponse, error) {
			return armeventhub.EventHubsClientDeleteResponse{}, nil
		},
		newListByNamespacePagerFn: func(_, _ string, _ *armeventhub.EventHubsClientListByNamespaceOptions) *runtime.Pager[armeventhub.EventHubsClientListByNamespaceResponse] {
			return runtime.NewPager(runtime.PagingHandler[armeventhub.EventHubsClientListByNamespaceResponse]{
				More: func(_ armeventhub.EventHubsClientListByNamespaceResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armeventhub.EventHubsClientListByNamespaceResponse) (armeventhub.EventHubsClientListByNamespaceResponse, error) {
					return armeventhub.EventHubsClientListByNamespaceResponse{
						ListResult: armeventhub.ListResult{
							Value: []*armeventhub.Eventhub{{ID: to.Ptr(testEventHubNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestEventHub(fake)

	mkProps := func() json.RawMessage {
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName":      "rg-1",
			"namespaceName":          "ns-1",
			"name":                   "hub-1",
			"partitionCount":         2,
			"messageRetentionInDays": 1,
			"status":                 "Active",
			"userMetadata":           "conformance",
		})
		return props
	}

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testEventHubNativeID, got.ProgressResult.NativeID)

		var serialized map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &serialized))
		require.Equal(t, "hub-1", serialized["name"])
		require.Equal(t, "ns-1", serialized["namespaceName"])
		require.Equal(t, "rg-1", serialized["resourceGroupName"])
		require.Equal(t, float64(2), serialized["partitionCount"])
		require.Equal(t, float64(1), serialized["messageRetentionInDays"])
		require.Equal(t, "Active", serialized["status"])
		require.Equal(t, "conformance", serialized["userMetadata"])
	})

	t.Run("Create_forwards_params_to_ARM", func(t *testing.T) {
		var seen armeventhub.Eventhub
		var seenRG, seenNS, seenHub string
		fake.createOrUpdateFn = func(_ context.Context, rg, ns, hub string, params armeventhub.Eventhub, _ *armeventhub.EventHubsClientCreateOrUpdateOptions) (armeventhub.EventHubsClientCreateOrUpdateResponse, error) {
			seen, seenRG, seenNS, seenHub = params, rg, ns, hub
			return armeventhub.EventHubsClientCreateOrUpdateResponse{Eventhub: model}, nil
		}
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, "rg-1", seenRG)
		require.Equal(t, "ns-1", seenNS)
		require.Equal(t, "hub-1", seenHub)
		require.Equal(t, int64(2), *seen.Properties.PartitionCount)
		require.Equal(t, int64(1), *seen.Properties.MessageRetentionInDays)
		require.Equal(t, armeventhub.EntityStatusActive, *seen.Properties.Status)

		fake.createOrUpdateFn = func(_ context.Context, _, _, _ string, _ armeventhub.Eventhub, _ *armeventhub.EventHubsClientCreateOrUpdateOptions) (armeventhub.EventHubsClientCreateOrUpdateResponse, error) {
			return armeventhub.EventHubsClientCreateOrUpdateResponse{Eventhub: model}, nil
		}
	})

	t.Run("Create_forwards_retentionDescription", func(t *testing.T) {
		var seen armeventhub.Eventhub
		fake.createOrUpdateFn = func(_ context.Context, _, _, _ string, params armeventhub.Eventhub, _ *armeventhub.EventHubsClientCreateOrUpdateOptions) (armeventhub.EventHubsClientCreateOrUpdateResponse, error) {
			seen = params
			return armeventhub.EventHubsClientCreateOrUpdateResponse{Eventhub: model}, nil
		}
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName": "rg-1",
			"namespaceName":     "ns-1",
			"name":              "hub-1",
			"partitionCount":    2,
			"retentionDescription": map[string]any{
				"cleanupPolicy":        "Delete",
				"retentionTimeInHours": 24,
			},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.NotNil(t, seen.Properties.RetentionDescription)
		require.Equal(t, armeventhub.CleanupPolicyRetentionDescriptionDelete, *seen.Properties.RetentionDescription.CleanupPolicy)
		require.Equal(t, int64(24), *seen.Properties.RetentionDescription.RetentionTimeInHours)

		fake.createOrUpdateFn = func(_ context.Context, _, _, _ string, _ armeventhub.Eventhub, _ *armeventhub.EventHubsClientCreateOrUpdateOptions) (armeventhub.EventHubsClientCreateOrUpdateResponse, error) {
			return armeventhub.EventHubsClientCreateOrUpdateResponse{Eventhub: model}, nil
		}
	})

	t.Run("Create_requires_namespaceName", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"resourceGroupName": "rg-1", "name": "hub-1"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "namespaceName is required")
	})

	t.Run("Create_requires_resourceGroupName", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"namespaceName": "ns-1", "name": "hub-1"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "resourceGroupName is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testEventHubNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
		require.Equal(t, ResourceTypeEventHub, got.ResourceType)
	})

	t.Run("Read_not_found", func(t *testing.T) {
		fake.getFn = func(_ context.Context, _, _, _ string, _ *armeventhub.EventHubsClientGetOptions) (armeventhub.EventHubsClientGetResponse, error) {
			return armeventhub.EventHubsClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testEventHubNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)

		fake.getFn = func(_ context.Context, _, _, _ string, _ *armeventhub.EventHubsClientGetOptions) (armeventhub.EventHubsClientGetResponse, error) {
			return armeventhub.EventHubsClientGetResponse{Eventhub: model}, nil
		}
	})

	// Update derives rg/namespace/hub from the native ID rather than the payload.
	t.Run("Update_derives_names_from_native_id", func(t *testing.T) {
		var seenRG, seenNS, seenHub string
		fake.createOrUpdateFn = func(_ context.Context, rg, ns, hub string, _ armeventhub.Eventhub, _ *armeventhub.EventHubsClientCreateOrUpdateOptions) (armeventhub.EventHubsClientCreateOrUpdateResponse, error) {
			seenRG, seenNS, seenHub = rg, ns, hub
			return armeventhub.EventHubsClientCreateOrUpdateResponse{Eventhub: model}, nil
		}
		desired, _ := json.Marshal(map[string]any{"messageRetentionInDays": 3, "partitionCount": 2})
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testEventHubNativeID,
			DesiredProperties: desired,
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, "rg-1", seenRG)
		require.Equal(t, "ns-1", seenNS)
		require.Equal(t, "hub-1", seenHub)
	})

	t.Run("Delete", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testEventHubNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _, _ string, _ *armeventhub.EventHubsClientDeleteOptions) (armeventhub.EventHubsClientDeleteResponse, error) {
			return armeventhub.EventHubsClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testEventHubNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Status_is_sync_success", func(t *testing.T) {
		got, err := prov.Status(context.Background(), &resource.StatusRequest{RequestID: "anything"})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_namespace", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "namespaceName": "ns-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testEventHubNativeID}, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.createOrUpdateFn = func(_ context.Context, _, _, _ string, _ armeventhub.Eventhub, _ *armeventhub.EventHubsClientCreateOrUpdateOptions) (armeventhub.EventHubsClientCreateOrUpdateResponse, error) {
			return armeventhub.EventHubsClientCreateOrUpdateResponse{}, &azcore.ResponseError{StatusCode: 403}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

func TestEventHubIDParts(t *testing.T) {
	rg, ns, hub, err := eventHubIDParts(testEventHubNativeID)
	require.NoError(t, err)
	require.Equal(t, "rg-1", rg)
	require.Equal(t, "ns-1", ns)
	require.Equal(t, "hub-1", hub)

	_, _, _, err = eventHubIDParts("/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.EventHub/namespaces/ns-1")
	require.Error(t, err)
}

// --- Test helpers ---

func newTestEventHub(api eventHubsAPI) *EventHub {
	return &EventHub{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

type fakeEventHubsAPI struct {
	createOrUpdateFn          func(ctx context.Context, rgName, nsName, hubName string, params armeventhub.Eventhub, opts *armeventhub.EventHubsClientCreateOrUpdateOptions) (armeventhub.EventHubsClientCreateOrUpdateResponse, error)
	getFn                     func(ctx context.Context, rgName, nsName, hubName string, opts *armeventhub.EventHubsClientGetOptions) (armeventhub.EventHubsClientGetResponse, error)
	deleteFn                  func(ctx context.Context, rgName, nsName, hubName string, opts *armeventhub.EventHubsClientDeleteOptions) (armeventhub.EventHubsClientDeleteResponse, error)
	newListByNamespacePagerFn func(rgName, nsName string, opts *armeventhub.EventHubsClientListByNamespaceOptions) *runtime.Pager[armeventhub.EventHubsClientListByNamespaceResponse]
}

func (f *fakeEventHubsAPI) CreateOrUpdate(ctx context.Context, rgName, nsName, hubName string, params armeventhub.Eventhub, opts *armeventhub.EventHubsClientCreateOrUpdateOptions) (armeventhub.EventHubsClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, nsName, hubName, params, opts)
}

func (f *fakeEventHubsAPI) Get(ctx context.Context, rgName, nsName, hubName string, opts *armeventhub.EventHubsClientGetOptions) (armeventhub.EventHubsClientGetResponse, error) {
	return f.getFn(ctx, rgName, nsName, hubName, opts)
}

func (f *fakeEventHubsAPI) Delete(ctx context.Context, rgName, nsName, hubName string, opts *armeventhub.EventHubsClientDeleteOptions) (armeventhub.EventHubsClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, nsName, hubName, opts)
}

func (f *fakeEventHubsAPI) NewListByNamespacePager(rgName, nsName string, opts *armeventhub.EventHubsClientListByNamespaceOptions) *runtime.Pager[armeventhub.EventHubsClientListByNamespaceResponse] {
	return f.newListByNamespacePagerFn(rgName, nsName, opts)
}
