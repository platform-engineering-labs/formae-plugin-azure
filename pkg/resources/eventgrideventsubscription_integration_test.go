// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/eventgrid/armeventgrid"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const (
	testEventSubScope    = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.EventGrid/topics/topic-1"
	testEventSubNativeID = testEventSubScope + "/providers/Microsoft.EventGrid/eventSubscriptions/sub-1-name"
	testEventSubSAID     = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Storage/storageAccounts/sa1"
)

func newTestEventSubscription(api eventGridEventSubscriptionsAPI) *EventGridEventSubscription {
	return &EventGridEventSubscription{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func eventSubDesired(subjectPrefix string) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":  "sub-1-name",
		"scope": testEventSubScope,
		"storageQueueDestination": map[string]any{
			"storageAccountId": testEventSubSAID,
			"queueName":        "events",
		},
		"filter": map[string]any{
			"subjectBeginsWith":  subjectPrefix,
			"includedEventTypes": []any{"Microsoft.Storage.BlobCreated"},
		},
		"eventDeliverySchema": "EventGridSchema",
	})
	return out
}

func TestEventGridEventSubscription_CRUD(t *testing.T) {
	var sent armeventgrid.EventSubscription
	var sawScope string
	echo := func(params armeventgrid.EventSubscription) armeventgrid.EventSubscription {
		params.ID = to.Ptr(testEventSubNativeID)
		params.Name = to.Ptr("sub-1-name")
		return params
	}

	createCalls := 0
	deleteCalls := 0
	fake := &fakeEventSubscriptionsAPI{
		beginCreateOrUpdateFn: func(_ context.Context, scope, name string, params armeventgrid.EventSubscription, _ *armeventgrid.EventSubscriptionsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armeventgrid.EventSubscriptionsClientCreateOrUpdateResponse], error) {
			require.Equal(t, "sub-1-name", name)
			sawScope = scope
			sent = params
			createCalls++
			return newDonePoller(armeventgrid.EventSubscriptionsClientCreateOrUpdateResponse{EventSubscription: echo(params)}), nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armeventgrid.EventSubscriptionsClientGetOptions) (armeventgrid.EventSubscriptionsClientGetResponse, error) {
			return armeventgrid.EventSubscriptionsClientGetResponse{EventSubscription: echo(sent)}, nil
		},
		beginDeleteFn: func(_ context.Context, _, _ string, _ *armeventgrid.EventSubscriptionsClientBeginDeleteOptions) (*runtime.Poller[armeventgrid.EventSubscriptionsClientDeleteResponse], error) {
			deleteCalls++
			return newDonePoller(armeventgrid.EventSubscriptionsClientDeleteResponse{}), nil
		},
		newListGlobalBySubscriptionPagerFn: func(_ *armeventgrid.EventSubscriptionsClientListGlobalBySubscriptionOptions) *runtime.Pager[armeventgrid.EventSubscriptionsClientListGlobalBySubscriptionResponse] {
			return runtime.NewPager(runtime.PagingHandler[armeventgrid.EventSubscriptionsClientListGlobalBySubscriptionResponse]{
				More: func(_ armeventgrid.EventSubscriptionsClientListGlobalBySubscriptionResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armeventgrid.EventSubscriptionsClientListGlobalBySubscriptionResponse) (armeventgrid.EventSubscriptionsClientListGlobalBySubscriptionResponse, error) {
					return armeventgrid.EventSubscriptionsClientListGlobalBySubscriptionResponse{
						EventSubscriptionsListResult: armeventgrid.EventSubscriptionsListResult{
							Value: []*armeventgrid.EventSubscription{{ID: to.Ptr(testEventSubNativeID)}},
						},
					}, nil
				},
			})
		},
		newListByResourcePagerFn: func(_, _, _, _ string, _ *armeventgrid.EventSubscriptionsClientListByResourceOptions) *runtime.Pager[armeventgrid.EventSubscriptionsClientListByResourceResponse] {
			return runtime.NewPager(runtime.PagingHandler[armeventgrid.EventSubscriptionsClientListByResourceResponse]{
				More: func(_ armeventgrid.EventSubscriptionsClientListByResourceResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armeventgrid.EventSubscriptionsClientListByResourceResponse) (armeventgrid.EventSubscriptionsClientListByResourceResponse, error) {
					return armeventgrid.EventSubscriptionsClientListByResourceResponse{
						EventSubscriptionsListResult: armeventgrid.EventSubscriptionsListResult{
							Value: []*armeventgrid.EventSubscription{{ID: to.Ptr(testEventSubNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestEventSubscription(fake)

	// An event subscription hangs off an arbitrary resource, so discovery cannot hand
	// down the four ARM path parts. Without the global fallback the type is never
	// discovered at all.
	t.Run("List_without_scope_falls_back_to_subscription_wide", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Equal(t, []string{testEventSubNativeID}, got.NativeIDs)
	})

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "sub-1-name", Properties: eventSubDesired("/blobServices/"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testEventSubNativeID, got.ProgressResult.NativeID)

		// Scope-based API: the scope is passed as-is, not decomposed.
		require.Equal(t, testEventSubScope, sawScope)

		// The destination must go out as the storage-queue union member, with the
		// discriminator ARM requires.
		queue, ok := sent.Properties.Destination.(*armeventgrid.StorageQueueEventSubscriptionDestination)
		require.True(t, ok)
		require.Equal(t, armeventgrid.EndpointTypeStorageQueue, *queue.EndpointType)
		require.Equal(t, testEventSubSAID, *queue.Properties.ResourceID)
		require.Equal(t, "events", *queue.Properties.QueueName)

		require.Equal(t, "/blobServices/", *sent.Properties.Filter.SubjectBeginsWith)
		require.Len(t, sent.Properties.Filter.IncludedEventTypes, 1)
	})

	t.Run("Create_requires_scope", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "sub-1-name",
			"storageQueueDestination": map[string]any{
				"storageAccountId": testEventSubSAID, "queueName": "events",
			},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "scope is required")
	})

	t.Run("Create_requires_queue_name", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "sub-1-name", "scope": testEventSubScope,
			"storageQueueDestination": map[string]any{"storageAccountId": testEventSubSAID},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "storageQueueDestination.queueName is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testEventSubNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "sub-1-name", props["name"])
		// The scope comes back out of the native ID, not the response body.
		require.Equal(t, testEventSubScope, props["scope"])

		dest := props["storageQueueDestination"].(map[string]any)
		require.Equal(t, testEventSubSAID, dest["storageAccountId"])
		require.Equal(t, "events", dest["queueName"])

		filter := props["filter"].(map[string]any)
		require.Equal(t, "/blobServices/", filter["subjectBeginsWith"])
	})

	t.Run("Update_reissues_create_or_update", func(t *testing.T) {
		before := createCalls
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testEventSubNativeID,
			DesiredProperties: eventSubDesired("/queueServices/"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, createCalls)
		require.Equal(t, "/queueServices/", *sent.Properties.Filter.SubjectBeginsWith)
	})

	t.Run("Delete", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testEventSubNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _ string, _ *armeventgrid.EventSubscriptionsClientBeginDeleteOptions) (*runtime.Poller[armeventgrid.EventSubscriptionsClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testEventSubNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_resource", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{
				"resourceGroupName": "rg-1", "providerNamespace": "Microsoft.EventGrid",
				"resourceTypeName": "topics", "resourceName": "topic-1",
			},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testEventSubNativeID}, got.NativeIDs)
	})

	// ARM has no listing that spans scopes of every kind, so without the scope
	// broken into parts there is nothing to page.
	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, _ armeventgrid.EventSubscription, _ *armeventgrid.EventSubscriptionsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armeventgrid.EventSubscriptionsClientCreateOrUpdateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 409}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "sub-1-name", Properties: eventSubDesired("/blobServices/"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

// The native ID is <scope>/providers/Microsoft.EventGrid/eventSubscriptions/<name>,
// and ARM echoes that provider segment back with varying case, so parsing must be
// case-insensitive.
func TestEventGridEventSubscription_ParseID(t *testing.T) {
	scope, name, err := parseEventSubscriptionID(testEventSubScope + "/providers/microsoft.eventgrid/eventsubscriptions/lower")
	require.NoError(t, err)
	require.Equal(t, testEventSubScope, scope)
	require.Equal(t, "lower", name)

	_, _, err = parseEventSubscriptionID("/subscriptions/sub-1/resourceGroups/rg-1")
	require.ErrorContains(t, err, "invalid event subscription id")
}

// Only the storage-queue destination is modelled. A webhook (or any other) endpoint
// must be omitted rather than half-read, or it would show as drift forever.
func TestEventGridEventSubscription_ReadSkipsUnmodelledDestination(t *testing.T) {
	fake := &fakeEventSubscriptionsAPI{
		getFn: func(_ context.Context, _, _ string, _ *armeventgrid.EventSubscriptionsClientGetOptions) (armeventgrid.EventSubscriptionsClientGetResponse, error) {
			return armeventgrid.EventSubscriptionsClientGetResponse{EventSubscription: armeventgrid.EventSubscription{
				ID:   to.Ptr(testEventSubNativeID),
				Name: to.Ptr("sub-1-name"),
				Properties: &armeventgrid.EventSubscriptionProperties{
					Destination: &armeventgrid.WebHookEventSubscriptionDestination{
						EndpointType: to.Ptr(armeventgrid.EndpointTypeWebHook),
						Properties: &armeventgrid.WebHookEventSubscriptionDestinationProperties{
							EndpointURL: to.Ptr("https://example.invalid/hook"),
						},
					},
				},
			}}, nil
		},
	}
	got, err := newTestEventSubscription(fake).Read(context.Background(), &resource.ReadRequest{NativeID: testEventSubNativeID})
	require.NoError(t, err)
	require.NotContains(t, got.Properties, "storageQueueDestination")
	require.NotContains(t, got.Properties, "example.invalid")
}

func TestEventGridEventSubscription_ReadNotFound(t *testing.T) {
	fake := &fakeEventSubscriptionsAPI{
		getFn: func(_ context.Context, _, _ string, _ *armeventgrid.EventSubscriptionsClientGetOptions) (armeventgrid.EventSubscriptionsClientGetResponse, error) {
			return armeventgrid.EventSubscriptionsClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestEventSubscription(fake).Read(context.Background(), &resource.ReadRequest{NativeID: testEventSubNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeEventSubscriptionsAPI struct {
	beginCreateOrUpdateFn              func(ctx context.Context, scope, name string, params armeventgrid.EventSubscription, options *armeventgrid.EventSubscriptionsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armeventgrid.EventSubscriptionsClientCreateOrUpdateResponse], error)
	getFn                              func(ctx context.Context, scope, name string, options *armeventgrid.EventSubscriptionsClientGetOptions) (armeventgrid.EventSubscriptionsClientGetResponse, error)
	beginDeleteFn                      func(ctx context.Context, scope, name string, options *armeventgrid.EventSubscriptionsClientBeginDeleteOptions) (*runtime.Poller[armeventgrid.EventSubscriptionsClientDeleteResponse], error)
	newListGlobalBySubscriptionPagerFn func(options *armeventgrid.EventSubscriptionsClientListGlobalBySubscriptionOptions) *runtime.Pager[armeventgrid.EventSubscriptionsClientListGlobalBySubscriptionResponse]
	newListByResourcePagerFn           func(rgName, providerNamespace, resourceTypeName, resourceName string, options *armeventgrid.EventSubscriptionsClientListByResourceOptions) *runtime.Pager[armeventgrid.EventSubscriptionsClientListByResourceResponse]
}

func (f *fakeEventSubscriptionsAPI) BeginCreateOrUpdate(ctx context.Context, scope, name string, params armeventgrid.EventSubscription, options *armeventgrid.EventSubscriptionsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armeventgrid.EventSubscriptionsClientCreateOrUpdateResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, scope, name, params, options)
}

func (f *fakeEventSubscriptionsAPI) Get(ctx context.Context, scope, name string, options *armeventgrid.EventSubscriptionsClientGetOptions) (armeventgrid.EventSubscriptionsClientGetResponse, error) {
	return f.getFn(ctx, scope, name, options)
}

func (f *fakeEventSubscriptionsAPI) BeginDelete(ctx context.Context, scope, name string, options *armeventgrid.EventSubscriptionsClientBeginDeleteOptions) (*runtime.Poller[armeventgrid.EventSubscriptionsClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, scope, name, options)
}

func (f *fakeEventSubscriptionsAPI) NewListGlobalBySubscriptionPager(options *armeventgrid.EventSubscriptionsClientListGlobalBySubscriptionOptions) *runtime.Pager[armeventgrid.EventSubscriptionsClientListGlobalBySubscriptionResponse] {
	return f.newListGlobalBySubscriptionPagerFn(options)
}

func (f *fakeEventSubscriptionsAPI) NewListByResourcePager(rgName, providerNamespace, resourceTypeName, resourceName string, options *armeventgrid.EventSubscriptionsClientListByResourceOptions) *runtime.Pager[armeventgrid.EventSubscriptionsClientListByResourceResponse] {
	return f.newListByResourcePagerFn(rgName, providerNamespace, resourceTypeName, resourceName, options)
}

// Update hands out a resume token from a BeginCreateOrUpdate poller, so Status must
// resume it as a CreateOrUpdate response — see the comment there. Resuming it as
// the SDK's Update response type killed the plugin operator mid-poll ("Plugin
// operator is missing in action"). That type mismatch is only observable against
// real ARM (the fake poller below cannot mint a resumable token), so conformance's
// [Update] phase is what guards it; this test just pins the in-progress contract.
func TestEventGridEventSubscription_PendingUpdateReportsInProgress(t *testing.T) {
	fake := &fakeEventSubscriptionsAPI{
		beginCreateOrUpdateFn: func(_ context.Context, _, _ string, _ armeventgrid.EventSubscription, _ *armeventgrid.EventSubscriptionsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armeventgrid.EventSubscriptionsClientCreateOrUpdateResponse], error) {
			return newPendingPoller[armeventgrid.EventSubscriptionsClientCreateOrUpdateResponse](), nil
		},
	}

	got, err := newTestEventSubscription(fake).Update(context.Background(), &resource.UpdateRequest{
		NativeID:          testEventSubNativeID,
		DesiredProperties: eventSubDesired("/orders/"),
	})
	require.NoError(t, err)
	require.Equal(t, resource.OperationStatusInProgress, got.ProgressResult.OperationStatus)
	require.NotEmpty(t, got.ProgressResult.RequestID)
	require.Equal(t, testEventSubNativeID, got.ProgressResult.NativeID)
}
