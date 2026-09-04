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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/datafactory/armdatafactory"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testBlobEventTriggerScope = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Storage/storageAccounts/sa1"

func newTestTriggerBlobEvent(api dataFactoryTriggersAPI) *DataFactoryTriggerBlobEvent {
	return &DataFactoryTriggerBlobEvent{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func triggerBlobEventDesired(overrides map[string]any) []byte {
	props := map[string]any{
		"name":               "trg-1",
		"resourceGroupName":  "rg-1",
		"factoryName":        "adf-1",
		"scope":              testBlobEventTriggerScope,
		"events":             []string{"Microsoft.Storage.BlobCreated"},
		"blobPathBeginsWith": "/landing/blobs/incoming/",
		"ignoreEmptyBlobs":   true,
	}
	for k, v := range overrides {
		if v == nil {
			delete(props, k)
			continue
		}
		props[k] = v
	}
	out, _ := json.Marshal(props)
	return out
}

func TestDataFactoryTriggerBlobEvent_CRUD(t *testing.T) {
	result := armdatafactory.TriggerResource{
		ID:   to.Ptr(testTriggerNativeID),
		Name: to.Ptr("trg-1"),
		Properties: &armdatafactory.BlobEventsTrigger{
			Type:        to.Ptr("BlobEventsTrigger"),
			Description: to.Ptr("land on arrival"),
			Annotations: []any{"conformance"},
			// Service-managed state. It must never reach the property set.
			RuntimeState: to.Ptr(armdatafactory.TriggerRuntimeStateStopped),
			Pipelines: []*armdatafactory.TriggerPipelineReference{
				{
					PipelineReference: &armdatafactory.PipelineReference{
						Type:          to.Ptr(armdatafactory.PipelineReferenceTypePipelineReference),
						ReferenceName: to.Ptr("pl-1"),
					},
				},
			},
			TypeProperties: &armdatafactory.BlobEventsTriggerTypeProperties{
				Scope:              to.Ptr(testBlobEventTriggerScope),
				Events:             []*armdatafactory.BlobEventTypes{to.Ptr(armdatafactory.BlobEventTypesMicrosoftStorageBlobCreated)},
				BlobPathBeginsWith: to.Ptr("/landing/blobs/incoming/"),
				IgnoreEmptyBlobs:   to.Ptr(true),
			},
		},
	}

	var sent armdatafactory.TriggerResource
	var sawRG, sawFactory, sawName string
	createCalls := 0
	deleteCalls := 0
	fake := &fakeTriggersAPI{
		createOrUpdateFn: func(_ context.Context, rgName, factoryName, name string, params armdatafactory.TriggerResource, _ *armdatafactory.TriggersClientCreateOrUpdateOptions) (armdatafactory.TriggersClientCreateOrUpdateResponse, error) {
			sawRG, sawFactory, sawName, sent = rgName, factoryName, name, params
			createCalls++
			return armdatafactory.TriggersClientCreateOrUpdateResponse{TriggerResource: result}, nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ *armdatafactory.TriggersClientGetOptions) (armdatafactory.TriggersClientGetResponse, error) {
			return armdatafactory.TriggersClientGetResponse{TriggerResource: result}, nil
		},
		deleteFn: func(_ context.Context, _, _, _ string, _ *armdatafactory.TriggersClientDeleteOptions) (armdatafactory.TriggersClientDeleteResponse, error) {
			deleteCalls++
			return armdatafactory.TriggersClientDeleteResponse{}, nil
		},
		newListByFactoryPagerFn: func(_, _ string, _ *armdatafactory.TriggersClientListByFactoryOptions) *runtime.Pager[armdatafactory.TriggersClientListByFactoryResponse] {
			return runtime.NewPager(runtime.PagingHandler[armdatafactory.TriggersClientListByFactoryResponse]{
				More: func(_ armdatafactory.TriggersClientListByFactoryResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armdatafactory.TriggersClientListByFactoryResponse) (armdatafactory.TriggersClientListByFactoryResponse, error) {
					return armdatafactory.TriggersClientListByFactoryResponse{
						TriggerListResponse: armdatafactory.TriggerListResponse{
							Value: []*armdatafactory.TriggerResource{
								{
									ID:         to.Ptr(testTriggerNativeID),
									Properties: &armdatafactory.BlobEventsTrigger{Type: to.Ptr("BlobEventsTrigger")},
								},
								{
									// A different trigger kind in the same
									// factory: it must not be claimed here.
									ID:         to.Ptr(testDataFactoryNativeID + "/triggers/sched-1"),
									Properties: &armdatafactory.ScheduleTrigger{Type: to.Ptr("ScheduleTrigger")},
								},
								// No ID and no properties: skipped, not a panic.
								{},
							},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestTriggerBlobEvent(fake)

	// CreateOrUpdate, Get and Delete are all synchronous, and the Event Grid
	// subscription is created by SubscribeToEvents when the trigger is STARTED —
	// which this provisioner never does. So a create reports success directly and
	// never hands back a resume token.
	t.Run("Create_is_synchronous", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "trg-1",
			Properties: triggerBlobEventDesired(map[string]any{
				"description":   "land on arrival",
				"pipelineNames": []string{"pl-1"},
				"annotations":   []string{"conformance"},
			}),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testTriggerNativeID, got.ProgressResult.NativeID)
		require.Empty(t, got.ProgressResult.RequestID)

		require.Equal(t, "rg-1", sawRG)
		require.Equal(t, "adf-1", sawFactory)
		require.Equal(t, "trg-1", sawName)

		trigger, ok := sent.Properties.(*armdatafactory.BlobEventsTrigger)
		require.True(t, ok)
		require.Equal(t, "land on arrival", *trigger.Description)
		require.Equal(t, []any{"conformance"}, trigger.Annotations)
		require.Len(t, trigger.Pipelines, 1)
		require.Equal(t, "pl-1", *trigger.Pipelines[0].PipelineReference.ReferenceName)

		typeProps := trigger.TypeProperties
		require.Equal(t, testBlobEventTriggerScope, *typeProps.Scope)
		require.Len(t, typeProps.Events, 1)
		require.Equal(t, armdatafactory.BlobEventTypesMicrosoftStorageBlobCreated, *typeProps.Events[0])
		require.Equal(t, "/landing/blobs/incoming/", *typeProps.BlobPathBeginsWith)
		require.Nil(t, typeProps.BlobPathEndsWith)
		require.True(t, *typeProps.IgnoreEmptyBlobs)
	})

	t.Run("Create_requires_scope_and_events", func(t *testing.T) {
		_, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "trg-1",
			Properties: triggerBlobEventDesired(map[string]any{"scope": nil}),
		})
		require.ErrorContains(t, err, "scope is required")

		_, err = prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "trg-1",
			Properties: triggerBlobEventDesired(map[string]any{"events": nil}),
		})
		require.ErrorContains(t, err, "events is required")
	})

	// ignoreEmptyBlobs is required rather than optional because the service fills
	// it in with true when omitted, and a service-chosen value would read back as
	// drift against a forma that did not state it.
	t.Run("Create_requires_ignore_empty_blobs", func(t *testing.T) {
		_, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "trg-1",
			Properties: triggerBlobEventDesired(map[string]any{"ignoreEmptyBlobs": nil}),
		})
		require.ErrorContains(t, err, "ignoreEmptyBlobs is required")
	})

	// ARM's own rule, checked before any call is made: a trigger filtering on
	// neither end of the blob path would fire for every blob in the account.
	t.Run("Create_requires_a_path_filter", func(t *testing.T) {
		_, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "trg-1",
			Properties: triggerBlobEventDesired(map[string]any{"blobPathBeginsWith": nil}),
		})
		require.ErrorContains(t, err, "one of blobPathBeginsWith or blobPathEndsWith is required")
	})

	t.Run("Create_accepts_ends_with_alone", func(t *testing.T) {
		_, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "trg-1",
			Properties: triggerBlobEventDesired(map[string]any{
				"blobPathBeginsWith": nil, "blobPathEndsWith": ".csv",
			}),
		})
		require.NoError(t, err)
		trigger, ok := sent.Properties.(*armdatafactory.BlobEventsTrigger)
		require.True(t, ok)
		require.Nil(t, trigger.TypeProperties.BlobPathBeginsWith)
		require.Equal(t, ".csv", *trigger.TypeProperties.BlobPathEndsWith)
	})

	t.Run("Create_requires_parents", func(t *testing.T) {
		_, err := prov.Create(context.Background(), &resource.CreateRequest{
			Properties: triggerBlobEventDesired(map[string]any{"factoryName": nil}),
		})
		require.ErrorContains(t, err, "factoryName is required")

		_, err = prov.Create(context.Background(), &resource.CreateRequest{
			Properties: triggerBlobEventDesired(map[string]any{"resourceGroupName": nil}),
		})
		require.ErrorContains(t, err, "resourceGroupName is required")
	})

	t.Run("Create_falls_back_to_label_for_name", func(t *testing.T) {
		_, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "trg-1",
			Properties: triggerBlobEventDesired(map[string]any{"name": nil}),
		})
		require.NoError(t, err)
		require.Equal(t, "trg-1", sawName)
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testTriggerNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
		require.Equal(t, ResourceTypeDataFactoryTriggerBlobEvent, got.ResourceType)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "trg-1", props["name"])
		// Both parents come from the native ID, not the response body.
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "adf-1", props["factoryName"])
		require.Equal(t, testBlobEventTriggerScope, props["scope"])
		require.Equal(t, []any{"Microsoft.Storage.BlobCreated"}, props["events"])
		require.Equal(t, "/landing/blobs/incoming/", props["blobPathBeginsWith"])
		require.Equal(t, true, props["ignoreEmptyBlobs"])
		require.Equal(t, "land on arrival", props["description"])
		require.Equal(t, []any{"pl-1"}, props["pipelineNames"])
		require.Equal(t, []any{"conformance"}, props["annotations"])
		// Whether a trigger is Started or Stopped is changed by Start / Stop, not
		// by the definition, so it must never appear in the property set.
		require.NotContains(t, props, "runtimeState")
		require.NotContains(t, props, "blobPathEndsWith")
	})

	// ignoreEmptyBlobs = false must survive the round trip: dropping a false would
	// make "explicitly keep empty blobs" indistinguishable from "unset", and the
	// service's own default is true.
	t.Run("false_ignore_empty_blobs_round_trips", func(t *testing.T) {
		var props dataFactoryTriggerBlobEventProps
		require.NoError(t, props.parse(triggerBlobEventDesired(map[string]any{"ignoreEmptyBlobs": false}), "trg-1"))
		params := props.params()
		trigger, ok := params.Properties.(*armdatafactory.BlobEventsTrigger)
		require.True(t, ok)
		require.False(t, *trigger.TypeProperties.IgnoreEmptyBlobs)

		read := newTestTriggerBlobEvent(nil).buildPropertiesFromResult(&armdatafactory.TriggerResource{
			ID:         to.Ptr(testTriggerNativeID),
			Name:       to.Ptr("trg-1"),
			Properties: trigger,
		}, "rg-1", "adf-1")
		require.Equal(t, false, read["ignoreEmptyBlobs"])
	})

	t.Run("Update_reissues_create_or_update", func(t *testing.T) {
		before := createCalls
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID: testTriggerNativeID,
			DesiredProperties: triggerBlobEventDesired(map[string]any{
				"events":      []string{"Microsoft.Storage.BlobCreated", "Microsoft.Storage.BlobDeleted"},
				"description": "land and clean up",
			}),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Empty(t, got.ProgressResult.RequestID)
		require.Equal(t, before+1, createCalls)
		trigger, ok := sent.Properties.(*armdatafactory.BlobEventsTrigger)
		require.True(t, ok)
		require.Len(t, trigger.TypeProperties.Events, 2)
	})

	t.Run("Delete_is_synchronous", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testTriggerNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _, _ string, _ *armdatafactory.TriggersClientDeleteOptions) (armdatafactory.TriggersClientDeleteResponse, error) {
			return armdatafactory.TriggersClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testTriggerNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Delete_of_a_started_trigger_maps_to_failure_with_reason", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _, _ string, _ *armdatafactory.TriggersClientDeleteOptions) (armdatafactory.TriggersClientDeleteResponse, error) {
			return armdatafactory.TriggersClientDeleteResponse{},
				&azcore.ResponseError{StatusCode: 400, ErrorCode: "TriggerIsStarted"}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testTriggerNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.Equal(t, resource.OperationErrorCodeInvalidRequest, got.ProgressResult.ErrorCode)
		require.Contains(t, got.ProgressResult.StatusMessage, "TriggerIsStarted")
	})

	t.Run("List_keeps_only_blob_event_triggers", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "factoryName": "adf-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testTriggerNativeID}, got.NativeIDs)
	})

	// ARM has no subscription-wide listing here: without both parents there is
	// nothing to page, so List must return empty rather than error.
	t.Run("List_without_parents_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})

	// A storage account the factory's identity cannot see arrives as a 403 and
	// must surface with the provider's own reason.
	t.Run("Azure_error_maps_to_failure_with_reason", func(t *testing.T) {
		fake.createOrUpdateFn = func(_ context.Context, _, _, _ string, _ armdatafactory.TriggerResource, _ *armdatafactory.TriggersClientCreateOrUpdateOptions) (armdatafactory.TriggersClientCreateOrUpdateResponse, error) {
			return armdatafactory.TriggersClientCreateOrUpdateResponse{},
				&azcore.ResponseError{StatusCode: 400, ErrorCode: "InvalidStorageAccountScope"}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "trg-1", Properties: triggerBlobEventDesired(nil),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.Equal(t, resource.OperationErrorCodeInvalidRequest, got.ProgressResult.ErrorCode)
		require.Contains(t, got.ProgressResult.StatusMessage, "InvalidStorageAccountScope")
	})
}

func TestDataFactoryTriggerBlobEvent_ReadNotFound(t *testing.T) {
	fake := &fakeTriggersAPI{
		getFn: func(_ context.Context, _, _, _ string, _ *armdatafactory.TriggersClientGetOptions) (armdatafactory.TriggersClientGetResponse, error) {
			return armdatafactory.TriggersClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestTriggerBlobEvent(fake).
		Read(context.Background(), &resource.ReadRequest{NativeID: testTriggerNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// Reading a trigger of another kind must degrade to the parents rather than
// panicking on the type assertion.
func TestDataFactoryTriggerBlobEvent_ReadOfWrongKindIsSafe(t *testing.T) {
	fake := &fakeTriggersAPI{
		getFn: func(_ context.Context, _, _, _ string, _ *armdatafactory.TriggersClientGetOptions) (armdatafactory.TriggersClientGetResponse, error) {
			return armdatafactory.TriggersClientGetResponse{
				TriggerResource: armdatafactory.TriggerResource{
					ID:         to.Ptr(testTriggerNativeID),
					Name:       to.Ptr("trg-1"),
					Properties: &armdatafactory.ScheduleTrigger{Type: to.Ptr("ScheduleTrigger")},
				},
			}, nil
		},
	}
	got, err := newTestTriggerBlobEvent(fake).
		Read(context.Background(), &resource.ReadRequest{NativeID: testTriggerNativeID})
	require.NoError(t, err)
	require.NotContains(t, got.Properties, "scope")
}

func TestDataFactoryTriggerBlobEvent_StatusIsAlwaysDone(t *testing.T) {
	got, err := newTestTriggerBlobEvent(&fakeTriggersAPI{}).
		Status(context.Background(), &resource.StatusRequest{RequestID: "anything"})
	require.NoError(t, err)
	require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
}
