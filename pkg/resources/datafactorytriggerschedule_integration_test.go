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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/datafactory/armdatafactory"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testTriggerNativeID = testDataFactoryNativeID + "/triggers/trg-1"

func newTestTriggerSchedule(api dataFactoryTriggersAPI) *DataFactoryTriggerSchedule {
	return &DataFactoryTriggerSchedule{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func triggerScheduleDesired(overrides map[string]any) []byte {
	props := map[string]any{
		"name":              "trg-1",
		"resourceGroupName": "rg-1",
		"factoryName":       "adf-1",
		"frequency":         "Hour",
		"interval":          1,
		"startTime":         "2027-01-01T00:00:00Z",
		"timeZone":          "UTC",
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

func TestDataFactoryTriggerSchedule_CRUD(t *testing.T) {
	startTime := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	result := armdatafactory.TriggerResource{
		ID:   to.Ptr(testTriggerNativeID),
		Name: to.Ptr("trg-1"),
		Properties: &armdatafactory.ScheduleTrigger{
			Type:        to.Ptr("ScheduleTrigger"),
			Description: to.Ptr("hourly load"),
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
			TypeProperties: &armdatafactory.ScheduleTriggerTypeProperties{
				Recurrence: &armdatafactory.ScheduleTriggerRecurrence{
					Frequency: to.Ptr(armdatafactory.RecurrenceFrequencyHour),
					Interval:  to.Ptr[int32](1),
					StartTime: &startTime,
					TimeZone:  to.Ptr("UTC"),
				},
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
									Properties: &armdatafactory.ScheduleTrigger{Type: to.Ptr("ScheduleTrigger")},
								},
								{
									// A different trigger kind in the same
									// factory: it must not be claimed here.
									ID:         to.Ptr(testDataFactoryNativeID + "/triggers/blob-1"),
									Properties: &armdatafactory.BlobEventsTrigger{Type: to.Ptr("BlobEventsTrigger")},
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
	prov := newTestTriggerSchedule(fake)

	// CreateOrUpdate, Get and Delete are all synchronous: a create reports success
	// directly and never hands back a resume token. The BeginStart / BeginStop
	// verbs exist but are never called.
	t.Run("Create_is_synchronous", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "trg-1",
			Properties: triggerScheduleDesired(map[string]any{
				"description":   "hourly load",
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

		trigger, ok := sent.Properties.(*armdatafactory.ScheduleTrigger)
		require.True(t, ok)
		require.Equal(t, "hourly load", *trigger.Description)
		require.Equal(t, []any{"conformance"}, trigger.Annotations)
		require.Len(t, trigger.Pipelines, 1)
		require.Equal(t, "pl-1", *trigger.Pipelines[0].PipelineReference.ReferenceName)
		require.Equal(t, armdatafactory.PipelineReferenceTypePipelineReference,
			*trigger.Pipelines[0].PipelineReference.Type)

		recurrence := trigger.TypeProperties.Recurrence
		require.Equal(t, armdatafactory.RecurrenceFrequencyHour, *recurrence.Frequency)
		require.Equal(t, int32(1), *recurrence.Interval)
		require.Equal(t, "UTC", *recurrence.TimeZone)
		require.Equal(t, startTime, *recurrence.StartTime)
		require.Nil(t, recurrence.EndTime)
		// No finer filter declared means no schedule block at all.
		require.Nil(t, recurrence.Schedule)
	})

	// The recurrence's five scalars are all caller-owned, so every one of them has
	// to be refused when missing rather than left for ARM to fill in.
	t.Run("Create_requires_the_whole_recurrence", func(t *testing.T) {
		for field, message := range map[string]string{
			"frequency": "frequency is required",
			"interval":  "interval is required",
			"startTime": "startTime is required",
			"timeZone":  "timeZone is required",
		} {
			_, err := prov.Create(context.Background(), &resource.CreateRequest{
				Label:      "trg-1",
				Properties: triggerScheduleDesired(map[string]any{field: nil}),
			})
			require.ErrorContains(t, err, message)
		}
	})

	t.Run("Create_requires_parents", func(t *testing.T) {
		_, err := prov.Create(context.Background(), &resource.CreateRequest{
			Properties: triggerScheduleDesired(map[string]any{"factoryName": nil}),
		})
		require.ErrorContains(t, err, "factoryName is required")

		_, err = prov.Create(context.Background(), &resource.CreateRequest{
			Properties: triggerScheduleDesired(map[string]any{"resourceGroupName": nil}),
		})
		require.ErrorContains(t, err, "resourceGroupName is required")
	})

	t.Run("Create_falls_back_to_label_for_name", func(t *testing.T) {
		_, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "trg-1",
			Properties: triggerScheduleDesired(map[string]any{"name": nil}),
		})
		require.NoError(t, err)
		require.Equal(t, "trg-1", sawName)
	})

	// A malformed instant must fail before any ARM call, not as an opaque 400.
	t.Run("Create_rejects_a_non_rfc3339_start_time", func(t *testing.T) {
		_, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "trg-1",
			Properties: triggerScheduleDesired(map[string]any{"startTime": "next tuesday"}),
		})
		require.ErrorContains(t, err, "startTime must be an RFC-3339 instant")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testTriggerNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
		require.Equal(t, ResourceTypeDataFactoryTriggerSchedule, got.ResourceType)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "trg-1", props["name"])
		// Both parents come from the native ID, not the response body.
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "adf-1", props["factoryName"])
		require.Equal(t, "Hour", props["frequency"])
		require.Equal(t, float64(1), props["interval"])
		require.Equal(t, "2027-01-01T00:00:00Z", props["startTime"])
		require.Equal(t, "UTC", props["timeZone"])
		require.Equal(t, "hourly load", props["description"])
		require.Equal(t, []any{"pl-1"}, props["pipelineNames"])
		require.Equal(t, []any{"conformance"}, props["annotations"])
		// Whether a trigger is Started or Stopped is changed by Start / Stop, not
		// by the definition, so it must never appear in the property set.
		require.NotContains(t, props, "runtimeState")
		require.NotContains(t, props, "endTime")
	})

	t.Run("Update_reissues_create_or_update", func(t *testing.T) {
		before := createCalls
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID: testTriggerNativeID,
			DesiredProperties: triggerScheduleDesired(map[string]any{
				"interval":    4,
				"description": "four-hourly load",
			}),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Empty(t, got.ProgressResult.RequestID)
		require.Equal(t, before+1, createCalls)
		trigger, ok := sent.Properties.(*armdatafactory.ScheduleTrigger)
		require.True(t, ok)
		require.Equal(t, int32(4), *trigger.TypeProperties.Recurrence.Interval)
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

	// A started trigger cannot be deleted; that arrives as a 400 and must surface
	// with the provider's own reason.
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

	// One factory pager returns every trigger kind, so the results must be
	// filtered by discriminator.
	t.Run("List_keeps_only_schedule_triggers", func(t *testing.T) {
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

	t.Run("Azure_error_maps_to_failure_with_reason", func(t *testing.T) {
		fake.createOrUpdateFn = func(_ context.Context, _, _, _ string, _ armdatafactory.TriggerResource, _ *armdatafactory.TriggersClientCreateOrUpdateOptions) (armdatafactory.TriggersClientCreateOrUpdateResponse, error) {
			return armdatafactory.TriggersClientCreateOrUpdateResponse{},
				&azcore.ResponseError{StatusCode: 404, ErrorCode: "PipelineNotFound"}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "trg-1",
			Properties: triggerScheduleDesired(map[string]any{"pipelineNames": []string{"missing"}}),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.Equal(t, resource.OperationErrorCodeNotFound, got.ProgressResult.ErrorCode)
		require.Contains(t, got.ProgressResult.StatusMessage, "PipelineNotFound")
	})
}

// The inner schedule block is optional: declaring any one of the four lists brings
// it into the request, declaring none leaves it out entirely.
func TestDataFactoryTriggerSchedule_RecurrenceSchedule(t *testing.T) {
	build := func(t *testing.T, overrides map[string]any) *armdatafactory.ScheduleTrigger {
		t.Helper()
		var props dataFactoryTriggerScheduleProps
		require.NoError(t, props.parse(triggerScheduleDesired(overrides), "trg-1"))
		params, err := props.params()
		require.NoError(t, err)
		trigger, ok := params.Properties.(*armdatafactory.ScheduleTrigger)
		require.True(t, ok)
		return trigger
	}

	t.Run("no_lists_means_no_schedule", func(t *testing.T) {
		require.Nil(t, build(t, nil).TypeProperties.Recurrence.Schedule)
	})

	t.Run("week_days_and_hours_round_trip", func(t *testing.T) {
		trigger := build(t, map[string]any{
			"frequency":         "Week",
			"scheduleWeekDays":  []string{"Monday", "Thursday"},
			"scheduleHours":     []int{3, 15},
			"scheduleMinutes":   []int{0},
			"scheduleMonthDays": []int{-1},
		})
		schedule := trigger.TypeProperties.Recurrence.Schedule
		require.NotNil(t, schedule)
		require.Len(t, schedule.WeekDays, 2)
		require.Equal(t, armdatafactory.DaysOfWeekMonday, *schedule.WeekDays[0])
		require.Equal(t, int32(3), *schedule.Hours[0])
		require.Equal(t, int32(0), *schedule.Minutes[0])
		require.Equal(t, int32(-1), *schedule.MonthDays[0])

		props := newTestTriggerSchedule(nil).buildPropertiesFromResult(&armdatafactory.TriggerResource{
			ID:         to.Ptr(testTriggerNativeID),
			Name:       to.Ptr("trg-1"),
			Properties: trigger,
		}, "rg-1", "adf-1")
		require.Equal(t, []string{"Monday", "Thursday"}, props["scheduleWeekDays"])
		require.Equal(t, []int32{3, 15}, props["scheduleHours"])
		require.Equal(t, []int32{0}, props["scheduleMinutes"])
		require.Equal(t, []int32{-1}, props["scheduleMonthDays"])
	})

	t.Run("end_time_round_trips", func(t *testing.T) {
		trigger := build(t, map[string]any{"endTime": "2028-01-01T00:00:00Z"})
		require.Equal(t, time.Date(2028, 1, 1, 0, 0, 0, 0, time.UTC),
			*trigger.TypeProperties.Recurrence.EndTime)
	})

	t.Run("a_malformed_end_time_is_refused", func(t *testing.T) {
		var props dataFactoryTriggerScheduleProps
		require.NoError(t, props.parse(triggerScheduleDesired(map[string]any{"endTime": "soon"}), "trg-1"))
		_, err := props.params()
		require.ErrorContains(t, err, "endTime must be an RFC-3339 instant")
	})
}

// The drift guard on this type: ARM normalises the recurrence timestamps to UTC and
// drops sub-second precision, so the read side has to normalise identically or a
// trigger nobody touched reports drift on every reconcile.
func TestDataFactoryTriggerSchedule_TimestampsAreNormalised(t *testing.T) {
	offset := time.FixedZone("CET", 2*60*60)
	instant := time.Date(2027, 1, 1, 2, 0, 0, 123456789, offset)
	got, ok := dataFactoryTriggerTimeString(&instant)
	require.True(t, ok)
	require.Equal(t, "2027-01-01T00:00:00Z", got)

	_, ok = dataFactoryTriggerTimeString(nil)
	require.False(t, ok)

	var zero time.Time
	_, ok = dataFactoryTriggerTimeString(&zero)
	require.False(t, ok)
}

func TestDataFactoryTriggerSchedule_ReadNotFound(t *testing.T) {
	fake := &fakeTriggersAPI{
		getFn: func(_ context.Context, _, _, _ string, _ *armdatafactory.TriggersClientGetOptions) (armdatafactory.TriggersClientGetResponse, error) {
			return armdatafactory.TriggersClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestTriggerSchedule(fake).
		Read(context.Background(), &resource.ReadRequest{NativeID: testTriggerNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// Reading a trigger of another kind must degrade to the parents rather than
// panicking on the type assertion.
func TestDataFactoryTriggerSchedule_ReadOfWrongKindIsSafe(t *testing.T) {
	fake := &fakeTriggersAPI{
		getFn: func(_ context.Context, _, _, _ string, _ *armdatafactory.TriggersClientGetOptions) (armdatafactory.TriggersClientGetResponse, error) {
			return armdatafactory.TriggersClientGetResponse{
				TriggerResource: armdatafactory.TriggerResource{
					ID:         to.Ptr(testTriggerNativeID),
					Name:       to.Ptr("trg-1"),
					Properties: &armdatafactory.BlobEventsTrigger{Type: to.Ptr("BlobEventsTrigger")},
				},
			}, nil
		},
	}
	got, err := newTestTriggerSchedule(fake).
		Read(context.Background(), &resource.ReadRequest{NativeID: testTriggerNativeID})
	require.NoError(t, err)
	require.NotContains(t, got.Properties, "frequency")
}

func TestDataFactoryTriggerSchedule_StatusIsAlwaysDone(t *testing.T) {
	got, err := newTestTriggerSchedule(&fakeTriggersAPI{}).
		Status(context.Background(), &resource.StatusRequest{RequestID: "anything"})
	require.NoError(t, err)
	require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
}

// --- Test helpers ---
//
// Shared with datafactorytriggerblobevent_integration_test.go: both trigger types
// speak to the one dataFactoryTriggersAPI.

type fakeTriggersAPI struct {
	createOrUpdateFn        func(ctx context.Context, rgName, factoryName, name string, params armdatafactory.TriggerResource, options *armdatafactory.TriggersClientCreateOrUpdateOptions) (armdatafactory.TriggersClientCreateOrUpdateResponse, error)
	getFn                   func(ctx context.Context, rgName, factoryName, name string, options *armdatafactory.TriggersClientGetOptions) (armdatafactory.TriggersClientGetResponse, error)
	deleteFn                func(ctx context.Context, rgName, factoryName, name string, options *armdatafactory.TriggersClientDeleteOptions) (armdatafactory.TriggersClientDeleteResponse, error)
	newListByFactoryPagerFn func(rgName, factoryName string, options *armdatafactory.TriggersClientListByFactoryOptions) *runtime.Pager[armdatafactory.TriggersClientListByFactoryResponse]
}

func (f *fakeTriggersAPI) CreateOrUpdate(ctx context.Context, rgName, factoryName, name string, params armdatafactory.TriggerResource, options *armdatafactory.TriggersClientCreateOrUpdateOptions) (armdatafactory.TriggersClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, factoryName, name, params, options)
}

func (f *fakeTriggersAPI) Get(ctx context.Context, rgName, factoryName, name string, options *armdatafactory.TriggersClientGetOptions) (armdatafactory.TriggersClientGetResponse, error) {
	return f.getFn(ctx, rgName, factoryName, name, options)
}

func (f *fakeTriggersAPI) Delete(ctx context.Context, rgName, factoryName, name string, options *armdatafactory.TriggersClientDeleteOptions) (armdatafactory.TriggersClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, factoryName, name, options)
}

func (f *fakeTriggersAPI) NewListByFactoryPager(rgName, factoryName string, options *armdatafactory.TriggersClientListByFactoryOptions) *runtime.Pager[armdatafactory.TriggersClientListByFactoryResponse] {
	return f.newListByFactoryPagerFn(rgName, factoryName, options)
}
