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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/desktopvirtualization/armdesktopvirtualization"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const (
	testAvdScalingPlanNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.DesktopVirtualization/scalingPlans/sp-1"
	testAvdScalingPlanHostPool = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.DesktopVirtualization/hostPools/hp-1"
)

func newTestAvdScalingPlan(api avdScalingPlansAPI) *AvdScalingPlan {
	return &AvdScalingPlan{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func avdScalingPlanSchedule() map[string]any {
	return map[string]any{
		"name":                           "weekdays",
		"daysOfWeek":                     []string{"Monday", "Tuesday"},
		"rampUpStartTime":                "06:00",
		"rampUpLoadBalancingAlgorithm":   "BreadthFirst",
		"rampUpMinimumHostsPct":          20,
		"rampUpCapacityThresholdPct":     60,
		"peakStartTime":                  "09:00",
		"peakLoadBalancingAlgorithm":     "BreadthFirst",
		"rampDownStartTime":              "18:00",
		"rampDownLoadBalancingAlgorithm": "DepthFirst",
		"rampDownMinimumHostsPct":        10,
		"rampDownCapacityThresholdPct":   90,
		"rampDownForceLogoffUsers":       false,
		"rampDownWaitTimeMinutes":        30,
		"rampDownNotificationMessage":    "You will be signed out in 30 minutes.",
		"rampDownStopHostsWhen":          "ZeroSessions",
		"offPeakStartTime":               "20:00",
		"offPeakLoadBalancingAlgorithm":  "DepthFirst",
	}
}

func avdScalingPlanDesired(tagValue string) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":              "sp-1",
		"location":          "eastus",
		"resourceGroupName": "rg-1",
		"timeZone":          "UTC",
		"hostPoolType":      "Pooled",
		"description":       "conformance scaling plan",
		"friendlyName":      "sp one",
		"hostPoolReferences": []map[string]any{{
			"hostPoolArmPath":    testAvdScalingPlanHostPool,
			"scalingPlanEnabled": false,
		}},
		"schedules": []map[string]any{avdScalingPlanSchedule()},
		"Tags":      []map[string]string{{"Key": "env", "Value": tagValue}},
	})
	return out
}

// avdScalingPlanResponseTime is how the service hands a phase start time back:
// a full timestamp whose date part is arbitrary. Only the wall clock survives
// into desired state.
func avdScalingPlanResponseTime(hour, minute int) *time.Time {
	return to.Ptr(time.Date(2023, time.June, 15, hour, minute, 0, 0, time.UTC))
}

func TestAvdScalingPlan_CRUD(t *testing.T) {
	planResult := armdesktopvirtualization.ScalingPlan{
		ID:       to.Ptr(testAvdScalingPlanNativeID),
		Name:     to.Ptr("sp-1"),
		Location: to.Ptr("East US"),
		Properties: &armdesktopvirtualization.ScalingPlanProperties{
			TimeZone:     to.Ptr("UTC"),
			HostPoolType: to.Ptr(armdesktopvirtualization.HostPoolTypePooled),
			Description:  to.Ptr("conformance scaling plan"),
			FriendlyName: to.Ptr("sp one"),
			ObjectID:     to.Ptr("00000000-0000-0000-0000-000000000005"),
			HostPoolReferences: []*armdesktopvirtualization.ScalingHostPoolReference{{
				HostPoolArmPath:    to.Ptr(testAvdScalingPlanHostPool),
				ScalingPlanEnabled: to.Ptr(false),
			}},
			Schedules: []*armdesktopvirtualization.ScalingSchedule{{
				Name: to.Ptr("weekdays"),
				DaysOfWeek: []*armdesktopvirtualization.ScalingScheduleDaysOfWeekItem{
					to.Ptr(armdesktopvirtualization.ScalingScheduleDaysOfWeekItemMonday),
					to.Ptr(armdesktopvirtualization.ScalingScheduleDaysOfWeekItemTuesday),
				},
				RampUpStartTime:                avdScalingPlanResponseTime(6, 0),
				RampUpLoadBalancingAlgorithm:   to.Ptr(armdesktopvirtualization.SessionHostLoadBalancingAlgorithmBreadthFirst),
				RampUpMinimumHostsPct:          to.Ptr(int32(20)),
				RampUpCapacityThresholdPct:     to.Ptr(int32(60)),
				PeakStartTime:                  avdScalingPlanResponseTime(9, 0),
				PeakLoadBalancingAlgorithm:     to.Ptr(armdesktopvirtualization.SessionHostLoadBalancingAlgorithmBreadthFirst),
				RampDownStartTime:              avdScalingPlanResponseTime(18, 0),
				RampDownLoadBalancingAlgorithm: to.Ptr(armdesktopvirtualization.SessionHostLoadBalancingAlgorithmDepthFirst),
				RampDownMinimumHostsPct:        to.Ptr(int32(10)),
				RampDownCapacityThresholdPct:   to.Ptr(int32(90)),
				RampDownForceLogoffUsers:       to.Ptr(false),
				RampDownWaitTimeMinutes:        to.Ptr(int32(30)),
				RampDownNotificationMessage:    to.Ptr("You will be signed out in 30 minutes."),
				RampDownStopHostsWhen:          to.Ptr(armdesktopvirtualization.StopHostsWhenZeroSessions),
				OffPeakStartTime:               avdScalingPlanResponseTime(20, 0),
				OffPeakLoadBalancingAlgorithm:  to.Ptr(armdesktopvirtualization.SessionHostLoadBalancingAlgorithmDepthFirst),
			}},
		},
		Tags: map[string]*string{"env": to.Ptr("conformance")},
	}

	var sentCreate armdesktopvirtualization.ScalingPlan
	var sentUpdate *armdesktopvirtualization.ScalingPlanPatch
	deleteCalls := 0
	fake := &fakeAvdScalingPlansAPI{
		createFn: func(_ context.Context, rgName, name string, params armdesktopvirtualization.ScalingPlan, _ *armdesktopvirtualization.ScalingPlansClientCreateOptions) (armdesktopvirtualization.ScalingPlansClientCreateResponse, error) {
			require.Equal(t, "rg-1", rgName)
			require.Equal(t, "sp-1", name)
			sentCreate = params
			return armdesktopvirtualization.ScalingPlansClientCreateResponse{ScalingPlan: planResult}, nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armdesktopvirtualization.ScalingPlansClientGetOptions) (armdesktopvirtualization.ScalingPlansClientGetResponse, error) {
			return armdesktopvirtualization.ScalingPlansClientGetResponse{ScalingPlan: planResult}, nil
		},
		updateFn: func(_ context.Context, _, _ string, options *armdesktopvirtualization.ScalingPlansClientUpdateOptions) (armdesktopvirtualization.ScalingPlansClientUpdateResponse, error) {
			sentUpdate = options.ScalingPlan
			return armdesktopvirtualization.ScalingPlansClientUpdateResponse{ScalingPlan: planResult}, nil
		},
		deleteFn: func(_ context.Context, _, _ string, _ *armdesktopvirtualization.ScalingPlansClientDeleteOptions) (armdesktopvirtualization.ScalingPlansClientDeleteResponse, error) {
			deleteCalls++
			return armdesktopvirtualization.ScalingPlansClientDeleteResponse{}, nil
		},
		newListByResourceGroupPagerFn: func(rgName string, _ *armdesktopvirtualization.ScalingPlansClientListByResourceGroupOptions) *runtime.Pager[armdesktopvirtualization.ScalingPlansClientListByResourceGroupResponse] {
			require.Equal(t, "rg-1", rgName)
			return runtime.NewPager(runtime.PagingHandler[armdesktopvirtualization.ScalingPlansClientListByResourceGroupResponse]{
				More: func(armdesktopvirtualization.ScalingPlansClientListByResourceGroupResponse) bool { return false },
				Fetcher: func(context.Context, *armdesktopvirtualization.ScalingPlansClientListByResourceGroupResponse) (armdesktopvirtualization.ScalingPlansClientListByResourceGroupResponse, error) {
					return armdesktopvirtualization.ScalingPlansClientListByResourceGroupResponse{
						ScalingPlanList: armdesktopvirtualization.ScalingPlanList{
							Value: []*armdesktopvirtualization.ScalingPlan{{ID: to.Ptr(testAvdScalingPlanNativeID)}},
						},
					}, nil
				},
			})
		},
		newListBySubscriptionPagerFn: func(_ *armdesktopvirtualization.ScalingPlansClientListBySubscriptionOptions) *runtime.Pager[armdesktopvirtualization.ScalingPlansClientListBySubscriptionResponse] {
			return runtime.NewPager(runtime.PagingHandler[armdesktopvirtualization.ScalingPlansClientListBySubscriptionResponse]{
				More: func(armdesktopvirtualization.ScalingPlansClientListBySubscriptionResponse) bool { return false },
				Fetcher: func(context.Context, *armdesktopvirtualization.ScalingPlansClientListBySubscriptionResponse) (armdesktopvirtualization.ScalingPlansClientListBySubscriptionResponse, error) {
					return armdesktopvirtualization.ScalingPlansClientListBySubscriptionResponse{
						ScalingPlanList: armdesktopvirtualization.ScalingPlanList{
							Value: []*armdesktopvirtualization.ScalingPlan{{ID: to.Ptr(testAvdScalingPlanNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestAvdScalingPlan(fake)

	t.Run("Create_is_synchronous", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "sp-1",
			Properties: avdScalingPlanDesired("conformance"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testAvdScalingPlanNativeID, got.ProgressResult.NativeID)
		require.Empty(t, got.ProgressResult.RequestID)

		require.Equal(t, "eastus", *sentCreate.Location)
		require.Equal(t, "UTC", *sentCreate.Properties.TimeZone)
		require.Equal(t, armdesktopvirtualization.HostPoolTypePooled, *sentCreate.Properties.HostPoolType)
		// The pools a plan drives are a field, not association resources.
		require.Len(t, sentCreate.Properties.HostPoolReferences, 1)
		require.Equal(t, testAvdScalingPlanHostPool, *sentCreate.Properties.HostPoolReferences[0].HostPoolArmPath)
		require.False(t, *sentCreate.Properties.HostPoolReferences[0].ScalingPlanEnabled)
	})

	// A HH:MM wall clock is pinned onto one fixed reference day: the API's date
	// part is meaningless and the service re-serialises it, so an absolute
	// instant declared in a forma could never round-trip.
	t.Run("Create_pins_schedule_times_to_a_fixed_date", func(t *testing.T) {
		require.Len(t, sentCreate.Properties.Schedules, 1)
		sent := sentCreate.Properties.Schedules[0]
		require.Equal(t, 6, sent.RampUpStartTime.Hour())
		require.Equal(t, 0, sent.RampUpStartTime.Minute())
		require.Equal(t, 9, sent.PeakStartTime.Hour())
		require.Equal(t, 18, sent.RampDownStartTime.Hour())
		require.Equal(t, 20, sent.OffPeakStartTime.Hour())
		// Same reference day on every phase, so a forma never carries a date.
		require.Equal(t, 2020, sent.RampUpStartTime.Year())
		require.Equal(t, sent.RampUpStartTime.YearDay(), sent.OffPeakStartTime.YearDay())
		require.Equal(t, int32(30), *sent.RampDownWaitTimeMinutes)
		require.Equal(t, armdesktopvirtualization.StopHostsWhenZeroSessions, *sent.RampDownStopHostsWhen)
	})

	t.Run("Create_requires_time_zone", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "sp-1", "resourceGroupName": "rg-1", "location": "eastus",
			"hostPoolType": "Pooled",
			"schedules":    []map[string]any{avdScalingPlanSchedule()},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "timeZone is required")
	})

	// ARM rejects a Pooled schedule with a missing phase, so an incomplete one is
	// refused here rather than sent for an opaque BadRequest.
	t.Run("Create_requires_at_least_one_schedule", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "sp-1", "resourceGroupName": "rg-1", "location": "eastus",
			"timeZone": "UTC", "hostPoolType": "Pooled",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "schedules is required")
	})

	t.Run("Create_rejects_a_schedule_missing_a_ramp_phase", func(t *testing.T) {
		schedule := avdScalingPlanSchedule()
		delete(schedule, "rampDownStartTime")
		props, _ := json.Marshal(map[string]any{
			"name": "sp-1", "resourceGroupName": "rg-1", "location": "eastus",
			"timeZone": "UTC", "hostPoolType": "Pooled",
			"schedules": []map[string]any{schedule},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "schedules[0].rampDownStartTime is required")
	})

	t.Run("Create_rejects_a_non_wall_clock_time", func(t *testing.T) {
		schedule := avdScalingPlanSchedule()
		schedule["peakStartTime"] = "2026-09-02T09:00:00Z"
		props, _ := json.Marshal(map[string]any{
			"name": "sp-1", "resourceGroupName": "rg-1", "location": "eastus",
			"timeZone": "UTC", "hostPoolType": "Pooled",
			"schedules": []map[string]any{schedule},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "schedules[0].peakStartTime must be a HH:MM wall-clock time")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testAvdScalingPlanNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "sp-1", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "eastus", props["location"])
		require.Equal(t, "UTC", props["timeZone"])
		require.Equal(t, "Pooled", props["hostPoolType"])
		require.Equal(t, []any{map[string]any{
			"hostPoolArmPath":    testAvdScalingPlanHostPool,
			"scalingPlanEnabled": false,
		}}, props["hostPoolReferences"])
	})

	// The service hands back a timestamp on an arbitrary date; only the wall
	// clock reaches desired state, so a declared "06:00" round-trips exactly.
	t.Run("Read_reduces_schedule_times_to_a_wall_clock", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testAvdScalingPlanNativeID})
		require.NoError(t, err)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		schedules, ok := props["schedules"].([]any)
		require.True(t, ok)
		require.Len(t, schedules, 1)
		schedule := schedules[0].(map[string]any)
		require.Equal(t, "06:00", schedule["rampUpStartTime"])
		require.Equal(t, "09:00", schedule["peakStartTime"])
		require.Equal(t, "18:00", schedule["rampDownStartTime"])
		require.Equal(t, "20:00", schedule["offPeakStartTime"])
		require.Equal(t, []any{"Monday", "Tuesday"}, schedule["daysOfWeek"])
		require.Equal(t, "ZeroSessions", schedule["rampDownStopHostsWhen"])
		// No trace of the date the service put on the timestamps.
		require.NotContains(t, got.Properties, "2023-06-15")
	})

	t.Run("Read_drops_service_state", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testAvdScalingPlanNativeID})
		require.NoError(t, err)
		require.NotContains(t, got.Properties, "objectId")
	})

	// The schedule list and the host-pool references are PATCHed whole so a
	// dropped schedule or a dropped pool actually disappears.
	t.Run("Update_sends_schedules_whole", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testAvdScalingPlanNativeID,
			DesiredProperties: avdScalingPlanDesired("conformance-updated"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Len(t, sentUpdate.Properties.Schedules, 1)
		require.Equal(t, 6, sentUpdate.Properties.Schedules[0].RampUpStartTime.Hour())
		require.Len(t, sentUpdate.Properties.HostPoolReferences, 1)
		require.Equal(t, "conformance-updated", *sentUpdate.Tags["env"])
	})

	t.Run("Delete_is_synchronous", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testAvdScalingPlanNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Empty(t, got.ProgressResult.RequestID)
		require.Equal(t, before+1, deleteCalls)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(context.Context, string, string, *armdesktopvirtualization.ScalingPlansClientDeleteOptions) (armdesktopvirtualization.ScalingPlansClientDeleteResponse, error) {
			return armdesktopvirtualization.ScalingPlansClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testAvdScalingPlanNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_resource_group", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testAvdScalingPlanNativeID}, got.NativeIDs)
	})

	t.Run("List_falls_back_to_subscription_wide", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Equal(t, []string{testAvdScalingPlanNativeID}, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure_with_cause", func(t *testing.T) {
		fake.createFn = func(context.Context, string, string, armdesktopvirtualization.ScalingPlan, *armdesktopvirtualization.ScalingPlansClientCreateOptions) (armdesktopvirtualization.ScalingPlansClientCreateResponse, error) {
			return armdesktopvirtualization.ScalingPlansClientCreateResponse{},
				&azcore.ResponseError{StatusCode: 400, ErrorCode: "ScalingPlanRequiresPooledHostPool"}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "sp-1", Properties: avdScalingPlanDesired("conformance"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.Contains(t, got.ProgressResult.StatusMessage, "ScalingPlanRequiresPooledHostPool")
	})
}

func TestAvdScalingPlan_ReadNotFound(t *testing.T) {
	fake := &fakeAvdScalingPlansAPI{
		getFn: func(context.Context, string, string, *armdesktopvirtualization.ScalingPlansClientGetOptions) (armdesktopvirtualization.ScalingPlansClientGetResponse, error) {
			return armdesktopvirtualization.ScalingPlansClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestAvdScalingPlan(fake).Read(context.Background(),
		&resource.ReadRequest{NativeID: testAvdScalingPlanNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeAvdScalingPlansAPI struct {
	createFn                      func(ctx context.Context, rgName, name string, params armdesktopvirtualization.ScalingPlan, options *armdesktopvirtualization.ScalingPlansClientCreateOptions) (armdesktopvirtualization.ScalingPlansClientCreateResponse, error)
	getFn                         func(ctx context.Context, rgName, name string, options *armdesktopvirtualization.ScalingPlansClientGetOptions) (armdesktopvirtualization.ScalingPlansClientGetResponse, error)
	updateFn                      func(ctx context.Context, rgName, name string, options *armdesktopvirtualization.ScalingPlansClientUpdateOptions) (armdesktopvirtualization.ScalingPlansClientUpdateResponse, error)
	deleteFn                      func(ctx context.Context, rgName, name string, options *armdesktopvirtualization.ScalingPlansClientDeleteOptions) (armdesktopvirtualization.ScalingPlansClientDeleteResponse, error)
	newListByResourceGroupPagerFn func(rgName string, options *armdesktopvirtualization.ScalingPlansClientListByResourceGroupOptions) *runtime.Pager[armdesktopvirtualization.ScalingPlansClientListByResourceGroupResponse]
	newListBySubscriptionPagerFn  func(options *armdesktopvirtualization.ScalingPlansClientListBySubscriptionOptions) *runtime.Pager[armdesktopvirtualization.ScalingPlansClientListBySubscriptionResponse]
}

func (f *fakeAvdScalingPlansAPI) Create(ctx context.Context, rgName, name string, params armdesktopvirtualization.ScalingPlan, options *armdesktopvirtualization.ScalingPlansClientCreateOptions) (armdesktopvirtualization.ScalingPlansClientCreateResponse, error) {
	return f.createFn(ctx, rgName, name, params, options)
}

func (f *fakeAvdScalingPlansAPI) Get(ctx context.Context, rgName, name string, options *armdesktopvirtualization.ScalingPlansClientGetOptions) (armdesktopvirtualization.ScalingPlansClientGetResponse, error) {
	return f.getFn(ctx, rgName, name, options)
}

func (f *fakeAvdScalingPlansAPI) Update(ctx context.Context, rgName, name string, options *armdesktopvirtualization.ScalingPlansClientUpdateOptions) (armdesktopvirtualization.ScalingPlansClientUpdateResponse, error) {
	return f.updateFn(ctx, rgName, name, options)
}

func (f *fakeAvdScalingPlansAPI) Delete(ctx context.Context, rgName, name string, options *armdesktopvirtualization.ScalingPlansClientDeleteOptions) (armdesktopvirtualization.ScalingPlansClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, name, options)
}

func (f *fakeAvdScalingPlansAPI) NewListByResourceGroupPager(rgName string, options *armdesktopvirtualization.ScalingPlansClientListByResourceGroupOptions) *runtime.Pager[armdesktopvirtualization.ScalingPlansClientListByResourceGroupResponse] {
	return f.newListByResourceGroupPagerFn(rgName, options)
}

func (f *fakeAvdScalingPlansAPI) NewListBySubscriptionPager(options *armdesktopvirtualization.ScalingPlansClientListBySubscriptionOptions) *runtime.Pager[armdesktopvirtualization.ScalingPlansClientListBySubscriptionResponse] {
	return f.newListBySubscriptionPagerFn(options)
}
