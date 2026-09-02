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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/automation/armautomation"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testAutomationScheduleNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Automation/automationAccounts/aa-1/schedules/sch-1"

func newTestAutomationSchedule(api automationScheduleAPI) *AutomationSchedule {
	return &AutomationSchedule{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func automationScheduleDesired(description string, isEnabled bool, extra map[string]any) []byte {
	props := map[string]any{
		"name":                  "sch-1",
		"resourceGroupName":     "rg-1",
		"automationAccountName": "aa-1",
		"frequency":             "Hour",
		"startTime":             "2030-01-01T00:00:00Z",
		"timeZone":              "UTC",
		"isEnabled":             isEnabled,
		"interval":              1,
		"description":           description,
	}
	for k, v := range extra {
		props[k] = v
	}
	out, _ := json.Marshal(props)
	return out
}

func TestAutomationSchedule_CRUD(t *testing.T) {
	// The response carries what ARM really answers with: an offset-formatted
	// startTime rather than a Z-suffixed one, the year-9999 no-expiry sentinel,
	// interval as an untyped JSON number, and the four derived *OffsetMinutes.
	schResult := armautomation.Schedule{
		ID:   to.Ptr(testAutomationScheduleNativeID),
		Name: to.Ptr("sch-1"),
		Properties: &armautomation.ScheduleProperties{
			Frequency:               to.Ptr(armautomation.ScheduleFrequencyHour),
			StartTime:               to.Ptr(time.Date(2030, 1, 1, 0, 0, 0, 0, time.FixedZone("+02:00", 2*3600)).Add(2 * time.Hour)),
			ExpiryTime:              to.Ptr(time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)),
			TimeZone:                to.Ptr("UTC"),
			IsEnabled:               to.Ptr(true),
			Interval:                float64(1),
			Description:             to.Ptr("Conformance schedule"),
			NextRun:                 to.Ptr(time.Date(2030, 1, 1, 1, 0, 0, 0, time.UTC)),
			StartTimeOffsetMinutes:  to.Ptr(float64(0)),
			ExpiryTimeOffsetMinutes: to.Ptr(float64(0)),
			NextRunOffsetMinutes:    to.Ptr(float64(0)),
			CreationTime:            to.Ptr(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)),
			LastModifiedTime:        to.Ptr(time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)),
		},
	}

	var sentCreate armautomation.ScheduleCreateOrUpdateParameters
	var sentUpdate armautomation.ScheduleUpdateParameters
	deleteCalls := 0
	fake := &fakeAutomationScheduleAPI{
		createOrUpdateFn: func(_ context.Context, rgName, accountName, name string, params armautomation.ScheduleCreateOrUpdateParameters, _ *armautomation.ScheduleClientCreateOrUpdateOptions) (armautomation.ScheduleClientCreateOrUpdateResponse, error) {
			require.Equal(t, "rg-1", rgName)
			require.Equal(t, "aa-1", accountName)
			require.Equal(t, "sch-1", name)
			sentCreate = params
			return armautomation.ScheduleClientCreateOrUpdateResponse{Schedule: schResult}, nil
		},
		getFn: func(context.Context, string, string, string, *armautomation.ScheduleClientGetOptions) (armautomation.ScheduleClientGetResponse, error) {
			return armautomation.ScheduleClientGetResponse{Schedule: schResult}, nil
		},
		updateFn: func(_ context.Context, _, _, _ string, params armautomation.ScheduleUpdateParameters, _ *armautomation.ScheduleClientUpdateOptions) (armautomation.ScheduleClientUpdateResponse, error) {
			sentUpdate = params
			return armautomation.ScheduleClientUpdateResponse{Schedule: schResult}, nil
		},
		deleteFn: func(context.Context, string, string, string, *armautomation.ScheduleClientDeleteOptions) (armautomation.ScheduleClientDeleteResponse, error) {
			deleteCalls++
			return armautomation.ScheduleClientDeleteResponse{}, nil
		},
		newListByAutomationAccountPagerFn: func(rgName, accountName string, _ *armautomation.ScheduleClientListByAutomationAccountOptions) *runtime.Pager[armautomation.ScheduleClientListByAutomationAccountResponse] {
			require.Equal(t, "rg-1", rgName)
			require.Equal(t, "aa-1", accountName)
			return runtime.NewPager(runtime.PagingHandler[armautomation.ScheduleClientListByAutomationAccountResponse]{
				More: func(armautomation.ScheduleClientListByAutomationAccountResponse) bool { return false },
				Fetcher: func(context.Context, *armautomation.ScheduleClientListByAutomationAccountResponse) (armautomation.ScheduleClientListByAutomationAccountResponse, error) {
					return armautomation.ScheduleClientListByAutomationAccountResponse{
						ScheduleListResult: armautomation.ScheduleListResult{
							Value: []*armautomation.Schedule{{ID: to.Ptr(testAutomationScheduleNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestAutomationSchedule(fake)

	t.Run("Create_is_synchronous", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "sch-1",
			Properties: automationScheduleDesired("Conformance schedule", true, nil),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testAutomationScheduleNativeID, got.ProgressResult.NativeID)
		require.Empty(t, got.ProgressResult.RequestID)

		require.Equal(t, armautomation.ScheduleFrequencyHour, *sentCreate.Properties.Frequency)
		require.Equal(t, "2030-01-01T00:00:00Z", sentCreate.Properties.StartTime.UTC().Format(time.RFC3339))
		require.Equal(t, "UTC", *sentCreate.Properties.TimeZone)
		require.Equal(t, int64(1), sentCreate.Properties.Interval)
		// No expiry declared: the field must stay out of the body so ARM applies
		// its own no-expiry sentinel rather than being handed a zero time.
		require.Nil(t, sentCreate.Properties.ExpiryTime)
	})

	t.Run("Create_sends_a_declared_expiry", func(t *testing.T) {
		_, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "sch-1",
			Properties: automationScheduleDesired("Conformance schedule", true, map[string]any{
				"expiryTime": "2031-01-01T00:00:00Z",
			}),
		})
		require.NoError(t, err)
		require.Equal(t, "2031-01-01T00:00:00Z", sentCreate.Properties.ExpiryTime.UTC().Format(time.RFC3339))
	})

	t.Run("Create_rejects_an_unparseable_start_time", func(t *testing.T) {
		_, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "sch-1",
			Properties: automationScheduleDesired("d", true, map[string]any{
				"startTime": "next tuesday",
			}),
		})
		require.ErrorContains(t, err, "startTime")
	})

	t.Run("Create_requires_parents_frequency_and_start", func(t *testing.T) {
		for _, tc := range []struct {
			drop string
			want string
		}{
			{"resourceGroupName", "resourceGroupName is required"},
			{"automationAccountName", "automationAccountName is required"},
			{"frequency", "frequency is required"},
			{"startTime", "startTime is required"},
		} {
			var props map[string]any
			require.NoError(t, json.Unmarshal(automationScheduleDesired("d", true, nil), &props))
			delete(props, tc.drop)
			raw, _ := json.Marshal(props)
			_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: raw})
			require.ErrorContains(t, err, tc.want)
		}
	})

	// The offset-formatted startTime ARM answers with must come back as the same
	// instant in the Z form desired state carries, or every sync reports drift.
	t.Run("Read_normalizes_the_start_time_to_utc", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testAutomationScheduleNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "sch-1", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "aa-1", props["automationAccountName"])
		require.Equal(t, "Hour", props["frequency"])
		require.Equal(t, "2030-01-01T00:00:00Z", props["startTime"])
		require.Equal(t, "UTC", props["timeZone"])
		require.Equal(t, true, props["isEnabled"])
		require.Equal(t, float64(1), props["interval"])
		require.Equal(t, "Conformance schedule", props["description"])
	})

	// ARM answers a schedule with no expiry using 9999-12-31, not null. Echoing
	// that sentinel back would report drift against a forma that never declared
	// an expiry.
	t.Run("Read_drops_the_year_9999_no_expiry_sentinel", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testAutomationScheduleNativeID})
		require.NoError(t, err)
		require.NotContains(t, got.Properties, "expiryTime")
	})

	t.Run("Read_keeps_a_real_expiry", func(t *testing.T) {
		fake.getFn = func(context.Context, string, string, string, *armautomation.ScheduleClientGetOptions) (armautomation.ScheduleClientGetResponse, error) {
			withExpiry := schResult
			propsCopy := *schResult.Properties
			propsCopy.ExpiryTime = to.Ptr(time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC))
			withExpiry.Properties = &propsCopy
			return armautomation.ScheduleClientGetResponse{Schedule: withExpiry}, nil
		}
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testAutomationScheduleNativeID})
		require.NoError(t, err)
		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "2031-01-01T00:00:00Z", props["expiryTime"])
		fake.getFn = func(context.Context, string, string, string, *armautomation.ScheduleClientGetOptions) (armautomation.ScheduleClientGetResponse, error) {
			return armautomation.ScheduleClientGetResponse{Schedule: schResult}, nil
		}
	})

	// nextRun advances with every fired job and the *OffsetMinutes are derived:
	// all four would read back as drift.
	t.Run("Read_drops_derived_and_moving_state", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testAutomationScheduleNativeID})
		require.NoError(t, err)
		for _, key := range []string{"nextRun", "startTimeOffsetMinutes", "expiryTimeOffsetMinutes",
			"nextRunOffsetMinutes", "creationTime", "lastModifiedTime", "advancedSchedule"} {
			require.NotContains(t, got.Properties, key)
		}
	})

	// ScheduleUpdateProperties carries only isEnabled and the description; the
	// recurrence is createOnly, so nothing else may reach the PATCH body.
	t.Run("Update_patches_only_is_enabled_and_description", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testAutomationScheduleNativeID,
			DesiredProperties: automationScheduleDesired("Conformance schedule updated", false, nil),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.False(t, *sentUpdate.Properties.IsEnabled)
		require.Equal(t, "Conformance schedule updated", *sentUpdate.Properties.Description)
	})

	t.Run("Delete_is_synchronous", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testAutomationScheduleNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(context.Context, string, string, string, *armautomation.ScheduleClientDeleteOptions) (armautomation.ScheduleClientDeleteResponse, error) {
			return armautomation.ScheduleClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testAutomationScheduleNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_automation_account", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "automationAccountName": "aa-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testAutomationScheduleNativeID}, got.NativeIDs)
	})

	t.Run("List_without_parents_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure_with_cause", func(t *testing.T) {
		fake.createOrUpdateFn = func(context.Context, string, string, string, armautomation.ScheduleCreateOrUpdateParameters, *armautomation.ScheduleClientCreateOrUpdateOptions) (armautomation.ScheduleClientCreateOrUpdateResponse, error) {
			return armautomation.ScheduleClientCreateOrUpdateResponse{}, &azcore.ResponseError{StatusCode: 400, ErrorCode: "InvalidStartTime"}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "sch-1", Properties: automationScheduleDesired("d", true, nil),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.Contains(t, got.ProgressResult.StatusMessage, "InvalidStartTime")
	})
}

// The SDK types interval as `any` because the wire form is a bare JSON number,
// which arrives as a float64 rather than any integer type.
func TestAutomationScheduleInterval(t *testing.T) {
	for _, tc := range []struct {
		name  string
		raw   any
		want  int64
		wantK bool
	}{
		{"float64", float64(3), 3, true},
		{"int", 4, 4, true},
		{"int32", int32(5), 5, true},
		{"int64", int64(6), 6, true},
		{"nil", nil, 0, false},
		{"string", "7", 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := automationScheduleInterval(tc.raw)
			require.Equal(t, tc.wantK, ok)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestAutomationSchedule_ReadNotFound(t *testing.T) {
	fake := &fakeAutomationScheduleAPI{
		getFn: func(context.Context, string, string, string, *armautomation.ScheduleClientGetOptions) (armautomation.ScheduleClientGetResponse, error) {
			return armautomation.ScheduleClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestAutomationSchedule(fake).Read(context.Background(),
		&resource.ReadRequest{NativeID: testAutomationScheduleNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeAutomationScheduleAPI struct {
	createOrUpdateFn                  func(ctx context.Context, rgName, accountName, name string, params armautomation.ScheduleCreateOrUpdateParameters, options *armautomation.ScheduleClientCreateOrUpdateOptions) (armautomation.ScheduleClientCreateOrUpdateResponse, error)
	getFn                             func(ctx context.Context, rgName, accountName, name string, options *armautomation.ScheduleClientGetOptions) (armautomation.ScheduleClientGetResponse, error)
	updateFn                          func(ctx context.Context, rgName, accountName, name string, params armautomation.ScheduleUpdateParameters, options *armautomation.ScheduleClientUpdateOptions) (armautomation.ScheduleClientUpdateResponse, error)
	deleteFn                          func(ctx context.Context, rgName, accountName, name string, options *armautomation.ScheduleClientDeleteOptions) (armautomation.ScheduleClientDeleteResponse, error)
	newListByAutomationAccountPagerFn func(rgName, accountName string, options *armautomation.ScheduleClientListByAutomationAccountOptions) *runtime.Pager[armautomation.ScheduleClientListByAutomationAccountResponse]
}

func (f *fakeAutomationScheduleAPI) CreateOrUpdate(ctx context.Context, rgName, accountName, name string, params armautomation.ScheduleCreateOrUpdateParameters, options *armautomation.ScheduleClientCreateOrUpdateOptions) (armautomation.ScheduleClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, accountName, name, params, options)
}

func (f *fakeAutomationScheduleAPI) Get(ctx context.Context, rgName, accountName, name string, options *armautomation.ScheduleClientGetOptions) (armautomation.ScheduleClientGetResponse, error) {
	return f.getFn(ctx, rgName, accountName, name, options)
}

func (f *fakeAutomationScheduleAPI) Update(ctx context.Context, rgName, accountName, name string, params armautomation.ScheduleUpdateParameters, options *armautomation.ScheduleClientUpdateOptions) (armautomation.ScheduleClientUpdateResponse, error) {
	return f.updateFn(ctx, rgName, accountName, name, params, options)
}

func (f *fakeAutomationScheduleAPI) Delete(ctx context.Context, rgName, accountName, name string, options *armautomation.ScheduleClientDeleteOptions) (armautomation.ScheduleClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, accountName, name, options)
}

func (f *fakeAutomationScheduleAPI) NewListByAutomationAccountPager(rgName, accountName string, options *armautomation.ScheduleClientListByAutomationAccountOptions) *runtime.Pager[armautomation.ScheduleClientListByAutomationAccountResponse] {
	return f.newListByAutomationAccountPagerFn(rgName, accountName, options)
}
