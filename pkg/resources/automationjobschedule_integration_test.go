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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/automation/armautomation"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testAutomationJobScheduleGUID = "3f7c9e1a-5b2d-4c8e-9a6f-1d2e3b4c5d6e"

const testAutomationJobScheduleNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Automation/" +
	"automationAccounts/aa-1/jobSchedules/" + testAutomationJobScheduleGUID

func newTestAutomationJobSchedule(api automationJobScheduleAPI) *AutomationJobSchedule {
	return &AutomationJobSchedule{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func automationJobScheduleDesired(extra map[string]any) []byte {
	props := map[string]any{
		"name":                  testAutomationJobScheduleGUID,
		"resourceGroupName":     "rg-1",
		"automationAccountName": "aa-1",
		"runbookName":           "rb-1",
		"scheduleName":          "sch-1",
	}
	for k, v := range extra {
		props[k] = v
	}
	out, _ := json.Marshal(props)
	return out
}

func TestAutomationJobSchedule_CRUD(t *testing.T) {
	// ARM leaves the envelope name unset on this type and reports the GUID only
	// as properties.jobScheduleId, which is why the read path has to fall back.
	jsResult := armautomation.JobSchedule{
		ID: to.Ptr(testAutomationJobScheduleNativeID),
		Properties: &armautomation.JobScheduleProperties{
			JobScheduleID: to.Ptr(testAutomationJobScheduleGUID),
			Runbook:       &armautomation.RunbookAssociationProperty{Name: to.Ptr("rb-1")},
			Schedule:      &armautomation.ScheduleAssociationProperty{Name: to.Ptr("sch-1")},
		},
	}

	var sentCreate armautomation.JobScheduleCreateParameters
	var sawJobScheduleID string
	deleteCalls := 0
	fake := &fakeAutomationJobScheduleAPI{
		createFn: func(_ context.Context, rgName, accountName, jobScheduleID string, params armautomation.JobScheduleCreateParameters, _ *armautomation.JobScheduleClientCreateOptions) (armautomation.JobScheduleClientCreateResponse, error) {
			require.Equal(t, "rg-1", rgName)
			require.Equal(t, "aa-1", accountName)
			sawJobScheduleID = jobScheduleID
			sentCreate = params
			return armautomation.JobScheduleClientCreateResponse{JobSchedule: jsResult}, nil
		},
		getFn: func(context.Context, string, string, string, *armautomation.JobScheduleClientGetOptions) (armautomation.JobScheduleClientGetResponse, error) {
			return armautomation.JobScheduleClientGetResponse{JobSchedule: jsResult}, nil
		},
		deleteFn: func(context.Context, string, string, string, *armautomation.JobScheduleClientDeleteOptions) (armautomation.JobScheduleClientDeleteResponse, error) {
			deleteCalls++
			return armautomation.JobScheduleClientDeleteResponse{}, nil
		},
		newListByAutomationAccountPagerFn: func(rgName, accountName string, _ *armautomation.JobScheduleClientListByAutomationAccountOptions) *runtime.Pager[armautomation.JobScheduleClientListByAutomationAccountResponse] {
			require.Equal(t, "rg-1", rgName)
			require.Equal(t, "aa-1", accountName)
			return runtime.NewPager(runtime.PagingHandler[armautomation.JobScheduleClientListByAutomationAccountResponse]{
				More: func(armautomation.JobScheduleClientListByAutomationAccountResponse) bool { return false },
				Fetcher: func(context.Context, *armautomation.JobScheduleClientListByAutomationAccountResponse) (armautomation.JobScheduleClientListByAutomationAccountResponse, error) {
					return armautomation.JobScheduleClientListByAutomationAccountResponse{
						JobScheduleListResult: armautomation.JobScheduleListResult{
							Value: []*armautomation.JobSchedule{{ID: to.Ptr(testAutomationJobScheduleNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestAutomationJobSchedule(fake)

	// The name IS the jobScheduleId: it has to reach the URL segment, not just
	// the body.
	t.Run("Create_uses_the_name_as_the_job_schedule_id", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "js-1",
			Properties: automationJobScheduleDesired(nil),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testAutomationJobScheduleNativeID, got.ProgressResult.NativeID)
		require.Empty(t, got.ProgressResult.RequestID)

		require.Equal(t, testAutomationJobScheduleGUID, sawJobScheduleID)
		require.Equal(t, "rb-1", *sentCreate.Properties.Runbook.Name)
		require.Equal(t, "sch-1", *sentCreate.Properties.Schedule.Name)
		// Neither optional was declared, so both must stay out of the body.
		require.Nil(t, sentCreate.Properties.RunOn)
		require.Nil(t, sentCreate.Properties.Parameters)
	})

	// The entity-set shaped `parameters` listing has to reach ARM as the flat
	// map it expects.
	t.Run("Create_flattens_the_parameters_entity_set", func(t *testing.T) {
		_, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "js-1",
			Properties: automationJobScheduleDesired(map[string]any{
				"runOn": "hybrid-group-1",
				"parameters": []map[string]string{
					{"Key": "vmName", "Value": "vm-1"},
					{"Key": "resourceGroup", "Value": "rg-9"},
				},
			}),
		})
		require.NoError(t, err)
		require.Equal(t, "hybrid-group-1", *sentCreate.Properties.RunOn)
		require.Len(t, sentCreate.Properties.Parameters, 2)
		require.Equal(t, "vm-1", *sentCreate.Properties.Parameters["vmName"])
		require.Equal(t, "rg-9", *sentCreate.Properties.Parameters["resourceGroup"])
	})

	t.Run("Create_requires_parents_runbook_and_schedule", func(t *testing.T) {
		for _, tc := range []struct {
			drop string
			want string
		}{
			{"resourceGroupName", "resourceGroupName is required"},
			{"automationAccountName", "automationAccountName is required"},
			{"runbookName", "runbookName is required"},
			{"scheduleName", "scheduleName is required"},
		} {
			var props map[string]any
			require.NoError(t, json.Unmarshal(automationJobScheduleDesired(nil), &props))
			delete(props, tc.drop)
			raw, _ := json.Marshal(props)
			_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: raw})
			require.ErrorContains(t, err, tc.want)
		}
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testAutomationJobScheduleNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		// name comes from properties.jobScheduleId because ARM leaves the
		// envelope name unset here.
		require.Equal(t, testAutomationJobScheduleGUID, props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "aa-1", props["automationAccountName"])
		require.Equal(t, "rb-1", props["runbookName"])
		require.Equal(t, "sch-1", props["scheduleName"])
	})

	// jobScheduleId is the same value as name; emitting both would be an
	// undeclared property and fail the comparison.
	t.Run("Read_does_not_emit_job_schedule_id", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testAutomationJobScheduleNativeID})
		require.NoError(t, err)
		require.NotContains(t, got.Properties, "jobScheduleId")
		require.NotContains(t, got.Properties, "jobScheduleID")
	})

	// Neither optional was set, so ARM answers with an empty parameter map and a
	// null runOn: both must stay out of the read so an undeclared optional does
	// not read as drift.
	t.Run("Read_omits_unset_optionals", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testAutomationJobScheduleNativeID})
		require.NoError(t, err)
		require.NotContains(t, got.Properties, "runOn")
		require.NotContains(t, got.Properties, "parameters")
	})

	// The whole point of this type: ARM exposes no update verb, so Update must
	// refuse loudly with the cause on StatusMessage rather than silently
	// no-op'ing and letting core believe the change landed.
	t.Run("Update_refuses_because_the_type_is_immutable", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testAutomationJobScheduleNativeID,
			DesiredProperties: automationJobScheduleDesired(map[string]any{"runOn": "hybrid-group-2"}),
		})
		require.Error(t, err)
		require.ErrorContains(t, err, "immutable")
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.Equal(t, resource.OperationErrorCodeGeneralServiceException, got.ProgressResult.ErrorCode)
		require.Contains(t, got.ProgressResult.StatusMessage, "no update verb")
		require.Equal(t, testAutomationJobScheduleNativeID, got.ProgressResult.NativeID)
	})

	t.Run("Delete_is_synchronous", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testAutomationJobScheduleNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
	})

	// A replace deletes before it recreates, so a 404 on the delete leg has to
	// be success or every replace fails on the second attempt.
	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(context.Context, string, string, string, *armautomation.JobScheduleClientDeleteOptions) (armautomation.JobScheduleClientDeleteResponse, error) {
			return armautomation.JobScheduleClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testAutomationJobScheduleNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_automation_account", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "automationAccountName": "aa-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testAutomationJobScheduleNativeID}, got.NativeIDs)
	})

	t.Run("List_without_parents_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})

	// The most likely live failure for this type: attaching a runbook that was
	// created as a draft and never published.
	t.Run("Azure_error_maps_to_failure_with_cause", func(t *testing.T) {
		fake.createFn = func(context.Context, string, string, string, armautomation.JobScheduleCreateParameters, *armautomation.JobScheduleClientCreateOptions) (armautomation.JobScheduleClientCreateResponse, error) {
			return armautomation.JobScheduleClientCreateResponse{}, &azcore.ResponseError{StatusCode: 400, ErrorCode: "RunbookNotPublished"}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "js-1", Properties: automationJobScheduleDesired(nil),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.Contains(t, got.ProgressResult.StatusMessage, "RunbookNotPublished")
	})
}

// ARM's mixed-case "jobSchedules" segment must still parse: armIDParts matches
// case-insensitively, which is why the handler passes the lowercase form.
func TestAutomationJobScheduleIDParts(t *testing.T) {
	rgName, accountName, name, err := automationJobScheduleIDParts(testAutomationJobScheduleNativeID)
	require.NoError(t, err)
	require.Equal(t, "rg-1", rgName)
	require.Equal(t, "aa-1", accountName)
	require.Equal(t, testAutomationJobScheduleGUID, name)
}

func TestAutomationJobSchedule_ReadNotFound(t *testing.T) {
	fake := &fakeAutomationJobScheduleAPI{
		getFn: func(context.Context, string, string, string, *armautomation.JobScheduleClientGetOptions) (armautomation.JobScheduleClientGetResponse, error) {
			return armautomation.JobScheduleClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestAutomationJobSchedule(fake).Read(context.Background(),
		&resource.ReadRequest{NativeID: testAutomationJobScheduleNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeAutomationJobScheduleAPI struct {
	createFn                          func(ctx context.Context, rgName, accountName, jobScheduleID string, params armautomation.JobScheduleCreateParameters, options *armautomation.JobScheduleClientCreateOptions) (armautomation.JobScheduleClientCreateResponse, error)
	getFn                             func(ctx context.Context, rgName, accountName, jobScheduleID string, options *armautomation.JobScheduleClientGetOptions) (armautomation.JobScheduleClientGetResponse, error)
	deleteFn                          func(ctx context.Context, rgName, accountName, jobScheduleID string, options *armautomation.JobScheduleClientDeleteOptions) (armautomation.JobScheduleClientDeleteResponse, error)
	newListByAutomationAccountPagerFn func(rgName, accountName string, options *armautomation.JobScheduleClientListByAutomationAccountOptions) *runtime.Pager[armautomation.JobScheduleClientListByAutomationAccountResponse]
}

func (f *fakeAutomationJobScheduleAPI) Create(ctx context.Context, rgName, accountName, jobScheduleID string, params armautomation.JobScheduleCreateParameters, options *armautomation.JobScheduleClientCreateOptions) (armautomation.JobScheduleClientCreateResponse, error) {
	return f.createFn(ctx, rgName, accountName, jobScheduleID, params, options)
}

func (f *fakeAutomationJobScheduleAPI) Get(ctx context.Context, rgName, accountName, jobScheduleID string, options *armautomation.JobScheduleClientGetOptions) (armautomation.JobScheduleClientGetResponse, error) {
	return f.getFn(ctx, rgName, accountName, jobScheduleID, options)
}

func (f *fakeAutomationJobScheduleAPI) Delete(ctx context.Context, rgName, accountName, jobScheduleID string, options *armautomation.JobScheduleClientDeleteOptions) (armautomation.JobScheduleClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, accountName, jobScheduleID, options)
}

func (f *fakeAutomationJobScheduleAPI) NewListByAutomationAccountPager(rgName, accountName string, options *armautomation.JobScheduleClientListByAutomationAccountOptions) *runtime.Pager[armautomation.JobScheduleClientListByAutomationAccountResponse] {
	return f.newListByAutomationAccountPagerFn(rgName, accountName, options)
}
