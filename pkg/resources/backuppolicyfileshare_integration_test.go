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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/recoveryservices/armrecoveryservicesbackup/v4"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testBackupPolicyFileShareNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.RecoveryServices/vaults/rsv-1/backupPolicies/fspol-1"

func newTestBackupPolicyFileShare(api backupProtectionPoliciesAPI, listAPI backupPoliciesListAPI) *BackupPolicyFileShare {
	return &BackupPolicyFileShare{backupPolicyCore: backupPolicyCore{
		api:     api,
		listAPI: listAPI,
		config:  &config.Config{SubscriptionId: "sub-1"},
	}}
}

func backupPolicyFileShareDesired(withDaily bool) []byte {
	props := map[string]any{
		"name":              "fspol-1",
		"resourceGroupName": "rg-1",
		"vaultName":         "rsv-1",
		"timeZone":          "UTC",
		"backupSchedule": map[string]any{
			"frequency": "Daily",
			"times":     []string{"23:00"},
		},
		"weeklyRetention": map[string]any{"count": 4, "daysOfWeek": []string{"Sunday"}},
	}
	if withDaily {
		props["dailyRetention"] = map[string]any{"count": 10}
	}
	out, _ := json.Marshal(props)
	return out
}

func TestBackupPolicyFileShare_CRUD(t *testing.T) {
	runTime := mustBackupTime("23:00")
	result := armrecoveryservicesbackup.ProtectionPolicyResource{
		ID:   to.Ptr(testBackupPolicyFileShareNativeID),
		Name: to.Ptr("fspol-1"),
		Properties: &armrecoveryservicesbackup.AzureFileShareProtectionPolicy{
			BackupManagementType: to.Ptr("AzureStorage"),
			WorkLoadType:         to.Ptr(armrecoveryservicesbackup.WorkloadTypeAzureFileShare),
			TimeZone:             to.Ptr("UTC"),
			SchedulePolicy: &armrecoveryservicesbackup.SimpleSchedulePolicy{
				SchedulePolicyType:   to.Ptr("SimpleSchedulePolicy"),
				ScheduleRunFrequency: to.Ptr(armrecoveryservicesbackup.ScheduleRunTypeDaily),
				ScheduleRunTimes:     []*time.Time{runTime},
			},
			RetentionPolicy: &armrecoveryservicesbackup.LongTermRetentionPolicy{
				RetentionPolicyType: to.Ptr("LongTermRetentionPolicy"),
				DailySchedule: &armrecoveryservicesbackup.DailyRetentionSchedule{
					RetentionTimes:    []*time.Time{runTime},
					RetentionDuration: &armrecoveryservicesbackup.RetentionDuration{Count: to.Ptr(int32(10)), DurationType: to.Ptr(armrecoveryservicesbackup.RetentionDurationTypeDays)},
				},
				WeeklySchedule: &armrecoveryservicesbackup.WeeklyRetentionSchedule{
					RetentionTimes:    []*time.Time{runTime},
					DaysOfTheWeek:     []*armrecoveryservicesbackup.DayOfWeek{to.Ptr(armrecoveryservicesbackup.DayOfWeekSunday)},
					RetentionDuration: &armrecoveryservicesbackup.RetentionDuration{Count: to.Ptr(int32(4)), DurationType: to.Ptr(armrecoveryservicesbackup.RetentionDurationTypeWeeks)},
				},
			},
		},
	}

	var sent armrecoveryservicesbackup.ProtectionPolicyResource
	fake := &fakeBackupProtectionPoliciesAPI{
		createOrUpdateFn: func(_ context.Context, _, _, _ string, params armrecoveryservicesbackup.ProtectionPolicyResource, _ *armrecoveryservicesbackup.ProtectionPoliciesClientCreateOrUpdateOptions) (armrecoveryservicesbackup.ProtectionPoliciesClientCreateOrUpdateResponse, error) {
			sent = params
			return armrecoveryservicesbackup.ProtectionPoliciesClientCreateOrUpdateResponse{ProtectionPolicyResource: result}, nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ *armrecoveryservicesbackup.ProtectionPoliciesClientGetOptions) (armrecoveryservicesbackup.ProtectionPoliciesClientGetResponse, error) {
			return armrecoveryservicesbackup.ProtectionPoliciesClientGetResponse{ProtectionPolicyResource: result}, nil
		},
		beginDeleteFn: func(_ context.Context, _, _, _ string, _ *armrecoveryservicesbackup.ProtectionPoliciesClientBeginDeleteOptions) (*runtime.Poller[armrecoveryservicesbackup.ProtectionPoliciesClientDeleteResponse], error) {
			return newDonePoller(armrecoveryservicesbackup.ProtectionPoliciesClientDeleteResponse{}), nil
		},
	}
	list := &fakeBackupPoliciesListAPI{
		newListPagerFn: func(_, _ string, options *armrecoveryservicesbackup.BackupPoliciesClientListOptions) *runtime.Pager[armrecoveryservicesbackup.BackupPoliciesClientListResponse] {
			require.Equal(t, "backupManagementType eq 'AzureStorage'", *options.Filter)
			return runtime.NewPager(runtime.PagingHandler[armrecoveryservicesbackup.BackupPoliciesClientListResponse]{
				More: func(_ armrecoveryservicesbackup.BackupPoliciesClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armrecoveryservicesbackup.BackupPoliciesClientListResponse) (armrecoveryservicesbackup.BackupPoliciesClientListResponse, error) {
					return armrecoveryservicesbackup.BackupPoliciesClientListResponse{
						ProtectionPolicyResourceList: armrecoveryservicesbackup.ProtectionPolicyResourceList{
							Value: []*armrecoveryservicesbackup.ProtectionPolicyResource{
								{ID: to.Ptr(testBackupPolicyFileShareNativeID), Properties: &armrecoveryservicesbackup.AzureFileShareProtectionPolicy{}},
								// The vault's built-in hourly log policy shares the
								// AzureStorage management type and must be skipped.
								{ID: to.Ptr("/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.RecoveryServices/vaults/rsv-1/backupPolicies/HourlyLogBackup"),
									Properties: &armrecoveryservicesbackup.AzureVMWorkloadProtectionPolicy{}},
							},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestBackupPolicyFileShare(fake, list)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "fspol-1",
			Properties: backupPolicyFileShareDesired(true),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testBackupPolicyFileShareNativeID, got.ProgressResult.NativeID)

		policy := sent.Properties.(*armrecoveryservicesbackup.AzureFileShareProtectionPolicy)
		require.Equal(t, "AzureStorage", *policy.BackupManagementType)
		require.Equal(t, armrecoveryservicesbackup.WorkloadTypeAzureFileShare, *policy.WorkLoadType)

		retention := policy.RetentionPolicy.(*armrecoveryservicesbackup.LongTermRetentionPolicy)
		require.EqualValues(t, 10, *retention.DailySchedule.RetentionDuration.Count)
		require.EqualValues(t, 4, *retention.WeeklySchedule.RetentionDuration.Count)
	})

	// ARM rejects a file share policy without daily retention, so the plugin says
	// so rather than letting the service answer with a 400.
	t.Run("Create_requires_daily_retention", func(t *testing.T) {
		_, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "fspol-1",
			Properties: backupPolicyFileShareDesired(false),
		})
		require.ErrorContains(t, err, "dailyRetention is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testBackupPolicyFileShareNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "fspol-1", props["name"])
		require.Equal(t, "rsv-1", props["vaultName"])
		require.Equal(t, map[string]any{"count": float64(10)}, props["dailyRetention"])
		require.Equal(t, map[string]any{"count": float64(4), "daysOfWeek": []any{"Sunday"}}, props["weeklyRetention"])
		require.NotContains(t, props, "monthlyRetention")
		require.NotContains(t, props, "yearlyRetention")
	})

	t.Run("Update", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testBackupPolicyFileShareNativeID,
			DesiredProperties: backupPolicyFileShareDesired(true),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testBackupPolicyFileShareNativeID, got.ProgressResult.NativeID)
	})

	t.Run("Delete", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testBackupPolicyFileShareNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_keeps_only_file_share_policies", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"vaultName": "rsv-1", "resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testBackupPolicyFileShareNativeID}, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure_with_message", func(t *testing.T) {
		fake.createOrUpdateFn = func(_ context.Context, _, _, _ string, _ armrecoveryservicesbackup.ProtectionPolicyResource, _ *armrecoveryservicesbackup.ProtectionPoliciesClientCreateOrUpdateOptions) (armrecoveryservicesbackup.ProtectionPoliciesClientCreateOrUpdateResponse, error) {
			return armrecoveryservicesbackup.ProtectionPoliciesClientCreateOrUpdateResponse{}, &azcore.ResponseError{StatusCode: 403, ErrorCode: "AuthorizationFailed"}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "fspol-1", Properties: backupPolicyFileShareDesired(true)})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.Equal(t, resource.OperationErrorCodeAccessDenied, got.ProgressResult.ErrorCode)
		require.Contains(t, got.ProgressResult.StatusMessage, "AuthorizationFailed")
	})
}

func TestBackupPolicyFileShare_ReadNotFound(t *testing.T) {
	fake := &fakeBackupProtectionPoliciesAPI{
		getFn: func(_ context.Context, _, _, _ string, _ *armrecoveryservicesbackup.ProtectionPoliciesClientGetOptions) (armrecoveryservicesbackup.ProtectionPoliciesClientGetResponse, error) {
			return armrecoveryservicesbackup.ProtectionPoliciesClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestBackupPolicyFileShare(fake, nil).Read(context.Background(), &resource.ReadRequest{NativeID: testBackupPolicyFileShareNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}
