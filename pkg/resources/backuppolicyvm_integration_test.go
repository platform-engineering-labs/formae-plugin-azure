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

const testBackupPolicyVMNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.RecoveryServices/vaults/rsv-1/backupPolicies/vmpol-1"

func newTestBackupPolicyVM(api backupProtectionPoliciesAPI, listAPI backupPoliciesListAPI) *BackupPolicyVM {
	return &BackupPolicyVM{backupPolicyCore: backupPolicyCore{
		api:     api,
		listAPI: listAPI,
		config:  &config.Config{SubscriptionId: "sub-1"},
	}}
}

func backupPolicyVMDesired(dailyCount int, times ...string) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":                          "vmpol-1",
		"resourceGroupName":             "rg-1",
		"vaultName":                     "rsv-1",
		"timeZone":                      "UTC",
		"instantRpRetentionRangeInDays": 2,
		"backupSchedule": map[string]any{
			"frequency": "Daily",
			"times":     times,
		},
		"dailyRetention": map[string]any{"count": dailyCount},
	})
	return out
}

func vmPolicyResult() armrecoveryservicesbackup.ProtectionPolicyResource {
	runTime := mustBackupTime("23:00")
	return armrecoveryservicesbackup.ProtectionPolicyResource{
		ID:   to.Ptr(testBackupPolicyVMNativeID),
		Name: to.Ptr("vmpol-1"),
		Properties: &armrecoveryservicesbackup.AzureIaaSVMProtectionPolicy{
			BackupManagementType:          to.Ptr("AzureIaasVM"),
			PolicyType:                    to.Ptr(armrecoveryservicesbackup.IAASVMPolicyTypeV1),
			TimeZone:                      to.Ptr("UTC"),
			InstantRpRetentionRangeInDays: to.Ptr(int32(2)),
			ProtectedItemsCount:           to.Ptr(int32(3)),
			SchedulePolicy: &armrecoveryservicesbackup.SimpleSchedulePolicy{
				SchedulePolicyType:   to.Ptr("SimpleSchedulePolicy"),
				ScheduleRunFrequency: to.Ptr(armrecoveryservicesbackup.ScheduleRunTypeDaily),
				ScheduleRunTimes:     []*time.Time{runTime},
			},
			RetentionPolicy: &armrecoveryservicesbackup.LongTermRetentionPolicy{
				RetentionPolicyType: to.Ptr("LongTermRetentionPolicy"),
				DailySchedule: &armrecoveryservicesbackup.DailyRetentionSchedule{
					RetentionTimes: []*time.Time{runTime},
					RetentionDuration: &armrecoveryservicesbackup.RetentionDuration{
						Count:        to.Ptr(int32(7)),
						DurationType: to.Ptr(armrecoveryservicesbackup.RetentionDurationTypeDays),
					},
				},
			},
		},
	}
}

func TestBackupPolicyVM_CRUD(t *testing.T) {
	result := vmPolicyResult()

	var sent armrecoveryservicesbackup.ProtectionPolicyResource
	fake := &fakeBackupProtectionPoliciesAPI{
		createOrUpdateFn: func(_ context.Context, vaultName, rgName, policyName string, params armrecoveryservicesbackup.ProtectionPolicyResource, _ *armrecoveryservicesbackup.ProtectionPoliciesClientCreateOrUpdateOptions) (armrecoveryservicesbackup.ProtectionPoliciesClientCreateOrUpdateResponse, error) {
			require.Equal(t, "rsv-1", vaultName)
			require.Equal(t, "rg-1", rgName)
			require.Equal(t, "vmpol-1", policyName)
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
			require.NotNil(t, options.Filter)
			require.Equal(t, "backupManagementType eq 'AzureIaasVM'", *options.Filter)
			return runtime.NewPager(runtime.PagingHandler[armrecoveryservicesbackup.BackupPoliciesClientListResponse]{
				More: func(_ armrecoveryservicesbackup.BackupPoliciesClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armrecoveryservicesbackup.BackupPoliciesClientListResponse) (armrecoveryservicesbackup.BackupPoliciesClientListResponse, error) {
					return armrecoveryservicesbackup.BackupPoliciesClientListResponse{
						ProtectionPolicyResourceList: armrecoveryservicesbackup.ProtectionPolicyResourceList{
							Value: []*armrecoveryservicesbackup.ProtectionPolicyResource{
								{ID: to.Ptr(testBackupPolicyVMNativeID), Properties: &armrecoveryservicesbackup.AzureIaaSVMProtectionPolicy{}},
								// A different shape under the same management type
								// must not be picked up.
								{ID: to.Ptr("/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.RecoveryServices/vaults/rsv-1/backupPolicies/other"),
									Properties: &armrecoveryservicesbackup.AzureFileShareProtectionPolicy{}},
							},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestBackupPolicyVM(fake, list)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "vmpol-1",
			Properties: backupPolicyVMDesired(7, "23:00"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testBackupPolicyVMNativeID, got.ProgressResult.NativeID)

		policy := sent.Properties.(*armrecoveryservicesbackup.AzureIaaSVMProtectionPolicy)
		require.Equal(t, "AzureIaasVM", *policy.BackupManagementType)
		require.Equal(t, armrecoveryservicesbackup.IAASVMPolicyTypeV1, *policy.PolicyType)

		schedule := policy.SchedulePolicy.(*armrecoveryservicesbackup.SimpleSchedulePolicy)
		require.Equal(t, armrecoveryservicesbackup.ScheduleRunTypeDaily, *schedule.ScheduleRunFrequency)
		require.Len(t, schedule.ScheduleRunTimes, 1)
		require.Equal(t, "23:00", schedule.ScheduleRunTimes[0].UTC().Format("15:04"))

		// ARM rejects a policy whose retention times differ from its schedule
		// times, so the plugin derives one from the other.
		retention := policy.RetentionPolicy.(*armrecoveryservicesbackup.LongTermRetentionPolicy)
		require.Equal(t, schedule.ScheduleRunTimes, retention.DailySchedule.RetentionTimes)
		require.EqualValues(t, 7, *retention.DailySchedule.RetentionDuration.Count)
	})

	t.Run("Create_rejects_a_time_off_the_half_hour", func(t *testing.T) {
		_, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "vmpol-1",
			Properties: backupPolicyVMDesired(7, "23:17"),
		})
		require.ErrorContains(t, err, "must be HH:MM")
	})

	t.Run("Create_requires_a_retention_schedule", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "vmpol-1", "resourceGroupName": "rg-1", "vaultName": "rsv-1",
			"backupSchedule": map[string]any{"frequency": "Daily", "times": []string{"23:00"}},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "at least one retention schedule")
	})

	t.Run("Create_weekly_requires_days", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "vmpol-1", "resourceGroupName": "rg-1", "vaultName": "rsv-1",
			"backupSchedule":  map[string]any{"frequency": "Weekly", "times": []string{"23:00"}},
			"weeklyRetention": map[string]any{"count": 4, "daysOfWeek": []string{"Sunday"}},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "daysOfWeek is required when frequency is Weekly")
	})

	t.Run("Create_requires_vault", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "vmpol-1", "resourceGroupName": "rg-1"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "vaultName is required")
	})

	t.Run("Read_keeps_only_the_time_of_day", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testBackupPolicyVMNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "vmpol-1", props["name"])
		require.Equal(t, "rsv-1", props["vaultName"])
		require.Equal(t, "UTC", props["timeZone"])
		schedule := props["backupSchedule"].(map[string]any)
		require.Equal(t, "Daily", schedule["frequency"])
		require.Equal(t, []any{"23:00"}, schedule["times"])
		// Daily schedules carry no run days; the key must be absent rather than
		// null, because hasProviderDefault does not apply inside a nested class.
		require.NotContains(t, schedule, "daysOfWeek")
		require.Equal(t, map[string]any{"count": float64(7)}, props["dailyRetention"])
		require.NotContains(t, props, "protectedItemsCount")
	})

	t.Run("Update", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testBackupPolicyVMNativeID,
			DesiredProperties: backupPolicyVMDesired(14, "22:30"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testBackupPolicyVMNativeID, got.ProgressResult.NativeID)

		policy := sent.Properties.(*armrecoveryservicesbackup.AzureIaaSVMProtectionPolicy)
		schedule := policy.SchedulePolicy.(*armrecoveryservicesbackup.SimpleSchedulePolicy)
		require.Equal(t, "22:30", schedule.ScheduleRunTimes[0].UTC().Format("15:04"))
	})

	t.Run("Delete", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testBackupPolicyVMNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _, _ string, _ *armrecoveryservicesbackup.ProtectionPoliciesClientBeginDeleteOptions) (*runtime.Poller[armrecoveryservicesbackup.ProtectionPoliciesClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testBackupPolicyVMNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_keeps_only_VM_policies", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"vaultName": "rsv-1", "resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testBackupPolicyVMNativeID}, got.NativeIDs)
	})

	t.Run("List_needs_the_vault_coordinates", func(t *testing.T) {
		_, err := prov.List(context.Background(), &resource.ListRequest{})
		require.ErrorContains(t, err, "vaultName and resourceGroupName are required")
	})

	t.Run("Azure_error_maps_to_failure_with_message", func(t *testing.T) {
		fake.createOrUpdateFn = func(_ context.Context, _, _, _ string, _ armrecoveryservicesbackup.ProtectionPolicyResource, _ *armrecoveryservicesbackup.ProtectionPoliciesClientCreateOrUpdateOptions) (armrecoveryservicesbackup.ProtectionPoliciesClientCreateOrUpdateResponse, error) {
			return armrecoveryservicesbackup.ProtectionPoliciesClientCreateOrUpdateResponse{}, &azcore.ResponseError{StatusCode: 400, ErrorCode: "InvalidPolicyInput"}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "vmpol-1", Properties: backupPolicyVMDesired(7, "23:00")})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.Contains(t, got.ProgressResult.StatusMessage, "InvalidPolicyInput")
	})
}

// A 202 from ARM carries no body, so the write cannot report success yet and the
// operation has to be finished by reading the policy back.
func TestBackupPolicyVM_AcceptedWriteIsPolledByGet(t *testing.T) {
	result := vmPolicyResult()
	notFound := true
	fake := &fakeBackupProtectionPoliciesAPI{
		createOrUpdateFn: func(_ context.Context, _, _, _ string, _ armrecoveryservicesbackup.ProtectionPolicyResource, _ *armrecoveryservicesbackup.ProtectionPoliciesClientCreateOrUpdateOptions) (armrecoveryservicesbackup.ProtectionPoliciesClientCreateOrUpdateResponse, error) {
			return armrecoveryservicesbackup.ProtectionPoliciesClientCreateOrUpdateResponse{}, nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ *armrecoveryservicesbackup.ProtectionPoliciesClientGetOptions) (armrecoveryservicesbackup.ProtectionPoliciesClientGetResponse, error) {
			if notFound {
				notFound = false
				return armrecoveryservicesbackup.ProtectionPoliciesClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
			}
			return armrecoveryservicesbackup.ProtectionPoliciesClientGetResponse{ProtectionPolicyResource: result}, nil
		},
	}
	prov := newTestBackupPolicyVM(fake, nil)

	created, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "vmpol-1", Properties: backupPolicyVMDesired(7, "23:00")})
	require.NoError(t, err)
	require.Equal(t, resource.OperationStatusInProgress, created.ProgressResult.OperationStatus)
	require.Equal(t, testBackupPolicyVMNativeID, created.ProgressResult.NativeID)

	req := &resource.StatusRequest{RequestID: created.ProgressResult.RequestID, NativeID: created.ProgressResult.NativeID}

	pending, err := prov.Status(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, resource.OperationStatusInProgress, pending.ProgressResult.OperationStatus)

	done, err := prov.Status(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, resource.OperationStatusSuccess, done.ProgressResult.OperationStatus)
	require.Equal(t, testBackupPolicyVMNativeID, done.ProgressResult.NativeID)
}

// --- Test helpers ---

func mustBackupTime(hhmm string) *time.Time {
	times, err := backupPolicyTimes([]string{hhmm})
	if err != nil {
		panic(err)
	}
	return times[0]
}

type fakeBackupProtectionPoliciesAPI struct {
	createOrUpdateFn func(ctx context.Context, vaultName, rgName, policyName string, params armrecoveryservicesbackup.ProtectionPolicyResource, options *armrecoveryservicesbackup.ProtectionPoliciesClientCreateOrUpdateOptions) (armrecoveryservicesbackup.ProtectionPoliciesClientCreateOrUpdateResponse, error)
	getFn            func(ctx context.Context, vaultName, rgName, policyName string, options *armrecoveryservicesbackup.ProtectionPoliciesClientGetOptions) (armrecoveryservicesbackup.ProtectionPoliciesClientGetResponse, error)
	beginDeleteFn    func(ctx context.Context, vaultName, rgName, policyName string, options *armrecoveryservicesbackup.ProtectionPoliciesClientBeginDeleteOptions) (*runtime.Poller[armrecoveryservicesbackup.ProtectionPoliciesClientDeleteResponse], error)
}

func (f *fakeBackupProtectionPoliciesAPI) CreateOrUpdate(ctx context.Context, vaultName, rgName, policyName string, params armrecoveryservicesbackup.ProtectionPolicyResource, options *armrecoveryservicesbackup.ProtectionPoliciesClientCreateOrUpdateOptions) (armrecoveryservicesbackup.ProtectionPoliciesClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, vaultName, rgName, policyName, params, options)
}

func (f *fakeBackupProtectionPoliciesAPI) Get(ctx context.Context, vaultName, rgName, policyName string, options *armrecoveryservicesbackup.ProtectionPoliciesClientGetOptions) (armrecoveryservicesbackup.ProtectionPoliciesClientGetResponse, error) {
	return f.getFn(ctx, vaultName, rgName, policyName, options)
}

func (f *fakeBackupProtectionPoliciesAPI) BeginDelete(ctx context.Context, vaultName, rgName, policyName string, options *armrecoveryservicesbackup.ProtectionPoliciesClientBeginDeleteOptions) (*runtime.Poller[armrecoveryservicesbackup.ProtectionPoliciesClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, vaultName, rgName, policyName, options)
}

type fakeBackupPoliciesListAPI struct {
	newListPagerFn func(vaultName, rgName string, options *armrecoveryservicesbackup.BackupPoliciesClientListOptions) *runtime.Pager[armrecoveryservicesbackup.BackupPoliciesClientListResponse]
}

func (f *fakeBackupPoliciesListAPI) NewListPager(vaultName, rgName string, options *armrecoveryservicesbackup.BackupPoliciesClientListOptions) *runtime.Pager[armrecoveryservicesbackup.BackupPoliciesClientListResponse] {
	return f.newListPagerFn(vaultName, rgName, options)
}
