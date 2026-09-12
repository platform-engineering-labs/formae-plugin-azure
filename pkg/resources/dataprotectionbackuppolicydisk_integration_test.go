// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/dataprotection/armdataprotection/v3"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

// The fake client and the shared props builders live in
// dataprotectionbackuppolicyblobstorage_integration_test.go.

func TestDataProtectionBackupPolicyDisk_CRUD(t *testing.T) {
	const name = "bp-disk-1"
	nativeID := dpPolicyNativeID("bv-1", name)

	var sent armdataprotection.BaseBackupPolicyResource
	fake := dpPolicyEcho(t, nativeID, name, &sent)
	prov := dpPolicyProvisioner(fake,
		ResourceTypeDataProtectionBackupPolicyDisk,
		datasourceDataProtectionBackupPolicyDisk)

	// ARM's own disk template: Incremental, OperationalStore, PT4H, no timeZone.
	desired := dpScheduledProps(name, "Incremental", "OperationalStore",
		"R/2024-01-01T13:00:00+00:00/PT4H", "", "P7D")

	t.Run("Create sends a schedule-based trigger and the disk datasource", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Label: name, Properties: desired})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)

		policy := sent.Properties.(*armdataprotection.BackupPolicy)
		require.Equal(t, "Microsoft.Compute/disks", *policy.DatasourceTypes[0])
		require.Len(t, policy.PolicyRules, 2)

		backup, ok := policy.PolicyRules[0].(*armdataprotection.AzureBackupRule)
		require.True(t, ok, "backup rules are emitted before retention rules")
		require.Equal(t, "AzureBackupRule", *backup.ObjectType)
		require.Equal(t, armdataprotection.DataStoreTypesOperationalStore, *backup.DataStore.DataStoreType)

		params, ok := backup.BackupParameters.(*armdataprotection.AzureBackupParams)
		require.True(t, ok)
		require.Equal(t, "Incremental", *params.BackupType)

		trigger, ok := backup.Trigger.(*armdataprotection.ScheduleBasedTriggerContext)
		require.True(t, ok)
		require.Equal(t, "ScheduleBasedTriggerContext", *trigger.ObjectType)
		require.Len(t, trigger.Schedule.RepeatingTimeIntervals, 1)
		require.Equal(t, "R/2024-01-01T13:00:00+00:00/PT4H", *trigger.Schedule.RepeatingTimeIntervals[0])
		// timeZone was not declared, so nothing is sent and ARM fills in UTC —
		// which is why the nested field carries hasProviderDefault.
		require.Nil(t, trigger.Schedule.TimeZone)

		require.Len(t, trigger.TaggingCriteria, 1)
		require.Equal(t, "Default", *trigger.TaggingCriteria[0].TagInfo.TagName)
		require.True(t, *trigger.TaggingCriteria[0].IsDefault)
		require.Equal(t, int64(99), *trigger.TaggingCriteria[0].TaggingPriority)
		// A default criterion carries no criteria; ARM rejects one that does.
		require.Empty(t, trigger.TaggingCriteria[0].Criteria)

		_, ok = policy.PolicyRules[1].(*armdataprotection.AzureRetentionRule)
		require.True(t, ok)
	})

	t.Run("Read splits the polymorphic rule list back into two typed lists", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: nativeID})
		require.NoError(t, err)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))

		backupRules := props["backupRules"].([]any)
		require.Len(t, backupRules, 1)
		rule := backupRules[0].(map[string]any)
		require.Equal(t, "BackupRule", rule["name"])
		require.Equal(t, "Incremental", rule["backupType"])
		require.Equal(t, "OperationalStore", rule["datastoreType"])
		require.NotContains(t, rule, "timeZone", "an unset timeZone must not read back")

		criteria := rule["taggingCriteria"].([]any)
		require.Len(t, criteria, 1)
		require.Equal(t, "Default", criteria[0].(map[string]any)["tagName"])
		require.NotContains(t, criteria[0].(map[string]any), "absoluteCriteria")

		require.Len(t, props["retentionRules"].([]any), 1)
	})

	t.Run("An absoluteCriteria marker becomes a ScheduleBasedBackupCriteria", func(t *testing.T) {
		var raw map[string]any
		require.NoError(t, json.Unmarshal(desired, &raw))
		rule := raw["backupRules"].([]any)[0].(map[string]any)
		rule["taggingCriteria"].([]any)[0].(map[string]any)["isDefault"] = false
		rule["taggingCriteria"].([]any)[0].(map[string]any)["tagName"] = "Daily"
		rule["taggingCriteria"].([]any)[0].(map[string]any)["absoluteCriteria"] = []string{"FirstOfDay"}
		withMarker, err := json.Marshal(raw)
		require.NoError(t, err)

		_, err = prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          nativeID,
			DesiredProperties: withMarker,
		})
		require.NoError(t, err)

		policy := sent.Properties.(*armdataprotection.BackupPolicy)
		trigger := policy.PolicyRules[0].(*armdataprotection.AzureBackupRule).Trigger.(*armdataprotection.ScheduleBasedTriggerContext)
		require.Len(t, trigger.TaggingCriteria[0].Criteria, 1)
		sched, ok := trigger.TaggingCriteria[0].Criteria[0].(*armdataprotection.ScheduleBasedBackupCriteria)
		require.True(t, ok)
		require.Equal(t, armdataprotection.AbsoluteMarkerFirstOfDay, *sched.AbsoluteCriteria[0])

		read, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: nativeID})
		require.NoError(t, err)
		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(read.Properties), &props))
		criteria := props["backupRules"].([]any)[0].(map[string]any)["taggingCriteria"].([]any)[0].(map[string]any)
		require.Equal(t, []any{"FirstOfDay"}, criteria["absoluteCriteria"])
	})

	t.Run("List returns only disk policies", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "vaultName": "bv-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{nativeID}, got.NativeIDs)
	})

	t.Run("Delete succeeds", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: nativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Status re-reads the policy, because every verb is synchronous", func(t *testing.T) {
		got, err := prov.Status(context.Background(), &resource.StatusRequest{
			NativeID:  nativeID,
			RequestID: "not-an-lro-token",
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, nativeID, got.ProgressResult.NativeID)
	})
}

func TestDataProtectionBackupPolicyDisk_Registration(t *testing.T) {
	require.Equal(t, "AZURE::DataProtection::BackupPolicyDisk", ResourceTypeDataProtectionBackupPolicyDisk)
	require.Equal(t, "Microsoft.Compute/disks", datasourceDataProtectionBackupPolicyDisk)
}
