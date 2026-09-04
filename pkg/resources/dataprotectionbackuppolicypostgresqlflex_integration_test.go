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

func TestDataProtectionBackupPolicyPostgreSqlFlexibleServer_CRUD(t *testing.T) {
	const name = "bp-pg-1"
	nativeID := dpPolicyNativeID("bv-1", name)

	var sent armdataprotection.BaseBackupPolicyResource
	fake := dpPolicyEcho(t, nativeID, name, &sent)
	prov := dpPolicyProvisioner(fake,
		ResourceTypeDataProtectionBackupPolicyPostgreSqlFlexibleServer,
		datasourceDataProtectionBackupPolicyPostgreSqlFlexibleServer)

	// ARM's own flexible-server template: Full, VaultStore, weekly, timeZone UTC.
	desired := dpScheduledProps(name, "Full", "VaultStore",
		"R/2024-01-01T06:30:00+00:00/P1W", "UTC", "P3M")

	t.Run("Create sends a vault-tier full backup", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Label: name, Properties: desired})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)

		policy := sent.Properties.(*armdataprotection.BackupPolicy)
		require.Equal(t, "Microsoft.DBforPostgreSQL/flexibleServers", *policy.DatasourceTypes[0])

		backup := policy.PolicyRules[0].(*armdataprotection.AzureBackupRule)
		require.Equal(t, armdataprotection.DataStoreTypesVaultStore, *backup.DataStore.DataStoreType)
		require.Equal(t, "Full", *backup.BackupParameters.(*armdataprotection.AzureBackupParams).BackupType)

		trigger := backup.Trigger.(*armdataprotection.ScheduleBasedTriggerContext)
		require.Equal(t, "UTC", *trigger.Schedule.TimeZone, "a declared timeZone must reach ARM")

		retention := policy.PolicyRules[1].(*armdataprotection.AzureRetentionRule)
		require.Equal(t, armdataprotection.DataStoreTypesVaultStore, *retention.Lifecycles[0].SourceDataStore.DataStoreType)
		require.Equal(t, "P3M", *retention.Lifecycles[0].DeleteAfter.(*armdataprotection.AbsoluteDeleteOption).Duration)
	})

	t.Run("Read echoes the declared timeZone", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: nativeID})
		require.NoError(t, err)
		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "UTC", props["backupRules"].([]any)[0].(map[string]any)["timeZone"])
	})

	t.Run("Update stretches the retention window", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID: nativeID,
			DesiredProperties: dpScheduledProps(name, "Full", "VaultStore",
				"R/2024-01-01T06:30:00+00:00/P1W", "UTC", "P6M"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)

		policy := sent.Properties.(*armdataprotection.BackupPolicy)
		retention := policy.PolicyRules[1].(*armdataprotection.AzureRetentionRule)
		require.Equal(t, "P6M", *retention.Lifecycles[0].DeleteAfter.(*armdataprotection.AbsoluteDeleteOption).Duration)
	})

	t.Run("List returns only flexible-server policies", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "vaultName": "bv-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{nativeID}, got.NativeIDs)
	})
}

func TestDataProtectionBackupPolicyPostgreSqlFlexibleServer_Registration(t *testing.T) {
	require.Equal(t, "AZURE::DataProtection::BackupPolicyPostgreSqlFlexibleServer",
		ResourceTypeDataProtectionBackupPolicyPostgreSqlFlexibleServer)
	require.Equal(t, "Microsoft.DBforPostgreSQL/flexibleServers",
		datasourceDataProtectionBackupPolicyPostgreSqlFlexibleServer)
}
