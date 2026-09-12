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

func TestDataProtectionBackupPolicyKubernetesCluster_CRUD(t *testing.T) {
	const name = "bp-aks-1"
	nativeID := dpPolicyNativeID("bv-1", name)

	var sent armdataprotection.BaseBackupPolicyResource
	fake := dpPolicyEcho(t, nativeID, name, &sent)
	prov := dpPolicyProvisioner(fake,
		ResourceTypeDataProtectionBackupPolicyKubernetesCluster,
		datasourceDataProtectionBackupPolicyKubernetesCluster)

	// ARM's own AKS template: Incremental, OperationalStore, PT4H, no timeZone.
	desired := dpScheduledProps(name, "Incremental", "OperationalStore",
		"R/2024-01-01T09:00:00+00:00/PT4H", "", "P7D")

	t.Run("Create sends the managedClusters datasource", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Label: name, Properties: desired})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)

		policy := sent.Properties.(*armdataprotection.BackupPolicy)
		require.Equal(t, "Microsoft.ContainerService/managedClusters", *policy.DatasourceTypes[0])
		require.Len(t, policy.PolicyRules, 2)
	})

	// A vault-tier copy on an AKS policy is a targetCopySettings entry on the
	// operational retention lifecycle, not a second backup rule.
	t.Run("A targetCopySetting without a duration is an ImmediateCopyOption", func(t *testing.T) {
		var raw map[string]any
		require.NoError(t, json.Unmarshal(desired, &raw))
		lifecycle := raw["retentionRules"].([]any)[0].(map[string]any)["lifecycles"].([]any)[0].(map[string]any)
		lifecycle["targetCopySettings"] = []map[string]any{{"datastoreType": "VaultStore"}}
		withCopy, err := json.Marshal(raw)
		require.NoError(t, err)

		_, err = prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          nativeID,
			DesiredProperties: withCopy,
		})
		require.NoError(t, err)

		policy := sent.Properties.(*armdataprotection.BackupPolicy)
		retention := policy.PolicyRules[1].(*armdataprotection.AzureRetentionRule)
		require.Len(t, retention.Lifecycles[0].TargetDataStoreCopySettings, 1)
		copySetting := retention.Lifecycles[0].TargetDataStoreCopySettings[0]
		require.Equal(t, armdataprotection.DataStoreTypesVaultStore, *copySetting.DataStore.DataStoreType)
		_, ok := copySetting.CopyAfter.(*armdataprotection.ImmediateCopyOption)
		require.True(t, ok, "no duration means copy immediately")

		// Read back: an ImmediateCopyOption carries no duration, so the entry
		// reads as the datastore alone rather than gaining a phantom field.
		read, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: nativeID})
		require.NoError(t, err)
		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(read.Properties), &props))
		settings := props["retentionRules"].([]any)[0].(map[string]any)["lifecycles"].([]any)[0].(map[string]any)["targetCopySettings"].([]any)
		require.Len(t, settings, 1)
		require.Equal(t, "VaultStore", settings[0].(map[string]any)["datastoreType"])
		require.NotContains(t, settings[0].(map[string]any), "copyAfterDuration")
	})

	t.Run("A targetCopySetting with a duration is a CustomCopyOption", func(t *testing.T) {
		var raw map[string]any
		require.NoError(t, json.Unmarshal(desired, &raw))
		lifecycle := raw["retentionRules"].([]any)[0].(map[string]any)["lifecycles"].([]any)[0].(map[string]any)
		lifecycle["targetCopySettings"] = []map[string]any{{"datastoreType": "VaultStore", "copyAfterDuration": "P1D"}}
		withCopy, err := json.Marshal(raw)
		require.NoError(t, err)

		_, err = prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          nativeID,
			DesiredProperties: withCopy,
		})
		require.NoError(t, err)

		policy := sent.Properties.(*armdataprotection.BackupPolicy)
		retention := policy.PolicyRules[1].(*armdataprotection.AzureRetentionRule)
		custom, ok := retention.Lifecycles[0].TargetDataStoreCopySettings[0].CopyAfter.(*armdataprotection.CustomCopyOption)
		require.True(t, ok)
		require.Equal(t, "P1D", *custom.Duration)

		read, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: nativeID})
		require.NoError(t, err)
		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(read.Properties), &props))
		settings := props["retentionRules"].([]any)[0].(map[string]any)["lifecycles"].([]any)[0].(map[string]any)["targetCopySettings"].([]any)
		require.Equal(t, "P1D", settings[0].(map[string]any)["copyAfterDuration"])
	})

	t.Run("List returns only managed-cluster policies", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "vaultName": "bv-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{nativeID}, got.NativeIDs)
	})
}

func TestDataProtectionBackupPolicyKubernetesCluster_Registration(t *testing.T) {
	require.Equal(t, "AZURE::DataProtection::BackupPolicyKubernetesCluster",
		ResourceTypeDataProtectionBackupPolicyKubernetesCluster)
	require.Equal(t, "Microsoft.ContainerService/managedClusters",
		datasourceDataProtectionBackupPolicyKubernetesCluster)
}
