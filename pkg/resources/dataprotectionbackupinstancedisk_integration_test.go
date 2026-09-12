// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/dataprotection/armdataprotection/v3"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

// The fake BackupInstancesClient lives in
// dataprotectionbackupinstanceblobstorage_integration_test.go.

const (
	testDPDiskID            = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Compute/disks/disk-1"
	testDPSnapshotGroupID   = "/subscriptions/sub-1/resourceGroups/rg-snapshots"
	testDPUserIdentityARMID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.ManagedIdentity/userAssignedIdentities/uami-1"
)

func newTestDPBackupInstanceDisk(api dpDiskBackupInstancesAPI) *DataProtectionBackupInstanceDisk {
	return &DataProtectionBackupInstanceDisk{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func dpDiskInstanceDesired(name, snapshotGroupID, userIdentityARMID string) json.RawMessage {
	props := map[string]any{
		"name":               name,
		"resourceGroupName":  "rg-1",
		"vaultName":          "bv-1",
		"dataSourceId":       testDPDiskID,
		"dataSourceLocation": "eastus",
		"policyId":           dpPolicyNativeID("bv-1", "bp-disk-1"),
	}
	if snapshotGroupID != "" {
		props["snapshotResourceGroupId"] = snapshotGroupID
	}
	if userIdentityARMID != "" {
		props["userAssignedIdentityArmUrl"] = userIdentityARMID
	}
	out, _ := json.Marshal(props)
	return out
}

func TestDataProtectionBackupInstanceDisk_CRUD(t *testing.T) {
	const name = "bi-disk-1"
	nativeID := dpInstanceNativeID("bv-1", name)

	var sent armdataprotection.BackupInstanceResource
	fake := dpInstanceEcho(t, nativeID, name, "Microsoft.Storage/storageAccounts/blobServices", &sent)
	prov := newTestDPBackupInstanceDisk(fake)

	t.Run("Create sends the disk datasource and the snapshot resource group", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      name,
			Properties: dpDiskInstanceDesired(name, testDPSnapshotGroupID, ""),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, nativeID, got.ProgressResult.NativeID)

		ds := sent.Properties.DataSourceInfo
		require.Equal(t, testDPDiskID, *ds.ResourceID)
		require.Equal(t, "disk-1", *ds.ResourceName)
		// Unlike blob, the datasource type and the resource type coincide.
		require.Equal(t, "Microsoft.Compute/disks", *ds.DatasourceType)
		require.Equal(t, "Microsoft.Compute/disks", *ds.ResourceType)

		// The snapshot resource group rides as an operational-tier data-store
		// parameter, not as a top-level field.
		list := sent.Properties.PolicyInfo.PolicyParameters.DataStoreParametersList
		require.Len(t, list, 1)
		opStore, ok := list[0].(*armdataprotection.AzureOperationalStoreParameters)
		require.True(t, ok)
		require.Equal(t, "AzureOperationalStoreParameters", *opStore.ObjectType)
		require.Equal(t, armdataprotection.DataStoreTypesOperationalStore, *opStore.DataStoreType)
		require.Equal(t, testDPSnapshotGroupID, *opStore.ResourceGroupID)
	})

	t.Run("Read round-trips the snapshot resource group", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: nativeID})
		require.NoError(t, err)
		require.Equal(t, ResourceTypeDataProtectionBackupInstanceDisk, got.ResourceType)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, testDPDiskID, props["dataSourceId"])
		require.Equal(t, testDPSnapshotGroupID, props["snapshotResourceGroupId"])
		require.Equal(t, "ProtectionConfigured", props["currentProtectionState"])
		require.NotContains(t, props, "userAssignedIdentityArmUrl")
		// friendlyName was not declared and ARM echoed none.
		require.NotContains(t, props, "friendlyName")
	})

	t.Run("A user-assigned identity turns off the system-assigned default", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          nativeID,
			DesiredProperties: dpDiskInstanceDesired(name, testDPSnapshotGroupID, testDPUserIdentityARMID),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)

		id := sent.Properties.IdentityDetails
		require.NotNil(t, id)
		require.False(t, *id.UseSystemAssignedIdentity)
		require.Equal(t, testDPUserIdentityARMID, *id.UserAssignedIdentityArmURL)

		read, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: nativeID})
		require.NoError(t, err)
		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(read.Properties), &props))
		require.Equal(t, testDPUserIdentityARMID, props["userAssignedIdentityArmUrl"])
	})

	t.Run("Omitting the snapshot group sends no policy parameters", func(t *testing.T) {
		_, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          nativeID,
			DesiredProperties: dpDiskInstanceDesired(name, "", ""),
		})
		require.NoError(t, err)
		require.Nil(t, sent.Properties.PolicyInfo.PolicyParameters)
	})

	t.Run("List returns only disk instances", func(t *testing.T) {
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

	t.Run("An unparseable native ID is an error, not a silent no-op", func(t *testing.T) {
		_, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: "not-an-arm-id"})
		require.Error(t, err)
	})
}

func TestDataProtectionBackupInstanceDisk_Registration(t *testing.T) {
	require.Equal(t, "AZURE::DataProtection::BackupInstanceDisk", ResourceTypeDataProtectionBackupInstanceDisk)
	require.Equal(t, "Microsoft.Compute/disks", datasourceTypeManagedDisk)
}
