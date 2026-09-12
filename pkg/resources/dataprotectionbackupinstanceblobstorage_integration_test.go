// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/dataprotection/armdataprotection/v3"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

// This file carries the fake BackupInstancesClient used by both backup-instance
// test files. dpBlobBackupInstancesAPI and dpDiskBackupInstancesAPI declare the
// same method set, so one fake satisfies both.

func dpInstanceNativeID(vault, name string) string {
	return fmt.Sprintf("/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.DataProtection/backupVaults/%s/backupInstances/%s", vault, name)
}

type fakeDPBackupInstancesAPI struct {
	beginCreateOrUpdateFn func(ctx context.Context, rgName, vaultName, instanceName string, params armdataprotection.BackupInstanceResource, opts *armdataprotection.BackupInstancesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armdataprotection.BackupInstancesClientCreateOrUpdateResponse], error)
	getFn                 func(ctx context.Context, rgName, vaultName, instanceName string, opts *armdataprotection.BackupInstancesClientGetOptions) (armdataprotection.BackupInstancesClientGetResponse, error)
	beginDeleteFn         func(ctx context.Context, rgName, vaultName, instanceName string, opts *armdataprotection.BackupInstancesClientBeginDeleteOptions) (*runtime.Poller[armdataprotection.BackupInstancesClientDeleteResponse], error)
	newListPagerFn        func(rgName, vaultName string, opts *armdataprotection.BackupInstancesClientListOptions) *runtime.Pager[armdataprotection.BackupInstancesClientListResponse]
}

func (f *fakeDPBackupInstancesAPI) BeginCreateOrUpdate(ctx context.Context, rgName, vaultName, instanceName string, params armdataprotection.BackupInstanceResource, opts *armdataprotection.BackupInstancesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armdataprotection.BackupInstancesClientCreateOrUpdateResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, rgName, vaultName, instanceName, params, opts)
}

func (f *fakeDPBackupInstancesAPI) Get(ctx context.Context, rgName, vaultName, instanceName string, opts *armdataprotection.BackupInstancesClientGetOptions) (armdataprotection.BackupInstancesClientGetResponse, error) {
	return f.getFn(ctx, rgName, vaultName, instanceName, opts)
}

func (f *fakeDPBackupInstancesAPI) BeginDelete(ctx context.Context, rgName, vaultName, instanceName string, opts *armdataprotection.BackupInstancesClientBeginDeleteOptions) (*runtime.Poller[armdataprotection.BackupInstancesClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, vaultName, instanceName, opts)
}

func (f *fakeDPBackupInstancesAPI) NewListPager(rgName, vaultName string, opts *armdataprotection.BackupInstancesClientListOptions) *runtime.Pager[armdataprotection.BackupInstancesClientListResponse] {
	return f.newListPagerFn(rgName, vaultName, opts)
}

// dpInstanceEcho echoes the instance body it was sent back as the stored resource,
// and adds the READ-ONLY currentProtectionState ARM stamps on it.
func dpInstanceEcho(t *testing.T, nativeID, name, otherDatasource string, sent *armdataprotection.BackupInstanceResource) *fakeDPBackupInstancesAPI {
	t.Helper()
	stored := func() armdataprotection.BackupInstanceResource {
		out := *sent
		out.ID = to.Ptr(nativeID)
		out.Name = to.Ptr(name)
		if out.Properties != nil {
			props := *out.Properties
			props.CurrentProtectionState = to.Ptr(armdataprotection.CurrentProtectionStateProtectionConfigured)
			out.Properties = &props
		}
		return out
	}
	fake := &fakeDPBackupInstancesAPI{}
	fake.beginCreateOrUpdateFn = func(_ context.Context, _, _, instanceName string, params armdataprotection.BackupInstanceResource, _ *armdataprotection.BackupInstancesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armdataprotection.BackupInstancesClientCreateOrUpdateResponse], error) {
		require.Equal(t, name, instanceName)
		*sent = params
		return newDonePoller(armdataprotection.BackupInstancesClientCreateOrUpdateResponse{BackupInstanceResource: stored()}), nil
	}
	fake.getFn = func(_ context.Context, _, _, _ string, _ *armdataprotection.BackupInstancesClientGetOptions) (armdataprotection.BackupInstancesClientGetResponse, error) {
		return armdataprotection.BackupInstancesClientGetResponse{BackupInstanceResource: stored()}, nil
	}
	fake.beginDeleteFn = func(_ context.Context, _, _, _ string, _ *armdataprotection.BackupInstancesClientBeginDeleteOptions) (*runtime.Poller[armdataprotection.BackupInstancesClientDeleteResponse], error) {
		return newDonePoller(armdataprotection.BackupInstancesClientDeleteResponse{}), nil
	}
	fake.newListPagerFn = func(_, _ string, _ *armdataprotection.BackupInstancesClientListOptions) *runtime.Pager[armdataprotection.BackupInstancesClientListResponse] {
		mine := stored()
		return runtime.NewPager(runtime.PagingHandler[armdataprotection.BackupInstancesClientListResponse]{
			More: func(_ armdataprotection.BackupInstancesClientListResponse) bool { return false },
			Fetcher: func(_ context.Context, _ *armdataprotection.BackupInstancesClientListResponse) (armdataprotection.BackupInstancesClientListResponse, error) {
				return armdataprotection.BackupInstancesClientListResponse{
					BackupInstanceResourceList: armdataprotection.BackupInstanceResourceList{
						Value: []*armdataprotection.BackupInstanceResource{
							&mine,
							// An instance for the other flavour in the same vault:
							// each type must ignore the other's instances.
							{
								ID: to.Ptr(dpInstanceNativeID("bv-1", "someone-elses")),
								Properties: &armdataprotection.BackupInstance{
									DataSourceInfo: &armdataprotection.Datasource{
										DatasourceType: to.Ptr(otherDatasource),
									},
								},
							},
						},
					},
				}, nil
			},
		})
	}
	return fake
}

// --- AZURE::DataProtection::BackupInstanceBlobStorage ---

const testDPBlobAccountID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Storage/storageAccounts/stg1"

func newTestDPBackupInstanceBlobStorage(api dpBlobBackupInstancesAPI) *DataProtectionBackupInstanceBlobStorage {
	return &DataProtectionBackupInstanceBlobStorage{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func dpBlobInstanceDesired(name string, containers []string) json.RawMessage {
	props := map[string]any{
		"name":               name,
		"resourceGroupName":  "rg-1",
		"vaultName":          "bv-1",
		"dataSourceId":       testDPBlobAccountID,
		"dataSourceLocation": "eastus",
		"policyId":           dpPolicyNativeID("bv-1", "bp-blob-1"),
		"friendlyName":       "stg1-blobs",
	}
	if containers != nil {
		props["containersList"] = containers
	}
	out, _ := json.Marshal(props)
	return out
}

func TestDataProtectionBackupInstanceBlobStorage_CRUD(t *testing.T) {
	const name = "bi-blob-1"
	nativeID := dpInstanceNativeID("bv-1", name)

	var sent armdataprotection.BackupInstanceResource
	fake := dpInstanceEcho(t, nativeID, name, "Microsoft.Compute/disks", &sent)
	prov := newTestDPBackupInstanceBlobStorage(fake)

	t.Run("Create derives the datasource name and type from the ARM ID", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      name,
			Properties: dpBlobInstanceDesired(name, nil),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, nativeID, got.ProgressResult.NativeID)

		instance := sent.Properties
		require.Equal(t, "BackupInstance", *instance.ObjectType)

		ds := instance.DataSourceInfo
		require.Equal(t, testDPBlobAccountID, *ds.ResourceID)
		require.Equal(t, testDPBlobAccountID, *ds.ResourceURI)
		// ARM rejects a resourceName that disagrees with resourceID, so it is
		// derived rather than declared.
		require.Equal(t, "stg1", *ds.ResourceName)
		// The datasource is the blob SERVICE; the ID points at the ACCOUNT.
		require.Equal(t, "Microsoft.Storage/storageAccounts/blobServices", *ds.DatasourceType)
		require.Equal(t, "Microsoft.Storage/storageAccounts", *ds.ResourceType)
		require.Equal(t, "eastus", *ds.ResourceLocation)

		require.Equal(t, dpPolicyNativeID("bv-1", "bp-blob-1"), *instance.PolicyInfo.PolicyID)
		require.Equal(t, "stg1-blobs", *instance.FriendlyName)
		// No containers declared: an operational-tier policy covers the whole
		// account and takes no policy parameters.
		require.Nil(t, instance.PolicyInfo.PolicyParameters)
		// No user-assigned identity declared, so identityDetails is omitted and
		// ARM applies its documented system-assigned default.
		require.Nil(t, instance.IdentityDetails)
	})

	t.Run("Read surfaces the service-owned protection state", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: nativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
		require.Equal(t, ResourceTypeDataProtectionBackupInstanceBlobStorage, got.ResourceType)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "bv-1", props["vaultName"])
		require.Equal(t, testDPBlobAccountID, props["dataSourceId"])
		require.Equal(t, "eastus", props["dataSourceLocation"])
		require.Equal(t, "ProtectionConfigured", props["currentProtectionState"])
		require.NotContains(t, props, "containersList")
	})

	t.Run("A container list becomes BlobBackupDatasourceParameters", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          nativeID,
			DesiredProperties: dpBlobInstanceDesired(name, []string{"data", "logs"}),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)

		list := sent.Properties.PolicyInfo.PolicyParameters.BackupDatasourceParametersList
		require.Len(t, list, 1)
		blob, ok := list[0].(*armdataprotection.BlobBackupDatasourceParameters)
		require.True(t, ok)
		require.Equal(t, "BlobBackupDatasourceParameters", *blob.ObjectType)
		require.Equal(t, []string{"data", "logs"}, stringsFromPointers(blob.ContainersList))

		read, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: nativeID})
		require.NoError(t, err)
		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(read.Properties), &props))
		require.Equal(t, []any{"data", "logs"}, props["containersList"])
	})

	t.Run("List returns only blob-service instances", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "vaultName": "bv-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{nativeID}, got.NativeIDs)
	})

	t.Run("List without a vault scope enumerates nothing", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})

	t.Run("Delete succeeds", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: nativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("A missing role assignment reports the provider error", func(t *testing.T) {
		// This is the failure the type hits in practice: the vault identity has
		// not been granted Storage Account Backup Contributor on the account, or
		// the grant has not propagated yet.
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _, _ string, _ armdataprotection.BackupInstanceResource, _ *armdataprotection.BackupInstancesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armdataprotection.BackupInstancesClientCreateOrUpdateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 400, ErrorCode: "UserErrorMissingRequiredPermissions"}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      name,
			Properties: dpBlobInstanceDesired(name, nil),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.NotEmpty(t, got.ProgressResult.ErrorCode)
		require.Contains(t, got.ProgressResult.StatusMessage, "UserErrorMissingRequiredPermissions")
	})
}

func TestDataProtectionBackupInstanceBlobStorage_RequiredFields(t *testing.T) {
	prov := newTestDPBackupInstanceBlobStorage(&fakeDPBackupInstancesAPI{})

	for _, missing := range []string{"vaultName", "dataSourceId", "dataSourceLocation", "policyId"} {
		t.Run("missing "+missing, func(t *testing.T) {
			var props map[string]any
			require.NoError(t, json.Unmarshal(dpBlobInstanceDesired("bi-blob-1", nil), &props))
			delete(props, missing)
			payload, err := json.Marshal(props)
			require.NoError(t, err)

			_, err = prov.Create(context.Background(), &resource.CreateRequest{Properties: payload})
			require.ErrorContains(t, err, missing+" is required")
		})
	}
}
