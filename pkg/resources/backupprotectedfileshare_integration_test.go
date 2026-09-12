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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/recoveryservices/armrecoveryservicesbackup/v4"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const (
	testProtectedShareContainer = "StorageContainer;Storage;rg-1;sa1"
	testProtectedShareItem      = "AzureFileShare;abcdef0123456789"
	testProtectedShareNativeID  = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.RecoveryServices/vaults/rsv-1/backupFabrics/Azure/protectionContainers/" +
		testProtectedShareContainer + "/protectedItems/" + testProtectedShareItem
	testProtectedSharePolicyID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.RecoveryServices/vaults/rsv-1/backupPolicies/fspol-1"
	testProtectedShareSourceID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Storage/storageAccounts/sa1"
)

func newTestProtectedFileShare(f *fakeProtectedFileShareAPIs) *BackupProtectedFileShare {
	return &BackupProtectedFileShare{
		api:            f,
		listAPI:        fakeProtectedItemsList{f},
		containersAPI:  f,
		protectableAPI: fakeProtectableItemsList{f},
		config:         &config.Config{SubscriptionId: "sub-1"},
	}
}

func protectedFileShareDesired(policyName string) []byte {
	out, _ := json.Marshal(map[string]any{
		"resourceGroupName":               "rg-1",
		"vaultName":                       "rsv-1",
		"storageAccountResourceGroupName": "rg-1",
		"storageAccountName":              "sa1",
		"fileShareName":                   "share-1",
		"backupPolicyName":                policyName,
	})
	return out
}

func protectedShareItem(policyID string) armrecoveryservicesbackup.ProtectedItemResource {
	return armrecoveryservicesbackup.ProtectedItemResource{
		ID:   to.Ptr(testProtectedShareNativeID),
		Name: to.Ptr(testProtectedShareItem),
		Properties: &armrecoveryservicesbackup.AzureFileshareProtectedItem{
			ProtectedItemType: to.Ptr("AzureFileShareProtectedItem"),
			FriendlyName:      to.Ptr("share-1"),
			PolicyID:          to.Ptr(policyID),
			SourceResourceID:  to.Ptr(testProtectedShareSourceID),
			ProtectionState:   to.Ptr(armrecoveryservicesbackup.ProtectionStateProtected),
		},
	}
}

// The whole point of this resource is the four-step chain, so the test walks it
// end to end: register, inquire until the share is discoverable, write the item,
// then poll until the policy is actually bound.
func TestBackupProtectedFileShare_CreateWalksTheChain(t *testing.T) {
	fake := newFakeProtectedFileShareAPIs()
	prov := newTestProtectedFileShare(fake)

	// The container registration finishes immediately, but the inquiry has not
	// surfaced the share yet.
	fake.protectableItems = nil

	created, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: protectedFileShareDesired("fspol-1")})
	require.NoError(t, err)
	require.Equal(t, resource.OperationStatusInProgress, created.ProgressResult.OperationStatus)
	require.Equal(t, 1, fake.registerCalls)

	state, err := decodeProtectedFileShareRequestID(created.ProgressResult.RequestID)
	require.NoError(t, err)
	require.Equal(t, protectedFileSharePhaseInquire, state.Phase)
	require.Equal(t, testProtectedShareContainer, state.ContainerName)
	require.Equal(t, 0, fake.createOrUpdateCalls)

	// The share appears; the next poll writes the protected item.
	fake.protectableItems = []*armrecoveryservicesbackup.WorkloadProtectableItemResource{{
		ID: to.Ptr("/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.RecoveryServices/vaults/rsv-1/backupFabrics/Azure/protectionContainers/" +
			testProtectedShareContainer + "/protectableItems/" + testProtectedShareItem),
		Name: to.Ptr(testProtectedShareItem),
		Properties: &armrecoveryservicesbackup.AzureFileShareProtectableItem{
			ProtectableItemType:         to.Ptr("AzureFileShare"),
			FriendlyName:                to.Ptr("share-1"),
			ParentContainerFriendlyName: to.Ptr("sa1"),
		},
	}}

	req := &resource.StatusRequest{RequestID: created.ProgressResult.RequestID}
	written, err := prov.Status(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, resource.OperationStatusInProgress, written.ProgressResult.OperationStatus)
	require.Equal(t, testProtectedShareNativeID, written.ProgressResult.NativeID)
	require.Equal(t, 1, fake.createOrUpdateCalls)
	require.Equal(t, testProtectedSharePolicyID, *fake.sentItem.Properties.(*armrecoveryservicesbackup.AzureFileshareProtectedItem).PolicyID)
	require.Equal(t, testProtectedShareSourceID, *fake.sentItem.Properties.(*armrecoveryservicesbackup.AzureFileshareProtectedItem).SourceResourceID)

	state, err = decodeProtectedFileShareRequestID(written.ProgressResult.RequestID)
	require.NoError(t, err)
	require.Equal(t, protectedFileSharePhaseVerify, state.Phase)

	// The item exists but is still on its old policy: not done yet.
	fake.item = to.Ptr(protectedShareItem("/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.RecoveryServices/vaults/rsv-1/backupPolicies/other"))
	req = &resource.StatusRequest{RequestID: written.ProgressResult.RequestID}
	pending, err := prov.Status(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, resource.OperationStatusInProgress, pending.ProgressResult.OperationStatus)

	// Policy bound: success, with properties built from the item.
	fake.item = to.Ptr(protectedShareItem(testProtectedSharePolicyID))
	done, err := prov.Status(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, resource.OperationStatusSuccess, done.ProgressResult.OperationStatus)
	require.Equal(t, testProtectedShareNativeID, done.ProgressResult.NativeID)

	var props map[string]any
	require.NoError(t, json.Unmarshal(done.ProgressResult.ResourceProperties, &props))
	require.Equal(t, "share-1", props["fileShareName"])
	require.Equal(t, "sa1", props["storageAccountName"])
	require.Equal(t, "rg-1", props["storageAccountResourceGroupName"])
	// Only the policy's leaf name is reported: ARM re-cases the ID it echoes.
	require.Equal(t, "fspol-1", props["backupPolicyName"])
	require.Equal(t, testProtectedShareContainer, props["containerName"])
	require.Equal(t, "Protected", props["protectionState"])
}

func TestBackupProtectedFileShare_CreateWaitsForRegistration(t *testing.T) {
	fake := newFakeProtectedFileShareAPIs()
	fake.registerPending = true
	prov := newTestProtectedFileShare(fake)

	created, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: protectedFileShareDesired("fspol-1")})
	require.NoError(t, err)
	require.Equal(t, resource.OperationStatusInProgress, created.ProgressResult.OperationStatus)

	state, err := decodeProtectedFileShareRequestID(created.ProgressResult.RequestID)
	require.NoError(t, err)
	require.Equal(t, protectedFileSharePhaseRegister, state.Phase)
	require.NotEmpty(t, state.ResumeToken)
	// The inquiry must not have run yet.
	require.Equal(t, 0, fake.inquireCalls)
}

func TestBackupProtectedFileShare_CreateValidatesInput(t *testing.T) {
	prov := newTestProtectedFileShare(newFakeProtectedFileShareAPIs())

	for _, missing := range []string{"vaultName", "storageAccountName", "fileShareName", "backupPolicyName"} {
		t.Run("missing_"+missing, func(t *testing.T) {
			var props map[string]any
			require.NoError(t, json.Unmarshal(protectedFileShareDesired("fspol-1"), &props))
			delete(props, missing)
			raw, _ := json.Marshal(props)
			_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: raw})
			require.ErrorContains(t, err, missing+" is required")
		})
	}
}

func TestBackupProtectedFileShare_Read(t *testing.T) {
	fake := newFakeProtectedFileShareAPIs()
	fake.item = to.Ptr(protectedShareItem(testProtectedSharePolicyID))
	prov := newTestProtectedFileShare(fake)

	got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testProtectedShareNativeID})
	require.NoError(t, err)
	require.Empty(t, got.ErrorCode)

	var props map[string]any
	require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
	require.Equal(t, "rg-1", props["resourceGroupName"])
	require.Equal(t, "rsv-1", props["vaultName"])
	require.Equal(t, testProtectedShareItem, props["name"])
	require.Equal(t, "fspol-1", props["backupPolicyName"])
}

func TestBackupProtectedFileShare_ReadNotFound(t *testing.T) {
	fake := newFakeProtectedFileShareAPIs()
	prov := newTestProtectedFileShare(fake)

	got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testProtectedShareNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// Update only rebinds the policy, so it starts at the write and skips the
// registration and inquiry the container has already been through.
func TestBackupProtectedFileShare_UpdateRebindsPolicy(t *testing.T) {
	fake := newFakeProtectedFileShareAPIs()
	prov := newTestProtectedFileShare(fake)

	got, err := prov.Update(context.Background(), &resource.UpdateRequest{
		NativeID:          testProtectedShareNativeID,
		DesiredProperties: protectedFileShareDesired("fspol-2"),
	})
	require.NoError(t, err)
	require.Equal(t, resource.OperationStatusInProgress, got.ProgressResult.OperationStatus)
	require.Equal(t, 0, fake.registerCalls)
	require.Equal(t, 0, fake.inquireCalls)
	require.Equal(t, 1, fake.createOrUpdateCalls)

	sent := fake.sentItem.Properties.(*armrecoveryservicesbackup.AzureFileshareProtectedItem)
	require.Contains(t, *sent.PolicyID, "/backupPolicies/fspol-2")

	state, err := decodeProtectedFileShareRequestID(got.ProgressResult.RequestID)
	require.NoError(t, err)
	require.Equal(t, protectedFileSharePhaseVerify, state.Phase)
	require.Equal(t, resource.OperationUpdate, state.operation())
}

// Delete has to unregister the container once the item is gone, or the vault can
// never be deleted.
func TestBackupProtectedFileShare_DeleteUnregistersContainer(t *testing.T) {
	fake := newFakeProtectedFileShareAPIs()
	fake.item = to.Ptr(protectedShareItem(testProtectedSharePolicyID))
	prov := newTestProtectedFileShare(fake)

	deleted, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testProtectedShareNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationStatusInProgress, deleted.ProgressResult.OperationStatus)
	require.Equal(t, 1, fake.deleteCalls)

	req := &resource.StatusRequest{RequestID: deleted.ProgressResult.RequestID}

	// Still there: keep waiting, and do not unregister yet.
	pending, err := prov.Status(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, resource.OperationStatusInProgress, pending.ProgressResult.OperationStatus)
	require.Equal(t, 0, fake.unregisterCalls)

	fake.item = nil
	done, err := prov.Status(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, resource.OperationStatusSuccess, done.ProgressResult.OperationStatus)
	require.Equal(t, 1, fake.unregisterCalls)
	require.Equal(t, testProtectedShareContainer, fake.unregisteredContainer)
}

// An unregister that fails because another share still uses the storage account
// must not turn a completed delete into a failure.
func TestBackupProtectedFileShare_DeleteToleratesUnregisterFailure(t *testing.T) {
	fake := newFakeProtectedFileShareAPIs()
	fake.unregisterErr = &azcore.ResponseError{StatusCode: 400, ErrorCode: "ContainerHasProtectedItems"}
	prov := newTestProtectedFileShare(fake)

	deleted, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testProtectedShareNativeID})
	require.NoError(t, err)

	done, err := prov.Status(context.Background(), &resource.StatusRequest{RequestID: deleted.ProgressResult.RequestID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationStatusSuccess, done.ProgressResult.OperationStatus)
}

func TestBackupProtectedFileShare_ProtectionErrorFails(t *testing.T) {
	fake := newFakeProtectedFileShareAPIs()
	item := protectedShareItem(testProtectedSharePolicyID)
	share := item.Properties.(*armrecoveryservicesbackup.AzureFileshareProtectedItem)
	share.ProtectionState = to.Ptr(armrecoveryservicesbackup.ProtectionStateProtectionError)
	share.ProtectionStatus = to.Ptr("the file share was deleted")
	fake.item = &item
	prov := newTestProtectedFileShare(fake)

	state := protectedFileShareRequestID{
		Phase:             protectedFileSharePhaseVerify,
		Operation:         lroOpCreate,
		NativeID:          testProtectedShareNativeID,
		ResourceGroupName: "rg-1",
		VaultName:         "rsv-1",
		ContainerName:     testProtectedShareContainer,
		PolicyName:        "fspol-1",
	}
	requestID, err := state.encode()
	require.NoError(t, err)

	got, err := prov.Status(context.Background(), &resource.StatusRequest{RequestID: requestID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	require.Equal(t, "the file share was deleted", got.ProgressResult.StatusMessage)
}

func TestBackupProtectedFileShare_List(t *testing.T) {
	fake := newFakeProtectedFileShareAPIs()
	prov := newTestProtectedFileShare(fake)

	got, err := prov.List(context.Background(), &resource.ListRequest{
		AdditionalProperties: map[string]string{"vaultName": "rsv-1", "resourceGroupName": "rg-1"},
	})
	require.NoError(t, err)
	require.Equal(t, []string{testProtectedShareNativeID}, got.NativeIDs)

	_, err = prov.List(context.Background(), &resource.ListRequest{})
	require.ErrorContains(t, err, "vaultName and resourceGroupName are required")
}

// --- Test helpers ---

// fakeProtectedFileShareAPIs stands in for all four SDK clients this resource
// drives, so a test can script the whole chain from one place.
type fakeProtectedFileShareAPIs struct {
	registerPending bool
	registerCalls   int
	inquireCalls    int

	protectableItems []*armrecoveryservicesbackup.WorkloadProtectableItemResource

	createOrUpdateCalls int
	sentItem            armrecoveryservicesbackup.ProtectedItemResource

	item           *armrecoveryservicesbackup.ProtectedItemResource
	protectedItems []*armrecoveryservicesbackup.ProtectedItemResource
	deleteCalls    int

	unregisterCalls       int
	unregisteredContainer string
	unregisterErr         error
}

func newFakeProtectedFileShareAPIs() *fakeProtectedFileShareAPIs {
	return &fakeProtectedFileShareAPIs{}
}

func (f *fakeProtectedFileShareAPIs) BeginRegister(_ context.Context, _, _, _, _ string, _ armrecoveryservicesbackup.ProtectionContainerResource, _ *armrecoveryservicesbackup.ProtectionContainersClientBeginRegisterOptions) (*runtime.Poller[armrecoveryservicesbackup.ProtectionContainersClientRegisterResponse], error) {
	f.registerCalls++
	if f.registerPending {
		return newInProgressPoller[armrecoveryservicesbackup.ProtectionContainersClientRegisterResponse](), nil
	}
	return newDonePoller(armrecoveryservicesbackup.ProtectionContainersClientRegisterResponse{}), nil
}

func (f *fakeProtectedFileShareAPIs) Inquire(_ context.Context, _, _, _, _ string, _ *armrecoveryservicesbackup.ProtectionContainersClientInquireOptions) (armrecoveryservicesbackup.ProtectionContainersClientInquireResponse, error) {
	f.inquireCalls++
	return armrecoveryservicesbackup.ProtectionContainersClientInquireResponse{}, nil
}

func (f *fakeProtectedFileShareAPIs) Unregister(_ context.Context, _, _, _, containerName string, _ *armrecoveryservicesbackup.ProtectionContainersClientUnregisterOptions) (armrecoveryservicesbackup.ProtectionContainersClientUnregisterResponse, error) {
	f.unregisterCalls++
	f.unregisteredContainer = containerName
	return armrecoveryservicesbackup.ProtectionContainersClientUnregisterResponse{}, f.unregisterErr
}

func (f *fakeProtectedFileShareAPIs) CreateOrUpdate(_ context.Context, _, _, _, _, _ string, params armrecoveryservicesbackup.ProtectedItemResource, _ *armrecoveryservicesbackup.ProtectedItemsClientCreateOrUpdateOptions) (armrecoveryservicesbackup.ProtectedItemsClientCreateOrUpdateResponse, error) {
	f.createOrUpdateCalls++
	f.sentItem = params
	return armrecoveryservicesbackup.ProtectedItemsClientCreateOrUpdateResponse{}, nil
}

func (f *fakeProtectedFileShareAPIs) Get(_ context.Context, _, _, _, _, _ string, _ *armrecoveryservicesbackup.ProtectedItemsClientGetOptions) (armrecoveryservicesbackup.ProtectedItemsClientGetResponse, error) {
	if f.item == nil {
		return armrecoveryservicesbackup.ProtectedItemsClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
	}
	return armrecoveryservicesbackup.ProtectedItemsClientGetResponse{ProtectedItemResource: *f.item}, nil
}

func (f *fakeProtectedFileShareAPIs) Delete(_ context.Context, _, _, _, _, _ string, _ *armrecoveryservicesbackup.ProtectedItemsClientDeleteOptions) (armrecoveryservicesbackup.ProtectedItemsClientDeleteResponse, error) {
	f.deleteCalls++
	return armrecoveryservicesbackup.ProtectedItemsClientDeleteResponse{}, nil
}

// The two list pagers are separate SDK clients with the same method name and
// different response types, so one Go type cannot carry both. These adapters let
// a single fake back them.
type fakeProtectableItemsList struct{ f *fakeProtectedFileShareAPIs }

func (a fakeProtectableItemsList) NewListPager(vaultName, rgName string, options *armrecoveryservicesbackup.BackupProtectableItemsClientListOptions) *runtime.Pager[armrecoveryservicesbackup.BackupProtectableItemsClientListResponse] {
	return a.f.listProtectable(vaultName, rgName, options)
}

type fakeProtectedItemsList struct{ f *fakeProtectedFileShareAPIs }

func (a fakeProtectedItemsList) NewListPager(vaultName, rgName string, options *armrecoveryservicesbackup.BackupProtectedItemsClientListOptions) *runtime.Pager[armrecoveryservicesbackup.BackupProtectedItemsClientListResponse] {
	return a.f.listProtected(vaultName, rgName, options)
}

func (f *fakeProtectedFileShareAPIs) listProtectable(_, _ string, _ *armrecoveryservicesbackup.BackupProtectableItemsClientListOptions) *runtime.Pager[armrecoveryservicesbackup.BackupProtectableItemsClientListResponse] {
	return runtime.NewPager(runtime.PagingHandler[armrecoveryservicesbackup.BackupProtectableItemsClientListResponse]{
		More: func(_ armrecoveryservicesbackup.BackupProtectableItemsClientListResponse) bool { return false },
		Fetcher: func(_ context.Context, _ *armrecoveryservicesbackup.BackupProtectableItemsClientListResponse) (armrecoveryservicesbackup.BackupProtectableItemsClientListResponse, error) {
			return armrecoveryservicesbackup.BackupProtectableItemsClientListResponse{
				WorkloadProtectableItemResourceList: armrecoveryservicesbackup.WorkloadProtectableItemResourceList{Value: f.protectableItems},
			}, nil
		},
	})
}

func (f *fakeProtectedFileShareAPIs) listProtected(_, _ string, _ *armrecoveryservicesbackup.BackupProtectedItemsClientListOptions) *runtime.Pager[armrecoveryservicesbackup.BackupProtectedItemsClientListResponse] {
	return runtime.NewPager(runtime.PagingHandler[armrecoveryservicesbackup.BackupProtectedItemsClientListResponse]{
		More: func(_ armrecoveryservicesbackup.BackupProtectedItemsClientListResponse) bool { return false },
		Fetcher: func(_ context.Context, _ *armrecoveryservicesbackup.BackupProtectedItemsClientListResponse) (armrecoveryservicesbackup.BackupProtectedItemsClientListResponse, error) {
			value := f.protectedItems
			if value == nil {
				value = []*armrecoveryservicesbackup.ProtectedItemResource{
					{ID: to.Ptr(testProtectedShareNativeID), Properties: &armrecoveryservicesbackup.AzureFileshareProtectedItem{}},
				}
			}
			return armrecoveryservicesbackup.BackupProtectedItemsClientListResponse{
				ProtectedItemResourceList: armrecoveryservicesbackup.ProtectedItemResourceList{
					Value: append(append([]*armrecoveryservicesbackup.ProtectedItemResource{}, value...), []*armrecoveryservicesbackup.ProtectedItemResource{
						// A VM item in the same vault must be skipped.
						{ID: to.Ptr("/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.RecoveryServices/vaults/rsv-1/backupFabrics/Azure/protectionContainers/IaasVMContainer;x/protectedItems/VM;y"),
							Properties: &armrecoveryservicesbackup.AzureIaaSComputeVMProtectedItem{}},
					}...),
				},
			}, nil
		},
	})
}

// The chain must finish even if the agent replays the original create token
// instead of the one each phase hands back: a poll that can see the item settles
// on the item, and never writes it a second time.
func TestBackupProtectedFileShare_StaleTokenStillConverges(t *testing.T) {
	fake := newFakeProtectedFileShareAPIs()
	fake.item = to.Ptr(protectedShareItem(testProtectedSharePolicyID))
	fake.protectedItems = []*armrecoveryservicesbackup.ProtectedItemResource{fake.item}
	prov := newTestProtectedFileShare(fake)

	// A token still stuck on the very first phase, with no native id yet.
	state := protectedFileShareRequestID{
		Phase:                       protectedFileSharePhaseRegister,
		Operation:                   lroOpCreate,
		ResumeToken:                 "stale",
		ResourceGroupName:           "rg-1",
		VaultName:                   "rsv-1",
		ContainerName:               testProtectedShareContainer,
		StorageAccountResourceGroup: "rg-1",
		StorageAccountName:          "sa1",
		FileShareName:               "share-1",
		PolicyName:                  "fspol-1",
	}
	requestID, err := state.encode()
	require.NoError(t, err)

	got, err := prov.Status(context.Background(), &resource.StatusRequest{RequestID: requestID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	require.Equal(t, testProtectedShareNativeID, got.ProgressResult.NativeID)
	// Neither the registration nor a second write was replayed.
	require.Equal(t, 0, fake.registerCalls)
	require.Equal(t, 0, fake.createOrUpdateCalls)
}
