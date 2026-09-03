// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/recoveryservices/armrecoveryservicesbackup/v4"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeBackupProtectedFileShare = "AZURE::RecoveryServices::BackupProtectedFileShare"

// backupFabricAzure is the only fabric name ARM accepts for Azure-native
// workloads. It is a literal path segment, not a region or a discoverable value.
const backupFabricAzure = "Azure"

// Phases of the protected-item lifecycle. Protecting a file share is not one ARM
// call but a chain of four, each of which finishes asynchronously:
//
//  1. register  - PUT the storage account into the vault as a protection
//     container (a real LRO with a resume token).
//  2. inquire   - POST /inquire, then poll the vault's protectable items until
//     the share shows up. The inquiry is accepted with a 202 and no operation
//     handle at all, so the only way to know it finished is that the item
//     appears.
//  3. verify    - PUT the protected item, then poll it until ARM reports the
//     policy actually bound.
//  4. purge     - after DELETE, poll until the item is gone, then unregister the
//     container so the vault itself can be deleted.
//
// The phase lives in the progress token, but Status does not depend on the token
// advancing: every non-purge poll looks for the protected item first and finishes
// on it if ARM has one. See Status.
const (
	protectedFileSharePhaseRegister = "register"
	protectedFileSharePhaseInquire  = "inquire"
	protectedFileSharePhaseVerify   = "verify"
	protectedFileSharePhasePurge    = "purge"
)

// backupProtectedItemsAPI is the protected-item CRUD surface. None of these are
// modelled as LROs by the SDK even though ARM answers 202: the operation handle
// goes to a backupOperationResults endpoint the generated client does not poll,
// so this resource polls the item itself instead.
type backupProtectedItemsAPI interface {
	CreateOrUpdate(ctx context.Context, vaultName string, resourceGroupName string, fabricName string, containerName string, protectedItemName string, parameters armrecoveryservicesbackup.ProtectedItemResource, options *armrecoveryservicesbackup.ProtectedItemsClientCreateOrUpdateOptions) (armrecoveryservicesbackup.ProtectedItemsClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, vaultName string, resourceGroupName string, fabricName string, containerName string, protectedItemName string, options *armrecoveryservicesbackup.ProtectedItemsClientGetOptions) (armrecoveryservicesbackup.ProtectedItemsClientGetResponse, error)
	Delete(ctx context.Context, vaultName string, resourceGroupName string, fabricName string, containerName string, protectedItemName string, options *armrecoveryservicesbackup.ProtectedItemsClientDeleteOptions) (armrecoveryservicesbackup.ProtectedItemsClientDeleteResponse, error)
}

type backupProtectedItemsListAPI interface {
	NewListPager(vaultName string, resourceGroupName string, options *armrecoveryservicesbackup.BackupProtectedItemsClientListOptions) *runtime.Pager[armrecoveryservicesbackup.BackupProtectedItemsClientListResponse]
}

type backupProtectionContainersAPI interface {
	BeginRegister(ctx context.Context, vaultName string, resourceGroupName string, fabricName string, containerName string, parameters armrecoveryservicesbackup.ProtectionContainerResource, options *armrecoveryservicesbackup.ProtectionContainersClientBeginRegisterOptions) (*runtime.Poller[armrecoveryservicesbackup.ProtectionContainersClientRegisterResponse], error)
	Inquire(ctx context.Context, vaultName string, resourceGroupName string, fabricName string, containerName string, options *armrecoveryservicesbackup.ProtectionContainersClientInquireOptions) (armrecoveryservicesbackup.ProtectionContainersClientInquireResponse, error)
	Unregister(ctx context.Context, vaultName string, resourceGroupName string, fabricName string, containerName string, options *armrecoveryservicesbackup.ProtectionContainersClientUnregisterOptions) (armrecoveryservicesbackup.ProtectionContainersClientUnregisterResponse, error)
}

type backupProtectableItemsAPI interface {
	NewListPager(vaultName string, resourceGroupName string, options *armrecoveryservicesbackup.BackupProtectableItemsClientListOptions) *runtime.Pager[armrecoveryservicesbackup.BackupProtectableItemsClientListResponse]
}

func init() {
	registry.Register(ResourceTypeBackupProtectedFileShare, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &BackupProtectedFileShare{
			api:            c.BackupProtectedItemsClient,
			listAPI:        c.BackupProtectedItemsListClient,
			containersAPI:  c.BackupProtectionContainersClient,
			protectableAPI: c.BackupProtectableItemsClient,
			pipeline:       c.Pipeline(),
			config:         cfg,
		}
	})
}

// BackupProtectedFileShare is the provisioner for an Azure Files share protected
// by a Recovery Services vault
// (Microsoft.RecoveryServices/vaults/backupFabrics/protectionContainers/protectedItems).
type BackupProtectedFileShare struct {
	api            backupProtectedItemsAPI
	listAPI        backupProtectedItemsListAPI
	containersAPI  backupProtectionContainersAPI
	protectableAPI backupProtectableItemsAPI
	pipeline       runtime.Pipeline
	config         *config.Config
}

// backupProtectedFileShareProps mirrors
// schema/pkl/recoveryservices/backupprotectedfileshare.pkl.
//
// The storage account is addressed by resource group plus name rather than by its
// ARM ID, and the policy by name rather than ID, on purpose: ARM echoes both back
// with its own casing (`/resourcegroups/`, `/microsoft.storage/`), so round-
// tripping a full ARM ID through the read path reports drift on every sync. Names
// come back exactly as sent.
type backupProtectedFileShareProps struct {
	ResourceGroupName               string `json:"resourceGroupName"`
	VaultName                       string `json:"vaultName"`
	StorageAccountResourceGroupName string `json:"storageAccountResourceGroupName"`
	StorageAccountName              string `json:"storageAccountName"`
	FileShareName                   string `json:"fileShareName"`
	BackupPolicyName                string `json:"backupPolicyName"`
}

// protectedFileShareRequestID is this resource's own progress token.
//
// The shared lroRequestID cannot carry it: the chain has four phases, only the
// first of which has a resume token, and every later phase needs the vault,
// container and policy coordinates to continue from. JSON shape must stay
// backward compatible — it is persisted as ProgressResult.RequestID.
type protectedFileShareRequestID struct {
	Phase                       string `json:"phase"`
	Operation                   string `json:"operation"`
	ResumeToken                 string `json:"resumeToken,omitempty"`
	NativeID                    string `json:"nativeID,omitempty"`
	ResourceGroupName           string `json:"resourceGroupName"`
	VaultName                   string `json:"vaultName"`
	ContainerName               string `json:"containerName"`
	StorageAccountResourceGroup string `json:"storageAccountResourceGroup"`
	StorageAccountName          string `json:"storageAccountName"`
	FileShareName               string `json:"fileShareName"`
	PolicyName                  string `json:"policyName"`
}

func (r protectedFileShareRequestID) encode() (string, error) {
	out, err := json.Marshal(r)
	if err != nil {
		return "", fmt.Errorf("failed to marshal protected file share request id: %w", err)
	}
	return string(out), nil
}

func decodeProtectedFileShareRequestID(requestID string) (protectedFileShareRequestID, error) {
	var out protectedFileShareRequestID
	if err := json.Unmarshal([]byte(requestID), &out); err != nil {
		return protectedFileShareRequestID{}, fmt.Errorf("failed to parse protected file share request id: %w", err)
	}
	return out, nil
}

func (r protectedFileShareRequestID) operation() resource.Operation {
	switch r.Operation {
	case lroOpUpdate:
		return resource.OperationUpdate
	case lroOpDelete:
		return resource.OperationDelete
	default:
		return resource.OperationCreate
	}
}

// backupStorageContainerName builds the container name ARM uses for a storage
// account registered into a vault. The shape is fixed by the service:
// "StorageContainer;Storage;<resource group>;<account name>".
func backupStorageContainerName(rgName, accountName string) string {
	return fmt.Sprintf("StorageContainer;Storage;%s;%s", rgName, accountName)
}

func (b *BackupProtectedFileShare) storageAccountID(rgName, accountName string) string {
	return fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Storage/storageAccounts/%s",
		b.config.SubscriptionId, rgName, accountName)
}

func (b *BackupProtectedFileShare) policyID(rgName, vaultName, policyName string) string {
	return fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.RecoveryServices/vaults/%s/backupPolicies/%s",
		b.config.SubscriptionId, rgName, vaultName, policyName)
}

func (b *BackupProtectedFileShare) protectedItemID(rgName, vaultName, containerName, itemName string) string {
	return fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.RecoveryServices/vaults/%s/backupFabrics/%s/protectionContainers/%s/protectedItems/%s",
		b.config.SubscriptionId, rgName, vaultName, backupFabricAzure, containerName, itemName)
}

func backupProtectedFileShareIDParts(resourceID string) (rgName, vaultName, containerName, itemName string, err error) {
	rgName, names, err := armIDParts(resourceID, "vaults", "protectioncontainers", "protecteditems")
	if err != nil {
		return "", "", "", "", err
	}
	return rgName, names["vaults"], names["protectioncontainers"], names["protecteditems"], nil
}

// backupContainerNameParts pulls the storage account's resource group and name
// back out of a container name. Used as the read-path fallback when ARM omits
// sourceResourceId.
func backupContainerNameParts(containerName string) (rgName, accountName string, ok bool) {
	parts := strings.Split(containerName, ";")
	if len(parts) != 4 {
		return "", "", false
	}
	return parts[2], parts[3], true
}

func (b *BackupProtectedFileShare) buildPropertiesFromResult(item *armrecoveryservicesbackup.ProtectedItemResource, rgName, vaultName, containerName string) map[string]any {
	props := map[string]any{
		"resourceGroupName": rgName,
		"vaultName":         vaultName,
	}
	if containerName != "" {
		props["containerName"] = containerName
	}
	if item.ID != nil {
		props["id"] = *item.ID
	}
	if item.Name != nil {
		props["name"] = *item.Name
	}

	share, ok := item.Properties.(*armrecoveryservicesbackup.AzureFileshareProtectedItem)
	if !ok || share == nil {
		return props
	}

	if share.FriendlyName != nil {
		props["fileShareName"] = *share.FriendlyName
	}
	if share.ProtectionState != nil {
		props["protectionState"] = string(*share.ProtectionState)
	}

	// The policy is reported as a full ARM ID whose casing ARM chooses; only the
	// leaf name is stable, and that is what the schema models.
	if share.PolicyID != nil {
		if _, _, policyName, err := backupPolicyIDParts(*share.PolicyID); err == nil {
			props["backupPolicyName"] = policyName
		}
	}

	// Same story for the storage account: prefer the container name, which the
	// plugin composed, and fall back to parsing sourceResourceId.
	if saRG, saName, parsed := backupContainerNameParts(containerName); parsed {
		props["storageAccountResourceGroupName"] = saRG
		props["storageAccountName"] = saName
	} else if share.SourceResourceID != nil {
		if saRG, names, err := armIDParts(*share.SourceResourceID, "storageaccounts"); err == nil {
			props["storageAccountResourceGroupName"] = saRG
			props["storageAccountName"] = names["storageaccounts"]
		}
	}

	return props
}

func (b *BackupProtectedFileShare) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props backupProtectedFileShareProps
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	if props.VaultName == "" {
		return nil, fmt.Errorf("vaultName is required")
	}
	if props.StorageAccountName == "" {
		return nil, fmt.Errorf("storageAccountName is required")
	}
	if props.StorageAccountResourceGroupName == "" {
		return nil, fmt.Errorf("storageAccountResourceGroupName is required")
	}
	if props.FileShareName == "" {
		return nil, fmt.Errorf("fileShareName is required")
	}
	if props.BackupPolicyName == "" {
		return nil, fmt.Errorf("backupPolicyName is required")
	}

	state := protectedFileShareRequestID{
		Operation:                   lroOpCreate,
		ResourceGroupName:           props.ResourceGroupName,
		VaultName:                   props.VaultName,
		ContainerName:               backupStorageContainerName(props.StorageAccountResourceGroupName, props.StorageAccountName),
		StorageAccountResourceGroup: props.StorageAccountResourceGroupName,
		StorageAccountName:          props.StorageAccountName,
		FileShareName:               props.FileShareName,
		PolicyName:                  props.BackupPolicyName,
	}

	container := armrecoveryservicesbackup.ProtectionContainerResource{
		Properties: &armrecoveryservicesbackup.AzureStorageContainer{
			ContainerType:        to.Ptr(armrecoveryservicesbackup.ProtectableContainerTypeStorageContainer),
			BackupManagementType: to.Ptr(armrecoveryservicesbackup.BackupManagementTypeAzureStorage),
			SourceResourceID:     to.Ptr(b.storageAccountID(props.StorageAccountResourceGroupName, props.StorageAccountName)),
			FriendlyName:         to.Ptr(props.StorageAccountName),
			// Without the lock ARM will happily let the storage account be deleted
			// out from under its own backups.
			AcquireStorageAccountLock: to.Ptr(armrecoveryservicesbackup.AcquireStorageAccountLockAcquire),
		},
	}

	poller, err := b.containersAPI.BeginRegister(ctx, state.VaultName, state.ResourceGroupName, backupFabricAzure, state.ContainerName, container, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
				StatusMessage:   err.Error(),
			},
		}, nil
	}

	if poller.Done() {
		if _, err := poller.Result(ctx); err != nil {
			return &resource.CreateResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationCreate,
					OperationStatus: resource.OperationStatusFailure,
					ErrorCode:       operationErrorCode(err),
					StatusMessage:   err.Error(),
				},
			}, nil
		}
		progress, err := b.advanceInquire(ctx, state, "")
		if err != nil {
			return nil, err
		}
		return &resource.CreateResult{ProgressResult: progress}, nil
	}

	resumeToken, err := poller.ResumeToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get resume token: %w", err)
	}
	state.Phase = protectedFileSharePhaseRegister
	state.ResumeToken = resumeToken
	reqID, err := state.encode()
	if err != nil {
		return nil, err
	}
	return &resource.CreateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationCreate,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       reqID,
		},
	}, nil
}

// advanceInquire runs the discovery half: ask the container to re-enumerate its
// shares, then look for the one being protected. When it appears, the protected
// item is written and the chain moves to the verify phase; until then the caller
// stays in the inquire phase and tries again on the next poll.
func (b *BackupProtectedFileShare) advanceInquire(ctx context.Context, state protectedFileShareRequestID, requestID string) (*resource.ProgressResult, error) {
	operation := state.operation()

	filter := "backupManagementType eq 'AzureStorage'"
	if _, err := b.containersAPI.Inquire(ctx, state.VaultName, state.ResourceGroupName, backupFabricAzure, state.ContainerName,
		&armrecoveryservicesbackup.ProtectionContainersClientInquireOptions{Filter: &filter}); err != nil {
		return &resource.ProgressResult{
			Operation:       operation,
			OperationStatus: resource.OperationStatusFailure,
			RequestID:       requestID,
			ErrorCode:       operationErrorCode(err),
			StatusMessage:   err.Error(),
		}, nil
	}

	itemName, containerName, err := b.findProtectableItem(ctx, state)
	if err != nil {
		return &resource.ProgressResult{
			Operation:       operation,
			OperationStatus: resource.OperationStatusFailure,
			RequestID:       requestID,
			ErrorCode:       operationErrorCode(err),
			StatusMessage:   err.Error(),
		}, nil
	}

	if itemName == "" {
		state.Phase = protectedFileSharePhaseInquire
		state.ResumeToken = ""
		reqID, err := state.encode()
		if err != nil {
			return nil, err
		}
		return &resource.ProgressResult{
			Operation:       operation,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       reqID,
		}, nil
	}

	if containerName != "" {
		state.ContainerName = containerName
	}
	return b.writeProtectedItem(ctx, state, itemName, requestID)
}

// findProtectableItem scans the vault's protectable items for this share. It
// returns the item name ARM assigned — the protected item has to be created under
// exactly that name, which is a service-generated "AzureFileShare;<hash>" and not
// the share's own name — plus the container name taken from the item's ARM ID,
// which is authoritative where the composed one is only a good guess.
func (b *BackupProtectedFileShare) findProtectableItem(ctx context.Context, state protectedFileShareRequestID) (itemName, containerName string, err error) {
	filter := "backupManagementType eq 'AzureStorage' and workloadType eq 'AzureFileShare'"
	pager := b.protectableAPI.NewListPager(state.VaultName, state.ResourceGroupName,
		&armrecoveryservicesbackup.BackupProtectableItemsClientListOptions{Filter: &filter})

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return "", "", fmt.Errorf("failed to list protectable file shares: %w", err)
		}
		for _, item := range page.Value {
			if item == nil || item.Name == nil {
				continue
			}
			share, ok := item.Properties.(*armrecoveryservicesbackup.AzureFileShareProtectableItem)
			if !ok || share == nil || share.FriendlyName == nil {
				continue
			}
			if !strings.EqualFold(*share.FriendlyName, state.FileShareName) {
				continue
			}
			if share.ParentContainerFriendlyName != nil &&
				!strings.EqualFold(*share.ParentContainerFriendlyName, state.StorageAccountName) {
				continue
			}
			container := ""
			if item.ID != nil {
				if _, names, err := armIDParts(*item.ID, "protectioncontainers"); err == nil {
					container = names["protectioncontainers"]
				}
			}
			return *item.Name, container, nil
		}
	}
	return "", "", nil
}

// writeProtectedItem PUTs the protected item and moves to the verify phase. ARM
// answers 202 with an empty body, so there is nothing useful to report yet.
func (b *BackupProtectedFileShare) writeProtectedItem(ctx context.Context, state protectedFileShareRequestID, itemName, requestID string) (*resource.ProgressResult, error) {
	operation := state.operation()
	nativeID := b.protectedItemID(state.ResourceGroupName, state.VaultName, state.ContainerName, itemName)

	params := armrecoveryservicesbackup.ProtectedItemResource{
		Properties: &armrecoveryservicesbackup.AzureFileshareProtectedItem{
			ProtectedItemType: to.Ptr("AzureFileShareProtectedItem"),
			PolicyID:          to.Ptr(b.policyID(state.ResourceGroupName, state.VaultName, state.PolicyName)),
			SourceResourceID:  to.Ptr(b.storageAccountID(state.StorageAccountResourceGroup, state.StorageAccountName)),
		},
	}

	if _, err := b.api.CreateOrUpdate(ctx, state.VaultName, state.ResourceGroupName, backupFabricAzure,
		state.ContainerName, itemName, params, nil); err != nil {
		return &resource.ProgressResult{
			Operation:       operation,
			OperationStatus: resource.OperationStatusFailure,
			RequestID:       requestID,
			NativeID:        nativeID,
			ErrorCode:       operationErrorCode(err),
			StatusMessage:   err.Error(),
		}, nil
	}

	state.Phase = protectedFileSharePhaseVerify
	state.ResumeToken = ""
	state.NativeID = nativeID
	reqID, err := state.encode()
	if err != nil {
		return nil, err
	}
	return &resource.ProgressResult{
		Operation:       operation,
		OperationStatus: resource.OperationStatusInProgress,
		RequestID:       reqID,
		NativeID:        nativeID,
	}, nil
}

// locateItem finds the protected item for this share, if ARM has one yet.
//
// It looks the item up by native ID once that is known, and otherwise scans the
// vault's protected items for the share by friendly name. The scan is what makes
// the chain converge without depending on the agent carrying a rewritten
// RequestID forward between polls: whatever phase the token still says, a poll
// that can see the item finishes on the item.
func (b *BackupProtectedFileShare) locateItem(ctx context.Context, state protectedFileShareRequestID) (item *armrecoveryservicesbackup.ProtectedItemResource, nativeID, containerName string, err error) {
	if state.NativeID != "" {
		rgName, vaultName, container, itemName, err := backupProtectedFileShareIDParts(state.NativeID)
		if err != nil {
			return nil, "", "", err
		}
		result, err := b.api.Get(ctx, vaultName, rgName, backupFabricAzure, container, itemName, nil)
		if err != nil {
			if operationErrorCode(err) == resource.OperationErrorCodeNotFound {
				return nil, "", "", nil
			}
			return nil, "", "", err
		}
		return &result.ProtectedItemResource, state.NativeID, container, nil
	}

	filter := "backupManagementType eq 'AzureStorage' and itemType eq 'AzureFileShare'"
	pager := b.listAPI.NewListPager(state.VaultName, state.ResourceGroupName,
		&armrecoveryservicesbackup.BackupProtectedItemsClientListOptions{Filter: &filter})
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, "", "", fmt.Errorf("failed to list protected file shares: %w", err)
		}
		for _, candidate := range page.Value {
			if candidate == nil || candidate.ID == nil {
				continue
			}
			share, ok := candidate.Properties.(*armrecoveryservicesbackup.AzureFileshareProtectedItem)
			if !ok || share == nil || share.FriendlyName == nil {
				continue
			}
			if !strings.EqualFold(*share.FriendlyName, state.FileShareName) {
				continue
			}
			_, _, container, _, err := backupProtectedFileShareIDParts(*candidate.ID)
			if err != nil || !strings.EqualFold(container, state.ContainerName) {
				continue
			}
			return candidate, *candidate.ID, container, nil
		}
	}
	return nil, "", "", nil
}

// itemStatus turns a located protected item into a terminal or in-progress
// result. Waiting on the policy id and not merely on the item existing is what
// makes Update deterministic: the item is already there, only its policy changes.
func (b *BackupProtectedFileShare) itemStatus(state protectedFileShareRequestID, item *armrecoveryservicesbackup.ProtectedItemResource,
	nativeID, containerName, requestID string) (*resource.StatusResult, error) {

	operation := state.operation()

	share, ok := item.Properties.(*armrecoveryservicesbackup.AzureFileshareProtectedItem)
	if !ok || share == nil {
		return lroFailure(operation, requestID, resource.OperationErrorCodeGeneralServiceException,
			"protected item is not an Azure file share item"), nil
	}
	if share.ProtectionState != nil && *share.ProtectionState == armrecoveryservicesbackup.ProtectionStateProtectionError {
		message := "protection failed"
		if share.ProtectionStatus != nil {
			message = *share.ProtectionStatus
		}
		return lroFailure(operation, requestID, resource.OperationErrorCodeGeneralServiceException, message), nil
	}

	wanted := b.policyID(state.ResourceGroupName, state.VaultName, state.PolicyName)
	if share.PolicyID == nil || !strings.EqualFold(*share.PolicyID, wanted) {
		return lroInProgress(operation, requestID, nativeID), nil
	}

	rgName, vaultName, _, _, err := backupProtectedFileShareIDParts(nativeID)
	if err != nil {
		return nil, err
	}
	propsJSON, err := json.Marshal(b.buildPropertiesFromResult(item, rgName, vaultName, containerName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return lroSuccess(operation, requestID, nativeID, propsJSON), nil
}

// advancePurge waits for the deleted item to disappear, then unregisters the
// container.
//
// The unregister matters beyond tidiness: a Recovery Services vault refuses its
// own delete while any container is still registered, so leaving it behind would
// strand the whole stack. It is best-effort because the same storage account may
// still hold another protected share, in which case ARM rejects the unregister and
// the delete of this item is nonetheless complete.
func (b *BackupProtectedFileShare) advancePurge(ctx context.Context, state protectedFileShareRequestID, requestID string) (*resource.StatusResult, error) {
	rgName, vaultName, containerName, itemName, err := backupProtectedFileShareIDParts(state.NativeID)
	if err != nil {
		return nil, err
	}

	_, err = b.api.Get(ctx, vaultName, rgName, backupFabricAzure, containerName, itemName, nil)
	switch {
	case err == nil:
		return lroInProgress(resource.OperationDelete, requestID, state.NativeID), nil
	case isDeleteSuccessError(err):
		_, _ = b.containersAPI.Unregister(ctx, vaultName, rgName, backupFabricAzure, containerName, nil)
		return lroDeleteSuccess(requestID, state.NativeID), nil
	default:
		return lroFailure(resource.OperationDelete, requestID, operationErrorCode(err), err.Error()), nil
	}
}

func (b *BackupProtectedFileShare) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, vaultName, containerName, itemName, err := backupProtectedFileShareIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := b.api.Get(ctx, vaultName, rgName, backupFabricAzure, containerName, itemName, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(b.buildPropertiesFromResult(&result.ProtectedItemResource, rgName, vaultName, containerName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeBackupProtectedFileShare,
		Properties:   string(propsJSON),
	}, nil
}

// Update re-PUTs the protected item. Everything except the policy is createOnly,
// so this only ever rebinds the share to a different policy — and the container is
// already registered, so the chain starts at the write.
func (b *BackupProtectedFileShare) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, vaultName, containerName, itemName, err := backupProtectedFileShareIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props backupProtectedFileShareProps
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.BackupPolicyName == "" {
		return nil, fmt.Errorf("backupPolicyName is required")
	}

	saRG, saName, ok := backupContainerNameParts(containerName)
	if !ok {
		saRG, saName = props.StorageAccountResourceGroupName, props.StorageAccountName
	}

	state := protectedFileShareRequestID{
		Operation:                   lroOpUpdate,
		ResourceGroupName:           rgName,
		VaultName:                   vaultName,
		ContainerName:               containerName,
		StorageAccountResourceGroup: saRG,
		StorageAccountName:          saName,
		FileShareName:               props.FileShareName,
		PolicyName:                  props.BackupPolicyName,
	}

	progress, err := b.writeProtectedItem(ctx, state, itemName, "")
	if err != nil {
		return nil, err
	}
	return &resource.UpdateResult{ProgressResult: progress}, nil
}

func (b *BackupProtectedFileShare) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, vaultName, containerName, itemName, err := backupProtectedFileShareIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	if _, err := b.api.Delete(ctx, vaultName, rgName, backupFabricAzure, containerName, itemName, nil); err != nil && !isDeleteSuccessError(err) {
		return &resource.DeleteResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationDelete,
				OperationStatus: resource.OperationStatusFailure,
				NativeID:        request.NativeID,
				ErrorCode:       operationErrorCode(err),
				StatusMessage:   err.Error(),
			},
		}, nil
	}

	saRG, saName, _ := backupContainerNameParts(containerName)
	state := protectedFileShareRequestID{
		Phase:                       protectedFileSharePhasePurge,
		Operation:                   lroOpDelete,
		NativeID:                    request.NativeID,
		ResourceGroupName:           rgName,
		VaultName:                   vaultName,
		ContainerName:               containerName,
		StorageAccountResourceGroup: saRG,
		StorageAccountName:          saName,
	}
	reqID, err := state.encode()
	if err != nil {
		return nil, err
	}

	return &resource.DeleteResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationDelete,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       reqID,
			NativeID:        request.NativeID,
		},
	}, nil
}

func (b *BackupProtectedFileShare) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	state, err := decodeProtectedFileShareRequestID(request.RequestID)
	if err != nil {
		return nil, err
	}

	if state.Phase == protectedFileSharePhasePurge {
		return b.advancePurge(ctx, state, request.RequestID)
	}

	// Whatever the token still says, an item that already exists settles the
	// operation. This runs first so a poll never re-writes an item ARM has
	// already accepted, and so the chain finishes even if the phase in the token
	// never advances.
	item, nativeID, containerName, err := b.locateItem(ctx, state)
	if err != nil {
		return lroFailure(state.operation(), request.RequestID, operationErrorCode(err), err.Error()), nil
	}
	if item != nil {
		return b.itemStatus(state, item, nativeID, containerName, request.RequestID)
	}

	if state.Phase == protectedFileSharePhaseRegister {
		poller, err := resumePoller[armrecoveryservicesbackup.ProtectionContainersClientRegisterResponse](b.pipeline, state.ResumeToken)
		if err != nil {
			return lroFailure(state.operation(), request.RequestID, resource.OperationErrorCodeGeneralServiceException,
				fmt.Sprintf("failed to resume poller: %v", err)), fmt.Errorf("failed to resume poller: %w", err)
		}
		if !poller.Done() {
			if _, err := poller.Poll(ctx); err != nil {
				return lroFailure(state.operation(), request.RequestID, operationErrorCode(err), err.Error()), nil
			}
			if !poller.Done() {
				return lroInProgress(state.operation(), request.RequestID, state.NativeID), nil
			}
		}
		if _, err := poller.Result(ctx); err != nil {
			return lroFailure(state.operation(), request.RequestID, operationErrorCode(err), err.Error()), nil
		}
	}

	progress, err := b.advanceInquire(ctx, state, request.RequestID)
	if err != nil {
		return nil, err
	}
	return &resource.StatusResult{ProgressResult: progress}, nil
}

// List enumerates the vault's protected items and keeps the Azure Files ones.
func (b *BackupProtectedFileShare) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	vaultName := request.AdditionalProperties["vaultName"]
	rgName := request.AdditionalProperties["resourceGroupName"]
	if vaultName == "" || rgName == "" {
		return nil, fmt.Errorf("vaultName and resourceGroupName are required to list protected file shares")
	}

	filter := "backupManagementType eq 'AzureStorage' and itemType eq 'AzureFileShare'"
	pager := b.listAPI.NewListPager(vaultName, rgName, &armrecoveryservicesbackup.BackupProtectedItemsClientListOptions{
		Filter: &filter,
	})

	var nativeIDs []string
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list protected file shares: %w", err)
		}
		for _, item := range page.Value {
			if item == nil || item.ID == nil {
				continue
			}
			if _, ok := item.Properties.(*armrecoveryservicesbackup.AzureFileshareProtectedItem); !ok {
				continue
			}
			nativeIDs = append(nativeIDs, *item.ID)
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
