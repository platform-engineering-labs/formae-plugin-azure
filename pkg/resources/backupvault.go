// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/dataprotection/armdataprotection/v3"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeBackupVault = "AZURE::DataProtection::BackupVault"

// backupVaultsAPI is the armdataprotection surface used here. Create, Update and
// Delete are all LROs. Note the list pagers are named GetIn*, not List*.
type backupVaultsAPI interface {
	BeginCreateOrUpdate(ctx context.Context, resourceGroupName string, vaultName string, parameters armdataprotection.BackupVaultResource, options *armdataprotection.BackupVaultsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armdataprotection.BackupVaultsClientCreateOrUpdateResponse], error)
	Get(ctx context.Context, resourceGroupName string, vaultName string, options *armdataprotection.BackupVaultsClientGetOptions) (armdataprotection.BackupVaultsClientGetResponse, error)
	BeginUpdate(ctx context.Context, resourceGroupName string, vaultName string, parameters armdataprotection.PatchResourceRequestInput, options *armdataprotection.BackupVaultsClientBeginUpdateOptions) (*runtime.Poller[armdataprotection.BackupVaultsClientUpdateResponse], error)
	BeginDelete(ctx context.Context, resourceGroupName string, vaultName string, options *armdataprotection.BackupVaultsClientBeginDeleteOptions) (*runtime.Poller[armdataprotection.BackupVaultsClientDeleteResponse], error)
	NewGetInSubscriptionPager(options *armdataprotection.BackupVaultsClientGetInSubscriptionOptions) *runtime.Pager[armdataprotection.BackupVaultsClientGetInSubscriptionResponse]
	NewGetInResourceGroupPager(resourceGroupName string, options *armdataprotection.BackupVaultsClientGetInResourceGroupOptions) *runtime.Pager[armdataprotection.BackupVaultsClientGetInResourceGroupResponse]
}

func init() {
	registry.Register(ResourceTypeBackupVault, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &BackupVault{
			api:      c.BackupVaultsClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// BackupVault is the provisioner for Backup vaults
// (Microsoft.DataProtection/backupVaults).
type BackupVault struct {
	api      backupVaultsAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

// backupVaultProps mirrors schema/pkl/dataprotection/backupvault.pkl.
type backupVaultProps struct {
	Name                          string                 `json:"name"`
	Location                      string                 `json:"location"`
	ResourceGroupName             string                 `json:"resourceGroupName"`
	StorageSettings               []backupStorageSetting `json:"storageSettings"`
	SoftDeleteState               string                 `json:"softDeleteState"`
	SoftDeleteRetentionDays       *float64               `json:"softDeleteRetentionDays"`
	CrossSubscriptionRestoreState string                 `json:"crossSubscriptionRestoreState"`
}

type backupStorageSetting struct {
	DatastoreType string `json:"datastoreType"`
	Type          string `json:"type"`
}

func backupVaultIDParts(resourceID string) (rgName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "backupvaults")
	if err != nil {
		return "", "", err
	}
	return rgName, names["backupvaults"], nil
}

func (b *BackupVault) buildPropertiesFromResult(vault *armdataprotection.BackupVaultResource, rgName string) map[string]any {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName

	if vault.ID != nil {
		props["id"] = *vault.ID
	}
	if vault.Name != nil {
		props["name"] = *vault.Name
	}
	if vault.Location != nil {
		props["location"] = normalizeAzureLocation(*vault.Location)
	}

	if p := vault.Properties; p != nil {
		settings := make([]map[string]any, 0, len(p.StorageSettings))
		for _, st := range p.StorageSettings {
			if st == nil {
				continue
			}
			entry := map[string]any{}
			if st.DatastoreType != nil {
				entry["datastoreType"] = canonicalizeEnum(string(*st.DatastoreType),
					"VaultStore", "OperationalStore", "ArchiveStore")
			}
			if st.Type != nil {
				entry["type"] = canonicalizeEnum(string(*st.Type),
					"LocallyRedundant", "ZoneRedundant", "GeoRedundant")
			}
			if len(entry) > 0 {
				settings = append(settings, entry)
			}
		}
		if len(settings) > 0 {
			props["storageSettings"] = settings
		}

		if sec := p.SecuritySettings; sec != nil {
			if sd := sec.SoftDeleteSettings; sd != nil {
				if sd.State != nil {
					props["softDeleteState"] = canonicalizeEnum(string(*sd.State), "Off", "On", "AlwaysOn")
				}
				if sd.RetentionDurationInDays != nil {
					props["softDeleteRetentionDays"] = *sd.RetentionDurationInDays
				}
			}
		}
		if fs := p.FeatureSettings; fs != nil {
			if cs := fs.CrossSubscriptionRestoreSettings; cs != nil && cs.State != nil {
				props["crossSubscriptionRestoreState"] = canonicalizeEnum(string(*cs.State),
					"Enabled", "Disabled", "PermanentlyDisabled")
			}
		}
	}

	if tags := azureTagsToFormaeTags(vault.Tags); tags != nil {
		props["Tags"] = tags
	}

	return props
}

func backupVaultSecuritySettings(props backupVaultProps) *armdataprotection.SecuritySettings {
	if props.SoftDeleteState == "" && props.SoftDeleteRetentionDays == nil {
		return nil
	}
	sd := &armdataprotection.SoftDeleteSettings{}
	if props.SoftDeleteState != "" {
		sd.State = to.Ptr(armdataprotection.SoftDeleteState(props.SoftDeleteState))
	}
	if props.SoftDeleteRetentionDays != nil {
		sd.RetentionDurationInDays = props.SoftDeleteRetentionDays
	}
	return &armdataprotection.SecuritySettings{SoftDeleteSettings: sd}
}

func backupVaultFeatureSettings(props backupVaultProps) *armdataprotection.FeatureSettings {
	if props.CrossSubscriptionRestoreState == "" {
		return nil
	}
	return &armdataprotection.FeatureSettings{
		CrossSubscriptionRestoreSettings: &armdataprotection.CrossSubscriptionRestoreSettings{
			State: to.Ptr(armdataprotection.CrossSubscriptionRestoreState(props.CrossSubscriptionRestoreState)),
		},
	}
}

func (b *BackupVault) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props backupVaultProps
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	if props.Location == "" {
		return nil, fmt.Errorf("location is required")
	}
	if len(props.StorageSettings) == 0 {
		return nil, fmt.Errorf("at least one storageSetting is required")
	}
	name := props.Name
	if name == "" {
		name = request.Label
	}
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}

	storage := make([]*armdataprotection.StorageSetting, 0, len(props.StorageSettings))
	for _, st := range props.StorageSettings {
		entry := &armdataprotection.StorageSetting{}
		if st.DatastoreType != "" {
			entry.DatastoreType = to.Ptr(armdataprotection.StorageSettingStoreTypes(st.DatastoreType))
		}
		if st.Type != "" {
			entry.Type = to.Ptr(armdataprotection.StorageSettingTypes(st.Type))
		}
		storage = append(storage, entry)
	}

	params := armdataprotection.BackupVaultResource{
		Location: to.Ptr(props.Location),
		Properties: &armdataprotection.BackupVault{
			StorageSettings:  storage,
			SecuritySettings: backupVaultSecuritySettings(props),
			FeatureSettings:  backupVaultFeatureSettings(props),
		},
	}
	if azureTags := formaeTagsToAzureTags(request.Properties); azureTags != nil {
		params.Tags = azureTags
	}

	poller, err := b.api.BeginCreateOrUpdate(ctx, props.ResourceGroupName, name, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.DataProtection/backupVaults/%s",
		b.config.SubscriptionId, props.ResourceGroupName, name)

	if poller.Done() {
		result, err := poller.Result(ctx)
		if err != nil {
			return &resource.CreateResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationCreate,
					OperationStatus: resource.OperationStatusFailure,
					ErrorCode:       operationErrorCode(err),
				},
			}, nil
		}
		propsJSON, err := json.Marshal(b.buildPropertiesFromResult(&result.BackupVaultResource, props.ResourceGroupName))
		if err != nil {
			return nil, fmt.Errorf("failed to marshal response properties: %w", err)
		}
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:          resource.OperationCreate,
				OperationStatus:    resource.OperationStatusSuccess,
				NativeID:           *result.ID,
				ResourceProperties: propsJSON,
			},
		}, nil
	}

	resumeToken, err := poller.ResumeToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get resume token: %w", err)
	}
	reqIDJSON, err := encodeLROStart(lroOpCreate, resumeToken, expectedNativeID)
	if err != nil {
		return nil, err
	}

	return &resource.CreateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationCreate,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       reqIDJSON,
			NativeID:        expectedNativeID,
		},
	}, nil
}

func (b *BackupVault) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, name, err := backupVaultIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := b.api.Get(ctx, rgName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(b.buildPropertiesFromResult(&result.BackupVaultResource, rgName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeBackupVault,
		Properties:   string(propsJSON),
	}, nil
}

// Update patches only what ARM's PatchBackupVaultInput accepts: security and
// feature settings plus tags. storageSettings is createOnly in the schema because
// the patch body cannot carry it.
func (b *BackupVault) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, name, err := backupVaultIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props backupVaultProps
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	params := armdataprotection.PatchResourceRequestInput{
		Properties: &armdataprotection.PatchBackupVaultInput{
			SecuritySettings: backupVaultSecuritySettings(props),
			FeatureSettings:  backupVaultFeatureSettings(props),
		},
	}
	if azureTags := formaeTagsToAzureTags(request.DesiredProperties); azureTags != nil {
		params.Tags = azureTags
	}

	poller, err := b.api.BeginUpdate(ctx, rgName, name, params, nil)
	if err != nil {
		return &resource.UpdateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationUpdate,
				OperationStatus: resource.OperationStatusFailure,
				NativeID:        request.NativeID,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	if poller.Done() {
		result, err := poller.Result(ctx)
		if err != nil {
			return &resource.UpdateResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationUpdate,
					OperationStatus: resource.OperationStatusFailure,
					NativeID:        request.NativeID,
					ErrorCode:       operationErrorCode(err),
				},
			}, nil
		}
		propsJSON, err := json.Marshal(b.buildPropertiesFromResult(&result.BackupVaultResource, rgName))
		if err != nil {
			return nil, fmt.Errorf("failed to marshal response properties: %w", err)
		}
		return &resource.UpdateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:          resource.OperationUpdate,
				OperationStatus:    resource.OperationStatusSuccess,
				NativeID:           request.NativeID,
				ResourceProperties: propsJSON,
			},
		}, nil
	}

	resumeToken, err := poller.ResumeToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get resume token: %w", err)
	}
	reqIDJSON, err := encodeLROStart(lroOpUpdate, resumeToken, request.NativeID)
	if err != nil {
		return nil, err
	}

	return &resource.UpdateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationUpdate,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       reqIDJSON,
			NativeID:        request.NativeID,
		},
	}, nil
}

func (b *BackupVault) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, name, err := backupVaultIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, err := b.api.BeginDelete(ctx, rgName, name, nil)
	if err != nil {
		if isDeleteSuccessError(err) {
			return &resource.DeleteResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationDelete,
					OperationStatus: resource.OperationStatusSuccess,
					NativeID:        request.NativeID,
				},
			}, nil
		}
		return &resource.DeleteResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationDelete,
				OperationStatus: resource.OperationStatusFailure,
				NativeID:        request.NativeID,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	if poller.Done() {
		if _, err := poller.Result(ctx); err != nil && !isDeleteSuccessError(err) {
			return &resource.DeleteResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationDelete,
					OperationStatus: resource.OperationStatusFailure,
					NativeID:        request.NativeID,
					ErrorCode:       operationErrorCode(err),
				},
			}, nil
		}
		return &resource.DeleteResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationDelete,
				OperationStatus: resource.OperationStatusSuccess,
				NativeID:        request.NativeID,
			},
		}, nil
	}

	resumeToken, err := poller.ResumeToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get resume token: %w", err)
	}
	reqIDJSON, err := encodeLROStart(lroOpDelete, resumeToken, request.NativeID)
	if err != nil {
		return nil, err
	}

	return &resource.DeleteResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationDelete,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       reqIDJSON,
			NativeID:        request.NativeID,
		},
	}, nil
}

func (b *BackupVault) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	reqID, err := decodeLROStatus(request.RequestID)
	if err != nil {
		return nil, err
	}

	switch reqID.OperationType {
	case lroOpCreate:
		return statusLRO(ctx, request, &reqID, resource.OperationCreate,
			func(token string) (*runtime.Poller[armdataprotection.BackupVaultsClientCreateOrUpdateResponse], error) {
				return resumePoller[armdataprotection.BackupVaultsClientCreateOrUpdateResponse](b.pipeline, token)
			},
			func(_ context.Context, result armdataprotection.BackupVaultsClientCreateOrUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				return b.completeFromVault(&result.BackupVaultResource)
			})
	case lroOpUpdate:
		return statusLRO(ctx, request, &reqID, resource.OperationUpdate,
			func(token string) (*runtime.Poller[armdataprotection.BackupVaultsClientUpdateResponse], error) {
				return resumePoller[armdataprotection.BackupVaultsClientUpdateResponse](b.pipeline, token)
			},
			func(_ context.Context, result armdataprotection.BackupVaultsClientUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				return b.completeFromVault(&result.BackupVaultResource)
			})
	case lroOpDelete:
		return statusDeleteLRO(ctx, request, &reqID,
			func(token string) (*runtime.Poller[armdataprotection.BackupVaultsClientDeleteResponse], error) {
				return resumePoller[armdataprotection.BackupVaultsClientDeleteResponse](b.pipeline, token)
			}, nil)
	default:
		return nil, fmt.Errorf("unknown operation type: %s", reqID.OperationType)
	}
}

func (b *BackupVault) completeFromVault(vault *armdataprotection.BackupVaultResource) (string, json.RawMessage, error) {
	nativeID := ""
	rgName := ""
	if vault.ID != nil {
		nativeID = *vault.ID
		if rg, _, err := backupVaultIDParts(*vault.ID); err == nil {
			rgName = rg
		}
	}
	propsJSON, err := json.Marshal(b.buildPropertiesFromResult(vault, rgName))
	if err != nil {
		return "", nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return nativeID, propsJSON, nil
}

func (b *BackupVault) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]

	var nativeIDs []string

	if rgName != "" {
		pager := b.api.NewGetInResourceGroupPager(rgName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list backup vaults: %w", err)
			}
			for _, vault := range page.Value {
				if vault.ID != nil {
					nativeIDs = append(nativeIDs, *vault.ID)
				}
			}
		}
		return &resource.ListResult{NativeIDs: nativeIDs}, nil
	}

	pager := b.api.NewGetInSubscriptionPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list backup vaults: %w", err)
		}
		for _, vault := range page.Value {
			if vault.ID != nil {
				nativeIDs = append(nativeIDs, *vault.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
