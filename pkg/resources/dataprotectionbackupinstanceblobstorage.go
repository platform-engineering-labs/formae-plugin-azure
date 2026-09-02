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

const ResourceTypeDataProtectionBackupInstanceBlobStorage = "AZURE::DataProtection::BackupInstanceBlobStorage"

const (
	// datasourceTypeBlobStorage is the `datasourceType` ARM matches against the
	// policy's own datasourceTypes. It names the blob service, not the account.
	datasourceTypeBlobStorage = "Microsoft.Storage/storageAccounts/blobServices"
	// resourceTypeBlobStorageAccount is the ARM type of the resource the ID points
	// at, which IS the account.
	resourceTypeBlobStorageAccount = "Microsoft.Storage/storageAccounts"
)

// dpBlobBackupInstancesAPI is the armdataprotection surface used here. Create and
// Delete are LROs; Get and the list pager are synchronous. There is no PATCH verb —
// an update is another BeginCreateOrUpdate (trap 8).
type dpBlobBackupInstancesAPI interface {
	BeginCreateOrUpdate(ctx context.Context, resourceGroupName string, vaultName string, backupInstanceName string, parameters armdataprotection.BackupInstanceResource, options *armdataprotection.BackupInstancesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armdataprotection.BackupInstancesClientCreateOrUpdateResponse], error)
	Get(ctx context.Context, resourceGroupName string, vaultName string, backupInstanceName string, options *armdataprotection.BackupInstancesClientGetOptions) (armdataprotection.BackupInstancesClientGetResponse, error)
	BeginDelete(ctx context.Context, resourceGroupName string, vaultName string, backupInstanceName string, options *armdataprotection.BackupInstancesClientBeginDeleteOptions) (*runtime.Poller[armdataprotection.BackupInstancesClientDeleteResponse], error)
	NewListPager(resourceGroupName string, vaultName string, options *armdataprotection.BackupInstancesClientListOptions) *runtime.Pager[armdataprotection.BackupInstancesClientListResponse]
}

func init() {
	registry.Register(ResourceTypeDataProtectionBackupInstanceBlobStorage, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &DataProtectionBackupInstanceBlobStorage{
			api:      c.DataProtectionBackupInstancesClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// DataProtectionBackupInstanceBlobStorage is the provisioner for a blob-storage
// backup instance
// (`Microsoft.DataProtection/backupVaults/backupInstances`, datasource
// `Microsoft.Storage/storageAccounts/blobServices`).
type DataProtectionBackupInstanceBlobStorage struct {
	api      dpBlobBackupInstancesAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

// dpBlobInstanceProps mirrors
// schema/pkl/dataprotection/dataprotectionbackupinstanceblobstorage.pkl.
type dpBlobInstanceProps struct {
	Name                       string   `json:"name"`
	ResourceGroupName          string   `json:"resourceGroupName"`
	VaultName                  string   `json:"vaultName"`
	DataSourceID               string   `json:"dataSourceId"`
	DataSourceLocation         string   `json:"dataSourceLocation"`
	PolicyID                   string   `json:"policyId"`
	FriendlyName               string   `json:"friendlyName"`
	ContainersList             []string `json:"containersList"`
	UserAssignedIdentityArmURL string   `json:"userAssignedIdentityArmUrl"`
}

func dpBackupInstanceIDParts(resourceID string) (rgName, vaultName, instanceName string, err error) {
	rgName, names, err := armIDParts(resourceID, "backupvaults", "backupinstances")
	if err != nil {
		return "", "", "", err
	}
	return rgName, names["backupvaults"], names["backupinstances"], nil
}

// dpDatasourceLeafName pulls the datasource's own name out of its ARM ID. ARM
// requires `resourceName` alongside `resourceID` and rejects the pair when they
// disagree, so it is derived rather than asked for.
func dpDatasourceLeafName(resourceID string) (string, error) {
	id, err := parseARMResourceID(resourceID)
	if err != nil {
		return "", err
	}
	if id.Name == "" {
		return "", fmt.Errorf("dataSourceId %q names no resource", resourceID)
	}
	return id.Name, nil
}

func (d *DataProtectionBackupInstanceBlobStorage) buildInstance(props dpBlobInstanceProps) (*armdataprotection.BackupInstance, error) {
	leafName, err := dpDatasourceLeafName(props.DataSourceID)
	if err != nil {
		return nil, err
	}

	policyInfo := &armdataprotection.PolicyInfo{PolicyID: to.Ptr(props.PolicyID)}
	// A vault-tier blob policy needs the containers spelled out; an
	// operational-tier-only policy takes the whole account and carries none.
	if len(props.ContainersList) > 0 {
		policyInfo.PolicyParameters = &armdataprotection.PolicyParameters{
			BackupDatasourceParametersList: []armdataprotection.BackupDatasourceParametersClassification{
				&armdataprotection.BlobBackupDatasourceParameters{
					ObjectType:     to.Ptr("BlobBackupDatasourceParameters"),
					ContainersList: stringPointers(props.ContainersList),
				},
			},
		}
	}

	instance := &armdataprotection.BackupInstance{
		ObjectType: to.Ptr("BackupInstance"),
		DataSourceInfo: &armdataprotection.Datasource{
			ObjectType:       to.Ptr("Datasource"),
			ResourceID:       to.Ptr(props.DataSourceID),
			ResourceURI:      to.Ptr(props.DataSourceID),
			ResourceName:     to.Ptr(leafName),
			ResourceType:     to.Ptr(resourceTypeBlobStorageAccount),
			DatasourceType:   to.Ptr(datasourceTypeBlobStorage),
			ResourceLocation: to.Ptr(props.DataSourceLocation),
		},
		PolicyInfo: policyInfo,
	}
	if props.FriendlyName != "" {
		instance.FriendlyName = to.Ptr(props.FriendlyName)
	}
	// Omitting identityDetails entirely is ARM's documented "system assigned"
	// default, so only a user-assigned identity is ever sent.
	if props.UserAssignedIdentityArmURL != "" {
		instance.IdentityDetails = &armdataprotection.IdentityDetails{
			UseSystemAssignedIdentity:  to.Ptr(false),
			UserAssignedIdentityArmURL: to.Ptr(props.UserAssignedIdentityArmURL),
		}
	}
	return instance, nil
}

func (d *DataProtectionBackupInstanceBlobStorage) buildPropertiesFromResult(res *armdataprotection.BackupInstanceResource, rgName, vaultName string) map[string]any {
	props := map[string]any{
		"resourceGroupName": rgName,
		"vaultName":         vaultName,
	}
	if res.ID != nil {
		props["id"] = *res.ID
	}
	if res.Name != nil {
		props["name"] = *res.Name
	}

	if p := res.Properties; p != nil {
		if ds := p.DataSourceInfo; ds != nil {
			if ds.ResourceID != nil {
				props["dataSourceId"] = *ds.ResourceID
			}
			if ds.ResourceLocation != nil {
				props["dataSourceLocation"] = normalizeAzureLocation(*ds.ResourceLocation)
			}
		}
		if pi := p.PolicyInfo; pi != nil {
			if pi.PolicyID != nil {
				props["policyId"] = *pi.PolicyID
			}
			if pp := pi.PolicyParameters; pp != nil {
				for _, raw := range pp.BackupDatasourceParametersList {
					blob, ok := raw.(*armdataprotection.BlobBackupDatasourceParameters)
					if !ok {
						continue
					}
					if containers := stringsFromPointers(blob.ContainersList); len(containers) > 0 {
						props["containersList"] = containers
					}
				}
			}
		}
		if p.FriendlyName != nil {
			props["friendlyName"] = *p.FriendlyName
		}
		if id := p.IdentityDetails; id != nil && id.UserAssignedIdentityArmURL != nil {
			props["userAssignedIdentityArmUrl"] = *id.UserAssignedIdentityArmURL
		}
		if p.CurrentProtectionState != nil {
			props["currentProtectionState"] = string(*p.CurrentProtectionState)
		}
	}

	if tags := azureTagsToFormaeTags(res.Tags); tags != nil {
		props["Tags"] = tags
	}

	return props
}

func (d *DataProtectionBackupInstanceBlobStorage) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props dpBlobInstanceProps
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	if props.VaultName == "" {
		return nil, fmt.Errorf("vaultName is required")
	}
	if props.DataSourceID == "" {
		return nil, fmt.Errorf("dataSourceId is required")
	}
	if props.DataSourceLocation == "" {
		return nil, fmt.Errorf("dataSourceLocation is required")
	}
	if props.PolicyID == "" {
		return nil, fmt.Errorf("policyId is required")
	}
	name := props.Name
	if name == "" {
		name = request.Label
	}
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}

	instance, err := d.buildInstance(props)
	if err != nil {
		return nil, err
	}

	params := armdataprotection.BackupInstanceResource{Properties: instance}
	if azureTags := formaeTagsToAzureTags(request.Properties); azureTags != nil {
		params.Tags = azureTags
	}

	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.DataProtection/backupVaults/%s/backupInstances/%s",
		d.config.SubscriptionId, props.ResourceGroupName, props.VaultName, name)

	poller, err := d.api.BeginCreateOrUpdate(ctx, props.ResourceGroupName, props.VaultName, name, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				NativeID:        expectedNativeID,
				ErrorCode:       operationErrorCode(err),
				StatusMessage:   err.Error(),
			},
		}, nil
	}

	if poller.Done() {
		result, err := poller.Result(ctx)
		if err != nil {
			return &resource.CreateResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationCreate,
					OperationStatus: resource.OperationStatusFailure,
					NativeID:        expectedNativeID,
					ErrorCode:       operationErrorCode(err),
					StatusMessage:   err.Error(),
				},
			}, nil
		}
		propsJSON, err := json.Marshal(d.buildPropertiesFromResult(&result.BackupInstanceResource, props.ResourceGroupName, props.VaultName))
		if err != nil {
			return nil, fmt.Errorf("failed to marshal response properties: %w", err)
		}
		nativeID := expectedNativeID
		if result.ID != nil {
			nativeID = *result.ID
		}
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:          resource.OperationCreate,
				OperationStatus:    resource.OperationStatusSuccess,
				NativeID:           nativeID,
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

func (d *DataProtectionBackupInstanceBlobStorage) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, vaultName, name, err := dpBackupInstanceIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := d.api.Get(ctx, rgName, vaultName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(d.buildPropertiesFromResult(&result.BackupInstanceResource, rgName, vaultName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}

	return &resource.ReadResult{
		ResourceType: ResourceTypeDataProtectionBackupInstanceBlobStorage,
		Properties:   string(propsJSON),
	}, nil
}

// Update re-PUTs the instance: the API has no PATCH verb. dataSourceId is
// createOnly in the schema, so in practice this changes the policy the instance
// points at, its friendly name, or its container list.
func (d *DataProtectionBackupInstanceBlobStorage) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, vaultName, name, err := dpBackupInstanceIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props dpBlobInstanceProps
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse desired properties: %w", err)
	}

	instance, err := d.buildInstance(props)
	if err != nil {
		return nil, err
	}

	params := armdataprotection.BackupInstanceResource{Properties: instance}
	if azureTags := formaeTagsToAzureTags(request.DesiredProperties); azureTags != nil {
		params.Tags = azureTags
	}

	poller, err := d.api.BeginCreateOrUpdate(ctx, rgName, vaultName, name, params, nil)
	if err != nil {
		return &resource.UpdateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationUpdate,
				OperationStatus: resource.OperationStatusFailure,
				NativeID:        request.NativeID,
				ErrorCode:       operationErrorCode(err),
				StatusMessage:   err.Error(),
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
					StatusMessage:   err.Error(),
				},
			}, nil
		}
		propsJSON, err := json.Marshal(d.buildPropertiesFromResult(&result.BackupInstanceResource, rgName, vaultName))
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

func (d *DataProtectionBackupInstanceBlobStorage) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, vaultName, name, err := dpBackupInstanceIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, err := d.api.BeginDelete(ctx, rgName, vaultName, name, nil)
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
				StatusMessage:   err.Error(),
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
					StatusMessage:   err.Error(),
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

func (d *DataProtectionBackupInstanceBlobStorage) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	reqID, err := decodeLROStatus(request.RequestID)
	if err != nil {
		return nil, err
	}

	switch reqID.OperationType {
	case lroOpCreate, lroOpUpdate:
		operation := resource.OperationCreate
		if reqID.OperationType == lroOpUpdate {
			operation = resource.OperationUpdate
		}
		return statusLRO(ctx, request, &reqID, operation,
			func(token string) (*runtime.Poller[armdataprotection.BackupInstancesClientCreateOrUpdateResponse], error) {
				return resumePoller[armdataprotection.BackupInstancesClientCreateOrUpdateResponse](d.pipeline, token)
			},
			func(_ context.Context, result armdataprotection.BackupInstancesClientCreateOrUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				return d.completeFromInstance(&result.BackupInstanceResource)
			})
	case lroOpDelete:
		return statusDeleteLRO(ctx, request, &reqID,
			func(token string) (*runtime.Poller[armdataprotection.BackupInstancesClientDeleteResponse], error) {
				return resumePoller[armdataprotection.BackupInstancesClientDeleteResponse](d.pipeline, token)
			}, nil)
	default:
		return nil, fmt.Errorf("unknown operation type: %s", reqID.OperationType)
	}
}

func (d *DataProtectionBackupInstanceBlobStorage) completeFromInstance(res *armdataprotection.BackupInstanceResource) (string, json.RawMessage, error) {
	nativeID := ""
	rgName, vaultName := "", ""
	if res.ID != nil {
		nativeID = *res.ID
		if rg, vault, _, err := dpBackupInstanceIDParts(*res.ID); err == nil {
			rgName, vaultName = rg, vault
		}
	}
	propsJSON, err := json.Marshal(d.buildPropertiesFromResult(res, rgName, vaultName))
	if err != nil {
		return "", nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return nativeID, propsJSON, nil
}

// List enumerates one vault's backup instances. ARM has no cross-vault pager, so an
// empty scope yields nothing rather than falling back subscription-wide, and the
// type needs no subscriptionWideList entry.
//
// The pager returns every instance in the vault regardless of datasource, so filter
// to blob services; otherwise this type would also claim the disk instances.
func (d *DataProtectionBackupInstanceBlobStorage) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	vaultName := request.AdditionalProperties["vaultName"]
	if rgName == "" || vaultName == "" {
		return &resource.ListResult{}, nil
	}

	var nativeIDs []string
	pager := d.api.NewListPager(rgName, vaultName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list backup instances: %w", err)
		}
		for _, item := range page.Value {
			if item == nil || item.ID == nil {
				continue
			}
			if !dpInstanceHasDatasource(item, datasourceTypeBlobStorage) {
				continue
			}
			nativeIDs = append(nativeIDs, *item.ID)
		}
	}

	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}

// dpInstanceHasDatasource reports whether a listed instance protects the given
// datasource type. Shared by both backup-instance flavours.
func dpInstanceHasDatasource(item *armdataprotection.BackupInstanceResource, datasourceType string) bool {
	if item.Properties == nil || item.Properties.DataSourceInfo == nil {
		return false
	}
	dst := item.Properties.DataSourceInfo.DatasourceType
	return dst != nil && *dst == datasourceType
}
