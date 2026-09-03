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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/recoveryservices/armrecoveryservices"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeRecoveryServicesVault = "AZURE::RecoveryServices::Vault"

// recoveryServicesVaultsAPI is the armrecoveryservices surface used here.
//
// The asymmetry is ARM's, not ours: create and update are long-running
// (BeginCreateOrUpdate / BeginUpdate) but Delete is a plain synchronous call
// that either returns 204 or fails outright — it never hands back an
// Azure-AsyncOperation to poll.
type recoveryServicesVaultsAPI interface {
	BeginCreateOrUpdate(ctx context.Context, resourceGroupName string, vaultName string, vault armrecoveryservices.Vault, options *armrecoveryservices.VaultsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armrecoveryservices.VaultsClientCreateOrUpdateResponse], error)
	Get(ctx context.Context, resourceGroupName string, vaultName string, options *armrecoveryservices.VaultsClientGetOptions) (armrecoveryservices.VaultsClientGetResponse, error)
	Delete(ctx context.Context, resourceGroupName string, vaultName string, options *armrecoveryservices.VaultsClientDeleteOptions) (armrecoveryservices.VaultsClientDeleteResponse, error)
	NewListBySubscriptionIDPager(options *armrecoveryservices.VaultsClientListBySubscriptionIDOptions) *runtime.Pager[armrecoveryservices.VaultsClientListBySubscriptionIDResponse]
	NewListByResourceGroupPager(resourceGroupName string, options *armrecoveryservices.VaultsClientListByResourceGroupOptions) *runtime.Pager[armrecoveryservices.VaultsClientListByResourceGroupResponse]
}

func init() {
	registry.Register(ResourceTypeRecoveryServicesVault, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &RecoveryServicesVault{
			api:      c.RecoveryServicesVaultsClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// RecoveryServicesVault is the provisioner for Recovery Services vaults
// (Microsoft.RecoveryServices/vaults).
type RecoveryServicesVault struct {
	api      recoveryServicesVaultsAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

// recoveryServicesVaultProps mirrors schema/pkl/recoveryservices/vault.pkl.
type recoveryServicesVaultProps struct {
	Name                          string `json:"name"`
	Location                      string `json:"location"`
	ResourceGroupName             string `json:"resourceGroupName"`
	SkuName                       string `json:"skuName"`
	SkuTier                       string `json:"skuTier"`
	PublicNetworkAccess           string `json:"publicNetworkAccess"`
	SoftDeleteState               string `json:"softDeleteState"`
	SoftDeleteRetentionDays       *int32 `json:"softDeleteRetentionDays"`
	ImmutabilityState             string `json:"immutabilityState"`
	CrossSubscriptionRestoreState string `json:"crossSubscriptionRestoreState"`
	AlertsForAllJobFailures       string `json:"alertsForAllJobFailures"`
	AlertsForCriticalOperations   string `json:"alertsForCriticalOperations"`
}

func recoveryServicesVaultIDParts(resourceID string) (rgName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "vaults")
	if err != nil {
		return "", "", err
	}
	return rgName, names["vaults"], nil
}

func (v *RecoveryServicesVault) buildPropertiesFromResult(vault *armrecoveryservices.Vault, rgName string) map[string]any {
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

	if sku := vault.SKU; sku != nil {
		if sku.Name != nil {
			props["skuName"] = canonicalizeEnum(string(*sku.Name), "Standard", "RS0")
		}
		if sku.Tier != nil {
			props["skuTier"] = *sku.Tier
		}
	}

	if p := vault.Properties; p != nil {
		if p.PublicNetworkAccess != nil {
			props["publicNetworkAccess"] = canonicalizeEnum(string(*p.PublicNetworkAccess), "Enabled", "Disabled")
		}
		if p.ProvisioningState != nil {
			props["provisioningState"] = *p.ProvisioningState
		}
		if sec := p.SecuritySettings; sec != nil {
			if sd := sec.SoftDeleteSettings; sd != nil {
				if sd.SoftDeleteState != nil {
					props["softDeleteState"] = canonicalizeEnum(string(*sd.SoftDeleteState),
						"Enabled", "Disabled", "AlwaysON")
				}
				if sd.SoftDeleteRetentionPeriodInDays != nil {
					props["softDeleteRetentionDays"] = *sd.SoftDeleteRetentionPeriodInDays
				}
			}
			if im := sec.ImmutabilitySettings; im != nil && im.State != nil {
				props["immutabilityState"] = canonicalizeEnum(string(*im.State), "Disabled", "Unlocked", "Locked")
			}
		}
		if rs := p.RestoreSettings; rs != nil {
			if cs := rs.CrossSubscriptionRestoreSettings; cs != nil && cs.CrossSubscriptionRestoreState != nil {
				props["crossSubscriptionRestoreState"] = canonicalizeEnum(string(*cs.CrossSubscriptionRestoreState),
					"Enabled", "Disabled", "PermanentlyDisabled")
			}
		}
		if ms := p.MonitoringSettings; ms != nil {
			if am := ms.AzureMonitorAlertSettings; am != nil && am.AlertsForAllJobFailures != nil {
				props["alertsForAllJobFailures"] = canonicalizeEnum(string(*am.AlertsForAllJobFailures), "Enabled", "Disabled")
			}
			if ca := ms.ClassicAlertSettings; ca != nil && ca.AlertsForCriticalOperations != nil {
				props["alertsForCriticalOperations"] = canonicalizeEnum(string(*ca.AlertsForCriticalOperations), "Enabled", "Disabled")
			}
		}
		// redundancySettings is read-only on the ARM contract: storage redundancy
		// is set through the separate backupstorageconfig sub-resource, not on the
		// vault body. Surfaced as top-level read-only properties so a discovered
		// vault reports what it actually has.
		if rd := p.RedundancySettings; rd != nil {
			if rd.StandardTierStorageRedundancy != nil {
				props["standardTierStorageRedundancy"] = canonicalizeEnum(string(*rd.StandardTierStorageRedundancy),
					"LocallyRedundant", "ZoneRedundant", "GeoRedundant")
			}
			if rd.CrossRegionRestore != nil {
				props["crossRegionRestore"] = canonicalizeEnum(string(*rd.CrossRegionRestore), "Enabled", "Disabled")
			}
		}
	}

	if tags := azureTagsToFormaeTags(vault.Tags); tags != nil {
		props["Tags"] = tags
	}

	return props
}

func recoveryServicesVaultSecuritySettings(props recoveryServicesVaultProps) *armrecoveryservices.SecuritySettings {
	var settings *armrecoveryservices.SecuritySettings

	if props.SoftDeleteState != "" || props.SoftDeleteRetentionDays != nil {
		sd := &armrecoveryservices.SoftDeleteSettings{}
		if props.SoftDeleteState != "" {
			sd.SoftDeleteState = to.Ptr(armrecoveryservices.SoftDeleteState(props.SoftDeleteState))
		}
		if props.SoftDeleteRetentionDays != nil {
			sd.SoftDeleteRetentionPeriodInDays = props.SoftDeleteRetentionDays
		}
		settings = &armrecoveryservices.SecuritySettings{SoftDeleteSettings: sd}
	}

	if props.ImmutabilityState != "" {
		if settings == nil {
			settings = &armrecoveryservices.SecuritySettings{}
		}
		settings.ImmutabilitySettings = &armrecoveryservices.ImmutabilitySettings{
			State: to.Ptr(armrecoveryservices.ImmutabilityState(props.ImmutabilityState)),
		}
	}

	return settings
}

func recoveryServicesVaultMonitoringSettings(props recoveryServicesVaultProps) *armrecoveryservices.MonitoringSettings {
	if props.AlertsForAllJobFailures == "" && props.AlertsForCriticalOperations == "" {
		return nil
	}
	settings := &armrecoveryservices.MonitoringSettings{}
	if props.AlertsForAllJobFailures != "" {
		settings.AzureMonitorAlertSettings = &armrecoveryservices.AzureMonitorAlertSettings{
			AlertsForAllJobFailures: to.Ptr(armrecoveryservices.AlertsState(props.AlertsForAllJobFailures)),
		}
	}
	if props.AlertsForCriticalOperations != "" {
		settings.ClassicAlertSettings = &armrecoveryservices.ClassicAlertSettings{
			AlertsForCriticalOperations: to.Ptr(armrecoveryservices.AlertsState(props.AlertsForCriticalOperations)),
		}
	}
	return settings
}

func recoveryServicesVaultRestoreSettings(props recoveryServicesVaultProps) *armrecoveryservices.RestoreSettings {
	if props.CrossSubscriptionRestoreState == "" {
		return nil
	}
	return &armrecoveryservices.RestoreSettings{
		CrossSubscriptionRestoreSettings: &armrecoveryservices.CrossSubscriptionRestoreSettings{
			CrossSubscriptionRestoreState: to.Ptr(armrecoveryservices.CrossSubscriptionRestoreState(props.CrossSubscriptionRestoreState)),
		},
	}
}

// vaultParams builds the PUT body used by both Create and Update.
//
// Update goes back through PUT rather than ARM's PATCH: the PATCH body for a
// Recovery Services vault is a full PatchVault anyway, and a PATCH that omits
// securitySettings leaves the previous value in place — which would make a
// removed field silently stick instead of reverting. A PUT of the whole desired
// vault is what reconcile means.
func recoveryServicesVaultParams(props recoveryServicesVaultProps, rawProperties []byte) armrecoveryservices.Vault {
	sku := &armrecoveryservices.SKU{
		Name: to.Ptr(armrecoveryservices.SKUName(props.SkuName)),
	}
	if props.SkuTier != "" {
		sku.Tier = to.Ptr(props.SkuTier)
	}

	vaultProps := &armrecoveryservices.VaultProperties{
		SecuritySettings:   recoveryServicesVaultSecuritySettings(props),
		MonitoringSettings: recoveryServicesVaultMonitoringSettings(props),
		RestoreSettings:    recoveryServicesVaultRestoreSettings(props),
	}
	if props.PublicNetworkAccess != "" {
		vaultProps.PublicNetworkAccess = to.Ptr(armrecoveryservices.PublicNetworkAccess(props.PublicNetworkAccess))
	}

	params := armrecoveryservices.Vault{
		Location:   to.Ptr(props.Location),
		SKU:        sku,
		Properties: vaultProps,
	}
	if azureTags := formaeTagsToAzureTags(rawProperties); azureTags != nil {
		params.Tags = azureTags
	}
	return params
}

func (v *RecoveryServicesVault) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props recoveryServicesVaultProps
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	if props.Location == "" {
		return nil, fmt.Errorf("location is required")
	}
	if props.SkuName == "" {
		return nil, fmt.Errorf("skuName is required")
	}
	name := props.Name
	if name == "" {
		name = request.Label
	}
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}

	poller, err := v.api.BeginCreateOrUpdate(ctx, props.ResourceGroupName, name,
		recoveryServicesVaultParams(props, request.Properties), nil)
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

	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.RecoveryServices/vaults/%s",
		v.config.SubscriptionId, props.ResourceGroupName, name)

	if poller.Done() {
		result, err := poller.Result(ctx)
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
		nativeID, propsJSON, err := v.completeFromVault(&result.Vault)
		if err != nil {
			return nil, err
		}
		if nativeID == "" {
			nativeID = expectedNativeID
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

func (v *RecoveryServicesVault) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, name, err := recoveryServicesVaultIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := v.api.Get(ctx, rgName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(v.buildPropertiesFromResult(&result.Vault, rgName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeRecoveryServicesVault,
		Properties:   string(propsJSON),
	}, nil
}

func (v *RecoveryServicesVault) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, name, err := recoveryServicesVaultIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props recoveryServicesVaultProps
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.Location == "" {
		return nil, fmt.Errorf("location is required")
	}
	if props.SkuName == "" {
		return nil, fmt.Errorf("skuName is required")
	}

	poller, err := v.api.BeginCreateOrUpdate(ctx, rgName, name,
		recoveryServicesVaultParams(props, request.DesiredProperties), nil)
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
		_, propsJSON, err := v.completeFromVault(&result.Vault)
		if err != nil {
			return nil, err
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

// Delete is synchronous. ARM refuses the call outright while the vault still has
// a registered container or a protected item attached, so the error text matters
// here more than usual — it is the only place the "cannot delete, items are still
// protected" reason ever surfaces.
func (v *RecoveryServicesVault) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, name, err := recoveryServicesVaultIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	if _, err := v.api.Delete(ctx, rgName, name, nil); err != nil && !isDeleteSuccessError(err) {
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

func (v *RecoveryServicesVault) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
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
			func(token string) (*runtime.Poller[armrecoveryservices.VaultsClientCreateOrUpdateResponse], error) {
				return resumePoller[armrecoveryservices.VaultsClientCreateOrUpdateResponse](v.pipeline, token)
			},
			func(_ context.Context, result armrecoveryservices.VaultsClientCreateOrUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				nativeID, propsJSON, err := v.completeFromVault(&result.Vault)
				if err != nil {
					return "", nil, err
				}
				if nativeID == "" {
					nativeID = reqID.NativeID
				}
				return nativeID, propsJSON, nil
			})
	default:
		return nil, fmt.Errorf("unknown operation type: %s", reqID.OperationType)
	}
}

func (v *RecoveryServicesVault) completeFromVault(vault *armrecoveryservices.Vault) (string, json.RawMessage, error) {
	nativeID := ""
	rgName := ""
	if vault.ID != nil {
		nativeID = *vault.ID
		if rg, _, err := recoveryServicesVaultIDParts(*vault.ID); err == nil {
			rgName = rg
		}
	}
	propsJSON, err := json.Marshal(v.buildPropertiesFromResult(vault, rgName))
	if err != nil {
		return "", nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return nativeID, propsJSON, nil
}

func (v *RecoveryServicesVault) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]

	var nativeIDs []string

	if rgName != "" {
		pager := v.api.NewListByResourceGroupPager(rgName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list recovery services vaults: %w", err)
			}
			for _, vault := range page.Value {
				if vault.ID != nil {
					nativeIDs = append(nativeIDs, *vault.ID)
				}
			}
		}
		return &resource.ListResult{NativeIDs: nativeIDs}, nil
	}

	pager := v.api.NewListBySubscriptionIDPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list recovery services vaults: %w", err)
		}
		for _, vault := range page.Value {
			if vault.ID != nil {
				nativeIDs = append(nativeIDs, *vault.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
