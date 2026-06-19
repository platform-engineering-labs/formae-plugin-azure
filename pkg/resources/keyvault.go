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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/keyvault/armkeyvault"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeKeyVault = "AZURE::KeyVault::Vault"

type vaultsAPI interface {
	BeginCreateOrUpdate(ctx context.Context, resourceGroupName string, vaultName string, parameters armkeyvault.VaultCreateOrUpdateParameters, options *armkeyvault.VaultsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armkeyvault.VaultsClientCreateOrUpdateResponse], error)
	Get(ctx context.Context, resourceGroupName string, vaultName string, options *armkeyvault.VaultsClientGetOptions) (armkeyvault.VaultsClientGetResponse, error)
	Delete(ctx context.Context, resourceGroupName string, vaultName string, options *armkeyvault.VaultsClientDeleteOptions) (armkeyvault.VaultsClientDeleteResponse, error)
	NewListByResourceGroupPager(resourceGroupName string, options *armkeyvault.VaultsClientListByResourceGroupOptions) *runtime.Pager[armkeyvault.VaultsClientListByResourceGroupResponse]
	NewListBySubscriptionPager(options *armkeyvault.VaultsClientListBySubscriptionOptions) *runtime.Pager[armkeyvault.VaultsClientListBySubscriptionResponse]
}

func init() {
	registry.Register(ResourceTypeKeyVault, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &KeyVault{
			api:      c.VaultsClient,
			config:   cfg,
			pipeline: c.Pipeline(),
		}
	})
}

// KeyVault is the provisioner for Azure Key Vaults.
type KeyVault struct {
	api      vaultsAPI
	config   *config.Config
	pipeline runtime.Pipeline
}

func (kv *KeyVault) parseNativeID(nativeID string) (rgName, vaultName string, err error) {
	rgName, names, err := armIDParts(nativeID, "vaults")
	if err != nil {
		return "", "", err
	}
	return rgName, names["vaults"], nil
}

// serializeKeyVaultProperties converts an Azure Vault to Formae property format
func serializeKeyVaultProperties(result armkeyvault.Vault, rgName, vaultName string) (json.RawMessage, error) {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	if result.Name != nil {
		props["name"] = *result.Name
	} else {
		props["name"] = vaultName
	}

	if result.Location != nil {
		props["location"] = *result.Location
	}

	if result.Properties != nil {
		if result.Properties.TenantID != nil {
			props["tenantId"] = *result.Properties.TenantID
		}

		if result.Properties.SKU != nil {
			sku := make(map[string]any)
			if result.Properties.SKU.Family != nil {
				sku["family"] = string(*result.Properties.SKU.Family)
			}
			if result.Properties.SKU.Name != nil {
				sku["name"] = string(*result.Properties.SKU.Name)
			}
			props["sku"] = sku
		}

		if result.Properties.VaultURI != nil {
			props["vaultUri"] = *result.Properties.VaultURI
		}

		if result.Properties.EnabledForDeployment != nil {
			props["enabledForDeployment"] = *result.Properties.EnabledForDeployment
		}

		if result.Properties.EnabledForDiskEncryption != nil {
			props["enabledForDiskEncryption"] = *result.Properties.EnabledForDiskEncryption
		}

		if result.Properties.EnabledForTemplateDeployment != nil {
			props["enabledForTemplateDeployment"] = *result.Properties.EnabledForTemplateDeployment
		}

		if result.Properties.EnableSoftDelete != nil {
			props["enableSoftDelete"] = *result.Properties.EnableSoftDelete
		}

		if result.Properties.SoftDeleteRetentionInDays != nil {
			props["softDeleteRetentionInDays"] = *result.Properties.SoftDeleteRetentionInDays
		}

		if result.Properties.EnablePurgeProtection != nil {
			props["enablePurgeProtection"] = *result.Properties.EnablePurgeProtection
		}

		if result.Properties.EnableRbacAuthorization != nil {
			props["enableRbacAuthorization"] = *result.Properties.EnableRbacAuthorization
		}

		// Serialize access policies
		if len(result.Properties.AccessPolicies) > 0 {
			accessPolicies := make([]map[string]any, 0, len(result.Properties.AccessPolicies))
			for _, ap := range result.Properties.AccessPolicies {
				policy := make(map[string]any)
				if ap.TenantID != nil {
					policy["tenantId"] = *ap.TenantID
				}
				if ap.ObjectID != nil {
					policy["objectId"] = *ap.ObjectID
				}
				if ap.Permissions != nil {
					permissions := make(map[string]any)
					if ap.Permissions.Keys != nil {
						keys := make([]string, 0, len(ap.Permissions.Keys))
						for _, k := range ap.Permissions.Keys {
							if k != nil {
								keys = append(keys, string(*k))
							}
						}
						permissions["keys"] = keys
					}
					if ap.Permissions.Secrets != nil {
						secrets := make([]string, 0, len(ap.Permissions.Secrets))
						for _, s := range ap.Permissions.Secrets {
							if s != nil {
								secrets = append(secrets, string(*s))
							}
						}
						permissions["secrets"] = secrets
					}
					if ap.Permissions.Certificates != nil {
						certs := make([]string, 0, len(ap.Permissions.Certificates))
						for _, c := range ap.Permissions.Certificates {
							if c != nil {
								certs = append(certs, string(*c))
							}
						}
						permissions["certificates"] = certs
					}
					if ap.Permissions.Storage != nil {
						storage := make([]string, 0, len(ap.Permissions.Storage))
						for _, s := range ap.Permissions.Storage {
							if s != nil {
								storage = append(storage, string(*s))
							}
						}
						permissions["storage"] = storage
					}
					policy["permissions"] = permissions
				}
				accessPolicies = append(accessPolicies, policy)
			}
			props["accessPolicies"] = accessPolicies
		}

		// Serialize network ACLs
		if result.Properties.NetworkACLs != nil {
			networkAcls := make(map[string]any)
			if result.Properties.NetworkACLs.DefaultAction != nil {
				networkAcls["defaultAction"] = string(*result.Properties.NetworkACLs.DefaultAction)
			}
			if result.Properties.NetworkACLs.Bypass != nil {
				networkAcls["bypass"] = string(*result.Properties.NetworkACLs.Bypass)
			}
			if len(result.Properties.NetworkACLs.IPRules) > 0 {
				ipRules := make([]map[string]any, 0, len(result.Properties.NetworkACLs.IPRules))
				for _, rule := range result.Properties.NetworkACLs.IPRules {
					if rule.Value != nil {
						ipRules = append(ipRules, map[string]any{"value": *rule.Value})
					}
				}
				networkAcls["ipRules"] = ipRules
			}
			if len(result.Properties.NetworkACLs.VirtualNetworkRules) > 0 {
				vnetRules := make([]map[string]any, 0, len(result.Properties.NetworkACLs.VirtualNetworkRules))
				for _, rule := range result.Properties.NetworkACLs.VirtualNetworkRules {
					if rule.ID != nil {
						vnetRules = append(vnetRules, map[string]any{"id": *rule.ID})
					}
				}
				networkAcls["virtualNetworkRules"] = vnetRules
			}
			props["networkAcls"] = networkAcls
		}
	}

	// Add tags
	if tags := azureTagsToFormaeTags(result.Tags); tags != nil {
		props["Tags"] = tags
	}

	// Read-only properties
	if result.ID != nil {
		props["id"] = *result.ID
	}

	return json.Marshal(props)
}

// keyVaultProps mirrors schema/pkl/keyvault/vault.pkl; pointer fields stay nil when absent.
type keyVaultProps struct {
	ResourceGroupName            string                 `json:"resourceGroupName"`
	Location                     string                 `json:"location"`
	Name                         string                 `json:"name"`
	TenantID                     string                 `json:"tenantId"`
	SKU                          *keyVaultSKU           `json:"sku"`
	EnabledForDeployment         *bool                  `json:"enabledForDeployment"`
	EnabledForDiskEncryption     *bool                  `json:"enabledForDiskEncryption"`
	EnabledForTemplateDeployment *bool                  `json:"enabledForTemplateDeployment"`
	EnableSoftDelete             *bool                  `json:"enableSoftDelete"`
	SoftDeleteRetentionInDays    *int32                 `json:"softDeleteRetentionInDays"`
	EnablePurgeProtection        *bool                  `json:"enablePurgeProtection"`
	EnableRbacAuthorization      *bool                  `json:"enableRbacAuthorization"`
	AccessPolicies               []keyVaultAccessPolicy `json:"accessPolicies"`
	NetworkACLs                  *keyVaultNetworkACLs   `json:"networkAcls"`
}

type keyVaultSKU struct {
	Name string `json:"name"`
}

type keyVaultAccessPolicy struct {
	TenantID    *string              `json:"tenantId"`
	ObjectID    *string              `json:"objectId"`
	Permissions *keyVaultPermissions `json:"permissions"`
}

type keyVaultPermissions struct {
	Keys         []string `json:"keys"`
	Secrets      []string `json:"secrets"`
	Certificates []string `json:"certificates"`
	Storage      []string `json:"storage"`
}

type keyVaultNetworkACLs struct {
	DefaultAction       *string            `json:"defaultAction"`
	Bypass              *string            `json:"bypass"`
	IPRules             []keyVaultIPRule   `json:"ipRules"`
	VirtualNetworkRules []keyVaultVNetRule `json:"virtualNetworkRules"`
}

type keyVaultIPRule struct {
	Value *string `json:"value"`
}

type keyVaultVNetRule struct {
	ID *string `json:"id"`
}

// toVaultParams validates the fields Azure requires and builds the SDK params; tags are applied by the caller.
func (p keyVaultProps) toVaultParams() (armkeyvault.VaultCreateOrUpdateParameters, error) {
	var params armkeyvault.VaultCreateOrUpdateParameters

	if p.Location == "" {
		return params, fmt.Errorf("location is required")
	}
	if p.TenantID == "" {
		return params, fmt.Errorf("tenantId is required")
	}
	if p.SKU == nil {
		return params, fmt.Errorf("sku is required")
	}
	if p.SKU.Name == "" {
		return params, fmt.Errorf("sku.name is required")
	}

	params = armkeyvault.VaultCreateOrUpdateParameters{
		Location: stringPtr(p.Location),
		Properties: &armkeyvault.VaultProperties{
			TenantID: stringPtr(p.TenantID),
			SKU: &armkeyvault.SKU{
				Family: to.Ptr(armkeyvault.SKUFamilyA),
				Name:   to.Ptr(armkeyvault.SKUName(p.SKU.Name)),
			},
			EnabledForDeployment:         p.EnabledForDeployment,
			EnabledForDiskEncryption:     p.EnabledForDiskEncryption,
			EnabledForTemplateDeployment: p.EnabledForTemplateDeployment,
			EnableSoftDelete:             p.EnableSoftDelete,
			SoftDeleteRetentionInDays:    p.SoftDeleteRetentionInDays,
			EnablePurgeProtection:        p.EnablePurgeProtection,
			EnableRbacAuthorization:      p.EnableRbacAuthorization,
			AccessPolicies:               p.accessPoliciesToAzure(),
			NetworkACLs:                  p.networkACLsToAzure(),
		},
	}
	return params, nil
}

// accessPoliciesToAzure always returns a non-nil slice: Azure requires accessPolicies to be present.
func (p keyVaultProps) accessPoliciesToAzure() []*armkeyvault.AccessPolicyEntry {
	entries := make([]*armkeyvault.AccessPolicyEntry, 0, len(p.AccessPolicies))
	for _, ap := range p.AccessPolicies {
		entry := &armkeyvault.AccessPolicyEntry{
			TenantID: ap.TenantID,
			ObjectID: ap.ObjectID,
		}
		if ap.Permissions != nil {
			entry.Permissions = &armkeyvault.Permissions{
				Keys:         keyVaultPermPtrs[armkeyvault.KeyPermissions](ap.Permissions.Keys),
				Secrets:      keyVaultPermPtrs[armkeyvault.SecretPermissions](ap.Permissions.Secrets),
				Certificates: keyVaultPermPtrs[armkeyvault.CertificatePermissions](ap.Permissions.Certificates),
				Storage:      keyVaultPermPtrs[armkeyvault.StoragePermissions](ap.Permissions.Storage),
			}
		}
		entries = append(entries, entry)
	}
	return entries
}

func (p keyVaultProps) networkACLsToAzure() *armkeyvault.NetworkRuleSet {
	if p.NetworkACLs == nil {
		return nil
	}
	acls := &armkeyvault.NetworkRuleSet{}
	if p.NetworkACLs.DefaultAction != nil {
		action := armkeyvault.NetworkRuleAction(*p.NetworkACLs.DefaultAction)
		acls.DefaultAction = &action
	}
	if p.NetworkACLs.Bypass != nil {
		bypass := armkeyvault.NetworkRuleBypassOptions(*p.NetworkACLs.Bypass)
		acls.Bypass = &bypass
	}
	if p.NetworkACLs.IPRules != nil {
		ipRules := make([]*armkeyvault.IPRule, 0, len(p.NetworkACLs.IPRules))
		for _, rule := range p.NetworkACLs.IPRules {
			if rule.Value != nil {
				ipRules = append(ipRules, &armkeyvault.IPRule{Value: rule.Value})
			}
		}
		acls.IPRules = ipRules
	}
	if p.NetworkACLs.VirtualNetworkRules != nil {
		vnetRules := make([]*armkeyvault.VirtualNetworkRule, 0, len(p.NetworkACLs.VirtualNetworkRules))
		for _, rule := range p.NetworkACLs.VirtualNetworkRules {
			if rule.ID != nil {
				vnetRules = append(vnetRules, &armkeyvault.VirtualNetworkRule{ID: rule.ID})
			}
		}
		acls.VirtualNetworkRules = vnetRules
	}
	return acls
}

// keyVaultPermPtrs maps a permission list to the SDK pointer slice; nil stays nil (category omitted).
func keyVaultPermPtrs[T ~string](values []string) []*T {
	if values == nil {
		return nil
	}
	out := make([]*T, 0, len(values))
	for _, v := range values {
		perm := T(v)
		out = append(out, &perm)
	}
	return out
}

func (kv *KeyVault) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props keyVaultProps
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	if props.ResourceGroupName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	rgName := props.ResourceGroupName

	vaultName := props.Name
	if vaultName == "" {
		vaultName = request.Label
	}

	params, err := props.toVaultParams()
	if err != nil {
		return nil, err
	}

	// Add tags if present
	if azureTags := formaeTagsToAzureTags(request.Properties); azureTags != nil {
		params.Tags = azureTags
	}

	// Call Azure API to create Key Vault (async/LRO operation)
	poller, err := kv.api.BeginCreateOrUpdate(
		ctx,
		rgName,
		vaultName,
		params,
		nil,
	)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,

				ErrorCode: operationErrorCode(err),
			},
		}, nil
	}

	// Build expected NativeID
	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.KeyVault/vaults/%s",
		kv.config.SubscriptionId, rgName, vaultName)

	// Check if the operation completed synchronously
	if poller.Done() {
		result, err := poller.Result(ctx)
		if err != nil {
			return &resource.CreateResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationCreate,
					OperationStatus: resource.OperationStatusFailure,

					ErrorCode: operationErrorCode(err),
				},
			}, nil
		}

		propsJSON, err := serializeKeyVaultProperties(result.Vault, rgName, vaultName)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize Key Vault properties: %w", err)
		}

		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusSuccess,
				NativeID:        *result.ID,

				ResourceProperties: propsJSON,
			},
		}, nil
	}

	// Get the ResumeToken for tracking the operation
	resumeToken, err := poller.ResumeToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get resume token: %w", err)
	}

	// Encode operation type + resume token as RequestID
	reqID := lroRequestID{
		OperationType: "create",
		ResumeToken:   resumeToken,
		NativeID:      expectedNativeID,
	}
	reqIDJSON, err := json.Marshal(reqID)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request ID: %w", err)
	}

	return &resource.CreateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationCreate,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       string(reqIDJSON),
			NativeID:        expectedNativeID,
		},
	}, nil
}

func (kv *KeyVault) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, vaultName, err := kv.parseNativeID(request.NativeID)
	if err != nil {
		return nil, err
	}

	// Get Key Vault from Azure
	result, err := kv.api.Get(ctx, rgName, vaultName, nil)
	if err != nil {
		return &resource.ReadResult{

			ErrorCode: operationErrorCode(err),
		}, nil
	}

	propsJSON, err := serializeKeyVaultProperties(result.Vault, rgName, vaultName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize Key Vault properties: %w", err)
	}

	return &resource.ReadResult{
		ResourceType: ResourceTypeKeyVault,
		Properties:   string(propsJSON),
	}, nil
}

func (kv *KeyVault) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, vaultName, err := kv.parseNativeID(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props keyVaultProps
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	params, err := props.toVaultParams()
	if err != nil {
		return nil, err
	}

	// Add tags if present
	if azureTags := formaeTagsToAzureTags(request.DesiredProperties); azureTags != nil {
		params.Tags = azureTags
	}

	// Call Azure API to update Key Vault
	poller, err := kv.api.BeginCreateOrUpdate(
		ctx,
		rgName,
		vaultName,
		params,
		nil,
	)
	if err != nil {
		return &resource.UpdateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationUpdate,
				OperationStatus: resource.OperationStatusFailure,
				NativeID:        request.NativeID,

				ErrorCode: operationErrorCode(err),
			},
		}, nil
	}

	// Check if completed synchronously
	if poller.Done() {
		result, err := poller.Result(ctx)
		if err != nil {
			return &resource.UpdateResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationUpdate,
					OperationStatus: resource.OperationStatusFailure,
					NativeID:        request.NativeID,

					ErrorCode: operationErrorCode(err),
				},
			}, nil
		}

		propsJSON, err := serializeKeyVaultProperties(result.Vault, rgName, vaultName)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize Key Vault properties: %w", err)
		}

		return &resource.UpdateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationUpdate,
				OperationStatus: resource.OperationStatusSuccess,
				NativeID:        *result.ID,

				ResourceProperties: propsJSON,
			},
		}, nil
	}

	// Get the ResumeToken for tracking the operation
	resumeToken, err := poller.ResumeToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get resume token: %w", err)
	}

	reqID := lroRequestID{
		OperationType: "update",
		ResumeToken:   resumeToken,
		NativeID:      request.NativeID,
	}
	reqIDJSON, err := json.Marshal(reqID)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request ID: %w", err)
	}

	return &resource.UpdateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationUpdate,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       string(reqIDJSON),
			NativeID:        request.NativeID,
		},
	}, nil
}

func (kv *KeyVault) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, vaultName, err := kv.parseNativeID(request.NativeID)
	if err != nil {
		return nil, err
	}

	// First, soft-delete the vault (synchronous operation)
	_, err = kv.api.Delete(ctx, rgName, vaultName, nil)
	if err != nil {
		// If the resource is already gone (NotFound), treat as success
		if operationErrorCode(err) == resource.OperationErrorCodeNotFound {
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

				ErrorCode: operationErrorCode(err),
			},
		}, fmt.Errorf("failed to delete Key Vault: %w", err)
	}

	// Note: If purge protection is NOT enabled, we could optionally purge the vault here
	// using BeginPurgeDeleted. For now, we just soft-delete which is sufficient for most cases.

	return &resource.DeleteResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationDelete,
			OperationStatus: resource.OperationStatusSuccess,
			NativeID:        request.NativeID,
		},
	}, nil
}

func (kv *KeyVault) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {

	reqID, err := decodeLROStatus(request.RequestID)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,

				ErrorCode: resource.OperationErrorCodeGeneralServiceException,
			},
		}, fmt.Errorf("failed to parse request ID: %w", err)
	}

	switch reqID.OperationType {
	case lroOpCreate, lroOpUpdate:
		return kv.statusCreateOrUpdate(ctx, request, &reqID)
	case lroOpDelete:
		return kv.statusDelete(ctx, request, &reqID)
	default:
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,

				ErrorCode: resource.OperationErrorCodeGeneralServiceException,
			},
		}, fmt.Errorf("unknown operation type: %s", reqID.OperationType)
	}
}

func (kv *KeyVault) statusCreateOrUpdate(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	operation := resource.OperationCreate
	if reqID.OperationType == lroOpUpdate {
		operation = resource.OperationUpdate
	}

	return statusLRO(ctx, request, reqID, operation,
		func(token string) (*runtime.Poller[armkeyvault.VaultsClientCreateOrUpdateResponse], error) {
			return resumePoller[armkeyvault.VaultsClientCreateOrUpdateResponse](kv.pipeline, token)
		},
		func(_ context.Context, result armkeyvault.VaultsClientCreateOrUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
			rgName, vaultName, err := kv.parseNativeID(*result.ID)
			if err != nil {
				return "", nil, err
			}
			propsJSON, err := serializeKeyVaultProperties(result.Vault, rgName, vaultName)
			if err != nil {
				return "", nil, fmt.Errorf("failed to serialize Key Vault properties: %w", err)
			}
			return *result.ID, propsJSON, nil
		},
	)
}

func (kv *KeyVault) statusDelete(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	// Key Vault delete is synchronous, so if we get here with a delete operation,
	// it means we returned InProgress but the delete should already be complete.
	// We can verify by trying to read the vault - if it fails with NotFound, delete succeeded.

	rgName, vaultName, err := kv.parseNativeID(reqID.NativeID)
	if err != nil {
		return nil, err
	}

	_, err = kv.api.Get(ctx, rgName, vaultName, nil)
	if err != nil {
		// If we get an error (likely NotFound), the vault was deleted
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationDelete,
				OperationStatus: resource.OperationStatusSuccess,
				RequestID:       request.RequestID,

				NativeID: reqID.NativeID,
			},
		}, nil
	}

	// Vault still exists, delete is in progress
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationDelete,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       request.RequestID,

			NativeID: reqID.NativeID,
		},
	}, nil
}

func (kv *KeyVault) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	resourceGroupName := request.AdditionalProperties["resourceGroupName"]

	var nativeIDs []string

	if resourceGroupName != "" {
		pager := kv.api.NewListByResourceGroupPager(resourceGroupName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list Key Vaults: %w", err)
			}
			for _, vault := range page.Value {
				if vault.ID != nil {
					nativeIDs = append(nativeIDs, *vault.ID)
				}
			}
		}
	} else {
		pager := kv.api.NewListBySubscriptionPager(nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list Key Vaults: %w", err)
			}
			for _, vault := range page.Value {
				if vault.ID != nil {
					nativeIDs = append(nativeIDs, *vault.ID)
				}
			}
		}
	}

	return &resource.ListResult{
		NativeIDs: nativeIDs,
	}, nil
}
