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

func (kv *KeyVault) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {

	// Parse properties JSON
	var props map[string]any
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	// Extract resourceGroupName (required)
	rgName, ok := props["resourceGroupName"].(string)
	if !ok || rgName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}

	// Extract location (required)
	location, ok := props["location"].(string)
	if !ok || location == "" {
		return nil, fmt.Errorf("location is required")
	}

	// Extract vault name from properties, fall back to label
	vaultName, ok := props["name"].(string)
	if !ok || vaultName == "" {
		vaultName = request.Label
	}

	// Extract tenantId (required)
	tenantId, ok := props["tenantId"].(string)
	if !ok || tenantId == "" {
		return nil, fmt.Errorf("tenantId is required")
	}

	// Extract SKU (required)
	skuMap, ok := props["sku"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("sku is required")
	}
	skuName, ok := skuMap["name"].(string)
	if !ok || skuName == "" {
		return nil, fmt.Errorf("sku.name is required")
	}

	// Build Vault parameters
	params := armkeyvault.VaultCreateOrUpdateParameters{
		Location: stringPtr(location),
		Properties: &armkeyvault.VaultProperties{
			TenantID: stringPtr(tenantId),
			SKU: &armkeyvault.SKU{
				Family: to.Ptr(armkeyvault.SKUFamilyA),
				Name:   to.Ptr(armkeyvault.SKUName(skuName)),
			},
		},
	}

	// Add optional properties
	if enabledForDeployment, ok := props["enabledForDeployment"].(bool); ok {
		params.Properties.EnabledForDeployment = to.Ptr(enabledForDeployment)
	}

	if enabledForDiskEncryption, ok := props["enabledForDiskEncryption"].(bool); ok {
		params.Properties.EnabledForDiskEncryption = to.Ptr(enabledForDiskEncryption)
	}

	if enabledForTemplateDeployment, ok := props["enabledForTemplateDeployment"].(bool); ok {
		params.Properties.EnabledForTemplateDeployment = to.Ptr(enabledForTemplateDeployment)
	}

	if enableSoftDelete, ok := props["enableSoftDelete"].(bool); ok {
		params.Properties.EnableSoftDelete = to.Ptr(enableSoftDelete)
	}

	if softDeleteRetentionInDays, ok := props["softDeleteRetentionInDays"].(float64); ok {
		params.Properties.SoftDeleteRetentionInDays = to.Ptr(int32(softDeleteRetentionInDays))
	}

	if enablePurgeProtection, ok := props["enablePurgeProtection"].(bool); ok {
		params.Properties.EnablePurgeProtection = to.Ptr(enablePurgeProtection)
	}

	if enableRbacAuthorization, ok := props["enableRbacAuthorization"].(bool); ok {
		params.Properties.EnableRbacAuthorization = to.Ptr(enableRbacAuthorization)
	}

	// Parse access policies (Azure requires this field, even if empty)
	if accessPoliciesRaw, ok := props["accessPolicies"].([]any); ok {
		accessPolicies := make([]*armkeyvault.AccessPolicyEntry, 0, len(accessPoliciesRaw))
		for _, apRaw := range accessPoliciesRaw {
			apMap, ok := apRaw.(map[string]any)
			if !ok {
				continue
			}
			entry := &armkeyvault.AccessPolicyEntry{}
			if tid, ok := apMap["tenantId"].(string); ok {
				entry.TenantID = stringPtr(tid)
			}
			if oid, ok := apMap["objectId"].(string); ok {
				entry.ObjectID = stringPtr(oid)
			}
			if permsRaw, ok := apMap["permissions"].(map[string]any); ok {
				entry.Permissions = &armkeyvault.Permissions{}
				if keysRaw, ok := permsRaw["keys"].([]any); ok {
					keys := make([]*armkeyvault.KeyPermissions, 0, len(keysRaw))
					for _, k := range keysRaw {
						if ks, ok := k.(string); ok {
							perm := armkeyvault.KeyPermissions(ks)
							keys = append(keys, &perm)
						}
					}
					entry.Permissions.Keys = keys
				}
				if secretsRaw, ok := permsRaw["secrets"].([]any); ok {
					secrets := make([]*armkeyvault.SecretPermissions, 0, len(secretsRaw))
					for _, s := range secretsRaw {
						if ss, ok := s.(string); ok {
							perm := armkeyvault.SecretPermissions(ss)
							secrets = append(secrets, &perm)
						}
					}
					entry.Permissions.Secrets = secrets
				}
				if certsRaw, ok := permsRaw["certificates"].([]any); ok {
					certs := make([]*armkeyvault.CertificatePermissions, 0, len(certsRaw))
					for _, c := range certsRaw {
						if cs, ok := c.(string); ok {
							perm := armkeyvault.CertificatePermissions(cs)
							certs = append(certs, &perm)
						}
					}
					entry.Permissions.Certificates = certs
				}
				if storageRaw, ok := permsRaw["storage"].([]any); ok {
					storage := make([]*armkeyvault.StoragePermissions, 0, len(storageRaw))
					for _, s := range storageRaw {
						if ss, ok := s.(string); ok {
							perm := armkeyvault.StoragePermissions(ss)
							storage = append(storage, &perm)
						}
					}
					entry.Permissions.Storage = storage
				}
			}
			accessPolicies = append(accessPolicies, entry)
		}
		params.Properties.AccessPolicies = accessPolicies
	} else {
		// Azure API requires accessPolicies to be present, default to empty
		params.Properties.AccessPolicies = []*armkeyvault.AccessPolicyEntry{}
	}

	// Parse network ACLs
	if networkAclsRaw, ok := props["networkAcls"].(map[string]any); ok {
		params.Properties.NetworkACLs = &armkeyvault.NetworkRuleSet{}
		if defaultAction, ok := networkAclsRaw["defaultAction"].(string); ok {
			action := armkeyvault.NetworkRuleAction(defaultAction)
			params.Properties.NetworkACLs.DefaultAction = &action
		}
		if bypass, ok := networkAclsRaw["bypass"].(string); ok {
			bypassVal := armkeyvault.NetworkRuleBypassOptions(bypass)
			params.Properties.NetworkACLs.Bypass = &bypassVal
		}
		if ipRulesRaw, ok := networkAclsRaw["ipRules"].([]any); ok {
			ipRules := make([]*armkeyvault.IPRule, 0, len(ipRulesRaw))
			for _, rule := range ipRulesRaw {
				if ruleMap, ok := rule.(map[string]any); ok {
					if value, ok := ruleMap["value"].(string); ok {
						ipRules = append(ipRules, &armkeyvault.IPRule{Value: stringPtr(value)})
					}
				}
			}
			params.Properties.NetworkACLs.IPRules = ipRules
		}
		if vnetRulesRaw, ok := networkAclsRaw["virtualNetworkRules"].([]any); ok {
			vnetRules := make([]*armkeyvault.VirtualNetworkRule, 0, len(vnetRulesRaw))
			for _, rule := range vnetRulesRaw {
				if ruleMap, ok := rule.(map[string]any); ok {
					if id, ok := ruleMap["id"].(string); ok {
						vnetRules = append(vnetRules, &armkeyvault.VirtualNetworkRule{ID: stringPtr(id)})
					}
				}
			}
			params.Properties.NetworkACLs.VirtualNetworkRules = vnetRules
		}
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

	// Parse properties JSON
	var props map[string]any
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	// Extract location (required)
	location, ok := props["location"].(string)
	if !ok || location == "" {
		return nil, fmt.Errorf("location is required")
	}

	// Extract tenantId (required)
	tenantId, ok := props["tenantId"].(string)
	if !ok || tenantId == "" {
		return nil, fmt.Errorf("tenantId is required")
	}

	// Extract SKU (required)
	skuMap, ok := props["sku"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("sku is required")
	}
	skuName, ok := skuMap["name"].(string)
	if !ok || skuName == "" {
		return nil, fmt.Errorf("sku.name is required")
	}

	// Build Vault parameters
	params := armkeyvault.VaultCreateOrUpdateParameters{
		Location: stringPtr(location),
		Properties: &armkeyvault.VaultProperties{
			TenantID: stringPtr(tenantId),
			SKU: &armkeyvault.SKU{
				Family: to.Ptr(armkeyvault.SKUFamilyA),
				Name:   to.Ptr(armkeyvault.SKUName(skuName)),
			},
		},
	}

	// Add optional properties (same as Create)
	if enabledForDeployment, ok := props["enabledForDeployment"].(bool); ok {
		params.Properties.EnabledForDeployment = to.Ptr(enabledForDeployment)
	}

	if enabledForDiskEncryption, ok := props["enabledForDiskEncryption"].(bool); ok {
		params.Properties.EnabledForDiskEncryption = to.Ptr(enabledForDiskEncryption)
	}

	if enabledForTemplateDeployment, ok := props["enabledForTemplateDeployment"].(bool); ok {
		params.Properties.EnabledForTemplateDeployment = to.Ptr(enabledForTemplateDeployment)
	}

	if enableSoftDelete, ok := props["enableSoftDelete"].(bool); ok {
		params.Properties.EnableSoftDelete = to.Ptr(enableSoftDelete)
	}

	if softDeleteRetentionInDays, ok := props["softDeleteRetentionInDays"].(float64); ok {
		params.Properties.SoftDeleteRetentionInDays = to.Ptr(int32(softDeleteRetentionInDays))
	}

	if enablePurgeProtection, ok := props["enablePurgeProtection"].(bool); ok {
		params.Properties.EnablePurgeProtection = to.Ptr(enablePurgeProtection)
	}

	if enableRbacAuthorization, ok := props["enableRbacAuthorization"].(bool); ok {
		params.Properties.EnableRbacAuthorization = to.Ptr(enableRbacAuthorization)
	}

	// Parse access policies (Azure requires this field, even if empty)
	if accessPoliciesRaw, ok := props["accessPolicies"].([]any); ok {
		accessPolicies := make([]*armkeyvault.AccessPolicyEntry, 0, len(accessPoliciesRaw))
		for _, apRaw := range accessPoliciesRaw {
			apMap, ok := apRaw.(map[string]any)
			if !ok {
				continue
			}
			entry := &armkeyvault.AccessPolicyEntry{}
			if tid, ok := apMap["tenantId"].(string); ok {
				entry.TenantID = stringPtr(tid)
			}
			if oid, ok := apMap["objectId"].(string); ok {
				entry.ObjectID = stringPtr(oid)
			}
			if permsRaw, ok := apMap["permissions"].(map[string]any); ok {
				entry.Permissions = &armkeyvault.Permissions{}
				if keysRaw, ok := permsRaw["keys"].([]any); ok {
					keys := make([]*armkeyvault.KeyPermissions, 0, len(keysRaw))
					for _, k := range keysRaw {
						if ks, ok := k.(string); ok {
							perm := armkeyvault.KeyPermissions(ks)
							keys = append(keys, &perm)
						}
					}
					entry.Permissions.Keys = keys
				}
				if secretsRaw, ok := permsRaw["secrets"].([]any); ok {
					secrets := make([]*armkeyvault.SecretPermissions, 0, len(secretsRaw))
					for _, s := range secretsRaw {
						if ss, ok := s.(string); ok {
							perm := armkeyvault.SecretPermissions(ss)
							secrets = append(secrets, &perm)
						}
					}
					entry.Permissions.Secrets = secrets
				}
				if certsRaw, ok := permsRaw["certificates"].([]any); ok {
					certs := make([]*armkeyvault.CertificatePermissions, 0, len(certsRaw))
					for _, c := range certsRaw {
						if cs, ok := c.(string); ok {
							perm := armkeyvault.CertificatePermissions(cs)
							certs = append(certs, &perm)
						}
					}
					entry.Permissions.Certificates = certs
				}
				if storageRaw, ok := permsRaw["storage"].([]any); ok {
					storage := make([]*armkeyvault.StoragePermissions, 0, len(storageRaw))
					for _, s := range storageRaw {
						if ss, ok := s.(string); ok {
							perm := armkeyvault.StoragePermissions(ss)
							storage = append(storage, &perm)
						}
					}
					entry.Permissions.Storage = storage
				}
			}
			accessPolicies = append(accessPolicies, entry)
		}
		params.Properties.AccessPolicies = accessPolicies
	} else {
		// Azure API requires accessPolicies to be present, default to empty
		params.Properties.AccessPolicies = []*armkeyvault.AccessPolicyEntry{}
	}

	// Parse network ACLs (same as Create)
	if networkAclsRaw, ok := props["networkAcls"].(map[string]any); ok {
		params.Properties.NetworkACLs = &armkeyvault.NetworkRuleSet{}
		if defaultAction, ok := networkAclsRaw["defaultAction"].(string); ok {
			action := armkeyvault.NetworkRuleAction(defaultAction)
			params.Properties.NetworkACLs.DefaultAction = &action
		}
		if bypass, ok := networkAclsRaw["bypass"].(string); ok {
			bypassVal := armkeyvault.NetworkRuleBypassOptions(bypass)
			params.Properties.NetworkACLs.Bypass = &bypassVal
		}
		if ipRulesRaw, ok := networkAclsRaw["ipRules"].([]any); ok {
			ipRules := make([]*armkeyvault.IPRule, 0, len(ipRulesRaw))
			for _, rule := range ipRulesRaw {
				if ruleMap, ok := rule.(map[string]any); ok {
					if value, ok := ruleMap["value"].(string); ok {
						ipRules = append(ipRules, &armkeyvault.IPRule{Value: stringPtr(value)})
					}
				}
			}
			params.Properties.NetworkACLs.IPRules = ipRules
		}
		if vnetRulesRaw, ok := networkAclsRaw["virtualNetworkRules"].([]any); ok {
			vnetRules := make([]*armkeyvault.VirtualNetworkRule, 0, len(vnetRulesRaw))
			for _, rule := range vnetRulesRaw {
				if ruleMap, ok := rule.(map[string]any); ok {
					if id, ok := ruleMap["id"].(string); ok {
						vnetRules = append(vnetRules, &armkeyvault.VirtualNetworkRule{ID: stringPtr(id)})
					}
				}
			}
			params.Properties.NetworkACLs.VirtualNetworkRules = vnetRules
		}
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
