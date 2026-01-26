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
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
)

const ResourceTypeKeyVault = "Azure::KeyVault::Vault"

func init() {
	registry.Register(ResourceTypeKeyVault, func(client *client.Client, cfg *config.Config) prov.Provisioner {
		return &KeyVault{client, cfg}
	})
}

// KeyVault is the provisioner for Azure Key Vaults.
type KeyVault struct {
	Client *client.Client
	Config *config.Config
}

// serializeKeyVaultProperties converts an Azure Vault to Formae property format
func serializeKeyVaultProperties(result armkeyvault.Vault, rgName, vaultName string) (json.RawMessage, error) {
	props := make(map[string]interface{})

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
			sku := make(map[string]interface{})
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
		if result.Properties.AccessPolicies != nil && len(result.Properties.AccessPolicies) > 0 {
			accessPolicies := make([]map[string]interface{}, 0, len(result.Properties.AccessPolicies))
			for _, ap := range result.Properties.AccessPolicies {
				policy := make(map[string]interface{})
				if ap.TenantID != nil {
					policy["tenantId"] = *ap.TenantID
				}
				if ap.ObjectID != nil {
					policy["objectId"] = *ap.ObjectID
				}
				if ap.Permissions != nil {
					permissions := make(map[string]interface{})
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
			networkAcls := make(map[string]interface{})
			if result.Properties.NetworkACLs.DefaultAction != nil {
				networkAcls["defaultAction"] = string(*result.Properties.NetworkACLs.DefaultAction)
			}
			if result.Properties.NetworkACLs.Bypass != nil {
				networkAcls["bypass"] = string(*result.Properties.NetworkACLs.Bypass)
			}
			if result.Properties.NetworkACLs.IPRules != nil && len(result.Properties.NetworkACLs.IPRules) > 0 {
				ipRules := make([]map[string]interface{}, 0, len(result.Properties.NetworkACLs.IPRules))
				for _, rule := range result.Properties.NetworkACLs.IPRules {
					if rule.Value != nil {
						ipRules = append(ipRules, map[string]interface{}{"value": *rule.Value})
					}
				}
				networkAcls["ipRules"] = ipRules
			}
			if result.Properties.NetworkACLs.VirtualNetworkRules != nil && len(result.Properties.NetworkACLs.VirtualNetworkRules) > 0 {
				vnetRules := make([]map[string]interface{}, 0, len(result.Properties.NetworkACLs.VirtualNetworkRules))
				for _, rule := range result.Properties.NetworkACLs.VirtualNetworkRules {
					if rule.ID != nil {
						vnetRules = append(vnetRules, map[string]interface{}{"id": *rule.ID})
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
	var props map[string]interface{}
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
	skuMap, ok := props["sku"].(map[string]interface{})
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

	// Parse access policies
	if accessPoliciesRaw, ok := props["accessPolicies"].([]interface{}); ok {
		accessPolicies := make([]*armkeyvault.AccessPolicyEntry, 0, len(accessPoliciesRaw))
		for _, apRaw := range accessPoliciesRaw {
			apMap, ok := apRaw.(map[string]interface{})
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
			if permsRaw, ok := apMap["permissions"].(map[string]interface{}); ok {
				entry.Permissions = &armkeyvault.Permissions{}
				if keysRaw, ok := permsRaw["keys"].([]interface{}); ok {
					keys := make([]*armkeyvault.KeyPermissions, 0, len(keysRaw))
					for _, k := range keysRaw {
						if ks, ok := k.(string); ok {
							perm := armkeyvault.KeyPermissions(ks)
							keys = append(keys, &perm)
						}
					}
					entry.Permissions.Keys = keys
				}
				if secretsRaw, ok := permsRaw["secrets"].([]interface{}); ok {
					secrets := make([]*armkeyvault.SecretPermissions, 0, len(secretsRaw))
					for _, s := range secretsRaw {
						if ss, ok := s.(string); ok {
							perm := armkeyvault.SecretPermissions(ss)
							secrets = append(secrets, &perm)
						}
					}
					entry.Permissions.Secrets = secrets
				}
				if certsRaw, ok := permsRaw["certificates"].([]interface{}); ok {
					certs := make([]*armkeyvault.CertificatePermissions, 0, len(certsRaw))
					for _, c := range certsRaw {
						if cs, ok := c.(string); ok {
							perm := armkeyvault.CertificatePermissions(cs)
							certs = append(certs, &perm)
						}
					}
					entry.Permissions.Certificates = certs
				}
				if storageRaw, ok := permsRaw["storage"].([]interface{}); ok {
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
	}

	// Parse network ACLs
	if networkAclsRaw, ok := props["networkAcls"].(map[string]interface{}); ok {
		params.Properties.NetworkACLs = &armkeyvault.NetworkRuleSet{}
		if defaultAction, ok := networkAclsRaw["defaultAction"].(string); ok {
			action := armkeyvault.NetworkRuleAction(defaultAction)
			params.Properties.NetworkACLs.DefaultAction = &action
		}
		if bypass, ok := networkAclsRaw["bypass"].(string); ok {
			bypassVal := armkeyvault.NetworkRuleBypassOptions(bypass)
			params.Properties.NetworkACLs.Bypass = &bypassVal
		}
		if ipRulesRaw, ok := networkAclsRaw["ipRules"].([]interface{}); ok {
			ipRules := make([]*armkeyvault.IPRule, 0, len(ipRulesRaw))
			for _, rule := range ipRulesRaw {
				if ruleMap, ok := rule.(map[string]interface{}); ok {
					if value, ok := ruleMap["value"].(string); ok {
						ipRules = append(ipRules, &armkeyvault.IPRule{Value: stringPtr(value)})
					}
				}
			}
			params.Properties.NetworkACLs.IPRules = ipRules
		}
		if vnetRulesRaw, ok := networkAclsRaw["virtualNetworkRules"].([]interface{}); ok {
			vnetRules := make([]*armkeyvault.VirtualNetworkRule, 0, len(vnetRulesRaw))
			for _, rule := range vnetRulesRaw {
				if ruleMap, ok := rule.(map[string]interface{}); ok {
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
	poller, err := kv.Client.VaultsClient.BeginCreateOrUpdate(
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

				ErrorCode: mapAzureErrorToOperationErrorCode(err),
			},
		}, fmt.Errorf("failed to start Key Vault creation: %w", err)
	}

	// Build expected NativeID
	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.KeyVault/vaults/%s",
		kv.Config.SubscriptionId, rgName, vaultName)

	// Check if the operation completed synchronously
	if poller.Done() {
		result, err := poller.Result(ctx)
		if err != nil {
			return &resource.CreateResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationCreate,
					OperationStatus: resource.OperationStatusFailure,

					ErrorCode: mapAzureErrorToOperationErrorCode(err),
				},
			}, fmt.Errorf("failed to get Key Vault create result: %w", err)
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
	// Parse NativeID to extract resourceGroupName and vaultName
	parts := splitResourceID(request.NativeID)

	rgName, ok := parts["resourcegroups"]
	if !ok || rgName == "" {
		return nil, fmt.Errorf("invalid NativeID: could not extract resource group name from %s", request.NativeID)
	}

	vaultName, ok := parts["vaults"]
	if !ok || vaultName == "" {
		return nil, fmt.Errorf("invalid NativeID: could not extract vault name from %s", request.NativeID)
	}

	// Get Key Vault from Azure
	result, err := kv.Client.VaultsClient.Get(ctx, rgName, vaultName, nil)
	if err != nil {
		return &resource.ReadResult{

			ErrorCode: mapAzureErrorToOperationErrorCode(err),
		}, fmt.Errorf("failed to read Key Vault: %w", err)
	}

	propsJSON, err := serializeKeyVaultProperties(result.Vault, rgName, vaultName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize Key Vault properties: %w", err)
	}

	return &resource.ReadResult{

		Properties: string(propsJSON),
	}, nil
}

func (kv *KeyVault) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	// Parse NativeID to extract resourceGroupName and vaultName
	parts := splitResourceID(request.NativeID)

	rgName, ok := parts["resourcegroups"]
	if !ok || rgName == "" {
		return nil, fmt.Errorf("invalid NativeID: could not extract resource group name from %s", request.NativeID)
	}

	vaultName, ok := parts["vaults"]
	if !ok || vaultName == "" {
		return nil, fmt.Errorf("invalid NativeID: could not extract vault name from %s", request.NativeID)
	}

	// Parse properties JSON
	var props map[string]interface{}
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
	skuMap, ok := props["sku"].(map[string]interface{})
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

	// Parse access policies (same as Create)
	if accessPoliciesRaw, ok := props["accessPolicies"].([]interface{}); ok {
		accessPolicies := make([]*armkeyvault.AccessPolicyEntry, 0, len(accessPoliciesRaw))
		for _, apRaw := range accessPoliciesRaw {
			apMap, ok := apRaw.(map[string]interface{})
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
			if permsRaw, ok := apMap["permissions"].(map[string]interface{}); ok {
				entry.Permissions = &armkeyvault.Permissions{}
				if keysRaw, ok := permsRaw["keys"].([]interface{}); ok {
					keys := make([]*armkeyvault.KeyPermissions, 0, len(keysRaw))
					for _, k := range keysRaw {
						if ks, ok := k.(string); ok {
							perm := armkeyvault.KeyPermissions(ks)
							keys = append(keys, &perm)
						}
					}
					entry.Permissions.Keys = keys
				}
				if secretsRaw, ok := permsRaw["secrets"].([]interface{}); ok {
					secrets := make([]*armkeyvault.SecretPermissions, 0, len(secretsRaw))
					for _, s := range secretsRaw {
						if ss, ok := s.(string); ok {
							perm := armkeyvault.SecretPermissions(ss)
							secrets = append(secrets, &perm)
						}
					}
					entry.Permissions.Secrets = secrets
				}
				if certsRaw, ok := permsRaw["certificates"].([]interface{}); ok {
					certs := make([]*armkeyvault.CertificatePermissions, 0, len(certsRaw))
					for _, c := range certsRaw {
						if cs, ok := c.(string); ok {
							perm := armkeyvault.CertificatePermissions(cs)
							certs = append(certs, &perm)
						}
					}
					entry.Permissions.Certificates = certs
				}
				if storageRaw, ok := permsRaw["storage"].([]interface{}); ok {
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
	}

	// Parse network ACLs (same as Create)
	if networkAclsRaw, ok := props["networkAcls"].(map[string]interface{}); ok {
		params.Properties.NetworkACLs = &armkeyvault.NetworkRuleSet{}
		if defaultAction, ok := networkAclsRaw["defaultAction"].(string); ok {
			action := armkeyvault.NetworkRuleAction(defaultAction)
			params.Properties.NetworkACLs.DefaultAction = &action
		}
		if bypass, ok := networkAclsRaw["bypass"].(string); ok {
			bypassVal := armkeyvault.NetworkRuleBypassOptions(bypass)
			params.Properties.NetworkACLs.Bypass = &bypassVal
		}
		if ipRulesRaw, ok := networkAclsRaw["ipRules"].([]interface{}); ok {
			ipRules := make([]*armkeyvault.IPRule, 0, len(ipRulesRaw))
			for _, rule := range ipRulesRaw {
				if ruleMap, ok := rule.(map[string]interface{}); ok {
					if value, ok := ruleMap["value"].(string); ok {
						ipRules = append(ipRules, &armkeyvault.IPRule{Value: stringPtr(value)})
					}
				}
			}
			params.Properties.NetworkACLs.IPRules = ipRules
		}
		if vnetRulesRaw, ok := networkAclsRaw["virtualNetworkRules"].([]interface{}); ok {
			vnetRules := make([]*armkeyvault.VirtualNetworkRule, 0, len(vnetRulesRaw))
			for _, rule := range vnetRulesRaw {
				if ruleMap, ok := rule.(map[string]interface{}); ok {
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
	poller, err := kv.Client.VaultsClient.BeginCreateOrUpdate(
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

				ErrorCode: mapAzureErrorToOperationErrorCode(err),
			},
		}, fmt.Errorf("failed to start Key Vault update: %w", err)
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

					ErrorCode: mapAzureErrorToOperationErrorCode(err),
				},
			}, fmt.Errorf("failed to get Key Vault update result: %w", err)
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
	// Parse NativeID to extract resourceGroupName and vaultName
	parts := splitResourceID(request.NativeID)

	rgName, ok := parts["resourcegroups"]
	if !ok || rgName == "" {
		return nil, fmt.Errorf("invalid NativeID: could not extract resource group name from %s", request.NativeID)
	}

	vaultName, ok := parts["vaults"]
	if !ok || vaultName == "" {
		return nil, fmt.Errorf("invalid NativeID: could not extract vault name from %s", request.NativeID)
	}

	// First, soft-delete the vault (synchronous operation)
	_, err := kv.Client.VaultsClient.Delete(ctx, rgName, vaultName, nil)
	if err != nil {
		// If the resource is already gone (NotFound), treat as success
		if mapAzureErrorToOperationErrorCode(err) == resource.OperationErrorCodeNotFound {
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

				ErrorCode: mapAzureErrorToOperationErrorCode(err),
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

	// Parse the RequestID to determine operation type
	var reqID lroRequestID
	if err := json.Unmarshal([]byte(request.RequestID), &reqID); err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,

				ErrorCode: resource.OperationErrorCodeGeneralServiceException,
			},
		}, fmt.Errorf("failed to parse request ID: %w", err)
	}

	switch reqID.OperationType {
	case "create", "update":
		return kv.statusCreateOrUpdate(ctx, request, &reqID)
	case "delete":
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
	if reqID.OperationType == "update" {
		operation = resource.OperationUpdate
	}

	// Reconstruct the poller from the resume token
	poller, err := kv.Client.ResumeCreateKeyVaultPoller(reqID.ResumeToken)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       operation,
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,

				ErrorCode: resource.OperationErrorCodeGeneralServiceException,
			},
		}, fmt.Errorf("failed to resume poller from token: %w", err)
	}

	// Check if the operation is already done
	if poller.Done() {
		return kv.handleCreateOrUpdateComplete(ctx, request, reqID, poller, operation)
	}

	// Poll for updated status
	_, err = poller.Poll(ctx)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       operation,
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,

				ErrorCode: mapAzureErrorToOperationErrorCode(err),
			},
		}, nil
	}

	// Still in progress - the next status check will determine if Done()
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       operation,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       request.RequestID,

			NativeID: reqID.NativeID,
		},
	}, nil
}

func (kv *KeyVault) handleCreateOrUpdateComplete(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID, poller *runtime.Poller[armkeyvault.VaultsClientCreateOrUpdateResponse], operation resource.Operation) (*resource.StatusResult, error) {
	result, err := poller.Result(ctx)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       operation,
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,

				ErrorCode: mapAzureErrorToOperationErrorCode(err),
			},
		}, nil
	}

	// Extract resource group name from native ID
	parts := splitResourceID(reqID.NativeID)
	rgName := parts["resourcegroups"]

	propsJSON, err := serializeKeyVaultProperties(result.Vault, rgName, *result.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize Key Vault properties: %w", err)
	}

	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       operation,
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,

			NativeID:           *result.ID,
			ResourceProperties: propsJSON,
		},
	}, nil
}

func (kv *KeyVault) statusDelete(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	// Key Vault delete is synchronous, so if we get here with a delete operation,
	// it means we returned InProgress but the delete should already be complete.
	// We can verify by trying to read the vault - if it fails with NotFound, delete succeeded.

	parts := splitResourceID(reqID.NativeID)
	rgName := parts["resourcegroups"]
	vaultName := parts["vaults"]

	_, err := kv.Client.VaultsClient.Get(ctx, rgName, vaultName, nil)
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
	// Get resourceGroupName from AdditionalProperties
	resourceGroupName, ok := request.AdditionalProperties["resourceGroupName"]
	if !ok || resourceGroupName == "" {
		return nil, fmt.Errorf("resourceGroupName is required in AdditionalProperties for listing Key Vaults")
	}

	pager := kv.Client.VaultsClient.NewListByResourceGroupPager(resourceGroupName, nil)

	var nativeIDs []string

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list Key Vaults in resource group %s: %w", resourceGroupName, err)
		}

		for _, vault := range page.Value {
			if vault.ID == nil {
				continue
			}

			nativeIDs = append(nativeIDs, *vault.ID)
		}
	}

	return &resource.ListResult{

		NativeIDs: nativeIDs,
	}, nil
}
