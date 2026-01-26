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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerservice/armcontainerservice/v4"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
)

const ResourceTypeManagedCluster = "Azure::ContainerService::ManagedCluster"

func init() {
	registry.Register(ResourceTypeManagedCluster, func(client *client.Client, cfg *config.Config) prov.Provisioner {
		return &ManagedCluster{client, cfg}
	})
}

// ManagedCluster is the provisioner for Azure Kubernetes Service (AKS) clusters.
type ManagedCluster struct {
	Client *client.Client
	Config *config.Config
}

// serializeManagedClusterProperties converts an Azure ManagedCluster to Formae property format
func serializeManagedClusterProperties(result armcontainerservice.ManagedCluster, rgName, clusterName string) (json.RawMessage, error) {
	props := make(map[string]interface{})

	props["resourceGroupName"] = rgName
	if result.Name != nil {
		props["name"] = *result.Name
	} else {
		props["name"] = clusterName
	}

	if result.Location != nil {
		props["location"] = *result.Location
	}

	if result.ID != nil {
		props["id"] = *result.ID
	}

	// SKU
	if result.SKU != nil {
		sku := make(map[string]interface{})
		if result.SKU.Name != nil {
			sku["name"] = string(*result.SKU.Name)
		}
		if result.SKU.Tier != nil {
			sku["tier"] = string(*result.SKU.Tier)
		}
		props["sku"] = sku
	}

	// Identity
	if result.Identity != nil {
		identity := make(map[string]interface{})
		if result.Identity.Type != nil {
			identity["type"] = string(*result.Identity.Type)
		}
		props["identity"] = identity
	}

	if result.Properties != nil {
		// DNS prefix
		if result.Properties.DNSPrefix != nil {
			props["dnsPrefix"] = *result.Properties.DNSPrefix
		}

		// FQDN (read-only output)
		if result.Properties.Fqdn != nil {
			props["fqdn"] = *result.Properties.Fqdn
		}

		// Kubernetes version
		if result.Properties.KubernetesVersion != nil {
			props["kubernetesVersion"] = *result.Properties.KubernetesVersion
		}

		// Enable RBAC
		if result.Properties.EnableRBAC != nil {
			props["enableRBAC"] = *result.Properties.EnableRBAC
		}

		// Agent pool profiles
		if result.Properties.AgentPoolProfiles != nil {
			pools := make([]map[string]interface{}, 0, len(result.Properties.AgentPoolProfiles))
			for _, pool := range result.Properties.AgentPoolProfiles {
				if pool == nil {
					continue
				}
				poolMap := make(map[string]interface{})
				if pool.Name != nil {
					poolMap["name"] = *pool.Name
				}
				if pool.Count != nil {
					poolMap["count"] = *pool.Count
				}
				if pool.VMSize != nil {
					poolMap["vmSize"] = *pool.VMSize
				}
				if pool.OSDiskSizeGB != nil {
					poolMap["osDiskSizeGB"] = *pool.OSDiskSizeGB
				}
				if pool.OSType != nil {
					poolMap["osType"] = string(*pool.OSType)
				}
				if pool.Mode != nil {
					poolMap["mode"] = string(*pool.Mode)
				}
				if pool.EnableAutoScaling != nil {
					poolMap["enableAutoScaling"] = *pool.EnableAutoScaling
				}
				if pool.MinCount != nil {
					poolMap["minCount"] = *pool.MinCount
				}
				if pool.MaxCount != nil {
					poolMap["maxCount"] = *pool.MaxCount
				}
				pools = append(pools, poolMap)
			}
			if len(pools) > 0 {
				props["agentPoolProfiles"] = pools
			}
		}

		// Network profile
		if result.Properties.NetworkProfile != nil {
			np := result.Properties.NetworkProfile
			netProfile := make(map[string]interface{})
			if np.NetworkPlugin != nil {
				netProfile["networkPlugin"] = string(*np.NetworkPlugin)
			}
			if np.NetworkPluginMode != nil {
				netProfile["networkPluginMode"] = string(*np.NetworkPluginMode)
			}
			if np.NetworkPolicy != nil {
				netProfile["networkPolicy"] = string(*np.NetworkPolicy)
			}
			if np.ServiceCidr != nil {
				netProfile["serviceCidr"] = *np.ServiceCidr
			}
			if np.DNSServiceIP != nil {
				netProfile["dnsServiceIP"] = *np.DNSServiceIP
			}
			if np.PodCidr != nil {
				netProfile["podCidr"] = *np.PodCidr
			}
			if np.LoadBalancerSKU != nil {
				netProfile["loadBalancerSku"] = string(*np.LoadBalancerSKU)
			}
			if len(netProfile) > 0 {
				props["networkProfile"] = netProfile
			}
		}

		// AAD profile
		if result.Properties.AADProfile != nil {
			aad := result.Properties.AADProfile
			aadProfile := make(map[string]interface{})
			if aad.Managed != nil {
				aadProfile["managed"] = *aad.Managed
			}
			if aad.EnableAzureRBAC != nil {
				aadProfile["enableAzureRBAC"] = *aad.EnableAzureRBAC
			}
			if aad.TenantID != nil {
				aadProfile["tenantID"] = *aad.TenantID
			}
			if len(aadProfile) > 0 {
				props["aadProfile"] = aadProfile
			}
		}
	}

	// Tags
	if tags := azureTagsToFormaeTags(result.Tags); tags != nil {
		props["Tags"] = tags
	}

	return json.Marshal(props)
}

func (mc *ManagedCluster) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props map[string]interface{}
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	rgName, ok := props["resourceGroupName"].(string)
	if !ok || rgName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}

	location, ok := props["location"].(string)
	if !ok || location == "" {
		return nil, fmt.Errorf("location is required")
	}

	clusterName, ok := props["name"].(string)
	if !ok || clusterName == "" {
		clusterName = request.Label
	}

	params := armcontainerservice.ManagedCluster{
		Location: to.Ptr(location),
	}

	// Parse SKU
	if skuRaw, ok := props["sku"].(map[string]interface{}); ok {
		sku := &armcontainerservice.ManagedClusterSKU{}
		if name, ok := skuRaw["name"].(string); ok {
			skuName := armcontainerservice.ManagedClusterSKUName(name)
			sku.Name = &skuName
		}
		if tier, ok := skuRaw["tier"].(string); ok {
			skuTier := armcontainerservice.ManagedClusterSKUTier(tier)
			sku.Tier = &skuTier
		}
		params.SKU = sku
	}

	// Parse Identity
	if identityRaw, ok := props["identity"].(map[string]interface{}); ok {
		identity := &armcontainerservice.ManagedClusterIdentity{}
		if identityType, ok := identityRaw["type"].(string); ok {
			t := armcontainerservice.ResourceIdentityType(identityType)
			identity.Type = &t
		}
		params.Identity = identity
	}

	// Initialize properties
	params.Properties = &armcontainerservice.ManagedClusterProperties{}

	// DNS prefix
	if dnsPrefix, ok := props["dnsPrefix"].(string); ok && dnsPrefix != "" {
		params.Properties.DNSPrefix = to.Ptr(dnsPrefix)
	}

	// Kubernetes version
	if kubeVersion, ok := props["kubernetesVersion"].(string); ok && kubeVersion != "" {
		params.Properties.KubernetesVersion = to.Ptr(kubeVersion)
	}

	// Enable RBAC
	if enableRBAC, ok := props["enableRBAC"].(bool); ok {
		params.Properties.EnableRBAC = to.Ptr(enableRBAC)
	}

	// Parse agent pool profiles
	if poolsRaw, ok := props["agentPoolProfiles"].([]interface{}); ok && len(poolsRaw) > 0 {
		pools := make([]*armcontainerservice.ManagedClusterAgentPoolProfile, 0, len(poolsRaw))
		for i, poolRaw := range poolsRaw {
			poolMap, ok := poolRaw.(map[string]interface{})
			if !ok {
				return nil, fmt.Errorf("agentPoolProfiles[%d] must be an object", i)
			}

			pool := &armcontainerservice.ManagedClusterAgentPoolProfile{}

			if name, ok := poolMap["name"].(string); ok {
				pool.Name = to.Ptr(name)
			}
			if count, ok := poolMap["count"].(float64); ok {
				pool.Count = to.Ptr(int32(count))
			}
			if vmSize, ok := poolMap["vmSize"].(string); ok {
				pool.VMSize = to.Ptr(vmSize)
			}
			if osDiskSize, ok := poolMap["osDiskSizeGB"].(float64); ok {
				pool.OSDiskSizeGB = to.Ptr(int32(osDiskSize))
			}
			if osType, ok := poolMap["osType"].(string); ok {
				t := armcontainerservice.OSType(osType)
				pool.OSType = &t
			}
			if mode, ok := poolMap["mode"].(string); ok {
				m := armcontainerservice.AgentPoolMode(mode)
				pool.Mode = &m
			}
			if enableAutoScaling, ok := poolMap["enableAutoScaling"].(bool); ok {
				pool.EnableAutoScaling = to.Ptr(enableAutoScaling)
			}
			if minCount, ok := poolMap["minCount"].(float64); ok {
				pool.MinCount = to.Ptr(int32(minCount))
			}
			if maxCount, ok := poolMap["maxCount"].(float64); ok {
				pool.MaxCount = to.Ptr(int32(maxCount))
			}

			pools = append(pools, pool)
		}
		params.Properties.AgentPoolProfiles = pools
	}

	// Parse network profile
	if netRaw, ok := props["networkProfile"].(map[string]interface{}); ok {
		netProfile := &armcontainerservice.NetworkProfile{}
		if plugin, ok := netRaw["networkPlugin"].(string); ok {
			p := armcontainerservice.NetworkPlugin(plugin)
			netProfile.NetworkPlugin = &p
		}
		if pluginMode, ok := netRaw["networkPluginMode"].(string); ok {
			m := armcontainerservice.NetworkPluginMode(pluginMode)
			netProfile.NetworkPluginMode = &m
		}
		if policy, ok := netRaw["networkPolicy"].(string); ok {
			p := armcontainerservice.NetworkPolicy(policy)
			netProfile.NetworkPolicy = &p
		}
		if serviceCidr, ok := netRaw["serviceCidr"].(string); ok {
			netProfile.ServiceCidr = to.Ptr(serviceCidr)
		}
		if dnsServiceIP, ok := netRaw["dnsServiceIP"].(string); ok {
			netProfile.DNSServiceIP = to.Ptr(dnsServiceIP)
		}
		if podCidr, ok := netRaw["podCidr"].(string); ok {
			netProfile.PodCidr = to.Ptr(podCidr)
		}
		if lbSku, ok := netRaw["loadBalancerSku"].(string); ok {
			sku := armcontainerservice.LoadBalancerSKU(lbSku)
			netProfile.LoadBalancerSKU = &sku
		}
		params.Properties.NetworkProfile = netProfile
	}

	// Parse AAD profile
	if aadRaw, ok := props["aadProfile"].(map[string]interface{}); ok {
		aadProfile := &armcontainerservice.ManagedClusterAADProfile{}
		if managed, ok := aadRaw["managed"].(bool); ok {
			aadProfile.Managed = to.Ptr(managed)
		}
		if enableAzureRBAC, ok := aadRaw["enableAzureRBAC"].(bool); ok {
			aadProfile.EnableAzureRBAC = to.Ptr(enableAzureRBAC)
		}
		if tenantID, ok := aadRaw["tenantID"].(string); ok {
			aadProfile.TenantID = to.Ptr(tenantID)
		}
		params.Properties.AADProfile = aadProfile
	}

	// Parse Linux profile
	if linuxRaw, ok := props["linuxProfile"].(map[string]interface{}); ok {
		linuxProfile := &armcontainerservice.LinuxProfile{}
		if adminUsername, ok := linuxRaw["adminUsername"].(string); ok {
			linuxProfile.AdminUsername = to.Ptr(adminUsername)
		}
		if sshRaw, ok := linuxRaw["ssh"].(map[string]interface{}); ok {
			if keysRaw, ok := sshRaw["publicKeys"].([]interface{}); ok {
				keys := make([]*armcontainerservice.SSHPublicKey, 0, len(keysRaw))
				for _, keyRaw := range keysRaw {
					if keyMap, ok := keyRaw.(map[string]interface{}); ok {
						if keyData, ok := keyMap["keyData"].(string); ok {
							keys = append(keys, &armcontainerservice.SSHPublicKey{
								KeyData: to.Ptr(keyData),
							})
						}
					}
				}
				if len(keys) > 0 {
					linuxProfile.SSH = &armcontainerservice.SSHConfiguration{
						PublicKeys: keys,
					}
				}
			}
		}
		params.Properties.LinuxProfile = linuxProfile
	}

	// Tags
	if azureTags := formaeTagsToAzureTags(request.Properties); azureTags != nil {
		params.Tags = azureTags
	}

	poller, err := mc.Client.ManagedClustersClient.BeginCreateOrUpdate(ctx, rgName, clusterName, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       mapAzureErrorToOperationErrorCode(err),
			},
		}, fmt.Errorf("failed to start AKS cluster creation: %w", err)
	}

	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.ContainerService/managedClusters/%s",
		mc.Config.SubscriptionId, rgName, clusterName)

	if poller.Done() {
		result, err := poller.Result(ctx)
		if err != nil {
			return &resource.CreateResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationCreate,
					OperationStatus: resource.OperationStatusFailure,
					ErrorCode:       mapAzureErrorToOperationErrorCode(err),
				},
			}, fmt.Errorf("failed to get AKS cluster create result: %w", err)
		}

		propsJSON, err := serializeManagedClusterProperties(result.ManagedCluster, rgName, clusterName)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize AKS cluster properties: %w", err)
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

func (mc *ManagedCluster) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	parts := splitResourceID(request.NativeID)

	rgName, ok := parts["resourcegroups"]
	if !ok || rgName == "" {
		return nil, fmt.Errorf("invalid NativeID: could not extract resource group name from %s", request.NativeID)
	}

	clusterName, ok := parts["managedclusters"]
	if !ok || clusterName == "" {
		return nil, fmt.Errorf("invalid NativeID: could not extract cluster name from %s", request.NativeID)
	}

	result, err := mc.Client.ManagedClustersClient.Get(ctx, rgName, clusterName, nil)
	if err != nil {
		return &resource.ReadResult{
			ErrorCode: mapAzureErrorToOperationErrorCode(err),
		}, fmt.Errorf("failed to read AKS cluster: %w", err)
	}

	propsJSON, err := serializeManagedClusterProperties(result.ManagedCluster, rgName, clusterName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize AKS cluster properties: %w", err)
	}

	return &resource.ReadResult{
		Properties: string(propsJSON),
	}, nil
}

func (mc *ManagedCluster) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	parts := splitResourceID(request.NativeID)

	rgName, ok := parts["resourcegroups"]
	if !ok || rgName == "" {
		return nil, fmt.Errorf("invalid NativeID: could not extract resource group name from %s", request.NativeID)
	}

	clusterName, ok := parts["managedclusters"]
	if !ok || clusterName == "" {
		return nil, fmt.Errorf("invalid NativeID: could not extract cluster name from %s", request.NativeID)
	}

	var props map[string]interface{}
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	location, ok := props["location"].(string)
	if !ok || location == "" {
		return nil, fmt.Errorf("location is required")
	}

	params := armcontainerservice.ManagedCluster{
		Location:   to.Ptr(location),
		Properties: &armcontainerservice.ManagedClusterProperties{},
	}

	// Parse SKU
	if skuRaw, ok := props["sku"].(map[string]interface{}); ok {
		sku := &armcontainerservice.ManagedClusterSKU{}
		if name, ok := skuRaw["name"].(string); ok {
			skuName := armcontainerservice.ManagedClusterSKUName(name)
			sku.Name = &skuName
		}
		if tier, ok := skuRaw["tier"].(string); ok {
			skuTier := armcontainerservice.ManagedClusterSKUTier(tier)
			sku.Tier = &skuTier
		}
		params.SKU = sku
	}

	// Parse Identity
	if identityRaw, ok := props["identity"].(map[string]interface{}); ok {
		identity := &armcontainerservice.ManagedClusterIdentity{}
		if identityType, ok := identityRaw["type"].(string); ok {
			t := armcontainerservice.ResourceIdentityType(identityType)
			identity.Type = &t
		}
		params.Identity = identity
	}

	// Tags
	if azureTags := formaeTagsToAzureTags(request.DesiredProperties); azureTags != nil {
		params.Tags = azureTags
	}

	poller, err := mc.Client.ManagedClustersClient.BeginCreateOrUpdate(ctx, rgName, clusterName, params, nil)
	if err != nil {
		return &resource.UpdateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationUpdate,
				OperationStatus: resource.OperationStatusFailure,
				NativeID:        request.NativeID,
				ErrorCode:       mapAzureErrorToOperationErrorCode(err),
			},
		}, fmt.Errorf("failed to start AKS cluster update: %w", err)
	}

	if poller.Done() {
		result, err := poller.Result(ctx)
		if err != nil {
			return &resource.UpdateResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationUpdate,
					OperationStatus: resource.OperationStatusFailure,
					NativeID:        request.NativeID,
					ErrorCode:       mapAzureErrorToOperationErrorCode(err),
				},
			}, fmt.Errorf("failed to get AKS cluster update result: %w", err)
		}

		propsJSON, err := serializeManagedClusterProperties(result.ManagedCluster, rgName, clusterName)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize AKS cluster properties: %w", err)
		}

		return &resource.UpdateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:          resource.OperationUpdate,
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

func (mc *ManagedCluster) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	parts := splitResourceID(request.NativeID)

	rgName, ok := parts["resourcegroups"]
	if !ok || rgName == "" {
		return nil, fmt.Errorf("invalid NativeID: could not extract resource group name from %s", request.NativeID)
	}

	clusterName, ok := parts["managedclusters"]
	if !ok || clusterName == "" {
		return nil, fmt.Errorf("invalid NativeID: could not extract cluster name from %s", request.NativeID)
	}

	poller, err := mc.Client.ManagedClustersClient.BeginDelete(ctx, rgName, clusterName, nil)
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
				ErrorCode:       mapAzureErrorToOperationErrorCode(err),
			},
		}, fmt.Errorf("failed to start AKS cluster deletion: %w", err)
	}

	resumeToken, err := poller.ResumeToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get resume token: %w", err)
	}

	reqID := lroRequestID{
		OperationType: "delete",
		ResumeToken:   resumeToken,
		NativeID:      request.NativeID,
	}
	reqIDJSON, err := json.Marshal(reqID)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request ID: %w", err)
	}

	return &resource.DeleteResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationDelete,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       string(reqIDJSON),
			NativeID:        request.NativeID,
		},
	}, nil
}

func (mc *ManagedCluster) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	var reqID lroRequestID
	if err := json.Unmarshal([]byte(request.RequestID), &reqID); err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
			},
		}, fmt.Errorf("failed to parse request ID: %w", err)
	}

	switch reqID.OperationType {
	case "create", "update":
		return mc.statusCreateOrUpdate(ctx, request, &reqID)
	case "delete":
		return mc.statusDelete(ctx, request, &reqID)
	default:
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
			},
		}, fmt.Errorf("unknown operation type: %s", reqID.OperationType)
	}
}

func (mc *ManagedCluster) statusCreateOrUpdate(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	operation := resource.OperationCreate
	if reqID.OperationType == "update" {
		operation = resource.OperationUpdate
	}

	poller, err := mc.Client.ResumeCreateManagedClusterPoller(reqID.ResumeToken)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       operation,
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
			},
		}, fmt.Errorf("failed to resume poller from token: %w", err)
	}

	if poller.Done() {
		return mc.handleCreateOrUpdateComplete(ctx, request, reqID, poller, operation)
	}

	_, err = poller.Poll(ctx)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       operation,
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       mapAzureErrorToOperationErrorCode(err),
			},
		}, nil
	}

	// Check if this poll revealed completion
	if poller.Done() {
		return mc.handleCreateOrUpdateComplete(ctx, request, reqID, poller, operation)
	}

	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       operation,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       request.RequestID,
			NativeID:        reqID.NativeID,
		},
	}, nil
}

func (mc *ManagedCluster) handleCreateOrUpdateComplete(ctx context.Context, request *resource.StatusRequest, _ *lroRequestID, poller *runtime.Poller[armcontainerservice.ManagedClustersClientCreateOrUpdateResponse], operation resource.Operation) (*resource.StatusResult, error) {
	result, err := poller.Result(ctx)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       operation,
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       mapAzureErrorToOperationErrorCode(err),
			},
		}, nil
	}

	parts := splitResourceID(*result.ID)
	rgName := parts["resourcegroups"]

	propsJSON, err := serializeManagedClusterProperties(result.ManagedCluster, rgName, *result.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize AKS cluster properties: %w", err)
	}

	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			Operation:          operation,
			OperationStatus:    resource.OperationStatusSuccess,
			RequestID:          request.RequestID,
			NativeID:           *result.ID,
			ResourceProperties: propsJSON,
		},
	}, nil
}

func (mc *ManagedCluster) statusDelete(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	poller, err := mc.Client.ResumeDeleteManagedClusterPoller(reqID.ResumeToken)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationDelete,
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
			},
		}, fmt.Errorf("failed to resume poller from token: %w", err)
	}

	if poller.Done() {
		_, err := poller.Result(ctx)
		if err != nil {
			// NotFound means resource is already deleted - success
			if isDeleteSuccessError(err) {
				return &resource.StatusResult{
					ProgressResult: &resource.ProgressResult{
						Operation:       resource.OperationDelete,
						OperationStatus: resource.OperationStatusSuccess,
						RequestID:       request.RequestID,
						NativeID:        reqID.NativeID,
					},
				}, nil
			}
			return &resource.StatusResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationDelete,
					OperationStatus: resource.OperationStatusFailure,
					RequestID:       request.RequestID,
					ErrorCode:       mapAzureErrorToOperationErrorCode(err),
				},
			}, nil
		}
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationDelete,
				OperationStatus: resource.OperationStatusSuccess,
				RequestID:       request.RequestID,
				NativeID:        reqID.NativeID,
			},
		}, nil
	}

	_, err = poller.Poll(ctx)
	if err != nil {
		// NotFound means resource is already deleted - success
		if isDeleteSuccessError(err) {
			return &resource.StatusResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationDelete,
					OperationStatus: resource.OperationStatusSuccess,
					RequestID:       request.RequestID,
					NativeID:        reqID.NativeID,
				},
			}, nil
		}
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationDelete,
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       mapAzureErrorToOperationErrorCode(err),
			},
		}, nil
	}

	// Check if this poll revealed completion
	if poller.Done() {
		_, err := poller.Result(ctx)
		if err != nil {
			// NotFound means resource is already deleted - success
			if isDeleteSuccessError(err) {
				return &resource.StatusResult{
					ProgressResult: &resource.ProgressResult{
						Operation:       resource.OperationDelete,
						OperationStatus: resource.OperationStatusSuccess,
						RequestID:       request.RequestID,
						NativeID:        reqID.NativeID,
					},
				}, nil
			}
			return &resource.StatusResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationDelete,
					OperationStatus: resource.OperationStatusFailure,
					RequestID:       request.RequestID,
					ErrorCode:       mapAzureErrorToOperationErrorCode(err),
				},
			}, nil
		}
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationDelete,
				OperationStatus: resource.OperationStatusSuccess,
				RequestID:       request.RequestID,
				NativeID:        reqID.NativeID,
			},
		}, nil
	}

	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationDelete,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       request.RequestID,
			NativeID:        reqID.NativeID,
		},
	}, nil
}

func (mc *ManagedCluster) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	resourceGroupName, ok := request.AdditionalProperties["resourceGroupName"]
	if !ok || resourceGroupName == "" {
		return nil, fmt.Errorf("resourceGroupName is required in AdditionalProperties for listing ManagedClusters")
	}

	pager := mc.Client.ManagedClustersClient.NewListByResourceGroupPager(resourceGroupName, nil)

	var nativeIDs []string

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list AKS clusters in resource group %s: %w", resourceGroupName, err)
		}

		for _, cluster := range page.Value {
			if cluster.ID == nil {
				continue
			}

			nativeIDs = append(nativeIDs, *cluster.ID)
		}
	}

	return &resource.ListResult{
		NativeIDs: nativeIDs,
	}, nil
}
