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
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"gopkg.in/yaml.v3"
)

const ResourceTypeManagedCluster = "AZURE::ContainerService::ManagedCluster"

type managedClustersAPI interface {
	BeginCreateOrUpdate(ctx context.Context, resourceGroupName string, resourceName string, parameters armcontainerservice.ManagedCluster, options *armcontainerservice.ManagedClustersClientBeginCreateOrUpdateOptions) (*runtime.Poller[armcontainerservice.ManagedClustersClientCreateOrUpdateResponse], error)
	Get(ctx context.Context, resourceGroupName string, resourceName string, options *armcontainerservice.ManagedClustersClientGetOptions) (armcontainerservice.ManagedClustersClientGetResponse, error)
	BeginDelete(ctx context.Context, resourceGroupName string, resourceName string, options *armcontainerservice.ManagedClustersClientBeginDeleteOptions) (*runtime.Poller[armcontainerservice.ManagedClustersClientDeleteResponse], error)
	NewListByResourceGroupPager(resourceGroupName string, options *armcontainerservice.ManagedClustersClientListByResourceGroupOptions) *runtime.Pager[armcontainerservice.ManagedClustersClientListByResourceGroupResponse]
	ListClusterAdminCredentials(ctx context.Context, resourceGroupName string, resourceName string, options *armcontainerservice.ManagedClustersClientListClusterAdminCredentialsOptions) (armcontainerservice.ManagedClustersClientListClusterAdminCredentialsResponse, error)
}

func init() {
	registry.Register(ResourceTypeManagedCluster, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &ManagedCluster{
			api:      c.ManagedClustersClient,
			config:   cfg,
			pipeline: c.Pipeline(),
		}
	})
}

// ManagedCluster is the provisioner for Azure Kubernetes Service (AKS) clusters.
type ManagedCluster struct {
	api      managedClustersAPI
	config   *config.Config
	pipeline runtime.Pipeline
}

func (mc *ManagedCluster) parseNativeID(nativeID string) (rgName, clusterName string, err error) {
	rgName, names, err := armIDParts(nativeID, "managedclusters")
	if err != nil {
		return "", "", err
	}
	return rgName, names["managedclusters"], nil
}

// fetchCertificateAuthority retrieves the cluster's CA cert by parsing the
// admin kubeconfig (the AKS REST API exposes the CA only via the credentials
// list endpoint, not on the ManagedCluster resource directly). Returns the
// base64-encoded `certificate-authority-data` string, or empty on any error
// (callers treat the field as optional — failing the create/read just because
// CA fetch failed would be heavy-handed).
func (mc *ManagedCluster) fetchCertificateAuthority(ctx context.Context, rgName, clusterName string) string {
	resp, err := mc.api.ListClusterAdminCredentials(ctx, rgName, clusterName, nil)
	if err != nil {
		return ""
	}
	if len(resp.Kubeconfigs) == 0 {
		return ""
	}
	kc := resp.Kubeconfigs[0]
	if kc == nil || len(kc.Value) == 0 {
		return ""
	}
	var doc struct {
		Clusters []struct {
			Cluster struct {
				CertificateAuthorityData string `yaml:"certificate-authority-data"`
			} `yaml:"cluster"`
		} `yaml:"clusters"`
	}
	if err := yaml.Unmarshal(kc.Value, &doc); err != nil {
		return ""
	}
	if len(doc.Clusters) == 0 {
		return ""
	}
	return doc.Clusters[0].Cluster.CertificateAuthorityData
}

// serializeManagedClusterProperties converts an Azure ManagedCluster to Formae property format
func serializeManagedClusterProperties(result armcontainerservice.ManagedCluster, rgName, clusterName, certificateAuthority string) (json.RawMessage, error) {
	props := make(map[string]any)

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
		sku := make(map[string]any)
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
		identity := make(map[string]any)
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

		// Provisioning state (read-only output)
		if result.Properties.ProvisioningState != nil {
			props["provisioningState"] = *result.Properties.ProvisioningState
		}

		// Current Kubernetes version (read-only output — actual running version)
		if result.Properties.CurrentKubernetesVersion != nil {
			props["currentKubernetesVersion"] = *result.Properties.CurrentKubernetesVersion
		}

		// Node resource group (read-only output)
		if result.Properties.NodeResourceGroup != nil {
			props["nodeResourceGroup"] = *result.Properties.NodeResourceGroup
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
			pools := make([]map[string]any, 0, len(result.Properties.AgentPoolProfiles))
			for _, pool := range result.Properties.AgentPoolProfiles {
				if pool == nil {
					continue
				}
				poolMap := make(map[string]any)
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
			netProfile := make(map[string]any)
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
			aadProfile := make(map[string]any)
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

	// Certificate authority (sourced from a separate ListClusterAdminCredentials
	// call; the ManagedCluster resource itself doesn't expose this).
	if certificateAuthority != "" {
		props["certificateAuthority"] = certificateAuthority
	}

	return json.Marshal(props)
}

func (mc *ManagedCluster) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props map[string]any
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
	if skuRaw, ok := props["sku"].(map[string]any); ok {
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
	if identityRaw, ok := props["identity"].(map[string]any); ok {
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
	if poolsRaw, ok := props["agentPoolProfiles"].([]any); ok && len(poolsRaw) > 0 {
		pools := make([]*armcontainerservice.ManagedClusterAgentPoolProfile, 0, len(poolsRaw))
		for i, poolRaw := range poolsRaw {
			poolMap, ok := poolRaw.(map[string]any)
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
	if netRaw, ok := props["networkProfile"].(map[string]any); ok {
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
	if aadRaw, ok := props["aadProfile"].(map[string]any); ok {
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
	if linuxRaw, ok := props["linuxProfile"].(map[string]any); ok {
		linuxProfile := &armcontainerservice.LinuxProfile{}
		if adminUsername, ok := linuxRaw["adminUsername"].(string); ok {
			linuxProfile.AdminUsername = to.Ptr(adminUsername)
		}
		if sshRaw, ok := linuxRaw["ssh"].(map[string]any); ok {
			if keysRaw, ok := sshRaw["publicKeys"].([]any); ok {
				keys := make([]*armcontainerservice.SSHPublicKey, 0, len(keysRaw))
				for _, keyRaw := range keysRaw {
					if keyMap, ok := keyRaw.(map[string]any); ok {
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

	poller, err := mc.api.BeginCreateOrUpdate(ctx, rgName, clusterName, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.ContainerService/managedClusters/%s",
		mc.config.SubscriptionId, rgName, clusterName)

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

		certificateAuthority := mc.fetchCertificateAuthority(ctx, rgName, clusterName)
		propsJSON, err := serializeManagedClusterProperties(result.ManagedCluster, rgName, clusterName, certificateAuthority)
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
	rgName, clusterName, err := mc.parseNativeID(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := mc.api.Get(ctx, rgName, clusterName, nil)
	if err != nil {
		return &resource.ReadResult{
			ErrorCode: operationErrorCode(err),
		}, nil
	}

	certificateAuthority := mc.fetchCertificateAuthority(ctx, rgName, clusterName)
	propsJSON, err := serializeManagedClusterProperties(result.ManagedCluster, rgName, clusterName, certificateAuthority)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize AKS cluster properties: %w", err)
	}

	return &resource.ReadResult{
		Properties: string(propsJSON),
	}, nil
}

func (mc *ManagedCluster) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, clusterName, err := mc.parseNativeID(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props map[string]any
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
	if skuRaw, ok := props["sku"].(map[string]any); ok {
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
	if identityRaw, ok := props["identity"].(map[string]any); ok {
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

	poller, err := mc.api.BeginCreateOrUpdate(ctx, rgName, clusterName, params, nil)
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

		certificateAuthority := mc.fetchCertificateAuthority(ctx, rgName, clusterName)
		propsJSON, err := serializeManagedClusterProperties(result.ManagedCluster, rgName, clusterName, certificateAuthority)
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
	rgName, clusterName, err := mc.parseNativeID(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, err := mc.api.BeginDelete(ctx, rgName, clusterName, nil)
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
				ErrorCode:       operationErrorCode(err),
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
	reqID, err := decodeLROStatus(request.RequestID)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
			},
		}, fmt.Errorf("failed to parse request ID: %w", err)
	}

	switch reqID.OperationType {
	case lroOpCreate, lroOpUpdate:
		return mc.statusCreateOrUpdate(ctx, request, &reqID)
	case lroOpDelete:
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
	if reqID.OperationType == lroOpUpdate {
		operation = resource.OperationUpdate
	}

	return statusLRO(ctx, request, reqID, operation,
		func(token string) (*runtime.Poller[armcontainerservice.ManagedClustersClientCreateOrUpdateResponse], error) {
			return resumePoller[armcontainerservice.ManagedClustersClientCreateOrUpdateResponse](mc.pipeline, token)
		},
		func(ctx context.Context, result armcontainerservice.ManagedClustersClientCreateOrUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
			rgName, clusterName, err := mc.parseNativeID(*result.ID)
			if err != nil {
				return "", nil, err
			}
			certificateAuthority := mc.fetchCertificateAuthority(ctx, rgName, clusterName)
			propsJSON, err := serializeManagedClusterProperties(result.ManagedCluster, rgName, clusterName, certificateAuthority)
			if err != nil {
				return "", nil, fmt.Errorf("failed to serialize AKS cluster properties: %w", err)
			}
			return *result.ID, propsJSON, nil
		},
	)
}

func (mc *ManagedCluster) statusDelete(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	return statusDeleteLRO(ctx, request, reqID,
		func(token string) (*runtime.Poller[armcontainerservice.ManagedClustersClientDeleteResponse], error) {
			return resumePoller[armcontainerservice.ManagedClustersClientDeleteResponse](mc.pipeline, token)
		},
		nil,
	)
}

func (mc *ManagedCluster) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	resourceGroupName, ok := request.AdditionalProperties["resourceGroupName"]
	if !ok || resourceGroupName == "" {
		return nil, fmt.Errorf("resourceGroupName is required in AdditionalProperties for listing ManagedClusters")
	}

	pager := mc.api.NewListByResourceGroupPager(resourceGroupName, nil)

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
