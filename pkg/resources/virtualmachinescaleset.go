// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v5"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeVirtualMachineScaleSet = "Azure::Compute::VirtualMachineScaleSet"

type vmssAPI interface {
	BeginCreateOrUpdate(ctx context.Context, resourceGroupName, vmScaleSetName string, parameters armcompute.VirtualMachineScaleSet, options *armcompute.VirtualMachineScaleSetsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armcompute.VirtualMachineScaleSetsClientCreateOrUpdateResponse], error)
	Get(ctx context.Context, resourceGroupName, vmScaleSetName string, options *armcompute.VirtualMachineScaleSetsClientGetOptions) (armcompute.VirtualMachineScaleSetsClientGetResponse, error)
	BeginUpdate(ctx context.Context, resourceGroupName, vmScaleSetName string, parameters armcompute.VirtualMachineScaleSetUpdate, options *armcompute.VirtualMachineScaleSetsClientBeginUpdateOptions) (*runtime.Poller[armcompute.VirtualMachineScaleSetsClientUpdateResponse], error)
	BeginDelete(ctx context.Context, resourceGroupName, vmScaleSetName string, options *armcompute.VirtualMachineScaleSetsClientBeginDeleteOptions) (*runtime.Poller[armcompute.VirtualMachineScaleSetsClientDeleteResponse], error)
	NewListPager(resourceGroupName string, options *armcompute.VirtualMachineScaleSetsClientListOptions) *runtime.Pager[armcompute.VirtualMachineScaleSetsClientListResponse]
}

func init() {
	registry.Register(ResourceTypeVirtualMachineScaleSet, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &VirtualMachineScaleSet{api: c.VMScaleSetsClient, config: cfg, pipeline: c.Pipeline()}
	})
}

// VirtualMachineScaleSet is the provisioner for Azure VMSS — the platform primitive
// behind AKS node pools and any "fleet of identical VMs" workload.
type VirtualMachineScaleSet struct {
	api      vmssAPI
	config   *config.Config
	pipeline runtime.Pipeline
}

func serializeVMSSProperties(result armcompute.VirtualMachineScaleSet, rgName, vmssName string) (json.RawMessage, error) {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	if result.Name != nil {
		props["name"] = *result.Name
	} else {
		props["name"] = vmssName
	}
	if result.Location != nil {
		props["location"] = *result.Location
	}

	if result.SKU != nil {
		sku := map[string]any{}
		if result.SKU.Name != nil {
			sku["name"] = *result.SKU.Name
		}
		if result.SKU.Capacity != nil {
			sku["capacity"] = int(*result.SKU.Capacity)
		}
		if result.SKU.Tier != nil {
			sku["tier"] = *result.SKU.Tier
		}
		props["sku"] = sku
	}

	if result.Properties != nil {
		if result.Properties.OrchestrationMode != nil {
			props["orchestrationMode"] = string(*result.Properties.OrchestrationMode)
		}
		if result.Properties.UpgradePolicy != nil && result.Properties.UpgradePolicy.Mode != nil {
			props["upgradePolicy"] = map[string]any{"mode": string(*result.Properties.UpgradePolicy.Mode)}
		}
		if result.Properties.VirtualMachineProfile != nil {
			props["virtualMachineProfile"] = vmssSerializeVMProfile(result.Properties.VirtualMachineProfile)
		}
	}

	if tags := azureTagsToFormaeTags(result.Tags); tags != nil {
		props["Tags"] = tags
	}

	if result.ID != nil {
		props["id"] = *result.ID
	}

	return json.Marshal(props)
}

func vmssSerializeVMProfile(vmp *armcompute.VirtualMachineScaleSetVMProfile) map[string]any {
	out := map[string]any{}

	if vmp.OSProfile != nil {
		osp := map[string]any{}
		if vmp.OSProfile.ComputerNamePrefix != nil {
			osp["computerNamePrefix"] = *vmp.OSProfile.ComputerNamePrefix
		}
		if vmp.OSProfile.AdminUsername != nil {
			osp["adminUsername"] = *vmp.OSProfile.AdminUsername
		}
		if vmp.OSProfile.AdminPassword != nil {
			osp["adminPassword"] = *vmp.OSProfile.AdminPassword
		}
		if vmp.OSProfile.CustomData != nil {
			osp["customData"] = *vmp.OSProfile.CustomData
		}
		if vmp.OSProfile.LinuxConfiguration != nil {
			lc := map[string]any{}
			if vmp.OSProfile.LinuxConfiguration.DisablePasswordAuthentication != nil {
				lc["disablePasswordAuthentication"] = *vmp.OSProfile.LinuxConfiguration.DisablePasswordAuthentication
			}
			if len(lc) > 0 {
				osp["linuxConfiguration"] = lc
			}
		}
		out["osProfile"] = osp
	}

	if vmp.StorageProfile != nil {
		sp := map[string]any{}
		if vmp.StorageProfile.ImageReference != nil {
			ir := map[string]any{}
			if vmp.StorageProfile.ImageReference.Publisher != nil {
				ir["publisher"] = *vmp.StorageProfile.ImageReference.Publisher
			}
			if vmp.StorageProfile.ImageReference.Offer != nil {
				ir["offer"] = *vmp.StorageProfile.ImageReference.Offer
			}
			if vmp.StorageProfile.ImageReference.SKU != nil {
				ir["sku"] = *vmp.StorageProfile.ImageReference.SKU
			}
			if vmp.StorageProfile.ImageReference.Version != nil {
				ir["version"] = *vmp.StorageProfile.ImageReference.Version
			}
			sp["imageReference"] = ir
		}
		if vmp.StorageProfile.OSDisk != nil {
			od := map[string]any{}
			if vmp.StorageProfile.OSDisk.CreateOption != nil {
				od["createOption"] = string(*vmp.StorageProfile.OSDisk.CreateOption)
			}
			if vmp.StorageProfile.OSDisk.Caching != nil {
				od["caching"] = string(*vmp.StorageProfile.OSDisk.Caching)
			}
			if vmp.StorageProfile.OSDisk.DiskSizeGB != nil {
				od["diskSizeGB"] = int(*vmp.StorageProfile.OSDisk.DiskSizeGB)
			}
			if vmp.StorageProfile.OSDisk.ManagedDisk != nil && vmp.StorageProfile.OSDisk.ManagedDisk.StorageAccountType != nil {
				od["managedDisk"] = map[string]any{"storageAccountType": string(*vmp.StorageProfile.OSDisk.ManagedDisk.StorageAccountType)}
			}
			sp["osDisk"] = od
		}
		out["storageProfile"] = sp
	}

	if vmp.NetworkProfile != nil {
		nics := make([]map[string]any, 0, len(vmp.NetworkProfile.NetworkInterfaceConfigurations))
		for _, nic := range vmp.NetworkProfile.NetworkInterfaceConfigurations {
			n := map[string]any{}
			if nic.Name != nil {
				n["name"] = *nic.Name
			}
			if nic.Properties != nil {
				if nic.Properties.Primary != nil {
					n["primary"] = *nic.Properties.Primary
				}
				ips := make([]map[string]any, 0, len(nic.Properties.IPConfigurations))
				for _, ip := range nic.Properties.IPConfigurations {
					ipMap := map[string]any{}
					if ip.Name != nil {
						ipMap["name"] = *ip.Name
					}
					if ip.Properties != nil && ip.Properties.Subnet != nil && ip.Properties.Subnet.ID != nil {
						ipMap["subnetId"] = *ip.Properties.Subnet.ID
					}
					ips = append(ips, ipMap)
				}
				n["ipConfigurations"] = ips
			}
			nics = append(nics, n)
		}
		out["networkProfile"] = map[string]any{"networkInterfaceConfigurations": nics}
	}

	return out
}

func vmssParamsFromProperties(props map[string]any) (armcompute.VirtualMachineScaleSet, error) {
	location, _ := props["location"].(string)
	if location == "" {
		return armcompute.VirtualMachineScaleSet{}, fmt.Errorf("location is required")
	}

	skuMap, ok := props["sku"].(map[string]any)
	if !ok {
		return armcompute.VirtualMachineScaleSet{}, fmt.Errorf("sku is required")
	}
	skuName, _ := skuMap["name"].(string)
	if skuName == "" {
		return armcompute.VirtualMachineScaleSet{}, fmt.Errorf("sku.name is required")
	}
	capF, _ := skuMap["capacity"].(float64)
	cap64 := int64(capF)
	tier, _ := skuMap["tier"].(string)
	if tier == "" {
		tier = "Standard"
	}
	sku := &armcompute.SKU{Name: &skuName, Capacity: &cap64, Tier: &tier}

	upgMap, _ := props["upgradePolicy"].(map[string]any)
	if upgMap == nil {
		return armcompute.VirtualMachineScaleSet{}, fmt.Errorf("upgradePolicy is required")
	}
	mode, _ := upgMap["mode"].(string)
	if mode == "" {
		return armcompute.VirtualMachineScaleSet{}, fmt.Errorf("upgradePolicy.mode is required")
	}
	upgMode := armcompute.UpgradeMode(mode)

	properties := &armcompute.VirtualMachineScaleSetProperties{
		UpgradePolicy: &armcompute.UpgradePolicy{Mode: &upgMode},
	}

	if om, ok := props["orchestrationMode"].(string); ok && om != "" {
		omc := armcompute.OrchestrationMode(om)
		properties.OrchestrationMode = &omc
	}

	vmpMap, ok := props["virtualMachineProfile"].(map[string]any)
	if !ok {
		return armcompute.VirtualMachineScaleSet{}, fmt.Errorf("virtualMachineProfile is required")
	}
	vmp, err := vmssBuildVMProfile(vmpMap)
	if err != nil {
		return armcompute.VirtualMachineScaleSet{}, err
	}
	properties.VirtualMachineProfile = vmp

	vmss := armcompute.VirtualMachineScaleSet{
		Location:   &location,
		SKU:        sku,
		Properties: properties,
	}

	if azureTags := formaeTagsToAzureTags(mustMarshalJSON(props)); azureTags != nil {
		vmss.Tags = azureTags
	}

	return vmss, nil
}

func vmssBuildVMProfile(m map[string]any) (*armcompute.VirtualMachineScaleSetVMProfile, error) {
	vmp := &armcompute.VirtualMachineScaleSetVMProfile{}

	if osMap, ok := m["osProfile"].(map[string]any); ok {
		osp := &armcompute.VirtualMachineScaleSetOSProfile{}
		if v, ok := osMap["computerNamePrefix"].(string); ok && v != "" {
			osp.ComputerNamePrefix = &v
		}
		if v, ok := osMap["adminUsername"].(string); ok && v != "" {
			osp.AdminUsername = &v
		}
		if v, ok := osMap["adminPassword"].(string); ok && v != "" {
			osp.AdminPassword = &v
		}
		if v, ok := osMap["customData"].(string); ok && v != "" {
			osp.CustomData = &v
		}
		if linMap, ok := osMap["linuxConfiguration"].(map[string]any); ok {
			lc := &armcompute.LinuxConfiguration{}
			if v, ok := linMap["disablePasswordAuthentication"].(bool); ok {
				lc.DisablePasswordAuthentication = &v
			}
			osp.LinuxConfiguration = lc
		}
		vmp.OSProfile = osp
	}

	if storMap, ok := m["storageProfile"].(map[string]any); ok {
		sp := &armcompute.VirtualMachineScaleSetStorageProfile{}
		if irMap, ok := storMap["imageReference"].(map[string]any); ok {
			ir := &armcompute.ImageReference{}
			if v, ok := irMap["publisher"].(string); ok && v != "" {
				ir.Publisher = &v
			}
			if v, ok := irMap["offer"].(string); ok && v != "" {
				ir.Offer = &v
			}
			if v, ok := irMap["sku"].(string); ok && v != "" {
				ir.SKU = &v
			}
			if v, ok := irMap["version"].(string); ok && v != "" {
				ir.Version = &v
			}
			sp.ImageReference = ir
		}
		if osDiskMap, ok := storMap["osDisk"].(map[string]any); ok {
			od := &armcompute.VirtualMachineScaleSetOSDisk{}
			if v, ok := osDiskMap["createOption"].(string); ok && v != "" {
				co := armcompute.DiskCreateOptionTypes(v)
				od.CreateOption = &co
			}
			if v, ok := osDiskMap["caching"].(string); ok && v != "" {
				c := armcompute.CachingTypes(v)
				od.Caching = &c
			}
			if v, ok := osDiskMap["diskSizeGB"].(float64); ok {
				size := int32(v)
				od.DiskSizeGB = &size
			}
			if mdMap, ok := osDiskMap["managedDisk"].(map[string]any); ok {
				md := &armcompute.VirtualMachineScaleSetManagedDiskParameters{}
				if v, ok := mdMap["storageAccountType"].(string); ok && v != "" {
					sat := armcompute.StorageAccountTypes(v)
					md.StorageAccountType = &sat
				}
				od.ManagedDisk = md
			}
			sp.OSDisk = od
		}
		vmp.StorageProfile = sp
	}

	if netMap, ok := m["networkProfile"].(map[string]any); ok {
		np := &armcompute.VirtualMachineScaleSetNetworkProfile{}
		rawNICs, _ := netMap["networkInterfaceConfigurations"].([]any)
		for _, raw := range rawNICs {
			nMap, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			nic := &armcompute.VirtualMachineScaleSetNetworkConfiguration{
				Properties: &armcompute.VirtualMachineScaleSetNetworkConfigurationProperties{},
			}
			if v, ok := nMap["name"].(string); ok && v != "" {
				nic.Name = &v
			}
			if v, ok := nMap["primary"].(bool); ok {
				nic.Properties.Primary = &v
			}
			rawIPs, _ := nMap["ipConfigurations"].([]any)
			for _, rip := range rawIPs {
				ipMap, ok := rip.(map[string]any)
				if !ok {
					continue
				}
				ip := &armcompute.VirtualMachineScaleSetIPConfiguration{
					Properties: &armcompute.VirtualMachineScaleSetIPConfigurationProperties{},
				}
				if v, ok := ipMap["name"].(string); ok && v != "" {
					ip.Name = &v
				}
				if v, ok := ipMap["subnetId"].(string); ok && v != "" {
					ip.Properties.Subnet = &armcompute.APIEntityReference{ID: &v}
				}
				nic.Properties.IPConfigurations = append(nic.Properties.IPConfigurations, ip)
			}
			np.NetworkInterfaceConfigurations = append(np.NetworkInterfaceConfigurations, nic)
		}
		vmp.NetworkProfile = np
	}

	return vmp, nil
}

func (v *VirtualMachineScaleSet) parseNativeID(nativeID string) (rgName, vmssName string, err error) {
	parts := splitResourceID(nativeID)
	rgName = parts["resourcegroups"]
	vmssName = parts["virtualmachinescalesets"]
	if rgName == "" || vmssName == "" {
		return "", "", fmt.Errorf("invalid NativeID: %s", nativeID)
	}
	return rgName, vmssName, nil
}

func (v *VirtualMachineScaleSet) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props map[string]any
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	rgName, _ := props["resourceGroupName"].(string)
	if rgName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	vmssName, _ := props["name"].(string)
	if vmssName == "" {
		vmssName = request.Label
	}
	if vmssName == "" {
		return nil, fmt.Errorf("name is required")
	}

	params, err := vmssParamsFromProperties(props)
	if err != nil {
		return nil, err
	}

	poller, err := v.api.BeginCreateOrUpdate(ctx, rgName, vmssName, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       mapAzureErrorToOperationErrorCode(err),
			},
		}, nil
	}

	expectedID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Compute/virtualMachineScaleSets/%s",
		v.config.SubscriptionId, rgName, vmssName)

	if poller.Done() {
		result, err := poller.Result(ctx)
		if err != nil {
			return &resource.CreateResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationCreate,
					OperationStatus: resource.OperationStatusFailure,
					ErrorCode:       mapAzureErrorToOperationErrorCode(err),
				},
			}, nil
		}
		propsJSON, err := serializeVMSSProperties(result.VirtualMachineScaleSet, rgName, vmssName)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize VMSS properties: %w", err)
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

	token, err := poller.ResumeToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get resume token: %w", err)
	}
	reqID, err := encodeLROStart(lroOpCreate, token, expectedID)
	if err != nil {
		return nil, err
	}

	return &resource.CreateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationCreate,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       reqID,
			NativeID:        expectedID,
		},
	}, nil
}

func (v *VirtualMachineScaleSet) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, vmssName, err := v.parseNativeID(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := v.api.Get(ctx, rgName, vmssName, nil)
	if err != nil {
		return &resource.ReadResult{
			ErrorCode: mapAzureErrorToOperationErrorCode(err),
		}, nil
	}

	propsJSON, err := serializeVMSSProperties(result.VirtualMachineScaleSet, rgName, vmssName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize VMSS properties: %w", err)
	}

	return &resource.ReadResult{
		ResourceType: ResourceTypeVirtualMachineScaleSet,
		Properties:   string(propsJSON),
	}, nil
}

func (v *VirtualMachineScaleSet) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, vmssName, err := v.parseNativeID(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props map[string]any
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse desired properties: %w", err)
	}

	update := armcompute.VirtualMachineScaleSetUpdate{}
	if skuMap, ok := props["sku"].(map[string]any); ok {
		s := &armcompute.SKU{}
		if name, ok := skuMap["name"].(string); ok && name != "" {
			s.Name = &name
		}
		if capF, ok := skuMap["capacity"].(float64); ok {
			c := int64(capF)
			s.Capacity = &c
		}
		if tier, ok := skuMap["tier"].(string); ok && tier != "" {
			s.Tier = &tier
		}
		update.SKU = s
	}
	if azureTags := formaeTagsToAzureTags(request.DesiredProperties); azureTags != nil {
		update.Tags = azureTags
	}

	poller, err := v.api.BeginUpdate(ctx, rgName, vmssName, update, nil)
	if err != nil {
		return &resource.UpdateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationUpdate,
				OperationStatus: resource.OperationStatusFailure,
				NativeID:        request.NativeID,
				ErrorCode:       mapAzureErrorToOperationErrorCode(err),
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
					ErrorCode:       mapAzureErrorToOperationErrorCode(err),
				},
			}, nil
		}
		propsJSON, err := serializeVMSSProperties(result.VirtualMachineScaleSet, rgName, vmssName)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize VMSS properties: %w", err)
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

	token, err := poller.ResumeToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get resume token: %w", err)
	}
	reqID, err := encodeLROStart(lroOpUpdate, token, request.NativeID)
	if err != nil {
		return nil, err
	}

	return &resource.UpdateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationUpdate,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       reqID,
			NativeID:        request.NativeID,
		},
	}, nil
}

func (v *VirtualMachineScaleSet) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, vmssName, err := v.parseNativeID(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, err := v.api.BeginDelete(ctx, rgName, vmssName, nil)
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
				ErrorCode:       mapAzureErrorToOperationErrorCode(err),
			},
		}, fmt.Errorf("failed to delete VMSS: %w", err)
	}

	if poller.Done() {
		return &resource.DeleteResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationDelete,
				OperationStatus: resource.OperationStatusSuccess,
				NativeID:        request.NativeID,
			},
		}, nil
	}

	token, err := poller.ResumeToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get resume token: %w", err)
	}
	reqID, err := encodeLROStart(lroOpDelete, token, request.NativeID)
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

func (v *VirtualMachineScaleSet) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	reqID, err := decodeLROStatus(request.RequestID)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
			},
		}, err
	}

	switch reqID.OperationType {
	case lroOpCreate:
		return v.statusCreate(ctx, request, &reqID)
	case lroOpUpdate:
		return v.statusUpdate(ctx, request, &reqID)
	case lroOpDelete:
		return v.statusDelete(ctx, request, &reqID)
	default:
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
			},
		}, fmt.Errorf("unknown LRO operation type: %s", reqID.OperationType)
	}
}

func (v *VirtualMachineScaleSet) statusCreate(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	poller, err := resumePoller[armcompute.VirtualMachineScaleSetsClientCreateOrUpdateResponse](v.pipeline, reqID.ResumeToken)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
			},
		}, err
	}

	if !poller.Done() {
		if _, err := poller.Poll(ctx); err != nil {
			return &resource.StatusResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationCreate,
					OperationStatus: resource.OperationStatusFailure,
					RequestID:       request.RequestID,
					ErrorCode:       mapAzureErrorToOperationErrorCode(err),
				},
			}, err
		}
		if !poller.Done() {
			return &resource.StatusResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationCreate,
					OperationStatus: resource.OperationStatusInProgress,
					RequestID:       request.RequestID,
					NativeID:        reqID.NativeID,
				},
			}, nil
		}
	}

	result, err := poller.Result(ctx)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       mapAzureErrorToOperationErrorCode(err),
			},
		}, err
	}

	rgName, vmssName, err := v.parseNativeID(*result.ID)
	if err != nil {
		return nil, err
	}

	propsJSON, err := serializeVMSSProperties(result.VirtualMachineScaleSet, rgName, vmssName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize VMSS properties: %w", err)
	}

	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			Operation:          resource.OperationCreate,
			OperationStatus:    resource.OperationStatusSuccess,
			RequestID:          request.RequestID,
			NativeID:           *result.ID,
			ResourceProperties: propsJSON,
		},
	}, nil
}

func (v *VirtualMachineScaleSet) statusUpdate(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	poller, err := resumePoller[armcompute.VirtualMachineScaleSetsClientUpdateResponse](v.pipeline, reqID.ResumeToken)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationUpdate,
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
			},
		}, err
	}

	if !poller.Done() {
		if _, err := poller.Poll(ctx); err != nil {
			return &resource.StatusResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationUpdate,
					OperationStatus: resource.OperationStatusFailure,
					RequestID:       request.RequestID,
					ErrorCode:       mapAzureErrorToOperationErrorCode(err),
				},
			}, err
		}
		if !poller.Done() {
			return &resource.StatusResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationUpdate,
					OperationStatus: resource.OperationStatusInProgress,
					RequestID:       request.RequestID,
					NativeID:        reqID.NativeID,
				},
			}, nil
		}
	}

	result, err := poller.Result(ctx)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationUpdate,
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       mapAzureErrorToOperationErrorCode(err),
			},
		}, err
	}

	rgName, vmssName, err := v.parseNativeID(*result.ID)
	if err != nil {
		return nil, err
	}

	propsJSON, err := serializeVMSSProperties(result.VirtualMachineScaleSet, rgName, vmssName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize VMSS properties: %w", err)
	}

	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			Operation:          resource.OperationUpdate,
			OperationStatus:    resource.OperationStatusSuccess,
			RequestID:          request.RequestID,
			NativeID:           *result.ID,
			ResourceProperties: propsJSON,
		},
	}, nil
}

func (v *VirtualMachineScaleSet) statusDelete(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	poller, err := resumePoller[armcompute.VirtualMachineScaleSetsClientDeleteResponse](v.pipeline, reqID.ResumeToken)
	if err != nil {
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
				ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
			},
		}, err
	}

	if poller.Done() {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationDelete,
				OperationStatus: resource.OperationStatusSuccess,
				RequestID:       request.RequestID,
				NativeID:        reqID.NativeID,
			},
		}, nil
	}

	if _, err := poller.Poll(ctx); err != nil {
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
		}, err
	}

	if poller.Done() {
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

func (v *VirtualMachineScaleSet) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	if rgName == "" {
		return &resource.ListResult{}, nil
	}

	var nativeIDs []string
	pager := v.api.NewListPager(rgName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list VMSS: %w", err)
		}
		for _, vmss := range page.Value {
			if vmss.ID != nil {
				nativeIDs = append(nativeIDs, *vmss.ID)
			}
		}
	}

	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
