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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v5"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeVirtualMachine = "AZURE::Compute::VirtualMachine"

type virtualMachinesAPI interface {
	BeginCreateOrUpdate(ctx context.Context, resourceGroupName string, vmName string, parameters armcompute.VirtualMachine, options *armcompute.VirtualMachinesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armcompute.VirtualMachinesClientCreateOrUpdateResponse], error)
	Get(ctx context.Context, resourceGroupName string, vmName string, options *armcompute.VirtualMachinesClientGetOptions) (armcompute.VirtualMachinesClientGetResponse, error)
	BeginUpdate(ctx context.Context, resourceGroupName string, vmName string, parameters armcompute.VirtualMachineUpdate, options *armcompute.VirtualMachinesClientBeginUpdateOptions) (*runtime.Poller[armcompute.VirtualMachinesClientUpdateResponse], error)
	BeginDelete(ctx context.Context, resourceGroupName string, vmName string, options *armcompute.VirtualMachinesClientBeginDeleteOptions) (*runtime.Poller[armcompute.VirtualMachinesClientDeleteResponse], error)
	NewListPager(resourceGroupName string, options *armcompute.VirtualMachinesClientListOptions) *runtime.Pager[armcompute.VirtualMachinesClientListResponse]
}

func init() {
	registry.Register(ResourceTypeVirtualMachine, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &VirtualMachine{
			api:      c.VirtualMachinesClient,
			config:   cfg,
			pipeline: c.Pipeline(),
		}
	})
}

// VirtualMachine is the provisioner for Azure Virtual Machines.
type VirtualMachine struct {
	api      virtualMachinesAPI
	config   *config.Config
	pipeline runtime.Pipeline
}

func (vm *VirtualMachine) parseNativeID(nativeID string) (rgName, vmName string, err error) {
	rgName, names, err := armIDParts(nativeID, "virtualmachines")
	if err != nil {
		return "", "", err
	}
	return rgName, names["virtualmachines"], nil
}

// serializeVirtualMachineProperties converts an Azure VirtualMachine to Formae property format
func serializeVirtualMachineProperties(result armcompute.VirtualMachine, rgName, vmName string) (json.RawMessage, error) {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	if result.Name != nil {
		props["name"] = *result.Name
	} else {
		props["name"] = vmName
	}

	if result.Location != nil {
		props["location"] = *result.Location
	}

	if result.Properties != nil {
		// VM Size
		if result.Properties.HardwareProfile != nil && result.Properties.HardwareProfile.VMSize != nil {
			props["vmSize"] = string(*result.Properties.HardwareProfile.VMSize)
		}

		// Network interfaces
		if result.Properties.NetworkProfile != nil && result.Properties.NetworkProfile.NetworkInterfaces != nil {
			nics := make([]map[string]any, 0, len(result.Properties.NetworkProfile.NetworkInterfaces))
			for _, nic := range result.Properties.NetworkProfile.NetworkInterfaces {
				nicMap := make(map[string]any)
				if nic.ID != nil {
					nicMap["id"] = *nic.ID
				}
				if nic.Properties != nil && nic.Properties.Primary != nil {
					nicMap["primary"] = *nic.Properties.Primary
				}
				nics = append(nics, nicMap)
			}
			props["networkInterfaces"] = nics
		}

		// Storage profile
		if result.Properties.StorageProfile != nil {
			// Image reference
			if result.Properties.StorageProfile.ImageReference != nil {
				imgRef := result.Properties.StorageProfile.ImageReference
				imageRef := make(map[string]any)
				if imgRef.Publisher != nil {
					imageRef["publisher"] = *imgRef.Publisher
				}
				if imgRef.Offer != nil {
					imageRef["offer"] = *imgRef.Offer
				}
				if imgRef.SKU != nil {
					imageRef["sku"] = *imgRef.SKU
				}
				if imgRef.Version != nil {
					imageRef["version"] = *imgRef.Version
				}
				props["imageReference"] = imageRef
			}

			// OS disk
			if result.Properties.StorageProfile.OSDisk != nil {
				osDiskData := result.Properties.StorageProfile.OSDisk
				osDisk := make(map[string]any)
				if osDiskData.Name != nil {
					osDisk["name"] = *osDiskData.Name
				}
				if osDiskData.CreateOption != nil {
					osDisk["createOption"] = string(*osDiskData.CreateOption)
				}
				if osDiskData.DiskSizeGB != nil {
					osDisk["diskSizeGB"] = *osDiskData.DiskSizeGB
				}
				if osDiskData.Caching != nil {
					osDisk["caching"] = string(*osDiskData.Caching)
				}
				if osDiskData.ManagedDisk != nil && osDiskData.ManagedDisk.StorageAccountType != nil {
					osDisk["managedDisk"] = map[string]any{
						"storageAccountType": string(*osDiskData.ManagedDisk.StorageAccountType),
					}
				}
				props["osDisk"] = osDisk
			}
		}

		// OS profile
		if result.Properties.OSProfile != nil {
			if result.Properties.OSProfile.AdminUsername != nil {
				props["adminUsername"] = *result.Properties.OSProfile.AdminUsername
			}
			if result.Properties.OSProfile.ComputerName != nil {
				props["computerName"] = *result.Properties.OSProfile.ComputerName
			}

			// Linux configuration
			if result.Properties.OSProfile.LinuxConfiguration != nil {
				linuxConfig := result.Properties.OSProfile.LinuxConfiguration
				lc := make(map[string]any)
				if linuxConfig.DisablePasswordAuthentication != nil {
					lc["disablePasswordAuthentication"] = *linuxConfig.DisablePasswordAuthentication
				}
				if linuxConfig.ProvisionVMAgent != nil {
					lc["provisionVMAgent"] = *linuxConfig.ProvisionVMAgent
				}
				// Serialize SSH public keys: keyData is the public half (not a
				// secret; Azure returns it on GET). Omitting it made every
				// reconcile plan an add of linuxConfiguration.ssh forever.
				if linuxConfig.SSH != nil && len(linuxConfig.SSH.PublicKeys) > 0 {
					keys := make([]any, 0, len(linuxConfig.SSH.PublicKeys))
					for _, k := range linuxConfig.SSH.PublicKeys {
						key := make(map[string]any)
						if k.Path != nil {
							key["path"] = *k.Path
						}
						if k.KeyData != nil {
							key["keyData"] = *k.KeyData
						}
						keys = append(keys, key)
					}
					lc["ssh"] = map[string]any{"publicKeys": keys}
				}
				props["linuxConfiguration"] = lc
			}

			// Windows configuration
			if result.Properties.OSProfile.WindowsConfiguration != nil {
				winConfig := result.Properties.OSProfile.WindowsConfiguration
				wc := make(map[string]any)
				if winConfig.ProvisionVMAgent != nil {
					wc["provisionVMAgent"] = *winConfig.ProvisionVMAgent
				}
				if winConfig.EnableAutomaticUpdates != nil {
					wc["enableAutomaticUpdates"] = *winConfig.EnableAutomaticUpdates
				}
				if winConfig.TimeZone != nil {
					wc["timeZone"] = *winConfig.TimeZone
				}
				props["windowsConfiguration"] = wc
			}
		}

		// Provisioning state
		if result.Properties.ProvisioningState != nil {
			props["provisioningState"] = *result.Properties.ProvisioningState
		}

		// VM ID
		if result.Properties.VMID != nil {
			props["vmId"] = *result.Properties.VMID
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

func (vm *VirtualMachine) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {

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

	// Extract VM name from properties, fall back to label
	vmName, ok := props["name"].(string)
	if !ok || vmName == "" {
		vmName = request.Label
	}

	// Extract vmSize (required)
	vmSize, ok := props["vmSize"].(string)
	if !ok || vmSize == "" {
		return nil, fmt.Errorf("vmSize is required")
	}

	// Extract networkInterfaces (required)
	nicsRaw, ok := props["networkInterfaces"].([]any)
	if !ok || len(nicsRaw) == 0 {
		return nil, fmt.Errorf("networkInterfaces is required")
	}

	networkInterfaces := make([]*armcompute.NetworkInterfaceReference, 0, len(nicsRaw))
	for i, nicRaw := range nicsRaw {
		nicMap, ok := nicRaw.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("networkInterfaces[%d] must be an object", i)
		}
		nicID, ok := nicMap["id"].(string)
		if !ok || nicID == "" {
			return nil, fmt.Errorf("networkInterfaces[%d].id is required", i)
		}
		nicRef := &armcompute.NetworkInterfaceReference{
			ID: stringPtr(nicID),
		}
		if primary, ok := nicMap["primary"].(bool); ok {
			nicRef.Properties = &armcompute.NetworkInterfaceReferenceProperties{
				Primary: to.Ptr(primary),
			}
		}
		networkInterfaces = append(networkInterfaces, nicRef)
	}

	// Extract imageReference (required)
	imageRefRaw, ok := props["imageReference"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("imageReference is required")
	}
	imageRef := &armcompute.ImageReference{}
	if publisher, ok := imageRefRaw["publisher"].(string); ok {
		imageRef.Publisher = stringPtr(publisher)
	}
	if offer, ok := imageRefRaw["offer"].(string); ok {
		imageRef.Offer = stringPtr(offer)
	}
	if sku, ok := imageRefRaw["sku"].(string); ok {
		imageRef.SKU = stringPtr(sku)
	}
	if version, ok := imageRefRaw["version"].(string); ok {
		imageRef.Version = stringPtr(version)
	}

	// Extract osDisk (required)
	osDiskRaw, ok := props["osDisk"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("osDisk is required")
	}
	osDisk := &armcompute.OSDisk{}
	if name, ok := osDiskRaw["name"].(string); ok && name != "" {
		osDisk.Name = stringPtr(name)
	}
	if createOption, ok := osDiskRaw["createOption"].(string); ok {
		co := armcompute.DiskCreateOptionTypes(createOption)
		osDisk.CreateOption = &co
	}
	if diskSizeGB, ok := osDiskRaw["diskSizeGB"].(float64); ok {
		osDisk.DiskSizeGB = to.Ptr(int32(diskSizeGB))
	}
	if caching, ok := osDiskRaw["caching"].(string); ok {
		c := armcompute.CachingTypes(caching)
		osDisk.Caching = &c
	}
	if managedDiskRaw, ok := osDiskRaw["managedDisk"].(map[string]any); ok {
		osDisk.ManagedDisk = &armcompute.ManagedDiskParameters{}
		if storageAccountType, ok := managedDiskRaw["storageAccountType"].(string); ok {
			sat := armcompute.StorageAccountTypes(storageAccountType)
			osDisk.ManagedDisk.StorageAccountType = &sat
		}
	}

	// Extract adminUsername (required)
	adminUsername, ok := props["adminUsername"].(string)
	if !ok || adminUsername == "" {
		return nil, fmt.Errorf("adminUsername is required")
	}

	// Build VM parameters
	computerName := vmName
	if cn, ok := props["computerName"].(string); ok && cn != "" {
		computerName = cn
	}

	params := armcompute.VirtualMachine{
		Location: stringPtr(location),
		Properties: &armcompute.VirtualMachineProperties{
			HardwareProfile: &armcompute.HardwareProfile{
				VMSize: to.Ptr(armcompute.VirtualMachineSizeTypes(vmSize)),
			},
			NetworkProfile: &armcompute.NetworkProfile{
				NetworkInterfaces: networkInterfaces,
			},
			StorageProfile: &armcompute.StorageProfile{
				ImageReference: imageRef,
				OSDisk:         osDisk,
			},
			OSProfile: &armcompute.OSProfile{
				ComputerName:  stringPtr(computerName),
				AdminUsername: stringPtr(adminUsername),
			},
		},
	}

	// Add admin password if provided
	if adminPassword, ok := props["adminPassword"].(string); ok && adminPassword != "" {
		params.Properties.OSProfile.AdminPassword = stringPtr(adminPassword)
	}

	// Add Linux configuration if provided
	if linuxConfigRaw, ok := props["linuxConfiguration"].(map[string]any); ok {
		linuxConfig := &armcompute.LinuxConfiguration{}
		if disablePassword, ok := linuxConfigRaw["disablePasswordAuthentication"].(bool); ok {
			linuxConfig.DisablePasswordAuthentication = to.Ptr(disablePassword)
		}
		if provisionVMAgent, ok := linuxConfigRaw["provisionVMAgent"].(bool); ok {
			linuxConfig.ProvisionVMAgent = to.Ptr(provisionVMAgent)
		}
		// Parse SSH configuration
		if sshRaw, ok := linuxConfigRaw["ssh"].(map[string]any); ok {
			if publicKeysRaw, ok := sshRaw["publicKeys"].([]any); ok {
				publicKeys := make([]*armcompute.SSHPublicKey, 0, len(publicKeysRaw))
				for _, pkRaw := range publicKeysRaw {
					if pkMap, ok := pkRaw.(map[string]any); ok {
						pk := &armcompute.SSHPublicKey{}
						if path, ok := pkMap["path"].(string); ok {
							pk.Path = stringPtr(path)
						}
						if keyData, ok := pkMap["keyData"].(string); ok {
							pk.KeyData = stringPtr(keyData)
						}
						publicKeys = append(publicKeys, pk)
					}
				}
				linuxConfig.SSH = &armcompute.SSHConfiguration{
					PublicKeys: publicKeys,
				}
			}
		}
		params.Properties.OSProfile.LinuxConfiguration = linuxConfig
	}

	// Add Windows configuration if provided
	if windowsConfigRaw, ok := props["windowsConfiguration"].(map[string]any); ok {
		windowsConfig := &armcompute.WindowsConfiguration{}
		if provisionVMAgent, ok := windowsConfigRaw["provisionVMAgent"].(bool); ok {
			windowsConfig.ProvisionVMAgent = to.Ptr(provisionVMAgent)
		}
		if enableAutoUpdates, ok := windowsConfigRaw["enableAutomaticUpdates"].(bool); ok {
			windowsConfig.EnableAutomaticUpdates = to.Ptr(enableAutoUpdates)
		}
		if timeZone, ok := windowsConfigRaw["timeZone"].(string); ok {
			windowsConfig.TimeZone = stringPtr(timeZone)
		}
		params.Properties.OSProfile.WindowsConfiguration = windowsConfig
	}

	// Add tags if present
	if azureTags := formaeTagsToAzureTags(request.Properties); azureTags != nil {
		params.Tags = azureTags
	}

	// Call Azure API to create VM (async/LRO operation)
	poller, err := vm.api.BeginCreateOrUpdate(
		ctx,
		rgName,
		vmName,
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
	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Compute/virtualMachines/%s",
		vm.config.SubscriptionId, rgName, vmName)

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

		propsJSON, err := serializeVirtualMachineProperties(result.VirtualMachine, rgName, vmName)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize VirtualMachine properties: %w", err)
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

func (vm *VirtualMachine) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, vmName, err := vm.parseNativeID(request.NativeID)
	if err != nil {
		return nil, err
	}

	// Get VM from Azure
	result, err := vm.api.Get(ctx, rgName, vmName, nil)
	if err != nil {
		return &resource.ReadResult{

			ErrorCode: operationErrorCode(err),
		}, nil
	}

	propsJSON, err := serializeVirtualMachineProperties(result.VirtualMachine, rgName, vmName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize VirtualMachine properties: %w", err)
	}

	return &resource.ReadResult{

		Properties: string(propsJSON),
	}, nil
}

func (vm *VirtualMachine) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, vmName, err := vm.parseNativeID(request.NativeID)
	if err != nil {
		return nil, err
	}

	// Parse properties JSON
	var props map[string]any
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	// For VM updates, we use the Update API which only allows certain fields
	// Most importantly: vmSize can be changed via Update
	updateParams := armcompute.VirtualMachineUpdate{}

	// Extract vmSize if provided (can be updated)
	if vmSize, ok := props["vmSize"].(string); ok && vmSize != "" {
		updateParams.Properties = &armcompute.VirtualMachineProperties{
			HardwareProfile: &armcompute.HardwareProfile{
				VMSize: to.Ptr(armcompute.VirtualMachineSizeTypes(vmSize)),
			},
		}
	}

	// Add tags if present
	if azureTags := formaeTagsToAzureTags(request.DesiredProperties); azureTags != nil {
		updateParams.Tags = azureTags
	}

	// Call Azure API to update VM
	poller, err := vm.api.BeginUpdate(
		ctx,
		rgName,
		vmName,
		updateParams,
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

		propsJSON, err := serializeVirtualMachineProperties(result.VirtualMachine, rgName, vmName)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize VirtualMachine properties: %w", err)
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

func (vm *VirtualMachine) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, vmName, err := vm.parseNativeID(request.NativeID)
	if err != nil {
		return nil, err
	}

	// Start async deletion
	poller, err := vm.api.BeginDelete(ctx, rgName, vmName, nil)
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
		}, fmt.Errorf("failed to start VirtualMachine deletion: %w", err)
	}

	// Check if completed synchronously
	if poller.Done() {
		_, err := poller.Result(ctx)
		if err != nil {
			return &resource.DeleteResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationDelete,
					OperationStatus: resource.OperationStatusFailure,
					NativeID:        request.NativeID,

					ErrorCode: operationErrorCode(err),
				},
			}, fmt.Errorf("failed to get VirtualMachine delete result: %w", err)
		}

		return &resource.DeleteResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationDelete,
				OperationStatus: resource.OperationStatusSuccess,
				NativeID:        request.NativeID,
			},
		}, nil
	}

	// Get the ResumeToken for tracking the operation
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

func (vm *VirtualMachine) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
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
	case lroOpCreate:
		return vm.statusCreate(ctx, request, &reqID)
	case lroOpUpdate:
		return vm.statusUpdate(ctx, request, &reqID)
	case lroOpDelete:
		return vm.statusDelete(ctx, request, &reqID)
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

func (vm *VirtualMachine) statusCreate(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	return statusLRO(ctx, request, reqID, resource.OperationCreate,
		func(token string) (*runtime.Poller[armcompute.VirtualMachinesClientCreateOrUpdateResponse], error) {
			return resumePoller[armcompute.VirtualMachinesClientCreateOrUpdateResponse](vm.pipeline, token)
		},
		func(_ context.Context, result armcompute.VirtualMachinesClientCreateOrUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
			rgName, vmName, err := vm.parseNativeID(*result.ID)
			if err != nil {
				return "", nil, err
			}
			propsJSON, err := serializeVirtualMachineProperties(result.VirtualMachine, rgName, vmName)
			if err != nil {
				return "", nil, fmt.Errorf("failed to serialize VirtualMachine properties: %w", err)
			}
			return *result.ID, propsJSON, nil
		},
	)
}

func (vm *VirtualMachine) statusUpdate(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	return statusLRO(ctx, request, reqID, resource.OperationUpdate,
		func(token string) (*runtime.Poller[armcompute.VirtualMachinesClientUpdateResponse], error) {
			return resumePoller[armcompute.VirtualMachinesClientUpdateResponse](vm.pipeline, token)
		},
		func(_ context.Context, result armcompute.VirtualMachinesClientUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
			rgName, vmName, err := vm.parseNativeID(*result.ID)
			if err != nil {
				return "", nil, err
			}
			propsJSON, err := serializeVirtualMachineProperties(result.VirtualMachine, rgName, vmName)
			if err != nil {
				return "", nil, fmt.Errorf("failed to serialize VirtualMachine properties: %w", err)
			}
			return *result.ID, propsJSON, nil
		},
	)
}

func (vm *VirtualMachine) statusDelete(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	return statusDeleteLRO(ctx, request, reqID,
		func(token string) (*runtime.Poller[armcompute.VirtualMachinesClientDeleteResponse], error) {
			return resumePoller[armcompute.VirtualMachinesClientDeleteResponse](vm.pipeline, token)
		},
		nil,
	)
}

func (vm *VirtualMachine) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	// Get resourceGroupName from AdditionalProperties
	resourceGroupName, ok := request.AdditionalProperties["resourceGroupName"]
	if !ok || resourceGroupName == "" {
		return nil, fmt.Errorf("resourceGroupName is required in AdditionalProperties for listing VirtualMachines")
	}

	pager := vm.api.NewListPager(resourceGroupName, nil)

	var nativeIDs []string

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list VirtualMachines in resource group %s: %w", resourceGroupName, err)
		}

		for _, vmResult := range page.Value {
			if vmResult.ID == nil {
				continue
			}

			nativeIDs = append(nativeIDs, *vmResult.ID)
		}
	}

	return &resource.ListResult{

		NativeIDs: nativeIDs,
	}, nil
}
