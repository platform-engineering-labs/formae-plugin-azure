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

const ResourceTypeVirtualMachine = "Azure::Compute::VirtualMachine"

func init() {
	registry.Register(ResourceTypeVirtualMachine, func(client *client.Client, cfg *config.Config) prov.Provisioner {
		return &VirtualMachine{client, cfg}
	})
}

// VirtualMachine is the provisioner for Azure Virtual Machines.
type VirtualMachine struct {
	Client *client.Client
	Config *config.Config
}

// serializeVirtualMachineProperties converts an Azure VirtualMachine to Formae property format
func serializeVirtualMachineProperties(result armcompute.VirtualMachine, rgName, vmName string) (json.RawMessage, error) {
	props := make(map[string]interface{})

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
			nics := make([]map[string]interface{}, 0, len(result.Properties.NetworkProfile.NetworkInterfaces))
			for _, nic := range result.Properties.NetworkProfile.NetworkInterfaces {
				nicMap := make(map[string]interface{})
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
				imageRef := make(map[string]interface{})
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
				osDisk := make(map[string]interface{})
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
					osDisk["managedDisk"] = map[string]interface{}{
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
				lc := make(map[string]interface{})
				if linuxConfig.DisablePasswordAuthentication != nil {
					lc["disablePasswordAuthentication"] = *linuxConfig.DisablePasswordAuthentication
				}
				if linuxConfig.ProvisionVMAgent != nil {
					lc["provisionVMAgent"] = *linuxConfig.ProvisionVMAgent
				}
				// We don't serialize SSH keys back (security)
				props["linuxConfiguration"] = lc
			}

			// Windows configuration
			if result.Properties.OSProfile.WindowsConfiguration != nil {
				winConfig := result.Properties.OSProfile.WindowsConfiguration
				wc := make(map[string]interface{})
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
	nicsRaw, ok := props["networkInterfaces"].([]interface{})
	if !ok || len(nicsRaw) == 0 {
		return nil, fmt.Errorf("networkInterfaces is required")
	}

	networkInterfaces := make([]*armcompute.NetworkInterfaceReference, 0, len(nicsRaw))
	for i, nicRaw := range nicsRaw {
		nicMap, ok := nicRaw.(map[string]interface{})
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
	imageRefRaw, ok := props["imageReference"].(map[string]interface{})
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
	osDiskRaw, ok := props["osDisk"].(map[string]interface{})
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
	if managedDiskRaw, ok := osDiskRaw["managedDisk"].(map[string]interface{}); ok {
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
	if linuxConfigRaw, ok := props["linuxConfiguration"].(map[string]interface{}); ok {
		linuxConfig := &armcompute.LinuxConfiguration{}
		if disablePassword, ok := linuxConfigRaw["disablePasswordAuthentication"].(bool); ok {
			linuxConfig.DisablePasswordAuthentication = to.Ptr(disablePassword)
		}
		if provisionVMAgent, ok := linuxConfigRaw["provisionVMAgent"].(bool); ok {
			linuxConfig.ProvisionVMAgent = to.Ptr(provisionVMAgent)
		}
		// Parse SSH configuration
		if sshRaw, ok := linuxConfigRaw["ssh"].(map[string]interface{}); ok {
			if publicKeysRaw, ok := sshRaw["publicKeys"].([]interface{}); ok {
				publicKeys := make([]*armcompute.SSHPublicKey, 0, len(publicKeysRaw))
				for _, pkRaw := range publicKeysRaw {
					if pkMap, ok := pkRaw.(map[string]interface{}); ok {
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
	if windowsConfigRaw, ok := props["windowsConfiguration"].(map[string]interface{}); ok {
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
	poller, err := vm.Client.VirtualMachinesClient.BeginCreateOrUpdate(
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

				ErrorCode: mapAzureErrorToOperationErrorCode(err),
			},
		}, fmt.Errorf("failed to start VirtualMachine creation: %w", err)
	}

	// Build expected NativeID
	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Compute/virtualMachines/%s",
		vm.Config.SubscriptionId, rgName, vmName)

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
			}, fmt.Errorf("failed to get VirtualMachine create result: %w", err)
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
	// Parse NativeID to extract resourceGroupName and vmName
	parts := splitResourceID(request.NativeID)

	rgName, ok := parts["resourcegroups"]
	if !ok || rgName == "" {
		return nil, fmt.Errorf("invalid NativeID: could not extract resource group name from %s", request.NativeID)
	}

	vmName, ok := parts["virtualmachines"]
	if !ok || vmName == "" {
		return nil, fmt.Errorf("invalid NativeID: could not extract virtual machine name from %s", request.NativeID)
	}

	// Get VM from Azure
	result, err := vm.Client.VirtualMachinesClient.Get(ctx, rgName, vmName, nil)
	if err != nil {
		return &resource.ReadResult{

			ErrorCode: mapAzureErrorToOperationErrorCode(err),
		}, fmt.Errorf("failed to read VirtualMachine: %w", err)
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
	// Parse NativeID to extract resourceGroupName and vmName
	parts := splitResourceID(request.NativeID)

	rgName, ok := parts["resourcegroups"]
	if !ok || rgName == "" {
		return nil, fmt.Errorf("invalid NativeID: could not extract resource group name from %s", request.NativeID)
	}

	vmName, ok := parts["virtualmachines"]
	if !ok || vmName == "" {
		return nil, fmt.Errorf("invalid NativeID: could not extract virtual machine name from %s", request.NativeID)
	}

	// Parse properties JSON
	var props map[string]interface{}
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
	poller, err := vm.Client.VirtualMachinesClient.BeginUpdate(
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

				ErrorCode: mapAzureErrorToOperationErrorCode(err),
			},
		}, fmt.Errorf("failed to start VirtualMachine update: %w", err)
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
			}, fmt.Errorf("failed to get VirtualMachine update result: %w", err)
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
	// Parse NativeID to extract resourceGroupName and vmName
	parts := splitResourceID(request.NativeID)

	rgName, ok := parts["resourcegroups"]
	if !ok || rgName == "" {
		return nil, fmt.Errorf("invalid NativeID: could not extract resource group name from %s", request.NativeID)
	}

	vmName, ok := parts["virtualmachines"]
	if !ok || vmName == "" {
		return nil, fmt.Errorf("invalid NativeID: could not extract virtual machine name from %s", request.NativeID)
	}

	// Start async deletion
	poller, err := vm.Client.VirtualMachinesClient.BeginDelete(ctx, rgName, vmName, nil)
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

					ErrorCode: mapAzureErrorToOperationErrorCode(err),
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
		return vm.statusCreateOrUpdate(ctx, request, &reqID)
	case "delete":
		return vm.statusDelete(ctx, request, &reqID)
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

func (vm *VirtualMachine) statusCreateOrUpdate(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	operation := resource.OperationCreate
	if reqID.OperationType == "update" {
		operation = resource.OperationUpdate
	}

	// Reconstruct the poller from the resume token
	poller, err := vm.Client.ResumeCreateVirtualMachinePoller(reqID.ResumeToken)
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
		return vm.handleCreateOrUpdateComplete(ctx, request, reqID, poller, operation)
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

	// Check if this poll revealed completion
	if poller.Done() {
		return vm.handleCreateOrUpdateComplete(ctx, request, reqID, poller, operation)
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

func (vm *VirtualMachine) handleCreateOrUpdateComplete(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID, poller *runtime.Poller[armcompute.VirtualMachinesClientCreateOrUpdateResponse], operation resource.Operation) (*resource.StatusResult, error) {
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

	propsJSON, err := serializeVirtualMachineProperties(result.VirtualMachine, rgName, *result.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize VirtualMachine properties: %w", err)
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

func (vm *VirtualMachine) statusDelete(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	// Reconstruct the poller from the resume token
	poller, err := vm.Client.ResumeDeleteVirtualMachinePoller(reqID.ResumeToken)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationDelete,
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,

				ErrorCode: resource.OperationErrorCodeGeneralServiceException,
			},
		}, fmt.Errorf("failed to resume poller from token: %w", err)
	}

	// Check if the operation is already done
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

	// Poll for updated status
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

	// Still in progress - the next status check will determine if Done()
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationDelete,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       request.RequestID,

			NativeID: reqID.NativeID,
		},
	}, nil
}

func (vm *VirtualMachine) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	// Get resourceGroupName from AdditionalProperties
	resourceGroupName, ok := request.AdditionalProperties["resourceGroupName"]
	if !ok || resourceGroupName == "" {
		return nil, fmt.Errorf("resourceGroupName is required in AdditionalProperties for listing VirtualMachines")
	}

	pager := vm.Client.VirtualMachinesClient.NewListPager(resourceGroupName, nil)

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
