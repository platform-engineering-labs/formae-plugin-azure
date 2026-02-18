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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v4"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeNetworkInterface = "Azure::Network::NetworkInterface"

func init() {
	registry.Register(ResourceTypeNetworkInterface, func(client *client.Client, cfg *config.Config) prov.Provisioner {
		return &NetworkInterface{client, cfg}
	})
}

// NetworkInterface is the provisioner for Azure Network Interfaces.
type NetworkInterface struct {
	Client *client.Client
	Config *config.Config
}

// serializeNetworkInterfaceProperties converts an Azure Interface to Formae property format
func serializeNetworkInterfaceProperties(result armnetwork.Interface, rgName, nicName string) (json.RawMessage, error) {
	props := make(map[string]interface{})

	props["resourceGroupName"] = rgName
	if result.Name != nil {
		props["name"] = *result.Name
	} else {
		props["name"] = nicName
	}

	if result.Location != nil {
		props["location"] = *result.Location
	}

	if result.Properties != nil {
		// Serialize IP configurations
		if result.Properties.IPConfigurations != nil {
			ipConfigs := make([]map[string]interface{}, 0, len(result.Properties.IPConfigurations))
			for _, ipConfig := range result.Properties.IPConfigurations {
				config := make(map[string]interface{})
				if ipConfig.Name != nil {
					config["name"] = *ipConfig.Name
				}
				if ipConfig.Properties != nil {
					if ipConfig.Properties.Subnet != nil && ipConfig.Properties.Subnet.ID != nil {
						config["subnet"] = *ipConfig.Properties.Subnet.ID
					}
					if ipConfig.Properties.PublicIPAddress != nil && ipConfig.Properties.PublicIPAddress.ID != nil {
						config["publicIPAddress"] = *ipConfig.Properties.PublicIPAddress.ID
					}
					if ipConfig.Properties.PrivateIPAllocationMethod != nil {
						config["privateIPAllocationMethod"] = string(*ipConfig.Properties.PrivateIPAllocationMethod)
					}
					// Only include privateIPAddress when statically assigned.
					// For Dynamic allocation, Azure assigns this at runtime and
					// it shouldn't round-trip as a managed property.
					if ipConfig.Properties.PrivateIPAddress != nil &&
						ipConfig.Properties.PrivateIPAllocationMethod != nil &&
						*ipConfig.Properties.PrivateIPAllocationMethod == armnetwork.IPAllocationMethodStatic {
						config["privateIPAddress"] = *ipConfig.Properties.PrivateIPAddress
					}
					if ipConfig.Properties.Primary != nil {
						config["primary"] = *ipConfig.Properties.Primary
					}
				}
				ipConfigs = append(ipConfigs, config)
			}
			props["ipConfigurations"] = ipConfigs
		}

		// Network security group
		if result.Properties.NetworkSecurityGroup != nil && result.Properties.NetworkSecurityGroup.ID != nil {
			props["networkSecurityGroup"] = *result.Properties.NetworkSecurityGroup.ID
		}

		// Additional properties
		if result.Properties.EnableAcceleratedNetworking != nil {
			props["enableAcceleratedNetworking"] = *result.Properties.EnableAcceleratedNetworking
		}
		if result.Properties.EnableIPForwarding != nil {
			props["enableIPForwarding"] = *result.Properties.EnableIPForwarding
		}

		// Read-only: MAC address
		if result.Properties.MacAddress != nil {
			props["macAddress"] = *result.Properties.MacAddress
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

func (nic *NetworkInterface) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
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

	// Extract NIC name from properties, fall back to label
	nicName, ok := props["name"].(string)
	if !ok || nicName == "" {
		nicName = request.Label
	}

	// Extract IP configurations (required)
	ipConfigsRaw, ok := props["ipConfigurations"].([]interface{})
	if !ok || len(ipConfigsRaw) == 0 {
		return nil, fmt.Errorf("ipConfigurations is required")
	}

	ipConfigs := make([]*armnetwork.InterfaceIPConfiguration, 0, len(ipConfigsRaw))
	for i, ipConfigRaw := range ipConfigsRaw {
		ipConfigMap, ok := ipConfigRaw.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("ipConfigurations[%d] must be an object", i)
		}

		ipConfig := &armnetwork.InterfaceIPConfiguration{
			Properties: &armnetwork.InterfaceIPConfigurationPropertiesFormat{},
		}

		if name, ok := ipConfigMap["name"].(string); ok {
			ipConfig.Name = stringPtr(name)
		}

		if subnet, ok := ipConfigMap["subnet"].(string); ok && subnet != "" {
			ipConfig.Properties.Subnet = &armnetwork.Subnet{
				ID: stringPtr(subnet),
			}
		}

		if publicIP, ok := ipConfigMap["publicIPAddress"].(string); ok && publicIP != "" {
			ipConfig.Properties.PublicIPAddress = &armnetwork.PublicIPAddress{
				ID: stringPtr(publicIP),
			}
		}

		if allocMethod, ok := ipConfigMap["privateIPAllocationMethod"].(string); ok {
			method := armnetwork.IPAllocationMethod(allocMethod)
			ipConfig.Properties.PrivateIPAllocationMethod = &method
		}

		if privateIP, ok := ipConfigMap["privateIPAddress"].(string); ok && privateIP != "" {
			ipConfig.Properties.PrivateIPAddress = stringPtr(privateIP)
		}

		if primary, ok := ipConfigMap["primary"].(bool); ok {
			ipConfig.Properties.Primary = to.Ptr(primary)
		}

		ipConfigs = append(ipConfigs, ipConfig)
	}

	// Build NetworkInterface parameters
	params := armnetwork.Interface{
		Location: stringPtr(location),
		Properties: &armnetwork.InterfacePropertiesFormat{
			IPConfigurations: ipConfigs,
		},
	}

	// Network security group (optional)
	if nsgID, ok := props["networkSecurityGroup"].(string); ok && nsgID != "" {
		params.Properties.NetworkSecurityGroup = &armnetwork.SecurityGroup{
			ID: stringPtr(nsgID),
		}
	}

	// Optional properties
	if enableAcceleratedNetworking, ok := props["enableAcceleratedNetworking"].(bool); ok {
		params.Properties.EnableAcceleratedNetworking = to.Ptr(enableAcceleratedNetworking)
	}

	if enableIPForwarding, ok := props["enableIPForwarding"].(bool); ok {
		params.Properties.EnableIPForwarding = to.Ptr(enableIPForwarding)
	}

	// Add tags if present
	if azureTags := formaeTagsToAzureTags(request.Properties); azureTags != nil {
		params.Tags = azureTags
	}

	// Call Azure API to create NetworkInterface (async/LRO operation)
	poller, err := nic.Client.InterfacesClient.BeginCreateOrUpdate(
		ctx,
		rgName,
		nicName,
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
		}, fmt.Errorf("failed to start NetworkInterface creation: %w", err)
	}

	// Build expected NativeID
	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/networkInterfaces/%s",
		nic.Config.SubscriptionId, rgName, nicName)

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
			}, fmt.Errorf("failed to get NetworkInterface create result: %w", err)
		}

		propsJSON, err := serializeNetworkInterfaceProperties(result.Interface, rgName, nicName)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize NetworkInterface properties: %w", err)
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

func (nic *NetworkInterface) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	// Parse NativeID to extract resourceGroupName and nicName
	parts := splitResourceID(request.NativeID)

	rgName, ok := parts["resourcegroups"]
	if !ok || rgName == "" {
		return nil, fmt.Errorf("invalid NativeID: could not extract resource group name from %s", request.NativeID)
	}

	nicName, ok := parts["networkinterfaces"]
	if !ok || nicName == "" {
		return nil, fmt.Errorf("invalid NativeID: could not extract network interface name from %s", request.NativeID)
	}

	// Get NetworkInterface from Azure
	result, err := nic.Client.InterfacesClient.Get(ctx, rgName, nicName, nil)
	if err != nil {
		return &resource.ReadResult{

			ErrorCode: mapAzureErrorToOperationErrorCode(err),
		}, fmt.Errorf("failed to read NetworkInterface: %w", err)
	}

	propsJSON, err := serializeNetworkInterfaceProperties(result.Interface, rgName, nicName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize NetworkInterface properties: %w", err)
	}

	return &resource.ReadResult{

		Properties: string(propsJSON),
	}, nil
}

func (nic *NetworkInterface) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	// Parse NativeID to extract resourceGroupName and nicName
	parts := splitResourceID(request.NativeID)

	rgName, ok := parts["resourcegroups"]
	if !ok || rgName == "" {
		return nil, fmt.Errorf("invalid NativeID: could not extract resource group name from %s", request.NativeID)
	}

	nicName, ok := parts["networkinterfaces"]
	if !ok || nicName == "" {
		return nil, fmt.Errorf("invalid NativeID: could not extract network interface name from %s", request.NativeID)
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

	// Extract IP configurations (required)
	ipConfigsRaw, ok := props["ipConfigurations"].([]interface{})
	if !ok || len(ipConfigsRaw) == 0 {
		return nil, fmt.Errorf("ipConfigurations is required")
	}

	ipConfigs := make([]*armnetwork.InterfaceIPConfiguration, 0, len(ipConfigsRaw))
	for i, ipConfigRaw := range ipConfigsRaw {
		ipConfigMap, ok := ipConfigRaw.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("ipConfigurations[%d] must be an object", i)
		}

		ipConfig := &armnetwork.InterfaceIPConfiguration{
			Properties: &armnetwork.InterfaceIPConfigurationPropertiesFormat{},
		}

		if name, ok := ipConfigMap["name"].(string); ok {
			ipConfig.Name = stringPtr(name)
		}

		if subnet, ok := ipConfigMap["subnet"].(string); ok && subnet != "" {
			ipConfig.Properties.Subnet = &armnetwork.Subnet{
				ID: stringPtr(subnet),
			}
		}

		if publicIP, ok := ipConfigMap["publicIPAddress"].(string); ok && publicIP != "" {
			ipConfig.Properties.PublicIPAddress = &armnetwork.PublicIPAddress{
				ID: stringPtr(publicIP),
			}
		}

		if allocMethod, ok := ipConfigMap["privateIPAllocationMethod"].(string); ok {
			method := armnetwork.IPAllocationMethod(allocMethod)
			ipConfig.Properties.PrivateIPAllocationMethod = &method
		}

		if privateIP, ok := ipConfigMap["privateIPAddress"].(string); ok && privateIP != "" {
			ipConfig.Properties.PrivateIPAddress = stringPtr(privateIP)
		}

		if primary, ok := ipConfigMap["primary"].(bool); ok {
			ipConfig.Properties.Primary = to.Ptr(primary)
		}

		ipConfigs = append(ipConfigs, ipConfig)
	}

	// Build NetworkInterface parameters
	params := armnetwork.Interface{
		Location: stringPtr(location),
		Properties: &armnetwork.InterfacePropertiesFormat{
			IPConfigurations: ipConfigs,
		},
	}

	// Network security group (optional)
	if nsgID, ok := props["networkSecurityGroup"].(string); ok && nsgID != "" {
		params.Properties.NetworkSecurityGroup = &armnetwork.SecurityGroup{
			ID: stringPtr(nsgID),
		}
	}

	// Optional properties
	if enableAcceleratedNetworking, ok := props["enableAcceleratedNetworking"].(bool); ok {
		params.Properties.EnableAcceleratedNetworking = to.Ptr(enableAcceleratedNetworking)
	}

	if enableIPForwarding, ok := props["enableIPForwarding"].(bool); ok {
		params.Properties.EnableIPForwarding = to.Ptr(enableIPForwarding)
	}

	// Add tags if present
	if azureTags := formaeTagsToAzureTags(request.DesiredProperties); azureTags != nil {
		params.Tags = azureTags
	}

	// Call Azure API to update NetworkInterface
	poller, err := nic.Client.InterfacesClient.BeginCreateOrUpdate(
		ctx,
		rgName,
		nicName,
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
		}, fmt.Errorf("failed to start NetworkInterface update: %w", err)
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
			}, fmt.Errorf("failed to get NetworkInterface update result: %w", err)
		}

		propsJSON, err := serializeNetworkInterfaceProperties(result.Interface, rgName, nicName)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize NetworkInterface properties: %w", err)
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

func (nic *NetworkInterface) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	// Parse NativeID to extract resourceGroupName and nicName
	parts := splitResourceID(request.NativeID)

	rgName, ok := parts["resourcegroups"]
	if !ok || rgName == "" {
		return nil, fmt.Errorf("invalid NativeID: could not extract resource group name from %s", request.NativeID)
	}

	nicName, ok := parts["networkinterfaces"]
	if !ok || nicName == "" {
		return nil, fmt.Errorf("invalid NativeID: could not extract network interface name from %s", request.NativeID)
	}

	// Start async deletion
	poller, err := nic.Client.InterfacesClient.BeginDelete(ctx, rgName, nicName, nil)
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
		}, fmt.Errorf("failed to start NetworkInterface deletion: %w", err)
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
			}, fmt.Errorf("failed to get NetworkInterface delete result: %w", err)
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

func (nic *NetworkInterface) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {

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
		return nic.statusCreateOrUpdate(ctx, request, &reqID)
	case "delete":
		return nic.statusDelete(ctx, request, &reqID)
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

func (nic *NetworkInterface) statusCreateOrUpdate(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	operation := resource.OperationCreate
	if reqID.OperationType == "update" {
		operation = resource.OperationUpdate
	}

	// Reconstruct the poller from the resume token
	poller, err := nic.Client.ResumeCreateNetworkInterfacePoller(reqID.ResumeToken)
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
		return nic.handleCreateOrUpdateComplete(ctx, request, reqID, poller, operation)
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

	// Check if done after polling
	if poller.Done() {
		return nic.handleCreateOrUpdateComplete(ctx, request, reqID, poller, operation)
	}

	// Still in progress
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       operation,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       request.RequestID,

			NativeID: reqID.NativeID,
		},
	}, nil
}

func (nic *NetworkInterface) handleCreateOrUpdateComplete(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID, poller *runtime.Poller[armnetwork.InterfacesClientCreateOrUpdateResponse], operation resource.Operation) (*resource.StatusResult, error) {
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

	propsJSON, err := serializeNetworkInterfaceProperties(result.Interface, rgName, *result.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize NetworkInterface properties: %w", err)
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

func (nic *NetworkInterface) statusDelete(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	// Reconstruct the poller from the resume token
	poller, err := nic.Client.ResumeDeleteNetworkInterfacePoller(reqID.ResumeToken)
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

	// Check if done after polling
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

	// Still in progress
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationDelete,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       request.RequestID,

			NativeID: reqID.NativeID,
		},
	}, nil
}

func (nic *NetworkInterface) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	// Get resourceGroupName from AdditionalProperties
	resourceGroupName, ok := request.AdditionalProperties["resourceGroupName"]
	if !ok || resourceGroupName == "" {
		return nil, fmt.Errorf("resourceGroupName is required in AdditionalProperties for listing NetworkInterfaces")
	}

	pager := nic.Client.InterfacesClient.NewListPager(resourceGroupName, nil)

	var nativeIDs []string

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list NetworkInterfaces in resource group %s: %w", resourceGroupName, err)
		}

		for _, iface := range page.Value {
			if iface.ID == nil {
				continue
			}

			nativeIDs = append(nativeIDs, *iface.ID)
		}
	}

	return &resource.ListResult{

		NativeIDs: nativeIDs,
	}, nil
}
