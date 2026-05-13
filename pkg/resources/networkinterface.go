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

const ResourceTypeNetworkInterface = "AZURE::Network::NetworkInterface"

type networkInterfacesAPI interface {
	BeginCreateOrUpdate(ctx context.Context, resourceGroupName string, networkInterfaceName string, parameters armnetwork.Interface, options *armnetwork.InterfacesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.InterfacesClientCreateOrUpdateResponse], error)
	Get(ctx context.Context, resourceGroupName string, networkInterfaceName string, options *armnetwork.InterfacesClientGetOptions) (armnetwork.InterfacesClientGetResponse, error)
	BeginDelete(ctx context.Context, resourceGroupName string, networkInterfaceName string, options *armnetwork.InterfacesClientBeginDeleteOptions) (*runtime.Poller[armnetwork.InterfacesClientDeleteResponse], error)
	NewListPager(resourceGroupName string, options *armnetwork.InterfacesClientListOptions) *runtime.Pager[armnetwork.InterfacesClientListResponse]
}

func init() {
	registry.Register(ResourceTypeNetworkInterface, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &NetworkInterface{
			api:      c.InterfacesClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// NetworkInterface is the provisioner for Azure Network Interfaces.
type NetworkInterface struct {
	api      networkInterfacesAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

// serializeNetworkInterfaceProperties converts an Azure Interface to Formae property format
func serializeNetworkInterfaceProperties(result armnetwork.Interface, rgName, nicName string) (json.RawMessage, error) {
	props := make(map[string]any)

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
			ipConfigs := make([]map[string]any, 0, len(result.Properties.IPConfigurations))
			for _, ipConfig := range result.Properties.IPConfigurations {
				config := make(map[string]any)
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

func parseNetworkInterfaceNativeID(nativeID string) (rgName, nicName string, err error) {
	rgName, names, err := armIDParts(nativeID, "networkinterfaces")
	if err != nil {
		return "", "", err
	}
	return rgName, names["networkinterfaces"], nil
}

func (nic *NetworkInterface) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
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

	// Extract NIC name from properties, fall back to label
	nicName, ok := props["name"].(string)
	if !ok || nicName == "" {
		nicName = request.Label
	}

	// Extract IP configurations (required)
	ipConfigsRaw, ok := props["ipConfigurations"].([]any)
	if !ok || len(ipConfigsRaw) == 0 {
		return nil, fmt.Errorf("ipConfigurations is required")
	}

	ipConfigs := make([]*armnetwork.InterfaceIPConfiguration, 0, len(ipConfigsRaw))
	for i, ipConfigRaw := range ipConfigsRaw {
		ipConfigMap, ok := ipConfigRaw.(map[string]any)
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
	poller, err := nic.api.BeginCreateOrUpdate(
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

				ErrorCode: operationErrorCode(err),
			},
		}, nil
	}

	// Build expected NativeID
	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/networkInterfaces/%s",
		nic.config.SubscriptionId, rgName, nicName)

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

func (nic *NetworkInterface) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, nicName, err := parseNetworkInterfaceNativeID(request.NativeID)
	if err != nil {
		return nil, err
	}

	// Get NetworkInterface from Azure
	result, err := nic.api.Get(ctx, rgName, nicName, nil)
	if err != nil {
		return &resource.ReadResult{

			ErrorCode: operationErrorCode(err),
		}, nil
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
	rgName, nicName, err := parseNetworkInterfaceNativeID(request.NativeID)
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

	// Extract IP configurations (required)
	ipConfigsRaw, ok := props["ipConfigurations"].([]any)
	if !ok || len(ipConfigsRaw) == 0 {
		return nil, fmt.Errorf("ipConfigurations is required")
	}

	ipConfigs := make([]*armnetwork.InterfaceIPConfiguration, 0, len(ipConfigsRaw))
	for i, ipConfigRaw := range ipConfigsRaw {
		ipConfigMap, ok := ipConfigRaw.(map[string]any)
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
	poller, err := nic.api.BeginCreateOrUpdate(
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

func (nic *NetworkInterface) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, nicName, err := parseNetworkInterfaceNativeID(request.NativeID)
	if err != nil {
		return nil, err
	}

	// Start async deletion
	poller, err := nic.api.BeginDelete(ctx, rgName, nicName, nil)
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

					ErrorCode: operationErrorCode(err),
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

	reqIDJSON, err := encodeLROStart(lroOpDelete, resumeToken, request.NativeID)
	if err != nil {
		return nil, err
	}

	return &resource.DeleteResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationDelete,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       reqIDJSON,
			NativeID:        request.NativeID,
		},
	}, nil
}

func (nic *NetworkInterface) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	reqID, err := decodeLROStatus(request.RequestID)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,

				ErrorCode: resource.OperationErrorCodeGeneralServiceException,
			},
		}, err
	}

	switch reqID.OperationType {
	case lroOpCreate, lroOpUpdate:
		return nic.statusCreateOrUpdate(ctx, request, &reqID)
	case lroOpDelete:
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
	if reqID.OperationType == lroOpUpdate {
		operation = resource.OperationUpdate
	}

	return statusLRO(ctx, request, reqID, operation,
		func(token string) (*runtime.Poller[armnetwork.InterfacesClientCreateOrUpdateResponse], error) {
			return resumePoller[armnetwork.InterfacesClientCreateOrUpdateResponse](nic.pipeline, token)
		},
		func(_ context.Context, result armnetwork.InterfacesClientCreateOrUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
			rgName, nicName, err := parseNetworkInterfaceNativeID(*result.ID)
			if err != nil {
				return "", nil, err
			}
			propsJSON, err := serializeNetworkInterfaceProperties(result.Interface, rgName, nicName)
			if err != nil {
				return "", nil, fmt.Errorf("failed to serialize NetworkInterface properties: %w", err)
			}
			return *result.ID, propsJSON, nil
		})
}

func (nic *NetworkInterface) statusDelete(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	return statusDeleteLRO(ctx, request, reqID,
		func(token string) (*runtime.Poller[armnetwork.InterfacesClientDeleteResponse], error) {
			return resumePoller[armnetwork.InterfacesClientDeleteResponse](nic.pipeline, token)
		}, nil)
}

func (nic *NetworkInterface) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	// Get resourceGroupName from AdditionalProperties
	resourceGroupName, ok := request.AdditionalProperties["resourceGroupName"]
	if !ok || resourceGroupName == "" {
		return nil, fmt.Errorf("resourceGroupName is required in AdditionalProperties for listing NetworkInterfaces")
	}

	pager := nic.api.NewListPager(resourceGroupName, nil)

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
