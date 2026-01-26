// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v4"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
)

const ResourceTypeVirtualNetwork = "Azure::Network::VirtualNetwork"

func init() {
	registry.Register(ResourceTypeVirtualNetwork, func(client *client.Client, cfg *config.Config) prov.Provisioner {
		return &VirtualNetwork{client, cfg}
	})
}

// lroRequestID stores the operation type and resume token for LRO operations
type lroRequestID struct {
	OperationType string `json:"operationType"`
	ResumeToken   string `json:"resumeToken"`
	NativeID      string `json:"nativeID,omitempty"`
}

// VirtualNetwork is the provisioner for Azure Virtual Networks.
type VirtualNetwork struct {
	Client *client.Client
	Config *config.Config
}

// buildPropertiesFromResult extracts properties from a VirtualNetwork Azure response.
// This is used by Create, Update, and Status to ensure consistent property format.
func (v *VirtualNetwork) buildPropertiesFromResult(vnet *armnetwork.VirtualNetwork) map[string]interface{} {
	// Include ALL properties (writable + createOnly + read-only) - the framework
	// will split them based on the schema in updateResourceProperties()
	props := make(map[string]interface{})

	// createOnly properties
	if vnet.ID != nil {
		parts := splitResourceID(*vnet.ID)
		props["resourceGroupName"] = parts["resourcegroups"]
	}

	if vnet.Name != nil {
		props["name"] = *vnet.Name
	}

	if vnet.Location != nil {
		props["location"] = *vnet.Location
	}

	// Writable properties
	if vnet.Properties != nil && vnet.Properties.AddressSpace != nil {
		prefixes := make([]string, 0)
		for _, p := range vnet.Properties.AddressSpace.AddressPrefixes {
			if p != nil {
				prefixes = append(prefixes, *p)
			}
		}
		props["addressSpace"] = map[string]interface{}{
			"addressPrefixes": prefixes,
		}
	}

	if tags := azureTagsToFormaeTags(vnet.Tags); tags != nil {
		props["Tags"] = tags
	}

	// Read-only properties
	if vnet.ID != nil {
		props["id"] = *vnet.ID
	}
	if vnet.Type != nil {
		props["type"] = *vnet.Type
	}
	if vnet.Etag != nil {
		props["etag"] = *vnet.Etag
	}
	if vnet.Properties != nil {
		if vnet.Properties.ProvisioningState != nil {
			props["provisioningState"] = *vnet.Properties.ProvisioningState
		}
		if vnet.Properties.ResourceGUID != nil {
			props["resourceGuid"] = *vnet.Properties.ResourceGUID
		}
	}

	return props
}

// serializeVirtualNetworkProperties converts an Azure VirtualNetwork to Formae property format
func serializeVirtualNetworkProperties(result armnetwork.VirtualNetwork, rgName, vnetName string) (json.RawMessage, error) {
	props := make(map[string]interface{})

	props["resourceGroupName"] = rgName
	if result.Name != nil {
		props["name"] = *result.Name
	} else {
		props["name"] = vnetName
	}

	if result.Location != nil {
		props["location"] = *result.Location
	}

	// Add addressSpace
	if result.Properties != nil && result.Properties.AddressSpace != nil {
		prefixes := make([]string, 0)
		for _, p := range result.Properties.AddressSpace.AddressPrefixes {
			if p != nil {
				prefixes = append(prefixes, *p)
			}
		}
		props["addressSpace"] = map[string]interface{}{
			"addressPrefixes": prefixes,
		}
	}

	// Add tags
	if tags := azureTagsToFormaeTags(result.Tags); tags != nil {
		props["Tags"] = tags
	}

	// Marshal properties to JSON
	return json.Marshal(props)
}

func (v *VirtualNetwork) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {

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

	// Extract VNet name from properties, fall back to label
	vnetName, ok := props["name"].(string)
	if !ok || vnetName == "" {
		vnetName = request.Label
	}

	// Extract addressSpace (required)
	addressSpace, ok := props["addressSpace"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("addressSpace is required")
	}
	addressPrefixesRaw, ok := addressSpace["addressPrefixes"].([]interface{})
	if !ok || len(addressPrefixesRaw) == 0 {
		return nil, fmt.Errorf("addressSpace.addressPrefixes is required")
	}
	addressPrefixes := make([]*string, len(addressPrefixesRaw))
	for i, p := range addressPrefixesRaw {
		prefix, ok := p.(string)
		if !ok {
			return nil, fmt.Errorf("addressSpace.addressPrefixes[%d] must be a string", i)
		}
		addressPrefixes[i] = stringPtr(prefix)
	}

	// Build VirtualNetwork parameters
	params := armnetwork.VirtualNetwork{
		Location: stringPtr(location),
		Properties: &armnetwork.VirtualNetworkPropertiesFormat{
			AddressSpace: &armnetwork.AddressSpace{
				AddressPrefixes: addressPrefixes,
			},
		},
	}

	// Add tags if present
	if azureTags := formaeTagsToAzureTags(request.Properties); azureTags != nil {
		params.Tags = azureTags
	}

	// Call Azure API to create VNet (async/LRO operation)
	poller, err := v.Client.VirtualNetworksClient.BeginCreateOrUpdate(
		ctx,
		rgName,
		vnetName,
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
		}, fmt.Errorf("failed to start VNet creation: %w", err)
	}

	// Build expected NativeID (we know the format)
	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/virtualNetworks/%s",
		v.Config.SubscriptionId, rgName, vnetName)

	// Check if the operation completed synchronously (already Done)
	// In this case, ResumeToken() fails because there's nothing to resume
	if poller.Done() {
		result, err := poller.Result(ctx)
		if err != nil {
			return &resource.CreateResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationCreate,
					OperationStatus: resource.OperationStatusFailure,

					ErrorCode: mapAzureErrorToOperationErrorCode(err),
				},
			}, fmt.Errorf("failed to get VNet create result: %w", err)
		}

		// Serialize properties using shared serialization logic
		propsJSON, err := serializeVirtualNetworkProperties(result.VirtualNetwork, rgName, vnetName)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize VNet properties: %w", err)
		}

		// Return CreateResult with properties for synchronous completion
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

	// Return InProgress - caller should poll Status
	return &resource.CreateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationCreate,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       string(reqIDJSON),
			NativeID:        expectedNativeID,
		},
	}, nil
}

func (v *VirtualNetwork) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	// Parse NativeID to extract resourceGroupName and vnetName
	// Format: /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Network/virtualNetworks/{vnet}
	parts := splitResourceID(request.NativeID)

	rgName, ok := parts["resourcegroups"]
	if !ok || rgName == "" {
		return nil, fmt.Errorf("invalid NativeID: could not extract resource group name from %s", request.NativeID)
	}

	vnetName, ok := parts["virtualnetworks"]
	if !ok || vnetName == "" {
		return nil, fmt.Errorf("invalid NativeID: could not extract VNet name from %s", request.NativeID)
	}

	// Get VNet from Azure
	result, err := v.Client.VirtualNetworksClient.Get(ctx, rgName, vnetName, nil)
	if err != nil {
		return &resource.ReadResult{

			ErrorCode: mapAzureErrorToOperationErrorCode(err),
		}, fmt.Errorf("failed to read VNet: %w", err)
	}

	// Serialize properties using shared serialization logic
	propsJSON, err := serializeVirtualNetworkProperties(result.VirtualNetwork, rgName, vnetName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize VNet properties: %w", err)
	}

	return &resource.ReadResult{

		Properties: string(propsJSON),
	}, nil
}

func (v *VirtualNetwork) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	// Parse NativeID to extract resourceGroupName and vnetName
	parts := splitResourceID(request.NativeID)

	rgName, ok := parts["resourcegroups"]
	if !ok || rgName == "" {
		return nil, fmt.Errorf("invalid NativeID: could not extract resource group name from %s", request.NativeID)
	}

	vnetName, ok := parts["virtualnetworks"]
	if !ok || vnetName == "" {
		return nil, fmt.Errorf("invalid NativeID: could not extract VNet name from %s", request.NativeID)
	}

	// First, read the existing VNet to preserve subnets
	// Azure's PUT API treats missing subnets as "delete all", so we must include existing ones
	existingVNet, err := v.Client.VirtualNetworksClient.Get(ctx, rgName, vnetName, nil)
	if err != nil {
		return &resource.UpdateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationUpdate,
				OperationStatus: resource.OperationStatusFailure,
				NativeID:        request.NativeID,
				ErrorCode:       mapAzureErrorToOperationErrorCode(err),
			},
		}, fmt.Errorf("failed to read existing VNet before update: %w", err)
	}

	// Parse properties JSON
	var props map[string]interface{}
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	// Extract location (required for Azure API)
	location, ok := props["location"].(string)
	if !ok || location == "" {
		return nil, fmt.Errorf("location is required")
	}

	// Extract addressSpace (required)
	addressSpace, ok := props["addressSpace"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("addressSpace is required")
	}
	addressPrefixesRaw, ok := addressSpace["addressPrefixes"].([]interface{})
	if !ok || len(addressPrefixesRaw) == 0 {
		return nil, fmt.Errorf("addressSpace.addressPrefixes is required")
	}
	addressPrefixes := make([]*string, len(addressPrefixesRaw))
	for i, p := range addressPrefixesRaw {
		prefix, ok := p.(string)
		if !ok {
			return nil, fmt.Errorf("addressSpace.addressPrefixes[%d] must be a string", i)
		}
		addressPrefixes[i] = stringPtr(prefix)
	}

	// Build VirtualNetwork parameters
	params := armnetwork.VirtualNetwork{
		Location: stringPtr(location),
		Properties: &armnetwork.VirtualNetworkPropertiesFormat{
			AddressSpace: &armnetwork.AddressSpace{
				AddressPrefixes: addressPrefixes,
			},
		},
	}

	// Preserve existing subnets: Azure's PUT replaces the entire VNet definition,
	// so omitting subnets means "delete all". Since subnets are managed separately
	// via the Subnet resource type, we must carry them forward to avoid accidental deletion.
	if existingVNet.Properties != nil && existingVNet.Properties.Subnets != nil {
		params.Properties.Subnets = existingVNet.Properties.Subnets
	}

	// Add tags if present
	if azureTags := formaeTagsToAzureTags(request.DesiredProperties); azureTags != nil {
		params.Tags = azureTags
	}

	// Call Azure API to update VNet (CreateOrUpdate is idempotent)
	poller, err := v.Client.VirtualNetworksClient.BeginCreateOrUpdate(
		ctx,
		rgName,
		vnetName,
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
		}, fmt.Errorf("failed to start VNet update: %w", err)
	}

	// Check if the operation completed synchronously (already Done)
	// In this case, ResumeToken() fails because there's nothing to resume
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
			}, fmt.Errorf("failed to get VNet update result: %w", err)
		}

		// Serialize properties using shared serialization logic
		propsJSON, err := serializeVirtualNetworkProperties(result.VirtualNetwork, rgName, vnetName)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize VNet properties: %w", err)
		}

		// Return UpdateResult with properties for synchronous completion
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

	// Encode operation type + resume token as RequestID
	reqID := lroRequestID{
		OperationType: "update",
		ResumeToken:   resumeToken,
		NativeID:      request.NativeID,
	}
	reqIDJSON, err := json.Marshal(reqID)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request ID: %w", err)
	}

	// Return InProgress - caller should poll Status
	return &resource.UpdateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationUpdate,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       string(reqIDJSON),
			NativeID:        request.NativeID,
		},
	}, nil
}

func (v *VirtualNetwork) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	// Parse NativeID to extract resourceGroupName and vnetName
	parts := splitResourceID(request.NativeID)

	rgName, ok := parts["resourcegroups"]
	if !ok || rgName == "" {
		return nil, fmt.Errorf("invalid NativeID: could not extract resource group name from %s", request.NativeID)
	}

	vnetName, ok := parts["virtualnetworks"]
	if !ok || vnetName == "" {
		return nil, fmt.Errorf("invalid NativeID: could not extract VNet name from %s", request.NativeID)
	}

	// Start async deletion
	poller, err := v.Client.VirtualNetworksClient.BeginDelete(ctx, rgName, vnetName, nil)
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
		}, fmt.Errorf("failed to start VNet deletion: %w", err)
	}

	// Get the ResumeToken for tracking the operation
	resumeToken, err := poller.ResumeToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get resume token: %w", err)
	}

	// Encode operation type + resume token as RequestID
	reqID := lroRequestID{
		OperationType: "delete",
		ResumeToken:   resumeToken,
		NativeID:      request.NativeID,
	}
	reqIDJSON, err := json.Marshal(reqID)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request ID: %w", err)
	}

	// Return InProgress - caller should poll Status
	return &resource.DeleteResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationDelete,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       string(reqIDJSON),
			NativeID:        request.NativeID,
		},
	}, nil
}

func (v *VirtualNetwork) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {

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
		return v.statusCreateOrUpdate(ctx, request, &reqID)
	case "delete":
		return v.statusDelete(ctx, request, &reqID)
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

func (v *VirtualNetwork) statusCreateOrUpdate(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	operation := resource.OperationCreate
	if reqID.OperationType == "update" {
		operation = resource.OperationUpdate
	}

	// Reconstruct the poller from the resume token
	poller, err := v.Client.ResumeCreateVirtualNetworkPoller(reqID.ResumeToken)
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
		return v.handleCreateOrUpdateComplete(ctx, request, reqID, poller, operation)
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
		return v.handleCreateOrUpdateComplete(ctx, request, reqID, poller, operation)
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

func (v *VirtualNetwork) handleCreateOrUpdateComplete(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID, poller *runtime.Poller[armnetwork.VirtualNetworksClientCreateOrUpdateResponse], operation resource.Operation) (*resource.StatusResult, error) {
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

	// Build properties using the helper function for consistency
	responseProps := v.buildPropertiesFromResult(&result.VirtualNetwork)
	propsJSON, err := json.Marshal(responseProps)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
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

func (v *VirtualNetwork) statusDelete(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	// Reconstruct the poller from the resume token
	poller, err := v.Client.ResumeDeleteVirtualNetworkPoller(reqID.ResumeToken)
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
			NativeID:        reqID.NativeID,
		},
	}, nil
}

func (v *VirtualNetwork) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	// Get resourceGroupName from AdditionalProperties (populated by discovery actor via listParam)
	resourceGroupName, ok := request.AdditionalProperties["resourceGroupName"]
	if !ok || resourceGroupName == "" {
		return nil, fmt.Errorf("resourceGroupName is required in AdditionalProperties for listing VirtualNetworks")
	}

	pager := v.Client.VirtualNetworksClient.NewListPager(resourceGroupName, nil)

	var nativeIDs []string

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list virtual networks in resource group %s: %w", resourceGroupName, err)
		}

		for _, vnet := range page.Value {
			if vnet.ID == nil {
				continue
			}

			// Build properties map (same structure as Read)
			props := make(map[string]interface{})

			// Use vnet.Name from Azure response for consistency with Read and Status
			if vnet.Name != nil {
				props["name"] = *vnet.Name
			}

			if vnet.Location != nil {
				props["location"] = *vnet.Location
			}

			props["resourceGroupName"] = resourceGroupName

			// Address space
			if vnet.Properties != nil && vnet.Properties.AddressSpace != nil {
				addressSpace := make(map[string]interface{})
				var prefixes []string
				for _, prefix := range vnet.Properties.AddressSpace.AddressPrefixes {
					if prefix != nil {
						prefixes = append(prefixes, *prefix)
					}
				}
				addressSpace["addressPrefixes"] = prefixes
				props["addressSpace"] = addressSpace
			}

			nativeIDs = append(nativeIDs, *vnet.ID)
		}
	}

	return &resource.ListResult{
		NativeIDs: nativeIDs,
	}, nil
}
