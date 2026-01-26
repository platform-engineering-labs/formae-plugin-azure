// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v4"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
)

const ResourceTypeSubnet = "Azure::Network::Subnet"

func init() {
	registry.Register(ResourceTypeSubnet, func(client *client.Client, cfg *config.Config) prov.Provisioner {
		return &Subnet{client, cfg}
	})
}

// Subnet is the provisioner for Azure Subnets.
type Subnet struct {
	Client *client.Client
	Config *config.Config
}

// buildPropertiesFromResult extracts properties from a Subnet Azure response.
// This is used by Create, Update, and Status to ensure consistent property format.
func (s *Subnet) buildPropertiesFromResult(subnet *armnetwork.Subnet, rgName, vnetName string) map[string]interface{} {
	// Include ALL properties (writable + createOnly + read-only) - the framework
	// will split them based on the schema in updateResourceProperties()
	props := make(map[string]interface{})

	// createOnly properties
	props["resourceGroupName"] = rgName
	props["virtualNetworkName"] = vnetName

	if subnet.Name != nil {
		props["name"] = *subnet.Name
	}

	// Writable properties
	if subnet.Properties != nil && subnet.Properties.AddressPrefix != nil {
		props["addressPrefix"] = *subnet.Properties.AddressPrefix
	}

	// Read-only properties
	if subnet.ID != nil {
		props["id"] = *subnet.ID
	}
	if subnet.Type != nil {
		props["type"] = *subnet.Type
	}
	if subnet.Etag != nil {
		props["etag"] = *subnet.Etag
	}
	if subnet.Properties != nil {
		if subnet.Properties.ProvisioningState != nil {
			props["provisioningState"] = string(*subnet.Properties.ProvisioningState)
		}
		if subnet.Properties.Purpose != nil {
			props["purpose"] = *subnet.Properties.Purpose
		}
	}

	return props
}

// serializeSubnetProperties converts an Azure Subnet to Formae property format
func serializeSubnetProperties(result armnetwork.Subnet, rgName, vnetName, subnetName string) (json.RawMessage, error) {
	props := make(map[string]interface{})
	props["resourceGroupName"] = rgName
	props["virtualNetworkName"] = vnetName

	if result.Name != nil {
		props["name"] = *result.Name
	} else {
		props["name"] = subnetName
	}

	if result.Properties != nil && result.Properties.AddressPrefix != nil {
		props["addressPrefix"] = *result.Properties.AddressPrefix
	}

	// Include id for resolvable references
	if result.ID != nil {
		props["id"] = *result.ID
	}

	// Marshal properties to JSON
	return json.Marshal(props)
}

func (s *Subnet) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
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

	// Extract virtualNetworkName (required)
	vnetName, ok := props["virtualNetworkName"].(string)
	if !ok || vnetName == "" {
		return nil, fmt.Errorf("virtualNetworkName is required")
	}

	// Extract subnet name from properties, fall back to label
	subnetName, ok := props["name"].(string)
	if !ok || subnetName == "" {
		subnetName = request.Label
	}

	// Extract addressPrefix (required)
	addressPrefix, ok := props["addressPrefix"].(string)
	if !ok || addressPrefix == "" {
		return nil, fmt.Errorf("addressPrefix is required")
	}

	// Build Subnet parameters (no location or tags for subnets)
	params := armnetwork.Subnet{
		Properties: &armnetwork.SubnetPropertiesFormat{
			AddressPrefix: stringPtr(addressPrefix),
		},
	}

	// Call Azure API to create Subnet (async/LRO operation)
	poller, err := s.Client.SubnetsClient.BeginCreateOrUpdate(
		ctx,
		rgName,
		vnetName,
		subnetName,
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
		}, fmt.Errorf("failed to start Subnet creation: %w", err)
	}

	// Build expected NativeID (we know the format)
	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/virtualNetworks/%s/subnets/%s",
		s.Config.SubscriptionId, rgName, vnetName, subnetName)

	// Check if the operation completed synchronously (already Done)
	if poller.Done() {
		result, err := poller.Result(ctx)
		if err != nil {
			return &resource.CreateResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationCreate,
					OperationStatus: resource.OperationStatusFailure,

					ErrorCode: mapAzureErrorToOperationErrorCode(err),
				},
			}, fmt.Errorf("failed to get Subnet create result: %w", err)
		}

		// Serialize properties using shared serialization logic
		propsJSON, err := serializeSubnetProperties(result.Subnet, rgName, vnetName, subnetName)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize Subnet properties: %w", err)
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

func (s *Subnet) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	// Parse NativeID to extract resourceGroupName, vnetName, and subnetName
	// Format: /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Network/virtualNetworks/{vnet}/subnets/{subnet}
	parts := splitResourceID(request.NativeID)

	rgName, ok := parts["resourcegroups"]
	if !ok || rgName == "" {
		return nil, fmt.Errorf("invalid NativeID: could not extract resource group name from %s", request.NativeID)
	}

	vnetName, ok := parts["virtualnetworks"]
	if !ok || vnetName == "" {
		return nil, fmt.Errorf("invalid NativeID: could not extract VNet name from %s", request.NativeID)
	}

	subnetName, ok := parts["subnets"]
	if !ok || subnetName == "" {
		return nil, fmt.Errorf("invalid NativeID: could not extract subnet name from %s", request.NativeID)
	}

	// Get Subnet from Azure
	result, err := s.Client.SubnetsClient.Get(ctx, rgName, vnetName, subnetName, nil)
	if err != nil {
		return &resource.ReadResult{

			ErrorCode: mapAzureErrorToOperationErrorCode(err),
		}, fmt.Errorf("failed to read Subnet: %w", err)
	}

	// Serialize properties using shared serialization logic
	propsJSON, err := serializeSubnetProperties(result.Subnet, rgName, vnetName, subnetName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize Subnet properties: %w", err)
	}

	return &resource.ReadResult{

		Properties: string(propsJSON),
	}, nil
}

func (s *Subnet) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	// Parse NativeID to extract resourceGroupName, vnetName, and subnetName
	parts := splitResourceID(request.NativeID)

	rgName, ok := parts["resourcegroups"]
	if !ok || rgName == "" {
		return nil, fmt.Errorf("invalid NativeID: could not extract resource group name from %s", request.NativeID)
	}

	vnetName, ok := parts["virtualnetworks"]
	if !ok || vnetName == "" {
		return nil, fmt.Errorf("invalid NativeID: could not extract VNet name from %s", request.NativeID)
	}

	subnetName, ok := parts["subnets"]
	if !ok || subnetName == "" {
		return nil, fmt.Errorf("invalid NativeID: could not extract subnet name from %s", request.NativeID)
	}

	// Parse properties JSON
	var props map[string]interface{}
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	// Extract addressPrefix (required)
	addressPrefix, ok := props["addressPrefix"].(string)
	if !ok || addressPrefix == "" {
		return nil, fmt.Errorf("addressPrefix is required")
	}

	// Build Subnet parameters (no location or tags for subnets)
	params := armnetwork.Subnet{
		Properties: &armnetwork.SubnetPropertiesFormat{
			AddressPrefix: stringPtr(addressPrefix),
		},
	}

	// Call Azure API to update Subnet (CreateOrUpdate is idempotent)
	poller, err := s.Client.SubnetsClient.BeginCreateOrUpdate(
		ctx,
		rgName,
		vnetName,
		subnetName,
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
		}, fmt.Errorf("failed to start Subnet update: %w", err)
	}

	// Check if the operation completed synchronously (already Done)
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
			}, fmt.Errorf("failed to get Subnet update result: %w", err)
		}

		// Serialize properties using shared serialization logic
		propsJSON, err := serializeSubnetProperties(result.Subnet, rgName, vnetName, subnetName)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize Subnet properties: %w", err)
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

func (s *Subnet) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	// Parse NativeID to extract resourceGroupName, vnetName, and subnetName
	parts := splitResourceID(request.NativeID)

	rgName, ok := parts["resourcegroups"]
	if !ok || rgName == "" {
		return nil, fmt.Errorf("invalid NativeID: could not extract resource group name from %s", request.NativeID)
	}

	vnetName, ok := parts["virtualnetworks"]
	if !ok || vnetName == "" {
		return nil, fmt.Errorf("invalid NativeID: could not extract VNet name from %s", request.NativeID)
	}

	subnetName, ok := parts["subnets"]
	if !ok || subnetName == "" {
		return nil, fmt.Errorf("invalid NativeID: could not extract subnet name from %s", request.NativeID)
	}

	// Start async deletion
	poller, err := s.Client.SubnetsClient.BeginDelete(ctx, rgName, vnetName, subnetName, nil)
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
		}, fmt.Errorf("failed to start Subnet deletion: %w", err)
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

func (s *Subnet) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
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
		return s.statusCreateOrUpdate(ctx, request, &reqID)
	case "delete":
		return s.statusDelete(ctx, request, &reqID)
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

func (s *Subnet) statusCreateOrUpdate(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	operation := resource.OperationCreate
	if reqID.OperationType == "update" {
		operation = resource.OperationUpdate
	}

	// Extract rgName and vnetName from NativeID for buildPropertiesFromResult
	parts := splitResourceID(reqID.NativeID)
	rgName := parts["resourcegroups"]
	vnetName := parts["virtualnetworks"]

	// Reconstruct the poller from the resume token
	poller, err := s.Client.ResumeCreateSubnetPoller(reqID.ResumeToken)
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
		return s.handleCreateOrUpdateComplete(ctx, request, reqID, poller, operation, rgName, vnetName)
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
		return s.handleCreateOrUpdateComplete(ctx, request, reqID, poller, operation, rgName, vnetName)
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

func (s *Subnet) handleCreateOrUpdateComplete(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID, poller interface {
	Result(context.Context) (armnetwork.SubnetsClientCreateOrUpdateResponse, error)
}, operation resource.Operation, rgName, vnetName string) (*resource.StatusResult, error) {
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
	responseProps := s.buildPropertiesFromResult(&result.Subnet, rgName, vnetName)
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

func (s *Subnet) statusDelete(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	// Reconstruct the poller from the resume token
	poller, err := s.Client.ResumeDeleteSubnetPoller(reqID.ResumeToken)
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

func (s *Subnet) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	// Get resourceGroupName and virtualNetworkName from AdditionalProperties
	// (populated by discovery actor via listParam from parent VirtualNetwork)
	resourceGroupName, ok := request.AdditionalProperties["resourceGroupName"]
	if !ok || resourceGroupName == "" {
		return nil, fmt.Errorf("resourceGroupName is required in AdditionalProperties for listing Subnets")
	}

	virtualNetworkName, ok := request.AdditionalProperties["virtualNetworkName"]
	if !ok || virtualNetworkName == "" {
		return nil, fmt.Errorf("virtualNetworkName is required in AdditionalProperties for listing Subnets")
	}

	pager := s.Client.SubnetsClient.NewListPager(resourceGroupName, virtualNetworkName, nil)

	var nativeIDs []string

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list subnets in vnet %s/%s: %w", resourceGroupName, virtualNetworkName, err)
		}

		for _, subnet := range page.Value {
			if subnet.ID == nil {
				continue
			}

			// Build properties map (same structure as Read)
			props := make(map[string]interface{})

			if subnet.Name != nil {
				props["name"] = *subnet.Name
			}

			props["resourceGroupName"] = resourceGroupName
			props["virtualNetworkName"] = virtualNetworkName

			nativeIDs = append(nativeIDs, *subnet.ID)
		}
	}

	return &resource.ListResult{

		NativeIDs: nativeIDs,
	}, nil
}
