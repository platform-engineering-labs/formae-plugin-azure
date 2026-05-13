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
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeSubnet = "AZURE::Network::Subnet"

type subnetsAPI interface {
	BeginCreateOrUpdate(ctx context.Context, resourceGroupName string, virtualNetworkName string, subnetName string, subnetParameters armnetwork.Subnet, options *armnetwork.SubnetsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.SubnetsClientCreateOrUpdateResponse], error)
	Get(ctx context.Context, resourceGroupName string, virtualNetworkName string, subnetName string, options *armnetwork.SubnetsClientGetOptions) (armnetwork.SubnetsClientGetResponse, error)
	BeginDelete(ctx context.Context, resourceGroupName string, virtualNetworkName string, subnetName string, options *armnetwork.SubnetsClientBeginDeleteOptions) (*runtime.Poller[armnetwork.SubnetsClientDeleteResponse], error)
	NewListPager(resourceGroupName string, virtualNetworkName string, options *armnetwork.SubnetsClientListOptions) *runtime.Pager[armnetwork.SubnetsClientListResponse]
	NewListAllVNetsPager(options *armnetwork.VirtualNetworksClientListAllOptions) *runtime.Pager[armnetwork.VirtualNetworksClientListAllResponse]
}

// subnetsWrapper composes the Subnets SDK client with cross-resource VNet
// discovery (Subnets need to enumerate VNets to list across the subscription).
type subnetsWrapper struct {
	*armnetwork.SubnetsClient
	vnetsClient *armnetwork.VirtualNetworksClient
}

func (w *subnetsWrapper) NewListAllVNetsPager(options *armnetwork.VirtualNetworksClientListAllOptions) *runtime.Pager[armnetwork.VirtualNetworksClientListAllResponse] {
	return w.vnetsClient.NewListAllPager(options)
}

func init() {
	registry.Register(ResourceTypeSubnet, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &Subnet{
			api: &subnetsWrapper{
				SubnetsClient: c.SubnetsClient,
				vnetsClient:   c.VirtualNetworksClient,
			},
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// Subnet is the provisioner for Azure Subnets.
type Subnet struct {
	api      subnetsAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

// buildPropertiesFromResult extracts properties from a Subnet Azure response.
// This is used by Create, Update, and Status to ensure consistent property format.
func (s *Subnet) buildPropertiesFromResult(subnet *armnetwork.Subnet, rgName, vnetName string) map[string]any {
	// Include ALL properties (writable + createOnly + read-only) - the framework
	// will split them based on the schema in updateResourceProperties()
	props := make(map[string]any)

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
	props := make(map[string]any)
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

func parseSubnetNativeID(nativeID string) (rgName, vnetName, subnetName string, err error) {
	rgName, names, err := armIDParts(nativeID, "virtualnetworks", "subnets")
	if err != nil {
		return "", "", "", err
	}
	return rgName, names["virtualnetworks"], names["subnets"], nil
}

func (s *Subnet) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
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
	poller, err := s.api.BeginCreateOrUpdate(
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

				ErrorCode: operationErrorCode(err),
			},
		}, nil
	}

	// Build expected NativeID (we know the format)
	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/virtualNetworks/%s/subnets/%s",
		s.config.SubscriptionId, rgName, vnetName, subnetName)

	// Check if the operation completed synchronously (already Done)
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

	reqIDJSON, err := encodeLROStart(lroOpCreate, resumeToken, expectedNativeID)
	if err != nil {
		return nil, err
	}

	// Return InProgress - caller should poll Status
	return &resource.CreateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationCreate,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       reqIDJSON,
			NativeID:        expectedNativeID,
		},
	}, nil
}

func (s *Subnet) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, vnetName, subnetName, err := parseSubnetNativeID(request.NativeID)
	if err != nil {
		return nil, err
	}

	// Get Subnet from Azure
	result, err := s.api.Get(ctx, rgName, vnetName, subnetName, nil)
	if err != nil {
		return &resource.ReadResult{

			ErrorCode: operationErrorCode(err),
		}, nil
	}

	// Serialize properties using shared serialization logic
	propsJSON, err := serializeSubnetProperties(result.Subnet, rgName, vnetName, subnetName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize Subnet properties: %w", err)
	}

	return &resource.ReadResult{
		ResourceType: ResourceTypeSubnet,
		Properties:   string(propsJSON),
	}, nil
}

func (s *Subnet) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, vnetName, subnetName, err := parseSubnetNativeID(request.NativeID)
	if err != nil {
		return nil, err
	}

	// Parse properties JSON
	var props map[string]any
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
	poller, err := s.api.BeginCreateOrUpdate(
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

				ErrorCode: operationErrorCode(err),
			},
		}, nil
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

					ErrorCode: operationErrorCode(err),
				},
			}, nil
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

	reqIDJSON, err := encodeLROStart(lroOpUpdate, resumeToken, request.NativeID)
	if err != nil {
		return nil, err
	}

	// Return InProgress - caller should poll Status
	return &resource.UpdateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationUpdate,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       reqIDJSON,
			NativeID:        request.NativeID,
		},
	}, nil
}

func (s *Subnet) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, vnetName, subnetName, err := parseSubnetNativeID(request.NativeID)
	if err != nil {
		return nil, err
	}

	// Start async deletion
	poller, err := s.api.BeginDelete(ctx, rgName, vnetName, subnetName, nil)
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
		}, fmt.Errorf("failed to start Subnet deletion: %w", err)
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

	// Return InProgress - caller should poll Status
	return &resource.DeleteResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationDelete,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       reqIDJSON,
			NativeID:        request.NativeID,
		},
	}, nil
}

func (s *Subnet) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
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
		return s.statusCreateOrUpdate(ctx, request, &reqID)
	case lroOpDelete:
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
	if reqID.OperationType == lroOpUpdate {
		operation = resource.OperationUpdate
	}

	return statusLRO(ctx, request, reqID, operation,
		func(token string) (*runtime.Poller[armnetwork.SubnetsClientCreateOrUpdateResponse], error) {
			return resumePoller[armnetwork.SubnetsClientCreateOrUpdateResponse](s.pipeline, token)
		},
		func(_ context.Context, result armnetwork.SubnetsClientCreateOrUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
			rgName, vnetName, _, err := parseSubnetNativeID(*result.ID)
			if err != nil {
				return "", nil, err
			}
			responseProps := s.buildPropertiesFromResult(&result.Subnet, rgName, vnetName)
			propsJSON, err := json.Marshal(responseProps)
			if err != nil {
				return "", nil, fmt.Errorf("failed to marshal response properties: %w", err)
			}
			return *result.ID, propsJSON, nil
		})
}

func (s *Subnet) statusDelete(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	return statusDeleteLRO(ctx, request, reqID,
		func(token string) (*runtime.Poller[armnetwork.SubnetsClientDeleteResponse], error) {
			return resumePoller[armnetwork.SubnetsClientDeleteResponse](s.pipeline, token)
		}, nil)
}

func (s *Subnet) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	resourceGroupName := request.AdditionalProperties["resourceGroupName"]
	virtualNetworkName := request.AdditionalProperties["virtualNetworkName"]

	var nativeIDs []string

	if resourceGroupName != "" && virtualNetworkName != "" {
		ids, err := s.listByVNet(ctx, resourceGroupName, virtualNetworkName)
		if err != nil {
			return nil, err
		}
		nativeIDs = ids
	} else {
		// Discovery path: enumerate all VNets across the subscription
		vnetPager := s.api.NewListAllVNetsPager(nil)
		for vnetPager.More() {
			page, err := vnetPager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list virtual networks for subnet discovery: %w", err)
			}
			for _, vnet := range page.Value {
				if vnet.ID == nil {
					continue
				}
				rgName, vnetName, err := parseVirtualNetworkNativeID(*vnet.ID)
				if err != nil {
					continue
				}
				ids, err := s.listByVNet(ctx, rgName, vnetName)
				if err != nil {
					return nil, err
				}
				nativeIDs = append(nativeIDs, ids...)
			}
		}
	}

	return &resource.ListResult{
		NativeIDs: nativeIDs,
	}, nil
}

func (s *Subnet) listByVNet(ctx context.Context, resourceGroupName, virtualNetworkName string) ([]string, error) {
	pager := s.api.NewListPager(resourceGroupName, virtualNetworkName, nil)

	var nativeIDs []string

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list subnets in vnet %s/%s: %w", resourceGroupName, virtualNetworkName, err)
		}
		for _, subnet := range page.Value {
			if subnet.ID != nil {
				nativeIDs = append(nativeIDs, *subnet.ID)
			}
		}
	}

	return nativeIDs, nil
}
