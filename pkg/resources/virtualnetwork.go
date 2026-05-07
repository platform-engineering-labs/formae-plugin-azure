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

const ResourceTypeVirtualNetwork = "Azure::Network::VirtualNetwork"

type virtualNetworksAPI interface {
	BeginCreateOrUpdate(ctx context.Context, resourceGroupName string, virtualNetworkName string, parameters armnetwork.VirtualNetwork, options *armnetwork.VirtualNetworksClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.VirtualNetworksClientCreateOrUpdateResponse], error)
	Get(ctx context.Context, resourceGroupName string, virtualNetworkName string, options *armnetwork.VirtualNetworksClientGetOptions) (armnetwork.VirtualNetworksClientGetResponse, error)
	BeginDelete(ctx context.Context, resourceGroupName string, virtualNetworkName string, options *armnetwork.VirtualNetworksClientBeginDeleteOptions) (*runtime.Poller[armnetwork.VirtualNetworksClientDeleteResponse], error)
	NewListPager(resourceGroupName string, options *armnetwork.VirtualNetworksClientListOptions) *runtime.Pager[armnetwork.VirtualNetworksClientListResponse]
	NewListAllPager(options *armnetwork.VirtualNetworksClientListAllOptions) *runtime.Pager[armnetwork.VirtualNetworksClientListAllResponse]
}

func init() {
	registry.Register(ResourceTypeVirtualNetwork, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &VirtualNetwork{
			api:      c.VirtualNetworksClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// VirtualNetwork is the provisioner for Azure Virtual Networks.
type VirtualNetwork struct {
	api      virtualNetworksAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

// buildPropertiesFromResult extracts properties from a VirtualNetwork Azure response.
// This is used by Create, Update, and Status to ensure consistent property format.
func (v *VirtualNetwork) buildPropertiesFromResult(vnet *armnetwork.VirtualNetwork) map[string]any {
	// Include ALL properties (writable + createOnly + read-only) - the framework
	// will split them based on the schema in updateResourceProperties()
	props := make(map[string]any)

	// createOnly properties
	if vnet.ID != nil {
		if rgName, _, err := parseVirtualNetworkNativeID(*vnet.ID); err == nil {
			props["resourceGroupName"] = rgName
		}
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
		props["addressSpace"] = map[string]any{
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

func parseVirtualNetworkNativeID(nativeID string) (rgName, vnetName string, err error) {
	rgName, names, err := armIDParts(nativeID, "virtualnetworks")
	if err != nil {
		return "", "", err
	}
	return rgName, names["virtualnetworks"], nil
}

// serializeVirtualNetworkProperties converts an Azure VirtualNetwork to Formae property format
func serializeVirtualNetworkProperties(result armnetwork.VirtualNetwork, rgName, vnetName string) (json.RawMessage, error) {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	if result.Name != nil {
		props["name"] = *result.Name
	} else {
		props["name"] = vnetName
	}

	if result.Location != nil {
		props["location"] = *result.Location
	}

	// Include the ARM ID — required for cross-resource Resolvable refs
	// (e.g., a PrivateDnsZoneVirtualNetworkLink resolving `vnet.res.id`).
	// The resolve cache lazy-loads via Read, so omitting `id` here makes
	// any `vnet.res.id` reference fail with "Unable to resolve property".
	if result.ID != nil {
		props["id"] = *result.ID
	}

	// Add addressSpace
	if result.Properties != nil && result.Properties.AddressSpace != nil {
		prefixes := make([]string, 0)
		for _, p := range result.Properties.AddressSpace.AddressPrefixes {
			if p != nil {
				prefixes = append(prefixes, *p)
			}
		}
		props["addressSpace"] = map[string]any{
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

	// Extract VNet name from properties, fall back to label
	vnetName, ok := props["name"].(string)
	if !ok || vnetName == "" {
		vnetName = request.Label
	}

	// Extract addressSpace (required)
	addressSpace, ok := props["addressSpace"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("addressSpace is required")
	}
	addressPrefixesRaw, ok := addressSpace["addressPrefixes"].([]any)
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
	poller, err := v.api.BeginCreateOrUpdate(
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

				ErrorCode: operationErrorCode(err),
			},
		}, nil
	}

	// Build expected NativeID (we know the format)
	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/virtualNetworks/%s",
		v.config.SubscriptionId, rgName, vnetName)

	// Check if the operation completed synchronously (already Done)
	// In this case, ResumeToken() fails because there's nothing to resume
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

func (v *VirtualNetwork) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, vnetName, err := parseVirtualNetworkNativeID(request.NativeID)
	if err != nil {
		return nil, err
	}

	// Get VNet from Azure
	result, err := v.api.Get(ctx, rgName, vnetName, nil)
	if err != nil {
		return &resource.ReadResult{

			ErrorCode: operationErrorCode(err),
		}, nil
	}

	// Serialize properties using shared serialization logic
	propsJSON, err := serializeVirtualNetworkProperties(result.VirtualNetwork, rgName, vnetName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize VNet properties: %w", err)
	}

	return &resource.ReadResult{
		ResourceType: ResourceTypeVirtualNetwork,
		Properties:   string(propsJSON),
	}, nil
}

func (v *VirtualNetwork) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, vnetName, err := parseVirtualNetworkNativeID(request.NativeID)
	if err != nil {
		return nil, err
	}

	// First, read the existing VNet to preserve subnets
	// Azure's PUT API treats missing subnets as "delete all", so we must include existing ones
	existingVNet, err := v.api.Get(ctx, rgName, vnetName, nil)
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

	// Parse properties JSON
	var props map[string]any
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	// Extract location (required for Azure API)
	location, ok := props["location"].(string)
	if !ok || location == "" {
		return nil, fmt.Errorf("location is required")
	}

	// Extract addressSpace (required)
	addressSpace, ok := props["addressSpace"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("addressSpace is required")
	}
	addressPrefixesRaw, ok := addressSpace["addressPrefixes"].([]any)
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
	poller, err := v.api.BeginCreateOrUpdate(
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

				ErrorCode: operationErrorCode(err),
			},
		}, nil
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

					ErrorCode: operationErrorCode(err),
				},
			}, nil
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

func (v *VirtualNetwork) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, vnetName, err := parseVirtualNetworkNativeID(request.NativeID)
	if err != nil {
		return nil, err
	}

	// Start async deletion
	poller, err := v.api.BeginDelete(ctx, rgName, vnetName, nil)
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
		}, fmt.Errorf("failed to start VNet deletion: %w", err)
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

func (v *VirtualNetwork) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {

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
		return v.statusCreateOrUpdate(ctx, request, &reqID)
	case lroOpDelete:
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
	if reqID.OperationType == lroOpUpdate {
		operation = resource.OperationUpdate
	}

	return statusLRO(ctx, request, reqID, operation,
		func(token string) (*runtime.Poller[armnetwork.VirtualNetworksClientCreateOrUpdateResponse], error) {
			return resumePoller[armnetwork.VirtualNetworksClientCreateOrUpdateResponse](v.pipeline, token)
		},
		func(_ context.Context, result armnetwork.VirtualNetworksClientCreateOrUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
			responseProps := v.buildPropertiesFromResult(&result.VirtualNetwork)
			propsJSON, err := json.Marshal(responseProps)
			if err != nil {
				return "", nil, fmt.Errorf("failed to marshal response properties: %w", err)
			}
			return *result.ID, propsJSON, nil
		})
}

func (v *VirtualNetwork) statusDelete(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	return statusDeleteLRO(ctx, request, reqID,
		func(token string) (*runtime.Poller[armnetwork.VirtualNetworksClientDeleteResponse], error) {
			return resumePoller[armnetwork.VirtualNetworksClientDeleteResponse](v.pipeline, token)
		}, nil)
}

func (v *VirtualNetwork) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	resourceGroupName := request.AdditionalProperties["resourceGroupName"]

	var nativeIDs []string

	if resourceGroupName != "" {
		pager := v.api.NewListPager(resourceGroupName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list virtual networks: %w", err)
			}
			for _, vnet := range page.Value {
				if vnet.ID != nil {
					nativeIDs = append(nativeIDs, *vnet.ID)
				}
			}
		}
	} else {
		pager := v.api.NewListAllPager(nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list virtual networks: %w", err)
			}
			for _, vnet := range page.Value {
				if vnet.ID != nil {
					nativeIDs = append(nativeIDs, *vnet.ID)
				}
			}
		}
	}

	return &resource.ListResult{
		NativeIDs: nativeIDs,
	}, nil
}
