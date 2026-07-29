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

const ResourceTypeVirtualNetworkPeering = "AZURE::Network::VirtualNetworkPeering"

// virtualNetworkPeeringsAPI is the subset of *armnetwork.VirtualNetworkPeeringsClient
// used here, plus the cross-resource VNet enumeration discovery needs (peerings can
// only be listed per-VNet, so listing the whole subscription means walking VNets —
// the same shape subnet.go uses).
type virtualNetworkPeeringsAPI interface {
	BeginCreateOrUpdate(ctx context.Context, resourceGroupName string, virtualNetworkName string, virtualNetworkPeeringName string, virtualNetworkPeeringParameters armnetwork.VirtualNetworkPeering, options *armnetwork.VirtualNetworkPeeringsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.VirtualNetworkPeeringsClientCreateOrUpdateResponse], error)
	Get(ctx context.Context, resourceGroupName string, virtualNetworkName string, virtualNetworkPeeringName string, options *armnetwork.VirtualNetworkPeeringsClientGetOptions) (armnetwork.VirtualNetworkPeeringsClientGetResponse, error)
	BeginDelete(ctx context.Context, resourceGroupName string, virtualNetworkName string, virtualNetworkPeeringName string, options *armnetwork.VirtualNetworkPeeringsClientBeginDeleteOptions) (*runtime.Poller[armnetwork.VirtualNetworkPeeringsClientDeleteResponse], error)
	NewListPager(resourceGroupName string, virtualNetworkName string, options *armnetwork.VirtualNetworkPeeringsClientListOptions) *runtime.Pager[armnetwork.VirtualNetworkPeeringsClientListResponse]
	NewListAllVNetsPager(options *armnetwork.VirtualNetworksClientListAllOptions) *runtime.Pager[armnetwork.VirtualNetworksClientListAllResponse]
}

// virtualNetworkPeeringsWrapper composes the VirtualNetworkPeerings SDK client with
// subscription-wide VNet discovery.
type virtualNetworkPeeringsWrapper struct {
	*armnetwork.VirtualNetworkPeeringsClient
	vnetsClient *armnetwork.VirtualNetworksClient
}

func (w *virtualNetworkPeeringsWrapper) NewListAllVNetsPager(options *armnetwork.VirtualNetworksClientListAllOptions) *runtime.Pager[armnetwork.VirtualNetworksClientListAllResponse] {
	return w.vnetsClient.NewListAllPager(options)
}

func init() {
	registry.Register(ResourceTypeVirtualNetworkPeering, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &VirtualNetworkPeering{
			api: &virtualNetworkPeeringsWrapper{
				VirtualNetworkPeeringsClient: c.VirtualNetworkPeeringsClient,
				vnetsClient:                  c.VirtualNetworksClient,
			},
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// VirtualNetworkPeering is the provisioner for Azure virtual network peerings
// (`Microsoft.Network/virtualNetworks/<vnet>/virtualNetworkPeerings/<name>`).
//
// A peering is one-directional: it lives under the local VNet and points at a
// remote one. A working bidirectional peering is therefore two resources, one per
// VNet, and each side owns its own flags.
type VirtualNetworkPeering struct {
	api      virtualNetworkPeeringsAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

func virtualNetworkPeeringIDParts(resourceID string) (rgName, vnetName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "virtualnetworks", "virtualnetworkpeerings")
	if err != nil {
		return "", "", "", err
	}
	return rgName, names["virtualnetworks"], names["virtualnetworkpeerings"], nil
}

func serializeVirtualNetworkPeeringProperties(result armnetwork.VirtualNetworkPeering, rgName, vnetName, name string) (json.RawMessage, error) {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	props["virtualNetworkName"] = vnetName
	if result.Name != nil {
		props["name"] = *result.Name
	} else {
		props["name"] = name
	}
	if result.ID != nil {
		props["id"] = *result.ID
	}

	if result.Properties != nil {
		if result.Properties.RemoteVirtualNetwork != nil && result.Properties.RemoteVirtualNetwork.ID != nil {
			props["remoteVirtualNetworkId"] = *result.Properties.RemoteVirtualNetwork.ID
		}
		if result.Properties.AllowVirtualNetworkAccess != nil {
			props["allowVirtualNetworkAccess"] = *result.Properties.AllowVirtualNetworkAccess
		}
		if result.Properties.AllowForwardedTraffic != nil {
			props["allowForwardedTraffic"] = *result.Properties.AllowForwardedTraffic
		}
		if result.Properties.AllowGatewayTransit != nil {
			props["allowGatewayTransit"] = *result.Properties.AllowGatewayTransit
		}
		if result.Properties.UseRemoteGateways != nil {
			props["useRemoteGateways"] = *result.Properties.UseRemoteGateways
		}
	}

	return json.Marshal(props)
}

func virtualNetworkPeeringParamsFromProperties(props map[string]any) (armnetwork.VirtualNetworkPeering, error) {
	remoteID, _ := props["remoteVirtualNetworkId"].(string)
	if remoteID == "" {
		return armnetwork.VirtualNetworkPeering{}, fmt.Errorf("remoteVirtualNetworkId is required")
	}

	peering := armnetwork.VirtualNetworkPeering{
		Properties: &armnetwork.VirtualNetworkPeeringPropertiesFormat{
			RemoteVirtualNetwork: &armnetwork.SubResource{ID: stringPtr(remoteID)},
		},
	}

	if v, ok := props["allowVirtualNetworkAccess"].(bool); ok {
		peering.Properties.AllowVirtualNetworkAccess = to.Ptr(v)
	}
	if v, ok := props["allowForwardedTraffic"].(bool); ok {
		peering.Properties.AllowForwardedTraffic = to.Ptr(v)
	}
	if v, ok := props["allowGatewayTransit"].(bool); ok {
		peering.Properties.AllowGatewayTransit = to.Ptr(v)
	}
	if v, ok := props["useRemoteGateways"].(bool); ok {
		peering.Properties.UseRemoteGateways = to.Ptr(v)
	}

	return peering, nil
}

func (p *VirtualNetworkPeering) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props map[string]any
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	rgName, _ := props["resourceGroupName"].(string)
	if rgName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	vnetName, _ := props["virtualNetworkName"].(string)
	if vnetName == "" {
		return nil, fmt.Errorf("virtualNetworkName is required")
	}
	name, _ := props["name"].(string)
	if name == "" {
		name = request.Label
	}
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}

	params, err := virtualNetworkPeeringParamsFromProperties(props)
	if err != nil {
		return nil, err
	}

	poller, err := p.api.BeginCreateOrUpdate(ctx, rgName, vnetName, name, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	expectedID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/virtualNetworks/%s/virtualNetworkPeerings/%s",
		p.config.SubscriptionId, rgName, vnetName, name)

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
		propsJSON, err := serializeVirtualNetworkPeeringProperties(result.VirtualNetworkPeering, rgName, vnetName, name)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize VirtualNetworkPeering properties: %w", err)
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

func (p *VirtualNetworkPeering) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, vnetName, name, err := virtualNetworkPeeringIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := p.api.Get(ctx, rgName, vnetName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := serializeVirtualNetworkPeeringProperties(result.VirtualNetworkPeering, rgName, vnetName, name)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize VirtualNetworkPeering properties: %w", err)
	}

	return &resource.ReadResult{
		ResourceType: ResourceTypeVirtualNetworkPeering,
		Properties:   string(propsJSON),
	}, nil
}

func (p *VirtualNetworkPeering) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	// Parent names come from the native ID, never from the payload.
	rgName, vnetName, name, err := virtualNetworkPeeringIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props map[string]any
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse desired properties: %w", err)
	}

	// There is no PATCH verb for peerings; the flags change via a full-body PUT and
	// remoteVirtualNetwork must be echoed back or ARM rejects the request.
	params, err := virtualNetworkPeeringParamsFromProperties(props)
	if err != nil {
		return nil, err
	}

	poller, err := p.api.BeginCreateOrUpdate(ctx, rgName, vnetName, name, params, nil)
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
		propsJSON, err := serializeVirtualNetworkPeeringProperties(result.VirtualNetworkPeering, rgName, vnetName, name)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize VirtualNetworkPeering properties: %w", err)
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

func (p *VirtualNetworkPeering) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, vnetName, name, err := virtualNetworkPeeringIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, err := p.api.BeginDelete(ctx, rgName, vnetName, name, nil)
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
				ErrorCode:       operationErrorCode(err),
			},
		}, fmt.Errorf("failed to delete VirtualNetworkPeering: %w", err)
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

func (p *VirtualNetworkPeering) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
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
	case lroOpCreate, lroOpUpdate:
		return p.statusCreateOrUpdate(ctx, request, &reqID)
	case lroOpDelete:
		return p.statusDelete(ctx, request, &reqID)
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

func (p *VirtualNetworkPeering) statusCreateOrUpdate(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	operation := resource.OperationCreate
	if reqID.OperationType == lroOpUpdate {
		operation = resource.OperationUpdate
	}

	return statusLRO(ctx, request, reqID, operation,
		func(token string) (*runtime.Poller[armnetwork.VirtualNetworkPeeringsClientCreateOrUpdateResponse], error) {
			return resumePoller[armnetwork.VirtualNetworkPeeringsClientCreateOrUpdateResponse](p.pipeline, token)
		},
		func(_ context.Context, result armnetwork.VirtualNetworkPeeringsClientCreateOrUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
			rgName, vnetName, name, err := virtualNetworkPeeringIDParts(*result.ID)
			if err != nil {
				return "", nil, err
			}
			propsJSON, err := serializeVirtualNetworkPeeringProperties(result.VirtualNetworkPeering, rgName, vnetName, name)
			if err != nil {
				return "", nil, fmt.Errorf("failed to serialize VirtualNetworkPeering properties: %w", err)
			}
			return *result.ID, propsJSON, nil
		})
}

func (p *VirtualNetworkPeering) statusDelete(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	return statusDeleteLRO(ctx, request, reqID,
		func(token string) (*runtime.Poller[armnetwork.VirtualNetworkPeeringsClientDeleteResponse], error) {
			return resumePoller[armnetwork.VirtualNetworkPeeringsClientDeleteResponse](p.pipeline, token)
		}, nil)
}

func (p *VirtualNetworkPeering) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	vnetName := request.AdditionalProperties["virtualNetworkName"]

	if rgName != "" && vnetName != "" {
		ids, err := p.listByVNet(ctx, rgName, vnetName)
		if err != nil {
			return nil, err
		}
		return &resource.ListResult{NativeIDs: ids}, nil
	}

	// Discovery path: peerings can only be listed per-VNet, so walk every VNet.
	var nativeIDs []string
	vnetPager := p.api.NewListAllVNetsPager(nil)
	for vnetPager.More() {
		page, err := vnetPager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list virtual networks for peering discovery: %w", err)
		}
		for _, vnet := range page.Value {
			if vnet.ID == nil {
				continue
			}
			vnetRG, name, err := parseVirtualNetworkNativeID(*vnet.ID)
			if err != nil {
				continue
			}
			ids, err := p.listByVNet(ctx, vnetRG, name)
			if err != nil {
				return nil, err
			}
			nativeIDs = append(nativeIDs, ids...)
		}
	}

	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}

func (p *VirtualNetworkPeering) listByVNet(ctx context.Context, rgName, vnetName string) ([]string, error) {
	pager := p.api.NewListPager(rgName, vnetName, nil)

	var nativeIDs []string
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list virtual network peerings in %s/%s: %w", rgName, vnetName, err)
		}
		for _, peering := range page.Value {
			if peering.ID != nil {
				nativeIDs = append(nativeIDs, *peering.ID)
			}
		}
	}

	return nativeIDs, nil
}
