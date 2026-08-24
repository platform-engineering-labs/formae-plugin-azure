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

// virtualNetworkPeeringsAPI is the armnetwork surface used here. Create and delete
// are LROs; there is no PATCH verb, so an update is another CreateOrUpdate.
type virtualNetworkPeeringsAPI interface {
	BeginCreateOrUpdate(ctx context.Context, resourceGroupName string, virtualNetworkName string, outboundEndpointName string, parameters armnetwork.VirtualNetworkPeering, options *armnetwork.VirtualNetworkPeeringsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.VirtualNetworkPeeringsClientCreateOrUpdateResponse], error)
	Get(ctx context.Context, resourceGroupName string, virtualNetworkName string, outboundEndpointName string, options *armnetwork.VirtualNetworkPeeringsClientGetOptions) (armnetwork.VirtualNetworkPeeringsClientGetResponse, error)
	BeginDelete(ctx context.Context, resourceGroupName string, virtualNetworkName string, outboundEndpointName string, options *armnetwork.VirtualNetworkPeeringsClientBeginDeleteOptions) (*runtime.Poller[armnetwork.VirtualNetworkPeeringsClientDeleteResponse], error)
	NewListPager(resourceGroupName string, virtualNetworkName string, options *armnetwork.VirtualNetworkPeeringsClientListOptions) *runtime.Pager[armnetwork.VirtualNetworkPeeringsClientListResponse]
}

func init() {
	registry.Register(ResourceTypeVirtualNetworkPeering, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &VirtualNetworkPeering{
			api:      c.VirtualNetworkPeeringsClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// VirtualNetworkPeering is the provisioner for one-directional vnet peerings
// (Microsoft.Network/virtualNetworks/virtualNetworkPeerings).
type VirtualNetworkPeering struct {
	api      virtualNetworkPeeringsAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

// virtualNetworkPeeringProps mirrors
// schema/pkl/network/virtualnetworkpeering.pkl.
type virtualNetworkPeeringProps struct {
	Name                      string `json:"name"`
	ResourceGroupName         string `json:"resourceGroupName"`
	VirtualNetworkName        string `json:"virtualNetworkName"`
	RemoteVirtualNetworkID    string `json:"remoteVirtualNetworkId"`
	AllowVirtualNetworkAccess *bool  `json:"allowVirtualNetworkAccess"`
	AllowForwardedTraffic     *bool  `json:"allowForwardedTraffic"`
	AllowGatewayTransit       *bool  `json:"allowGatewayTransit"`
	UseRemoteGateways         *bool  `json:"useRemoteGateways"`
}

// virtualNetworkPeeringParams builds the request body shared by create and update.
// A peering has no location or tags of its own — it inherits the vnet's.
func virtualNetworkPeeringParams(props virtualNetworkPeeringProps) armnetwork.VirtualNetworkPeering {
	return armnetwork.VirtualNetworkPeering{
		Properties: &armnetwork.VirtualNetworkPeeringPropertiesFormat{
			RemoteVirtualNetwork:      &armnetwork.SubResource{ID: to.Ptr(props.RemoteVirtualNetworkID)},
			AllowVirtualNetworkAccess: props.AllowVirtualNetworkAccess,
			AllowForwardedTraffic:     props.AllowForwardedTraffic,
			AllowGatewayTransit:       props.AllowGatewayTransit,
			UseRemoteGateways:         props.UseRemoteGateways,
		},
	}
}

func virtualNetworkPeeringIDParts(resourceID string) (rgName, virtualNetworkName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "virtualnetworks", "virtualnetworkpeerings")
	if err != nil {
		return "", "", "", err
	}
	return rgName, names["virtualnetworks"], names["virtualnetworkpeerings"], nil
}

func (d *VirtualNetworkPeering) buildPropertiesFromResult(peering *armnetwork.VirtualNetworkPeering, rgName, virtualNetworkName string) map[string]any {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	props["virtualNetworkName"] = virtualNetworkName

	if peering.ID != nil {
		props["id"] = *peering.ID
	}
	if peering.Name != nil {
		props["name"] = *peering.Name
	}
	if p := peering.Properties; p != nil {
		if p.RemoteVirtualNetwork != nil && p.RemoteVirtualNetwork.ID != nil {
			props["remoteVirtualNetworkId"] = *p.RemoteVirtualNetwork.ID
		}
		if p.AllowVirtualNetworkAccess != nil {
			props["allowVirtualNetworkAccess"] = *p.AllowVirtualNetworkAccess
		}
		if p.AllowForwardedTraffic != nil {
			props["allowForwardedTraffic"] = *p.AllowForwardedTraffic
		}
		if p.AllowGatewayTransit != nil {
			props["allowGatewayTransit"] = *p.AllowGatewayTransit
		}
		if p.UseRemoteGateways != nil {
			props["useRemoteGateways"] = *p.UseRemoteGateways
		}
		if p.PeeringState != nil {
			props["peeringState"] = string(*p.PeeringState)
		}
		// remoteAddressSpace, remoteVirtualNetworkAddressSpace, remoteBgpCommunities,
		// peeringSyncLevel, provisioningState and resourceGuid are all dropped: they
		// are ARM's view of the far side, not desired state, and they change whenever
		// the remote vnet does.
	}

	return props
}

func (d *VirtualNetworkPeering) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props virtualNetworkPeeringProps
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	if props.VirtualNetworkName == "" {
		return nil, fmt.Errorf("virtualNetworkName is required")
	}
	if props.RemoteVirtualNetworkID == "" {
		return nil, fmt.Errorf("remoteVirtualNetworkId is required")
	}
	name := props.Name
	if name == "" {
		name = request.Label
	}
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}

	params := virtualNetworkPeeringParams(props)

	poller, err := d.api.BeginCreateOrUpdate(ctx, props.ResourceGroupName, props.VirtualNetworkName, name, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/virtualNetworks/%s/virtualNetworkPeerings/%s",
		d.config.SubscriptionId, props.ResourceGroupName, props.VirtualNetworkName, name)

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
		nativeID, propsJSON, err := d.completeFromEndpoint(&result.VirtualNetworkPeering)
		if err != nil {
			return nil, err
		}
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:          resource.OperationCreate,
				OperationStatus:    resource.OperationStatusSuccess,
				NativeID:           nativeID,
				ResourceProperties: propsJSON,
			},
		}, nil
	}

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

func (d *VirtualNetworkPeering) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, virtualNetworkName, name, err := virtualNetworkPeeringIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := d.api.Get(ctx, rgName, virtualNetworkName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(d.buildPropertiesFromResult(&result.VirtualNetworkPeering, rgName, virtualNetworkName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeVirtualNetworkPeering,
		Properties:   string(propsJSON),
	}, nil
}

// Update re-PUTs through BeginCreateOrUpdate: this API has no PATCH verb. The
// remote vnet is createOnly in the schema, so only the four traffic flags really
// change here.
func (d *VirtualNetworkPeering) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, virtualNetworkName, name, err := virtualNetworkPeeringIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props virtualNetworkPeeringProps
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.RemoteVirtualNetworkID == "" {
		return nil, fmt.Errorf("remoteVirtualNetworkId is required")
	}

	params := virtualNetworkPeeringParams(props)

	poller, err := d.api.BeginCreateOrUpdate(ctx, rgName, virtualNetworkName, name, params, nil)
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
		propsJSON, err := json.Marshal(d.buildPropertiesFromResult(&result.VirtualNetworkPeering, rgName, virtualNetworkName))
		if err != nil {
			return nil, fmt.Errorf("failed to marshal response properties: %w", err)
		}
		return &resource.UpdateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:          resource.OperationUpdate,
				OperationStatus:    resource.OperationStatusSuccess,
				NativeID:           request.NativeID,
				ResourceProperties: propsJSON,
			},
		}, nil
	}

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

func (d *VirtualNetworkPeering) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, virtualNetworkName, name, err := virtualNetworkPeeringIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, err := d.api.BeginDelete(ctx, rgName, virtualNetworkName, name, nil)
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
		}, nil
	}

	if poller.Done() {
		if _, err := poller.Result(ctx); err != nil && !isDeleteSuccessError(err) {
			return &resource.DeleteResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationDelete,
					OperationStatus: resource.OperationStatusFailure,
					NativeID:        request.NativeID,
					ErrorCode:       operationErrorCode(err),
				},
			}, nil
		}
		return &resource.DeleteResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationDelete,
				OperationStatus: resource.OperationStatusSuccess,
				NativeID:        request.NativeID,
			},
		}, nil
	}

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

func (d *VirtualNetworkPeering) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	reqID, err := decodeLROStatus(request.RequestID)
	if err != nil {
		return nil, err
	}

	switch reqID.OperationType {
	case lroOpCreate:
		return statusLRO(ctx, request, &reqID, resource.OperationCreate,
			func(token string) (*runtime.Poller[armnetwork.VirtualNetworkPeeringsClientCreateOrUpdateResponse], error) {
				return resumePoller[armnetwork.VirtualNetworkPeeringsClientCreateOrUpdateResponse](d.pipeline, token)
			},
			func(_ context.Context, result armnetwork.VirtualNetworkPeeringsClientCreateOrUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				return d.completeFromEndpoint(&result.VirtualNetworkPeering)
			})
	case lroOpUpdate:
		// Resumed as a CreateOrUpdate response: Update issues BeginCreateOrUpdate,
		// so that is the poller whose token was handed out. Decoding it as some other
		// response type kills the plugin operator mid-poll.
		return statusLRO(ctx, request, &reqID, resource.OperationUpdate,
			func(token string) (*runtime.Poller[armnetwork.VirtualNetworkPeeringsClientCreateOrUpdateResponse], error) {
				return resumePoller[armnetwork.VirtualNetworkPeeringsClientCreateOrUpdateResponse](d.pipeline, token)
			},
			func(_ context.Context, result armnetwork.VirtualNetworkPeeringsClientCreateOrUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				return d.completeFromEndpoint(&result.VirtualNetworkPeering)
			})
	case lroOpDelete:
		return statusDeleteLRO(ctx, request, &reqID,
			func(token string) (*runtime.Poller[armnetwork.VirtualNetworkPeeringsClientDeleteResponse], error) {
				return resumePoller[armnetwork.VirtualNetworkPeeringsClientDeleteResponse](d.pipeline, token)
			}, nil)
	default:
		return nil, fmt.Errorf("unknown operation type: %s", reqID.OperationType)
	}
}

func (d *VirtualNetworkPeering) completeFromEndpoint(peering *armnetwork.VirtualNetworkPeering) (string, json.RawMessage, error) {
	nativeID := ""
	rgName := ""
	virtualNetworkName := ""
	if peering.ID != nil {
		nativeID = *peering.ID
		if rg, vnet, _, err := virtualNetworkPeeringIDParts(*peering.ID); err == nil {
			rgName = rg
			virtualNetworkName = vnet
		}
	}
	propsJSON, err := json.Marshal(d.buildPropertiesFromResult(peering, rgName, virtualNetworkName))
	if err != nil {
		return "", nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return nativeID, propsJSON, nil
}

// List requires both the resource group and the virtual network name: ARM has no
// subscription-wide listing for outbound endpoints.
func (d *VirtualNetworkPeering) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	virtualNetworkName := request.AdditionalProperties["virtualNetworkName"]
	if rgName == "" || virtualNetworkName == "" {
		return &resource.ListResult{}, nil
	}

	var nativeIDs []string
	pager := d.api.NewListPager(rgName, virtualNetworkName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list virtual network peerings: %w", err)
		}
		for _, peering := range page.Value {
			if peering.ID != nil {
				nativeIDs = append(nativeIDs, *peering.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
