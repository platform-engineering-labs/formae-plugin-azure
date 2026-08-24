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

const ResourceTypeNetworkLocalNetworkGateway = "AZURE::Network::LocalNetworkGateway"

// networkLocalNetworkGatewaysAPI is the armnetwork surface used here. UpdateTags is
// deliberately absent: it cannot change the address space or the peer address, so
// every update is a re-PUT.
type networkLocalNetworkGatewaysAPI interface {
	BeginCreateOrUpdate(ctx context.Context, resourceGroupName string, localNetworkGatewayName string, parameters armnetwork.LocalNetworkGateway, options *armnetwork.LocalNetworkGatewaysClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.LocalNetworkGatewaysClientCreateOrUpdateResponse], error)
	Get(ctx context.Context, resourceGroupName string, localNetworkGatewayName string, options *armnetwork.LocalNetworkGatewaysClientGetOptions) (armnetwork.LocalNetworkGatewaysClientGetResponse, error)
	BeginDelete(ctx context.Context, resourceGroupName string, localNetworkGatewayName string, options *armnetwork.LocalNetworkGatewaysClientBeginDeleteOptions) (*runtime.Poller[armnetwork.LocalNetworkGatewaysClientDeleteResponse], error)
	NewListPager(resourceGroupName string, options *armnetwork.LocalNetworkGatewaysClientListOptions) *runtime.Pager[armnetwork.LocalNetworkGatewaysClientListResponse]
}

func init() {
	registry.Register(ResourceTypeNetworkLocalNetworkGateway, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &NetworkLocalNetworkGateway{
			api:      c.LocalNetworkGatewaysClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// NetworkLocalNetworkGateway is the provisioner for the on-premises end of a
// site-to-site VPN (Microsoft.Network/localNetworkGateways).
type NetworkLocalNetworkGateway struct {
	api      networkLocalNetworkGatewaysAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

// networkLocalNetworkGatewayProps mirrors
// schema/pkl/network/localnetworkgateway.pkl.
type networkLocalNetworkGatewayProps struct {
	Name                     string                              `json:"name"`
	ResourceGroupName        string                              `json:"resourceGroupName"`
	Location                 string                              `json:"location"`
	GatewayIPAddress         *string                             `json:"gatewayIpAddress"`
	Fqdn                     *string                             `json:"fqdn"`
	LocalNetworkAddressSpace []string                            `json:"localNetworkAddressSpace"`
	BgpSettings              *networkLocalNetworkGatewayBgpProps `json:"bgpSettings"`
}

type networkLocalNetworkGatewayBgpProps struct {
	Asn               *int64 `json:"asn"`
	BgpPeeringAddress string `json:"bgpPeeringAddress"`
	PeerWeight        *int32 `json:"peerWeight"`
}

func networkLocalNetworkGatewayIDParts(resourceID string) (rgName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "localnetworkgateways")
	if err != nil {
		return "", "", err
	}
	return rgName, names["localnetworkgateways"], nil
}

func (r *NetworkLocalNetworkGateway) buildPropertiesFromResult(gateway *armnetwork.LocalNetworkGateway, rgName string) map[string]any {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName

	if gateway.ID != nil {
		props["id"] = *gateway.ID
	}
	if gateway.Name != nil {
		props["name"] = *gateway.Name
	}
	if gateway.Location != nil {
		props["location"] = normalizeAzureLocation(*gateway.Location)
	}
	if tags := azureTagsToFormaeTags(gateway.Tags); len(tags) > 0 {
		props["Tags"] = tags
	}

	if p := gateway.Properties; p != nil {
		if p.GatewayIPAddress != nil && *p.GatewayIPAddress != "" {
			props["gatewayIpAddress"] = *p.GatewayIPAddress
		}
		if p.Fqdn != nil && *p.Fqdn != "" {
			props["fqdn"] = *p.Fqdn
		}
		if space := p.LocalNetworkAddressSpace; space != nil {
			if prefixes := stringsFromPointers(space.AddressPrefixes); prefixes != nil {
				props["localNetworkAddressSpace"] = prefixes
			}
		}
		if bgp := p.BgpSettings; bgp != nil {
			settings := make(map[string]any)
			if bgp.Asn != nil {
				settings["asn"] = *bgp.Asn
			}
			if bgp.BgpPeeringAddress != nil {
				settings["bgpPeeringAddress"] = *bgp.BgpPeeringAddress
			}
			if bgp.PeerWeight != nil {
				settings["peerWeight"] = *bgp.PeerWeight
			}
			// bgpPeeringAddresses is the gateway-side view of the peering, populated
			// only once a connection exists, and it is not modelled.
			props["bgpSettings"] = settings
		}
		// provisioningState and resourceGuid are service state.
	}

	return props
}

// networkLocalNetworkGatewayParams builds the request body shared by create and
// update.
func networkLocalNetworkGatewayParams(props networkLocalNetworkGatewayProps, payload json.RawMessage) armnetwork.LocalNetworkGateway {
	params := armnetwork.LocalNetworkGateway{
		Location: to.Ptr(props.Location),
		Properties: &armnetwork.LocalNetworkGatewayPropertiesFormat{
			GatewayIPAddress: props.GatewayIPAddress,
			Fqdn:             props.Fqdn,
			LocalNetworkAddressSpace: &armnetwork.AddressSpace{
				AddressPrefixes: stringPointers(props.LocalNetworkAddressSpace),
			},
		},
	}

	if bgp := props.BgpSettings; bgp != nil {
		params.Properties.BgpSettings = &armnetwork.BgpSettings{
			Asn:               bgp.Asn,
			BgpPeeringAddress: to.Ptr(bgp.BgpPeeringAddress),
			PeerWeight:        bgp.PeerWeight,
		}
	}

	if tags := formaeTagsToAzureTags(payload); len(tags) > 0 {
		params.Tags = tags
	}

	return params
}

// upsert backs both Create and Update: UpdateTags cannot touch the peer address or
// the address space, so an update is another CreateOrUpdate.
func (r *NetworkLocalNetworkGateway) upsert(ctx context.Context, payload json.RawMessage, label string) (*runtime.Poller[armnetwork.LocalNetworkGatewaysClientCreateOrUpdateResponse], networkLocalNetworkGatewayProps, string, error) {
	var props networkLocalNetworkGatewayProps
	if err := json.Unmarshal(payload, &props); err != nil {
		return nil, props, "", fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return nil, props, "", fmt.Errorf("resourceGroupName is required")
	}
	if props.Location == "" {
		return nil, props, "", fmt.Errorf("location is required")
	}
	if len(props.LocalNetworkAddressSpace) == 0 {
		return nil, props, "", fmt.Errorf("localNetworkAddressSpace is required")
	}
	// ARM rejects a gateway with neither, and ignores fqdn when both are set.
	if props.GatewayIPAddress == nil && props.Fqdn == nil {
		return nil, props, "", fmt.Errorf("one of gatewayIpAddress or fqdn is required")
	}
	if props.GatewayIPAddress != nil && props.Fqdn != nil {
		return nil, props, "", fmt.Errorf("gatewayIpAddress and fqdn are mutually exclusive")
	}
	name := props.Name
	if name == "" {
		name = label
	}
	if name == "" {
		return nil, props, "", fmt.Errorf("name is required")
	}

	poller, err := r.api.BeginCreateOrUpdate(ctx, props.ResourceGroupName, name,
		networkLocalNetworkGatewayParams(props, payload), nil)
	return poller, props, name, err
}

func (r *NetworkLocalNetworkGateway) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	poller, props, name, err := r.upsert(ctx, request.Properties, request.Label)
	if err != nil {
		if name == "" {
			return nil, err
		}
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/localNetworkGateways/%s",
		r.config.SubscriptionId, props.ResourceGroupName, name)

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
		nativeID, propsJSON, err := r.completeFromGateway(&result.LocalNetworkGateway)
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

func (r *NetworkLocalNetworkGateway) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, name, err := networkLocalNetworkGatewayIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := r.api.Get(ctx, rgName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(r.buildPropertiesFromResult(&result.LocalNetworkGateway, rgName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeNetworkLocalNetworkGateway,
		Properties:   string(propsJSON),
	}, nil
}

func (r *NetworkLocalNetworkGateway) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, _, err := networkLocalNetworkGatewayIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, _, name, err := r.upsert(ctx, request.DesiredProperties, "")
	if err != nil {
		if name == "" {
			return nil, err
		}
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
		propsJSON, err := json.Marshal(r.buildPropertiesFromResult(&result.LocalNetworkGateway, rgName))
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

func (r *NetworkLocalNetworkGateway) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, name, err := networkLocalNetworkGatewayIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, err := r.api.BeginDelete(ctx, rgName, name, nil)
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

func (r *NetworkLocalNetworkGateway) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	reqID, err := decodeLROStatus(request.RequestID)
	if err != nil {
		return nil, err
	}

	switch reqID.OperationType {
	case lroOpCreate, lroOpUpdate:
		// Both resume as CreateOrUpdate responses: Update re-PUTs, so the poller that
		// issued the token has the same response type in either case.
		operation := resource.OperationCreate
		if reqID.OperationType == lroOpUpdate {
			operation = resource.OperationUpdate
		}
		return statusLRO(ctx, request, &reqID, operation,
			func(token string) (*runtime.Poller[armnetwork.LocalNetworkGatewaysClientCreateOrUpdateResponse], error) {
				return resumePoller[armnetwork.LocalNetworkGatewaysClientCreateOrUpdateResponse](r.pipeline, token)
			},
			func(_ context.Context, result armnetwork.LocalNetworkGatewaysClientCreateOrUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				return r.completeFromGateway(&result.LocalNetworkGateway)
			})
	case lroOpDelete:
		return statusDeleteLRO(ctx, request, &reqID,
			func(token string) (*runtime.Poller[armnetwork.LocalNetworkGatewaysClientDeleteResponse], error) {
				return resumePoller[armnetwork.LocalNetworkGatewaysClientDeleteResponse](r.pipeline, token)
			}, nil)
	default:
		return nil, fmt.Errorf("unknown operation type: %s", reqID.OperationType)
	}
}

func (r *NetworkLocalNetworkGateway) completeFromGateway(gateway *armnetwork.LocalNetworkGateway) (string, json.RawMessage, error) {
	nativeID := ""
	rgName := ""
	if gateway.ID != nil {
		nativeID = *gateway.ID
		if rg, _, err := networkLocalNetworkGatewayIDParts(*gateway.ID); err == nil {
			rgName = rg
		}
	}
	propsJSON, err := json.Marshal(r.buildPropertiesFromResult(gateway, rgName))
	if err != nil {
		return "", nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return nativeID, propsJSON, nil
}

// List is scoped to a resource group: ARM offers no subscription-wide listing for
// local network gateways.
func (r *NetworkLocalNetworkGateway) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	if rgName == "" {
		return &resource.ListResult{}, nil
	}

	var nativeIDs []string
	pager := r.api.NewListPager(rgName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list local network gateways: %w", err)
		}
		for _, gateway := range page.Value {
			if gateway.ID != nil {
				nativeIDs = append(nativeIDs, *gateway.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
