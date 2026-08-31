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

const ResourceTypeVpnGateway = "AZURE::Network::VpnGateway"

// vpnGatewaysAPI is the armnetwork surface used here. BeginUpdateTags is
// deliberately absent: it cannot change the scale unit or the connections, so every
// update is a re-PUT.
type vpnGatewaysAPI interface {
	BeginCreateOrUpdate(ctx context.Context, resourceGroupName string, gatewayName string, vpnGatewayParameters armnetwork.VPNGateway, options *armnetwork.VPNGatewaysClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.VPNGatewaysClientCreateOrUpdateResponse], error)
	Get(ctx context.Context, resourceGroupName string, gatewayName string, options *armnetwork.VPNGatewaysClientGetOptions) (armnetwork.VPNGatewaysClientGetResponse, error)
	BeginDelete(ctx context.Context, resourceGroupName string, gatewayName string, options *armnetwork.VPNGatewaysClientBeginDeleteOptions) (*runtime.Poller[armnetwork.VPNGatewaysClientDeleteResponse], error)
	NewListByResourceGroupPager(resourceGroupName string, options *armnetwork.VPNGatewaysClientListByResourceGroupOptions) *runtime.Pager[armnetwork.VPNGatewaysClientListByResourceGroupResponse]
	NewListPager(options *armnetwork.VPNGatewaysClientListOptions) *runtime.Pager[armnetwork.VPNGatewaysClientListResponse]
}

func init() {
	registry.Register(ResourceTypeVpnGateway, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &VpnGateway{
			api:      c.VPNGatewaysClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// VpnGateway is the provisioner for the site-to-site VPN gateway inside a Virtual
// WAN hub (Microsoft.Network/vpnGateways).
type VpnGateway struct {
	api      vpnGatewaysAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

// vpnGatewayProps mirrors schema/pkl/network/vpngateway.pkl.
type vpnGatewayProps struct {
	Name                            string                      `json:"name"`
	ResourceGroupName               string                      `json:"resourceGroupName"`
	Location                        string                      `json:"location"`
	VirtualHubID                    string                      `json:"virtualHubId"`
	VpnGatewayScaleUnit             *int32                      `json:"vpnGatewayScaleUnit"`
	BgpSettings                     *vpnGatewayBgpProps         `json:"bgpSettings"`
	Connections                     []vpnGatewayConnectionProps `json:"connections"`
	EnableBgpRouteTranslationForNat *bool                       `json:"enableBgpRouteTranslationForNat"`
	IsRoutingPreferenceInternet     *bool                       `json:"isRoutingPreferenceInternet"`
}

type vpnGatewayBgpProps struct {
	Asn        *int64 `json:"asn"`
	PeerWeight *int32 `json:"peerWeight"`
}

type vpnGatewayConnectionProps struct {
	Name                      string  `json:"name"`
	RemoteVpnSiteID           string  `json:"remoteVpnSiteId"`
	ConnectionBandwidth       *int32  `json:"connectionBandwidth"`
	EnableBgp                 *bool   `json:"enableBgp"`
	RoutingWeight             *int32  `json:"routingWeight"`
	VpnConnectionProtocolType *string `json:"vpnConnectionProtocolType"`
	SharedKey                 *string `json:"sharedKey"`
}

// vpnConnectionProtocols carries the canonical casing for the IKE version enum,
// applied on the read path because ARM echoes it back inconsistently.
var vpnConnectionProtocols = []string{"IKEv1", "IKEv2"}

func vpnGatewayIDParts(resourceID string) (rgName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "vpngateways")
	if err != nil {
		return "", "", err
	}
	return rgName, names["vpngateways"], nil
}

func (r *VpnGateway) buildPropertiesFromResult(gateway *armnetwork.VPNGateway, rgName string) map[string]any {
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
		if p.VirtualHub != nil && p.VirtualHub.ID != nil {
			props["virtualHubId"] = *p.VirtualHub.ID
		}
		if p.VPNGatewayScaleUnit != nil {
			props["vpnGatewayScaleUnit"] = *p.VPNGatewayScaleUnit
		}
		if p.EnableBgpRouteTranslationForNat != nil {
			props["enableBgpRouteTranslationForNat"] = *p.EnableBgpRouteTranslationForNat
		}
		if p.IsRoutingPreferenceInternet != nil {
			props["isRoutingPreferenceInternet"] = *p.IsRoutingPreferenceInternet
		}
		if bgp := p.BgpSettings; bgp != nil {
			settings := make(map[string]any)
			if bgp.Asn != nil {
				settings["asn"] = *bgp.Asn
			}
			if bgp.PeerWeight != nil {
				settings["peerWeight"] = *bgp.PeerWeight
			}
			if len(settings) > 0 {
				props["bgpSettings"] = settings
			}
			// bgpPeeringAddress and bgpPeeringAddresses are allocated by Azure out of
			// the hub's address prefix, so they are dropped rather than compared.
		}
		if conns := vpnGatewayConnectionsToProps(p.Connections); len(conns) > 0 {
			props["connections"] = conns
		}
		// provisioningState, ipConfigurations and natRules are service state or not
		// modelled.
	}

	return props
}

// vpnGatewayConnectionsToProps is the read-path inverse of
// vpnGatewayConnectionsFromProps. It emits only the modelled fields: the child ARM
// ID and etag, the vpnLinkConnections Azure seeds per remote link, the connection
// status and the byte counters are all service-owned. sharedKey is write-only and
// never surfaced.
func vpnGatewayConnectionsToProps(conns []*armnetwork.VPNConnection) []map[string]any {
	if len(conns) == 0 {
		return nil
	}
	out := make([]map[string]any, 0, len(conns))
	for _, conn := range conns {
		if conn == nil {
			continue
		}
		entry := make(map[string]any)
		if conn.Name != nil {
			entry["name"] = *conn.Name
		}
		if cp := conn.Properties; cp != nil {
			if cp.RemoteVPNSite != nil && cp.RemoteVPNSite.ID != nil {
				entry["remoteVpnSiteId"] = *cp.RemoteVPNSite.ID
			}
			if cp.ConnectionBandwidth != nil {
				entry["connectionBandwidth"] = *cp.ConnectionBandwidth
			}
			if cp.EnableBgp != nil {
				entry["enableBgp"] = *cp.EnableBgp
			}
			if cp.RoutingWeight != nil {
				entry["routingWeight"] = *cp.RoutingWeight
			}
			if cp.VPNConnectionProtocolType != nil && *cp.VPNConnectionProtocolType != "" {
				entry["vpnConnectionProtocolType"] = canonicalizeEnum(string(*cp.VPNConnectionProtocolType), vpnConnectionProtocols...)
			}
		}
		out = append(out, entry)
	}
	return out
}

// vpnGatewayConnectionsFromProps builds the request-side connection list.
func vpnGatewayConnectionsFromProps(conns []vpnGatewayConnectionProps) []*armnetwork.VPNConnection {
	if len(conns) == 0 {
		return nil
	}
	out := make([]*armnetwork.VPNConnection, 0, len(conns))
	for i := range conns {
		conn := conns[i]
		armConn := &armnetwork.VPNConnection{
			Name: to.Ptr(conn.Name),
			Properties: &armnetwork.VPNConnectionProperties{
				RemoteVPNSite:       &armnetwork.SubResource{ID: to.Ptr(conn.RemoteVpnSiteID)},
				ConnectionBandwidth: conn.ConnectionBandwidth,
				EnableBgp:           conn.EnableBgp,
				RoutingWeight:       conn.RoutingWeight,
				SharedKey:           conn.SharedKey,
			},
		}
		if conn.VpnConnectionProtocolType != nil {
			armConn.Properties.VPNConnectionProtocolType = to.Ptr(armnetwork.VirtualNetworkGatewayConnectionProtocol(*conn.VpnConnectionProtocolType))
		}
		out = append(out, armConn)
	}
	return out
}

// vpnGatewayParams builds the request body shared by create and update.
func vpnGatewayParams(props vpnGatewayProps, payload json.RawMessage) armnetwork.VPNGateway {
	params := armnetwork.VPNGateway{
		Location: to.Ptr(props.Location),
		Properties: &armnetwork.VPNGatewayProperties{
			VirtualHub:                      &armnetwork.SubResource{ID: to.Ptr(props.VirtualHubID)},
			VPNGatewayScaleUnit:             props.VpnGatewayScaleUnit,
			EnableBgpRouteTranslationForNat: props.EnableBgpRouteTranslationForNat,
			IsRoutingPreferenceInternet:     props.IsRoutingPreferenceInternet,
			Connections:                     vpnGatewayConnectionsFromProps(props.Connections),
		},
	}
	if bgp := props.BgpSettings; bgp != nil {
		params.Properties.BgpSettings = &armnetwork.BgpSettings{
			Asn:        bgp.Asn,
			PeerWeight: bgp.PeerWeight,
		}
	}

	if tags := formaeTagsToAzureTags(payload); len(tags) > 0 {
		params.Tags = tags
	}

	return params
}

// upsert backs both Create and Update: BeginUpdateTags cannot touch the scale unit
// or the connections, so an update is another CreateOrUpdate.
func (r *VpnGateway) upsert(ctx context.Context, payload json.RawMessage, label string) (*runtime.Poller[armnetwork.VPNGatewaysClientCreateOrUpdateResponse], vpnGatewayProps, string, error) {
	var props vpnGatewayProps
	if err := json.Unmarshal(payload, &props); err != nil {
		return nil, props, "", fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return nil, props, "", fmt.Errorf("resourceGroupName is required")
	}
	if props.Location == "" {
		return nil, props, "", fmt.Errorf("location is required")
	}
	if props.VirtualHubID == "" {
		return nil, props, "", fmt.Errorf("virtualHubId is required")
	}
	for _, conn := range props.Connections {
		if conn.Name == "" {
			return nil, props, "", fmt.Errorf("every connections entry needs a name")
		}
		if conn.RemoteVpnSiteID == "" {
			return nil, props, "", fmt.Errorf("connections entry %q needs a remoteVpnSiteId", conn.Name)
		}
	}
	name := props.Name
	if name == "" {
		name = label
	}
	if name == "" {
		return nil, props, "", fmt.Errorf("name is required")
	}

	poller, err := r.api.BeginCreateOrUpdate(ctx, props.ResourceGroupName, name,
		vpnGatewayParams(props, payload), nil)
	return poller, props, name, err
}

func (r *VpnGateway) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
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

	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/vpnGateways/%s",
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
		nativeID, propsJSON, err := r.completeFromGateway(&result.VPNGateway)
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

func (r *VpnGateway) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, name, err := vpnGatewayIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := r.api.Get(ctx, rgName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(r.buildPropertiesFromResult(&result.VPNGateway, rgName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeVpnGateway,
		Properties:   string(propsJSON),
	}, nil
}

func (r *VpnGateway) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, _, err := vpnGatewayIDParts(request.NativeID)
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
		propsJSON, err := json.Marshal(r.buildPropertiesFromResult(&result.VPNGateway, rgName))
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

func (r *VpnGateway) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, name, err := vpnGatewayIDParts(request.NativeID)
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

func (r *VpnGateway) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
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
			func(token string) (*runtime.Poller[armnetwork.VPNGatewaysClientCreateOrUpdateResponse], error) {
				return resumePoller[armnetwork.VPNGatewaysClientCreateOrUpdateResponse](r.pipeline, token)
			},
			func(_ context.Context, result armnetwork.VPNGatewaysClientCreateOrUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				return r.completeFromGateway(&result.VPNGateway)
			})
	case lroOpDelete:
		return statusDeleteLRO(ctx, request, &reqID,
			func(token string) (*runtime.Poller[armnetwork.VPNGatewaysClientDeleteResponse], error) {
				return resumePoller[armnetwork.VPNGatewaysClientDeleteResponse](r.pipeline, token)
			}, nil)
	default:
		return nil, fmt.Errorf("unknown operation type: %s", reqID.OperationType)
	}
}

func (r *VpnGateway) completeFromGateway(gateway *armnetwork.VPNGateway) (string, json.RawMessage, error) {
	nativeID := ""
	rgName := ""
	if gateway.ID != nil {
		nativeID = *gateway.ID
		if rg, _, err := vpnGatewayIDParts(*gateway.ID); err == nil {
			rgName = rg
		}
	}
	propsJSON, err := json.Marshal(r.buildPropertiesFromResult(gateway, rgName))
	if err != nil {
		return "", nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return nativeID, propsJSON, nil
}

// List narrows to a resource group when one is supplied and otherwise sweeps the
// whole subscription.
func (r *VpnGateway) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]

	var nativeIDs []string
	if rgName != "" {
		pager := r.api.NewListByResourceGroupPager(rgName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list VPN gateways in resource group %s: %w", rgName, err)
			}
			for _, gateway := range page.Value {
				if gateway.ID != nil {
					nativeIDs = append(nativeIDs, *gateway.ID)
				}
			}
		}
		return &resource.ListResult{NativeIDs: nativeIDs}, nil
	}

	pager := r.api.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list VPN gateways: %w", err)
		}
		for _, gateway := range page.Value {
			if gateway.ID != nil {
				nativeIDs = append(nativeIDs, *gateway.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
