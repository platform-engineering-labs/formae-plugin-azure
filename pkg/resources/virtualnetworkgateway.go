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

const ResourceTypeVirtualNetworkGateway = "AZURE::Network::VirtualNetworkGateway"

// gatewaySubnetName is the only subnet name Azure accepts for a virtual network
// gateway. It is checked before the request goes out so the failure names the real
// problem instead of surfacing ARM's generic rejection.
const gatewaySubnetName = "GatewaySubnet"

// virtualNetworkGatewaysAPI is the armnetwork surface used here. BeginUpdateTags is
// deliberately absent: it cannot resize the SKU or change the BGP settings, so every
// update is a re-PUT.
type virtualNetworkGatewaysAPI interface {
	BeginCreateOrUpdate(ctx context.Context, resourceGroupName string, virtualNetworkGatewayName string, parameters armnetwork.VirtualNetworkGateway, options *armnetwork.VirtualNetworkGatewaysClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.VirtualNetworkGatewaysClientCreateOrUpdateResponse], error)
	Get(ctx context.Context, resourceGroupName string, virtualNetworkGatewayName string, options *armnetwork.VirtualNetworkGatewaysClientGetOptions) (armnetwork.VirtualNetworkGatewaysClientGetResponse, error)
	BeginDelete(ctx context.Context, resourceGroupName string, virtualNetworkGatewayName string, options *armnetwork.VirtualNetworkGatewaysClientBeginDeleteOptions) (*runtime.Poller[armnetwork.VirtualNetworkGatewaysClientDeleteResponse], error)
	NewListPager(resourceGroupName string, options *armnetwork.VirtualNetworkGatewaysClientListOptions) *runtime.Pager[armnetwork.VirtualNetworkGatewaysClientListResponse]
}

func init() {
	registry.Register(ResourceTypeVirtualNetworkGateway, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &VirtualNetworkGateway{
			api:      c.VirtualNetworkGatewaysClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// VirtualNetworkGateway is the provisioner for the classic vnet-scoped gateway
// (Microsoft.Network/virtualNetworkGateways).
type VirtualNetworkGateway struct {
	api      virtualNetworkGatewaysAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

// virtualNetworkGatewayProps mirrors
// schema/pkl/network/virtualnetworkgateway.pkl.
type virtualNetworkGatewayProps struct {
	Name                   string                               `json:"name"`
	ResourceGroupName      string                               `json:"resourceGroupName"`
	Location               string                               `json:"location"`
	GatewayType            string                               `json:"gatewayType"`
	VpnType                string                               `json:"vpnType"`
	SKU                    *virtualNetworkGatewaySkuProps       `json:"sku"`
	IPConfigurations       []virtualNetworkGatewayIPConfigProps `json:"ipConfigurations"`
	ActiveActive           *bool                                `json:"activeActive"`
	EnableBgp              *bool                                `json:"enableBgp"`
	BgpSettings            *virtualNetworkGatewayBgpProps       `json:"bgpSettings"`
	VpnGatewayGeneration   *string                              `json:"vpnGatewayGeneration"`
	VpnClientConfiguration *virtualNetworkGatewayVpnClientProps `json:"vpnClientConfiguration"`
	EnablePrivateIPAddress *bool                                `json:"enablePrivateIpAddress"`
	AllowVirtualWanTraffic *bool                                `json:"allowVirtualWanTraffic"`
	AllowRemoteVnetTraffic *bool                                `json:"allowRemoteVnetTraffic"`
	GatewayDefaultSiteID   *string                              `json:"gatewayDefaultSiteId"`
	CustomRoutes           []string                             `json:"customRoutes"`
}

type virtualNetworkGatewaySkuProps struct {
	Name string `json:"name"`
	Tier string `json:"tier"`
}

type virtualNetworkGatewayIPConfigProps struct {
	Name                      string  `json:"name"`
	SubnetID                  string  `json:"subnetId"`
	PublicIPAddressID         string  `json:"publicIpAddressId"`
	PrivateIPAllocationMethod *string `json:"privateIpAllocationMethod"`
}

type virtualNetworkGatewayBgpProps struct {
	Asn        *int64 `json:"asn"`
	PeerWeight *int32 `json:"peerWeight"`
}

type virtualNetworkGatewayVpnClientProps struct {
	VpnClientAddressPool      []string                             `json:"vpnClientAddressPool"`
	VpnClientProtocols        []string                             `json:"vpnClientProtocols"`
	VpnAuthenticationTypes    []string                             `json:"vpnAuthenticationTypes"`
	VpnClientRootCertificates []virtualNetworkGatewayRootCertProps `json:"vpnClientRootCertificates"`
	RadiusServerAddress       *string                              `json:"radiusServerAddress"`
	RadiusServerSecret        *string                              `json:"radiusServerSecret"`
	AadTenant                 *string                              `json:"aadTenant"`
	AadAudience               *string                              `json:"aadAudience"`
	AadIssuer                 *string                              `json:"aadIssuer"`
}

type virtualNetworkGatewayRootCertProps struct {
	Name           string `json:"name"`
	PublicCertData string `json:"publicCertData"`
}

var (
	// The canonical casing for every enum the gateway echoes back, applied on the
	// read path because ARM is inconsistent about it.
	virtualNetworkGatewayTypes = []string{"Vpn", "ExpressRoute", "LocalGateway"}
	vpnTypes                   = []string{"RouteBased", "PolicyBased"}
	virtualNetworkGatewaySkus  = []string{
		"Basic", "Standard", "HighPerformance", "UltraPerformance",
		"VpnGw1", "VpnGw2", "VpnGw3", "VpnGw4", "VpnGw5",
		"VpnGw1AZ", "VpnGw2AZ", "VpnGw3AZ", "VpnGw4AZ", "VpnGw5AZ",
		"ErGw1AZ", "ErGw2AZ", "ErGw3AZ",
	}
	vpnGatewayGenerations  = []string{"None", "Generation1", "Generation2"}
	vpnClientProtocols     = []string{"IkeV2", "OpenVPN", "SSTP"}
	vpnAuthenticationTypes = []string{"Certificate", "Radius", "AAD"}
	gatewayIPAllocations   = []string{"Dynamic", "Static"}
)

func virtualNetworkGatewayIDParts(resourceID string) (rgName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "virtualnetworkgateways")
	if err != nil {
		return "", "", err
	}
	return rgName, names["virtualnetworkgateways"], nil
}

func (r *VirtualNetworkGateway) buildPropertiesFromResult(gateway *armnetwork.VirtualNetworkGateway, rgName string) map[string]any {
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

	p := gateway.Properties
	if p == nil {
		return props
	}

	if p.GatewayType != nil && *p.GatewayType != "" {
		props["gatewayType"] = canonicalizeEnum(string(*p.GatewayType), virtualNetworkGatewayTypes...)
	}
	if p.VPNType != nil && *p.VPNType != "" {
		props["vpnType"] = canonicalizeEnum(string(*p.VPNType), vpnTypes...)
	}
	if sku := p.SKU; sku != nil {
		entry := make(map[string]any)
		if sku.Name != nil && *sku.Name != "" {
			entry["name"] = canonicalizeEnum(string(*sku.Name), virtualNetworkGatewaySkus...)
		}
		if sku.Tier != nil && *sku.Tier != "" {
			entry["tier"] = canonicalizeEnum(string(*sku.Tier), virtualNetworkGatewaySkus...)
		}
		if len(entry) > 0 {
			// sku.capacity is the instance count Azure derives from the SKU.
			props["sku"] = entry
		}
	}
	if p.Active != nil {
		props["activeActive"] = *p.Active
	}
	if p.EnableBgp != nil {
		props["enableBgp"] = *p.EnableBgp
	}
	if p.VPNGatewayGeneration != nil && *p.VPNGatewayGeneration != "" {
		props["vpnGatewayGeneration"] = canonicalizeEnum(string(*p.VPNGatewayGeneration), vpnGatewayGenerations...)
	}
	if p.EnablePrivateIPAddress != nil {
		props["enablePrivateIpAddress"] = *p.EnablePrivateIPAddress
	}
	if p.AllowVirtualWanTraffic != nil {
		props["allowVirtualWanTraffic"] = *p.AllowVirtualWanTraffic
	}
	if p.AllowRemoteVnetTraffic != nil {
		props["allowRemoteVnetTraffic"] = *p.AllowRemoteVnetTraffic
	}
	if p.GatewayDefaultSite != nil && p.GatewayDefaultSite.ID != nil {
		props["gatewayDefaultSiteId"] = *p.GatewayDefaultSite.ID
	}
	if routes := p.CustomRoutes; routes != nil {
		if prefixes := stringsFromPointers(routes.AddressPrefixes); prefixes != nil {
			props["customRoutes"] = prefixes
		}
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
		// bgpPeeringAddress and bgpPeeringAddresses are allocated by Azure out of the
		// GatewaySubnet, so they are dropped rather than compared.
	}
	if configs := virtualNetworkGatewayIPConfigsToProps(p.IPConfigurations); len(configs) > 0 {
		props["ipConfigurations"] = configs
	}
	if vpnClient := virtualNetworkGatewayVpnClientToProps(p.VPNClientConfiguration); len(vpnClient) > 0 {
		props["vpnClientConfiguration"] = vpnClient
	}
	// provisioningState, resourceGuid, inboundDnsForwardingEndpoint and natRules are
	// service state or not modelled.

	return props
}

// virtualNetworkGatewayIPConfigsToProps is the read-path inverse of
// virtualNetworkGatewayIPConfigsFromProps. The per-config ARM ID, etag,
// provisioningState and the private IP Azure picks are all service-assigned.
func virtualNetworkGatewayIPConfigsToProps(configs []*armnetwork.VirtualNetworkGatewayIPConfiguration) []map[string]any {
	if len(configs) == 0 {
		return nil
	}
	out := make([]map[string]any, 0, len(configs))
	for _, cfg := range configs {
		if cfg == nil {
			continue
		}
		entry := make(map[string]any)
		if cfg.Name != nil {
			entry["name"] = *cfg.Name
		}
		if cp := cfg.Properties; cp != nil {
			if cp.Subnet != nil && cp.Subnet.ID != nil {
				entry["subnetId"] = *cp.Subnet.ID
			}
			if cp.PublicIPAddress != nil && cp.PublicIPAddress.ID != nil {
				entry["publicIpAddressId"] = *cp.PublicIPAddress.ID
			}
			if cp.PrivateIPAllocationMethod != nil && *cp.PrivateIPAllocationMethod != "" {
				entry["privateIpAllocationMethod"] = canonicalizeEnum(string(*cp.PrivateIPAllocationMethod), gatewayIPAllocations...)
			}
		}
		out = append(out, entry)
	}
	return out
}

// virtualNetworkGatewayIPConfigsFromProps builds the request-side IP configuration
// list.
func virtualNetworkGatewayIPConfigsFromProps(configs []virtualNetworkGatewayIPConfigProps) []*armnetwork.VirtualNetworkGatewayIPConfiguration {
	if len(configs) == 0 {
		return nil
	}
	out := make([]*armnetwork.VirtualNetworkGatewayIPConfiguration, 0, len(configs))
	for i := range configs {
		cfg := configs[i]
		armCfg := &armnetwork.VirtualNetworkGatewayIPConfiguration{
			Name: to.Ptr(cfg.Name),
			Properties: &armnetwork.VirtualNetworkGatewayIPConfigurationPropertiesFormat{
				Subnet:          &armnetwork.SubResource{ID: to.Ptr(cfg.SubnetID)},
				PublicIPAddress: &armnetwork.SubResource{ID: to.Ptr(cfg.PublicIPAddressID)},
			},
		}
		if cfg.PrivateIPAllocationMethod != nil {
			armCfg.Properties.PrivateIPAllocationMethod = to.Ptr(armnetwork.IPAllocationMethod(*cfg.PrivateIPAllocationMethod))
		}
		out = append(out, armCfg)
	}
	return out
}

// virtualNetworkGatewayVpnClientToProps is the read-path inverse of
// virtualNetworkGatewayVpnClientFromProps. radiusServerSecret is write-only and
// never surfaced, and the per-certificate ARM ID / etag / provisioningState are
// service-assigned.
func virtualNetworkGatewayVpnClientToProps(cfg *armnetwork.VPNClientConfiguration) map[string]any {
	if cfg == nil {
		return nil
	}
	out := make(map[string]any)
	if pool := cfg.VPNClientAddressPool; pool != nil {
		if prefixes := stringsFromPointers(pool.AddressPrefixes); prefixes != nil {
			out["vpnClientAddressPool"] = prefixes
		}
	}
	if len(cfg.VPNClientProtocols) > 0 {
		protocols := make([]string, 0, len(cfg.VPNClientProtocols))
		for _, protocol := range cfg.VPNClientProtocols {
			if protocol == nil || *protocol == "" {
				continue
			}
			protocols = append(protocols, canonicalizeEnum(string(*protocol), vpnClientProtocols...))
		}
		if len(protocols) > 0 {
			out["vpnClientProtocols"] = protocols
		}
	}
	if len(cfg.VPNAuthenticationTypes) > 0 {
		types := make([]string, 0, len(cfg.VPNAuthenticationTypes))
		for _, authType := range cfg.VPNAuthenticationTypes {
			if authType == nil || *authType == "" {
				continue
			}
			types = append(types, canonicalizeEnum(string(*authType), vpnAuthenticationTypes...))
		}
		if len(types) > 0 {
			out["vpnAuthenticationTypes"] = types
		}
	}
	if len(cfg.VPNClientRootCertificates) > 0 {
		certs := make([]map[string]any, 0, len(cfg.VPNClientRootCertificates))
		for _, cert := range cfg.VPNClientRootCertificates {
			if cert == nil {
				continue
			}
			entry := make(map[string]any)
			if cert.Name != nil {
				entry["name"] = *cert.Name
			}
			if cert.Properties != nil && cert.Properties.PublicCertData != nil {
				entry["publicCertData"] = *cert.Properties.PublicCertData
			}
			certs = append(certs, entry)
		}
		if len(certs) > 0 {
			out["vpnClientRootCertificates"] = certs
		}
	}
	if cfg.RadiusServerAddress != nil && *cfg.RadiusServerAddress != "" {
		out["radiusServerAddress"] = *cfg.RadiusServerAddress
	}
	if cfg.AADTenant != nil && *cfg.AADTenant != "" {
		out["aadTenant"] = *cfg.AADTenant
	}
	if cfg.AADAudience != nil && *cfg.AADAudience != "" {
		out["aadAudience"] = *cfg.AADAudience
	}
	if cfg.AADIssuer != nil && *cfg.AADIssuer != "" {
		out["aadIssuer"] = *cfg.AADIssuer
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// virtualNetworkGatewayVpnClientFromProps builds the request-side point-to-site
// configuration.
func virtualNetworkGatewayVpnClientFromProps(cfg *virtualNetworkGatewayVpnClientProps) *armnetwork.VPNClientConfiguration {
	if cfg == nil {
		return nil
	}
	out := &armnetwork.VPNClientConfiguration{
		RadiusServerAddress: cfg.RadiusServerAddress,
		RadiusServerSecret:  cfg.RadiusServerSecret,
		AADTenant:           cfg.AadTenant,
		AADAudience:         cfg.AadAudience,
		AADIssuer:           cfg.AadIssuer,
	}
	if prefixes := stringPointers(cfg.VpnClientAddressPool); prefixes != nil {
		out.VPNClientAddressPool = &armnetwork.AddressSpace{AddressPrefixes: prefixes}
	}
	for _, protocol := range cfg.VpnClientProtocols {
		out.VPNClientProtocols = append(out.VPNClientProtocols, to.Ptr(armnetwork.VPNClientProtocol(protocol)))
	}
	for _, authType := range cfg.VpnAuthenticationTypes {
		out.VPNAuthenticationTypes = append(out.VPNAuthenticationTypes, to.Ptr(armnetwork.VPNAuthenticationType(authType)))
	}
	for i := range cfg.VpnClientRootCertificates {
		cert := cfg.VpnClientRootCertificates[i]
		out.VPNClientRootCertificates = append(out.VPNClientRootCertificates, &armnetwork.VPNClientRootCertificate{
			Name: to.Ptr(cert.Name),
			Properties: &armnetwork.VPNClientRootCertificatePropertiesFormat{
				PublicCertData: to.Ptr(cert.PublicCertData),
			},
		})
	}
	return out
}

// virtualNetworkGatewayParams builds the request body shared by create and update.
func virtualNetworkGatewayParams(props virtualNetworkGatewayProps, payload json.RawMessage) armnetwork.VirtualNetworkGateway {
	params := armnetwork.VirtualNetworkGateway{
		Location: to.Ptr(props.Location),
		Properties: &armnetwork.VirtualNetworkGatewayPropertiesFormat{
			GatewayType:            to.Ptr(armnetwork.VirtualNetworkGatewayType(props.GatewayType)),
			VPNType:                to.Ptr(armnetwork.VPNType(props.VpnType)),
			IPConfigurations:       virtualNetworkGatewayIPConfigsFromProps(props.IPConfigurations),
			Active:                 props.ActiveActive,
			EnableBgp:              props.EnableBgp,
			EnablePrivateIPAddress: props.EnablePrivateIPAddress,
			AllowVirtualWanTraffic: props.AllowVirtualWanTraffic,
			AllowRemoteVnetTraffic: props.AllowRemoteVnetTraffic,
			VPNClientConfiguration: virtualNetworkGatewayVpnClientFromProps(props.VpnClientConfiguration),
		},
	}
	if sku := props.SKU; sku != nil {
		params.Properties.SKU = &armnetwork.VirtualNetworkGatewaySKU{
			Name: to.Ptr(armnetwork.VirtualNetworkGatewaySKUName(sku.Name)),
			Tier: to.Ptr(armnetwork.VirtualNetworkGatewaySKUTier(sku.Tier)),
		}
	}
	if props.VpnGatewayGeneration != nil {
		params.Properties.VPNGatewayGeneration = to.Ptr(armnetwork.VPNGatewayGeneration(*props.VpnGatewayGeneration))
	}
	if bgp := props.BgpSettings; bgp != nil {
		params.Properties.BgpSettings = &armnetwork.BgpSettings{
			Asn:        bgp.Asn,
			PeerWeight: bgp.PeerWeight,
		}
	}
	if props.GatewayDefaultSiteID != nil && *props.GatewayDefaultSiteID != "" {
		params.Properties.GatewayDefaultSite = &armnetwork.SubResource{ID: props.GatewayDefaultSiteID}
	}
	if routes := stringPointers(props.CustomRoutes); routes != nil {
		params.Properties.CustomRoutes = &armnetwork.AddressSpace{AddressPrefixes: routes}
	}

	if tags := formaeTagsToAzureTags(payload); len(tags) > 0 {
		params.Tags = tags
	}

	return params
}

// upsert backs both Create and Update: BeginUpdateTags cannot resize the SKU or
// change the BGP settings, so an update is another CreateOrUpdate.
func (r *VirtualNetworkGateway) upsert(ctx context.Context, payload json.RawMessage, label string) (*runtime.Poller[armnetwork.VirtualNetworkGatewaysClientCreateOrUpdateResponse], virtualNetworkGatewayProps, string, error) {
	var props virtualNetworkGatewayProps
	if err := json.Unmarshal(payload, &props); err != nil {
		return nil, props, "", fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return nil, props, "", fmt.Errorf("resourceGroupName is required")
	}
	if props.Location == "" {
		return nil, props, "", fmt.Errorf("location is required")
	}
	if props.GatewayType == "" {
		return nil, props, "", fmt.Errorf("gatewayType is required")
	}
	if props.VpnType == "" {
		return nil, props, "", fmt.Errorf("vpnType is required")
	}
	if props.SKU == nil || props.SKU.Name == "" {
		return nil, props, "", fmt.Errorf("sku is required")
	}
	if len(props.IPConfigurations) == 0 {
		return nil, props, "", fmt.Errorf("ipConfigurations is required")
	}
	for _, cfg := range props.IPConfigurations {
		if cfg.Name == "" {
			return nil, props, "", fmt.Errorf("every ipConfigurations entry needs a name")
		}
		if cfg.SubnetID == "" {
			return nil, props, "", fmt.Errorf("ipConfigurations entry %q needs a subnetId", cfg.Name)
		}
		if cfg.PublicIPAddressID == "" {
			return nil, props, "", fmt.Errorf("ipConfigurations entry %q needs a publicIpAddressId", cfg.Name)
		}
		// Azure only accepts a gateway in a subnet literally named GatewaySubnet.
		// Catching it here turns a slow ARM rejection into an immediate, specific
		// error.
		if subnet, ok := lastARMSegment(cfg.SubnetID); ok && subnet != gatewaySubnetName {
			return nil, props, "", fmt.Errorf("ipConfigurations entry %q references subnet %q: a virtual network gateway requires a subnet named exactly %s",
				cfg.Name, subnet, gatewaySubnetName)
		}
	}
	// Active-active needs a second front end, and Azure rejects the combination
	// rather than silently ignoring it.
	if props.ActiveActive != nil && *props.ActiveActive && len(props.IPConfigurations) < 2 {
		return nil, props, "", fmt.Errorf("activeActive requires two ipConfigurations entries, got %d", len(props.IPConfigurations))
	}
	name := props.Name
	if name == "" {
		name = label
	}
	if name == "" {
		return nil, props, "", fmt.Errorf("name is required")
	}

	poller, err := r.api.BeginCreateOrUpdate(ctx, props.ResourceGroupName, name,
		virtualNetworkGatewayParams(props, payload), nil)
	return poller, props, name, err
}

func (r *VirtualNetworkGateway) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
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

	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/virtualNetworkGateways/%s",
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
		nativeID, propsJSON, err := r.completeFromGateway(&result.VirtualNetworkGateway)
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

func (r *VirtualNetworkGateway) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, name, err := virtualNetworkGatewayIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := r.api.Get(ctx, rgName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(r.buildPropertiesFromResult(&result.VirtualNetworkGateway, rgName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeVirtualNetworkGateway,
		Properties:   string(propsJSON),
	}, nil
}

func (r *VirtualNetworkGateway) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, _, err := virtualNetworkGatewayIDParts(request.NativeID)
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
		propsJSON, err := json.Marshal(r.buildPropertiesFromResult(&result.VirtualNetworkGateway, rgName))
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

func (r *VirtualNetworkGateway) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, name, err := virtualNetworkGatewayIDParts(request.NativeID)
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

func (r *VirtualNetworkGateway) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
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
			func(token string) (*runtime.Poller[armnetwork.VirtualNetworkGatewaysClientCreateOrUpdateResponse], error) {
				return resumePoller[armnetwork.VirtualNetworkGatewaysClientCreateOrUpdateResponse](r.pipeline, token)
			},
			func(_ context.Context, result armnetwork.VirtualNetworkGatewaysClientCreateOrUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				return r.completeFromGateway(&result.VirtualNetworkGateway)
			})
	case lroOpDelete:
		return statusDeleteLRO(ctx, request, &reqID,
			func(token string) (*runtime.Poller[armnetwork.VirtualNetworkGatewaysClientDeleteResponse], error) {
				return resumePoller[armnetwork.VirtualNetworkGatewaysClientDeleteResponse](r.pipeline, token)
			}, nil)
	default:
		return nil, fmt.Errorf("unknown operation type: %s", reqID.OperationType)
	}
}

func (r *VirtualNetworkGateway) completeFromGateway(gateway *armnetwork.VirtualNetworkGateway) (string, json.RawMessage, error) {
	nativeID := ""
	rgName := ""
	if gateway.ID != nil {
		nativeID = *gateway.ID
		if rg, _, err := virtualNetworkGatewayIDParts(*gateway.ID); err == nil {
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
// virtual network gateways.
func (r *VirtualNetworkGateway) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	if rgName == "" {
		return &resource.ListResult{}, nil
	}

	var nativeIDs []string
	pager := r.api.NewListPager(rgName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list virtual network gateways in resource group %s: %w", rgName, err)
		}
		for _, gateway := range page.Value {
			if gateway.ID != nil {
				nativeIDs = append(nativeIDs, *gateway.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
