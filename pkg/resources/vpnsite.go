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

const ResourceTypeVpnSite = "AZURE::Network::VpnSite"

// vpnSitesAPI is the armnetwork surface used here. UpdateTags is deliberately
// absent: it cannot change the address space or the links, so every update is a
// re-PUT.
type vpnSitesAPI interface {
	BeginCreateOrUpdate(ctx context.Context, resourceGroupName string, vpnSiteName string, vpnSiteParameters armnetwork.VPNSite, options *armnetwork.VPNSitesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.VPNSitesClientCreateOrUpdateResponse], error)
	Get(ctx context.Context, resourceGroupName string, vpnSiteName string, options *armnetwork.VPNSitesClientGetOptions) (armnetwork.VPNSitesClientGetResponse, error)
	BeginDelete(ctx context.Context, resourceGroupName string, vpnSiteName string, options *armnetwork.VPNSitesClientBeginDeleteOptions) (*runtime.Poller[armnetwork.VPNSitesClientDeleteResponse], error)
	NewListByResourceGroupPager(resourceGroupName string, options *armnetwork.VPNSitesClientListByResourceGroupOptions) *runtime.Pager[armnetwork.VPNSitesClientListByResourceGroupResponse]
	NewListPager(options *armnetwork.VPNSitesClientListOptions) *runtime.Pager[armnetwork.VPNSitesClientListResponse]
}

func init() {
	registry.Register(ResourceTypeVpnSite, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &VpnSite{
			api:      c.VPNSitesClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// VpnSite is the provisioner for the Virtual WAN description of a branch
// (Microsoft.Network/vpnSites).
type VpnSite struct {
	api      vpnSitesAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

// vpnSiteProps mirrors schema/pkl/network/vpnsite.pkl.
type vpnSiteProps struct {
	Name              string                      `json:"name"`
	ResourceGroupName string                      `json:"resourceGroupName"`
	Location          string                      `json:"location"`
	VirtualWanID      string                      `json:"virtualWanId"`
	AddressSpace      []string                    `json:"addressSpace"`
	DeviceProperties  *vpnSiteDevicePropertyProps `json:"deviceProperties"`
	IPAddress         *string                     `json:"ipAddress"`
	VpnSiteLinks      []vpnSiteLinkProps          `json:"vpnSiteLinks"`
}

type vpnSiteDevicePropertyProps struct {
	DeviceVendor    *string `json:"deviceVendor"`
	DeviceModel     *string `json:"deviceModel"`
	LinkSpeedInMbps *int32  `json:"linkSpeedInMbps"`
}

type vpnSiteLinkProps struct {
	Name           string                    `json:"name"`
	IPAddress      *string                   `json:"ipAddress"`
	Fqdn           *string                   `json:"fqdn"`
	LinkProperties *vpnSiteLinkProviderProps `json:"linkProperties"`
	BgpProperties  *vpnSiteLinkBgpProps      `json:"bgpProperties"`
}

type vpnSiteLinkProviderProps struct {
	LinkProviderName *string `json:"linkProviderName"`
	LinkSpeedInMbps  *int32  `json:"linkSpeedInMbps"`
}

type vpnSiteLinkBgpProps struct {
	Asn               *int64 `json:"asn"`
	BgpPeeringAddress string `json:"bgpPeeringAddress"`
}

func vpnSiteIDParts(resourceID string) (rgName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "vpnsites")
	if err != nil {
		return "", "", err
	}
	return rgName, names["vpnsites"], nil
}

func (r *VpnSite) buildPropertiesFromResult(site *armnetwork.VPNSite, rgName string) map[string]any {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName

	if site.ID != nil {
		props["id"] = *site.ID
	}
	if site.Name != nil {
		props["name"] = *site.Name
	}
	if site.Location != nil {
		props["location"] = normalizeAzureLocation(*site.Location)
	}
	if tags := azureTagsToFormaeTags(site.Tags); len(tags) > 0 {
		props["Tags"] = tags
	}

	if p := site.Properties; p != nil {
		if p.VirtualWan != nil && p.VirtualWan.ID != nil {
			props["virtualWanId"] = *p.VirtualWan.ID
		}
		if space := p.AddressSpace; space != nil {
			if prefixes := stringsFromPointers(space.AddressPrefixes); prefixes != nil {
				props["addressSpace"] = prefixes
			}
		}
		if p.IPAddress != nil && *p.IPAddress != "" {
			props["ipAddress"] = *p.IPAddress
		}
		if dev := p.DeviceProperties; dev != nil {
			device := make(map[string]any)
			if dev.DeviceVendor != nil && *dev.DeviceVendor != "" {
				device["deviceVendor"] = *dev.DeviceVendor
			}
			if dev.DeviceModel != nil && *dev.DeviceModel != "" {
				device["deviceModel"] = *dev.DeviceModel
			}
			if dev.LinkSpeedInMbps != nil {
				device["linkSpeedInMbps"] = *dev.LinkSpeedInMbps
			}
			if len(device) > 0 {
				props["deviceProperties"] = device
			}
		}
		if links := vpnSiteLinksToProps(p.VPNSiteLinks); len(links) > 0 {
			props["vpnSiteLinks"] = links
		}
		// provisioningState, siteKey, isSecuritySite and o365Policy are service state
		// or not modelled, and the per-link id / etag / type / provisioningState are
		// assigned by ARM.
	}

	return props
}

// vpnSiteLinksToProps is the read-path inverse of vpnSiteLinksFromProps. It emits
// only the modelled fields: the per-link ARM ID, etag, type and provisioningState
// are service-assigned and would read as drift.
func vpnSiteLinksToProps(links []*armnetwork.VPNSiteLink) []map[string]any {
	if len(links) == 0 {
		return nil
	}
	out := make([]map[string]any, 0, len(links))
	for _, link := range links {
		if link == nil {
			continue
		}
		entry := make(map[string]any)
		if link.Name != nil {
			entry["name"] = *link.Name
		}
		if lp := link.Properties; lp != nil {
			if lp.IPAddress != nil && *lp.IPAddress != "" {
				entry["ipAddress"] = *lp.IPAddress
			}
			if lp.Fqdn != nil && *lp.Fqdn != "" {
				entry["fqdn"] = *lp.Fqdn
			}
			if provider := lp.LinkProperties; provider != nil {
				linkProps := make(map[string]any)
				if provider.LinkProviderName != nil && *provider.LinkProviderName != "" {
					linkProps["linkProviderName"] = *provider.LinkProviderName
				}
				if provider.LinkSpeedInMbps != nil {
					linkProps["linkSpeedInMbps"] = *provider.LinkSpeedInMbps
				}
				if len(linkProps) > 0 {
					entry["linkProperties"] = linkProps
				}
			}
			if bgp := lp.BgpProperties; bgp != nil {
				bgpProps := make(map[string]any)
				if bgp.Asn != nil {
					bgpProps["asn"] = *bgp.Asn
				}
				if bgp.BgpPeeringAddress != nil {
					bgpProps["bgpPeeringAddress"] = *bgp.BgpPeeringAddress
				}
				if len(bgpProps) > 0 {
					entry["bgpProperties"] = bgpProps
				}
			}
		}
		out = append(out, entry)
	}
	return out
}

// vpnSiteLinksFromProps builds the request-side link list.
func vpnSiteLinksFromProps(links []vpnSiteLinkProps) []*armnetwork.VPNSiteLink {
	if len(links) == 0 {
		return nil
	}
	out := make([]*armnetwork.VPNSiteLink, 0, len(links))
	for i := range links {
		link := links[i]
		armLink := &armnetwork.VPNSiteLink{
			Name: to.Ptr(link.Name),
			Properties: &armnetwork.VPNSiteLinkProperties{
				IPAddress: link.IPAddress,
				Fqdn:      link.Fqdn,
			},
		}
		if provider := link.LinkProperties; provider != nil {
			armLink.Properties.LinkProperties = &armnetwork.VPNLinkProviderProperties{
				LinkProviderName: provider.LinkProviderName,
				LinkSpeedInMbps:  provider.LinkSpeedInMbps,
			}
		}
		if bgp := link.BgpProperties; bgp != nil {
			armLink.Properties.BgpProperties = &armnetwork.VPNLinkBgpSettings{
				Asn:               bgp.Asn,
				BgpPeeringAddress: to.Ptr(bgp.BgpPeeringAddress),
			}
		}
		out = append(out, armLink)
	}
	return out
}

// vpnSiteParams builds the request body shared by create and update.
func vpnSiteParams(props vpnSiteProps, payload json.RawMessage) armnetwork.VPNSite {
	params := armnetwork.VPNSite{
		Location: to.Ptr(props.Location),
		Properties: &armnetwork.VPNSiteProperties{
			VirtualWan:   &armnetwork.SubResource{ID: to.Ptr(props.VirtualWanID)},
			IPAddress:    props.IPAddress,
			VPNSiteLinks: vpnSiteLinksFromProps(props.VpnSiteLinks),
		},
	}
	if prefixes := stringPointers(props.AddressSpace); prefixes != nil {
		params.Properties.AddressSpace = &armnetwork.AddressSpace{AddressPrefixes: prefixes}
	}
	if dev := props.DeviceProperties; dev != nil {
		params.Properties.DeviceProperties = &armnetwork.DeviceProperties{
			DeviceVendor:    dev.DeviceVendor,
			DeviceModel:     dev.DeviceModel,
			LinkSpeedInMbps: dev.LinkSpeedInMbps,
		}
	}

	if tags := formaeTagsToAzureTags(payload); len(tags) > 0 {
		params.Tags = tags
	}

	return params
}

// upsert backs both Create and Update: UpdateTags cannot touch the address space or
// the links, so an update is another CreateOrUpdate.
func (r *VpnSite) upsert(ctx context.Context, payload json.RawMessage, label string) (*runtime.Poller[armnetwork.VPNSitesClientCreateOrUpdateResponse], vpnSiteProps, string, error) {
	var props vpnSiteProps
	if err := json.Unmarshal(payload, &props); err != nil {
		return nil, props, "", fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return nil, props, "", fmt.Errorf("resourceGroupName is required")
	}
	if props.Location == "" {
		return nil, props, "", fmt.Errorf("location is required")
	}
	if props.VirtualWanID == "" {
		return nil, props, "", fmt.Errorf("virtualWanId is required")
	}
	// ARM accepts a site addressed by a bare ipAddress or by links, but a site with
	// neither has no endpoint and no connection can ever target it.
	if props.IPAddress == nil && len(props.VpnSiteLinks) == 0 {
		return nil, props, "", fmt.Errorf("one of ipAddress or vpnSiteLinks is required")
	}
	for _, link := range props.VpnSiteLinks {
		if link.Name == "" {
			return nil, props, "", fmt.Errorf("every vpnSiteLinks entry needs a name")
		}
		if link.IPAddress == nil && link.Fqdn == nil {
			return nil, props, "", fmt.Errorf("vpnSiteLinks entry %q needs one of ipAddress or fqdn", link.Name)
		}
		if link.IPAddress != nil && link.Fqdn != nil {
			return nil, props, "", fmt.Errorf("vpnSiteLinks entry %q sets both ipAddress and fqdn, which are mutually exclusive", link.Name)
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
		vpnSiteParams(props, payload), nil)
	return poller, props, name, err
}

func (r *VpnSite) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
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

	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/vpnSites/%s",
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
		nativeID, propsJSON, err := r.completeFromSite(&result.VPNSite)
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

func (r *VpnSite) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, name, err := vpnSiteIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := r.api.Get(ctx, rgName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(r.buildPropertiesFromResult(&result.VPNSite, rgName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeVpnSite,
		Properties:   string(propsJSON),
	}, nil
}

func (r *VpnSite) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, _, err := vpnSiteIDParts(request.NativeID)
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
		propsJSON, err := json.Marshal(r.buildPropertiesFromResult(&result.VPNSite, rgName))
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

func (r *VpnSite) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, name, err := vpnSiteIDParts(request.NativeID)
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

func (r *VpnSite) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
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
			func(token string) (*runtime.Poller[armnetwork.VPNSitesClientCreateOrUpdateResponse], error) {
				return resumePoller[armnetwork.VPNSitesClientCreateOrUpdateResponse](r.pipeline, token)
			},
			func(_ context.Context, result armnetwork.VPNSitesClientCreateOrUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				return r.completeFromSite(&result.VPNSite)
			})
	case lroOpDelete:
		return statusDeleteLRO(ctx, request, &reqID,
			func(token string) (*runtime.Poller[armnetwork.VPNSitesClientDeleteResponse], error) {
				return resumePoller[armnetwork.VPNSitesClientDeleteResponse](r.pipeline, token)
			}, nil)
	default:
		return nil, fmt.Errorf("unknown operation type: %s", reqID.OperationType)
	}
}

func (r *VpnSite) completeFromSite(site *armnetwork.VPNSite) (string, json.RawMessage, error) {
	nativeID := ""
	rgName := ""
	if site.ID != nil {
		nativeID = *site.ID
		if rg, _, err := vpnSiteIDParts(*site.ID); err == nil {
			rgName = rg
		}
	}
	propsJSON, err := json.Marshal(r.buildPropertiesFromResult(site, rgName))
	if err != nil {
		return "", nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return nativeID, propsJSON, nil
}

// List narrows to a resource group when one is supplied and otherwise sweeps the
// whole subscription.
func (r *VpnSite) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]

	var nativeIDs []string
	if rgName != "" {
		pager := r.api.NewListByResourceGroupPager(rgName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list VPN sites in resource group %s: %w", rgName, err)
			}
			for _, site := range page.Value {
				if site.ID != nil {
					nativeIDs = append(nativeIDs, *site.ID)
				}
			}
		}
		return &resource.ListResult{NativeIDs: nativeIDs}, nil
	}

	pager := r.api.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list VPN sites: %w", err)
		}
		for _, site := range page.Value {
			if site.ID != nil {
				nativeIDs = append(nativeIDs, *site.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
