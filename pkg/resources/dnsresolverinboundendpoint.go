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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/dnsresolver/armdnsresolver"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeDNSResolverInboundEndpoint = "AZURE::Network::DnsResolverInboundEndpoint"

// dnsResolverInboundEndpointsAPI is the armdnsresolver surface used here. As with
// the resolver itself, InboundEndpointPatch carries tags and nothing else, so
// every other property is createOnly in the schema.
type dnsResolverInboundEndpointsAPI interface {
	BeginCreateOrUpdate(ctx context.Context, resourceGroupName string, dnsResolverName string, inboundEndpointName string, parameters armdnsresolver.InboundEndpoint, options *armdnsresolver.InboundEndpointsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armdnsresolver.InboundEndpointsClientCreateOrUpdateResponse], error)
	Get(ctx context.Context, resourceGroupName string, dnsResolverName string, inboundEndpointName string, options *armdnsresolver.InboundEndpointsClientGetOptions) (armdnsresolver.InboundEndpointsClientGetResponse, error)
	BeginUpdate(ctx context.Context, resourceGroupName string, dnsResolverName string, inboundEndpointName string, parameters armdnsresolver.InboundEndpointPatch, options *armdnsresolver.InboundEndpointsClientBeginUpdateOptions) (*runtime.Poller[armdnsresolver.InboundEndpointsClientUpdateResponse], error)
	BeginDelete(ctx context.Context, resourceGroupName string, dnsResolverName string, inboundEndpointName string, options *armdnsresolver.InboundEndpointsClientBeginDeleteOptions) (*runtime.Poller[armdnsresolver.InboundEndpointsClientDeleteResponse], error)
	NewListPager(resourceGroupName string, dnsResolverName string, options *armdnsresolver.InboundEndpointsClientListOptions) *runtime.Pager[armdnsresolver.InboundEndpointsClientListResponse]
}

func init() {
	registry.Register(ResourceTypeDNSResolverInboundEndpoint, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &DNSResolverInboundEndpoint{
			api:      c.DNSResolverInboundEndpointsClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// DNSResolverInboundEndpoint is the provisioner for inbound endpoints on an Azure
// DNS Private Resolver (Microsoft.Network/dnsResolvers/inboundEndpoints).
type DNSResolverInboundEndpoint struct {
	api      dnsResolverInboundEndpointsAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

// dnsResolverInboundEndpointProps mirrors
// schema/pkl/network/dnsresolverinboundendpoint.pkl.
type dnsResolverInboundEndpointProps struct {
	Name              string                       `json:"name"`
	Location          string                       `json:"location"`
	ResourceGroupName string                       `json:"resourceGroupName"`
	DNSResolverName   string                       `json:"dnsResolverName"`
	IPConfigurations  []dnsResolverIPConfiguration `json:"ipConfigurations"`
}

type dnsResolverIPConfiguration struct {
	SubnetID                  string `json:"subnetId"`
	PrivateIPAddress          string `json:"privateIpAddress"`
	PrivateIPAllocationMethod string `json:"privateIpAllocationMethod"`
}

func dnsResolverInboundEndpointIDParts(resourceID string) (rgName, resolverName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "dnsresolvers", "inboundendpoints")
	if err != nil {
		return "", "", "", err
	}
	return rgName, names["dnsresolvers"], names["inboundendpoints"], nil
}

func (d *DNSResolverInboundEndpoint) buildPropertiesFromResult(endpoint *armdnsresolver.InboundEndpoint, rgName, resolverName string) map[string]any {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	props["dnsResolverName"] = resolverName

	if endpoint.ID != nil {
		props["id"] = *endpoint.ID
	}
	if endpoint.Name != nil {
		props["name"] = *endpoint.Name
	}
	if endpoint.Location != nil {
		props["location"] = normalizeAzureLocation(*endpoint.Location)
	}

	if p := endpoint.Properties; p != nil && len(p.IPConfigurations) > 0 {
		ipConfigs := make([]map[string]any, 0, len(p.IPConfigurations))
		addresses := make([]string, 0, len(p.IPConfigurations))
		for _, cfg := range p.IPConfigurations {
			if cfg == nil {
				continue
			}
			entry := make(map[string]any)
			if cfg.Subnet != nil && cfg.Subnet.ID != nil {
				entry["subnetId"] = *cfg.Subnet.ID
			}
			allocation := ""
			if cfg.PrivateIPAllocationMethod != nil {
				allocation = canonicalizeEnum(string(*cfg.PrivateIPAllocationMethod), "Dynamic", "Static")
				entry["privateIpAllocationMethod"] = allocation
			}
			if cfg.PrivateIPAddress != nil {
				addresses = append(addresses, *cfg.PrivateIPAddress)
				// Only echo the address back inside the ipConfiguration when it was
				// the caller who chose it. With Dynamic allocation ARM assigns one
				// and hasProviderDefault is NOT honoured on nested class fields, so
				// echoing it there fails conformance [Verify] with "not expected and
				// not a provider default". The allocated address is reported through
				// the top-level privateIpAddresses output instead.
				if allocation == "Static" {
					entry["privateIpAddress"] = *cfg.PrivateIPAddress
				}
			}
			ipConfigs = append(ipConfigs, entry)
		}
		props["ipConfigurations"] = ipConfigs
		if len(addresses) > 0 {
			props["privateIpAddresses"] = addresses
		}
	}

	if tags := azureTagsToFormaeTags(endpoint.Tags); tags != nil {
		props["Tags"] = tags
	}

	return props
}

func (d *DNSResolverInboundEndpoint) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props dnsResolverInboundEndpointProps
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	if props.DNSResolverName == "" {
		return nil, fmt.Errorf("dnsResolverName is required")
	}
	if props.Location == "" {
		return nil, fmt.Errorf("location is required")
	}
	if len(props.IPConfigurations) == 0 {
		return nil, fmt.Errorf("ipConfigurations is required")
	}
	name := props.Name
	if name == "" {
		name = request.Label
	}
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}

	ipConfigs := make([]*armdnsresolver.IPConfiguration, 0, len(props.IPConfigurations))
	for _, cfg := range props.IPConfigurations {
		if cfg.SubnetID == "" {
			return nil, fmt.Errorf("ipConfigurations[].subnetId is required")
		}
		ipConfig := &armdnsresolver.IPConfiguration{
			Subnet: &armdnsresolver.SubResource{ID: to.Ptr(cfg.SubnetID)},
		}
		if cfg.PrivateIPAddress != "" {
			ipConfig.PrivateIPAddress = to.Ptr(cfg.PrivateIPAddress)
		}
		if cfg.PrivateIPAllocationMethod != "" {
			ipConfig.PrivateIPAllocationMethod = to.Ptr(armdnsresolver.IPAllocationMethod(cfg.PrivateIPAllocationMethod))
		}
		ipConfigs = append(ipConfigs, ipConfig)
	}

	params := armdnsresolver.InboundEndpoint{
		Location: to.Ptr(props.Location),
		Properties: &armdnsresolver.InboundEndpointProperties{
			IPConfigurations: ipConfigs,
		},
	}
	if azureTags := formaeTagsToAzureTags(request.Properties); azureTags != nil {
		params.Tags = azureTags
	}

	poller, err := d.api.BeginCreateOrUpdate(ctx, props.ResourceGroupName, props.DNSResolverName, name, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/dnsResolvers/%s/inboundEndpoints/%s",
		d.config.SubscriptionId, props.ResourceGroupName, props.DNSResolverName, name)

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
		nativeID, propsJSON, err := d.completeFromEndpoint(&result.InboundEndpoint)
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

func (d *DNSResolverInboundEndpoint) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, resolverName, name, err := dnsResolverInboundEndpointIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := d.api.Get(ctx, rgName, resolverName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(d.buildPropertiesFromResult(&result.InboundEndpoint, rgName, resolverName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeDNSResolverInboundEndpoint,
		Properties:   string(propsJSON),
	}, nil
}

// Update can only ever change tags: armdnsresolver.InboundEndpointPatch has no
// other field, and the schema marks everything else createOnly to match.
func (d *DNSResolverInboundEndpoint) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, resolverName, name, err := dnsResolverInboundEndpointIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	params := armdnsresolver.InboundEndpointPatch{Tags: formaeTagsToAzureTags(request.DesiredProperties)}

	poller, err := d.api.BeginUpdate(ctx, rgName, resolverName, name, params, nil)
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
		propsJSON, err := json.Marshal(d.buildPropertiesFromResult(&result.InboundEndpoint, rgName, resolverName))
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

func (d *DNSResolverInboundEndpoint) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, resolverName, name, err := dnsResolverInboundEndpointIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, err := d.api.BeginDelete(ctx, rgName, resolverName, name, nil)
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

func (d *DNSResolverInboundEndpoint) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	reqID, err := decodeLROStatus(request.RequestID)
	if err != nil {
		return nil, err
	}

	switch reqID.OperationType {
	case lroOpCreate:
		return statusLRO(ctx, request, &reqID, resource.OperationCreate,
			func(token string) (*runtime.Poller[armdnsresolver.InboundEndpointsClientCreateOrUpdateResponse], error) {
				return resumePoller[armdnsresolver.InboundEndpointsClientCreateOrUpdateResponse](d.pipeline, token)
			},
			func(_ context.Context, result armdnsresolver.InboundEndpointsClientCreateOrUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				return d.completeFromEndpoint(&result.InboundEndpoint)
			})
	case lroOpUpdate:
		return statusLRO(ctx, request, &reqID, resource.OperationUpdate,
			func(token string) (*runtime.Poller[armdnsresolver.InboundEndpointsClientUpdateResponse], error) {
				return resumePoller[armdnsresolver.InboundEndpointsClientUpdateResponse](d.pipeline, token)
			},
			func(_ context.Context, result armdnsresolver.InboundEndpointsClientUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				return d.completeFromEndpoint(&result.InboundEndpoint)
			})
	case lroOpDelete:
		return statusDeleteLRO(ctx, request, &reqID,
			func(token string) (*runtime.Poller[armdnsresolver.InboundEndpointsClientDeleteResponse], error) {
				return resumePoller[armdnsresolver.InboundEndpointsClientDeleteResponse](d.pipeline, token)
			}, nil)
	default:
		return nil, fmt.Errorf("unknown operation type: %s", reqID.OperationType)
	}
}

func (d *DNSResolverInboundEndpoint) completeFromEndpoint(endpoint *armdnsresolver.InboundEndpoint) (string, json.RawMessage, error) {
	nativeID := ""
	rgName := ""
	resolverName := ""
	if endpoint.ID != nil {
		nativeID = *endpoint.ID
		if rg, resolver, _, err := dnsResolverInboundEndpointIDParts(*endpoint.ID); err == nil {
			rgName = rg
			resolverName = resolver
		}
	}
	propsJSON, err := json.Marshal(d.buildPropertiesFromResult(endpoint, rgName, resolverName))
	if err != nil {
		return "", nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return nativeID, propsJSON, nil
}

// List requires both the resource group and the resolver name: ARM has no
// subscription-wide listing for inbound endpoints.
func (d *DNSResolverInboundEndpoint) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	resolverName := request.AdditionalProperties["dnsResolverName"]
	if rgName == "" || resolverName == "" {
		return &resource.ListResult{}, nil
	}

	var nativeIDs []string
	pager := d.api.NewListPager(rgName, resolverName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list dns resolver inbound endpoints: %w", err)
		}
		for _, endpoint := range page.Value {
			if endpoint.ID != nil {
				nativeIDs = append(nativeIDs, *endpoint.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
