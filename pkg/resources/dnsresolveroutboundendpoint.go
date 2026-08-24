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

const ResourceTypeDNSResolverOutboundEndpoint = "AZURE::Network::DnsResolverOutboundEndpoint"

// dnsResolverOutboundEndpointsAPI is the armdnsresolver surface used here. As with
// the resolver itself, OutboundEndpointPatch carries tags and nothing else, so
// every other property is createOnly in the schema.
type dnsResolverOutboundEndpointsAPI interface {
	BeginCreateOrUpdate(ctx context.Context, resourceGroupName string, dnsResolverName string, outboundEndpointName string, parameters armdnsresolver.OutboundEndpoint, options *armdnsresolver.OutboundEndpointsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armdnsresolver.OutboundEndpointsClientCreateOrUpdateResponse], error)
	Get(ctx context.Context, resourceGroupName string, dnsResolverName string, outboundEndpointName string, options *armdnsresolver.OutboundEndpointsClientGetOptions) (armdnsresolver.OutboundEndpointsClientGetResponse, error)
	BeginUpdate(ctx context.Context, resourceGroupName string, dnsResolverName string, outboundEndpointName string, parameters armdnsresolver.OutboundEndpointPatch, options *armdnsresolver.OutboundEndpointsClientBeginUpdateOptions) (*runtime.Poller[armdnsresolver.OutboundEndpointsClientUpdateResponse], error)
	BeginDelete(ctx context.Context, resourceGroupName string, dnsResolverName string, outboundEndpointName string, options *armdnsresolver.OutboundEndpointsClientBeginDeleteOptions) (*runtime.Poller[armdnsresolver.OutboundEndpointsClientDeleteResponse], error)
	NewListPager(resourceGroupName string, dnsResolverName string, options *armdnsresolver.OutboundEndpointsClientListOptions) *runtime.Pager[armdnsresolver.OutboundEndpointsClientListResponse]
}

func init() {
	registry.Register(ResourceTypeDNSResolverOutboundEndpoint, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &DNSResolverOutboundEndpoint{
			api:      c.DNSResolverOutboundEndpointsClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// DNSResolverOutboundEndpoint is the provisioner for outbound endpoints on an Azure
// DNS Private Resolver (Microsoft.Network/dnsResolvers/outboundEndpoints).
type DNSResolverOutboundEndpoint struct {
	api      dnsResolverOutboundEndpointsAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

// dnsResolverOutboundEndpointProps mirrors
// schema/pkl/network/dnsresolveroutboundendpoint.pkl.
type dnsResolverOutboundEndpointProps struct {
	Name              string `json:"name"`
	Location          string `json:"location"`
	ResourceGroupName string `json:"resourceGroupName"`
	DNSResolverName   string `json:"dnsResolverName"`
	SubnetID          string `json:"subnetId"`
}

func dnsResolverOutboundEndpointIDParts(resourceID string) (rgName, resolverName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "dnsresolvers", "outboundendpoints")
	if err != nil {
		return "", "", "", err
	}
	return rgName, names["dnsresolvers"], names["outboundendpoints"], nil
}

func (d *DNSResolverOutboundEndpoint) buildPropertiesFromResult(endpoint *armdnsresolver.OutboundEndpoint, rgName, resolverName string) map[string]any {
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

	if p := endpoint.Properties; p != nil && p.Subnet != nil && p.Subnet.ID != nil {
		props["subnetId"] = *p.Subnet.ID
	}

	if tags := azureTagsToFormaeTags(endpoint.Tags); tags != nil {
		props["Tags"] = tags
	}

	return props
}

func (d *DNSResolverOutboundEndpoint) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props dnsResolverOutboundEndpointProps
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
	if props.SubnetID == "" {
		return nil, fmt.Errorf("subnetId is required")
	}
	name := props.Name
	if name == "" {
		name = request.Label
	}
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}

	params := armdnsresolver.OutboundEndpoint{
		Location: to.Ptr(props.Location),
		Properties: &armdnsresolver.OutboundEndpointProperties{
			Subnet: &armdnsresolver.SubResource{ID: to.Ptr(props.SubnetID)},
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

	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/dnsResolvers/%s/outboundEndpoints/%s",
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
		nativeID, propsJSON, err := d.completeFromEndpoint(&result.OutboundEndpoint)
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

func (d *DNSResolverOutboundEndpoint) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, resolverName, name, err := dnsResolverOutboundEndpointIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := d.api.Get(ctx, rgName, resolverName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(d.buildPropertiesFromResult(&result.OutboundEndpoint, rgName, resolverName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeDNSResolverOutboundEndpoint,
		Properties:   string(propsJSON),
	}, nil
}

// Update can only ever change tags: armdnsresolver.OutboundEndpointPatch has no
// other field, and the schema marks everything else createOnly to match.
func (d *DNSResolverOutboundEndpoint) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, resolverName, name, err := dnsResolverOutboundEndpointIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	params := armdnsresolver.OutboundEndpointPatch{Tags: formaeTagsToAzureTags(request.DesiredProperties)}

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
		propsJSON, err := json.Marshal(d.buildPropertiesFromResult(&result.OutboundEndpoint, rgName, resolverName))
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

func (d *DNSResolverOutboundEndpoint) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, resolverName, name, err := dnsResolverOutboundEndpointIDParts(request.NativeID)
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

func (d *DNSResolverOutboundEndpoint) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	reqID, err := decodeLROStatus(request.RequestID)
	if err != nil {
		return nil, err
	}

	switch reqID.OperationType {
	case lroOpCreate:
		return statusLRO(ctx, request, &reqID, resource.OperationCreate,
			func(token string) (*runtime.Poller[armdnsresolver.OutboundEndpointsClientCreateOrUpdateResponse], error) {
				return resumePoller[armdnsresolver.OutboundEndpointsClientCreateOrUpdateResponse](d.pipeline, token)
			},
			func(_ context.Context, result armdnsresolver.OutboundEndpointsClientCreateOrUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				return d.completeFromEndpoint(&result.OutboundEndpoint)
			})
	case lroOpUpdate:
		return statusLRO(ctx, request, &reqID, resource.OperationUpdate,
			func(token string) (*runtime.Poller[armdnsresolver.OutboundEndpointsClientUpdateResponse], error) {
				return resumePoller[armdnsresolver.OutboundEndpointsClientUpdateResponse](d.pipeline, token)
			},
			func(_ context.Context, result armdnsresolver.OutboundEndpointsClientUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				return d.completeFromEndpoint(&result.OutboundEndpoint)
			})
	case lroOpDelete:
		return statusDeleteLRO(ctx, request, &reqID,
			func(token string) (*runtime.Poller[armdnsresolver.OutboundEndpointsClientDeleteResponse], error) {
				return resumePoller[armdnsresolver.OutboundEndpointsClientDeleteResponse](d.pipeline, token)
			}, nil)
	default:
		return nil, fmt.Errorf("unknown operation type: %s", reqID.OperationType)
	}
}

func (d *DNSResolverOutboundEndpoint) completeFromEndpoint(endpoint *armdnsresolver.OutboundEndpoint) (string, json.RawMessage, error) {
	nativeID := ""
	rgName := ""
	resolverName := ""
	if endpoint.ID != nil {
		nativeID = *endpoint.ID
		if rg, resolver, _, err := dnsResolverOutboundEndpointIDParts(*endpoint.ID); err == nil {
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
// subscription-wide listing for outbound endpoints.
func (d *DNSResolverOutboundEndpoint) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
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
			return nil, fmt.Errorf("failed to list dns resolver outbound endpoints: %w", err)
		}
		for _, endpoint := range page.Value {
			if endpoint.ID != nil {
				nativeIDs = append(nativeIDs, *endpoint.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
