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

const ResourceTypeDNSResolverPolicyVNetLink = "AZURE::Network::DnsResolverPolicyVirtualNetworkLink"

// dnsResolverPolicyVNetLinksAPI is the armdnsresolver surface used here. All three
// mutating calls are LROs, and PolicyVirtualNetworkLinkPatch carries tags and
// nothing else — unlike the forwarding ruleset's link, which carries metadata — so
// the virtual network binding is createOnly.
type dnsResolverPolicyVNetLinksAPI interface {
	BeginCreateOrUpdate(ctx context.Context, resourceGroupName string, dnsResolverPolicyName string, policyVNetLinkName string, parameters armdnsresolver.PolicyVirtualNetworkLink, options *armdnsresolver.PolicyVirtualNetworkLinksClientBeginCreateOrUpdateOptions) (*runtime.Poller[armdnsresolver.PolicyVirtualNetworkLinksClientCreateOrUpdateResponse], error)
	Get(ctx context.Context, resourceGroupName string, dnsResolverPolicyName string, policyVNetLinkName string, options *armdnsresolver.PolicyVirtualNetworkLinksClientGetOptions) (armdnsresolver.PolicyVirtualNetworkLinksClientGetResponse, error)
	BeginUpdate(ctx context.Context, resourceGroupName string, dnsResolverPolicyName string, policyVNetLinkName string, parameters armdnsresolver.PolicyVirtualNetworkLinkPatch, options *armdnsresolver.PolicyVirtualNetworkLinksClientBeginUpdateOptions) (*runtime.Poller[armdnsresolver.PolicyVirtualNetworkLinksClientUpdateResponse], error)
	BeginDelete(ctx context.Context, resourceGroupName string, dnsResolverPolicyName string, policyVNetLinkName string, options *armdnsresolver.PolicyVirtualNetworkLinksClientBeginDeleteOptions) (*runtime.Poller[armdnsresolver.PolicyVirtualNetworkLinksClientDeleteResponse], error)
	NewListPager(resourceGroupName string, dnsResolverPolicyName string, options *armdnsresolver.PolicyVirtualNetworkLinksClientListOptions) *runtime.Pager[armdnsresolver.PolicyVirtualNetworkLinksClientListResponse]
}

func init() {
	registry.Register(ResourceTypeDNSResolverPolicyVNetLink, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &DNSResolverPolicyVNetLink{
			api:      c.DNSResolverPolicyVNetLinksClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// DNSResolverPolicyVNetLink is the provisioner for the links that apply a DNS
// resolver policy to a virtual network
// (Microsoft.Network/dnsResolverPolicies/virtualNetworkLinks).
type DNSResolverPolicyVNetLink struct {
	api      dnsResolverPolicyVNetLinksAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

// dnsResolverPolicyVirtualNetworkLinkProps mirrors
// schema/pkl/network/dnsresolverpolicyvnetlink.pkl.
type dnsResolverPolicyVirtualNetworkLinkProps struct {
	Name                  string `json:"name"`
	Location              string `json:"location"`
	ResourceGroupName     string `json:"resourceGroupName"`
	DNSResolverPolicyName string `json:"dnsResolverPolicyName"`
	VirtualNetworkID      string `json:"virtualNetworkId"`
}

func dnsResolverPolicyVirtualNetworkLinkIDParts(resourceID string) (rgName, policyName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "dnsresolverpolicies", "virtualnetworklinks")
	if err != nil {
		return "", "", "", err
	}
	return rgName, names["dnsresolverpolicies"], names["virtualnetworklinks"], nil
}

func (d *DNSResolverPolicyVNetLink) buildPropertiesFromResult(link *armdnsresolver.PolicyVirtualNetworkLink, rgName, policyName string) map[string]any {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	props["dnsResolverPolicyName"] = policyName

	if link.ID != nil {
		props["id"] = *link.ID
	}
	if link.Name != nil {
		props["name"] = *link.Name
	}
	if link.Location != nil {
		props["location"] = normalizeAzureLocation(*link.Location)
	}

	if p := link.Properties; p != nil && p.VirtualNetwork != nil && p.VirtualNetwork.ID != nil {
		props["virtualNetworkId"] = *p.VirtualNetwork.ID
	}

	if tags := azureTagsToFormaeTags(link.Tags); tags != nil {
		props["Tags"] = tags
	}

	return props
}

func (d *DNSResolverPolicyVNetLink) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props dnsResolverPolicyVirtualNetworkLinkProps
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	if props.DNSResolverPolicyName == "" {
		return nil, fmt.Errorf("dnsResolverPolicyName is required")
	}
	if props.Location == "" {
		return nil, fmt.Errorf("location is required")
	}
	if props.VirtualNetworkID == "" {
		return nil, fmt.Errorf("virtualNetworkId is required")
	}
	name := props.Name
	if name == "" {
		name = request.Label
	}
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}

	params := armdnsresolver.PolicyVirtualNetworkLink{
		Location: to.Ptr(props.Location),
		Properties: &armdnsresolver.PolicyVirtualNetworkLinkProperties{
			VirtualNetwork: &armdnsresolver.SubResource{ID: to.Ptr(props.VirtualNetworkID)},
		},
	}
	if azureTags := formaeTagsToAzureTags(request.Properties); azureTags != nil {
		params.Tags = azureTags
	}

	poller, err := d.api.BeginCreateOrUpdate(ctx, props.ResourceGroupName, props.DNSResolverPolicyName, name, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/dnsResolverPolicies/%s/virtualNetworkLinks/%s",
		d.config.SubscriptionId, props.ResourceGroupName, props.DNSResolverPolicyName, name)

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
		nativeID, propsJSON, err := d.completeFromLink(&result.PolicyVirtualNetworkLink)
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

func (d *DNSResolverPolicyVNetLink) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, policyName, name, err := dnsResolverPolicyVirtualNetworkLinkIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := d.api.Get(ctx, rgName, policyName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(d.buildPropertiesFromResult(&result.PolicyVirtualNetworkLink, rgName, policyName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeDNSResolverPolicyVNetLink,
		Properties:   string(propsJSON),
	}, nil
}

// Update can only ever change tags: armdnsresolver.PolicyVirtualNetworkLinkPatch has no
// other field, and the schema marks everything else createOnly to match.
func (d *DNSResolverPolicyVNetLink) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, policyName, name, err := dnsResolverPolicyVirtualNetworkLinkIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	params := armdnsresolver.PolicyVirtualNetworkLinkPatch{Tags: formaeTagsToAzureTags(request.DesiredProperties)}

	poller, err := d.api.BeginUpdate(ctx, rgName, policyName, name, params, nil)
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
		propsJSON, err := json.Marshal(d.buildPropertiesFromResult(&result.PolicyVirtualNetworkLink, rgName, policyName))
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

func (d *DNSResolverPolicyVNetLink) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, policyName, name, err := dnsResolverPolicyVirtualNetworkLinkIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, err := d.api.BeginDelete(ctx, rgName, policyName, name, nil)
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

func (d *DNSResolverPolicyVNetLink) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	reqID, err := decodeLROStatus(request.RequestID)
	if err != nil {
		return nil, err
	}

	switch reqID.OperationType {
	case lroOpCreate:
		return statusLRO(ctx, request, &reqID, resource.OperationCreate,
			func(token string) (*runtime.Poller[armdnsresolver.PolicyVirtualNetworkLinksClientCreateOrUpdateResponse], error) {
				return resumePoller[armdnsresolver.PolicyVirtualNetworkLinksClientCreateOrUpdateResponse](d.pipeline, token)
			},
			func(_ context.Context, result armdnsresolver.PolicyVirtualNetworkLinksClientCreateOrUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				return d.completeFromLink(&result.PolicyVirtualNetworkLink)
			})
	case lroOpUpdate:
		return statusLRO(ctx, request, &reqID, resource.OperationUpdate,
			func(token string) (*runtime.Poller[armdnsresolver.PolicyVirtualNetworkLinksClientUpdateResponse], error) {
				return resumePoller[armdnsresolver.PolicyVirtualNetworkLinksClientUpdateResponse](d.pipeline, token)
			},
			func(_ context.Context, result armdnsresolver.PolicyVirtualNetworkLinksClientUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				return d.completeFromLink(&result.PolicyVirtualNetworkLink)
			})
	case lroOpDelete:
		return statusDeleteLRO(ctx, request, &reqID,
			func(token string) (*runtime.Poller[armdnsresolver.PolicyVirtualNetworkLinksClientDeleteResponse], error) {
				return resumePoller[armdnsresolver.PolicyVirtualNetworkLinksClientDeleteResponse](d.pipeline, token)
			}, nil)
	default:
		return nil, fmt.Errorf("unknown operation type: %s", reqID.OperationType)
	}
}

func (d *DNSResolverPolicyVNetLink) completeFromLink(link *armdnsresolver.PolicyVirtualNetworkLink) (string, json.RawMessage, error) {
	nativeID := ""
	rgName := ""
	policyName := ""
	if link.ID != nil {
		nativeID = *link.ID
		if rg, resolver, _, err := dnsResolverPolicyVirtualNetworkLinkIDParts(*link.ID); err == nil {
			rgName = rg
			policyName = resolver
		}
	}
	propsJSON, err := json.Marshal(d.buildPropertiesFromResult(link, rgName, policyName))
	if err != nil {
		return "", nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return nativeID, propsJSON, nil
}

// List requires both the resource group and the resolver name: ARM has no
// subscription-wide listing for outbound endpoints.
func (d *DNSResolverPolicyVNetLink) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	policyName := request.AdditionalProperties["dnsResolverPolicyName"]
	if rgName == "" || policyName == "" {
		return &resource.ListResult{}, nil
	}

	var nativeIDs []string
	pager := d.api.NewListPager(rgName, policyName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list dns resolver policy virtual network links: %w", err)
		}
		for _, link := range page.Value {
			if link.ID != nil {
				nativeIDs = append(nativeIDs, *link.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
