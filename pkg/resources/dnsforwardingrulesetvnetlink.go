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

const ResourceTypeDNSForwardingRulesetVNetLink = "AZURE::Network::DnsForwardingRulesetVirtualNetworkLink"

// dnsForwardingRulesetVNetLinksAPI is the armdnsresolver surface used here. As with
// the resolver itself, VirtualNetworkLinkPatch carries tags and nothing else, so
// every other property is createOnly in the schema.
type dnsForwardingRulesetVNetLinksAPI interface {
	BeginCreateOrUpdate(ctx context.Context, resourceGroupName string, dnsForwardingRulesetName string, virtualNetworkLinkName string, parameters armdnsresolver.VirtualNetworkLink, options *armdnsresolver.VirtualNetworkLinksClientBeginCreateOrUpdateOptions) (*runtime.Poller[armdnsresolver.VirtualNetworkLinksClientCreateOrUpdateResponse], error)
	Get(ctx context.Context, resourceGroupName string, dnsForwardingRulesetName string, virtualNetworkLinkName string, options *armdnsresolver.VirtualNetworkLinksClientGetOptions) (armdnsresolver.VirtualNetworkLinksClientGetResponse, error)
	BeginUpdate(ctx context.Context, resourceGroupName string, dnsForwardingRulesetName string, virtualNetworkLinkName string, parameters armdnsresolver.VirtualNetworkLinkPatch, options *armdnsresolver.VirtualNetworkLinksClientBeginUpdateOptions) (*runtime.Poller[armdnsresolver.VirtualNetworkLinksClientUpdateResponse], error)
	BeginDelete(ctx context.Context, resourceGroupName string, dnsForwardingRulesetName string, virtualNetworkLinkName string, options *armdnsresolver.VirtualNetworkLinksClientBeginDeleteOptions) (*runtime.Poller[armdnsresolver.VirtualNetworkLinksClientDeleteResponse], error)
	NewListPager(resourceGroupName string, dnsForwardingRulesetName string, options *armdnsresolver.VirtualNetworkLinksClientListOptions) *runtime.Pager[armdnsresolver.VirtualNetworkLinksClientListResponse]
}

func init() {
	registry.Register(ResourceTypeDNSForwardingRulesetVNetLink, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &DNSForwardingRulesetVNetLink{
			api:      c.DNSForwardingRulesetVNetLinksClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// DNSForwardingRulesetVNetLink is the provisioner for inbound endpoints on an Azure
// DNS Private Resolver (Microsoft.Network/dnsResolvers/virtualNetworkLinks).
type DNSForwardingRulesetVNetLink struct {
	api      dnsForwardingRulesetVNetLinksAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

// dnsForwardingRulesetVNetLinkProps mirrors
// schema/pkl/network/dnsforwardingrulesetvnetlink.pkl.
type dnsForwardingRulesetVNetLinkProps struct {
	Name                     string `json:"name"`
	ResourceGroupName        string `json:"resourceGroupName"`
	DNSForwardingRulesetName string `json:"dnsForwardingRulesetName"`
	VirtualNetworkID         string `json:"virtualNetworkId"`
}

// vnetLinkMetadata converts the schema's Key/Value entity set into the flat map
// ARM expects. Returning nil for an absent or empty set leaves the field out of
// the request rather than clearing it.
func vnetLinkMetadata(rawProps json.RawMessage) map[string]*string {
	var wrapper struct {
		Metadata []struct {
			Key   string `json:"Key"`
			Value string `json:"Value"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(rawProps, &wrapper); err != nil || len(wrapper.Metadata) == 0 {
		return nil
	}
	out := make(map[string]*string, len(wrapper.Metadata))
	for _, entry := range wrapper.Metadata {
		if entry.Key == "" {
			continue
		}
		value := entry.Value
		out[entry.Key] = &value
	}
	return out
}

func dnsForwardingRulesetVNetLinkIDParts(resourceID string) (rgName, rulesetName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "dnsforwardingrulesets", "virtualnetworklinks")
	if err != nil {
		return "", "", "", err
	}
	return rgName, names["dnsforwardingrulesets"], names["virtualnetworklinks"], nil
}

func (d *DNSForwardingRulesetVNetLink) buildPropertiesFromResult(link *armdnsresolver.VirtualNetworkLink, rgName, rulesetName string) map[string]any {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	props["dnsForwardingRulesetName"] = rulesetName

	if link.ID != nil {
		props["id"] = *link.ID
	}
	if link.Name != nil {
		props["name"] = *link.Name
	}

	if p := link.Properties; p != nil {
		if p.VirtualNetwork != nil && p.VirtualNetwork.ID != nil {
			props["virtualNetworkId"] = *p.VirtualNetwork.ID
		}
		if len(p.Metadata) > 0 {
			// Same Key/Value entity-set shape the storage resources use for
			// metadata, which is what the schema's indexField refers to.
			entries := make([]map[string]string, 0, len(p.Metadata))
			for k, v := range p.Metadata {
				val := ""
				if v != nil {
					val = *v
				}
				entries = append(entries, map[string]string{"Key": k, "Value": val})
			}
			props["metadata"] = entries
		}
	}

	return props
}

func (d *DNSForwardingRulesetVNetLink) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props dnsForwardingRulesetVNetLinkProps
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	if props.DNSForwardingRulesetName == "" {
		return nil, fmt.Errorf("dnsForwardingRulesetName is required")
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

	params := armdnsresolver.VirtualNetworkLink{
		Properties: &armdnsresolver.VirtualNetworkLinkProperties{
			VirtualNetwork: &armdnsresolver.SubResource{ID: to.Ptr(props.VirtualNetworkID)},
			Metadata:       vnetLinkMetadata(request.Properties),
		},
	}

	poller, err := d.api.BeginCreateOrUpdate(ctx, props.ResourceGroupName, props.DNSForwardingRulesetName, name, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/dnsResolvers/%s/virtualNetworkLinks/%s",
		d.config.SubscriptionId, props.ResourceGroupName, props.DNSForwardingRulesetName, name)

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
		nativeID, propsJSON, err := d.completeFromLink(&result.VirtualNetworkLink)
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

func (d *DNSForwardingRulesetVNetLink) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, rulesetName, name, err := dnsForwardingRulesetVNetLinkIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := d.api.Get(ctx, rgName, rulesetName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(d.buildPropertiesFromResult(&result.VirtualNetworkLink, rgName, rulesetName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeDNSForwardingRulesetVNetLink,
		Properties:   string(propsJSON),
	}, nil
}

// Update can only ever change metadata: VirtualNetworkLinkPatchProperties has no
// other field, and the schema marks everything else createOnly to match. Unlike
// the ruleset's patch model, this one nests correctly under "properties", so it
// actually works.
func (d *DNSForwardingRulesetVNetLink) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, rulesetName, name, err := dnsForwardingRulesetVNetLinkIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	params := armdnsresolver.VirtualNetworkLinkPatch{
		Properties: &armdnsresolver.VirtualNetworkLinkPatchProperties{
			Metadata: vnetLinkMetadata(request.DesiredProperties),
		},
	}

	poller, err := d.api.BeginUpdate(ctx, rgName, rulesetName, name, params, nil)
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
		propsJSON, err := json.Marshal(d.buildPropertiesFromResult(&result.VirtualNetworkLink, rgName, rulesetName))
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

func (d *DNSForwardingRulesetVNetLink) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, rulesetName, name, err := dnsForwardingRulesetVNetLinkIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, err := d.api.BeginDelete(ctx, rgName, rulesetName, name, nil)
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

func (d *DNSForwardingRulesetVNetLink) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	reqID, err := decodeLROStatus(request.RequestID)
	if err != nil {
		return nil, err
	}

	switch reqID.OperationType {
	case lroOpCreate:
		return statusLRO(ctx, request, &reqID, resource.OperationCreate,
			func(token string) (*runtime.Poller[armdnsresolver.VirtualNetworkLinksClientCreateOrUpdateResponse], error) {
				return resumePoller[armdnsresolver.VirtualNetworkLinksClientCreateOrUpdateResponse](d.pipeline, token)
			},
			func(_ context.Context, result armdnsresolver.VirtualNetworkLinksClientCreateOrUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				return d.completeFromLink(&result.VirtualNetworkLink)
			})
	case lroOpUpdate:
		return statusLRO(ctx, request, &reqID, resource.OperationUpdate,
			func(token string) (*runtime.Poller[armdnsresolver.VirtualNetworkLinksClientUpdateResponse], error) {
				return resumePoller[armdnsresolver.VirtualNetworkLinksClientUpdateResponse](d.pipeline, token)
			},
			func(_ context.Context, result armdnsresolver.VirtualNetworkLinksClientUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				return d.completeFromLink(&result.VirtualNetworkLink)
			})
	case lroOpDelete:
		return statusDeleteLRO(ctx, request, &reqID,
			func(token string) (*runtime.Poller[armdnsresolver.VirtualNetworkLinksClientDeleteResponse], error) {
				return resumePoller[armdnsresolver.VirtualNetworkLinksClientDeleteResponse](d.pipeline, token)
			}, nil)
	default:
		return nil, fmt.Errorf("unknown operation type: %s", reqID.OperationType)
	}
}

func (d *DNSForwardingRulesetVNetLink) completeFromLink(link *armdnsresolver.VirtualNetworkLink) (string, json.RawMessage, error) {
	nativeID := ""
	rgName := ""
	rulesetName := ""
	if link.ID != nil {
		nativeID = *link.ID
		if rg, resolver, _, err := dnsForwardingRulesetVNetLinkIDParts(*link.ID); err == nil {
			rgName = rg
			rulesetName = resolver
		}
	}
	propsJSON, err := json.Marshal(d.buildPropertiesFromResult(link, rgName, rulesetName))
	if err != nil {
		return "", nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return nativeID, propsJSON, nil
}

// List requires both the resource group and the resolver name: ARM has no
// subscription-wide listing for inbound endpoints.
func (d *DNSForwardingRulesetVNetLink) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	rulesetName := request.AdditionalProperties["dnsForwardingRulesetName"]
	if rgName == "" || rulesetName == "" {
		return &resource.ListResult{}, nil
	}

	var nativeIDs []string
	pager := d.api.NewListPager(rgName, rulesetName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list dns resolver inbound endpoints: %w", err)
		}
		for _, link := range page.Value {
			if link.ID != nil {
				nativeIDs = append(nativeIDs, *link.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
