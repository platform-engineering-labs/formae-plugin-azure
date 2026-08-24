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

const ResourceTypeDNSForwardingRuleset = "AZURE::Network::DnsForwardingRuleset"

// dnsForwardingRulesetsAPI is the armdnsresolver surface used here. All three
// mutating calls are LROs, and — as with the resolver and its endpoints — the
// patch body is effectively tags-only. See Update for why the outbound-endpoint
// list cannot ride along.
type dnsForwardingRulesetsAPI interface {
	BeginCreateOrUpdate(ctx context.Context, resourceGroupName string, dnsForwardingRulesetName string, parameters armdnsresolver.DNSForwardingRuleset, options *armdnsresolver.DNSForwardingRulesetsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armdnsresolver.DNSForwardingRulesetsClientCreateOrUpdateResponse], error)
	Get(ctx context.Context, resourceGroupName string, dnsForwardingRulesetName string, options *armdnsresolver.DNSForwardingRulesetsClientGetOptions) (armdnsresolver.DNSForwardingRulesetsClientGetResponse, error)
	BeginUpdate(ctx context.Context, resourceGroupName string, dnsForwardingRulesetName string, parameters armdnsresolver.DNSForwardingRulesetPatch, options *armdnsresolver.DNSForwardingRulesetsClientBeginUpdateOptions) (*runtime.Poller[armdnsresolver.DNSForwardingRulesetsClientUpdateResponse], error)
	BeginDelete(ctx context.Context, resourceGroupName string, dnsForwardingRulesetName string, options *armdnsresolver.DNSForwardingRulesetsClientBeginDeleteOptions) (*runtime.Poller[armdnsresolver.DNSForwardingRulesetsClientDeleteResponse], error)
	NewListPager(options *armdnsresolver.DNSForwardingRulesetsClientListOptions) *runtime.Pager[armdnsresolver.DNSForwardingRulesetsClientListResponse]
	NewListByResourceGroupPager(resourceGroupName string, options *armdnsresolver.DNSForwardingRulesetsClientListByResourceGroupOptions) *runtime.Pager[armdnsresolver.DNSForwardingRulesetsClientListByResourceGroupResponse]
}

func init() {
	registry.Register(ResourceTypeDNSForwardingRuleset, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &DNSForwardingRuleset{
			api:      c.DNSForwardingRulesetsClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// DNSResolver is the provisioner for Azure DNS Private Resolvers
// (Microsoft.Network/dnsResolvers).
type DNSForwardingRuleset struct {
	api      dnsForwardingRulesetsAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

// dnsForwardingRulesetProps mirrors schema/pkl/network/dnsresolver.pkl.
type dnsForwardingRulesetProps struct {
	Name                string   `json:"name"`
	Location            string   `json:"location"`
	ResourceGroupName   string   `json:"resourceGroupName"`
	OutboundEndpointIDs []string `json:"dnsResolverOutboundEndpointIds"`
}

// outboundEndpointSubResources wraps ARM IDs in the SubResource shape both the
// create body and the patch body expect.
func outboundEndpointSubResources(ids []string) []*armdnsresolver.SubResource {
	if len(ids) == 0 {
		return nil
	}
	out := make([]*armdnsresolver.SubResource, 0, len(ids))
	for _, id := range ids {
		if id == "" {
			continue
		}
		out = append(out, &armdnsresolver.SubResource{ID: to.Ptr(id)})
	}
	return out
}

func dnsForwardingRulesetIDParts(resourceID string) (rgName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "dnsforwardingrulesets")
	if err != nil {
		return "", "", err
	}
	return rgName, names["dnsforwardingrulesets"], nil
}

func (d *DNSForwardingRuleset) buildPropertiesFromResult(res *armdnsresolver.DNSForwardingRuleset, rgName string) map[string]any {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName

	if res.ID != nil {
		props["id"] = *res.ID
	}
	if res.Name != nil {
		props["name"] = *res.Name
	}
	if res.Location != nil {
		props["location"] = normalizeAzureLocation(*res.Location)
	}

	if p := res.Properties; p != nil {
		if len(p.DNSResolverOutboundEndpoints) > 0 {
			// Order is echoed as sent. ARM permits exactly one entry today, so
			// there is nothing to canonicalise; a list of several would need the
			// same sort treatment as Batch's allowedAuthenticationModes.
			ids := make([]string, 0, len(p.DNSResolverOutboundEndpoints))
			for _, endpoint := range p.DNSResolverOutboundEndpoints {
				if endpoint == nil || endpoint.ID == nil {
					continue
				}
				ids = append(ids, *endpoint.ID)
			}
			props["dnsResolverOutboundEndpointIds"] = ids
		}
		// resourceGuid and provisioningState are deliberately dropped: neither is
		// desired state and both would only ever read back as noise.
	}

	if tags := azureTagsToFormaeTags(res.Tags); tags != nil {
		props["Tags"] = tags
	}

	return props
}

func (d *DNSForwardingRuleset) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props dnsForwardingRulesetProps
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	if props.Location == "" {
		return nil, fmt.Errorf("location is required")
	}
	if len(props.OutboundEndpointIDs) == 0 {
		return nil, fmt.Errorf("dnsResolverOutboundEndpointIds is required")
	}
	name := props.Name
	if name == "" {
		name = request.Label
	}
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}

	params := armdnsresolver.DNSForwardingRuleset{
		Location: to.Ptr(props.Location),
		Properties: &armdnsresolver.DNSForwardingRulesetProperties{
			DNSResolverOutboundEndpoints: outboundEndpointSubResources(props.OutboundEndpointIDs),
		},
	}
	if azureTags := formaeTagsToAzureTags(request.Properties); azureTags != nil {
		params.Tags = azureTags
	}

	poller, err := d.api.BeginCreateOrUpdate(ctx, props.ResourceGroupName, name, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/dnsForwardingRulesets/%s",
		d.config.SubscriptionId, props.ResourceGroupName, name)

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
		nativeID, propsJSON, err := d.completeFromRuleset(&result.DNSForwardingRuleset)
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

func (d *DNSForwardingRuleset) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, name, err := dnsForwardingRulesetIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := d.api.Get(ctx, rgName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(d.buildPropertiesFromResult(&result.DNSForwardingRuleset, rgName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeDNSForwardingRuleset,
		Properties:   string(propsJSON),
	}, nil
}

// Update sends tags only.
//
// DNSForwardingRulesetPatch also has a DNSResolverOutboundEndpoints field, but the
// SDK marshals it at the TOP LEVEL of the request body, and ARM rejects that:
//
//	InvalidRequestContent: Could not find member 'dnsResolverOutboundEndpoints'
//	on object of type 'ResourceDefinition'
//
// (The same list nested under "properties" is accepted — verified with a direct
// PATCH — so this is an SDK serialisation bug, not an ARM limitation.) Sending it
// therefore fails every update, so the schema marks the list createOnly and this
// patch carries tags alone.
func (d *DNSForwardingRuleset) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, name, err := dnsForwardingRulesetIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	params := armdnsresolver.DNSForwardingRulesetPatch{
		Tags: formaeTagsToAzureTags(request.DesiredProperties),
	}

	poller, err := d.api.BeginUpdate(ctx, rgName, name, params, nil)
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
		propsJSON, err := json.Marshal(d.buildPropertiesFromResult(&result.DNSForwardingRuleset, rgName))
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

func (d *DNSForwardingRuleset) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, name, err := dnsForwardingRulesetIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, err := d.api.BeginDelete(ctx, rgName, name, nil)
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

func (d *DNSForwardingRuleset) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	reqID, err := decodeLROStatus(request.RequestID)
	if err != nil {
		return nil, err
	}

	switch reqID.OperationType {
	case lroOpCreate:
		return statusLRO(ctx, request, &reqID, resource.OperationCreate,
			func(token string) (*runtime.Poller[armdnsresolver.DNSForwardingRulesetsClientCreateOrUpdateResponse], error) {
				return resumePoller[armdnsresolver.DNSForwardingRulesetsClientCreateOrUpdateResponse](d.pipeline, token)
			},
			func(_ context.Context, result armdnsresolver.DNSForwardingRulesetsClientCreateOrUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				return d.completeFromRuleset(&result.DNSForwardingRuleset)
			})
	case lroOpUpdate:
		return statusLRO(ctx, request, &reqID, resource.OperationUpdate,
			func(token string) (*runtime.Poller[armdnsresolver.DNSForwardingRulesetsClientUpdateResponse], error) {
				return resumePoller[armdnsresolver.DNSForwardingRulesetsClientUpdateResponse](d.pipeline, token)
			},
			func(_ context.Context, result armdnsresolver.DNSForwardingRulesetsClientUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				return d.completeFromRuleset(&result.DNSForwardingRuleset)
			})
	case lroOpDelete:
		return statusDeleteLRO(ctx, request, &reqID,
			func(token string) (*runtime.Poller[armdnsresolver.DNSForwardingRulesetsClientDeleteResponse], error) {
				return resumePoller[armdnsresolver.DNSForwardingRulesetsClientDeleteResponse](d.pipeline, token)
			}, nil)
	default:
		return nil, fmt.Errorf("unknown operation type: %s", reqID.OperationType)
	}
}

func (d *DNSForwardingRuleset) completeFromRuleset(res *armdnsresolver.DNSForwardingRuleset) (string, json.RawMessage, error) {
	nativeID := ""
	rgName := ""
	if res.ID != nil {
		nativeID = *res.ID
		if rg, _, err := dnsForwardingRulesetIDParts(*res.ID); err == nil {
			rgName = rg
		}
	}
	propsJSON, err := json.Marshal(d.buildPropertiesFromResult(res, rgName))
	if err != nil {
		return "", nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return nativeID, propsJSON, nil
}

func (d *DNSForwardingRuleset) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]

	var nativeIDs []string

	if rgName != "" {
		pager := d.api.NewListByResourceGroupPager(rgName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list dns forwarding rulesets: %w", err)
			}
			for _, res := range page.Value {
				if res.ID != nil {
					nativeIDs = append(nativeIDs, *res.ID)
				}
			}
		}
		return &resource.ListResult{NativeIDs: nativeIDs}, nil
	}

	pager := d.api.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list dns forwarding rulesets: %w", err)
		}
		for _, res := range page.Value {
			if res.ID != nil {
				nativeIDs = append(nativeIDs, *res.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
