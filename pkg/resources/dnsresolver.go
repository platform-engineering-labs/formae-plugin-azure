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

const ResourceTypeDNSResolver = "AZURE::Network::DnsResolver"

// dnsResolversAPI is the armdnsresolver surface used here. All three mutating
// calls are LROs. Note that armdnsresolver.Patch carries tags and nothing else:
// every other property is createOnly in the schema because ARM has no way to
// change it in place.
type dnsResolversAPI interface {
	BeginCreateOrUpdate(ctx context.Context, resourceGroupName string, dnsResolverName string, parameters armdnsresolver.DNSResolver, options *armdnsresolver.DNSResolversClientBeginCreateOrUpdateOptions) (*runtime.Poller[armdnsresolver.DNSResolversClientCreateOrUpdateResponse], error)
	Get(ctx context.Context, resourceGroupName string, dnsResolverName string, options *armdnsresolver.DNSResolversClientGetOptions) (armdnsresolver.DNSResolversClientGetResponse, error)
	BeginUpdate(ctx context.Context, resourceGroupName string, dnsResolverName string, parameters armdnsresolver.Patch, options *armdnsresolver.DNSResolversClientBeginUpdateOptions) (*runtime.Poller[armdnsresolver.DNSResolversClientUpdateResponse], error)
	BeginDelete(ctx context.Context, resourceGroupName string, dnsResolverName string, options *armdnsresolver.DNSResolversClientBeginDeleteOptions) (*runtime.Poller[armdnsresolver.DNSResolversClientDeleteResponse], error)
	NewListPager(options *armdnsresolver.DNSResolversClientListOptions) *runtime.Pager[armdnsresolver.DNSResolversClientListResponse]
	NewListByResourceGroupPager(resourceGroupName string, options *armdnsresolver.DNSResolversClientListByResourceGroupOptions) *runtime.Pager[armdnsresolver.DNSResolversClientListByResourceGroupResponse]
}

func init() {
	registry.Register(ResourceTypeDNSResolver, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &DNSResolver{
			api:      c.DNSResolversClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// DNSResolver is the provisioner for Azure DNS Private Resolvers
// (Microsoft.Network/dnsResolvers).
type DNSResolver struct {
	api      dnsResolversAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

// dnsResolverProps mirrors schema/pkl/network/dnsresolver.pkl.
type dnsResolverProps struct {
	Name              string `json:"name"`
	Location          string `json:"location"`
	ResourceGroupName string `json:"resourceGroupName"`
	VirtualNetworkID  string `json:"virtualNetworkId"`
}

func dnsResolverIDParts(resourceID string) (rgName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "dnsresolvers")
	if err != nil {
		return "", "", err
	}
	return rgName, names["dnsresolvers"], nil
}

func (d *DNSResolver) buildPropertiesFromResult(res *armdnsresolver.DNSResolver, rgName string) map[string]any {
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
		if p.VirtualNetwork != nil && p.VirtualNetwork.ID != nil {
			props["virtualNetworkId"] = *p.VirtualNetwork.ID
		}
		if p.DNSResolverState != nil {
			props["dnsResolverState"] = string(*p.DNSResolverState)
		}
		// resourceGuid and provisioningState are deliberately dropped: neither is
		// desired state and both would only ever read back as noise.
	}

	if tags := azureTagsToFormaeTags(res.Tags); tags != nil {
		props["Tags"] = tags
	}

	return props
}

func (d *DNSResolver) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props dnsResolverProps
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
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

	params := armdnsresolver.DNSResolver{
		Location: to.Ptr(props.Location),
		Properties: &armdnsresolver.Properties{
			VirtualNetwork: &armdnsresolver.SubResource{ID: to.Ptr(props.VirtualNetworkID)},
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

	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/dnsResolvers/%s",
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
		nativeID, propsJSON, err := d.completeFromResolver(&result.DNSResolver)
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

func (d *DNSResolver) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, name, err := dnsResolverIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := d.api.Get(ctx, rgName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(d.buildPropertiesFromResult(&result.DNSResolver, rgName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeDNSResolver,
		Properties:   string(propsJSON),
	}, nil
}

// Update can only ever change tags: armdnsresolver.Patch has no other field, and
// the schema marks everything else createOnly to match.
func (d *DNSResolver) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, name, err := dnsResolverIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	params := armdnsresolver.Patch{Tags: formaeTagsToAzureTags(request.DesiredProperties)}

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
		propsJSON, err := json.Marshal(d.buildPropertiesFromResult(&result.DNSResolver, rgName))
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

func (d *DNSResolver) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, name, err := dnsResolverIDParts(request.NativeID)
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

func (d *DNSResolver) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	reqID, err := decodeLROStatus(request.RequestID)
	if err != nil {
		return nil, err
	}

	switch reqID.OperationType {
	case lroOpCreate:
		return statusLRO(ctx, request, &reqID, resource.OperationCreate,
			func(token string) (*runtime.Poller[armdnsresolver.DNSResolversClientCreateOrUpdateResponse], error) {
				return resumePoller[armdnsresolver.DNSResolversClientCreateOrUpdateResponse](d.pipeline, token)
			},
			func(_ context.Context, result armdnsresolver.DNSResolversClientCreateOrUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				return d.completeFromResolver(&result.DNSResolver)
			})
	case lroOpUpdate:
		return statusLRO(ctx, request, &reqID, resource.OperationUpdate,
			func(token string) (*runtime.Poller[armdnsresolver.DNSResolversClientUpdateResponse], error) {
				return resumePoller[armdnsresolver.DNSResolversClientUpdateResponse](d.pipeline, token)
			},
			func(_ context.Context, result armdnsresolver.DNSResolversClientUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				return d.completeFromResolver(&result.DNSResolver)
			})
	case lroOpDelete:
		return statusDeleteLRO(ctx, request, &reqID,
			func(token string) (*runtime.Poller[armdnsresolver.DNSResolversClientDeleteResponse], error) {
				return resumePoller[armdnsresolver.DNSResolversClientDeleteResponse](d.pipeline, token)
			}, nil)
	default:
		return nil, fmt.Errorf("unknown operation type: %s", reqID.OperationType)
	}
}

func (d *DNSResolver) completeFromResolver(res *armdnsresolver.DNSResolver) (string, json.RawMessage, error) {
	nativeID := ""
	rgName := ""
	if res.ID != nil {
		nativeID = *res.ID
		if rg, _, err := dnsResolverIDParts(*res.ID); err == nil {
			rgName = rg
		}
	}
	propsJSON, err := json.Marshal(d.buildPropertiesFromResult(res, rgName))
	if err != nil {
		return "", nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return nativeID, propsJSON, nil
}

func (d *DNSResolver) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]

	var nativeIDs []string

	if rgName != "" {
		pager := d.api.NewListByResourceGroupPager(rgName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list dns resolvers: %w", err)
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
			return nil, fmt.Errorf("failed to list dns resolvers: %w", err)
		}
		for _, res := range page.Value {
			if res.ID != nil {
				nativeIDs = append(nativeIDs, *res.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
