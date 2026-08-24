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

const ResourceTypeDNSResolverDomainList = "AZURE::Network::DnsResolverDomainList"

// dnsResolverDomainListsAPI is the armdnsresolver surface used here. All three mutating
// calls are LROs. Note that armdnsresolver.Patch carries tags and nothing else:
// every other property is createOnly in the schema because ARM has no way to
// change it in place.
type dnsResolverDomainListsAPI interface {
	BeginCreateOrUpdate(ctx context.Context, resourceGroupName string, dnsResolverName string, parameters armdnsresolver.DomainList, options *armdnsresolver.DomainListsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armdnsresolver.DomainListsClientCreateOrUpdateResponse], error)
	Get(ctx context.Context, resourceGroupName string, dnsResolverName string, options *armdnsresolver.DomainListsClientGetOptions) (armdnsresolver.DomainListsClientGetResponse, error)
	BeginUpdate(ctx context.Context, resourceGroupName string, dnsResolverName string, parameters armdnsresolver.DomainListPatch, options *armdnsresolver.DomainListsClientBeginUpdateOptions) (*runtime.Poller[armdnsresolver.DomainListsClientUpdateResponse], error)
	BeginDelete(ctx context.Context, resourceGroupName string, dnsResolverName string, options *armdnsresolver.DomainListsClientBeginDeleteOptions) (*runtime.Poller[armdnsresolver.DomainListsClientDeleteResponse], error)
	NewListPager(options *armdnsresolver.DomainListsClientListOptions) *runtime.Pager[armdnsresolver.DomainListsClientListResponse]
	NewListByResourceGroupPager(resourceGroupName string, options *armdnsresolver.DomainListsClientListByResourceGroupOptions) *runtime.Pager[armdnsresolver.DomainListsClientListByResourceGroupResponse]
}

func init() {
	registry.Register(ResourceTypeDNSResolverDomainList, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &DNSResolverDomainList{
			api:      c.DNSResolverDomainListsClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// DNSResolver is the provisioner for Azure DNS Private Resolvers
// (Microsoft.Network/dnsResolvers).
type DNSResolverDomainList struct {
	api      dnsResolverDomainListsAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

// dnsResolverDomainListProps mirrors schema/pkl/network/dnsresolverdomainlist.pkl.
type dnsResolverDomainListProps struct {
	Name              string   `json:"name"`
	Location          string   `json:"location"`
	ResourceGroupName string   `json:"resourceGroupName"`
	Domains           []string `json:"domains"`
}

// domainPointers converts the schema's domain strings into the pointer slice ARM
// expects, shared by the create body and the patch body.
func domainPointers(domains []string) []*string {
	if len(domains) == 0 {
		return nil
	}
	out := make([]*string, 0, len(domains))
	for _, domain := range domains {
		if domain == "" {
			continue
		}
		value := domain
		out = append(out, &value)
	}
	return out
}

func dnsResolverDomainListIDParts(resourceID string) (rgName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "dnsresolverdomainlists")
	if err != nil {
		return "", "", err
	}
	return rgName, names["dnsresolverdomainlists"], nil
}

func (d *DNSResolverDomainList) buildPropertiesFromResult(res *armdnsresolver.DomainList, rgName string) map[string]any {
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

	if p := res.Properties; p != nil && len(p.Domains) > 0 {
		// Order is echoed as ARM returns it. domainsUrl and resourceGuid are left
		// out: the first belongs to the bulk API this resource does not use, the
		// second is service bookkeeping.
		domains := make([]string, 0, len(p.Domains))
		for _, domain := range p.Domains {
			if domain == nil {
				continue
			}
			domains = append(domains, *domain)
		}
		props["domains"] = domains
	}

	if tags := azureTagsToFormaeTags(res.Tags); tags != nil {
		props["Tags"] = tags
	}

	return props
}

func (d *DNSResolverDomainList) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props dnsResolverDomainListProps
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	if props.Location == "" {
		return nil, fmt.Errorf("location is required")
	}
	if len(props.Domains) == 0 {
		return nil, fmt.Errorf("domains is required")
	}
	name := props.Name
	if name == "" {
		name = request.Label
	}
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}

	params := armdnsresolver.DomainList{
		Location: to.Ptr(props.Location),
		Properties: &armdnsresolver.DomainListProperties{
			Domains: domainPointers(props.Domains),
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

	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/dnsResolverDomainLists/%s",
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
		nativeID, propsJSON, err := d.completeFromDomainList(&result.DomainList)
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

func (d *DNSResolverDomainList) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, name, err := dnsResolverDomainListIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := d.api.Get(ctx, rgName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(d.buildPropertiesFromResult(&result.DomainList, rgName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeDNSResolverDomainList,
		Properties:   string(propsJSON),
	}, nil
}

// Update can only ever change tags: armdnsresolver.Patch has no other field, and
// the schema marks everything else createOnly to match.
func (d *DNSResolverDomainList) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, name, err := dnsResolverDomainListIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props dnsResolverDomainListProps
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	params := armdnsresolver.DomainListPatch{
		Tags: formaeTagsToAzureTags(request.DesiredProperties),
	}
	if domains := domainPointers(props.Domains); domains != nil {
		params.Properties = &armdnsresolver.DomainListPatchProperties{Domains: domains}
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
		propsJSON, err := json.Marshal(d.buildPropertiesFromResult(&result.DomainList, rgName))
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

func (d *DNSResolverDomainList) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, name, err := dnsResolverDomainListIDParts(request.NativeID)
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

func (d *DNSResolverDomainList) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	reqID, err := decodeLROStatus(request.RequestID)
	if err != nil {
		return nil, err
	}

	switch reqID.OperationType {
	case lroOpCreate:
		return statusLRO(ctx, request, &reqID, resource.OperationCreate,
			func(token string) (*runtime.Poller[armdnsresolver.DomainListsClientCreateOrUpdateResponse], error) {
				return resumePoller[armdnsresolver.DomainListsClientCreateOrUpdateResponse](d.pipeline, token)
			},
			func(_ context.Context, result armdnsresolver.DomainListsClientCreateOrUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				return d.completeFromDomainList(&result.DomainList)
			})
	case lroOpUpdate:
		return statusLRO(ctx, request, &reqID, resource.OperationUpdate,
			func(token string) (*runtime.Poller[armdnsresolver.DomainListsClientUpdateResponse], error) {
				return resumePoller[armdnsresolver.DomainListsClientUpdateResponse](d.pipeline, token)
			},
			func(_ context.Context, result armdnsresolver.DomainListsClientUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				return d.completeFromDomainList(&result.DomainList)
			})
	case lroOpDelete:
		return statusDeleteLRO(ctx, request, &reqID,
			func(token string) (*runtime.Poller[armdnsresolver.DomainListsClientDeleteResponse], error) {
				return resumePoller[armdnsresolver.DomainListsClientDeleteResponse](d.pipeline, token)
			}, nil)
	default:
		return nil, fmt.Errorf("unknown operation type: %s", reqID.OperationType)
	}
}

func (d *DNSResolverDomainList) completeFromDomainList(res *armdnsresolver.DomainList) (string, json.RawMessage, error) {
	nativeID := ""
	rgName := ""
	if res.ID != nil {
		nativeID = *res.ID
		if rg, _, err := dnsResolverDomainListIDParts(*res.ID); err == nil {
			rgName = rg
		}
	}
	propsJSON, err := json.Marshal(d.buildPropertiesFromResult(res, rgName))
	if err != nil {
		return "", nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return nativeID, propsJSON, nil
}

func (d *DNSResolverDomainList) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]

	var nativeIDs []string

	if rgName != "" {
		pager := d.api.NewListByResourceGroupPager(rgName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list dns resolver domain lists: %w", err)
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
			return nil, fmt.Errorf("failed to list dns resolver domain lists: %w", err)
		}
		for _, res := range page.Value {
			if res.ID != nil {
				nativeIDs = append(nativeIDs, *res.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
