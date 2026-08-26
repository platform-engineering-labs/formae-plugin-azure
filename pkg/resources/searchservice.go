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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/search/armsearch"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeSearchService = "AZURE::Search::Service"

// searchServicesAPI is the armsearch surface used here. Note the mixed shape:
// Create is an LRO, but Update and Delete are synchronous. Every call also takes
// a SearchManagementRequestOptions argument (for a client-request-id header),
// which this plugin always passes as nil.
type searchServicesAPI interface {
	BeginCreateOrUpdate(ctx context.Context, resourceGroupName string, searchServiceName string, service armsearch.Service, searchManagementRequestOptions *armsearch.SearchManagementRequestOptions, options *armsearch.ServicesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armsearch.ServicesClientCreateOrUpdateResponse], error)
	Get(ctx context.Context, resourceGroupName string, searchServiceName string, searchManagementRequestOptions *armsearch.SearchManagementRequestOptions, options *armsearch.ServicesClientGetOptions) (armsearch.ServicesClientGetResponse, error)
	Update(ctx context.Context, resourceGroupName string, searchServiceName string, service armsearch.ServiceUpdate, searchManagementRequestOptions *armsearch.SearchManagementRequestOptions, options *armsearch.ServicesClientUpdateOptions) (armsearch.ServicesClientUpdateResponse, error)
	Delete(ctx context.Context, resourceGroupName string, searchServiceName string, searchManagementRequestOptions *armsearch.SearchManagementRequestOptions, options *armsearch.ServicesClientDeleteOptions) (armsearch.ServicesClientDeleteResponse, error)
	NewListBySubscriptionPager(searchManagementRequestOptions *armsearch.SearchManagementRequestOptions, options *armsearch.ServicesClientListBySubscriptionOptions) *runtime.Pager[armsearch.ServicesClientListBySubscriptionResponse]
	NewListByResourceGroupPager(resourceGroupName string, searchManagementRequestOptions *armsearch.SearchManagementRequestOptions, options *armsearch.ServicesClientListByResourceGroupOptions) *runtime.Pager[armsearch.ServicesClientListByResourceGroupResponse]
}

func init() {
	registry.Register(ResourceTypeSearchService, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &SearchService{
			api:      c.SearchServicesClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// SearchService is the provisioner for Azure AI Search services
// (Microsoft.Search/searchServices).
//
// Admin and query API keys are never serialized: ARM returns them only from
// separate ListAdminKeys / ListQueryKeys calls, so putting them in resource state
// would persist live credentials.
type SearchService struct {
	api      searchServicesAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

// searchServiceProps mirrors schema/pkl/search/searchservice.pkl.
type searchServiceProps struct {
	Name                string          `json:"name"`
	Location            string          `json:"location"`
	ResourceGroupName   string          `json:"resourceGroupName"`
	SKU                 *searchSKUProps `json:"sku"`
	ReplicaCount        *int32          `json:"replicaCount"`
	PartitionCount      *int32          `json:"partitionCount"`
	HostingMode         string          `json:"hostingMode"`
	DisableLocalAuth    *bool           `json:"disableLocalAuth"`
	PublicNetworkAccess string          `json:"publicNetworkAccess"`
	SemanticSearch      string          `json:"semanticSearch"`
}

type searchSKUProps struct {
	Name string `json:"name"`
}

func searchServiceIDParts(resourceID string) (rgName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "searchservices")
	if err != nil {
		return "", "", err
	}
	return rgName, names["searchservices"], nil
}

func (s *SearchService) buildPropertiesFromResult(svc *armsearch.Service, rgName string) map[string]any {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName

	if svc.ID != nil {
		props["id"] = *svc.ID
	}
	if svc.Name != nil {
		props["name"] = *svc.Name
	}
	if svc.Location != nil {
		props["location"] = normalizeAzureLocation(*svc.Location)
	}
	if svc.SKU != nil && svc.SKU.Name != nil {
		props["sku"] = map[string]any{"name": canonicalizeEnum(string(*svc.SKU.Name),
			"free", "basic", "standard", "standard2", "standard3",
			"storage_optimized_l1", "storage_optimized_l2")}
	}

	if p := svc.Properties; p != nil {
		if p.ReplicaCount != nil {
			props["replicaCount"] = *p.ReplicaCount
		}
		if p.PartitionCount != nil {
			props["partitionCount"] = *p.PartitionCount
		}
		if p.HostingMode != nil {
			props["hostingMode"] = canonicalizeEnum(string(*p.HostingMode), "default", "highDensity")
		}
		if p.DisableLocalAuth != nil {
			props["disableLocalAuth"] = *p.DisableLocalAuth
		}
		if p.PublicNetworkAccess != nil {
			props["publicNetworkAccess"] = canonicalizeEnum(string(*p.PublicNetworkAccess),
				"enabled", "disabled", "securedByPerimeter")
		}
		if p.SemanticSearch != nil {
			props["semanticSearch"] = canonicalizeEnum(string(*p.SemanticSearch), "disabled", "free", "standard")
		}
		if p.Endpoint != nil {
			props["endpoint"] = *p.Endpoint
		}
	}

	if tags := azureTagsToFormaeTags(svc.Tags); tags != nil {
		props["Tags"] = tags
	}

	return props
}

// searchServicePropertiesFromProps builds the ARM properties block shared by the
// create body and the update patch.
func searchServicePropertiesFromProps(props searchServiceProps) *armsearch.ServiceProperties {
	svcProps := &armsearch.ServiceProperties{}
	if props.ReplicaCount != nil {
		svcProps.ReplicaCount = props.ReplicaCount
	}
	if props.PartitionCount != nil {
		svcProps.PartitionCount = props.PartitionCount
	}
	if props.HostingMode != "" {
		svcProps.HostingMode = to.Ptr(armsearch.HostingMode(props.HostingMode))
	}
	if props.DisableLocalAuth != nil {
		svcProps.DisableLocalAuth = props.DisableLocalAuth
	}
	if props.PublicNetworkAccess != "" {
		svcProps.PublicNetworkAccess = to.Ptr(armsearch.PublicNetworkAccess(props.PublicNetworkAccess))
	}
	if props.SemanticSearch != "" {
		svcProps.SemanticSearch = to.Ptr(armsearch.SearchSemanticSearch(props.SemanticSearch))
	}
	return svcProps
}

func (s *SearchService) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props searchServiceProps
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	if props.Location == "" {
		return nil, fmt.Errorf("location is required")
	}
	if props.SKU == nil || props.SKU.Name == "" {
		return nil, fmt.Errorf("sku.name is required")
	}
	name := props.Name
	if name == "" {
		name = request.Label
	}
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}

	params := armsearch.Service{
		Location:   to.Ptr(props.Location),
		SKU:        &armsearch.SKU{Name: to.Ptr(armsearch.SKUName(props.SKU.Name))},
		Properties: searchServicePropertiesFromProps(props),
	}
	if azureTags := formaeTagsToAzureTags(request.Properties); azureTags != nil {
		params.Tags = azureTags
	}

	poller, err := s.api.BeginCreateOrUpdate(ctx, props.ResourceGroupName, name, params, nil, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Search/searchServices/%s",
		s.config.SubscriptionId, props.ResourceGroupName, name)

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
		propsJSON, err := json.Marshal(s.buildPropertiesFromResult(&result.Service, props.ResourceGroupName))
		if err != nil {
			return nil, fmt.Errorf("failed to marshal response properties: %w", err)
		}
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:          resource.OperationCreate,
				OperationStatus:    resource.OperationStatusSuccess,
				NativeID:           *result.ID,
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

func (s *SearchService) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, name, err := searchServiceIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := s.api.Get(ctx, rgName, name, nil, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(s.buildPropertiesFromResult(&result.Service, rgName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeSearchService,
		Properties:   string(propsJSON),
	}, nil
}

// Update is a synchronous PATCH — unlike Create there is no poller, so Status is
// never reached for an update. sku and hostingMode are createOnly in the schema:
// ARM cannot retier or rehost a service in place.
func (s *SearchService) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, name, err := searchServiceIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props searchServiceProps
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	params := armsearch.ServiceUpdate{Properties: searchServicePropertiesFromProps(props)}
	if azureTags := formaeTagsToAzureTags(request.DesiredProperties); azureTags != nil {
		params.Tags = azureTags
	}

	result, err := s.api.Update(ctx, rgName, name, params, nil, nil)
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

	propsJSON, err := json.Marshal(s.buildPropertiesFromResult(&result.Service, rgName))
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

// Delete is synchronous: there is no poller to resume, so this returns a terminal
// status directly.
func (s *SearchService) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, name, err := searchServiceIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	if _, err := s.api.Delete(ctx, rgName, name, nil, nil); err != nil {
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

	return &resource.DeleteResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationDelete,
			OperationStatus: resource.OperationStatusSuccess,
			NativeID:        request.NativeID,
		},
	}, nil
}

// Status only ever handles a create: Update and Delete are synchronous here.
func (s *SearchService) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	reqID, err := decodeLROStatus(request.RequestID)
	if err != nil {
		return nil, err
	}

	switch reqID.OperationType {
	case lroOpCreate:
		return statusLRO(ctx, request, &reqID, resource.OperationCreate,
			func(token string) (*runtime.Poller[armsearch.ServicesClientCreateOrUpdateResponse], error) {
				return resumePoller[armsearch.ServicesClientCreateOrUpdateResponse](s.pipeline, token)
			},
			func(_ context.Context, result armsearch.ServicesClientCreateOrUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				return s.completeFromService(&result.Service)
			})
	default:
		return nil, fmt.Errorf("unknown operation type: %s", reqID.OperationType)
	}
}

func (s *SearchService) completeFromService(svc *armsearch.Service) (string, json.RawMessage, error) {
	nativeID := ""
	rgName := ""
	if svc.ID != nil {
		nativeID = *svc.ID
		if rg, _, err := searchServiceIDParts(*svc.ID); err == nil {
			rgName = rg
		}
	}
	propsJSON, err := json.Marshal(s.buildPropertiesFromResult(svc, rgName))
	if err != nil {
		return "", nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return nativeID, propsJSON, nil
}

func (s *SearchService) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]

	var nativeIDs []string

	if rgName != "" {
		pager := s.api.NewListByResourceGroupPager(rgName, nil, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list search services: %w", err)
			}
			for _, svc := range page.Value {
				if svc.ID != nil {
					nativeIDs = append(nativeIDs, *svc.ID)
				}
			}
		}
		return &resource.ListResult{NativeIDs: nativeIDs}, nil
	}

	pager := s.api.NewListBySubscriptionPager(nil, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list search services: %w", err)
		}
		for _, svc := range page.Value {
			if svc.ID != nil {
				nativeIDs = append(nativeIDs, *svc.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
