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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/eventgrid/armeventgrid"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeEventGridDomain = "AZURE::EventGrid::Domain"

// eventGridDomainsAPI is the subset of *armeventgrid.DomainsClient used here.
// Create/update/delete are LROs.
type eventGridDomainsAPI interface {
	BeginCreateOrUpdate(ctx context.Context, resourceGroupName, domainName string, domainInfo armeventgrid.Domain, options *armeventgrid.DomainsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armeventgrid.DomainsClientCreateOrUpdateResponse], error)
	Get(ctx context.Context, resourceGroupName, domainName string, options *armeventgrid.DomainsClientGetOptions) (armeventgrid.DomainsClientGetResponse, error)
	BeginDelete(ctx context.Context, resourceGroupName, domainName string, options *armeventgrid.DomainsClientBeginDeleteOptions) (*runtime.Poller[armeventgrid.DomainsClientDeleteResponse], error)
	NewListByResourceGroupPager(resourceGroupName string, options *armeventgrid.DomainsClientListByResourceGroupOptions) *runtime.Pager[armeventgrid.DomainsClientListByResourceGroupResponse]
	NewListBySubscriptionPager(options *armeventgrid.DomainsClientListBySubscriptionOptions) *runtime.Pager[armeventgrid.DomainsClientListBySubscriptionResponse]
}

func init() {
	registry.Register(ResourceTypeEventGridDomain, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &EventGridDomain{
			api:      c.EventGridDomainsClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// EventGridDomain is the provisioner for Event Grid domains
// (`Microsoft.EventGrid/domains/<name>`) — one ingress endpoint that fans out to
// many AZURE::EventGrid::DomainTopic children, so a multi-tenant publisher needs a
// single endpoint and a single set of credentials instead of one topic per tenant.
type EventGridDomain struct {
	api      eventGridDomainsAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

func eventGridDomainIDParts(resourceID string) (rgName, name string, err error) {
	rgName, names, err := armExactIDParts(resourceID, "domains")
	if err != nil {
		return "", "", err
	}
	return rgName, names[0], nil
}

func serializeEventGridDomainProperties(result armeventgrid.Domain, rgName, name string) (json.RawMessage, error) {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	if result.Name != nil {
		props["name"] = *result.Name
	} else {
		props["name"] = name
	}
	if result.Location != nil {
		props["location"] = *result.Location
	}
	if result.ID != nil {
		props["id"] = *result.ID
	}

	if p := result.Properties; p != nil {
		if p.InputSchema != nil {
			props["inputSchema"] = string(*p.InputSchema)
		}
		if p.PublicNetworkAccess != nil {
			props["publicNetworkAccess"] = string(*p.PublicNetworkAccess)
		}
		if p.DisableLocalAuth != nil {
			props["disableLocalAuth"] = *p.DisableLocalAuth
		}
		if p.AutoCreateTopicWithFirstSubscription != nil {
			props["autoCreateTopicWithFirstSubscription"] = *p.AutoCreateTopicWithFirstSubscription
		}
		if p.AutoDeleteTopicWithLastSubscription != nil {
			props["autoDeleteTopicWithLastSubscription"] = *p.AutoDeleteTopicWithLastSubscription
		}
		if rules := eventGridInboundIPRulesToProperties(p.InboundIPRules); rules != nil {
			props["inboundIpRules"] = rules
		}
		// endpoint is assigned by Azure; surfaced so publishers can reference it.
		if p.Endpoint != nil {
			props["endpoint"] = *p.Endpoint
		}
	}

	if tags := azureTagsToFormaeTags(result.Tags); tags != nil {
		props["Tags"] = tags
	}

	return json.Marshal(props)
}

func eventGridDomainParamsFromProperties(props map[string]any, rawProps json.RawMessage) (armeventgrid.Domain, error) {
	location, _ := props["location"].(string)
	if location == "" {
		return armeventgrid.Domain{}, fmt.Errorf("location is required")
	}

	domain := armeventgrid.Domain{
		Location:   to.Ptr(location),
		Properties: &armeventgrid.DomainProperties{},
	}

	if v, ok := props["inputSchema"].(string); ok && v != "" {
		domain.Properties.InputSchema = to.Ptr(armeventgrid.InputSchema(v))
	}
	if v, ok := props["publicNetworkAccess"].(string); ok && v != "" {
		domain.Properties.PublicNetworkAccess = to.Ptr(armeventgrid.PublicNetworkAccess(v))
	}
	if v, ok := props["disableLocalAuth"].(bool); ok {
		domain.Properties.DisableLocalAuth = to.Ptr(v)
	}
	if v, ok := props["autoCreateTopicWithFirstSubscription"].(bool); ok {
		domain.Properties.AutoCreateTopicWithFirstSubscription = to.Ptr(v)
	}
	if v, ok := props["autoDeleteTopicWithLastSubscription"].(bool); ok {
		domain.Properties.AutoDeleteTopicWithLastSubscription = to.Ptr(v)
	}
	rules, err := eventGridInboundIPRulesFromProperties(props)
	if err != nil {
		return armeventgrid.Domain{}, err
	}
	domain.Properties.InboundIPRules = rules

	if azureTags := formaeTagsToAzureTags(rawProps); azureTags != nil {
		domain.Tags = azureTags
	}

	return domain, nil
}

func (t *EventGridDomain) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props map[string]any
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	rgName, _ := props["resourceGroupName"].(string)
	if rgName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	name, _ := props["name"].(string)
	if name == "" {
		name = request.Label
	}
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}

	params, err := eventGridDomainParamsFromProperties(props, request.Properties)
	if err != nil {
		return nil, err
	}

	poller, err := t.api.BeginCreateOrUpdate(ctx, rgName, name, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	expectedID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.EventGrid/domains/%s",
		t.config.SubscriptionId, rgName, name)

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
		propsJSON, err := serializeEventGridDomainProperties(result.Domain, rgName, name)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize EventGrid Domain properties: %w", err)
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

	token, err := poller.ResumeToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get resume token: %w", err)
	}
	reqID, err := encodeLROStart(lroOpCreate, token, expectedID)
	if err != nil {
		return nil, err
	}

	return &resource.CreateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationCreate,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       reqID,
			NativeID:        expectedID,
		},
	}, nil
}

func (t *EventGridDomain) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, name, err := eventGridDomainIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := t.api.Get(ctx, rgName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := serializeEventGridDomainProperties(result.Domain, rgName, name)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize EventGrid Domain properties: %w", err)
	}

	return &resource.ReadResult{
		ResourceType: ResourceTypeEventGridDomain,
		Properties:   string(propsJSON),
	}, nil
}

func (t *EventGridDomain) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, name, err := eventGridDomainIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props map[string]any
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse desired properties: %w", err)
	}

	// Full-body PUT rather than the PATCH verb: DomainUpdateParameters covers only a
	// subset, and CreateOrUpdate is an idempotent upsert.
	params, err := eventGridDomainParamsFromProperties(props, request.DesiredProperties)
	if err != nil {
		return nil, err
	}

	poller, err := t.api.BeginCreateOrUpdate(ctx, rgName, name, params, nil)
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
		propsJSON, err := serializeEventGridDomainProperties(result.Domain, rgName, name)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize EventGrid Domain properties: %w", err)
		}
		return &resource.UpdateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:          resource.OperationUpdate,
				OperationStatus:    resource.OperationStatusSuccess,
				NativeID:           *result.ID,
				ResourceProperties: propsJSON,
			},
		}, nil
	}

	token, err := poller.ResumeToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get resume token: %w", err)
	}
	reqID, err := encodeLROStart(lroOpUpdate, token, request.NativeID)
	if err != nil {
		return nil, err
	}

	return &resource.UpdateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationUpdate,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       reqID,
			NativeID:        request.NativeID,
		},
	}, nil
}

func (t *EventGridDomain) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, name, err := eventGridDomainIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, err := t.api.BeginDelete(ctx, rgName, name, nil)
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
		}, fmt.Errorf("failed to delete EventGrid Domain: %w", err)
	}

	if poller.Done() {
		return &resource.DeleteResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationDelete,
				OperationStatus: resource.OperationStatusSuccess,
				NativeID:        request.NativeID,
			},
		}, nil
	}

	token, err := poller.ResumeToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get resume token: %w", err)
	}
	reqID, err := encodeLROStart(lroOpDelete, token, request.NativeID)
	if err != nil {
		return nil, err
	}

	return &resource.DeleteResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationDelete,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       reqID,
			NativeID:        request.NativeID,
		},
	}, nil
}

func (t *EventGridDomain) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	reqID, err := decodeLROStatus(request.RequestID)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
			},
		}, err
	}

	switch reqID.OperationType {
	case lroOpCreate, lroOpUpdate:
		return t.statusCreateOrUpdate(ctx, request, &reqID)
	case lroOpDelete:
		return t.statusDelete(ctx, request, &reqID)
	default:
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
			},
		}, fmt.Errorf("unknown LRO operation type: %s", reqID.OperationType)
	}
}

func (t *EventGridDomain) statusCreateOrUpdate(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	operation := resource.OperationCreate
	if reqID.OperationType == lroOpUpdate {
		operation = resource.OperationUpdate
	}

	return statusLRO(ctx, request, reqID, operation,
		func(token string) (*runtime.Poller[armeventgrid.DomainsClientCreateOrUpdateResponse], error) {
			return resumePoller[armeventgrid.DomainsClientCreateOrUpdateResponse](t.pipeline, token)
		},
		func(_ context.Context, result armeventgrid.DomainsClientCreateOrUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
			rgName, name, err := eventGridDomainIDParts(*result.ID)
			if err != nil {
				return "", nil, err
			}
			propsJSON, err := serializeEventGridDomainProperties(result.Domain, rgName, name)
			if err != nil {
				return "", nil, fmt.Errorf("failed to serialize EventGrid Domain properties: %w", err)
			}
			return *result.ID, propsJSON, nil
		})
}

func (t *EventGridDomain) statusDelete(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	return statusDeleteLRO(ctx, request, reqID,
		func(token string) (*runtime.Poller[armeventgrid.DomainsClientDeleteResponse], error) {
			return resumePoller[armeventgrid.DomainsClientDeleteResponse](t.pipeline, token)
		}, nil)
}

func (t *EventGridDomain) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]

	var nativeIDs []string
	if rgName != "" {
		pager := t.api.NewListByResourceGroupPager(rgName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list EventGrid domains in resource group %s: %w", rgName, err)
			}
			for _, domain := range page.Value {
				if domain.ID != nil {
					nativeIDs = append(nativeIDs, *domain.ID)
				}
			}
		}
		return &resource.ListResult{NativeIDs: nativeIDs}, nil
	}

	pager := t.api.NewListBySubscriptionPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list EventGrid domains: %w", err)
		}
		for _, domain := range page.Value {
			if domain.ID != nil {
				nativeIDs = append(nativeIDs, *domain.ID)
			}
		}
	}

	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
