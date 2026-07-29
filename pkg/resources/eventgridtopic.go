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

const ResourceTypeEventGridTopic = "AZURE::EventGrid::Topic"

// eventGridTopicsAPI is the subset of *armeventgrid.TopicsClient used here.
// Create/update/delete are LROs.
type eventGridTopicsAPI interface {
	BeginCreateOrUpdate(ctx context.Context, resourceGroupName, topicName string, topicInfo armeventgrid.Topic, options *armeventgrid.TopicsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armeventgrid.TopicsClientCreateOrUpdateResponse], error)
	Get(ctx context.Context, resourceGroupName, topicName string, options *armeventgrid.TopicsClientGetOptions) (armeventgrid.TopicsClientGetResponse, error)
	BeginDelete(ctx context.Context, resourceGroupName, topicName string, options *armeventgrid.TopicsClientBeginDeleteOptions) (*runtime.Poller[armeventgrid.TopicsClientDeleteResponse], error)
	NewListByResourceGroupPager(resourceGroupName string, options *armeventgrid.TopicsClientListByResourceGroupOptions) *runtime.Pager[armeventgrid.TopicsClientListByResourceGroupResponse]
	NewListBySubscriptionPager(options *armeventgrid.TopicsClientListBySubscriptionOptions) *runtime.Pager[armeventgrid.TopicsClientListBySubscriptionResponse]
}

func init() {
	registry.Register(ResourceTypeEventGridTopic, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &EventGridTopic{
			api:      c.EventGridTopicsClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// EventGridTopic is the provisioner for Event Grid custom topics
// (`Microsoft.EventGrid/topics/<name>`) — the ingress endpoint an application
// publishes its own events to, as opposed to the already-implemented
// AZURE::EventGrid::SystemTopic which wraps events emitted by an Azure resource.
type EventGridTopic struct {
	api      eventGridTopicsAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

func eventGridTopicIDParts(resourceID string) (rgName, name string, err error) {
	rgName, names, err := armExactIDParts(resourceID, "topics")
	if err != nil {
		return "", "", err
	}
	return rgName, names[0], nil
}

func serializeEventGridTopicProperties(result armeventgrid.Topic, rgName, name string) (json.RawMessage, error) {
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

func eventGridTopicParamsFromProperties(props map[string]any, rawProps json.RawMessage) (armeventgrid.Topic, error) {
	location, _ := props["location"].(string)
	if location == "" {
		return armeventgrid.Topic{}, fmt.Errorf("location is required")
	}

	topic := armeventgrid.Topic{
		Location:   to.Ptr(location),
		Properties: &armeventgrid.TopicProperties{},
	}

	if v, ok := props["inputSchema"].(string); ok && v != "" {
		topic.Properties.InputSchema = to.Ptr(armeventgrid.InputSchema(v))
	}
	if v, ok := props["publicNetworkAccess"].(string); ok && v != "" {
		topic.Properties.PublicNetworkAccess = to.Ptr(armeventgrid.PublicNetworkAccess(v))
	}
	if v, ok := props["disableLocalAuth"].(bool); ok {
		topic.Properties.DisableLocalAuth = to.Ptr(v)
	}
	rules, err := eventGridInboundIPRulesFromProperties(props)
	if err != nil {
		return armeventgrid.Topic{}, err
	}
	topic.Properties.InboundIPRules = rules

	if azureTags := formaeTagsToAzureTags(rawProps); azureTags != nil {
		topic.Tags = azureTags
	}

	return topic, nil
}

func (t *EventGridTopic) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
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

	params, err := eventGridTopicParamsFromProperties(props, request.Properties)
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

	expectedID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.EventGrid/topics/%s",
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
		propsJSON, err := serializeEventGridTopicProperties(result.Topic, rgName, name)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize EventGrid Topic properties: %w", err)
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

func (t *EventGridTopic) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, name, err := eventGridTopicIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := t.api.Get(ctx, rgName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := serializeEventGridTopicProperties(result.Topic, rgName, name)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize EventGrid Topic properties: %w", err)
	}

	return &resource.ReadResult{
		ResourceType: ResourceTypeEventGridTopic,
		Properties:   string(propsJSON),
	}, nil
}

func (t *EventGridTopic) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, name, err := eventGridTopicIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props map[string]any
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse desired properties: %w", err)
	}

	// Full-body PUT rather than the PATCH verb: TopicUpdateParameters covers only a
	// subset, and CreateOrUpdate is an idempotent upsert.
	params, err := eventGridTopicParamsFromProperties(props, request.DesiredProperties)
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
		propsJSON, err := serializeEventGridTopicProperties(result.Topic, rgName, name)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize EventGrid Topic properties: %w", err)
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

func (t *EventGridTopic) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, name, err := eventGridTopicIDParts(request.NativeID)
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
		}, fmt.Errorf("failed to delete EventGrid Topic: %w", err)
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

func (t *EventGridTopic) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
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

func (t *EventGridTopic) statusCreateOrUpdate(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	operation := resource.OperationCreate
	if reqID.OperationType == lroOpUpdate {
		operation = resource.OperationUpdate
	}

	return statusLRO(ctx, request, reqID, operation,
		func(token string) (*runtime.Poller[armeventgrid.TopicsClientCreateOrUpdateResponse], error) {
			return resumePoller[armeventgrid.TopicsClientCreateOrUpdateResponse](t.pipeline, token)
		},
		func(_ context.Context, result armeventgrid.TopicsClientCreateOrUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
			rgName, name, err := eventGridTopicIDParts(*result.ID)
			if err != nil {
				return "", nil, err
			}
			propsJSON, err := serializeEventGridTopicProperties(result.Topic, rgName, name)
			if err != nil {
				return "", nil, fmt.Errorf("failed to serialize EventGrid Topic properties: %w", err)
			}
			return *result.ID, propsJSON, nil
		})
}

func (t *EventGridTopic) statusDelete(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	return statusDeleteLRO(ctx, request, reqID,
		func(token string) (*runtime.Poller[armeventgrid.TopicsClientDeleteResponse], error) {
			return resumePoller[armeventgrid.TopicsClientDeleteResponse](t.pipeline, token)
		}, nil)
}

func (t *EventGridTopic) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]

	var nativeIDs []string
	if rgName != "" {
		pager := t.api.NewListByResourceGroupPager(rgName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list EventGrid topics in resource group %s: %w", rgName, err)
			}
			for _, topic := range page.Value {
				if topic.ID != nil {
					nativeIDs = append(nativeIDs, *topic.ID)
				}
			}
		}
		return &resource.ListResult{NativeIDs: nativeIDs}, nil
	}

	pager := t.api.NewListBySubscriptionPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list EventGrid topics: %w", err)
		}
		for _, topic := range page.Value {
			if topic.ID != nil {
				nativeIDs = append(nativeIDs, *topic.ID)
			}
		}
	}

	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
