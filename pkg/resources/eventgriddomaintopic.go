// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/eventgrid/armeventgrid"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeEventGridDomainTopic = "AZURE::EventGrid::DomainTopic"

// eventGridDomainTopicsAPI is the subset of *armeventgrid.DomainTopicsClient used
// here. Create/delete are LROs. Note BeginCreateOrUpdate takes **no request body**:
// a domain topic is a name under a domain and has no writable properties at all.
type eventGridDomainTopicsAPI interface {
	BeginCreateOrUpdate(ctx context.Context, resourceGroupName, domainName, domainTopicName string, options *armeventgrid.DomainTopicsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armeventgrid.DomainTopicsClientCreateOrUpdateResponse], error)
	Get(ctx context.Context, resourceGroupName, domainName, domainTopicName string, options *armeventgrid.DomainTopicsClientGetOptions) (armeventgrid.DomainTopicsClientGetResponse, error)
	BeginDelete(ctx context.Context, resourceGroupName, domainName, domainTopicName string, options *armeventgrid.DomainTopicsClientBeginDeleteOptions) (*runtime.Poller[armeventgrid.DomainTopicsClientDeleteResponse], error)
	NewListByDomainPager(resourceGroupName, domainName string, options *armeventgrid.DomainTopicsClientListByDomainOptions) *runtime.Pager[armeventgrid.DomainTopicsClientListByDomainResponse]
}

func init() {
	registry.Register(ResourceTypeEventGridDomainTopic, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &EventGridDomainTopic{
			api:      c.EventGridDomainTopicsClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// EventGridDomainTopic is the provisioner for Event Grid domain topics
// (`Microsoft.EventGrid/domains/<domain>/topics/<name>`) — one tenant/partition
// inside an AZURE::EventGrid::Domain.
//
// The type has no writable properties beyond its own name, so Update is a no-op
// that re-reads current state: there is nothing ARM would accept a change to.
type EventGridDomainTopic struct {
	api      eventGridDomainTopicsAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

// eventGridDomainTopicIDParts parses `.../domains/<domain>/topics/<name>`.
//
// armExactIDParts, not armIDParts: the leaf segment is also called "topics", so a
// loose parent-walking match would let a top-level AZURE::EventGrid::Topic ID parse
// as a domain topic and vice versa.
func eventGridDomainTopicIDParts(resourceID string) (rgName, domainName, topicName string, err error) {
	rgName, names, err := armExactIDParts(resourceID, "domains", "topics")
	if err != nil {
		return "", "", "", err
	}
	return rgName, names[0], names[1], nil
}

func serializeEventGridDomainTopicProperties(result armeventgrid.DomainTopic, rgName, domainName, topicName string) (json.RawMessage, error) {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	props["domainName"] = domainName
	if result.Name != nil {
		props["name"] = *result.Name
	} else {
		props["name"] = topicName
	}
	if result.ID != nil {
		props["id"] = *result.ID
	}

	return json.Marshal(props)
}

func (t *EventGridDomainTopic) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props map[string]any
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	rgName, _ := props["resourceGroupName"].(string)
	if rgName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	domainName, _ := props["domainName"].(string)
	if domainName == "" {
		return nil, fmt.Errorf("domainName is required")
	}
	topicName, _ := props["name"].(string)
	if topicName == "" {
		topicName = request.Label
	}
	if topicName == "" {
		return nil, fmt.Errorf("name is required")
	}

	poller, err := t.api.BeginCreateOrUpdate(ctx, rgName, domainName, topicName, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	expectedID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.EventGrid/domains/%s/topics/%s",
		t.config.SubscriptionId, rgName, domainName, topicName)

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
		propsJSON, err := serializeEventGridDomainTopicProperties(result.DomainTopic, rgName, domainName, topicName)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize EventGrid DomainTopic properties: %w", err)
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

func (t *EventGridDomainTopic) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, domainName, topicName, err := eventGridDomainTopicIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := t.api.Get(ctx, rgName, domainName, topicName, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := serializeEventGridDomainTopicProperties(result.DomainTopic, rgName, domainName, topicName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize EventGrid DomainTopic properties: %w", err)
	}

	return &resource.ReadResult{
		ResourceType: ResourceTypeEventGridDomainTopic,
		Properties:   string(propsJSON),
	}, nil
}

// Update re-reads and returns current state. A domain topic has no writable ARM
// properties — everything that identifies it is createOnly — so there is nothing to
// send. Returning success (rather than erroring) keeps a no-op reconcile clean.
func (t *EventGridDomainTopic) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, domainName, topicName, err := eventGridDomainTopicIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := t.api.Get(ctx, rgName, domainName, topicName, nil)
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

	propsJSON, err := serializeEventGridDomainTopicProperties(result.DomainTopic, rgName, domainName, topicName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize EventGrid DomainTopic properties: %w", err)
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

func (t *EventGridDomainTopic) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, domainName, topicName, err := eventGridDomainTopicIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, err := t.api.BeginDelete(ctx, rgName, domainName, topicName, nil)
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
		}, fmt.Errorf("failed to delete EventGrid DomainTopic: %w", err)
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

func (t *EventGridDomainTopic) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
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
		return statusLRO(ctx, request, &reqID, resource.OperationCreate,
			func(token string) (*runtime.Poller[armeventgrid.DomainTopicsClientCreateOrUpdateResponse], error) {
				return resumePoller[armeventgrid.DomainTopicsClientCreateOrUpdateResponse](t.pipeline, token)
			},
			func(_ context.Context, result armeventgrid.DomainTopicsClientCreateOrUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				rgName, domainName, topicName, err := eventGridDomainTopicIDParts(*result.ID)
				if err != nil {
					return "", nil, err
				}
				propsJSON, err := serializeEventGridDomainTopicProperties(result.DomainTopic, rgName, domainName, topicName)
				if err != nil {
					return "", nil, fmt.Errorf("failed to serialize EventGrid DomainTopic properties: %w", err)
				}
				return *result.ID, propsJSON, nil
			})
	case lroOpDelete:
		return statusDeleteLRO(ctx, request, &reqID,
			func(token string) (*runtime.Poller[armeventgrid.DomainTopicsClientDeleteResponse], error) {
				return resumePoller[armeventgrid.DomainTopicsClientDeleteResponse](t.pipeline, token)
			}, nil)
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

func (t *EventGridDomainTopic) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	domainName := request.AdditionalProperties["domainName"]

	var nativeIDs []string
	pager := t.api.NewListByDomainPager(rgName, domainName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list EventGrid domain topics in domain %s: %w", domainName, err)
		}
		for _, topic := range page.Value {
			if topic.ID != nil {
				nativeIDs = append(nativeIDs, *topic.ID)
			}
		}
	}

	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
