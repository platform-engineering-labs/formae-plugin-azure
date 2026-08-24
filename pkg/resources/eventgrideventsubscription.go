// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/eventgrid/armeventgrid"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeEventGridEventSubscription = "AZURE::EventGrid::EventSubscription"

// eventSubscriptionSegment is the ARM path segment that separates an event
// subscription's scope from its own name. Matched case-insensitively: ARM echoes
// the provider namespace back with varying case.
const eventSubscriptionSegment = "/providers/microsoft.eventgrid/eventsubscriptions/"

// eventGridEventSubscriptionsAPI is the armeventgrid surface used here. Every call
// is scope-based rather than resource-group-based — the scope is the ARM ID of
// whatever emits the events — and create, update and delete are all LROs.
type eventGridEventSubscriptionsAPI interface {
	BeginCreateOrUpdate(ctx context.Context, scope string, eventSubscriptionName string, eventSubscriptionInfo armeventgrid.EventSubscription, options *armeventgrid.EventSubscriptionsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armeventgrid.EventSubscriptionsClientCreateOrUpdateResponse], error)
	Get(ctx context.Context, scope string, eventSubscriptionName string, options *armeventgrid.EventSubscriptionsClientGetOptions) (armeventgrid.EventSubscriptionsClientGetResponse, error)
	BeginDelete(ctx context.Context, scope string, eventSubscriptionName string, options *armeventgrid.EventSubscriptionsClientBeginDeleteOptions) (*runtime.Poller[armeventgrid.EventSubscriptionsClientDeleteResponse], error)
	NewListByResourcePager(resourceGroupName string, providerNamespace string, resourceTypeName string, resourceName string, options *armeventgrid.EventSubscriptionsClientListByResourceOptions) *runtime.Pager[armeventgrid.EventSubscriptionsClientListByResourceResponse]
	NewListGlobalBySubscriptionPager(options *armeventgrid.EventSubscriptionsClientListGlobalBySubscriptionOptions) *runtime.Pager[armeventgrid.EventSubscriptionsClientListGlobalBySubscriptionResponse]
}

func init() {
	registry.Register(ResourceTypeEventGridEventSubscription, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &EventGridEventSubscription{
			api:      c.EventGridEventSubscriptionsClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// EventGridEventSubscription is the provisioner for Event Grid event subscriptions
// (Microsoft.EventGrid/eventSubscriptions), a scoped extension resource.
type EventGridEventSubscription struct {
	api      eventGridEventSubscriptionsAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

// eventGridEventSubscriptionProps mirrors
// schema/pkl/eventgrid/eventsubscription.pkl.
type eventGridEventSubscriptionProps struct {
	Name                    string                          `json:"name"`
	Scope                   string                          `json:"scope"`
	StorageQueueDestination *eventGridStorageQueueDestProps `json:"storageQueueDestination"`
	Filter                  *eventGridFilterProps           `json:"filter"`
	EventDeliverySchema     string                          `json:"eventDeliverySchema"`
}

type eventGridStorageQueueDestProps struct {
	StorageAccountID string `json:"storageAccountId"`
	QueueName        string `json:"queueName"`
}

type eventGridFilterProps struct {
	SubjectBeginsWith  *string  `json:"subjectBeginsWith"`
	SubjectEndsWith    *string  `json:"subjectEndsWith"`
	IncludedEventTypes []string `json:"includedEventTypes"`
}

func parseEventSubscriptionID(nativeID string) (scope, name string, err error) {
	idx := strings.Index(strings.ToLower(nativeID), eventSubscriptionSegment)
	if idx < 0 {
		return "", "", fmt.Errorf("invalid event subscription id %q: expected <scope>%s<name>", nativeID, eventSubscriptionSegment)
	}
	scope = nativeID[:idx]
	name = nativeID[idx+len(eventSubscriptionSegment):]
	if scope == "" || name == "" {
		return "", "", fmt.Errorf("invalid event subscription id %q", nativeID)
	}
	return scope, name, nil
}

func (e *EventGridEventSubscription) buildPropertiesFromResult(sub *armeventgrid.EventSubscription, scope string) map[string]any {
	props := make(map[string]any)

	props["scope"] = scope

	if sub.ID != nil {
		props["id"] = *sub.ID
	}
	if sub.Name != nil {
		props["name"] = *sub.Name
	}

	if p := sub.Properties; p != nil {
		if p.EventDeliverySchema != nil {
			props["eventDeliverySchema"] = string(*p.EventDeliverySchema)
		}

		// Only the Storage-queue destination is modelled. ARM's other endpoint types
		// are skipped rather than half-read: surfacing a destination the schema
		// cannot express would show as drift forever.
		if queue, ok := p.Destination.(*armeventgrid.StorageQueueEventSubscriptionDestination); ok && queue != nil && queue.Properties != nil {
			dest := make(map[string]any)
			if queue.Properties.ResourceID != nil {
				dest["storageAccountId"] = *queue.Properties.ResourceID
			}
			if queue.Properties.QueueName != nil {
				dest["queueName"] = *queue.Properties.QueueName
			}
			if len(dest) > 0 {
				props["storageQueueDestination"] = dest
			}
		}

		if f := p.Filter; f != nil {
			// Advanced filters are not modelled; a filter carrying them is read for
			// its simple parts only, which are still desired state.
			filter := make(map[string]any)
			if f.SubjectBeginsWith != nil && *f.SubjectBeginsWith != "" {
				filter["subjectBeginsWith"] = *f.SubjectBeginsWith
			}
			if f.SubjectEndsWith != nil && *f.SubjectEndsWith != "" {
				filter["subjectEndsWith"] = *f.SubjectEndsWith
			}
			if len(f.IncludedEventTypes) > 0 {
				types := make([]string, 0, len(f.IncludedEventTypes))
				for _, t := range f.IncludedEventTypes {
					if t == nil {
						continue
					}
					types = append(types, *t)
				}
				filter["includedEventTypes"] = types
			}
			if len(filter) > 0 {
				props["filter"] = filter
			}
		}
		// provisioningState and topic are dropped: neither is desired state, and
		// topic merely restates the scope.
	}

	return props
}

// eventGridEventSubscriptionParams builds the request body shared by create and
// update.
func eventGridEventSubscriptionParams(props eventGridEventSubscriptionProps) armeventgrid.EventSubscription {
	subProps := &armeventgrid.EventSubscriptionProperties{
		Destination: &armeventgrid.StorageQueueEventSubscriptionDestination{
			// ARM requires the discriminator on the destination.
			EndpointType: to.Ptr(armeventgrid.EndpointTypeStorageQueue),
			Properties: &armeventgrid.StorageQueueEventSubscriptionDestinationProperties{
				ResourceID: to.Ptr(props.StorageQueueDestination.StorageAccountID),
				QueueName:  to.Ptr(props.StorageQueueDestination.QueueName),
			},
		},
	}

	if props.EventDeliverySchema != "" {
		subProps.EventDeliverySchema = to.Ptr(armeventgrid.EventDeliverySchema(props.EventDeliverySchema))
	}

	if f := props.Filter; f != nil {
		filter := &armeventgrid.EventSubscriptionFilter{
			SubjectBeginsWith: f.SubjectBeginsWith,
			SubjectEndsWith:   f.SubjectEndsWith,
		}
		if len(f.IncludedEventTypes) > 0 {
			types := make([]*string, 0, len(f.IncludedEventTypes))
			for _, t := range f.IncludedEventTypes {
				types = append(types, to.Ptr(t))
			}
			filter.IncludedEventTypes = types
		}
		subProps.Filter = filter
	}

	return armeventgrid.EventSubscription{Properties: subProps}
}

func (e *EventGridEventSubscription) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props eventGridEventSubscriptionProps
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.Scope == "" {
		return nil, fmt.Errorf("scope is required")
	}
	if props.StorageQueueDestination == nil || props.StorageQueueDestination.StorageAccountID == "" {
		return nil, fmt.Errorf("storageQueueDestination.storageAccountId is required")
	}
	if props.StorageQueueDestination.QueueName == "" {
		return nil, fmt.Errorf("storageQueueDestination.queueName is required")
	}
	name := props.Name
	if name == "" {
		name = request.Label
	}
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}

	poller, err := e.api.BeginCreateOrUpdate(ctx, props.Scope, name,
		eventGridEventSubscriptionParams(props), nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	// ARM builds the native ID by appending its own provider segment to the scope.
	expectedNativeID := fmt.Sprintf("%s/providers/Microsoft.EventGrid/eventSubscriptions/%s", props.Scope, name)

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
		nativeID, propsJSON, err := e.completeFromSubscription(&result.EventSubscription, props.Scope)
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

func (e *EventGridEventSubscription) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	scope, name, err := parseEventSubscriptionID(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := e.api.Get(ctx, scope, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(e.buildPropertiesFromResult(&result.EventSubscription, scope))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeEventGridEventSubscription,
		Properties:   string(propsJSON),
	}, nil
}

// Update re-PUTs through BeginCreateOrUpdate rather than using the SDK's
// BeginUpdate: the patch body (EventSubscriptionUpdateParameters) takes the same
// full destination and filter anyway, so a full PUT keeps one code path.
func (e *EventGridEventSubscription) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	scope, name, err := parseEventSubscriptionID(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props eventGridEventSubscriptionProps
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.StorageQueueDestination == nil {
		return nil, fmt.Errorf("storageQueueDestination is required")
	}

	poller, err := e.api.BeginCreateOrUpdate(ctx, scope, name,
		eventGridEventSubscriptionParams(props), nil)
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
		propsJSON, err := json.Marshal(e.buildPropertiesFromResult(&result.EventSubscription, scope))
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

func (e *EventGridEventSubscription) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	scope, name, err := parseEventSubscriptionID(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, err := e.api.BeginDelete(ctx, scope, name, nil)
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

func (e *EventGridEventSubscription) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	reqID, err := decodeLROStatus(request.RequestID)
	if err != nil {
		return nil, err
	}

	switch reqID.OperationType {
	case lroOpCreate:
		return statusLRO(ctx, request, &reqID, resource.OperationCreate,
			func(token string) (*runtime.Poller[armeventgrid.EventSubscriptionsClientCreateOrUpdateResponse], error) {
				return resumePoller[armeventgrid.EventSubscriptionsClientCreateOrUpdateResponse](e.pipeline, token)
			},
			func(_ context.Context, result armeventgrid.EventSubscriptionsClientCreateOrUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				scope := ""
				if result.ID != nil {
					if parsed, _, err := parseEventSubscriptionID(*result.ID); err == nil {
						scope = parsed
					}
				}
				return e.completeFromSubscription(&result.EventSubscription, scope)
			})
	case lroOpUpdate:
		// Resumed as a CreateOrUpdate response, NOT an Update response: Update
		// issues BeginCreateOrUpdate (see there for why), so that is the poller whose
		// resume token was handed out. Decoding the token into the SDK's Update
		// response type instead kills the plugin operator mid-poll.
		return statusLRO(ctx, request, &reqID, resource.OperationUpdate,
			func(token string) (*runtime.Poller[armeventgrid.EventSubscriptionsClientCreateOrUpdateResponse], error) {
				return resumePoller[armeventgrid.EventSubscriptionsClientCreateOrUpdateResponse](e.pipeline, token)
			},
			func(_ context.Context, result armeventgrid.EventSubscriptionsClientCreateOrUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				scope := ""
				if result.ID != nil {
					if parsed, _, err := parseEventSubscriptionID(*result.ID); err == nil {
						scope = parsed
					}
				}
				return e.completeFromSubscription(&result.EventSubscription, scope)
			})
	case lroOpDelete:
		return statusDeleteLRO(ctx, request, &reqID,
			func(token string) (*runtime.Poller[armeventgrid.EventSubscriptionsClientDeleteResponse], error) {
				return resumePoller[armeventgrid.EventSubscriptionsClientDeleteResponse](e.pipeline, token)
			}, nil)
	default:
		return nil, fmt.Errorf("unknown operation type: %s", reqID.OperationType)
	}
}

func (e *EventGridEventSubscription) completeFromSubscription(sub *armeventgrid.EventSubscription, scope string) (string, json.RawMessage, error) {
	nativeID := ""
	if sub.ID != nil {
		nativeID = *sub.ID
	}
	propsJSON, err := json.Marshal(e.buildPropertiesFromResult(sub, scope))
	if err != nil {
		return "", nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return nativeID, propsJSON, nil
}

// List pages a single scope when the caller names one, and otherwise falls back to
// every subscription-level subscription.
//
// An event subscription hangs off an arbitrary resource, so discovery has no parent
// to hand down the four ARM path parts from. The global listing is what makes the
// type discoverable at all; it covers subscription-scoped subscriptions, which is
// what this provider creates.
func (e *EventGridEventSubscription) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	providerNamespace := request.AdditionalProperties["providerNamespace"]
	resourceTypeName := request.AdditionalProperties["resourceTypeName"]
	resourceName := request.AdditionalProperties["resourceName"]
	var nativeIDs []string

	if rgName == "" || providerNamespace == "" || resourceTypeName == "" || resourceName == "" {
		pager := e.api.NewListGlobalBySubscriptionPager(nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list event subscriptions: %w", err)
			}
			for _, sub := range page.Value {
				if sub != nil && sub.ID != nil {
					nativeIDs = append(nativeIDs, *sub.ID)
				}
			}
		}
		return &resource.ListResult{NativeIDs: nativeIDs}, nil
	}

	pager := e.api.NewListByResourcePager(rgName, providerNamespace, resourceTypeName, resourceName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list event subscriptions: %w", err)
		}
		for _, sub := range page.Value {
			if sub.ID != nil {
				nativeIDs = append(nativeIDs, *sub.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
