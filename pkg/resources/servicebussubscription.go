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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/servicebus/armservicebus"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeServiceBusSubscription = "AZURE::ServiceBus::Subscription"

// serviceBusSubscriptionsAPI is the subset of *armservicebus.SubscriptionsClient
// used here. Subscription operations are synchronous (no LRO/poller).
type serviceBusSubscriptionsAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName, namespaceName, topicName, subscriptionName string, parameters armservicebus.SBSubscription, options *armservicebus.SubscriptionsClientCreateOrUpdateOptions) (armservicebus.SubscriptionsClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName, namespaceName, topicName, subscriptionName string, options *armservicebus.SubscriptionsClientGetOptions) (armservicebus.SubscriptionsClientGetResponse, error)
	Delete(ctx context.Context, resourceGroupName, namespaceName, topicName, subscriptionName string, options *armservicebus.SubscriptionsClientDeleteOptions) (armservicebus.SubscriptionsClientDeleteResponse, error)
	NewListByTopicPager(resourceGroupName, namespaceName, topicName string, options *armservicebus.SubscriptionsClientListByTopicOptions) *runtime.Pager[armservicebus.SubscriptionsClientListByTopicResponse]
}

func init() {
	registry.Register(ResourceTypeServiceBusSubscription, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &ServiceBusSubscription{api: c.ServiceBusSubscriptionsClient, config: cfg}
	})
}

// ServiceBusSubscription is the provisioner for Service Bus topic subscriptions
// (`Microsoft.ServiceBus/namespaces/<ns>/topics/<topic>/subscriptions/<name>`). It
// is a child of AZURE::ServiceBus::Topic. All operations are synchronous.
//
// ponytail: subscription rules/filters (correlation and SQL filters) are a separate
// ARM sub-resource and are not modelled here.
type ServiceBusSubscription struct {
	api    serviceBusSubscriptionsAPI
	config *config.Config
}

func serviceBusSubscriptionIDParts(resourceID string) (rgName, namespaceName, topicName, subscriptionName string, err error) {
	// armExactIDParts, not armIDParts: "subscriptions" would otherwise match the
	// /subscriptions/{id} scope segment of every ARM ID.
	rgName, names, err := armExactIDParts(resourceID, "namespaces", "topics", "subscriptions")
	if err != nil {
		return "", "", "", "", err
	}
	return rgName, names[0], names[1], names[2], nil
}

func serializeServiceBusSubscriptionProperties(result armservicebus.SBSubscription, rgName, namespaceName, topicName, subscriptionName string) (json.RawMessage, error) {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	props["namespaceName"] = namespaceName
	props["topicName"] = topicName
	if result.Name != nil {
		props["name"] = *result.Name
	} else {
		props["name"] = subscriptionName
	}
	if result.ID != nil {
		props["id"] = *result.ID
	}

	if p := result.Properties; p != nil {
		sbPutString(props, "lockDuration", p.LockDuration)
		sbPutString(props, "defaultMessageTimeToLive", p.DefaultMessageTimeToLive)
		sbPutString(props, "autoDeleteOnIdle", p.AutoDeleteOnIdle)
		sbPutString(props, "forwardTo", p.ForwardTo)
		sbPutString(props, "forwardDeadLetteredMessagesTo", p.ForwardDeadLetteredMessagesTo)
		sbPutInt32(props, "maxDeliveryCount", p.MaxDeliveryCount)
		sbPutBool(props, "requiresSession", p.RequiresSession)
		sbPutBool(props, "deadLetteringOnMessageExpiration", p.DeadLetteringOnMessageExpiration)
		sbPutBool(props, "deadLetteringOnFilterEvaluationExceptions", p.DeadLetteringOnFilterEvaluationExceptions)
		sbPutBool(props, "enableBatchedOperations", p.EnableBatchedOperations)
		if p.Status != nil {
			props["status"] = string(*p.Status)
		}
	}

	return json.Marshal(props)
}

func serviceBusSubscriptionParamsFromProperties(props map[string]any) armservicebus.SBSubscription {
	p := &armservicebus.SBSubscriptionProperties{
		LockDuration:                              sbOptString(props, "lockDuration"),
		DefaultMessageTimeToLive:                  sbOptString(props, "defaultMessageTimeToLive"),
		AutoDeleteOnIdle:                          sbOptString(props, "autoDeleteOnIdle"),
		ForwardTo:                                 sbOptString(props, "forwardTo"),
		ForwardDeadLetteredMessagesTo:             sbOptString(props, "forwardDeadLetteredMessagesTo"),
		MaxDeliveryCount:                          sbOptInt32(props, "maxDeliveryCount"),
		RequiresSession:                           sbOptBool(props, "requiresSession"),
		DeadLetteringOnMessageExpiration:          sbOptBool(props, "deadLetteringOnMessageExpiration"),
		DeadLetteringOnFilterEvaluationExceptions: sbOptBool(props, "deadLetteringOnFilterEvaluationExceptions"),
		EnableBatchedOperations:                   sbOptBool(props, "enableBatchedOperations"),
	}
	if v, ok := props["status"].(string); ok && v != "" {
		p.Status = to.Ptr(armservicebus.EntityStatus(v))
	}
	return armservicebus.SBSubscription{Properties: p}
}

func (s *ServiceBusSubscription) upsert(ctx context.Context, operation resource.Operation, nativeID string, rawProps json.RawMessage, label string) (*resource.ProgressResult, error) {
	var props map[string]any
	if err := json.Unmarshal(rawProps, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	var rgName, namespaceName, topicName, subscriptionName string
	if operation == resource.OperationUpdate {
		var err error
		rgName, namespaceName, topicName, subscriptionName, err = serviceBusSubscriptionIDParts(nativeID)
		if err != nil {
			return nil, err
		}
	} else {
		rgName, _ = props["resourceGroupName"].(string)
		if rgName == "" {
			return nil, fmt.Errorf("resourceGroupName is required")
		}
		namespaceName, _ = props["namespaceName"].(string)
		if namespaceName == "" {
			return nil, fmt.Errorf("namespaceName is required")
		}
		topicName, _ = props["topicName"].(string)
		if topicName == "" {
			return nil, fmt.Errorf("topicName is required")
		}
		subscriptionName, _ = props["name"].(string)
		if subscriptionName == "" {
			subscriptionName = label
		}
		if subscriptionName == "" {
			return nil, fmt.Errorf("name is required")
		}
	}

	result, err := s.api.CreateOrUpdate(ctx, rgName, namespaceName, topicName, subscriptionName,
		serviceBusSubscriptionParamsFromProperties(props), nil)
	if err != nil {
		return &resource.ProgressResult{
			Operation:       operation,
			OperationStatus: resource.OperationStatusFailure,
			NativeID:        nativeID,
			ErrorCode:       operationErrorCode(err),
		}, nil
	}

	propsJSON, err := serializeServiceBusSubscriptionProperties(result.SBSubscription, rgName, namespaceName, topicName, subscriptionName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize ServiceBus Subscription properties: %w", err)
	}

	resolvedID := nativeID
	if result.ID != nil {
		resolvedID = *result.ID
	}

	return &resource.ProgressResult{
		Operation:          operation,
		OperationStatus:    resource.OperationStatusSuccess,
		NativeID:           resolvedID,
		ResourceProperties: propsJSON,
	}, nil
}

func (s *ServiceBusSubscription) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	progress, err := s.upsert(ctx, resource.OperationCreate, "", request.Properties, request.Label)
	if err != nil {
		return nil, err
	}
	return &resource.CreateResult{ProgressResult: progress}, nil
}

func (s *ServiceBusSubscription) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, namespaceName, topicName, subscriptionName, err := serviceBusSubscriptionIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := s.api.Get(ctx, rgName, namespaceName, topicName, subscriptionName, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := serializeServiceBusSubscriptionProperties(result.SBSubscription, rgName, namespaceName, topicName, subscriptionName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize ServiceBus Subscription properties: %w", err)
	}

	return &resource.ReadResult{
		ResourceType: ResourceTypeServiceBusSubscription,
		Properties:   string(propsJSON),
	}, nil
}

func (s *ServiceBusSubscription) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	progress, err := s.upsert(ctx, resource.OperationUpdate, request.NativeID, request.DesiredProperties, "")
	if err != nil {
		return nil, err
	}
	return &resource.UpdateResult{ProgressResult: progress}, nil
}

func (s *ServiceBusSubscription) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, namespaceName, topicName, subscriptionName, err := serviceBusSubscriptionIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	// Synchronous delete. NotFound means the goal is already achieved.
	if _, err := s.api.Delete(ctx, rgName, namespaceName, topicName, subscriptionName, nil); err != nil {
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

// Status is a no-op success passthrough: Service Bus subscription operations are
// synchronous, so Create/Update/Delete never return InProgress. It exists only to
// satisfy the Provisioner interface.
func (s *ServiceBusSubscription) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

func (s *ServiceBusSubscription) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	namespaceName := request.AdditionalProperties["namespaceName"]
	topicName := request.AdditionalProperties["topicName"]

	var nativeIDs []string
	pager := s.api.NewListByTopicPager(rgName, namespaceName, topicName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list Service Bus subscriptions for topic %s: %w", topicName, err)
		}
		for _, sub := range page.Value {
			if sub.ID != nil {
				nativeIDs = append(nativeIDs, *sub.ID)
			}
		}
	}

	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
