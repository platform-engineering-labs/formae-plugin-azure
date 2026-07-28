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

const ResourceTypeServiceBusQueue = "AZURE::ServiceBus::Queue"

// serviceBusQueuesAPI is the subset of *armservicebus.QueuesClient used here.
// Queue operations are synchronous (no LRO/poller).
type serviceBusQueuesAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName, namespaceName, queueName string, parameters armservicebus.SBQueue, options *armservicebus.QueuesClientCreateOrUpdateOptions) (armservicebus.QueuesClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName, namespaceName, queueName string, options *armservicebus.QueuesClientGetOptions) (armservicebus.QueuesClientGetResponse, error)
	Delete(ctx context.Context, resourceGroupName, namespaceName, queueName string, options *armservicebus.QueuesClientDeleteOptions) (armservicebus.QueuesClientDeleteResponse, error)
	NewListByNamespacePager(resourceGroupName, namespaceName string, options *armservicebus.QueuesClientListByNamespaceOptions) *runtime.Pager[armservicebus.QueuesClientListByNamespaceResponse]
}

func init() {
	registry.Register(ResourceTypeServiceBusQueue, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &ServiceBusQueue{api: c.ServiceBusQueuesClient, config: cfg}
	})
}

// ServiceBusQueue is the provisioner for Service Bus queues
// (`Microsoft.ServiceBus/namespaces/<ns>/queues/<name>`). It is a child of
// AZURE::ServiceBus::Namespace. All operations are synchronous.
//
// ponytail: authorization rules (the queue-scoped SAS policies) are a separate ARM
// sub-resource and are not modelled here.
type ServiceBusQueue struct {
	api    serviceBusQueuesAPI
	config *config.Config
}

func serviceBusQueueIDParts(resourceID string) (rgName, namespaceName, queueName string, err error) {
	rgName, names, err := armExactIDParts(resourceID, "namespaces", "queues")
	if err != nil {
		return "", "", "", err
	}
	return rgName, names[0], names[1], nil
}

func serializeServiceBusQueueProperties(result armservicebus.SBQueue, rgName, namespaceName, queueName string) (json.RawMessage, error) {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	props["namespaceName"] = namespaceName
	if result.Name != nil {
		props["name"] = *result.Name
	} else {
		props["name"] = queueName
	}
	if result.ID != nil {
		props["id"] = *result.ID
	}

	if p := result.Properties; p != nil {
		sbPutString(props, "lockDuration", p.LockDuration)
		sbPutString(props, "defaultMessageTimeToLive", p.DefaultMessageTimeToLive)
		sbPutString(props, "duplicateDetectionHistoryTimeWindow", p.DuplicateDetectionHistoryTimeWindow)
		sbPutString(props, "autoDeleteOnIdle", p.AutoDeleteOnIdle)
		sbPutString(props, "forwardTo", p.ForwardTo)
		sbPutString(props, "forwardDeadLetteredMessagesTo", p.ForwardDeadLetteredMessagesTo)
		sbPutInt32(props, "maxSizeInMegabytes", p.MaxSizeInMegabytes)
		sbPutInt32(props, "maxDeliveryCount", p.MaxDeliveryCount)
		sbPutInt64(props, "maxMessageSizeInKilobytes", p.MaxMessageSizeInKilobytes)
		sbPutBool(props, "requiresDuplicateDetection", p.RequiresDuplicateDetection)
		sbPutBool(props, "requiresSession", p.RequiresSession)
		sbPutBool(props, "deadLetteringOnMessageExpiration", p.DeadLetteringOnMessageExpiration)
		sbPutBool(props, "enableBatchedOperations", p.EnableBatchedOperations)
		sbPutBool(props, "enablePartitioning", p.EnablePartitioning)
		sbPutBool(props, "enableExpress", p.EnableExpress)
		if p.Status != nil {
			props["status"] = string(*p.Status)
		}
	}

	return json.Marshal(props)
}

func serviceBusQueueParamsFromProperties(props map[string]any) armservicebus.SBQueue {
	p := &armservicebus.SBQueueProperties{
		LockDuration:                        sbOptString(props, "lockDuration"),
		DefaultMessageTimeToLive:            sbOptString(props, "defaultMessageTimeToLive"),
		DuplicateDetectionHistoryTimeWindow: sbOptString(props, "duplicateDetectionHistoryTimeWindow"),
		AutoDeleteOnIdle:                    sbOptString(props, "autoDeleteOnIdle"),
		ForwardTo:                           sbOptString(props, "forwardTo"),
		ForwardDeadLetteredMessagesTo:       sbOptString(props, "forwardDeadLetteredMessagesTo"),
		MaxSizeInMegabytes:                  sbOptInt32(props, "maxSizeInMegabytes"),
		MaxDeliveryCount:                    sbOptInt32(props, "maxDeliveryCount"),
		MaxMessageSizeInKilobytes:           sbOptInt64(props, "maxMessageSizeInKilobytes"),
		RequiresDuplicateDetection:          sbOptBool(props, "requiresDuplicateDetection"),
		RequiresSession:                     sbOptBool(props, "requiresSession"),
		DeadLetteringOnMessageExpiration:    sbOptBool(props, "deadLetteringOnMessageExpiration"),
		EnableBatchedOperations:             sbOptBool(props, "enableBatchedOperations"),
		EnablePartitioning:                  sbOptBool(props, "enablePartitioning"),
		EnableExpress:                       sbOptBool(props, "enableExpress"),
	}
	if v, ok := props["status"].(string); ok && v != "" {
		p.Status = to.Ptr(armservicebus.EntityStatus(v))
	}
	return armservicebus.SBQueue{Properties: p}
}

func (q *ServiceBusQueue) upsert(ctx context.Context, operation resource.Operation, nativeID string, rawProps json.RawMessage, label string) (*resource.ProgressResult, error) {
	var props map[string]any
	if err := json.Unmarshal(rawProps, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	var rgName, namespaceName, queueName string
	if operation == resource.OperationUpdate {
		var err error
		rgName, namespaceName, queueName, err = serviceBusQueueIDParts(nativeID)
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
		queueName, _ = props["name"].(string)
		if queueName == "" {
			queueName = label
		}
		if queueName == "" {
			return nil, fmt.Errorf("name is required")
		}
	}

	result, err := q.api.CreateOrUpdate(ctx, rgName, namespaceName, queueName,
		serviceBusQueueParamsFromProperties(props), nil)
	if err != nil {
		return &resource.ProgressResult{
			Operation:       operation,
			OperationStatus: resource.OperationStatusFailure,
			NativeID:        nativeID,
			ErrorCode:       operationErrorCode(err),
		}, nil
	}

	propsJSON, err := serializeServiceBusQueueProperties(result.SBQueue, rgName, namespaceName, queueName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize ServiceBus Queue properties: %w", err)
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

func (q *ServiceBusQueue) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	progress, err := q.upsert(ctx, resource.OperationCreate, "", request.Properties, request.Label)
	if err != nil {
		return nil, err
	}
	return &resource.CreateResult{ProgressResult: progress}, nil
}

func (q *ServiceBusQueue) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, namespaceName, queueName, err := serviceBusQueueIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := q.api.Get(ctx, rgName, namespaceName, queueName, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := serializeServiceBusQueueProperties(result.SBQueue, rgName, namespaceName, queueName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize ServiceBus Queue properties: %w", err)
	}

	return &resource.ReadResult{
		ResourceType: ResourceTypeServiceBusQueue,
		Properties:   string(propsJSON),
	}, nil
}

func (q *ServiceBusQueue) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	progress, err := q.upsert(ctx, resource.OperationUpdate, request.NativeID, request.DesiredProperties, "")
	if err != nil {
		return nil, err
	}
	return &resource.UpdateResult{ProgressResult: progress}, nil
}

func (q *ServiceBusQueue) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, namespaceName, queueName, err := serviceBusQueueIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	// Synchronous delete. NotFound means the goal is already achieved.
	if _, err := q.api.Delete(ctx, rgName, namespaceName, queueName, nil); err != nil {
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

// Status is a no-op success passthrough: Service Bus queue operations are
// synchronous, so Create/Update/Delete never return InProgress. It exists only to
// satisfy the Provisioner interface.
func (q *ServiceBusQueue) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

func (q *ServiceBusQueue) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	namespaceName := request.AdditionalProperties["namespaceName"]

	var nativeIDs []string
	pager := q.api.NewListByNamespacePager(rgName, namespaceName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list Service Bus queues in namespace %s: %w", namespaceName, err)
		}
		for _, queue := range page.Value {
			if queue.ID != nil {
				nativeIDs = append(nativeIDs, *queue.ID)
			}
		}
	}

	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
