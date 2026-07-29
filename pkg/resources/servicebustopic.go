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

const ResourceTypeServiceBusTopic = "AZURE::ServiceBus::Topic"

// serviceBusTopicsAPI is the subset of *armservicebus.TopicsClient used here.
// Topic operations are synchronous (no LRO/poller).
type serviceBusTopicsAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName, namespaceName, topicName string, parameters armservicebus.SBTopic, options *armservicebus.TopicsClientCreateOrUpdateOptions) (armservicebus.TopicsClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName, namespaceName, topicName string, options *armservicebus.TopicsClientGetOptions) (armservicebus.TopicsClientGetResponse, error)
	Delete(ctx context.Context, resourceGroupName, namespaceName, topicName string, options *armservicebus.TopicsClientDeleteOptions) (armservicebus.TopicsClientDeleteResponse, error)
	NewListByNamespacePager(resourceGroupName, namespaceName string, options *armservicebus.TopicsClientListByNamespaceOptions) *runtime.Pager[armservicebus.TopicsClientListByNamespaceResponse]
}

func init() {
	registry.Register(ResourceTypeServiceBusTopic, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &ServiceBusTopic{api: c.ServiceBusTopicsClient, config: cfg}
	})
}

// ServiceBusTopic is the provisioner for Service Bus topics
// (`Microsoft.ServiceBus/namespaces/<ns>/topics/<name>`). It is a child of
// AZURE::ServiceBus::Namespace. All operations are synchronous.
//
// ponytail: topic-scoped authorization rules are a separate ARM sub-resource and are
// not modelled here.
type ServiceBusTopic struct {
	api    serviceBusTopicsAPI
	config *config.Config
}

func serviceBusTopicIDParts(resourceID string) (rgName, namespaceName, topicName string, err error) {
	rgName, names, err := armExactIDParts(resourceID, "namespaces", "topics")
	if err != nil {
		return "", "", "", err
	}
	return rgName, names[0], names[1], nil
}

func serializeServiceBusTopicProperties(result armservicebus.SBTopic, rgName, namespaceName, topicName string) (json.RawMessage, error) {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	props["namespaceName"] = namespaceName
	if result.Name != nil {
		props["name"] = *result.Name
	} else {
		props["name"] = topicName
	}
	if result.ID != nil {
		props["id"] = *result.ID
	}

	if p := result.Properties; p != nil {
		sbPutString(props, "defaultMessageTimeToLive", p.DefaultMessageTimeToLive)
		sbPutString(props, "duplicateDetectionHistoryTimeWindow", p.DuplicateDetectionHistoryTimeWindow)
		sbPutString(props, "autoDeleteOnIdle", p.AutoDeleteOnIdle)
		sbPutInt32(props, "maxSizeInMegabytes", p.MaxSizeInMegabytes)
		sbPutInt64(props, "maxMessageSizeInKilobytes", p.MaxMessageSizeInKilobytes)
		sbPutBool(props, "requiresDuplicateDetection", p.RequiresDuplicateDetection)
		sbPutBool(props, "enableBatchedOperations", p.EnableBatchedOperations)
		sbPutBool(props, "enablePartitioning", p.EnablePartitioning)
		sbPutBool(props, "enableExpress", p.EnableExpress)
		sbPutBool(props, "supportOrdering", p.SupportOrdering)
		if p.Status != nil {
			props["status"] = string(*p.Status)
		}
	}

	return json.Marshal(props)
}

func serviceBusTopicParamsFromProperties(props map[string]any) armservicebus.SBTopic {
	p := &armservicebus.SBTopicProperties{
		DefaultMessageTimeToLive:            sbOptString(props, "defaultMessageTimeToLive"),
		DuplicateDetectionHistoryTimeWindow: sbOptString(props, "duplicateDetectionHistoryTimeWindow"),
		AutoDeleteOnIdle:                    sbOptString(props, "autoDeleteOnIdle"),
		MaxSizeInMegabytes:                  sbOptInt32(props, "maxSizeInMegabytes"),
		MaxMessageSizeInKilobytes:           sbOptInt64(props, "maxMessageSizeInKilobytes"),
		RequiresDuplicateDetection:          sbOptBool(props, "requiresDuplicateDetection"),
		EnableBatchedOperations:             sbOptBool(props, "enableBatchedOperations"),
		EnablePartitioning:                  sbOptBool(props, "enablePartitioning"),
		EnableExpress:                       sbOptBool(props, "enableExpress"),
		SupportOrdering:                     sbOptBool(props, "supportOrdering"),
	}
	if v, ok := props["status"].(string); ok && v != "" {
		p.Status = to.Ptr(armservicebus.EntityStatus(v))
	}
	return armservicebus.SBTopic{Properties: p}
}

func (t *ServiceBusTopic) upsert(ctx context.Context, operation resource.Operation, nativeID string, rawProps json.RawMessage, label string) (*resource.ProgressResult, error) {
	var props map[string]any
	if err := json.Unmarshal(rawProps, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	var rgName, namespaceName, topicName string
	if operation == resource.OperationUpdate {
		var err error
		rgName, namespaceName, topicName, err = serviceBusTopicIDParts(nativeID)
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
		topicName, _ = props["name"].(string)
		if topicName == "" {
			topicName = label
		}
		if topicName == "" {
			return nil, fmt.Errorf("name is required")
		}
	}

	result, err := t.api.CreateOrUpdate(ctx, rgName, namespaceName, topicName,
		serviceBusTopicParamsFromProperties(props), nil)
	if err != nil {
		return &resource.ProgressResult{
			Operation:       operation,
			OperationStatus: resource.OperationStatusFailure,
			NativeID:        nativeID,
			ErrorCode:       operationErrorCode(err),
		}, nil
	}

	propsJSON, err := serializeServiceBusTopicProperties(result.SBTopic, rgName, namespaceName, topicName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize ServiceBus Topic properties: %w", err)
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

func (t *ServiceBusTopic) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	progress, err := t.upsert(ctx, resource.OperationCreate, "", request.Properties, request.Label)
	if err != nil {
		return nil, err
	}
	return &resource.CreateResult{ProgressResult: progress}, nil
}

func (t *ServiceBusTopic) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, namespaceName, topicName, err := serviceBusTopicIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := t.api.Get(ctx, rgName, namespaceName, topicName, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := serializeServiceBusTopicProperties(result.SBTopic, rgName, namespaceName, topicName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize ServiceBus Topic properties: %w", err)
	}

	return &resource.ReadResult{
		ResourceType: ResourceTypeServiceBusTopic,
		Properties:   string(propsJSON),
	}, nil
}

func (t *ServiceBusTopic) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	progress, err := t.upsert(ctx, resource.OperationUpdate, request.NativeID, request.DesiredProperties, "")
	if err != nil {
		return nil, err
	}
	return &resource.UpdateResult{ProgressResult: progress}, nil
}

func (t *ServiceBusTopic) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, namespaceName, topicName, err := serviceBusTopicIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	// Synchronous delete. NotFound means the goal is already achieved.
	if _, err := t.api.Delete(ctx, rgName, namespaceName, topicName, nil); err != nil {
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

// Status is a no-op success passthrough: Service Bus topic operations are
// synchronous, so Create/Update/Delete never return InProgress. It exists only to
// satisfy the Provisioner interface.
func (t *ServiceBusTopic) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

func (t *ServiceBusTopic) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	namespaceName := request.AdditionalProperties["namespaceName"]

	var nativeIDs []string
	pager := t.api.NewListByNamespacePager(rgName, namespaceName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list Service Bus topics in namespace %s: %w", namespaceName, err)
		}
		for _, topic := range page.Value {
			if topic.ID != nil {
				nativeIDs = append(nativeIDs, *topic.ID)
			}
		}
	}

	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
