// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/eventhub/armeventhub"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeEventHubConsumerGroup = "AZURE::EventHub::ConsumerGroup"

// eventHubConsumerGroupsAPI is the subset of *armeventhub.ConsumerGroupsClient
// used here. All operations are synchronous (no LRO/poller).
type eventHubConsumerGroupsAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName string, namespaceName string, eventHubName string, consumerGroupName string, parameters armeventhub.ConsumerGroup, options *armeventhub.ConsumerGroupsClientCreateOrUpdateOptions) (armeventhub.ConsumerGroupsClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName string, namespaceName string, eventHubName string, consumerGroupName string, options *armeventhub.ConsumerGroupsClientGetOptions) (armeventhub.ConsumerGroupsClientGetResponse, error)
	Delete(ctx context.Context, resourceGroupName string, namespaceName string, eventHubName string, consumerGroupName string, options *armeventhub.ConsumerGroupsClientDeleteOptions) (armeventhub.ConsumerGroupsClientDeleteResponse, error)
	NewListByEventHubPager(resourceGroupName string, namespaceName string, eventHubName string, options *armeventhub.ConsumerGroupsClientListByEventHubOptions) *runtime.Pager[armeventhub.ConsumerGroupsClientListByEventHubResponse]
}

func init() {
	registry.Register(ResourceTypeEventHubConsumerGroup, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &EventHubConsumerGroup{api: c.EventHubConsumerGroupsClient, config: cfg}
	})
}

// EventHubConsumerGroup is the provisioner for event hub consumer groups
// (`Microsoft.EventHub/namespaces/<ns>/eventhubs/<hub>/consumergroups/<name>`).
// It is a child of AZURE::EventHub::EventHub. All operations are synchronous.
//
// Every event hub has an implicit `$Default` consumer group that Azure creates
// and that cannot be deleted; it is filtered out of List so discovery does not
// try to manage it.
type EventHubConsumerGroup struct {
	api    eventHubConsumerGroupsAPI
	config *config.Config
}

// defaultConsumerGroupName is the implicit consumer group Azure creates for every
// event hub. It is not deletable and must not be surfaced as a managed resource.
const defaultConsumerGroupName = "$Default"

func eventHubConsumerGroupIDParts(resourceID string) (rgName, namespaceName, hubName, groupName string, err error) {
	rgName, names, err := armIDParts(resourceID, "namespaces", "eventhubs", "consumergroups")
	if err != nil {
		return "", "", "", "", err
	}
	return rgName, names["namespaces"], names["eventhubs"], names["consumergroups"], nil
}

func serializeEventHubConsumerGroupProperties(result armeventhub.ConsumerGroup, rgName, namespaceName, hubName, groupName string) (json.RawMessage, error) {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	props["namespaceName"] = namespaceName
	props["eventHubName"] = hubName
	if result.Name != nil {
		props["name"] = *result.Name
	} else {
		props["name"] = groupName
	}
	if result.ID != nil {
		props["id"] = *result.ID
	}
	if result.Properties != nil && result.Properties.UserMetadata != nil {
		props["userMetadata"] = *result.Properties.UserMetadata
	}

	return json.Marshal(props)
}

func eventHubConsumerGroupParamsFromProperties(props map[string]any) armeventhub.ConsumerGroup {
	group := armeventhub.ConsumerGroup{Properties: &armeventhub.ConsumerGroupProperties{}}
	if v, ok := props["userMetadata"].(string); ok {
		group.Properties.UserMetadata = stringPtr(v)
	}
	return group
}

func (c *EventHubConsumerGroup) upsert(ctx context.Context, operation resource.Operation, nativeID string, rawProps json.RawMessage, label string) (*resource.ProgressResult, error) {
	var props map[string]any
	if err := json.Unmarshal(rawProps, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	var rgName, namespaceName, hubName, groupName string
	if operation == resource.OperationUpdate {
		var err error
		rgName, namespaceName, hubName, groupName, err = eventHubConsumerGroupIDParts(nativeID)
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
		hubName, _ = props["eventHubName"].(string)
		if hubName == "" {
			return nil, fmt.Errorf("eventHubName is required")
		}
		groupName, _ = props["name"].(string)
		if groupName == "" {
			groupName = label
		}
		if groupName == "" {
			return nil, fmt.Errorf("name is required")
		}
	}

	result, err := c.api.CreateOrUpdate(ctx, rgName, namespaceName, hubName, groupName,
		eventHubConsumerGroupParamsFromProperties(props), nil)
	if err != nil {
		return &resource.ProgressResult{
			Operation:       operation,
			OperationStatus: resource.OperationStatusFailure,
			NativeID:        nativeID,
			ErrorCode:       operationErrorCode(err),
		}, nil
	}

	propsJSON, err := serializeEventHubConsumerGroupProperties(result.ConsumerGroup, rgName, namespaceName, hubName, groupName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize ConsumerGroup properties: %w", err)
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

func (c *EventHubConsumerGroup) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	progress, err := c.upsert(ctx, resource.OperationCreate, "", request.Properties, request.Label)
	if err != nil {
		return nil, err
	}
	return &resource.CreateResult{ProgressResult: progress}, nil
}

func (c *EventHubConsumerGroup) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, namespaceName, hubName, groupName, err := eventHubConsumerGroupIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := c.api.Get(ctx, rgName, namespaceName, hubName, groupName, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := serializeEventHubConsumerGroupProperties(result.ConsumerGroup, rgName, namespaceName, hubName, groupName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize ConsumerGroup properties: %w", err)
	}

	return &resource.ReadResult{
		ResourceType: ResourceTypeEventHubConsumerGroup,
		Properties:   string(propsJSON),
	}, nil
}

func (c *EventHubConsumerGroup) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	progress, err := c.upsert(ctx, resource.OperationUpdate, request.NativeID, request.DesiredProperties, "")
	if err != nil {
		return nil, err
	}
	return &resource.UpdateResult{ProgressResult: progress}, nil
}

func (c *EventHubConsumerGroup) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, namespaceName, hubName, groupName, err := eventHubConsumerGroupIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	// Synchronous delete. NotFound means the goal is already achieved.
	if _, err := c.api.Delete(ctx, rgName, namespaceName, hubName, groupName, nil); err != nil {
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

// Status is a no-op success passthrough: consumer group operations are
// synchronous, so Create/Update/Delete never return InProgress. It exists only
// to satisfy the Provisioner interface.
func (c *EventHubConsumerGroup) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

func (c *EventHubConsumerGroup) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	namespaceName := request.AdditionalProperties["namespaceName"]
	hubName := request.AdditionalProperties["eventHubName"]

	var nativeIDs []string
	pager := c.api.NewListByEventHubPager(rgName, namespaceName, hubName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list consumer groups for event hub %s: %w", hubName, err)
		}
		for _, group := range page.Value {
			if group.ID == nil {
				continue
			}
			// $Default is created by Azure and cannot be deleted — never surface it
			// as a manageable resource.
			if group.Name != nil && *group.Name == defaultConsumerGroupName {
				continue
			}
			nativeIDs = append(nativeIDs, *group.ID)
		}
	}

	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
