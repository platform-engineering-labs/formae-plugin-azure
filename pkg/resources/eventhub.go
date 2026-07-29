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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/eventhub/armeventhub"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeEventHub = "AZURE::EventHub::EventHub"

// eventHubsAPI is the subset of *armeventhub.EventHubsClient used here. Event hub
// entity operations are synchronous (no LRO/poller).
type eventHubsAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName string, namespaceName string, eventHubName string, parameters armeventhub.Eventhub, options *armeventhub.EventHubsClientCreateOrUpdateOptions) (armeventhub.EventHubsClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName string, namespaceName string, eventHubName string, options *armeventhub.EventHubsClientGetOptions) (armeventhub.EventHubsClientGetResponse, error)
	Delete(ctx context.Context, resourceGroupName string, namespaceName string, eventHubName string, options *armeventhub.EventHubsClientDeleteOptions) (armeventhub.EventHubsClientDeleteResponse, error)
	NewListByNamespacePager(resourceGroupName string, namespaceName string, options *armeventhub.EventHubsClientListByNamespaceOptions) *runtime.Pager[armeventhub.EventHubsClientListByNamespaceResponse]
}

func init() {
	registry.Register(ResourceTypeEventHub, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &EventHub{api: c.EventHubsClient, config: cfg}
	})
}

// EventHub is the provisioner for event hub entities
// (`Microsoft.EventHub/namespaces/<ns>/eventhubs/<name>`). It is a child of
// AZURE::EventHub::Namespace. All operations are synchronous.
//
// ponytail: captureDescription (archiving to blob/ADLS) is not modelled — it
// needs a storage account and container to be verifiable end to end, so it is
// deferred rather than shipped unverified.
type EventHub struct {
	api    eventHubsAPI
	config *config.Config
}

func eventHubIDParts(resourceID string) (rgName, namespaceName, hubName string, err error) {
	rgName, names, err := armIDParts(resourceID, "namespaces", "eventhubs")
	if err != nil {
		return "", "", "", err
	}
	return rgName, names["namespaces"], names["eventhubs"], nil
}

func serializeEventHubProperties(result armeventhub.Eventhub, rgName, namespaceName, hubName string) (json.RawMessage, error) {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	props["namespaceName"] = namespaceName
	if result.Name != nil {
		props["name"] = *result.Name
	} else {
		props["name"] = hubName
	}
	if result.ID != nil {
		props["id"] = *result.ID
	}

	if result.Properties != nil {
		if result.Properties.PartitionCount != nil {
			props["partitionCount"] = int(*result.Properties.PartitionCount)
		}
		if result.Properties.MessageRetentionInDays != nil {
			props["messageRetentionInDays"] = int(*result.Properties.MessageRetentionInDays)
		}
		if result.Properties.Status != nil {
			props["status"] = string(*result.Properties.Status)
		}
		if result.Properties.UserMetadata != nil {
			props["userMetadata"] = *result.Properties.UserMetadata
		}
		if rd := result.Properties.RetentionDescription; rd != nil {
			retention := map[string]any{}
			if rd.CleanupPolicy != nil {
				retention["cleanupPolicy"] = string(*rd.CleanupPolicy)
			}
			if rd.RetentionTimeInHours != nil {
				retention["retentionTimeInHours"] = int(*rd.RetentionTimeInHours)
			}
			if rd.TombstoneRetentionTimeInHours != nil {
				retention["tombstoneRetentionTimeInHours"] = int(*rd.TombstoneRetentionTimeInHours)
			}
			if len(retention) > 0 {
				props["retentionDescription"] = retention
			}
		}
	}

	return json.Marshal(props)
}

func eventHubParamsFromProperties(props map[string]any) armeventhub.Eventhub {
	hub := armeventhub.Eventhub{Properties: &armeventhub.Properties{}}

	if v, ok := props["partitionCount"].(float64); ok {
		hub.Properties.PartitionCount = to.Ptr(int64(v))
	}
	if v, ok := props["messageRetentionInDays"].(float64); ok {
		hub.Properties.MessageRetentionInDays = to.Ptr(int64(v))
	}
	if v, ok := props["status"].(string); ok && v != "" {
		hub.Properties.Status = to.Ptr(armeventhub.EntityStatus(v))
	}
	if v, ok := props["userMetadata"].(string); ok {
		hub.Properties.UserMetadata = stringPtr(v)
	}
	if rdMap, ok := props["retentionDescription"].(map[string]any); ok {
		rd := &armeventhub.RetentionDescription{}
		if v, ok := rdMap["cleanupPolicy"].(string); ok && v != "" {
			rd.CleanupPolicy = to.Ptr(armeventhub.CleanupPolicyRetentionDescription(v))
		}
		if v, ok := rdMap["retentionTimeInHours"].(float64); ok {
			rd.RetentionTimeInHours = to.Ptr(int64(v))
		}
		if v, ok := rdMap["tombstoneRetentionTimeInHours"].(float64); ok {
			rd.TombstoneRetentionTimeInHours = to.Ptr(int32(v))
		}
		hub.Properties.RetentionDescription = rd
	}

	return hub
}

func (h *EventHub) upsert(ctx context.Context, operation resource.Operation, nativeID string, rawProps json.RawMessage, label string) (*resource.ProgressResult, error) {
	var props map[string]any
	if err := json.Unmarshal(rawProps, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	var rgName, namespaceName, hubName string
	if operation == resource.OperationUpdate {
		var err error
		rgName, namespaceName, hubName, err = eventHubIDParts(nativeID)
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
		hubName, _ = props["name"].(string)
		if hubName == "" {
			hubName = label
		}
		if hubName == "" {
			return nil, fmt.Errorf("name is required")
		}
	}

	// Synchronous: CreateOrUpdate is an idempotent upsert returning final state.
	result, err := h.api.CreateOrUpdate(ctx, rgName, namespaceName, hubName, eventHubParamsFromProperties(props), nil)
	if err != nil {
		return &resource.ProgressResult{
			Operation:       operation,
			OperationStatus: resource.OperationStatusFailure,
			NativeID:        nativeID,
			ErrorCode:       operationErrorCode(err),
		}, nil
	}

	propsJSON, err := serializeEventHubProperties(result.Eventhub, rgName, namespaceName, hubName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize EventHub properties: %w", err)
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

func (h *EventHub) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	progress, err := h.upsert(ctx, resource.OperationCreate, "", request.Properties, request.Label)
	if err != nil {
		return nil, err
	}
	return &resource.CreateResult{ProgressResult: progress}, nil
}

func (h *EventHub) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, namespaceName, hubName, err := eventHubIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := h.api.Get(ctx, rgName, namespaceName, hubName, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := serializeEventHubProperties(result.Eventhub, rgName, namespaceName, hubName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize EventHub properties: %w", err)
	}

	return &resource.ReadResult{
		ResourceType: ResourceTypeEventHub,
		Properties:   string(propsJSON),
	}, nil
}

func (h *EventHub) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	progress, err := h.upsert(ctx, resource.OperationUpdate, request.NativeID, request.DesiredProperties, "")
	if err != nil {
		return nil, err
	}
	return &resource.UpdateResult{ProgressResult: progress}, nil
}

func (h *EventHub) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, namespaceName, hubName, err := eventHubIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	// Synchronous delete. NotFound means the goal is already achieved.
	if _, err := h.api.Delete(ctx, rgName, namespaceName, hubName, nil); err != nil {
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

// Status is a no-op success passthrough: event hub entity operations are
// synchronous, so Create/Update/Delete never return InProgress. It exists only
// to satisfy the Provisioner interface.
func (h *EventHub) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

func (h *EventHub) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	namespaceName := request.AdditionalProperties["namespaceName"]

	var nativeIDs []string
	pager := h.api.NewListByNamespacePager(rgName, namespaceName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list event hubs in namespace %s: %w", namespaceName, err)
		}
		for _, hub := range page.Value {
			if hub.ID != nil {
				nativeIDs = append(nativeIDs, *hub.ID)
			}
		}
	}

	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
