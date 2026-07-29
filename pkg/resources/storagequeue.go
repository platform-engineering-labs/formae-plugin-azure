// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeStorageQueue = "AZURE::Storage::Queue"

// storageQueuesAPI is the subset of *armstorage.QueueClient used here. Queue
// operations are synchronous (no LRO/poller).
type storageQueuesAPI interface {
	Create(ctx context.Context, resourceGroupName, accountName, queueName string, queue armstorage.Queue, options *armstorage.QueueClientCreateOptions) (armstorage.QueueClientCreateResponse, error)
	Get(ctx context.Context, resourceGroupName, accountName, queueName string, options *armstorage.QueueClientGetOptions) (armstorage.QueueClientGetResponse, error)
	Update(ctx context.Context, resourceGroupName, accountName, queueName string, queue armstorage.Queue, options *armstorage.QueueClientUpdateOptions) (armstorage.QueueClientUpdateResponse, error)
	Delete(ctx context.Context, resourceGroupName, accountName, queueName string, options *armstorage.QueueClientDeleteOptions) (armstorage.QueueClientDeleteResponse, error)
	NewListPager(resourceGroupName, accountName string, options *armstorage.QueueClientListOptions) *runtime.Pager[armstorage.QueueClientListResponse]
}

func init() {
	registry.Register(ResourceTypeStorageQueue, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &StorageQueue{api: c.StorageQueuesClient, config: cfg}
	})
}

// StorageQueue is the provisioner for storage queues
// (`Microsoft.Storage/storageAccounts/<acct>/queueServices/default/queues/<name>`).
// It is a child of AZURE::Storage::StorageAccount. All operations are synchronous.
type StorageQueue struct {
	api    storageQueuesAPI
	config *config.Config
}

func storageQueueIDParts(resourceID string) (rgName, accountName, queueName string, err error) {
	rgName, names, err := armIDParts(resourceID, "storageaccounts", "queues")
	if err != nil {
		return "", "", "", err
	}
	return rgName, names["storageaccounts"], names["queues"], nil
}

func serializeStorageQueueProperties(result armstorage.Queue, rgName, accountName, queueName string) (json.RawMessage, error) {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	props["storageAccountName"] = accountName
	if result.Name != nil {
		props["name"] = *result.Name
	} else {
		props["name"] = queueName
	}
	if result.ID != nil {
		props["id"] = *result.ID
	}

	// Metadata is a free-form map; surfaced as the same key/value entity-set shape
	// the plugin already uses for BlobContainer metadata so it stays diffable.
	if result.QueueProperties != nil && len(result.QueueProperties.Metadata) > 0 {
		props["metadata"] = azureTagsToFormaeTags(result.QueueProperties.Metadata)
	}

	return json.Marshal(props)
}

func (q *StorageQueue) resolveNames(operation resource.Operation, nativeID string, props map[string]any, label string) (rgName, accountName, queueName string, err error) {
	if operation == resource.OperationUpdate {
		return storageQueueIDParts(nativeID)
	}
	rgName, _ = props["resourceGroupName"].(string)
	if rgName == "" {
		return "", "", "", fmt.Errorf("resourceGroupName is required")
	}
	accountName, _ = props["storageAccountName"].(string)
	if accountName == "" {
		return "", "", "", fmt.Errorf("storageAccountName is required")
	}
	queueName, _ = props["name"].(string)
	if queueName == "" {
		queueName = label
	}
	if queueName == "" {
		return "", "", "", fmt.Errorf("name is required")
	}
	return rgName, accountName, queueName, nil
}

func (q *StorageQueue) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props map[string]any
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	rgName, accountName, queueName, err := q.resolveNames(resource.OperationCreate, "", props, request.Label)
	if err != nil {
		return nil, err
	}

	params := armstorage.Queue{
		QueueProperties: &armstorage.QueueProperties{Metadata: metadataFromProperties(props)},
	}

	result, err := q.api.Create(ctx, rgName, accountName, queueName, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	propsJSON, err := serializeStorageQueueProperties(result.Queue, rgName, accountName, queueName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize Queue properties: %w", err)
	}

	nativeID := ""
	if result.ID != nil {
		nativeID = *result.ID
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

func (q *StorageQueue) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, accountName, queueName, err := storageQueueIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := q.api.Get(ctx, rgName, accountName, queueName, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := serializeStorageQueueProperties(result.Queue, rgName, accountName, queueName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize Queue properties: %w", err)
	}

	return &resource.ReadResult{
		ResourceType: ResourceTypeStorageQueue,
		Properties:   string(propsJSON),
	}, nil
}

func (q *StorageQueue) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, accountName, queueName, err := storageQueueIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props map[string]any
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse desired properties: %w", err)
	}

	params := armstorage.Queue{
		QueueProperties: &armstorage.QueueProperties{Metadata: metadataFromProperties(props)},
	}

	result, err := q.api.Update(ctx, rgName, accountName, queueName, params, nil)
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

	propsJSON, err := serializeStorageQueueProperties(result.Queue, rgName, accountName, queueName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize Queue properties: %w", err)
	}

	nativeID := request.NativeID
	if result.ID != nil {
		nativeID = *result.ID
	}

	return &resource.UpdateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:          resource.OperationUpdate,
			OperationStatus:    resource.OperationStatusSuccess,
			NativeID:           nativeID,
			ResourceProperties: propsJSON,
		},
	}, nil
}

func (q *StorageQueue) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, accountName, queueName, err := storageQueueIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	// Synchronous delete. NotFound means the goal is already achieved.
	if _, err := q.api.Delete(ctx, rgName, accountName, queueName, nil); err != nil {
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

// Status is a no-op success passthrough: queue operations are synchronous, so
// Create/Update/Delete never return InProgress. It exists only to satisfy the
// Provisioner interface.
func (q *StorageQueue) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

func (q *StorageQueue) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	accountName := request.AdditionalProperties["storageAccountName"]

	var nativeIDs []string
	pager := q.api.NewListPager(rgName, accountName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list queues in storage account %s: %w", accountName, err)
		}
		for _, queue := range page.Value {
			if queue.ID != nil {
				nativeIDs = append(nativeIDs, *queue.ID)
			}
		}
	}

	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
