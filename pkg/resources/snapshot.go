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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v5"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeSnapshot = "AZURE::Compute::Snapshot"

// snapshotsAPI is the subset of *armcompute.SnapshotsClient used here. All verbs
// are LROs.
type snapshotsAPI interface {
	BeginCreateOrUpdate(ctx context.Context, resourceGroupName, snapshotName string, snapshot armcompute.Snapshot, options *armcompute.SnapshotsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armcompute.SnapshotsClientCreateOrUpdateResponse], error)
	Get(ctx context.Context, resourceGroupName, snapshotName string, options *armcompute.SnapshotsClientGetOptions) (armcompute.SnapshotsClientGetResponse, error)
	BeginUpdate(ctx context.Context, resourceGroupName, snapshotName string, snapshot armcompute.SnapshotUpdate, options *armcompute.SnapshotsClientBeginUpdateOptions) (*runtime.Poller[armcompute.SnapshotsClientUpdateResponse], error)
	BeginDelete(ctx context.Context, resourceGroupName, snapshotName string, options *armcompute.SnapshotsClientBeginDeleteOptions) (*runtime.Poller[armcompute.SnapshotsClientDeleteResponse], error)
	NewListByResourceGroupPager(resourceGroupName string, options *armcompute.SnapshotsClientListByResourceGroupOptions) *runtime.Pager[armcompute.SnapshotsClientListByResourceGroupResponse]
	NewListPager(options *armcompute.SnapshotsClientListOptions) *runtime.Pager[armcompute.SnapshotsClientListResponse]
}

func init() {
	registry.Register(ResourceTypeSnapshot, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &Snapshot{api: c.SnapshotsClient, config: cfg, pipeline: c.Pipeline()}
	})
}

// Snapshot is the provisioner for Azure managed disk snapshots
// (`Microsoft.Compute/snapshots/<name>`) — a read-only point-in-time copy of a
// managed disk, and the usual source for a managed Image.
type Snapshot struct {
	api      snapshotsAPI
	config   *config.Config
	pipeline runtime.Pipeline
}

func snapshotIDParts(resourceID string) (rgName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "snapshots")
	if err != nil {
		return "", "", err
	}
	return rgName, names["snapshots"], nil
}

func serializeSnapshotProperties(result armcompute.Snapshot, rgName, name string) (json.RawMessage, error) {
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

	// sku.tier is read-only ARM output with no schema field, so only name is echoed.
	if result.SKU != nil && result.SKU.Name != nil {
		props["sku"] = map[string]any{"name": string(*result.SKU.Name)}
	}

	if result.Properties != nil {
		if result.Properties.CreationData != nil {
			cd := map[string]any{}
			if result.Properties.CreationData.CreateOption != nil {
				cd["createOption"] = string(*result.Properties.CreationData.CreateOption)
			}
			if result.Properties.CreationData.SourceResourceID != nil {
				cd["sourceResourceId"] = *result.Properties.CreationData.SourceResourceID
			}
			props["creationData"] = cd
		}
		if result.Properties.DiskSizeGB != nil {
			props["diskSizeGB"] = int(*result.Properties.DiskSizeGB)
		}
		if result.Properties.Incremental != nil {
			props["incremental"] = *result.Properties.Incremental
		}
		if result.Properties.OSType != nil {
			props["osType"] = string(*result.Properties.OSType)
		}
	}

	if tags := azureTagsToFormaeTags(result.Tags); tags != nil {
		props["Tags"] = tags
	}

	return json.Marshal(props)
}

func snapshotParamsFromProperties(props map[string]any, rawProps json.RawMessage) (armcompute.Snapshot, error) {
	location, _ := props["location"].(string)
	if location == "" {
		return armcompute.Snapshot{}, fmt.Errorf("location is required")
	}

	cdMap, ok := props["creationData"].(map[string]any)
	if !ok {
		return armcompute.Snapshot{}, fmt.Errorf("creationData is required")
	}
	createOption, _ := cdMap["createOption"].(string)
	if createOption == "" {
		return armcompute.Snapshot{}, fmt.Errorf("creationData.createOption is required")
	}
	cd := &armcompute.CreationData{CreateOption: to.Ptr(armcompute.DiskCreateOption(createOption))}
	if src, ok := cdMap["sourceResourceId"].(string); ok && src != "" {
		cd.SourceResourceID = to.Ptr(src)
	}

	snap := armcompute.Snapshot{
		Location: to.Ptr(location),
		Properties: &armcompute.SnapshotProperties{
			CreationData: cd,
		},
	}

	if skuMap, ok := props["sku"].(map[string]any); ok {
		if skuName, ok := skuMap["name"].(string); ok && skuName != "" {
			snap.SKU = &armcompute.SnapshotSKU{Name: to.Ptr(armcompute.SnapshotStorageAccountTypes(skuName))}
		}
	}
	if v, ok := props["incremental"].(bool); ok {
		snap.Properties.Incremental = to.Ptr(v)
	}
	if v, ok := props["osType"].(string); ok && v != "" {
		snap.Properties.OSType = to.Ptr(armcompute.OperatingSystemTypes(v))
	}
	// diskSizeGB is only meaningful as a resize; ARM derives it from the source for
	// every createOption except Empty, so it is deliberately not sent on create.

	if azureTags := formaeTagsToAzureTags(rawProps); azureTags != nil {
		snap.Tags = azureTags
	}

	return snap, nil
}

func (s *Snapshot) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
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

	params, err := snapshotParamsFromProperties(props, request.Properties)
	if err != nil {
		return nil, err
	}

	poller, err := s.api.BeginCreateOrUpdate(ctx, rgName, name, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	expectedID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Compute/snapshots/%s",
		s.config.SubscriptionId, rgName, name)

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
		propsJSON, err := serializeSnapshotProperties(result.Snapshot, rgName, name)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize Snapshot properties: %w", err)
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

func (s *Snapshot) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, name, err := snapshotIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := s.api.Get(ctx, rgName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := serializeSnapshotProperties(result.Snapshot, rgName, name)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize Snapshot properties: %w", err)
	}

	return &resource.ReadResult{
		ResourceType: ResourceTypeSnapshot,
		Properties:   string(propsJSON),
	}, nil
}

func (s *Snapshot) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, name, err := snapshotIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props map[string]any
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse desired properties: %w", err)
	}

	// SnapshotUpdate is a real PATCH: creationData is immutable and must not appear.
	update := armcompute.SnapshotUpdate{Properties: &armcompute.SnapshotUpdateProperties{}}
	if v, ok := props["diskSizeGB"].(float64); ok {
		update.Properties.DiskSizeGB = to.Ptr(int32(v))
	}
	if skuMap, ok := props["sku"].(map[string]any); ok {
		if skuName, ok := skuMap["name"].(string); ok && skuName != "" {
			update.SKU = &armcompute.SnapshotSKU{Name: to.Ptr(armcompute.SnapshotStorageAccountTypes(skuName))}
		}
	}
	if azureTags := formaeTagsToAzureTags(request.DesiredProperties); azureTags != nil {
		update.Tags = azureTags
	}

	poller, err := s.api.BeginUpdate(ctx, rgName, name, update, nil)
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
		propsJSON, err := serializeSnapshotProperties(result.Snapshot, rgName, name)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize Snapshot properties: %w", err)
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

func (s *Snapshot) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, name, err := snapshotIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, err := s.api.BeginDelete(ctx, rgName, name, nil)
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
		}, fmt.Errorf("failed to delete Snapshot: %w", err)
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

func (s *Snapshot) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
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
	case lroOpCreate:
		return s.statusCreate(ctx, request, &reqID)
	case lroOpUpdate:
		return s.statusUpdate(ctx, request, &reqID)
	case lroOpDelete:
		return s.statusDelete(ctx, request, &reqID)
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

func (s *Snapshot) statusCreate(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	return statusLRO(ctx, request, reqID, resource.OperationCreate,
		func(token string) (*runtime.Poller[armcompute.SnapshotsClientCreateOrUpdateResponse], error) {
			return resumePoller[armcompute.SnapshotsClientCreateOrUpdateResponse](s.pipeline, token)
		},
		func(_ context.Context, result armcompute.SnapshotsClientCreateOrUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
			rgName, name, err := snapshotIDParts(*result.ID)
			if err != nil {
				return "", nil, err
			}
			propsJSON, err := serializeSnapshotProperties(result.Snapshot, rgName, name)
			if err != nil {
				return "", nil, fmt.Errorf("failed to serialize Snapshot properties: %w", err)
			}
			return *result.ID, propsJSON, nil
		})
}

func (s *Snapshot) statusUpdate(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	return statusLRO(ctx, request, reqID, resource.OperationUpdate,
		func(token string) (*runtime.Poller[armcompute.SnapshotsClientUpdateResponse], error) {
			return resumePoller[armcompute.SnapshotsClientUpdateResponse](s.pipeline, token)
		},
		func(_ context.Context, result armcompute.SnapshotsClientUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
			rgName, name, err := snapshotIDParts(*result.ID)
			if err != nil {
				return "", nil, err
			}
			propsJSON, err := serializeSnapshotProperties(result.Snapshot, rgName, name)
			if err != nil {
				return "", nil, fmt.Errorf("failed to serialize Snapshot properties: %w", err)
			}
			return *result.ID, propsJSON, nil
		})
}

func (s *Snapshot) statusDelete(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	return statusDeleteLRO(ctx, request, reqID,
		func(token string) (*runtime.Poller[armcompute.SnapshotsClientDeleteResponse], error) {
			return resumePoller[armcompute.SnapshotsClientDeleteResponse](s.pipeline, token)
		}, nil)
}

func (s *Snapshot) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]

	var nativeIDs []string
	if rgName != "" {
		pager := s.api.NewListByResourceGroupPager(rgName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list snapshots in resource group %s: %w", rgName, err)
			}
			for _, snap := range page.Value {
				if snap.ID != nil {
					nativeIDs = append(nativeIDs, *snap.ID)
				}
			}
		}
		return &resource.ListResult{NativeIDs: nativeIDs}, nil
	}

	pager := s.api.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list snapshots: %w", err)
		}
		for _, snap := range page.Value {
			if snap.ID != nil {
				nativeIDs = append(nativeIDs, *snap.ID)
			}
		}
	}

	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
