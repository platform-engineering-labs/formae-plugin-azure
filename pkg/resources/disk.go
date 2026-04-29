// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v5"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeDisk = "Azure::Compute::Disk"

type disksAPI interface {
	BeginCreateOrUpdate(ctx context.Context, resourceGroupName, diskName string, disk armcompute.Disk, options *armcompute.DisksClientBeginCreateOrUpdateOptions) (*runtime.Poller[armcompute.DisksClientCreateOrUpdateResponse], error)
	Get(ctx context.Context, resourceGroupName, diskName string, options *armcompute.DisksClientGetOptions) (armcompute.DisksClientGetResponse, error)
	BeginUpdate(ctx context.Context, resourceGroupName, diskName string, disk armcompute.DiskUpdate, options *armcompute.DisksClientBeginUpdateOptions) (*runtime.Poller[armcompute.DisksClientUpdateResponse], error)
	BeginDelete(ctx context.Context, resourceGroupName, diskName string, options *armcompute.DisksClientBeginDeleteOptions) (*runtime.Poller[armcompute.DisksClientDeleteResponse], error)
	NewListByResourceGroupPager(resourceGroupName string, options *armcompute.DisksClientListByResourceGroupOptions) *runtime.Pager[armcompute.DisksClientListByResourceGroupResponse]
	NewListPager(options *armcompute.DisksClientListOptions) *runtime.Pager[armcompute.DisksClientListResponse]
}

func init() {
	registry.Register(ResourceTypeDisk, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &Disk{api: c.DisksClient, config: cfg, pipeline: c.Pipeline()}
	})
}

// Disk is the provisioner for Azure managed disks
// (`Microsoft.Compute/disks/<name>`). All CRUD operations are LRO.
type Disk struct {
	api      disksAPI
	config   *config.Config
	pipeline runtime.Pipeline
}

func serializeDiskProperties(result armcompute.Disk, rgName, diskName string) (json.RawMessage, error) {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	if result.Name != nil {
		props["name"] = *result.Name
	} else {
		props["name"] = diskName
	}
	if result.Location != nil {
		props["location"] = *result.Location
	}

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
	}

	if len(result.Zones) > 0 {
		zones := make([]string, 0, len(result.Zones))
		for _, z := range result.Zones {
			if z != nil {
				zones = append(zones, *z)
			}
		}
		props["zones"] = zones
	}

	if tags := azureTagsToFormaeTags(result.Tags); tags != nil {
		props["Tags"] = tags
	}

	if result.ID != nil {
		props["id"] = *result.ID
	}

	return json.Marshal(props)
}

func diskParamsFromProperties(props map[string]any) (armcompute.Disk, error) {
	location, _ := props["location"].(string)
	if location == "" {
		return armcompute.Disk{}, fmt.Errorf("location is required")
	}

	cdMap, ok := props["creationData"].(map[string]any)
	if !ok {
		return armcompute.Disk{}, fmt.Errorf("creationData is required")
	}
	createOption, _ := cdMap["createOption"].(string)
	if createOption == "" {
		return armcompute.Disk{}, fmt.Errorf("creationData.createOption is required")
	}
	co := armcompute.DiskCreateOption(createOption)
	cd := &armcompute.CreationData{CreateOption: &co}
	if src, ok := cdMap["sourceResourceId"].(string); ok && src != "" {
		cd.SourceResourceID = &src
	}

	skuMap, ok := props["sku"].(map[string]any)
	if !ok {
		return armcompute.Disk{}, fmt.Errorf("sku is required")
	}
	skuName, _ := skuMap["name"].(string)
	if skuName == "" {
		return armcompute.Disk{}, fmt.Errorf("sku.name is required")
	}
	sn := armcompute.DiskStorageAccountTypes(skuName)

	d := armcompute.Disk{
		Location: &location,
		SKU:      &armcompute.DiskSKU{Name: &sn},
		Properties: &armcompute.DiskProperties{
			CreationData: cd,
		},
	}

	if v, ok := props["diskSizeGB"].(float64); ok {
		size := int32(v)
		d.Properties.DiskSizeGB = &size
	}

	if rawZones, ok := props["zones"].([]any); ok && len(rawZones) > 0 {
		zones := make([]*string, 0, len(rawZones))
		for _, z := range rawZones {
			if s, ok := z.(string); ok {
				v := s
				zones = append(zones, &v)
			}
		}
		d.Zones = zones
	}

	if azureTags := formaeTagsToAzureTags(mustMarshalJSON(props)); azureTags != nil {
		d.Tags = azureTags
	}

	return d, nil
}

func mustMarshalJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

func (d *Disk) parseNativeID(nativeID string) (rgName, diskName string, err error) {
	parts := splitResourceID(nativeID)
	rgName = parts["resourcegroups"]
	diskName = parts["disks"]
	if rgName == "" || diskName == "" {
		return "", "", fmt.Errorf("invalid NativeID: %s", nativeID)
	}
	return rgName, diskName, nil
}

func (d *Disk) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props map[string]any
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	rgName, _ := props["resourceGroupName"].(string)
	if rgName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	diskName, _ := props["name"].(string)
	if diskName == "" {
		diskName = request.Label
	}
	if diskName == "" {
		return nil, fmt.Errorf("name is required")
	}

	params, err := diskParamsFromProperties(props)
	if err != nil {
		return nil, err
	}

	poller, err := d.api.BeginCreateOrUpdate(ctx, rgName, diskName, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       mapAzureErrorToOperationErrorCode(err),
			},
		}, nil
	}

	expectedID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Compute/disks/%s",
		d.config.SubscriptionId, rgName, diskName)

	if poller.Done() {
		result, err := poller.Result(ctx)
		if err != nil {
			return &resource.CreateResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationCreate,
					OperationStatus: resource.OperationStatusFailure,
					ErrorCode:       mapAzureErrorToOperationErrorCode(err),
				},
			}, nil
		}
		propsJSON, err := serializeDiskProperties(result.Disk, rgName, diskName)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize Disk properties: %w", err)
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

func (d *Disk) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, diskName, err := d.parseNativeID(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := d.api.Get(ctx, rgName, diskName, nil)
	if err != nil {
		return &resource.ReadResult{
			ErrorCode: mapAzureErrorToOperationErrorCode(err),
		}, nil
	}

	propsJSON, err := serializeDiskProperties(result.Disk, rgName, diskName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize Disk properties: %w", err)
	}

	return &resource.ReadResult{
		ResourceType: ResourceTypeDisk,
		Properties:   string(propsJSON),
	}, nil
}

func (d *Disk) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, diskName, err := d.parseNativeID(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props map[string]any
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse desired properties: %w", err)
	}

	update := armcompute.DiskUpdate{Properties: &armcompute.DiskUpdateProperties{}}
	if v, ok := props["diskSizeGB"].(float64); ok {
		size := int32(v)
		update.Properties.DiskSizeGB = &size
	}
	if skuMap, ok := props["sku"].(map[string]any); ok {
		if name, ok := skuMap["name"].(string); ok && name != "" {
			n := armcompute.DiskStorageAccountTypes(name)
			update.SKU = &armcompute.DiskSKU{Name: &n}
		}
	}
	if azureTags := formaeTagsToAzureTags(request.DesiredProperties); azureTags != nil {
		update.Tags = azureTags
	}

	poller, err := d.api.BeginUpdate(ctx, rgName, diskName, update, nil)
	if err != nil {
		return &resource.UpdateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationUpdate,
				OperationStatus: resource.OperationStatusFailure,
				NativeID:        request.NativeID,
				ErrorCode:       mapAzureErrorToOperationErrorCode(err),
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
					ErrorCode:       mapAzureErrorToOperationErrorCode(err),
				},
			}, nil
		}
		propsJSON, err := serializeDiskProperties(result.Disk, rgName, diskName)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize Disk properties: %w", err)
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

func (d *Disk) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, diskName, err := d.parseNativeID(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, err := d.api.BeginDelete(ctx, rgName, diskName, nil)
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
				ErrorCode:       mapAzureErrorToOperationErrorCode(err),
			},
		}, fmt.Errorf("failed to delete Disk: %w", err)
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

func (d *Disk) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
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
		return d.statusCreate(ctx, request, &reqID)
	case lroOpUpdate:
		return d.statusUpdate(ctx, request, &reqID)
	case lroOpDelete:
		return d.statusDelete(ctx, request, &reqID)
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

func (d *Disk) statusCreate(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	poller, err := resumePoller[armcompute.DisksClientCreateOrUpdateResponse](d.pipeline, reqID.ResumeToken)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
			},
		}, err
	}

	if !poller.Done() {
		if _, err := poller.Poll(ctx); err != nil {
			return &resource.StatusResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationCreate,
					OperationStatus: resource.OperationStatusFailure,
					RequestID:       request.RequestID,
					ErrorCode:       mapAzureErrorToOperationErrorCode(err),
				},
			}, err
		}
		if !poller.Done() {
			return &resource.StatusResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationCreate,
					OperationStatus: resource.OperationStatusInProgress,
					RequestID:       request.RequestID,
					NativeID:        reqID.NativeID,
				},
			}, nil
		}
	}

	result, err := poller.Result(ctx)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       mapAzureErrorToOperationErrorCode(err),
			},
		}, err
	}

	rgName, diskName, err := d.parseNativeID(*result.ID)
	if err != nil {
		return nil, err
	}

	propsJSON, err := serializeDiskProperties(result.Disk, rgName, diskName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize Disk properties: %w", err)
	}

	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			Operation:          resource.OperationCreate,
			OperationStatus:    resource.OperationStatusSuccess,
			RequestID:          request.RequestID,
			NativeID:           *result.ID,
			ResourceProperties: propsJSON,
		},
	}, nil
}

func (d *Disk) statusUpdate(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	poller, err := resumePoller[armcompute.DisksClientUpdateResponse](d.pipeline, reqID.ResumeToken)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationUpdate,
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
			},
		}, err
	}

	if !poller.Done() {
		if _, err := poller.Poll(ctx); err != nil {
			return &resource.StatusResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationUpdate,
					OperationStatus: resource.OperationStatusFailure,
					RequestID:       request.RequestID,
					ErrorCode:       mapAzureErrorToOperationErrorCode(err),
				},
			}, err
		}
		if !poller.Done() {
			return &resource.StatusResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationUpdate,
					OperationStatus: resource.OperationStatusInProgress,
					RequestID:       request.RequestID,
					NativeID:        reqID.NativeID,
				},
			}, nil
		}
	}

	result, err := poller.Result(ctx)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationUpdate,
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       mapAzureErrorToOperationErrorCode(err),
			},
		}, err
	}

	rgName, diskName, err := d.parseNativeID(*result.ID)
	if err != nil {
		return nil, err
	}

	propsJSON, err := serializeDiskProperties(result.Disk, rgName, diskName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize Disk properties: %w", err)
	}

	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			Operation:          resource.OperationUpdate,
			OperationStatus:    resource.OperationStatusSuccess,
			RequestID:          request.RequestID,
			NativeID:           *result.ID,
			ResourceProperties: propsJSON,
		},
	}, nil
}

func (d *Disk) statusDelete(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	poller, err := resumePoller[armcompute.DisksClientDeleteResponse](d.pipeline, reqID.ResumeToken)
	if err != nil {
		if isDeleteSuccessError(err) {
			return &resource.StatusResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationDelete,
					OperationStatus: resource.OperationStatusSuccess,
					RequestID:       request.RequestID,
					NativeID:        reqID.NativeID,
				},
			}, nil
		}
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationDelete,
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
			},
		}, err
	}

	if poller.Done() {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationDelete,
				OperationStatus: resource.OperationStatusSuccess,
				RequestID:       request.RequestID,
				NativeID:        reqID.NativeID,
			},
		}, nil
	}

	if _, err := poller.Poll(ctx); err != nil {
		if isDeleteSuccessError(err) {
			return &resource.StatusResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationDelete,
					OperationStatus: resource.OperationStatusSuccess,
					RequestID:       request.RequestID,
					NativeID:        reqID.NativeID,
				},
			}, nil
		}
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationDelete,
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       mapAzureErrorToOperationErrorCode(err),
			},
		}, err
	}

	if poller.Done() {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationDelete,
				OperationStatus: resource.OperationStatusSuccess,
				RequestID:       request.RequestID,
				NativeID:        reqID.NativeID,
			},
		}, nil
	}

	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationDelete,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       request.RequestID,
			NativeID:        reqID.NativeID,
		},
	}, nil
}

func (d *Disk) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]

	var nativeIDs []string
	if rgName != "" {
		pager := d.api.NewListByResourceGroupPager(rgName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list disks: %w", err)
			}
			for _, disk := range page.Value {
				if disk.ID != nil {
					nativeIDs = append(nativeIDs, *disk.ID)
				}
			}
		}
	} else {
		pager := d.api.NewListPager(nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list disks: %w", err)
			}
			for _, disk := range page.Value {
				if disk.ID != nil {
					nativeIDs = append(nativeIDs, *disk.ID)
				}
			}
		}
	}

	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
