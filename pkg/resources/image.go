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

const ResourceTypeImage = "AZURE::Compute::Image"

// imagesAPI is the subset of *armcompute.ImagesClient used here. All verbs are LROs.
type imagesAPI interface {
	BeginCreateOrUpdate(ctx context.Context, resourceGroupName, imageName string, parameters armcompute.Image, options *armcompute.ImagesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armcompute.ImagesClientCreateOrUpdateResponse], error)
	Get(ctx context.Context, resourceGroupName, imageName string, options *armcompute.ImagesClientGetOptions) (armcompute.ImagesClientGetResponse, error)
	BeginUpdate(ctx context.Context, resourceGroupName, imageName string, parameters armcompute.ImageUpdate, options *armcompute.ImagesClientBeginUpdateOptions) (*runtime.Poller[armcompute.ImagesClientUpdateResponse], error)
	BeginDelete(ctx context.Context, resourceGroupName, imageName string, options *armcompute.ImagesClientBeginDeleteOptions) (*runtime.Poller[armcompute.ImagesClientDeleteResponse], error)
	NewListByResourceGroupPager(resourceGroupName string, options *armcompute.ImagesClientListByResourceGroupOptions) *runtime.Pager[armcompute.ImagesClientListByResourceGroupResponse]
	NewListPager(options *armcompute.ImagesClientListOptions) *runtime.Pager[armcompute.ImagesClientListResponse]
}

func init() {
	registry.Register(ResourceTypeImage, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &Image{api: c.ImagesClient, config: cfg, pipeline: c.Pipeline()}
	})
}

// Image is the provisioner for Azure managed images
// (`Microsoft.Compute/images/<name>`) — the pre-Compute-Gallery way to capture a
// generalized OS disk so VMs can be created from it.
//
// Only the OS disk is modelled, sourced from either a snapshot or a managed disk.
// Data disks, blob URIs and per-disk caching/encryption are deliberately left out
// until a consumer needs them.
type Image struct {
	api      imagesAPI
	config   *config.Config
	pipeline runtime.Pipeline
}

func imageIDParts(resourceID string) (rgName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "images")
	if err != nil {
		return "", "", err
	}
	return rgName, names["images"], nil
}

func serializeImageProperties(result armcompute.Image, rgName, name string) (json.RawMessage, error) {
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

	if result.Properties != nil {
		if result.Properties.HyperVGeneration != nil {
			props["hyperVGeneration"] = string(*result.Properties.HyperVGeneration)
		}
		if sp := result.Properties.StorageProfile; sp != nil && sp.OSDisk != nil {
			// Only the fields the create body sets are echoed back: ARM fills in
			// caching / storageAccountType / diskSizeGB on the nested OS disk, and
			// hasProviderDefault is not honoured below the top level, so surfacing
			// them here would show as permanent drift.
			osDisk := map[string]any{}
			if sp.OSDisk.OSType != nil {
				osDisk["osType"] = string(*sp.OSDisk.OSType)
			}
			if sp.OSDisk.OSState != nil {
				osDisk["osState"] = string(*sp.OSDisk.OSState)
			}
			if sp.OSDisk.Snapshot != nil && sp.OSDisk.Snapshot.ID != nil {
				osDisk["snapshotId"] = *sp.OSDisk.Snapshot.ID
			}
			if sp.OSDisk.ManagedDisk != nil && sp.OSDisk.ManagedDisk.ID != nil {
				osDisk["managedDiskId"] = *sp.OSDisk.ManagedDisk.ID
			}
			props["storageProfile"] = map[string]any{"osDisk": osDisk}
		}
	}

	if tags := azureTagsToFormaeTags(result.Tags); tags != nil {
		props["Tags"] = tags
	}

	return json.Marshal(props)
}

func imageParamsFromProperties(props map[string]any, rawProps json.RawMessage) (armcompute.Image, error) {
	location, _ := props["location"].(string)
	if location == "" {
		return armcompute.Image{}, fmt.Errorf("location is required")
	}

	spMap, ok := props["storageProfile"].(map[string]any)
	if !ok {
		return armcompute.Image{}, fmt.Errorf("storageProfile is required")
	}
	osDiskMap, ok := spMap["osDisk"].(map[string]any)
	if !ok {
		return armcompute.Image{}, fmt.Errorf("storageProfile.osDisk is required")
	}
	osType, _ := osDiskMap["osType"].(string)
	if osType == "" {
		return armcompute.Image{}, fmt.Errorf("storageProfile.osDisk.osType is required")
	}
	osState, _ := osDiskMap["osState"].(string)
	if osState == "" {
		return armcompute.Image{}, fmt.Errorf("storageProfile.osDisk.osState is required")
	}

	osDisk := &armcompute.ImageOSDisk{
		OSType:  to.Ptr(armcompute.OperatingSystemTypes(osType)),
		OSState: to.Ptr(armcompute.OperatingSystemStateTypes(osState)),
	}
	snapshotID, _ := osDiskMap["snapshotId"].(string)
	managedDiskID, _ := osDiskMap["managedDiskId"].(string)
	switch {
	case snapshotID != "":
		osDisk.Snapshot = &armcompute.SubResource{ID: to.Ptr(snapshotID)}
	case managedDiskID != "":
		osDisk.ManagedDisk = &armcompute.SubResource{ID: to.Ptr(managedDiskID)}
	default:
		return armcompute.Image{}, fmt.Errorf("storageProfile.osDisk needs either snapshotId or managedDiskId")
	}

	img := armcompute.Image{
		Location: to.Ptr(location),
		Properties: &armcompute.ImageProperties{
			StorageProfile: &armcompute.ImageStorageProfile{OSDisk: osDisk},
		},
	}

	if v, ok := props["hyperVGeneration"].(string); ok && v != "" {
		img.Properties.HyperVGeneration = to.Ptr(armcompute.HyperVGenerationTypes(v))
	}

	if azureTags := formaeTagsToAzureTags(rawProps); azureTags != nil {
		img.Tags = azureTags
	}

	return img, nil
}

func (i *Image) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
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

	params, err := imageParamsFromProperties(props, request.Properties)
	if err != nil {
		return nil, err
	}

	poller, err := i.api.BeginCreateOrUpdate(ctx, rgName, name, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	expectedID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Compute/images/%s",
		i.config.SubscriptionId, rgName, name)

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
		propsJSON, err := serializeImageProperties(result.Image, rgName, name)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize Image properties: %w", err)
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

func (i *Image) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, name, err := imageIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := i.api.Get(ctx, rgName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := serializeImageProperties(result.Image, rgName, name)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize Image properties: %w", err)
	}

	return &resource.ReadResult{
		ResourceType: ResourceTypeImage,
		Properties:   string(propsJSON),
	}, nil
}

func (i *Image) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, name, err := imageIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	// The storage profile is createOnly, so the PATCH carries tags only — a body
	// that re-declares the OS disk source makes ARM re-validate an immutable field.
	update := armcompute.ImageUpdate{}
	if azureTags := formaeTagsToAzureTags(request.DesiredProperties); azureTags != nil {
		update.Tags = azureTags
	}

	poller, err := i.api.BeginUpdate(ctx, rgName, name, update, nil)
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
		propsJSON, err := serializeImageProperties(result.Image, rgName, name)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize Image properties: %w", err)
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

func (i *Image) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, name, err := imageIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, err := i.api.BeginDelete(ctx, rgName, name, nil)
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
		}, fmt.Errorf("failed to delete Image: %w", err)
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

func (i *Image) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
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
		return i.statusCreate(ctx, request, &reqID)
	case lroOpUpdate:
		return i.statusUpdate(ctx, request, &reqID)
	case lroOpDelete:
		return i.statusDelete(ctx, request, &reqID)
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

func (i *Image) statusCreate(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	return statusLRO(ctx, request, reqID, resource.OperationCreate,
		func(token string) (*runtime.Poller[armcompute.ImagesClientCreateOrUpdateResponse], error) {
			return resumePoller[armcompute.ImagesClientCreateOrUpdateResponse](i.pipeline, token)
		},
		func(_ context.Context, result armcompute.ImagesClientCreateOrUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
			rgName, name, err := imageIDParts(*result.ID)
			if err != nil {
				return "", nil, err
			}
			propsJSON, err := serializeImageProperties(result.Image, rgName, name)
			if err != nil {
				return "", nil, fmt.Errorf("failed to serialize Image properties: %w", err)
			}
			return *result.ID, propsJSON, nil
		})
}

func (i *Image) statusUpdate(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	return statusLRO(ctx, request, reqID, resource.OperationUpdate,
		func(token string) (*runtime.Poller[armcompute.ImagesClientUpdateResponse], error) {
			return resumePoller[armcompute.ImagesClientUpdateResponse](i.pipeline, token)
		},
		func(_ context.Context, result armcompute.ImagesClientUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
			rgName, name, err := imageIDParts(*result.ID)
			if err != nil {
				return "", nil, err
			}
			propsJSON, err := serializeImageProperties(result.Image, rgName, name)
			if err != nil {
				return "", nil, fmt.Errorf("failed to serialize Image properties: %w", err)
			}
			return *result.ID, propsJSON, nil
		})
}

func (i *Image) statusDelete(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	return statusDeleteLRO(ctx, request, reqID,
		func(token string) (*runtime.Poller[armcompute.ImagesClientDeleteResponse], error) {
			return resumePoller[armcompute.ImagesClientDeleteResponse](i.pipeline, token)
		}, nil)
}

func (i *Image) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]

	var nativeIDs []string
	if rgName != "" {
		pager := i.api.NewListByResourceGroupPager(rgName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list images in resource group %s: %w", rgName, err)
			}
			for _, img := range page.Value {
				if img.ID != nil {
					nativeIDs = append(nativeIDs, *img.ID)
				}
			}
		}
		return &resource.ListResult{NativeIDs: nativeIDs}, nil
	}

	pager := i.api.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list images: %w", err)
		}
		for _, img := range page.Value {
			if img.ID != nil {
				nativeIDs = append(nativeIDs, *img.ID)
			}
		}
	}

	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
