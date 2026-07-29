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

const ResourceTypeGallery = "AZURE::Compute::Gallery"

// galleriesAPI is the subset of *armcompute.GalleriesClient used here. All verbs
// are LROs.
type galleriesAPI interface {
	BeginCreateOrUpdate(ctx context.Context, resourceGroupName, galleryName string, gallery armcompute.Gallery, options *armcompute.GalleriesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armcompute.GalleriesClientCreateOrUpdateResponse], error)
	Get(ctx context.Context, resourceGroupName, galleryName string, options *armcompute.GalleriesClientGetOptions) (armcompute.GalleriesClientGetResponse, error)
	BeginUpdate(ctx context.Context, resourceGroupName, galleryName string, gallery armcompute.GalleryUpdate, options *armcompute.GalleriesClientBeginUpdateOptions) (*runtime.Poller[armcompute.GalleriesClientUpdateResponse], error)
	BeginDelete(ctx context.Context, resourceGroupName, galleryName string, options *armcompute.GalleriesClientBeginDeleteOptions) (*runtime.Poller[armcompute.GalleriesClientDeleteResponse], error)
	NewListByResourceGroupPager(resourceGroupName string, options *armcompute.GalleriesClientListByResourceGroupOptions) *runtime.Pager[armcompute.GalleriesClientListByResourceGroupResponse]
	NewListPager(options *armcompute.GalleriesClientListOptions) *runtime.Pager[armcompute.GalleriesClientListResponse]
}

func init() {
	registry.Register(ResourceTypeGallery, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &Gallery{api: c.GalleriesClient, config: cfg, pipeline: c.Pipeline()}
	})
}

// Gallery is the provisioner for Azure Compute Galleries
// (`Microsoft.Compute/galleries/<name>`) — the container for versioned image
// definitions that replaced standalone managed images.
//
// Gallery names are more restrictive than most ARM names: alphanumerics, periods
// and underscores only, no hyphens.
type Gallery struct {
	api      galleriesAPI
	config   *config.Config
	pipeline runtime.Pipeline
}

func galleryIDParts(resourceID string) (rgName, name string, err error) {
	rgName, names, err := armExactIDParts(resourceID, "galleries")
	if err != nil {
		return "", "", err
	}
	return rgName, names[0], nil
}

func serializeGalleryProperties(result armcompute.Gallery, rgName, name string) (json.RawMessage, error) {
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

	// identifier.uniqueName, provisioningState and sharingStatus are read-only ARM
	// output with no schema field.
	if result.Properties != nil && result.Properties.Description != nil {
		props["description"] = *result.Properties.Description
	}

	if tags := azureTagsToFormaeTags(result.Tags); tags != nil {
		props["Tags"] = tags
	}

	return json.Marshal(props)
}

func galleryParamsFromProperties(props map[string]any, rawProps json.RawMessage) (armcompute.Gallery, error) {
	location, _ := props["location"].(string)
	if location == "" {
		return armcompute.Gallery{}, fmt.Errorf("location is required")
	}

	g := armcompute.Gallery{
		Location:   to.Ptr(location),
		Properties: &armcompute.GalleryProperties{},
	}
	if v, ok := props["description"].(string); ok && v != "" {
		g.Properties.Description = to.Ptr(v)
	}
	if azureTags := formaeTagsToAzureTags(rawProps); azureTags != nil {
		g.Tags = azureTags
	}

	return g, nil
}

func (g *Gallery) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
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

	params, err := galleryParamsFromProperties(props, request.Properties)
	if err != nil {
		return nil, err
	}

	poller, err := g.api.BeginCreateOrUpdate(ctx, rgName, name, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	expectedID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Compute/galleries/%s",
		g.config.SubscriptionId, rgName, name)

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
		propsJSON, err := serializeGalleryProperties(result.Gallery, rgName, name)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize Gallery properties: %w", err)
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

func (g *Gallery) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, name, err := galleryIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := g.api.Get(ctx, rgName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := serializeGalleryProperties(result.Gallery, rgName, name)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize Gallery properties: %w", err)
	}

	return &resource.ReadResult{
		ResourceType: ResourceTypeGallery,
		Properties:   string(propsJSON),
	}, nil
}

func (g *Gallery) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, name, err := galleryIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props map[string]any
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse desired properties: %w", err)
	}

	update := armcompute.GalleryUpdate{Properties: &armcompute.GalleryProperties{}}
	if v, ok := props["description"].(string); ok && v != "" {
		update.Properties.Description = to.Ptr(v)
	}
	if azureTags := formaeTagsToAzureTags(request.DesiredProperties); azureTags != nil {
		update.Tags = azureTags
	}

	poller, err := g.api.BeginUpdate(ctx, rgName, name, update, nil)
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
		propsJSON, err := serializeGalleryProperties(result.Gallery, rgName, name)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize Gallery properties: %w", err)
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

func (g *Gallery) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, name, err := galleryIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, err := g.api.BeginDelete(ctx, rgName, name, nil)
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
		}, fmt.Errorf("failed to delete Gallery: %w", err)
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

func (g *Gallery) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
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
		return g.statusCreate(ctx, request, &reqID)
	case lroOpUpdate:
		return g.statusUpdate(ctx, request, &reqID)
	case lroOpDelete:
		return g.statusDelete(ctx, request, &reqID)
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

func (g *Gallery) statusCreate(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	return statusLRO(ctx, request, reqID, resource.OperationCreate,
		func(token string) (*runtime.Poller[armcompute.GalleriesClientCreateOrUpdateResponse], error) {
			return resumePoller[armcompute.GalleriesClientCreateOrUpdateResponse](g.pipeline, token)
		},
		func(_ context.Context, result armcompute.GalleriesClientCreateOrUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
			rgName, name, err := galleryIDParts(*result.ID)
			if err != nil {
				return "", nil, err
			}
			propsJSON, err := serializeGalleryProperties(result.Gallery, rgName, name)
			if err != nil {
				return "", nil, fmt.Errorf("failed to serialize Gallery properties: %w", err)
			}
			return *result.ID, propsJSON, nil
		})
}

func (g *Gallery) statusUpdate(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	return statusLRO(ctx, request, reqID, resource.OperationUpdate,
		func(token string) (*runtime.Poller[armcompute.GalleriesClientUpdateResponse], error) {
			return resumePoller[armcompute.GalleriesClientUpdateResponse](g.pipeline, token)
		},
		func(_ context.Context, result armcompute.GalleriesClientUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
			rgName, name, err := galleryIDParts(*result.ID)
			if err != nil {
				return "", nil, err
			}
			propsJSON, err := serializeGalleryProperties(result.Gallery, rgName, name)
			if err != nil {
				return "", nil, fmt.Errorf("failed to serialize Gallery properties: %w", err)
			}
			return *result.ID, propsJSON, nil
		})
}

func (g *Gallery) statusDelete(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	return statusDeleteLRO(ctx, request, reqID,
		func(token string) (*runtime.Poller[armcompute.GalleriesClientDeleteResponse], error) {
			return resumePoller[armcompute.GalleriesClientDeleteResponse](g.pipeline, token)
		}, nil)
}

func (g *Gallery) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]

	var nativeIDs []string
	if rgName != "" {
		pager := g.api.NewListByResourceGroupPager(rgName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list galleries in resource group %s: %w", rgName, err)
			}
			for _, gal := range page.Value {
				if gal.ID != nil {
					nativeIDs = append(nativeIDs, *gal.ID)
				}
			}
		}
		return &resource.ListResult{NativeIDs: nativeIDs}, nil
	}

	pager := g.api.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list galleries: %w", err)
		}
		for _, gal := range page.Value {
			if gal.ID != nil {
				nativeIDs = append(nativeIDs, *gal.ID)
			}
		}
	}

	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
