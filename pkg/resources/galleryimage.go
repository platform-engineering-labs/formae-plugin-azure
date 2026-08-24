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

const ResourceTypeGalleryImage = "AZURE::Compute::GalleryImage"

// galleryImagesAPI is the subset of *armcompute.GalleryImagesClient used here,
// plus the gallery enumeration discovery needs: image definitions can only be
// listed per-gallery. All verbs are LROs.
type galleryImagesAPI interface {
	BeginCreateOrUpdate(ctx context.Context, resourceGroupName, galleryName, galleryImageName string, galleryImage armcompute.GalleryImage, options *armcompute.GalleryImagesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armcompute.GalleryImagesClientCreateOrUpdateResponse], error)
	Get(ctx context.Context, resourceGroupName, galleryName, galleryImageName string, options *armcompute.GalleryImagesClientGetOptions) (armcompute.GalleryImagesClientGetResponse, error)
	BeginUpdate(ctx context.Context, resourceGroupName, galleryName, galleryImageName string, galleryImage armcompute.GalleryImageUpdate, options *armcompute.GalleryImagesClientBeginUpdateOptions) (*runtime.Poller[armcompute.GalleryImagesClientUpdateResponse], error)
	BeginDelete(ctx context.Context, resourceGroupName, galleryName, galleryImageName string, options *armcompute.GalleryImagesClientBeginDeleteOptions) (*runtime.Poller[armcompute.GalleryImagesClientDeleteResponse], error)
	NewListByGalleryPager(resourceGroupName, galleryName string, options *armcompute.GalleryImagesClientListByGalleryOptions) *runtime.Pager[armcompute.GalleryImagesClientListByGalleryResponse]
	NewListGalleriesPager(options *armcompute.GalleriesClientListOptions) *runtime.Pager[armcompute.GalleriesClientListResponse]
}

// galleryImagesWrapper composes the GalleryImages SDK client with subscription-wide
// gallery discovery.
type galleryImagesWrapper struct {
	*armcompute.GalleryImagesClient
	galleriesClient *armcompute.GalleriesClient
}

func (w *galleryImagesWrapper) NewListGalleriesPager(options *armcompute.GalleriesClientListOptions) *runtime.Pager[armcompute.GalleriesClientListResponse] {
	return w.galleriesClient.NewListPager(options)
}

func init() {
	registry.Register(ResourceTypeGalleryImage, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &GalleryImage{
			api: &galleryImagesWrapper{
				GalleryImagesClient: c.GalleryImagesClient,
				galleriesClient:     c.GalleriesClient,
			},
			config:   cfg,
			pipeline: c.Pipeline(),
		}
	})
}

// GalleryImage is the provisioner for Compute Gallery image definitions
// (`Microsoft.Compute/galleries/<gallery>/images/<name>`) — the metadata shell
// (publisher/offer/sku, OS, generation) that gallery image *versions* hang off.
//
// Note the leaf ARM segment is `images`, the same word standalone managed images
// use, so the ID parser must match the full `galleries/images` chain exactly.
type GalleryImage struct {
	api      galleryImagesAPI
	config   *config.Config
	pipeline runtime.Pipeline
}

func galleryImageIDParts(resourceID string) (rgName, galleryName, name string, err error) {
	// armExactIDParts, not armIDParts: a standalone managed image ID also ends in an
	// "images" segment, so name-based matching would accept one here.
	rgName, names, err := armExactIDParts(resourceID, "galleries", "images")
	if err != nil {
		return "", "", "", err
	}
	return rgName, names[0], names[1], nil
}

func serializeGalleryImageProperties(result armcompute.GalleryImage, rgName, galleryName, name string) (json.RawMessage, error) {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	props["galleryName"] = galleryName
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
		p := result.Properties
		if p.Identifier != nil {
			identifier := map[string]any{}
			if p.Identifier.Publisher != nil {
				identifier["publisher"] = *p.Identifier.Publisher
			}
			if p.Identifier.Offer != nil {
				identifier["offer"] = *p.Identifier.Offer
			}
			if p.Identifier.SKU != nil {
				identifier["sku"] = *p.Identifier.SKU
			}
			props["identifier"] = identifier
		}
		if p.OSType != nil {
			props["osType"] = string(*p.OSType)
		}
		if p.OSState != nil {
			props["osState"] = string(*p.OSState)
		}
		if p.HyperVGeneration != nil {
			props["hyperVGeneration"] = string(*p.HyperVGeneration)
		}
		if p.Architecture != nil {
			props["architecture"] = string(*p.Architecture)
		}
		if p.Description != nil {
			props["description"] = *p.Description
		}
	}

	if tags := azureTagsToFormaeTags(result.Tags); tags != nil {
		props["Tags"] = tags
	}

	return json.Marshal(props)
}

// galleryImagePropsFromProperties builds the ARM properties block shared by create
// and update. ARM marks identifier / osType / osState as required on every write,
// including the PATCH, even though all three are immutable — so the update has to
// echo them back.
func galleryImagePropsFromProperties(props map[string]any) (*armcompute.GalleryImageProperties, error) {
	identifierMap, ok := props["identifier"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("identifier is required")
	}
	publisher, _ := identifierMap["publisher"].(string)
	offer, _ := identifierMap["offer"].(string)
	sku, _ := identifierMap["sku"].(string)
	if publisher == "" || offer == "" || sku == "" {
		return nil, fmt.Errorf("identifier.publisher, identifier.offer and identifier.sku are all required")
	}

	osType, _ := props["osType"].(string)
	if osType == "" {
		return nil, fmt.Errorf("osType is required")
	}
	osState, _ := props["osState"].(string)
	if osState == "" {
		return nil, fmt.Errorf("osState is required")
	}

	p := &armcompute.GalleryImageProperties{
		Identifier: &armcompute.GalleryImageIdentifier{
			Publisher: to.Ptr(publisher),
			Offer:     to.Ptr(offer),
			SKU:       to.Ptr(sku),
		},
		OSType:  to.Ptr(armcompute.OperatingSystemTypes(osType)),
		OSState: to.Ptr(armcompute.OperatingSystemStateTypes(osState)),
	}
	if v, ok := props["hyperVGeneration"].(string); ok && v != "" {
		p.HyperVGeneration = to.Ptr(armcompute.HyperVGeneration(v))
	}
	if v, ok := props["architecture"].(string); ok && v != "" {
		p.Architecture = to.Ptr(armcompute.Architecture(v))
	}
	if v, ok := props["description"].(string); ok && v != "" {
		p.Description = to.Ptr(v)
	}

	return p, nil
}

func (i *GalleryImage) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props map[string]any
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	rgName, _ := props["resourceGroupName"].(string)
	if rgName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	galleryName, _ := props["galleryName"].(string)
	if galleryName == "" {
		return nil, fmt.Errorf("galleryName is required")
	}
	name, _ := props["name"].(string)
	if name == "" {
		name = request.Label
	}
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}
	location, _ := props["location"].(string)
	if location == "" {
		return nil, fmt.Errorf("location is required")
	}

	armProps, err := galleryImagePropsFromProperties(props)
	if err != nil {
		return nil, err
	}
	params := armcompute.GalleryImage{
		Location:   to.Ptr(location),
		Properties: armProps,
	}
	if azureTags := formaeTagsToAzureTags(request.Properties); azureTags != nil {
		params.Tags = azureTags
	}

	poller, err := i.api.BeginCreateOrUpdate(ctx, rgName, galleryName, name, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	expectedID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Compute/galleries/%s/images/%s",
		i.config.SubscriptionId, rgName, galleryName, name)

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
		propsJSON, err := serializeGalleryImageProperties(result.GalleryImage, rgName, galleryName, name)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize GalleryImage properties: %w", err)
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

func (i *GalleryImage) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, galleryName, name, err := galleryImageIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := i.api.Get(ctx, rgName, galleryName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := serializeGalleryImageProperties(result.GalleryImage, rgName, galleryName, name)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize GalleryImage properties: %w", err)
	}

	return &resource.ReadResult{
		ResourceType: ResourceTypeGalleryImage,
		Properties:   string(propsJSON),
	}, nil
}

func (i *GalleryImage) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, galleryName, name, err := galleryImageIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props map[string]any
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse desired properties: %w", err)
	}

	armProps, err := galleryImagePropsFromProperties(props)
	if err != nil {
		return nil, err
	}
	update := armcompute.GalleryImageUpdate{Properties: armProps}
	if azureTags := formaeTagsToAzureTags(request.DesiredProperties); azureTags != nil {
		update.Tags = azureTags
	}

	poller, err := i.api.BeginUpdate(ctx, rgName, galleryName, name, update, nil)
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
		propsJSON, err := serializeGalleryImageProperties(result.GalleryImage, rgName, galleryName, name)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize GalleryImage properties: %w", err)
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

func (i *GalleryImage) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, galleryName, name, err := galleryImageIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, err := i.api.BeginDelete(ctx, rgName, galleryName, name, nil)
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
		}, fmt.Errorf("failed to delete GalleryImage: %w", err)
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

func (i *GalleryImage) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
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

func (i *GalleryImage) statusCreate(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	return statusLRO(ctx, request, reqID, resource.OperationCreate,
		func(token string) (*runtime.Poller[armcompute.GalleryImagesClientCreateOrUpdateResponse], error) {
			return resumePoller[armcompute.GalleryImagesClientCreateOrUpdateResponse](i.pipeline, token)
		},
		func(_ context.Context, result armcompute.GalleryImagesClientCreateOrUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
			rgName, galleryName, name, err := galleryImageIDParts(*result.ID)
			if err != nil {
				return "", nil, err
			}
			propsJSON, err := serializeGalleryImageProperties(result.GalleryImage, rgName, galleryName, name)
			if err != nil {
				return "", nil, fmt.Errorf("failed to serialize GalleryImage properties: %w", err)
			}
			return *result.ID, propsJSON, nil
		})
}

func (i *GalleryImage) statusUpdate(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	return statusLRO(ctx, request, reqID, resource.OperationUpdate,
		func(token string) (*runtime.Poller[armcompute.GalleryImagesClientUpdateResponse], error) {
			return resumePoller[armcompute.GalleryImagesClientUpdateResponse](i.pipeline, token)
		},
		func(_ context.Context, result armcompute.GalleryImagesClientUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
			rgName, galleryName, name, err := galleryImageIDParts(*result.ID)
			if err != nil {
				return "", nil, err
			}
			propsJSON, err := serializeGalleryImageProperties(result.GalleryImage, rgName, galleryName, name)
			if err != nil {
				return "", nil, fmt.Errorf("failed to serialize GalleryImage properties: %w", err)
			}
			return *result.ID, propsJSON, nil
		})
}

func (i *GalleryImage) statusDelete(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	return statusDeleteLRO(ctx, request, reqID,
		func(token string) (*runtime.Poller[armcompute.GalleryImagesClientDeleteResponse], error) {
			return resumePoller[armcompute.GalleryImagesClientDeleteResponse](i.pipeline, token)
		}, nil)
}

func (i *GalleryImage) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	galleryName := request.AdditionalProperties["galleryName"]

	if rgName != "" && galleryName != "" {
		ids, err := i.listByGallery(ctx, rgName, galleryName)
		if err != nil {
			return nil, err
		}
		return &resource.ListResult{NativeIDs: ids}, nil
	}

	// Discovery path: image definitions can only be listed per-gallery.
	var nativeIDs []string
	pager := i.api.NewListGalleriesPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list galleries for image definition discovery: %w", err)
		}
		for _, gal := range page.Value {
			if gal.ID == nil {
				continue
			}
			galRG, galName, err := galleryIDParts(*gal.ID)
			if err != nil {
				continue
			}
			ids, err := i.listByGallery(ctx, galRG, galName)
			if err != nil {
				return nil, err
			}
			nativeIDs = append(nativeIDs, ids...)
		}
	}

	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}

func (i *GalleryImage) listByGallery(ctx context.Context, rgName, galleryName string) ([]string, error) {
	pager := i.api.NewListByGalleryPager(rgName, galleryName, nil)

	var nativeIDs []string
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list image definitions in gallery %s/%s: %w", rgName, galleryName, err)
		}
		for _, img := range page.Value {
			if img.ID != nil {
				nativeIDs = append(nativeIDs, *img.ID)
			}
		}
	}

	return nativeIDs, nil
}
