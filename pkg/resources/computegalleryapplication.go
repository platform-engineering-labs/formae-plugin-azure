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

const ResourceTypeComputeGalleryApplication = "AZURE::Compute::GalleryApplication"

// computeGalleryApplicationsAPI is the armcompute surface used here. All three
// mutating calls are LROs. Create takes a GalleryApplication and update a
// GalleryApplicationUpdate, but both carry the same properties block — only
// location differs.
type computeGalleryApplicationsAPI interface {
	BeginCreateOrUpdate(ctx context.Context, resourceGroupName string, galleryName string, galleryApplicationName string, galleryApplication armcompute.GalleryApplication, options *armcompute.GalleryApplicationsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armcompute.GalleryApplicationsClientCreateOrUpdateResponse], error)
	Get(ctx context.Context, resourceGroupName string, galleryName string, galleryApplicationName string, options *armcompute.GalleryApplicationsClientGetOptions) (armcompute.GalleryApplicationsClientGetResponse, error)
	BeginUpdate(ctx context.Context, resourceGroupName string, galleryName string, galleryApplicationName string, galleryApplication armcompute.GalleryApplicationUpdate, options *armcompute.GalleryApplicationsClientBeginUpdateOptions) (*runtime.Poller[armcompute.GalleryApplicationsClientUpdateResponse], error)
	BeginDelete(ctx context.Context, resourceGroupName string, galleryName string, galleryApplicationName string, options *armcompute.GalleryApplicationsClientBeginDeleteOptions) (*runtime.Poller[armcompute.GalleryApplicationsClientDeleteResponse], error)
	NewListByGalleryPager(resourceGroupName string, galleryName string, options *armcompute.GalleryApplicationsClientListByGalleryOptions) *runtime.Pager[armcompute.GalleryApplicationsClientListByGalleryResponse]
}

func init() {
	registry.Register(ResourceTypeComputeGalleryApplication, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &ComputeGalleryApplication{
			api:      c.GalleryApplicationsClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// ComputeGalleryApplication is the provisioner for VM application definitions in an
// Azure Compute Gallery (Microsoft.Compute/galleries/applications).
type ComputeGalleryApplication struct {
	api      computeGalleryApplicationsAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

// computeGalleryApplicationProps mirrors
// schema/pkl/compute/galleryapplication.pkl.
type computeGalleryApplicationProps struct {
	Name              string  `json:"name"`
	Location          string  `json:"location"`
	ResourceGroupName string  `json:"resourceGroupName"`
	GalleryName       string  `json:"galleryName"`
	SupportedOSType   string  `json:"supportedOSType"`
	Description       *string `json:"description"`
}

func computeGalleryApplicationIDParts(resourceID string) (rgName, galleryName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "galleries", "applications")
	if err != nil {
		return "", "", "", err
	}
	return rgName, names["galleries"], names["applications"], nil
}

func (a *ComputeGalleryApplication) buildPropertiesFromResult(app *armcompute.GalleryApplication, rgName, galleryName string) map[string]any {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	props["galleryName"] = galleryName

	if app.ID != nil {
		props["id"] = *app.ID
	}
	if app.Name != nil {
		props["name"] = *app.Name
	}
	if app.Location != nil {
		props["location"] = normalizeAzureLocation(*app.Location)
	}

	if p := app.Properties; p != nil {
		if p.SupportedOSType != nil {
			props["supportedOSType"] = canonicalizeEnum(string(*p.SupportedOSType), "Windows", "Linux")
		}
		if p.Description != nil {
			props["description"] = *p.Description
		}
		// customActions, endOfLifeDate, eula, privacyStatementUri and releaseNoteUri
		// are not modelled, so they are not read back: surfacing a field the schema
		// cannot express would read as drift.
	}

	if tags := azureTagsToFormaeTags(app.Tags); tags != nil {
		props["Tags"] = tags
	}

	return props
}

// computeGalleryApplicationProperties builds the properties block shared by create
// and update.
func computeGalleryApplicationProperties(props computeGalleryApplicationProps) *armcompute.GalleryApplicationProperties {
	appProps := &armcompute.GalleryApplicationProperties{
		Description: props.Description,
	}
	if props.SupportedOSType != "" {
		appProps.SupportedOSType = to.Ptr(armcompute.OperatingSystemTypes(props.SupportedOSType))
	}
	return appProps
}

func (a *ComputeGalleryApplication) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props computeGalleryApplicationProps
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	if props.GalleryName == "" {
		return nil, fmt.Errorf("galleryName is required")
	}
	if props.Location == "" {
		return nil, fmt.Errorf("location is required")
	}
	if props.SupportedOSType == "" {
		return nil, fmt.Errorf("supportedOSType is required")
	}
	name := props.Name
	if name == "" {
		name = request.Label
	}
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}

	params := armcompute.GalleryApplication{
		Location:   to.Ptr(props.Location),
		Properties: computeGalleryApplicationProperties(props),
	}
	if azureTags := formaeTagsToAzureTags(request.Properties); azureTags != nil {
		params.Tags = azureTags
	}

	poller, err := a.api.BeginCreateOrUpdate(ctx, props.ResourceGroupName, props.GalleryName, name, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Compute/galleries/%s/applications/%s",
		a.config.SubscriptionId, props.ResourceGroupName, props.GalleryName, name)

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
		nativeID, propsJSON, err := a.completeFromApplication(&result.GalleryApplication)
		if err != nil {
			return nil, err
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

	resumeToken, err := poller.ResumeToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get resume token: %w", err)
	}
	reqIDJSON, err := encodeLROStart(lroOpCreate, resumeToken, expectedNativeID)
	if err != nil {
		return nil, err
	}

	return &resource.CreateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationCreate,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       reqIDJSON,
			NativeID:        expectedNativeID,
		},
	}, nil
}

func (a *ComputeGalleryApplication) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, galleryName, name, err := computeGalleryApplicationIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := a.api.Get(ctx, rgName, galleryName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(a.buildPropertiesFromResult(&result.GalleryApplication, rgName, galleryName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeComputeGalleryApplication,
		Properties:   string(propsJSON),
	}, nil
}

// Update takes GalleryApplicationUpdate, which has no location field, and
// supportedOSType is createOnly — so description and tags are what really move.
func (a *ComputeGalleryApplication) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, galleryName, name, err := computeGalleryApplicationIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props computeGalleryApplicationProps
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	params := armcompute.GalleryApplicationUpdate{Properties: computeGalleryApplicationProperties(props)}
	if azureTags := formaeTagsToAzureTags(request.DesiredProperties); azureTags != nil {
		params.Tags = azureTags
	}

	poller, err := a.api.BeginUpdate(ctx, rgName, galleryName, name, params, nil)
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
		propsJSON, err := json.Marshal(a.buildPropertiesFromResult(&result.GalleryApplication, rgName, galleryName))
		if err != nil {
			return nil, fmt.Errorf("failed to marshal response properties: %w", err)
		}
		return &resource.UpdateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:          resource.OperationUpdate,
				OperationStatus:    resource.OperationStatusSuccess,
				NativeID:           request.NativeID,
				ResourceProperties: propsJSON,
			},
		}, nil
	}

	resumeToken, err := poller.ResumeToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get resume token: %w", err)
	}
	reqIDJSON, err := encodeLROStart(lroOpUpdate, resumeToken, request.NativeID)
	if err != nil {
		return nil, err
	}

	return &resource.UpdateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationUpdate,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       reqIDJSON,
			NativeID:        request.NativeID,
		},
	}, nil
}

func (a *ComputeGalleryApplication) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, galleryName, name, err := computeGalleryApplicationIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, err := a.api.BeginDelete(ctx, rgName, galleryName, name, nil)
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
		}, nil
	}

	if poller.Done() {
		if _, err := poller.Result(ctx); err != nil && !isDeleteSuccessError(err) {
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

	resumeToken, err := poller.ResumeToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get resume token: %w", err)
	}
	reqIDJSON, err := encodeLROStart(lroOpDelete, resumeToken, request.NativeID)
	if err != nil {
		return nil, err
	}

	return &resource.DeleteResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationDelete,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       reqIDJSON,
			NativeID:        request.NativeID,
		},
	}, nil
}

func (a *ComputeGalleryApplication) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	reqID, err := decodeLROStatus(request.RequestID)
	if err != nil {
		return nil, err
	}

	switch reqID.OperationType {
	case lroOpCreate:
		return statusLRO(ctx, request, &reqID, resource.OperationCreate,
			func(token string) (*runtime.Poller[armcompute.GalleryApplicationsClientCreateOrUpdateResponse], error) {
				return resumePoller[armcompute.GalleryApplicationsClientCreateOrUpdateResponse](a.pipeline, token)
			},
			func(_ context.Context, result armcompute.GalleryApplicationsClientCreateOrUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				return a.completeFromApplication(&result.GalleryApplication)
			})
	case lroOpUpdate:
		// Resumed as an Update response, matching the BeginUpdate poller that handed
		// out this token.
		return statusLRO(ctx, request, &reqID, resource.OperationUpdate,
			func(token string) (*runtime.Poller[armcompute.GalleryApplicationsClientUpdateResponse], error) {
				return resumePoller[armcompute.GalleryApplicationsClientUpdateResponse](a.pipeline, token)
			},
			func(_ context.Context, result armcompute.GalleryApplicationsClientUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				return a.completeFromApplication(&result.GalleryApplication)
			})
	case lroOpDelete:
		return statusDeleteLRO(ctx, request, &reqID,
			func(token string) (*runtime.Poller[armcompute.GalleryApplicationsClientDeleteResponse], error) {
				return resumePoller[armcompute.GalleryApplicationsClientDeleteResponse](a.pipeline, token)
			}, nil)
	default:
		return nil, fmt.Errorf("unknown operation type: %s", reqID.OperationType)
	}
}

func (a *ComputeGalleryApplication) completeFromApplication(app *armcompute.GalleryApplication) (string, json.RawMessage, error) {
	nativeID := ""
	rgName := ""
	galleryName := ""
	if app.ID != nil {
		nativeID = *app.ID
		if rg, gallery, _, err := computeGalleryApplicationIDParts(*app.ID); err == nil {
			rgName = rg
			galleryName = gallery
		}
	}
	propsJSON, err := json.Marshal(a.buildPropertiesFromResult(app, rgName, galleryName))
	if err != nil {
		return "", nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return nativeID, propsJSON, nil
}

// List requires both the resource group and the gallery: ARM has no
// subscription-wide listing for application definitions.
func (a *ComputeGalleryApplication) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	galleryName := request.AdditionalProperties["galleryName"]
	if rgName == "" || galleryName == "" {
		return &resource.ListResult{}, nil
	}

	var nativeIDs []string
	pager := a.api.NewListByGalleryPager(rgName, galleryName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list gallery applications: %w", err)
		}
		for _, app := range page.Value {
			if app.ID != nil {
				nativeIDs = append(nativeIDs, *app.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
