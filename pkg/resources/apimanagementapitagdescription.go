// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/apimanagement/armapimanagement"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeApiManagementApiTagDescription = "AZURE::ApiManagement::ApiTagDescription"

// apiManagementAPITagDescriptionsAPI is the armapimanagement surface used here.
// All synchronous. There is no PATCH: an update is another CreateOrUpdate.
type apiManagementAPITagDescriptionsAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName string, serviceName string, apiID string, tagDescriptionID string, parameters armapimanagement.TagDescriptionCreateParameters, options *armapimanagement.APITagDescriptionClientCreateOrUpdateOptions) (armapimanagement.APITagDescriptionClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName string, serviceName string, apiID string, tagDescriptionID string, options *armapimanagement.APITagDescriptionClientGetOptions) (armapimanagement.APITagDescriptionClientGetResponse, error)
	Delete(ctx context.Context, resourceGroupName string, serviceName string, apiID string, tagDescriptionID string, ifMatch string, options *armapimanagement.APITagDescriptionClientDeleteOptions) (armapimanagement.APITagDescriptionClientDeleteResponse, error)
	NewListByServicePager(resourceGroupName string, serviceName string, apiID string, options *armapimanagement.APITagDescriptionClientListByServiceOptions) *runtime.Pager[armapimanagement.APITagDescriptionClientListByServiceResponse]
}

func init() {
	registry.Register(ResourceTypeApiManagementApiTagDescription, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &ApiManagementApiTagDescription{
			api:    c.ApiManagementAPITagDescriptionClient,
			config: cfg,
		}
	})
}

// ApiManagementApiTagDescription is the provisioner for per-API tag
// descriptions (Microsoft.ApiManagement/service/apis/tagDescriptions).
//
// The resource name is the identifier of a tag that must ALREADY EXIST in the
// service: ARM does not create the tag as a side effect of describing it.
// Tags are a separate ARM resource this plugin does not yet model, so a tag
// description can currently only be attached to a tag created outside formae.
type ApiManagementApiTagDescription struct {
	api    apiManagementAPITagDescriptionsAPI
	config *config.Config
}

// apiManagementApiTagDescriptionProps mirrors
// schema/pkl/apimanagement/apimanagementapitagdescription.pkl.
type apiManagementApiTagDescriptionProps struct {
	Name                    string  `json:"name"`
	ResourceGroupName       string  `json:"resourceGroupName"`
	ServiceName             string  `json:"serviceName"`
	APIName                 string  `json:"apiName"`
	Description             *string `json:"description"`
	ExternalDocsDescription *string `json:"externalDocsDescription"`
	ExternalDocsURL         *string `json:"externalDocsUrl"`
}

func apiManagementApiTagDescriptionIDParts(resourceID string) (rgName, serviceName, apiID, tagDescriptionID string, err error) {
	rgName, names, err := armExactIDParts(resourceID, "service", "apis", "tagDescriptions")
	if err != nil {
		return "", "", "", "", err
	}
	return rgName, names[0], names[1], names[2], nil
}

func (t *ApiManagementApiTagDescription) buildPropertiesFromResult(desc *armapimanagement.TagDescriptionContract, rgName, serviceName, apiID string) map[string]any {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	props["serviceName"] = serviceName
	props["apiName"] = apiID

	if desc.ID != nil {
		props["id"] = *desc.ID
	}
	if desc.Name != nil {
		props["name"] = *desc.Name
	}

	if p := desc.Properties; p != nil {
		if p.Description != nil {
			props["description"] = *p.Description
		}
		if p.ExternalDocsDescription != nil {
			props["externalDocsDescription"] = *p.ExternalDocsDescription
		}
		if p.ExternalDocsURL != nil {
			props["externalDocsUrl"] = *p.ExternalDocsURL
		}
		if p.DisplayName != nil {
			props["displayName"] = *p.DisplayName
		}
		if p.TagID != nil {
			props["tagId"] = *p.TagID
		}
	}

	return props
}

func (t *ApiManagementApiTagDescription) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props apiManagementApiTagDescriptionProps
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	if props.ServiceName == "" {
		return nil, fmt.Errorf("serviceName is required")
	}
	if props.APIName == "" {
		return nil, fmt.Errorf("apiName is required")
	}
	name := props.Name
	if name == "" {
		name = request.Label
	}
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}

	params := armapimanagement.TagDescriptionCreateParameters{
		Properties: &armapimanagement.TagDescriptionBaseProperties{
			Description:             props.Description,
			ExternalDocsDescription: props.ExternalDocsDescription,
			ExternalDocsURL:         props.ExternalDocsURL,
		},
	}

	result, err := t.api.CreateOrUpdate(ctx, props.ResourceGroupName, props.ServiceName, props.APIName, name, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
				StatusMessage:   err.Error(),
			},
		}, nil
	}

	nativeID := ""
	if result.ID != nil {
		nativeID = *result.ID
	}
	propsJSON, err := json.Marshal(t.buildPropertiesFromResult(&result.TagDescriptionContract,
		props.ResourceGroupName, props.ServiceName, props.APIName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
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

func (t *ApiManagementApiTagDescription) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, serviceName, apiID, tagDescriptionID, err := apiManagementApiTagDescriptionIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := t.api.Get(ctx, rgName, serviceName, apiID, tagDescriptionID, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(t.buildPropertiesFromResult(&result.TagDescriptionContract, rgName, serviceName, apiID))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeApiManagementApiTagDescription,
		Properties:   string(propsJSON),
	}, nil
}

// Update re-PUTs through CreateOrUpdate: a tag description has no PATCH verb.
func (t *ApiManagementApiTagDescription) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, serviceName, apiID, tagDescriptionID, err := apiManagementApiTagDescriptionIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props apiManagementApiTagDescriptionProps
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	params := armapimanagement.TagDescriptionCreateParameters{
		Properties: &armapimanagement.TagDescriptionBaseProperties{
			Description:             props.Description,
			ExternalDocsDescription: props.ExternalDocsDescription,
			ExternalDocsURL:         props.ExternalDocsURL,
		},
	}

	result, err := t.api.CreateOrUpdate(ctx, rgName, serviceName, apiID, tagDescriptionID, params, nil)
	if err != nil {
		return &resource.UpdateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationUpdate,
				OperationStatus: resource.OperationStatusFailure,
				NativeID:        request.NativeID,
				ErrorCode:       operationErrorCode(err),
				StatusMessage:   err.Error(),
			},
		}, nil
	}

	propsJSON, err := json.Marshal(t.buildPropertiesFromResult(&result.TagDescriptionContract, rgName, serviceName, apiID))
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

func (t *ApiManagementApiTagDescription) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, serviceName, apiID, tagDescriptionID, err := apiManagementApiTagDescriptionIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	if _, err := t.api.Delete(ctx, rgName, serviceName, apiID, tagDescriptionID, apimIfMatchAny, nil); err != nil && !isDeleteSuccessError(err) {
		return &resource.DeleteResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationDelete,
				OperationStatus: resource.OperationStatusFailure,
				NativeID:        request.NativeID,
				ErrorCode:       operationErrorCode(err),
				StatusMessage:   err.Error(),
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

// Status is never reached with real work to do: every write here is
// synchronous.
func (t *ApiManagementApiTagDescription) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

// List requires the resource group, the service and the API. The SDK calls the
// pager ListByService but it is scoped to a single API all the same.
func (t *ApiManagementApiTagDescription) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	serviceName := request.AdditionalProperties["serviceName"]
	apiName := request.AdditionalProperties["apiName"]
	if rgName == "" || serviceName == "" || apiName == "" {
		return &resource.ListResult{}, nil
	}

	var nativeIDs []string
	pager := t.api.NewListByServicePager(rgName, serviceName, apiName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list api management api tag descriptions: %w", err)
		}
		for _, desc := range page.Value {
			if desc.ID != nil {
				nativeIDs = append(nativeIDs, *desc.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
