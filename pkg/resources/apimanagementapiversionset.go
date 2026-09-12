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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/apimanagement/armapimanagement"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeApiManagementApiVersionSet = "AZURE::ApiManagement::ApiVersionSet"

// apiManagementAPIVersionSetsAPI is the armapimanagement surface used here.
// All synchronous, with ifMatch passed positionally on the PATCH and the
// delete.
type apiManagementAPIVersionSetsAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName string, serviceName string, versionSetID string, parameters armapimanagement.APIVersionSetContract, options *armapimanagement.APIVersionSetClientCreateOrUpdateOptions) (armapimanagement.APIVersionSetClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName string, serviceName string, versionSetID string, options *armapimanagement.APIVersionSetClientGetOptions) (armapimanagement.APIVersionSetClientGetResponse, error)
	Update(ctx context.Context, resourceGroupName string, serviceName string, versionSetID string, ifMatch string, parameters armapimanagement.APIVersionSetUpdateParameters, options *armapimanagement.APIVersionSetClientUpdateOptions) (armapimanagement.APIVersionSetClientUpdateResponse, error)
	Delete(ctx context.Context, resourceGroupName string, serviceName string, versionSetID string, ifMatch string, options *armapimanagement.APIVersionSetClientDeleteOptions) (armapimanagement.APIVersionSetClientDeleteResponse, error)
	NewListByServicePager(resourceGroupName string, serviceName string, options *armapimanagement.APIVersionSetClientListByServiceOptions) *runtime.Pager[armapimanagement.APIVersionSetClientListByServiceResponse]
}

func init() {
	registry.Register(ResourceTypeApiManagementApiVersionSet, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &ApiManagementApiVersionSet{
			api:    c.ApiManagementAPIVersionSetClient,
			config: cfg,
		}
	})
}

// ApiManagementApiVersionSet is the provisioner for API version sets
// (Microsoft.ApiManagement/service/apiVersionSets).
type ApiManagementApiVersionSet struct {
	api    apiManagementAPIVersionSetsAPI
	config *config.Config
}

// apiManagementApiVersionSetProps mirrors
// schema/pkl/apimanagement/apimanagementapiversionset.pkl.
type apiManagementApiVersionSetProps struct {
	Name              string  `json:"name"`
	ResourceGroupName string  `json:"resourceGroupName"`
	ServiceName       string  `json:"serviceName"`
	DisplayName       string  `json:"displayName"`
	VersioningScheme  string  `json:"versioningScheme"`
	Description       *string `json:"description"`
	VersionHeaderName *string `json:"versionHeaderName"`
	VersionQueryName  *string `json:"versionQueryName"`
}

func apiManagementApiVersionSetIDParts(resourceID string) (rgName, serviceName, versionSetID string, err error) {
	rgName, names, err := armExactIDParts(resourceID, "service", "apiVersionSets")
	if err != nil {
		return "", "", "", err
	}
	return rgName, names[0], names[1], nil
}

func (v *ApiManagementApiVersionSet) buildPropertiesFromResult(set *armapimanagement.APIVersionSetContract, rgName, serviceName string) map[string]any {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	props["serviceName"] = serviceName

	if set.ID != nil {
		props["id"] = *set.ID
	}
	if set.Name != nil {
		props["name"] = *set.Name
	}

	if p := set.Properties; p != nil {
		if p.DisplayName != nil {
			props["displayName"] = *p.DisplayName
		}
		if p.VersioningScheme != nil {
			props["versioningScheme"] = canonicalizeEnum(string(*p.VersioningScheme), "Segment", "Header", "Query")
		}
		if p.Description != nil {
			props["description"] = *p.Description
		}
		if p.VersionHeaderName != nil {
			props["versionHeaderName"] = *p.VersionHeaderName
		}
		if p.VersionQueryName != nil {
			props["versionQueryName"] = *p.VersionQueryName
		}
	}

	return props
}

func (v *ApiManagementApiVersionSet) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props apiManagementApiVersionSetProps
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	if props.ServiceName == "" {
		return nil, fmt.Errorf("serviceName is required")
	}
	if props.DisplayName == "" {
		return nil, fmt.Errorf("displayName is required")
	}
	if props.VersioningScheme == "" {
		return nil, fmt.Errorf("versioningScheme is required")
	}
	name := props.Name
	if name == "" {
		name = request.Label
	}
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}

	params := armapimanagement.APIVersionSetContract{
		Properties: &armapimanagement.APIVersionSetContractProperties{
			DisplayName:       to.Ptr(props.DisplayName),
			VersioningScheme:  to.Ptr(armapimanagement.VersioningScheme(props.VersioningScheme)),
			Description:       props.Description,
			VersionHeaderName: props.VersionHeaderName,
			VersionQueryName:  props.VersionQueryName,
		},
	}

	result, err := v.api.CreateOrUpdate(ctx, props.ResourceGroupName, props.ServiceName, name, params, nil)
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
	propsJSON, err := json.Marshal(v.buildPropertiesFromResult(&result.APIVersionSetContract,
		props.ResourceGroupName, props.ServiceName))
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

func (v *ApiManagementApiVersionSet) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, serviceName, versionSetID, err := apiManagementApiVersionSetIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := v.api.Get(ctx, rgName, serviceName, versionSetID, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(v.buildPropertiesFromResult(&result.APIVersionSetContract, rgName, serviceName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeApiManagementApiVersionSet,
		Properties:   string(propsJSON),
	}, nil
}

func (v *ApiManagementApiVersionSet) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, serviceName, versionSetID, err := apiManagementApiVersionSetIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props apiManagementApiVersionSetProps
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	updateProps := &armapimanagement.APIVersionSetUpdateParametersProperties{
		Description:       props.Description,
		VersionHeaderName: props.VersionHeaderName,
		VersionQueryName:  props.VersionQueryName,
	}
	if props.DisplayName != "" {
		updateProps.DisplayName = to.Ptr(props.DisplayName)
	}
	if props.VersioningScheme != "" {
		updateProps.VersioningScheme = to.Ptr(armapimanagement.VersioningScheme(props.VersioningScheme))
	}

	result, err := v.api.Update(ctx, rgName, serviceName, versionSetID, apimIfMatchAny,
		armapimanagement.APIVersionSetUpdateParameters{Properties: updateProps}, nil)
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

	propsJSON, err := json.Marshal(v.buildPropertiesFromResult(&result.APIVersionSetContract, rgName, serviceName))
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

func (v *ApiManagementApiVersionSet) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, serviceName, versionSetID, err := apiManagementApiVersionSetIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	if _, err := v.api.Delete(ctx, rgName, serviceName, versionSetID, apimIfMatchAny, nil); err != nil && !isDeleteSuccessError(err) {
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

// Status is never reached with real work to do: version-set writes are
// synchronous.
func (v *ApiManagementApiVersionSet) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

// List needs both the resource group and the service name: ARM has no
// subscription-wide listing of version sets.
func (v *ApiManagementApiVersionSet) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	serviceName := request.AdditionalProperties["serviceName"]
	if rgName == "" || serviceName == "" {
		return &resource.ListResult{}, nil
	}

	var nativeIDs []string
	pager := v.api.NewListByServicePager(rgName, serviceName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list api management api version sets: %w", err)
		}
		for _, set := range page.Value {
			if set.ID != nil {
				nativeIDs = append(nativeIDs, *set.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
