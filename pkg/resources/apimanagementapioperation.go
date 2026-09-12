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

const ResourceTypeApiManagementApiOperation = "AZURE::ApiManagement::ApiOperation"

// apiManagementAPIOperationsAPI is the armapimanagement surface used here.
// Everything is synchronous — an operation is a record, not a deployment — so
// Status never has real work to do.
type apiManagementAPIOperationsAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName string, serviceName string, apiID string, operationID string, parameters armapimanagement.OperationContract, options *armapimanagement.APIOperationClientCreateOrUpdateOptions) (armapimanagement.APIOperationClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName string, serviceName string, apiID string, operationID string, options *armapimanagement.APIOperationClientGetOptions) (armapimanagement.APIOperationClientGetResponse, error)
	Update(ctx context.Context, resourceGroupName string, serviceName string, apiID string, operationID string, ifMatch string, parameters armapimanagement.OperationUpdateContract, options *armapimanagement.APIOperationClientUpdateOptions) (armapimanagement.APIOperationClientUpdateResponse, error)
	Delete(ctx context.Context, resourceGroupName string, serviceName string, apiID string, operationID string, ifMatch string, options *armapimanagement.APIOperationClientDeleteOptions) (armapimanagement.APIOperationClientDeleteResponse, error)
	NewListByAPIPager(resourceGroupName string, serviceName string, apiID string, options *armapimanagement.APIOperationClientListByAPIOptions) *runtime.Pager[armapimanagement.APIOperationClientListByAPIResponse]
}

func init() {
	registry.Register(ResourceTypeApiManagementApiOperation, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &ApiManagementApiOperation{
			api:    c.ApiManagementAPIOperationClient,
			config: cfg,
		}
	})
}

// ApiManagementApiOperation is the provisioner for API operations
// (Microsoft.ApiManagement/service/apis/operations).
type ApiManagementApiOperation struct {
	api    apiManagementAPIOperationsAPI
	config *config.Config
}

// apiManagementApiOperationProps mirrors
// schema/pkl/apimanagement/apimanagementapioperation.pkl.
type apiManagementApiOperationProps struct {
	Name              string  `json:"name"`
	ResourceGroupName string  `json:"resourceGroupName"`
	ServiceName       string  `json:"serviceName"`
	APIName           string  `json:"apiName"`
	DisplayName       string  `json:"displayName"`
	Method            string  `json:"method"`
	URLTemplate       string  `json:"urlTemplate"`
	Description       *string `json:"description"`
}

func apiManagementApiOperationIDParts(resourceID string) (rgName, serviceName, apiID, operationID string, err error) {
	rgName, names, err := armExactIDParts(resourceID, "service", "apis", "operations")
	if err != nil {
		return "", "", "", "", err
	}
	return rgName, names[0], names[1], names[2], nil
}

func (o *ApiManagementApiOperation) buildPropertiesFromResult(op *armapimanagement.OperationContract, rgName, serviceName, apiID string) map[string]any {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	props["serviceName"] = serviceName
	props["apiName"] = apiID

	if op.ID != nil {
		props["id"] = *op.ID
	}
	if op.Name != nil {
		props["name"] = *op.Name
	}

	if p := op.Properties; p != nil {
		if p.DisplayName != nil {
			props["displayName"] = *p.DisplayName
		}
		if p.Method != nil {
			props["method"] = *p.Method
		}
		if p.URLTemplate != nil {
			props["urlTemplate"] = *p.URLTemplate
		}
		if p.Description != nil {
			props["description"] = *p.Description
		}
		// request, responses, templateParameters and policies are deliberately
		// dropped: the first three are not modelled by this resource (see the
		// PKL doc comment), and the operation's policy is its own resource.
	}

	return props
}

func (o *ApiManagementApiOperation) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props apiManagementApiOperationProps
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
	if props.DisplayName == "" {
		return nil, fmt.Errorf("displayName is required")
	}
	if props.Method == "" {
		return nil, fmt.Errorf("method is required")
	}
	if props.URLTemplate == "" {
		return nil, fmt.Errorf("urlTemplate is required")
	}
	name := props.Name
	if name == "" {
		name = request.Label
	}
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}

	params := armapimanagement.OperationContract{
		Properties: &armapimanagement.OperationContractProperties{
			DisplayName: to.Ptr(props.DisplayName),
			Method:      to.Ptr(props.Method),
			URLTemplate: to.Ptr(props.URLTemplate),
			Description: props.Description,
		},
	}

	result, err := o.api.CreateOrUpdate(ctx, props.ResourceGroupName, props.ServiceName, props.APIName, name, params, nil)
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
	propsJSON, err := json.Marshal(o.buildPropertiesFromResult(&result.OperationContract,
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

func (o *ApiManagementApiOperation) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, serviceName, apiID, operationID, err := apiManagementApiOperationIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := o.api.Get(ctx, rgName, serviceName, apiID, operationID, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(o.buildPropertiesFromResult(&result.OperationContract, rgName, serviceName, apiID))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeApiManagementApiOperation,
		Properties:   string(propsJSON),
	}, nil
}

func (o *ApiManagementApiOperation) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, serviceName, apiID, operationID, err := apiManagementApiOperationIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props apiManagementApiOperationProps
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	updateProps := &armapimanagement.OperationUpdateContractProperties{
		Description: props.Description,
	}
	if props.DisplayName != "" {
		updateProps.DisplayName = to.Ptr(props.DisplayName)
	}
	if props.Method != "" {
		updateProps.Method = to.Ptr(props.Method)
	}
	if props.URLTemplate != "" {
		updateProps.URLTemplate = to.Ptr(props.URLTemplate)
	}

	result, err := o.api.Update(ctx, rgName, serviceName, apiID, operationID, apimIfMatchAny,
		armapimanagement.OperationUpdateContract{Properties: updateProps}, nil)
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

	propsJSON, err := json.Marshal(o.buildPropertiesFromResult(&result.OperationContract, rgName, serviceName, apiID))
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

func (o *ApiManagementApiOperation) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, serviceName, apiID, operationID, err := apiManagementApiOperationIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	if _, err := o.api.Delete(ctx, rgName, serviceName, apiID, operationID, apimIfMatchAny, nil); err != nil && !isDeleteSuccessError(err) {
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

// Status is never reached with real work to do: every operation on an API
// operation is synchronous, so it echoes success.
func (o *ApiManagementApiOperation) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

// List requires the resource group, the service and the API: ARM has no
// service-wide or subscription-wide listing of operations.
func (o *ApiManagementApiOperation) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	serviceName := request.AdditionalProperties["serviceName"]
	apiName := request.AdditionalProperties["apiName"]
	if rgName == "" || serviceName == "" || apiName == "" {
		return &resource.ListResult{}, nil
	}

	var nativeIDs []string
	pager := o.api.NewListByAPIPager(rgName, serviceName, apiName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list api management api operations: %w", err)
		}
		for _, op := range page.Value {
			if op.ID != nil {
				nativeIDs = append(nativeIDs, *op.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
