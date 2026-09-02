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

const ResourceTypeApiManagementApiDiagnostic = "AZURE::ApiManagement::ApiDiagnostic"

// apiManagementAPIDiagnosticsAPI is the armapimanagement surface used here. All
// synchronous. Every verb carries the API id as an extra path segment, and
// Update takes the SAME DiagnosticContract as CreateOrUpdate.
type apiManagementAPIDiagnosticsAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName string, serviceName string, apiID string, diagnosticID string, parameters armapimanagement.DiagnosticContract, options *armapimanagement.APIDiagnosticClientCreateOrUpdateOptions) (armapimanagement.APIDiagnosticClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName string, serviceName string, apiID string, diagnosticID string, options *armapimanagement.APIDiagnosticClientGetOptions) (armapimanagement.APIDiagnosticClientGetResponse, error)
	Update(ctx context.Context, resourceGroupName string, serviceName string, apiID string, diagnosticID string, ifMatch string, parameters armapimanagement.DiagnosticContract, options *armapimanagement.APIDiagnosticClientUpdateOptions) (armapimanagement.APIDiagnosticClientUpdateResponse, error)
	Delete(ctx context.Context, resourceGroupName string, serviceName string, apiID string, diagnosticID string, ifMatch string, options *armapimanagement.APIDiagnosticClientDeleteOptions) (armapimanagement.APIDiagnosticClientDeleteResponse, error)
	NewListByServicePager(resourceGroupName string, serviceName string, apiID string, options *armapimanagement.APIDiagnosticClientListByServiceOptions) *runtime.Pager[armapimanagement.APIDiagnosticClientListByServiceResponse]
}

func init() {
	registry.Register(ResourceTypeApiManagementApiDiagnostic, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &ApiManagementApiDiagnostic{
			api:    c.ApiManagementAPIDiagnosticClient,
			config: cfg,
		}
	})
}

// ApiManagementApiDiagnostic is the provisioner for the per-API diagnostic
// (Microsoft.ApiManagement/service/apis/diagnostics) — what the gateway records
// about calls to ONE API, overriding the service-wide diagnostic for it.
//
// The body it writes is shared with AZURE::ApiManagement::Diagnostic; see
// apimanagementdiagnosticbody.go.
type ApiManagementApiDiagnostic struct {
	api    apiManagementAPIDiagnosticsAPI
	config *config.Config
}

// apiManagementApiDiagnosticProps mirrors
// schema/pkl/apimanagement/apimanagementapidiagnostic.pkl: the shared body plus
// the one name that makes it per-API.
type apiManagementApiDiagnosticProps struct {
	APIName string `json:"apiName"`
	apimDiagnosticProps
}

func apiManagementApiDiagnosticIDParts(resourceID string) (rgName, serviceName, apiID, diagnosticID string, err error) {
	rgName, names, err := armExactIDParts(resourceID, "service", "apis", "diagnostics")
	if err != nil {
		return "", "", "", "", err
	}
	return rgName, names[0], names[1], names[2], nil
}

func (d *ApiManagementApiDiagnostic) buildPropertiesFromResult(diag *armapimanagement.DiagnosticContract, rgName, serviceName, apiID string) map[string]any {
	props := map[string]any{
		"resourceGroupName": rgName,
		"serviceName":       serviceName,
		"apiName":           apiID,
	}
	if diag.ID != nil {
		props["id"] = *diag.ID
	}
	if diag.Name != nil {
		props["name"] = *diag.Name
	}
	apimDiagnosticReadProps(props, diag.Properties)
	return props
}

func (d *ApiManagementApiDiagnostic) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props apiManagementApiDiagnosticProps
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
	if props.LoggerID == "" {
		return nil, fmt.Errorf("loggerId is required")
	}
	name := props.Name
	if name == "" {
		name = request.Label
	}
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}

	result, err := d.api.CreateOrUpdate(ctx, props.ResourceGroupName, props.ServiceName, props.APIName,
		name, apimDiagnosticContract(props.apimDiagnosticProps), nil)
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
	propsJSON, err := json.Marshal(d.buildPropertiesFromResult(&result.DiagnosticContract,
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

func (d *ApiManagementApiDiagnostic) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, serviceName, apiID, diagnosticID, err := apiManagementApiDiagnosticIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := d.api.Get(ctx, rgName, serviceName, apiID, diagnosticID, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(d.buildPropertiesFromResult(&result.DiagnosticContract,
		rgName, serviceName, apiID))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeApiManagementApiDiagnostic,
		Properties:   string(propsJSON),
	}, nil
}

func (d *ApiManagementApiDiagnostic) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, serviceName, apiID, diagnosticID, err := apiManagementApiDiagnosticIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props apiManagementApiDiagnosticProps
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.LoggerID == "" {
		return nil, fmt.Errorf("loggerId is required")
	}

	result, err := d.api.Update(ctx, rgName, serviceName, apiID, diagnosticID, apimIfMatchAny,
		apimDiagnosticContract(props.apimDiagnosticProps), nil)
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

	propsJSON, err := json.Marshal(d.buildPropertiesFromResult(&result.DiagnosticContract,
		rgName, serviceName, apiID))
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

func (d *ApiManagementApiDiagnostic) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, serviceName, apiID, diagnosticID, err := apiManagementApiDiagnosticIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	if _, err := d.api.Delete(ctx, rgName, serviceName, apiID, diagnosticID, apimIfMatchAny, nil); err != nil &&
		!isDeleteSuccessError(err) {
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

// Status is never reached with real work to do: diagnostic writes are
// synchronous.
func (d *ApiManagementApiDiagnostic) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

// List requires the resource group, the service and the API: ARM has no
// service-wide listing of per-API diagnostics.
func (d *ApiManagementApiDiagnostic) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	serviceName := request.AdditionalProperties["serviceName"]
	apiName := request.AdditionalProperties["apiName"]
	if rgName == "" || serviceName == "" || apiName == "" {
		return &resource.ListResult{}, nil
	}

	var nativeIDs []string
	pager := d.api.NewListByServicePager(rgName, serviceName, apiName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list api management api diagnostics: %w", err)
		}
		for _, diag := range page.Value {
			if diag.ID != nil {
				nativeIDs = append(nativeIDs, *diag.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
