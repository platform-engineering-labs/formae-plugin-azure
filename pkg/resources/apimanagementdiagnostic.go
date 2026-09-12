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

const ResourceTypeApiManagementDiagnostic = "AZURE::ApiManagement::Diagnostic"

// apiManagementDiagnosticsAPI is the armapimanagement surface used here. All
// synchronous. Note that Update takes the SAME DiagnosticContract as
// CreateOrUpdate rather than a separate update-parameters type.
type apiManagementDiagnosticsAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName string, serviceName string, diagnosticID string, parameters armapimanagement.DiagnosticContract, options *armapimanagement.DiagnosticClientCreateOrUpdateOptions) (armapimanagement.DiagnosticClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName string, serviceName string, diagnosticID string, options *armapimanagement.DiagnosticClientGetOptions) (armapimanagement.DiagnosticClientGetResponse, error)
	Update(ctx context.Context, resourceGroupName string, serviceName string, diagnosticID string, ifMatch string, parameters armapimanagement.DiagnosticContract, options *armapimanagement.DiagnosticClientUpdateOptions) (armapimanagement.DiagnosticClientUpdateResponse, error)
	Delete(ctx context.Context, resourceGroupName string, serviceName string, diagnosticID string, ifMatch string, options *armapimanagement.DiagnosticClientDeleteOptions) (armapimanagement.DiagnosticClientDeleteResponse, error)
	NewListByServicePager(resourceGroupName string, serviceName string, options *armapimanagement.DiagnosticClientListByServiceOptions) *runtime.Pager[armapimanagement.DiagnosticClientListByServiceResponse]
}

func init() {
	registry.Register(ResourceTypeApiManagementDiagnostic, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &ApiManagementDiagnostic{
			api:    c.ApiManagementDiagnosticClient,
			config: cfg,
		}
	})
}

// ApiManagementDiagnostic is the provisioner for the service-wide diagnostic
// (Microsoft.ApiManagement/service/diagnostics) — what the gateway records
// about every call and where it sends it.
//
// The body it writes is shared with AZURE::ApiManagement::ApiDiagnostic; see
// apimanagementdiagnosticbody.go.
type ApiManagementDiagnostic struct {
	api    apiManagementDiagnosticsAPI
	config *config.Config
}

// apiManagementDiagnosticProps mirrors
// schema/pkl/apimanagement/apimanagementdiagnostic.pkl. Every field lives in
// the shared body: the service-wide diagnostic adds no scope of its own beyond
// the resource group and the service, which apimDiagnosticProps already carries.
type apiManagementDiagnosticProps struct {
	apimDiagnosticProps
}

func apiManagementDiagnosticIDParts(resourceID string) (rgName, serviceName, diagnosticID string, err error) {
	rgName, names, err := armExactIDParts(resourceID, "service", "diagnostics")
	if err != nil {
		return "", "", "", err
	}
	return rgName, names[0], names[1], nil
}

func (d *ApiManagementDiagnostic) buildPropertiesFromResult(diag *armapimanagement.DiagnosticContract, rgName, serviceName string) map[string]any {
	props := map[string]any{
		"resourceGroupName": rgName,
		"serviceName":       serviceName,
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

func (d *ApiManagementDiagnostic) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props apiManagementDiagnosticProps
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	if props.ServiceName == "" {
		return nil, fmt.Errorf("serviceName is required")
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

	result, err := d.api.CreateOrUpdate(ctx, props.ResourceGroupName, props.ServiceName, name,
		apimDiagnosticContract(props.apimDiagnosticProps), nil)
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

func (d *ApiManagementDiagnostic) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, serviceName, diagnosticID, err := apiManagementDiagnosticIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := d.api.Get(ctx, rgName, serviceName, diagnosticID, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(d.buildPropertiesFromResult(&result.DiagnosticContract, rgName, serviceName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeApiManagementDiagnostic,
		Properties:   string(propsJSON),
	}, nil
}

func (d *ApiManagementDiagnostic) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, serviceName, diagnosticID, err := apiManagementDiagnosticIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props apiManagementDiagnosticProps
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.LoggerID == "" {
		return nil, fmt.Errorf("loggerId is required")
	}

	result, err := d.api.Update(ctx, rgName, serviceName, diagnosticID, apimIfMatchAny,
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

	propsJSON, err := json.Marshal(d.buildPropertiesFromResult(&result.DiagnosticContract, rgName, serviceName))
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

func (d *ApiManagementDiagnostic) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, serviceName, diagnosticID, err := apiManagementDiagnosticIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	if _, err := d.api.Delete(ctx, rgName, serviceName, diagnosticID, apimIfMatchAny, nil); err != nil &&
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
func (d *ApiManagementDiagnostic) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

// List needs both the resource group and the service name: ARM has no
// subscription-wide listing of diagnostics.
func (d *ApiManagementDiagnostic) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	serviceName := request.AdditionalProperties["serviceName"]
	if rgName == "" || serviceName == "" {
		return &resource.ListResult{}, nil
	}

	var nativeIDs []string
	pager := d.api.NewListByServicePager(rgName, serviceName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list api management diagnostics: %w", err)
		}
		for _, diag := range page.Value {
			if diag.ID != nil {
				nativeIDs = append(nativeIDs, *diag.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
