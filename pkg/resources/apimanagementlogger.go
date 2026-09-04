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

const ResourceTypeApiManagementLogger = "AZURE::ApiManagement::Logger"

// apiManagementLoggersAPI is the armapimanagement surface used here. All
// synchronous, with ifMatch passed positionally on the PATCH and the delete.
type apiManagementLoggersAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName string, serviceName string, loggerID string, parameters armapimanagement.LoggerContract, options *armapimanagement.LoggerClientCreateOrUpdateOptions) (armapimanagement.LoggerClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName string, serviceName string, loggerID string, options *armapimanagement.LoggerClientGetOptions) (armapimanagement.LoggerClientGetResponse, error)
	Update(ctx context.Context, resourceGroupName string, serviceName string, loggerID string, ifMatch string, parameters armapimanagement.LoggerUpdateContract, options *armapimanagement.LoggerClientUpdateOptions) (armapimanagement.LoggerClientUpdateResponse, error)
	Delete(ctx context.Context, resourceGroupName string, serviceName string, loggerID string, ifMatch string, options *armapimanagement.LoggerClientDeleteOptions) (armapimanagement.LoggerClientDeleteResponse, error)
	NewListByServicePager(resourceGroupName string, serviceName string, options *armapimanagement.LoggerClientListByServiceOptions) *runtime.Pager[armapimanagement.LoggerClientListByServiceResponse]
}

func init() {
	registry.Register(ResourceTypeApiManagementLogger, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &ApiManagementLogger{
			api:    c.ApiManagementLoggerClient,
			config: cfg,
		}
	})
}

// ApiManagementLogger is the provisioner for loggers
// (Microsoft.ApiManagement/service/loggers) — the event sink a diagnostic
// writes to. A logger on its own emits nothing.
type ApiManagementLogger struct {
	api    apiManagementLoggersAPI
	config *config.Config
}

// apiManagementLoggerProps mirrors
// schema/pkl/apimanagement/apimanagementlogger.pkl.
type apiManagementLoggerProps struct {
	Name              string            `json:"name"`
	ResourceGroupName string            `json:"resourceGroupName"`
	ServiceName       string            `json:"serviceName"`
	LoggerType        string            `json:"loggerType"`
	Description       *string           `json:"description"`
	Credentials       map[string]string `json:"credentials"`
	ResourceID        *string           `json:"resourceId"`
	IsBuffered        *bool             `json:"isBuffered"`
}

func apiManagementLoggerIDParts(resourceID string) (rgName, serviceName, loggerID string, err error) {
	rgName, names, err := armExactIDParts(resourceID, "service", "loggers")
	if err != nil {
		return "", "", "", err
	}
	return rgName, names[0], names[1], nil
}

// credentialsContract turns the schema's flat map into ARM's map of pointers.
// Nil for an empty map so an azureMonitor logger, which takes no credentials,
// sends no block at all.
func (l *apiManagementLoggerProps) credentialsContract() map[string]*string {
	if len(l.Credentials) == 0 {
		return nil
	}
	out := make(map[string]*string, len(l.Credentials))
	for k, v := range l.Credentials {
		out[k] = to.Ptr(v)
	}
	return out
}

// buildPropertiesFromResult reports only what the schema declares.
//
// `credentials` is never reported. ARM does not store the value inline: it
// moves each entry into a hidden secret named value and answers a Get with a
// `{{Logger-Credentials-...}}` reference, so echoing the map back would report
// drift on every sync against the key that was actually declared.
func (l *ApiManagementLogger) buildPropertiesFromResult(logger *armapimanagement.LoggerContract, rgName, serviceName string) map[string]any {
	props := map[string]any{
		"resourceGroupName": rgName,
		"serviceName":       serviceName,
	}
	if logger.ID != nil {
		props["id"] = *logger.ID
	}
	if logger.Name != nil {
		props["name"] = *logger.Name
	}
	if lp := logger.Properties; lp != nil {
		if lp.LoggerType != nil {
			props["loggerType"] = canonicalizeEnum(string(*lp.LoggerType),
				"applicationInsights", "azureEventHub", "azureMonitor")
		}
		if lp.Description != nil {
			props["description"] = *lp.Description
		}
		if lp.ResourceID != nil {
			props["resourceId"] = *lp.ResourceID
		}
		if lp.IsBuffered != nil {
			props["isBuffered"] = *lp.IsBuffered
		}
	}
	return props
}

func (l *ApiManagementLogger) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props apiManagementLoggerProps
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	if props.ServiceName == "" {
		return nil, fmt.Errorf("serviceName is required")
	}
	if props.LoggerType == "" {
		return nil, fmt.Errorf("loggerType is required")
	}
	name := props.Name
	if name == "" {
		name = request.Label
	}
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}

	params := armapimanagement.LoggerContract{
		Properties: &armapimanagement.LoggerContractProperties{
			LoggerType:  to.Ptr(armapimanagement.LoggerType(props.LoggerType)),
			Description: props.Description,
			Credentials: props.credentialsContract(),
			ResourceID:  props.ResourceID,
			IsBuffered:  props.IsBuffered,
		},
	}

	result, err := l.api.CreateOrUpdate(ctx, props.ResourceGroupName, props.ServiceName, name, params, nil)
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
	propsJSON, err := json.Marshal(l.buildPropertiesFromResult(&result.LoggerContract,
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

func (l *ApiManagementLogger) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, serviceName, loggerID, err := apiManagementLoggerIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := l.api.Get(ctx, rgName, serviceName, loggerID, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(l.buildPropertiesFromResult(&result.LoggerContract, rgName, serviceName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeApiManagementLogger,
		Properties:   string(propsJSON),
	}, nil
}

// Update PATCHes. ARM's update contract nests its properties one level deeper
// than the create contract does — LoggerUpdateContract wraps
// LoggerUpdateParameters, which is the properties bag, not a second envelope.
func (l *ApiManagementLogger) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, serviceName, loggerID, err := apiManagementLoggerIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props apiManagementLoggerProps
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	updateProps := &armapimanagement.LoggerUpdateParameters{
		Description: props.Description,
		Credentials: props.credentialsContract(),
		IsBuffered:  props.IsBuffered,
	}
	if props.LoggerType != "" {
		updateProps.LoggerType = to.Ptr(armapimanagement.LoggerType(props.LoggerType))
	}

	result, err := l.api.Update(ctx, rgName, serviceName, loggerID, apimIfMatchAny,
		armapimanagement.LoggerUpdateContract{Properties: updateProps}, nil)
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

	propsJSON, err := json.Marshal(l.buildPropertiesFromResult(&result.LoggerContract, rgName, serviceName))
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

func (l *ApiManagementLogger) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, serviceName, loggerID, err := apiManagementLoggerIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	if _, err := l.api.Delete(ctx, rgName, serviceName, loggerID, apimIfMatchAny, nil); err != nil &&
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

// Status is never reached with real work to do: logger writes are synchronous.
func (l *ApiManagementLogger) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

// List needs both the resource group and the service name: ARM has no
// subscription-wide listing of loggers.
func (l *ApiManagementLogger) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	serviceName := request.AdditionalProperties["serviceName"]
	if rgName == "" || serviceName == "" {
		return &resource.ListResult{}, nil
	}

	var nativeIDs []string
	pager := l.api.NewListByServicePager(rgName, serviceName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list api management loggers: %w", err)
		}
		for _, logger := range page.Value {
			if logger.ID != nil {
				nativeIDs = append(nativeIDs, *logger.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
