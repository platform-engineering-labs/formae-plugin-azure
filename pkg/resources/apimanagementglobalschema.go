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

const ResourceTypeApiManagementGlobalSchema = "AZURE::ApiManagement::GlobalSchema"

// apiManagementGlobalSchemasAPI is the armapimanagement surface used here. The
// create is an LRO (ARM validates the document), while delete is synchronous
// and takes ifMatch positionally. There is no PATCH: an update is another
// CreateOrUpdate.
type apiManagementGlobalSchemasAPI interface {
	BeginCreateOrUpdate(ctx context.Context, resourceGroupName string, serviceName string, schemaID string, parameters armapimanagement.GlobalSchemaContract, options *armapimanagement.GlobalSchemaClientBeginCreateOrUpdateOptions) (*runtime.Poller[armapimanagement.GlobalSchemaClientCreateOrUpdateResponse], error)
	Get(ctx context.Context, resourceGroupName string, serviceName string, schemaID string, options *armapimanagement.GlobalSchemaClientGetOptions) (armapimanagement.GlobalSchemaClientGetResponse, error)
	Delete(ctx context.Context, resourceGroupName string, serviceName string, schemaID string, ifMatch string, options *armapimanagement.GlobalSchemaClientDeleteOptions) (armapimanagement.GlobalSchemaClientDeleteResponse, error)
	NewListByServicePager(resourceGroupName string, serviceName string, options *armapimanagement.GlobalSchemaClientListByServiceOptions) *runtime.Pager[armapimanagement.GlobalSchemaClientListByServiceResponse]
}

func init() {
	registry.Register(ResourceTypeApiManagementGlobalSchema, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &ApiManagementGlobalSchema{
			api:      c.ApiManagementGlobalSchemaClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// ApiManagementGlobalSchema is the provisioner for service-wide schemas
// (Microsoft.ApiManagement/service/schemas).
type ApiManagementGlobalSchema struct {
	api      apiManagementGlobalSchemasAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

// apiManagementGlobalSchemaProps mirrors
// schema/pkl/apimanagement/apimanagementglobalschema.pkl.
type apiManagementGlobalSchemaProps struct {
	Name              string  `json:"name"`
	ResourceGroupName string  `json:"resourceGroupName"`
	ServiceName       string  `json:"serviceName"`
	SchemaType        string  `json:"schemaType"`
	Value             string  `json:"value"`
	Description       *string `json:"description"`
}

func apiManagementGlobalSchemaIDParts(resourceID string) (rgName, serviceName, schemaID string, err error) {
	rgName, names, err := armExactIDParts(resourceID, "service", "schemas")
	if err != nil {
		return "", "", "", err
	}
	return rgName, names[0], names[1], nil
}

// apiManagementGlobalSchemaBody places the caller's text in the field ARM
// expects: an XSD travels as a plain string in `value`, a JSON schema as a
// structured document in `document`.
func apiManagementGlobalSchemaBody(schemaType, value string, props *armapimanagement.GlobalSchemaContractProperties) error {
	if schemaType == string(armapimanagement.SchemaTypeJSON) {
		parsed, err := apimJSONToAny(value)
		if err != nil {
			return err
		}
		props.Document = parsed
		return nil
	}
	props.Value = value
	return nil
}

func (g *ApiManagementGlobalSchema) buildPropertiesFromResult(schema *armapimanagement.GlobalSchemaContract, rgName, serviceName string, supplied json.RawMessage) map[string]any {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	props["serviceName"] = serviceName

	if schema.ID != nil {
		props["id"] = *schema.ID
	}
	if schema.Name != nil {
		props["name"] = *schema.Name
	}

	if p := schema.Properties; p != nil {
		schemaType := ""
		if p.SchemaType != nil {
			schemaType = string(*p.SchemaType)
			props["schemaType"] = schemaType
		}
		if p.Description != nil {
			props["description"] = *p.Description
		}

		actual := apimAnyToJSON(p.Value)
		equivalent := apimXMLEquivalent
		if schemaType == string(armapimanagement.SchemaTypeJSON) {
			actual = apimAnyToJSON(p.Document)
			equivalent = apimJSONEquivalent
		}
		if actual != "" {
			var priorProps apiManagementGlobalSchemaProps
			if len(supplied) > 0 {
				_ = json.Unmarshal(supplied, &priorProps)
			}
			props["value"] = apimEchoSuppliedDocument(priorProps.Value, actual, equivalent)
		}
	}

	return props
}

func (g *ApiManagementGlobalSchema) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props apiManagementGlobalSchemaProps
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	if props.ServiceName == "" {
		return nil, fmt.Errorf("serviceName is required")
	}
	if props.SchemaType == "" {
		return nil, fmt.Errorf("schemaType is required")
	}
	if props.Value == "" {
		return nil, fmt.Errorf("value is required")
	}
	name := props.Name
	if name == "" {
		name = request.Label
	}
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}

	schemaProps := &armapimanagement.GlobalSchemaContractProperties{
		SchemaType:  to.Ptr(armapimanagement.SchemaType(props.SchemaType)),
		Description: props.Description,
	}
	if err := apiManagementGlobalSchemaBody(props.SchemaType, props.Value, schemaProps); err != nil {
		return nil, err
	}

	poller, err := g.api.BeginCreateOrUpdate(ctx, props.ResourceGroupName, props.ServiceName, name,
		armapimanagement.GlobalSchemaContract{Properties: schemaProps}, nil)
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

	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.ApiManagement/service/%s/schemas/%s",
		g.config.SubscriptionId, props.ResourceGroupName, props.ServiceName, name)

	if poller.Done() {
		result, err := poller.Result(ctx)
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
		nativeID, propsJSON, err := g.completeFromSchema(&result.GlobalSchemaContract, request.Properties)
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

func (g *ApiManagementGlobalSchema) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, serviceName, schemaID, err := apiManagementGlobalSchemaIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := g.api.Get(ctx, rgName, serviceName, schemaID, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(g.buildPropertiesFromResult(&result.GlobalSchemaContract, rgName, serviceName, request.PriorProperties))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeApiManagementGlobalSchema,
		Properties:   string(propsJSON),
	}, nil
}

// Update re-PUTs through BeginCreateOrUpdate: a global schema has no PATCH
// verb.
func (g *ApiManagementGlobalSchema) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, serviceName, schemaID, err := apiManagementGlobalSchemaIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props apiManagementGlobalSchemaProps
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.SchemaType == "" {
		return nil, fmt.Errorf("schemaType is required")
	}
	if props.Value == "" {
		return nil, fmt.Errorf("value is required")
	}

	schemaProps := &armapimanagement.GlobalSchemaContractProperties{
		SchemaType:  to.Ptr(armapimanagement.SchemaType(props.SchemaType)),
		Description: props.Description,
	}
	if err := apiManagementGlobalSchemaBody(props.SchemaType, props.Value, schemaProps); err != nil {
		return nil, err
	}

	poller, err := g.api.BeginCreateOrUpdate(ctx, rgName, serviceName, schemaID,
		armapimanagement.GlobalSchemaContract{Properties: schemaProps}, nil)
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

	if poller.Done() {
		result, err := poller.Result(ctx)
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
		propsJSON, err := json.Marshal(g.buildPropertiesFromResult(&result.GlobalSchemaContract,
			rgName, serviceName, request.DesiredProperties))
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

func (g *ApiManagementGlobalSchema) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, serviceName, schemaID, err := apiManagementGlobalSchemaIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	if _, err := g.api.Delete(ctx, rgName, serviceName, schemaID, apimIfMatchAny, nil); err != nil && !isDeleteSuccessError(err) {
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

// Status handles create and update, both of which go through the same poller.
// The delete is synchronous and never reaches here.
func (g *ApiManagementGlobalSchema) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	reqID, err := decodeLROStatus(request.RequestID)
	if err != nil {
		return nil, err
	}

	resume := func(token string) (*runtime.Poller[armapimanagement.GlobalSchemaClientCreateOrUpdateResponse], error) {
		return resumePoller[armapimanagement.GlobalSchemaClientCreateOrUpdateResponse](g.pipeline, token)
	}
	complete := func(_ context.Context, result armapimanagement.GlobalSchemaClientCreateOrUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
		return g.completeFromSchema(&result.GlobalSchemaContract, nil)
	}

	switch reqID.OperationType {
	case lroOpCreate:
		return statusLRO(ctx, request, &reqID, resource.OperationCreate, resume, complete)
	case lroOpUpdate:
		return statusLRO(ctx, request, &reqID, resource.OperationUpdate, resume, complete)
	default:
		return nil, fmt.Errorf("unknown operation type: %s", reqID.OperationType)
	}
}

func (g *ApiManagementGlobalSchema) completeFromSchema(schema *armapimanagement.GlobalSchemaContract, supplied json.RawMessage) (string, json.RawMessage, error) {
	nativeID, rgName, serviceName := "", "", ""
	if schema.ID != nil {
		nativeID = *schema.ID
		if rg, svc, _, err := apiManagementGlobalSchemaIDParts(*schema.ID); err == nil {
			rgName, serviceName = rg, svc
		}
	}
	propsJSON, err := json.Marshal(g.buildPropertiesFromResult(schema, rgName, serviceName, supplied))
	if err != nil {
		return "", nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return nativeID, propsJSON, nil
}

// List needs both the resource group and the service name: ARM has no
// subscription-wide listing of global schemas.
func (g *ApiManagementGlobalSchema) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	serviceName := request.AdditionalProperties["serviceName"]
	if rgName == "" || serviceName == "" {
		return &resource.ListResult{}, nil
	}

	var nativeIDs []string
	pager := g.api.NewListByServicePager(rgName, serviceName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list api management global schemas: %w", err)
		}
		for _, schema := range page.Value {
			if schema.ID != nil {
				nativeIDs = append(nativeIDs, *schema.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
