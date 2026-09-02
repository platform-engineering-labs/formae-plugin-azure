// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/apimanagement/armapimanagement"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeApiManagementApiSchema = "AZURE::ApiManagement::ApiSchema"

// The two JSON content types ARM stores in a structured field rather than as
// text. Which field depends on the flavour: an OpenAPI components object goes
// into components, a Swagger 2.0 definitions object into definitions.
const (
	apimSchemaContentTypeOpenAPIComponents = "application/vnd.oai.openapi.components+json"
	apimSchemaContentTypeSwaggerDefs       = "application/vnd.ms-azure-apim.swagger.definitions+json"
)

// apiManagementAPISchemasAPI is the armapimanagement surface used here. The
// create is an LRO (ARM validates the document), while delete is synchronous
// and takes ifMatch positionally. There is no PATCH: an update is another
// CreateOrUpdate.
type apiManagementAPISchemasAPI interface {
	BeginCreateOrUpdate(ctx context.Context, resourceGroupName string, serviceName string, apiID string, schemaID string, parameters armapimanagement.SchemaContract, options *armapimanagement.APISchemaClientBeginCreateOrUpdateOptions) (*runtime.Poller[armapimanagement.APISchemaClientCreateOrUpdateResponse], error)
	Get(ctx context.Context, resourceGroupName string, serviceName string, apiID string, schemaID string, options *armapimanagement.APISchemaClientGetOptions) (armapimanagement.APISchemaClientGetResponse, error)
	Delete(ctx context.Context, resourceGroupName string, serviceName string, apiID string, schemaID string, ifMatch string, options *armapimanagement.APISchemaClientDeleteOptions) (armapimanagement.APISchemaClientDeleteResponse, error)
	NewListByAPIPager(resourceGroupName string, serviceName string, apiID string, options *armapimanagement.APISchemaClientListByAPIOptions) *runtime.Pager[armapimanagement.APISchemaClientListByAPIResponse]
}

func init() {
	registry.Register(ResourceTypeApiManagementApiSchema, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &ApiManagementApiSchema{
			api:      c.ApiManagementAPISchemaClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// ApiManagementApiSchema is the provisioner for per-API schemas
// (Microsoft.ApiManagement/service/apis/schemas).
type ApiManagementApiSchema struct {
	api      apiManagementAPISchemasAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

// apiManagementApiSchemaProps mirrors
// schema/pkl/apimanagement/apimanagementapischema.pkl.
type apiManagementApiSchemaProps struct {
	Name              string `json:"name"`
	ResourceGroupName string `json:"resourceGroupName"`
	ServiceName       string `json:"serviceName"`
	APIName           string `json:"apiName"`
	ContentType       string `json:"contentType"`
	Value             string `json:"value"`
}

func apiManagementApiSchemaIDParts(resourceID string) (rgName, serviceName, apiID, schemaID string, err error) {
	rgName, names, err := armExactIDParts(resourceID, "service", "apis", "schemas")
	if err != nil {
		return "", "", "", "", err
	}
	return rgName, names[0], names[1], names[2], nil
}

// apiManagementApiSchemaDocument places the caller's text in the field ARM
// expects for the declared content type: a structured document for the two
// JSON flavours, plain text for the XSD.
func apiManagementApiSchemaDocument(contentType, value string) (*armapimanagement.SchemaDocumentProperties, error) {
	switch contentType {
	case apimSchemaContentTypeOpenAPIComponents:
		parsed, err := apimJSONToAny(value)
		if err != nil {
			return nil, err
		}
		return &armapimanagement.SchemaDocumentProperties{Components: parsed}, nil
	case apimSchemaContentTypeSwaggerDefs:
		parsed, err := apimJSONToAny(value)
		if err != nil {
			return nil, err
		}
		return &armapimanagement.SchemaDocumentProperties{Definitions: parsed}, nil
	default:
		return &armapimanagement.SchemaDocumentProperties{Value: to.Ptr(value)}, nil
	}
}

// apiManagementApiSchemaValue is the inverse: it renders whichever field ARM
// populated back into the single text property the schema declares.
func apiManagementApiSchemaValue(doc *armapimanagement.SchemaDocumentProperties) string {
	if doc == nil {
		return ""
	}
	if doc.Components != nil {
		return apimAnyToJSON(doc.Components)
	}
	if doc.Definitions != nil {
		return apimAnyToJSON(doc.Definitions)
	}
	if doc.Value != nil {
		return *doc.Value
	}
	return ""
}

func (s *ApiManagementApiSchema) buildPropertiesFromResult(schema *armapimanagement.SchemaContract, rgName, serviceName, apiID string, prior json.RawMessage) map[string]any {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	props["serviceName"] = serviceName
	props["apiName"] = apiID

	if schema.ID != nil {
		props["id"] = *schema.ID
	}
	if schema.Name != nil {
		props["name"] = *schema.Name
	}

	contentType := ""
	if p := schema.Properties; p != nil {
		if p.ContentType != nil {
			contentType = *p.ContentType
			props["contentType"] = contentType
		}
		if value := apiManagementApiSchemaValue(p.Document); value != "" {
			props["value"] = s.reportedValue(contentType, value, prior)
		}
	}

	return props
}

// reportedValue picks between the caller's own document and ARM's rendering of
// it. See apimanagementpolicybody.go: ARM re-serializes what it is given, so
// reporting its rendering shows drift on every sync.
func (s *ApiManagementApiSchema) reportedValue(contentType, actual string, prior json.RawMessage) string {
	var priorProps apiManagementApiSchemaProps
	if len(prior) > 0 {
		_ = json.Unmarshal(prior, &priorProps)
	}
	equivalent := apimXMLEquivalent
	if strings.HasSuffix(contentType, "+json") {
		equivalent = apimJSONEquivalent
	}
	return apimEchoSuppliedDocument(priorProps.Value, actual, equivalent)
}

func (s *ApiManagementApiSchema) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props apiManagementApiSchemaProps
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
	if props.ContentType == "" {
		return nil, fmt.Errorf("contentType is required")
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

	document, err := apiManagementApiSchemaDocument(props.ContentType, props.Value)
	if err != nil {
		return nil, err
	}
	params := armapimanagement.SchemaContract{
		Properties: &armapimanagement.SchemaContractProperties{
			ContentType: to.Ptr(props.ContentType),
			Document:    document,
		},
	}

	poller, err := s.api.BeginCreateOrUpdate(ctx, props.ResourceGroupName, props.ServiceName, props.APIName, name, params, nil)
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

	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.ApiManagement/service/%s/apis/%s/schemas/%s",
		s.config.SubscriptionId, props.ResourceGroupName, props.ServiceName, props.APIName, name)

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
		nativeID, propsJSON, err := s.completeFromSchema(&result.SchemaContract, request.Properties)
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

func (s *ApiManagementApiSchema) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, serviceName, apiID, schemaID, err := apiManagementApiSchemaIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := s.api.Get(ctx, rgName, serviceName, apiID, schemaID, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(s.buildPropertiesFromResult(&result.SchemaContract, rgName, serviceName, apiID, request.PriorProperties))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeApiManagementApiSchema,
		Properties:   string(propsJSON),
	}, nil
}

// Update re-PUTs through BeginCreateOrUpdate: a schema has no PATCH verb.
func (s *ApiManagementApiSchema) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, serviceName, apiID, schemaID, err := apiManagementApiSchemaIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props apiManagementApiSchemaProps
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ContentType == "" {
		return nil, fmt.Errorf("contentType is required")
	}
	if props.Value == "" {
		return nil, fmt.Errorf("value is required")
	}

	document, err := apiManagementApiSchemaDocument(props.ContentType, props.Value)
	if err != nil {
		return nil, err
	}
	params := armapimanagement.SchemaContract{
		Properties: &armapimanagement.SchemaContractProperties{
			ContentType: to.Ptr(props.ContentType),
			Document:    document,
		},
	}

	poller, err := s.api.BeginCreateOrUpdate(ctx, rgName, serviceName, apiID, schemaID, params, nil)
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
		propsJSON, err := json.Marshal(s.buildPropertiesFromResult(&result.SchemaContract,
			rgName, serviceName, apiID, request.DesiredProperties))
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

func (s *ApiManagementApiSchema) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, serviceName, apiID, schemaID, err := apiManagementApiSchemaIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	if _, err := s.api.Delete(ctx, rgName, serviceName, apiID, schemaID, apimIfMatchAny, nil); err != nil && !isDeleteSuccessError(err) {
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
func (s *ApiManagementApiSchema) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	reqID, err := decodeLROStatus(request.RequestID)
	if err != nil {
		return nil, err
	}

	resume := func(token string) (*runtime.Poller[armapimanagement.APISchemaClientCreateOrUpdateResponse], error) {
		return resumePoller[armapimanagement.APISchemaClientCreateOrUpdateResponse](s.pipeline, token)
	}
	complete := func(_ context.Context, result armapimanagement.APISchemaClientCreateOrUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
		return s.completeFromSchema(&result.SchemaContract, nil)
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

func (s *ApiManagementApiSchema) completeFromSchema(schema *armapimanagement.SchemaContract, supplied json.RawMessage) (string, json.RawMessage, error) {
	nativeID, rgName, serviceName, apiID := "", "", "", ""
	if schema.ID != nil {
		nativeID = *schema.ID
		if rg, svc, api, _, err := apiManagementApiSchemaIDParts(*schema.ID); err == nil {
			rgName, serviceName, apiID = rg, svc, api
		}
	}
	propsJSON, err := json.Marshal(s.buildPropertiesFromResult(schema, rgName, serviceName, apiID, supplied))
	if err != nil {
		return "", nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return nativeID, propsJSON, nil
}

// List requires the resource group, the service and the API: ARM has no
// service-wide listing of per-API schemas.
func (s *ApiManagementApiSchema) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	serviceName := request.AdditionalProperties["serviceName"]
	apiName := request.AdditionalProperties["apiName"]
	if rgName == "" || serviceName == "" || apiName == "" {
		return &resource.ListResult{}, nil
	}

	var nativeIDs []string
	pager := s.api.NewListByAPIPager(rgName, serviceName, apiName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list api management api schemas: %w", err)
		}
		for _, schema := range page.Value {
			if schema.ID != nil {
				nativeIDs = append(nativeIDs, *schema.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
