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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/logic/armlogic"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeLogicIntegrationAccountSchema = "AZURE::Logic::IntegrationAccountSchema"

// logicIntegrationAccountSchemasAPI is the armlogic surface used here. Every
// verb is synchronous and there is no PATCH: an update is another
// CreateOrUpdate.
//
// ListContentCallbackURL is deliberately absent. It mints a short-lived SAS URL
// to the blob ARM copied the document into; that URL is a bearer credential and
// must not reach resource state.
type logicIntegrationAccountSchemasAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName string, integrationAccountName string, schemaName string, schema armlogic.IntegrationAccountSchema, options *armlogic.IntegrationAccountSchemasClientCreateOrUpdateOptions) (armlogic.IntegrationAccountSchemasClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName string, integrationAccountName string, schemaName string, options *armlogic.IntegrationAccountSchemasClientGetOptions) (armlogic.IntegrationAccountSchemasClientGetResponse, error)
	Delete(ctx context.Context, resourceGroupName string, integrationAccountName string, schemaName string, options *armlogic.IntegrationAccountSchemasClientDeleteOptions) (armlogic.IntegrationAccountSchemasClientDeleteResponse, error)
	NewListPager(resourceGroupName string, integrationAccountName string, options *armlogic.IntegrationAccountSchemasClientListOptions) *runtime.Pager[armlogic.IntegrationAccountSchemasClientListResponse]
}

func init() {
	registry.Register(ResourceTypeLogicIntegrationAccountSchema, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &LogicIntegrationAccountSchema{
			api:    c.LogicIntegrationAccountSchemasClient,
			config: cfg,
		}
	})
}

// LogicIntegrationAccountSchema is the provisioner for XSDs held in an
// integration account
// (Microsoft.Logic/integrationAccounts/schemas).
type LogicIntegrationAccountSchema struct {
	api    logicIntegrationAccountSchemasAPI
	config *config.Config
}

// logicIntegrationAccountSchemaProps mirrors
// schema/pkl/logic/logicintegrationaccountschema.pkl.
type logicIntegrationAccountSchemaProps struct {
	logicChildProps
	SchemaType string  `json:"schemaType"`
	Content    string  `json:"content"`
	FileName   *string `json:"fileName"`
}

func (p *logicIntegrationAccountSchemaProps) parse(payload json.RawMessage, fallbackName string) error {
	if err := json.Unmarshal(payload, p); err != nil {
		return fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if err := p.validate(fallbackName); err != nil {
		return err
	}
	if p.SchemaType == "" {
		return fmt.Errorf("schemaType is required")
	}
	if p.Content == "" {
		return fmt.Errorf("content is required")
	}
	return nil
}

// logicSchemaContentType is the media type ARM expects for a schema. Omitting it
// fails the create with
//
//	The 'contentType' property of schema 'conformance-order-schema' of type 'Xml'
//	must be set to 'application/xml'.
//
// SchemaType has only Xml and NotSpecified, and an integration-account schema is
// an XSD either way, so this does not vary with the type the way the sibling
// logicMapContentType does for Liquid. There is nothing for a caller to choose,
// so the schema deliberately exposes no field for it.
const logicSchemaContentType = "application/xml"

// params builds the request body shared by create and update.
func (s *LogicIntegrationAccountSchema) params(props logicIntegrationAccountSchemaProps) armlogic.IntegrationAccountSchema {
	return armlogic.IntegrationAccountSchema{
		Properties: &armlogic.IntegrationAccountSchemaProperties{
			SchemaType:  to.Ptr(armlogic.SchemaType(props.SchemaType)),
			ContentType: to.Ptr(logicSchemaContentType),
			Content:     to.Ptr(props.Content),
			FileName:    props.FileName,
		},
	}
}

func (s *LogicIntegrationAccountSchema) buildPropertiesFromResult(schema *armlogic.IntegrationAccountSchema, rgName, accountName string) map[string]any {
	props := logicChildBaseProps(rgName, accountName, schema.ID, schema.Name)

	if p := schema.Properties; p != nil {
		if p.SchemaType != nil {
			props["schemaType"] = canonicalizeEnum(string(*p.SchemaType), "Xml", "NotSpecified")
		}
		if p.FileName != nil && *p.FileName != "" {
			props["fileName"] = *p.FileName
		}
		// content is declared writeOnly in the schema and is NOT read back — not
		// because of formatting but because ARM never returns it. A GET answers
		// with a contentLink SAS URL to the blob ARM copied the document into, so
		// there is nothing to compare.
		//
		// contentLink is not read back either: the URL carries an embedded SAS
		// token and rotates on every read, so it is both a credential and a
		// guaranteed drift source.
		//
		// documentName and targetNamespace are not modelled: ARM derives both from
		// the XSD's root element and echoes its own values. metadata is arbitrary
		// JSON the schema cannot express, and the timestamps move on their own.
	}

	return props
}

func (s *LogicIntegrationAccountSchema) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props logicIntegrationAccountSchemaProps
	if err := props.parse(request.Properties, request.Label); err != nil {
		return nil, err
	}

	result, err := s.api.CreateOrUpdate(ctx, props.ResourceGroupName, props.IntegrationAccountName,
		props.Name, s.params(props), nil)
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
	propsJSON, err := json.Marshal(s.buildPropertiesFromResult(&result.IntegrationAccountSchema,
		props.ResourceGroupName, props.IntegrationAccountName))
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

func (s *LogicIntegrationAccountSchema) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, accountName, name, err := logicChildIDParts(request.NativeID, "schemas")
	if err != nil {
		return nil, err
	}

	result, err := s.api.Get(ctx, rgName, accountName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(s.buildPropertiesFromResult(&result.IntegrationAccountSchema, rgName, accountName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeLogicIntegrationAccountSchema,
		Properties:   string(propsJSON),
	}, nil
}

// Update reissues CreateOrUpdate: this API has no PATCH verb for schemas.
func (s *LogicIntegrationAccountSchema) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, accountName, name, err := logicChildIDParts(request.NativeID, "schemas")
	if err != nil {
		return nil, err
	}

	var props logicIntegrationAccountSchemaProps
	if err := props.parse(request.DesiredProperties, name); err != nil {
		return nil, err
	}

	result, err := s.api.CreateOrUpdate(ctx, rgName, accountName, name, s.params(props), nil)
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

	propsJSON, err := json.Marshal(s.buildPropertiesFromResult(&result.IntegrationAccountSchema, rgName, accountName))
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

func (s *LogicIntegrationAccountSchema) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, accountName, name, err := logicChildIDParts(request.NativeID, "schemas")
	if err != nil {
		return nil, err
	}

	if _, err := s.api.Delete(ctx, rgName, accountName, name, nil); err != nil && !isDeleteSuccessError(err) {
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

// Status echoes success: every verb this provisioner uses is synchronous.
func (s *LogicIntegrationAccountSchema) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

// List needs both the resource group and the integration account: ARM has no
// subscription-wide listing of integration account schemas.
func (s *LogicIntegrationAccountSchema) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	accountName := request.AdditionalProperties["integrationAccountName"]
	if rgName == "" || accountName == "" {
		return &resource.ListResult{}, nil
	}

	var nativeIDs []string
	pager := s.api.NewListPager(rgName, accountName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list logic integration account schemas: %w", err)
		}
		for _, schema := range page.Value {
			if schema != nil && schema.ID != nil {
				nativeIDs = append(nativeIDs, *schema.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
