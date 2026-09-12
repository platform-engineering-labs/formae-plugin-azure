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

const ResourceTypeLogicIntegrationAccountMap = "AZURE::Logic::IntegrationAccountMap"

// logicIntegrationAccountMapsAPI is the armlogic surface used here. Every verb
// is synchronous and there is no PATCH: an update is another CreateOrUpdate.
//
// ListContentCallbackURL is deliberately absent, for the same reason as on the
// schema client: it mints a SAS URL that is a bearer credential.
type logicIntegrationAccountMapsAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName string, integrationAccountName string, mapName string, mapParam armlogic.IntegrationAccountMap, options *armlogic.IntegrationAccountMapsClientCreateOrUpdateOptions) (armlogic.IntegrationAccountMapsClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName string, integrationAccountName string, mapName string, options *armlogic.IntegrationAccountMapsClientGetOptions) (armlogic.IntegrationAccountMapsClientGetResponse, error)
	Delete(ctx context.Context, resourceGroupName string, integrationAccountName string, mapName string, options *armlogic.IntegrationAccountMapsClientDeleteOptions) (armlogic.IntegrationAccountMapsClientDeleteResponse, error)
	NewListPager(resourceGroupName string, integrationAccountName string, options *armlogic.IntegrationAccountMapsClientListOptions) *runtime.Pager[armlogic.IntegrationAccountMapsClientListResponse]
}

func init() {
	registry.Register(ResourceTypeLogicIntegrationAccountMap, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &LogicIntegrationAccountMap{
			api:    c.LogicIntegrationAccountMapsClient,
			config: cfg,
		}
	})
}

// LogicIntegrationAccountMap is the provisioner for transforms held in an
// integration account — XSLT stylesheets and Liquid templates
// (Microsoft.Logic/integrationAccounts/maps).
type LogicIntegrationAccountMap struct {
	api    logicIntegrationAccountMapsAPI
	config *config.Config
}

// logicIntegrationAccountMapProps mirrors
// schema/pkl/logic/logicintegrationaccountmap.pkl.
type logicIntegrationAccountMapProps struct {
	logicChildProps
	MapType             string  `json:"mapType"`
	Content             string  `json:"content"`
	ParametersSchemaRef *string `json:"parametersSchemaRef"`
}

func (p *logicIntegrationAccountMapProps) parse(payload json.RawMessage, fallbackName string) error {
	if err := json.Unmarshal(payload, p); err != nil {
		return fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if err := p.validate(fallbackName); err != nil {
		return err
	}
	if p.MapType == "" {
		return fmt.Errorf("mapType is required")
	}
	if p.Content == "" {
		return fmt.Errorf("content is required")
	}
	return nil
}

// params builds the request body shared by create and update.
//
// ARM will not infer a content type for a map the way it does for a schema, and
// it rejects a map whose contentType is absent, so the media type is derived
// from mapType here rather than being a property the caller has to repeat.
func (m *LogicIntegrationAccountMap) params(props logicIntegrationAccountMapProps) armlogic.IntegrationAccountMap {
	mapProps := &armlogic.IntegrationAccountMapProperties{
		MapType:     to.Ptr(armlogic.MapType(props.MapType)),
		Content:     to.Ptr(props.Content),
		ContentType: to.Ptr(logicMapContentType(props.MapType)),
	}
	if props.ParametersSchemaRef != nil && *props.ParametersSchemaRef != "" {
		mapProps.ParametersSchema = &armlogic.IntegrationAccountMapPropertiesParametersSchema{
			Ref: props.ParametersSchemaRef,
		}
	}
	return armlogic.IntegrationAccountMap{Properties: mapProps}
}

// logicMapContentType is the media type ARM expects for each transform language.
// A Liquid template is plain text; every XSLT flavour is XML.
func logicMapContentType(mapType string) string {
	if mapType == string(armlogic.MapTypeLiquid) {
		return "text/plain"
	}
	return "application/xml"
}

func (m *LogicIntegrationAccountMap) buildPropertiesFromResult(mapResult *armlogic.IntegrationAccountMap, rgName, accountName string) map[string]any {
	props := logicChildBaseProps(rgName, accountName, mapResult.ID, mapResult.Name)

	if p := mapResult.Properties; p != nil {
		if p.MapType != nil {
			props["mapType"] = canonicalizeEnum(string(*p.MapType),
				"Xslt", "Xslt20", "Xslt30", "Liquid", "NotSpecified")
		}
		if p.ParametersSchema != nil && p.ParametersSchema.Ref != nil && *p.ParametersSchema.Ref != "" {
			props["parametersSchemaRef"] = *p.ParametersSchema.Ref
		}
		// content is declared writeOnly and is NOT read back: ARM answers a GET
		// with a contentLink SAS URL to the blob it copied the transform into,
		// never with the transform itself.
		//
		// contentLink is not read back either — the URL carries an embedded SAS
		// token and rotates on every read. contentType is derived from mapType
		// rather than modelled, metadata is arbitrary JSON the schema cannot
		// express, and the timestamps move on their own.
	}

	return props
}

func (m *LogicIntegrationAccountMap) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props logicIntegrationAccountMapProps
	if err := props.parse(request.Properties, request.Label); err != nil {
		return nil, err
	}

	result, err := m.api.CreateOrUpdate(ctx, props.ResourceGroupName, props.IntegrationAccountName,
		props.Name, m.params(props), nil)
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
	propsJSON, err := json.Marshal(m.buildPropertiesFromResult(&result.IntegrationAccountMap,
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

func (m *LogicIntegrationAccountMap) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, accountName, name, err := logicChildIDParts(request.NativeID, "maps")
	if err != nil {
		return nil, err
	}

	result, err := m.api.Get(ctx, rgName, accountName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(m.buildPropertiesFromResult(&result.IntegrationAccountMap, rgName, accountName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeLogicIntegrationAccountMap,
		Properties:   string(propsJSON),
	}, nil
}

// Update reissues CreateOrUpdate: this API has no PATCH verb for maps.
func (m *LogicIntegrationAccountMap) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, accountName, name, err := logicChildIDParts(request.NativeID, "maps")
	if err != nil {
		return nil, err
	}

	var props logicIntegrationAccountMapProps
	if err := props.parse(request.DesiredProperties, name); err != nil {
		return nil, err
	}

	result, err := m.api.CreateOrUpdate(ctx, rgName, accountName, name, m.params(props), nil)
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

	propsJSON, err := json.Marshal(m.buildPropertiesFromResult(&result.IntegrationAccountMap, rgName, accountName))
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

func (m *LogicIntegrationAccountMap) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, accountName, name, err := logicChildIDParts(request.NativeID, "maps")
	if err != nil {
		return nil, err
	}

	if _, err := m.api.Delete(ctx, rgName, accountName, name, nil); err != nil && !isDeleteSuccessError(err) {
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
func (m *LogicIntegrationAccountMap) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

// List needs both the resource group and the integration account: ARM has no
// subscription-wide listing of integration account maps.
func (m *LogicIntegrationAccountMap) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	accountName := request.AdditionalProperties["integrationAccountName"]
	if rgName == "" || accountName == "" {
		return &resource.ListResult{}, nil
	}

	var nativeIDs []string
	pager := m.api.NewListPager(rgName, accountName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list logic integration account maps: %w", err)
		}
		for _, mapResult := range page.Value {
			if mapResult != nil && mapResult.ID != nil {
				nativeIDs = append(nativeIDs, *mapResult.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
