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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/datafactory/armdatafactory"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

// This file carries everything the five AZURE::DataFactory::LinkedService* types
// share. All five POST the same LinkedServiceResource envelope to the same four
// verbs and differ only in the discriminated Properties block, so the envelope, the
// read-back mapping and the CRUD live here once and each type file contributes only
// its discriminator. Precedent: cosmoschild.go, servicebusprops.go, eventgridprops.go.

// dataFactoryLinkedServicesAPI is the armdatafactory surface all five types use.
// Every verb is synchronous — LinkedServicesClient has no BeginX at all — so no
// poller is ever created and Status never has real work to do.
type dataFactoryLinkedServicesAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName string, factoryName string, linkedServiceName string, linkedService armdatafactory.LinkedServiceResource, options *armdatafactory.LinkedServicesClientCreateOrUpdateOptions) (armdatafactory.LinkedServicesClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName string, factoryName string, linkedServiceName string, options *armdatafactory.LinkedServicesClientGetOptions) (armdatafactory.LinkedServicesClientGetResponse, error)
	Delete(ctx context.Context, resourceGroupName string, factoryName string, linkedServiceName string, options *armdatafactory.LinkedServicesClientDeleteOptions) (armdatafactory.LinkedServicesClientDeleteResponse, error)
	NewListByFactoryPager(resourceGroupName string, factoryName string, options *armdatafactory.LinkedServicesClientListByFactoryOptions) *runtime.Pager[armdatafactory.LinkedServicesClientListByFactoryResponse]
}

// dataFactoryLinkedServiceCommon is the part of every linked-service schema that
// does not depend on the connector.
type dataFactoryLinkedServiceCommon struct {
	Name                             string   `json:"name"`
	ResourceGroupName                string   `json:"resourceGroupName"`
	FactoryName                      string   `json:"factoryName"`
	Description                      *string  `json:"description"`
	ConnectViaIntegrationRuntimeName *string  `json:"connectViaIntegrationRuntimeName"`
	Annotations                      []string `json:"annotations"`
}

func (c *dataFactoryLinkedServiceCommon) parse(payload json.RawMessage, fallbackName string) error {
	if err := json.Unmarshal(payload, c); err != nil {
		return fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if c.ResourceGroupName == "" {
		return fmt.Errorf("resourceGroupName is required")
	}
	if c.FactoryName == "" {
		return fmt.Errorf("factoryName is required")
	}
	if c.Name == "" {
		c.Name = fallbackName
	}
	if c.Name == "" {
		return fmt.Errorf("name is required")
	}
	return nil
}

// connectVia builds the integration-runtime reference. Returning nil leaves the
// block out so the service routes through the factory's default AutoResolve
// runtime, which is what an undeclared runtime must mean.
func (c *dataFactoryLinkedServiceCommon) connectVia() *armdatafactory.IntegrationRuntimeReference {
	if c.ConnectViaIntegrationRuntimeName == nil || *c.ConnectViaIntegrationRuntimeName == "" {
		return nil
	}
	return &armdatafactory.IntegrationRuntimeReference{
		Type:          to.Ptr(armdatafactory.IntegrationRuntimeReferenceTypeIntegrationRuntimeReference),
		ReferenceName: c.ConnectViaIntegrationRuntimeName,
	}
}

// annotationList widens the schema's Listing<String> to the free-form JSON list
// ARM models annotations as.
func (c *dataFactoryLinkedServiceCommon) annotationList() []any {
	if len(c.Annotations) == 0 {
		return nil
	}
	out := make([]any, 0, len(c.Annotations))
	for _, annotation := range c.Annotations {
		out = append(out, annotation)
	}
	return out
}

// dataFactorySecureString wraps a credential in the SecureString envelope, so the
// service stores it encrypted and hands back only a mask.
//
// Every field that takes one of these is declared writeOnly in the schema: the mask
// is all a read can ever see, so comparing the value would report drift forever.
// Returning nil for an empty string keeps the field out of the request rather than
// writing an empty credential over a good one.
func dataFactorySecureString(value *string) *armdatafactory.SecureString {
	if value == nil || *value == "" {
		return nil
	}
	return &armdatafactory.SecureString{
		Type:  to.Ptr("SecureString"),
		Value: value,
	}
}

// dataFactoryExpressionString narrows one of ARM's `interface{}`-typed connector
// fields back to a plain string.
//
// Data Factory types most connector properties as "string, or Expression with
// resultType string": a literal comes back as a JSON string, while a factory
// expression comes back as an object. Only the literal form is expressible in the
// schema, so an object is reported as absent rather than rendered as Go's map
// formatting, which no PKL union could match.
func dataFactoryExpressionString(value any) (string, bool) {
	s, ok := value.(string)
	if !ok || s == "" {
		return "", false
	}
	return s, true
}

// linkedServiceKind is what a concrete linked-service type contributes: its Formae
// resource type, and the two halves of the discriminated Properties block.
type linkedServiceKind struct {
	// resourceType is the AZURE::DataFactory::LinkedService* name.
	resourceType string

	// armType is the ARM discriminator, e.g. "AzureBlobStorage". Used only in
	// List, to keep a factory's other linked services out of this type's results.
	armType string

	// build turns parsed properties into the concrete SDK model, base fields and
	// all. It is given the already-validated common block plus the raw payload so
	// it can pick out its own connector fields.
	build func(common *dataFactoryLinkedServiceCommon, payload json.RawMessage) (armdatafactory.LinkedServiceClassification, error)

	// readTypeProperties adds the connector-specific properties of an ARM response
	// to the property set. Secrets are never added: they come back masked.
	readTypeProperties func(properties armdatafactory.LinkedServiceClassification, props map[string]any)
}

// DataFactoryLinkedService is the provisioner shared by all five linked-service
// types (Microsoft.DataFactory/factories/linkedServices). The kind field decides
// which connector it speaks for.
//
// Creating a linked service is a metadata write: it costs nothing, and the service
// does not test the connection, so an unreachable endpoint still creates cleanly
// and only fails when an activity actually uses it.
type DataFactoryLinkedService struct {
	api    dataFactoryLinkedServicesAPI
	kind   *linkedServiceKind
	config *config.Config
}

func (l *DataFactoryLinkedService) buildPropertiesFromResult(res *armdatafactory.LinkedServiceResource, rgName, factoryName string) map[string]any {
	props := map[string]any{
		"resourceGroupName": rgName,
		"factoryName":       factoryName,
	}
	if res.ID != nil {
		props["id"] = *res.ID
	}
	if res.Name != nil {
		props["name"] = *res.Name
	}

	if res.Properties == nil {
		return props
	}
	if base := res.Properties.GetLinkedService(); base != nil {
		if base.Description != nil && *base.Description != "" {
			props["description"] = *base.Description
		}
		if base.ConnectVia != nil && base.ConnectVia.ReferenceName != nil && *base.ConnectVia.ReferenceName != "" {
			props["connectViaIntegrationRuntimeName"] = *base.ConnectVia.ReferenceName
		}
		if annotations := dataFactoryAnnotationStrings(base.Annotations); len(annotations) > 0 {
			props["annotations"] = annotations
		}
		// parameters is not modelled and is not read back: a linked service
		// authored in the Data Factory UI reads without it.
	}
	l.kind.readTypeProperties(res.Properties, props)
	return props
}

func (l *DataFactoryLinkedService) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var common dataFactoryLinkedServiceCommon
	if err := common.parse(request.Properties, request.Label); err != nil {
		return nil, err
	}
	properties, err := l.kind.build(&common, request.Properties)
	if err != nil {
		return nil, err
	}

	result, err := l.api.CreateOrUpdate(ctx, common.ResourceGroupName, common.FactoryName, common.Name,
		armdatafactory.LinkedServiceResource{Properties: properties}, nil)
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
	propsJSON, err := json.Marshal(l.buildPropertiesFromResult(&result.LinkedServiceResource,
		common.ResourceGroupName, common.FactoryName))
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

func (l *DataFactoryLinkedService) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, factoryName, name, err := dataFactoryChildIDParts(request.NativeID, "linkedservices")
	if err != nil {
		return nil, err
	}

	result, err := l.api.Get(ctx, rgName, factoryName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(l.buildPropertiesFromResult(&result.LinkedServiceResource, rgName, factoryName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: l.kind.resourceType,
		Properties:   string(propsJSON),
	}, nil
}

// Update reissues CreateOrUpdate: this API has no PATCH verb for linked services.
func (l *DataFactoryLinkedService) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, factoryName, name, err := dataFactoryChildIDParts(request.NativeID, "linkedservices")
	if err != nil {
		return nil, err
	}

	var common dataFactoryLinkedServiceCommon
	if err := common.parse(request.DesiredProperties, name); err != nil {
		return nil, err
	}
	properties, err := l.kind.build(&common, request.DesiredProperties)
	if err != nil {
		return nil, err
	}

	result, err := l.api.CreateOrUpdate(ctx, rgName, factoryName, name,
		armdatafactory.LinkedServiceResource{Properties: properties}, nil)
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

	propsJSON, err := json.Marshal(l.buildPropertiesFromResult(&result.LinkedServiceResource, rgName, factoryName))
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

// Delete is refused by the service while a dataset or activity still references the
// linked service; that arrives as a 400 and is surfaced as a failure with the
// provider's own reason.
func (l *DataFactoryLinkedService) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, factoryName, name, err := dataFactoryChildIDParts(request.NativeID, "linkedservices")
	if err != nil {
		return nil, err
	}

	if _, err := l.api.Delete(ctx, rgName, factoryName, name, nil); err != nil && !isDeleteSuccessError(err) {
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

// Status echoes success: every LinkedServicesClient verb is synchronous.
func (l *DataFactoryLinkedService) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

// List requires both the resource group and the factory name: ARM has no
// subscription-wide listing for linked services.
//
// A factory's pager returns every connector at once, so the results are filtered by
// discriminator: handing an AzureKeyVault linked service's ID to the blob-storage
// provisioner would read it with the wrong shape.
func (l *DataFactoryLinkedService) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	factoryName := request.AdditionalProperties["factoryName"]
	if rgName == "" || factoryName == "" {
		return &resource.ListResult{}, nil
	}

	var nativeIDs []string
	pager := l.api.NewListByFactoryPager(rgName, factoryName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list data factory linked services: %w", err)
		}
		for _, ls := range page.Value {
			if ls == nil || ls.ID == nil || ls.Properties == nil {
				continue
			}
			base := ls.Properties.GetLinkedService()
			if base == nil || base.Type == nil || *base.Type != l.kind.armType {
				continue
			}
			nativeIDs = append(nativeIDs, *ls.ID)
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
