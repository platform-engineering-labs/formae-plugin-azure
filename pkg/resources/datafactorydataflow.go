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
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeDataFactoryDataFlow = "AZURE::DataFactory::DataFlow"

// dataFactoryDataFlowsAPI is the armdatafactory surface used here. Every verb is
// synchronous: DataFlowsClient has no BeginX at all. The debug session that
// actually spins up a Spark cluster lives on a different client
// (DataFlowDebugSessionClient) and is not used — this provisioner manages the
// definition, never a debug run, so a data flow it writes costs nothing.
type dataFactoryDataFlowsAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName string, factoryName string, dataFlowName string, dataFlow armdatafactory.DataFlowResource, options *armdatafactory.DataFlowsClientCreateOrUpdateOptions) (armdatafactory.DataFlowsClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName string, factoryName string, dataFlowName string, options *armdatafactory.DataFlowsClientGetOptions) (armdatafactory.DataFlowsClientGetResponse, error)
	Delete(ctx context.Context, resourceGroupName string, factoryName string, dataFlowName string, options *armdatafactory.DataFlowsClientDeleteOptions) (armdatafactory.DataFlowsClientDeleteResponse, error)
	NewListByFactoryPager(resourceGroupName string, factoryName string, options *armdatafactory.DataFlowsClientListByFactoryOptions) *runtime.Pager[armdatafactory.DataFlowsClientListByFactoryResponse]
}

func init() {
	registry.Register(ResourceTypeDataFactoryDataFlow, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &DataFactoryDataFlow{
			api:    c.DataFactoryDataFlowsClient,
			config: cfg,
		}
	})
}

// DataFactoryDataFlow is the provisioner for mapping data flows
// (Microsoft.DataFactory/factories/dataflows, type MappingDataFlow).
//
// Flowlets — ARM's other DataFlow member — are not modelled: they are reusable
// fragments of a mapping data flow and this provisioner claims only MappingDataFlow
// in List, so a flowlet in the same factory is left alone.
type DataFactoryDataFlow struct {
	api    dataFactoryDataFlowsAPI
	config *config.Config
}

// dataFactoryDataFlowEndpointProps mirrors the DataFlowEndpoint class in
// schema/pkl/datafactory/datafactorydataflow.pkl. ARM has two structurally
// identical models for it, DataFlowSource and DataFlowSink, so one schema class
// serves both.
type dataFactoryDataFlowEndpointProps struct {
	Name              string  `json:"name"`
	Description       *string `json:"description"`
	DatasetName       *string `json:"datasetName"`
	LinkedServiceName *string `json:"linkedServiceName"`
}

// dataFactoryDataFlowProps mirrors schema/pkl/datafactory/datafactorydataflow.pkl.
type dataFactoryDataFlowProps struct {
	Name              string                             `json:"name"`
	ResourceGroupName string                             `json:"resourceGroupName"`
	FactoryName       string                             `json:"factoryName"`
	Description       *string                            `json:"description"`
	Script            string                             `json:"script"`
	Sources           []dataFactoryDataFlowEndpointProps `json:"sources"`
	Sinks             []dataFactoryDataFlowEndpointProps `json:"sinks"`
	FolderName        *string                            `json:"folderName"`
	Annotations       []string                           `json:"annotations"`
}

func (p *dataFactoryDataFlowProps) parse(payload json.RawMessage, fallbackName string) error {
	if err := json.Unmarshal(payload, p); err != nil {
		return fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if p.ResourceGroupName == "" {
		return fmt.Errorf("resourceGroupName is required")
	}
	if p.FactoryName == "" {
		return fmt.Errorf("factoryName is required")
	}
	if p.Name == "" {
		p.Name = fallbackName
	}
	if p.Name == "" {
		return fmt.Errorf("name is required")
	}
	if p.Script == "" {
		return fmt.Errorf("script is required")
	}
	for _, endpoint := range append(append([]dataFactoryDataFlowEndpointProps{}, p.Sources...), p.Sinks...) {
		if endpoint.Name == "" {
			return fmt.Errorf("every source and sink needs a name")
		}
	}
	return nil
}

// datasetRef and linkedServiceRef build the two references an endpoint may carry.
// A source or sink names EITHER a dataset or, for an inline dataset, the linked
// service the format is read through; ARM accepts an endpoint with neither, which is
// how a data flow is staged before its datasets exist.
func (e dataFactoryDataFlowEndpointProps) datasetRef() *armdatafactory.DatasetReference {
	if e.DatasetName == nil || *e.DatasetName == "" {
		return nil
	}
	return &armdatafactory.DatasetReference{
		Type:          to.Ptr(armdatafactory.DatasetReferenceTypeDatasetReference),
		ReferenceName: e.DatasetName,
	}
}

func (e dataFactoryDataFlowEndpointProps) linkedServiceRef() *armdatafactory.LinkedServiceReference {
	if e.LinkedServiceName == nil || *e.LinkedServiceName == "" {
		return nil
	}
	return &armdatafactory.LinkedServiceReference{
		Type:          to.Ptr(armdatafactory.LinkedServiceReferenceTypeLinkedServiceReference),
		ReferenceName: e.LinkedServiceName,
	}
}

// params builds the request body shared by create and update.
func (p dataFactoryDataFlowProps) params() armdatafactory.DataFlowResource {
	typeProps := &armdatafactory.MappingDataFlowTypeProperties{
		Script: to.Ptr(p.Script),
	}
	for _, source := range p.Sources {
		typeProps.Sources = append(typeProps.Sources, &armdatafactory.DataFlowSource{
			Name:          to.Ptr(source.Name),
			Description:   source.Description,
			Dataset:       source.datasetRef(),
			LinkedService: source.linkedServiceRef(),
		})
	}
	for _, sink := range p.Sinks {
		typeProps.Sinks = append(typeProps.Sinks, &armdatafactory.DataFlowSink{
			Name:          to.Ptr(sink.Name),
			Description:   sink.Description,
			Dataset:       sink.datasetRef(),
			LinkedService: sink.linkedServiceRef(),
		})
	}

	flow := &armdatafactory.MappingDataFlow{
		Type:           to.Ptr("MappingDataFlow"),
		Description:    p.Description,
		TypeProperties: typeProps,
	}
	if p.FolderName != nil && *p.FolderName != "" {
		flow.Folder = &armdatafactory.DataFlowFolder{Name: p.FolderName}
	}
	for _, annotation := range p.Annotations {
		flow.Annotations = append(flow.Annotations, annotation)
	}

	return armdatafactory.DataFlowResource{Properties: flow}
}

func (d *DataFactoryDataFlow) buildPropertiesFromResult(res *armdatafactory.DataFlowResource, rgName, factoryName string) map[string]any {
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

	flow, ok := res.Properties.(*armdatafactory.MappingDataFlow)
	if !ok || flow == nil {
		return props
	}
	if flow.Description != nil && *flow.Description != "" {
		props["description"] = *flow.Description
	}
	if flow.Folder != nil && flow.Folder.Name != nil && *flow.Folder.Name != "" {
		props["folderName"] = *flow.Folder.Name
	}
	if annotations := dataFactoryAnnotationStrings(flow.Annotations); len(annotations) > 0 {
		props["annotations"] = annotations
	}
	if flow.TypeProperties == nil {
		return props
	}
	// script is declared writeOnly in the schema and is deliberately NOT read
	// back: the service reparses the DSL and stores it as scriptLines, so what
	// comes back is a re-serialisation rather than the text that was authored and
	// would report drift on a data flow nobody touched. Same reasoning as
	// AZURE::DataFactory::Pipeline's `activities`.
	//
	// transformations is not modelled either: it is the body of the script in
	// object form, so declaring both would be two sources of truth for one thing.
	if sources := dataFactoryDataFlowSourceProps(flow.TypeProperties.Sources); len(sources) > 0 {
		props["sources"] = sources
	}
	if sinks := dataFactoryDataFlowSinkProps(flow.TypeProperties.Sinks); len(sinks) > 0 {
		props["sinks"] = sinks
	}
	return props
}

func dataFactoryDataFlowSourceProps(sources []*armdatafactory.DataFlowSource) []map[string]any {
	out := make([]map[string]any, 0, len(sources))
	for _, source := range sources {
		if source == nil || source.Name == nil || *source.Name == "" {
			continue
		}
		out = append(out, dataFactoryDataFlowEndpointEntry(*source.Name, source.Description,
			source.Dataset, source.LinkedService))
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func dataFactoryDataFlowSinkProps(sinks []*armdatafactory.DataFlowSink) []map[string]any {
	out := make([]map[string]any, 0, len(sinks))
	for _, sink := range sinks {
		if sink == nil || sink.Name == nil || *sink.Name == "" {
			continue
		}
		out = append(out, dataFactoryDataFlowEndpointEntry(*sink.Name, sink.Description,
			sink.Dataset, sink.LinkedService))
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// dataFactoryDataFlowEndpointEntry reads one source or sink back into the shape the
// DataFlowEndpoint schema class declares.
//
// flowlet, schemaLinkedService and rejectedDataLinkedService are not modelled and
// are not read back: flowlets are a separate DataFlow member this type does not
// claim, and the two extra linked services are only meaningful for schema drift
// handling the schema has no way to express.
func dataFactoryDataFlowEndpointEntry(name string, description *string,
	dataset *armdatafactory.DatasetReference, linkedService *armdatafactory.LinkedServiceReference) map[string]any {
	entry := map[string]any{"name": name}
	if description != nil && *description != "" {
		entry["description"] = *description
	}
	if dataset != nil && dataset.ReferenceName != nil && *dataset.ReferenceName != "" {
		entry["datasetName"] = *dataset.ReferenceName
	}
	if linkedService != nil && linkedService.ReferenceName != nil && *linkedService.ReferenceName != "" {
		entry["linkedServiceName"] = *linkedService.ReferenceName
	}
	return entry
}

func (d *DataFactoryDataFlow) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props dataFactoryDataFlowProps
	if err := props.parse(request.Properties, request.Label); err != nil {
		return nil, err
	}

	result, err := d.api.CreateOrUpdate(ctx, props.ResourceGroupName, props.FactoryName, props.Name, props.params(), nil)
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
	propsJSON, err := json.Marshal(d.buildPropertiesFromResult(&result.DataFlowResource,
		props.ResourceGroupName, props.FactoryName))
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

func (d *DataFactoryDataFlow) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, factoryName, name, err := dataFactoryChildIDParts(request.NativeID, "dataflows")
	if err != nil {
		return nil, err
	}

	result, err := d.api.Get(ctx, rgName, factoryName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(d.buildPropertiesFromResult(&result.DataFlowResource, rgName, factoryName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeDataFactoryDataFlow,
		Properties:   string(propsJSON),
	}, nil
}

// Update reissues CreateOrUpdate: this API has no PATCH verb for data flows.
func (d *DataFactoryDataFlow) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, factoryName, name, err := dataFactoryChildIDParts(request.NativeID, "dataflows")
	if err != nil {
		return nil, err
	}

	var props dataFactoryDataFlowProps
	if err := props.parse(request.DesiredProperties, name); err != nil {
		return nil, err
	}

	result, err := d.api.CreateOrUpdate(ctx, rgName, factoryName, name, props.params(), nil)
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

	propsJSON, err := json.Marshal(d.buildPropertiesFromResult(&result.DataFlowResource, rgName, factoryName))
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

// Delete is refused by the service while a pipeline's Execute Data Flow activity
// still references it; that arrives as a 400 and is surfaced as a failure with the
// provider's own reason.
func (d *DataFactoryDataFlow) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, factoryName, name, err := dataFactoryChildIDParts(request.NativeID, "dataflows")
	if err != nil {
		return nil, err
	}

	if _, err := d.api.Delete(ctx, rgName, factoryName, name, nil); err != nil && !isDeleteSuccessError(err) {
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

// Status echoes success: every DataFlowsClient verb is synchronous.
func (d *DataFactoryDataFlow) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

// List requires both the resource group and the factory name: ARM has no
// subscription-wide listing for data flows.
//
// The pager returns flowlets alongside mapping data flows, so the results are
// filtered by discriminator: handing a flowlet's ID to this provisioner would read
// it with the wrong shape.
func (d *DataFactoryDataFlow) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	factoryName := request.AdditionalProperties["factoryName"]
	if rgName == "" || factoryName == "" {
		return &resource.ListResult{}, nil
	}

	var nativeIDs []string
	pager := d.api.NewListByFactoryPager(rgName, factoryName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list data factory data flows: %w", err)
		}
		for _, flow := range page.Value {
			if flow == nil || flow.ID == nil || flow.Properties == nil {
				continue
			}
			base := flow.Properties.GetDataFlow()
			if base == nil || base.Type == nil || *base.Type != "MappingDataFlow" {
				continue
			}
			nativeIDs = append(nativeIDs, *flow.ID)
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
