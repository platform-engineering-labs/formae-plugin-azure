// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/datafactory/armdatafactory"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeDataFactoryPipeline = "AZURE::DataFactory::Pipeline"

// dataFactoryPipelinesAPI is the armdatafactory surface used here. Every verb is
// synchronous: PipelinesClient has no BeginX at all, and CreateRun (which starts a
// pipeline) is not used — this provisioner manages the definition, never a run.
type dataFactoryPipelinesAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName string, factoryName string, pipelineName string, pipeline armdatafactory.PipelineResource, options *armdatafactory.PipelinesClientCreateOrUpdateOptions) (armdatafactory.PipelinesClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName string, factoryName string, pipelineName string, options *armdatafactory.PipelinesClientGetOptions) (armdatafactory.PipelinesClientGetResponse, error)
	Delete(ctx context.Context, resourceGroupName string, factoryName string, pipelineName string, options *armdatafactory.PipelinesClientDeleteOptions) (armdatafactory.PipelinesClientDeleteResponse, error)
	NewListByFactoryPager(resourceGroupName string, factoryName string, options *armdatafactory.PipelinesClientListByFactoryOptions) *runtime.Pager[armdatafactory.PipelinesClientListByFactoryResponse]
}

func init() {
	registry.Register(ResourceTypeDataFactoryPipeline, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &DataFactoryPipeline{
			api:    c.DataFactoryPipelinesClient,
			config: cfg,
		}
	})
}

// DataFactoryPipeline is the provisioner for Data Factory pipelines
// (Microsoft.DataFactory/factories/pipelines).
//
// It manages the pipeline definition only. Nothing runs until a trigger fires or
// somebody calls CreateRun, so a pipeline this provider writes costs nothing.
type DataFactoryPipeline struct {
	api    dataFactoryPipelinesAPI
	config *config.Config
}

// dataFactoryPipelineProps mirrors schema/pkl/datafactory/datafactorypipeline.pkl.
type dataFactoryPipelineProps struct {
	Name              string   `json:"name"`
	ResourceGroupName string   `json:"resourceGroupName"`
	FactoryName       string   `json:"factoryName"`
	Description       *string  `json:"description"`
	Activities        string   `json:"activities"`
	Concurrency       *int32   `json:"concurrency"`
	FolderName        *string  `json:"folderName"`
	Annotations       []string `json:"annotations"`
}

func (p *dataFactoryPipelineProps) parse(payload json.RawMessage, fallbackName string) error {
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
	return nil
}

// params builds the request body.
//
// activities crosses the wire as a JSON string because the activity language is
// arbitrarily nested JSON no PKL class can describe. It is decoded here and handed
// to the SDK's own activity unmarshaller, so a malformed body fails before any ARM
// call rather than as an opaque 400.
func (p *DataFactoryPipeline) params(props dataFactoryPipelineProps) (armdatafactory.PipelineResource, error) {
	pipeline := &armdatafactory.Pipeline{
		Description: props.Description,
		Concurrency: props.Concurrency,
	}
	if props.FolderName != nil && *props.FolderName != "" {
		pipeline.Folder = &armdatafactory.PipelineFolder{Name: props.FolderName}
	}
	for _, annotation := range props.Annotations {
		pipeline.Annotations = append(pipeline.Annotations, annotation)
	}

	if props.Activities != "" {
		parsed, err := dataFactoryCanonicalJSON("activities", props.Activities)
		if err != nil {
			return armdatafactory.PipelineResource{}, err
		}
		list, ok := parsed.([]any)
		if !ok {
			return armdatafactory.PipelineResource{}, fmt.Errorf("activities must be a JSON array of activity objects")
		}
		encoded, err := json.Marshal(list)
		if err != nil {
			return armdatafactory.PipelineResource{}, fmt.Errorf("failed to re-encode activities: %w", err)
		}
		// The SDK models the activity union as an interface with a private
		// unmarshaller, reachable only by unmarshalling a whole Pipeline.
		var decoded armdatafactory.Pipeline
		if err := json.Unmarshal([]byte(`{"activities":`+string(encoded)+`}`), &decoded); err != nil {
			return armdatafactory.PipelineResource{}, fmt.Errorf("activities is not a valid activity list: %w", err)
		}
		pipeline.Activities = decoded.Activities
	}

	return armdatafactory.PipelineResource{Properties: pipeline}, nil
}

func (p *DataFactoryPipeline) buildPropertiesFromResult(res *armdatafactory.PipelineResource, rgName, factoryName string) map[string]any {
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

	pipeline := res.Properties
	if pipeline == nil {
		return props
	}
	if pipeline.Description != nil && *pipeline.Description != "" {
		props["description"] = *pipeline.Description
	}
	if pipeline.Concurrency != nil {
		props["concurrency"] = *pipeline.Concurrency
	}
	if pipeline.Folder != nil && pipeline.Folder.Name != nil && *pipeline.Folder.Name != "" {
		props["folderName"] = *pipeline.Folder.Name
	}
	if annotations := dataFactoryAnnotationStrings(pipeline.Annotations); len(annotations) > 0 {
		props["annotations"] = annotations
	}
	// activities is declared writeOnly in the schema and is deliberately NOT read
	// back: the service re-serialises the activity list through its own model and
	// fills in per-activity defaults, so the echo is not byte-stable against what
	// was authored and would report drift on a pipeline nobody touched.
	//
	// parameters, variables, policy and runDimensions are not modelled and are not
	// read back either: a pipeline authored in the Data Factory UI reads without
	// them.
	return props
}

// dataFactoryAnnotationStrings narrows ARM's []any annotation list to the strings
// the schema models. Non-string entries — annotations are typed as free-form JSON —
// are skipped rather than mangled.
func dataFactoryAnnotationStrings(annotations []any) []string {
	if len(annotations) == 0 {
		return nil
	}
	out := make([]string, 0, len(annotations))
	for _, annotation := range annotations {
		if s, ok := annotation.(string); ok && s != "" {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (p *DataFactoryPipeline) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props dataFactoryPipelineProps
	if err := props.parse(request.Properties, request.Label); err != nil {
		return nil, err
	}
	params, err := p.params(props)
	if err != nil {
		return nil, err
	}

	result, err := p.api.CreateOrUpdate(ctx, props.ResourceGroupName, props.FactoryName, props.Name, params, nil)
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
	propsJSON, err := json.Marshal(p.buildPropertiesFromResult(&result.PipelineResource, props.ResourceGroupName, props.FactoryName))
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

func (p *DataFactoryPipeline) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, factoryName, name, err := dataFactoryChildIDParts(request.NativeID, "pipelines")
	if err != nil {
		return nil, err
	}

	result, err := p.api.Get(ctx, rgName, factoryName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(p.buildPropertiesFromResult(&result.PipelineResource, rgName, factoryName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeDataFactoryPipeline,
		Properties:   string(propsJSON),
	}, nil
}

// Update reissues CreateOrUpdate: this API has no PATCH verb for pipelines.
func (p *DataFactoryPipeline) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, factoryName, name, err := dataFactoryChildIDParts(request.NativeID, "pipelines")
	if err != nil {
		return nil, err
	}

	var props dataFactoryPipelineProps
	if err := props.parse(request.DesiredProperties, name); err != nil {
		return nil, err
	}
	params, err := p.params(props)
	if err != nil {
		return nil, err
	}

	result, err := p.api.CreateOrUpdate(ctx, rgName, factoryName, name, params, nil)
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

	propsJSON, err := json.Marshal(p.buildPropertiesFromResult(&result.PipelineResource, rgName, factoryName))
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

func (p *DataFactoryPipeline) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, factoryName, name, err := dataFactoryChildIDParts(request.NativeID, "pipelines")
	if err != nil {
		return nil, err
	}

	if _, err := p.api.Delete(ctx, rgName, factoryName, name, nil); err != nil && !isDeleteSuccessError(err) {
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
func (p *DataFactoryPipeline) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

// List requires both the resource group and the factory name: ARM has no
// subscription-wide listing for pipelines.
func (p *DataFactoryPipeline) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	factoryName := request.AdditionalProperties["factoryName"]
	if rgName == "" || factoryName == "" {
		return &resource.ListResult{}, nil
	}

	var nativeIDs []string
	pager := p.api.NewListByFactoryPager(rgName, factoryName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list data factory pipelines: %w", err)
		}
		for _, pipeline := range page.Value {
			if pipeline != nil && pipeline.ID != nil {
				nativeIDs = append(nativeIDs, *pipeline.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
