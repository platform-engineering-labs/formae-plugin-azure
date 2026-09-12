// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/datafactory/armdatafactory"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeDataFactoryTriggerBlobEvent = "AZURE::DataFactory::TriggerBlobEvent"

func init() {
	registry.Register(ResourceTypeDataFactoryTriggerBlobEvent, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &DataFactoryTriggerBlobEvent{
			api:    c.DataFactoryTriggersClient,
			config: cfg,
		}
	})
}

// DataFactoryTriggerBlobEvent is the provisioner for blob-event triggers
// (Microsoft.DataFactory/factories/triggers, type BlobEventsTrigger).
//
// It shares dataFactoryTriggersAPI and the pipeline/annotation/discriminator
// helpers with DataFactoryTriggerSchedule; those live in
// datafactorytriggerschedule.go.
//
// Creating one is a metadata write and provisions nothing: the Event Grid system
// topic and event subscription that actually deliver blob events are created by
// BeginSubscribeToEvents, which runs when the trigger is STARTED. This provisioner
// never starts a trigger, so a blob-event trigger it writes is inert — it costs
// nothing and it does not touch the storage account it names beyond validating that
// the ARM ID resolves.
type DataFactoryTriggerBlobEvent struct {
	api    dataFactoryTriggersAPI
	config *config.Config
}

// dataFactoryTriggerBlobEventProps mirrors
// schema/pkl/datafactory/datafactorytriggerblobevent.pkl.
type dataFactoryTriggerBlobEventProps struct {
	Name               string   `json:"name"`
	ResourceGroupName  string   `json:"resourceGroupName"`
	FactoryName        string   `json:"factoryName"`
	Description        *string  `json:"description"`
	PipelineNames      []string `json:"pipelineNames"`
	Scope              string   `json:"scope"`
	Events             []string `json:"events"`
	BlobPathBeginsWith *string  `json:"blobPathBeginsWith"`
	BlobPathEndsWith   *string  `json:"blobPathEndsWith"`
	IgnoreEmptyBlobs   *bool    `json:"ignoreEmptyBlobs"`
	Annotations        []string `json:"annotations"`
}

func (p *dataFactoryTriggerBlobEventProps) parse(payload json.RawMessage, fallbackName string) error {
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
	if p.Scope == "" {
		return fmt.Errorf("scope is required")
	}
	if len(p.Events) == 0 {
		return fmt.Errorf("events is required")
	}
	if p.IgnoreEmptyBlobs == nil {
		return fmt.Errorf("ignoreEmptyBlobs is required")
	}
	// ARM's own rule, checked here so the mistake fails before any ARM call
	// rather than as an opaque 400: a trigger that filters on neither end of the
	// blob path would fire for every blob in the account.
	beginsWith := p.BlobPathBeginsWith != nil && *p.BlobPathBeginsWith != ""
	endsWith := p.BlobPathEndsWith != nil && *p.BlobPathEndsWith != ""
	if !beginsWith && !endsWith {
		return fmt.Errorf("one of blobPathBeginsWith or blobPathEndsWith is required")
	}
	return nil
}

// params builds the request body shared by create and update.
func (p dataFactoryTriggerBlobEventProps) params() armdatafactory.TriggerResource {
	events := make([]*armdatafactory.BlobEventTypes, 0, len(p.Events))
	for _, event := range p.Events {
		if event == "" {
			continue
		}
		events = append(events, to.Ptr(armdatafactory.BlobEventTypes(event)))
	}

	typeProps := &armdatafactory.BlobEventsTriggerTypeProperties{
		Scope:            to.Ptr(p.Scope),
		Events:           events,
		IgnoreEmptyBlobs: p.IgnoreEmptyBlobs,
	}
	if p.BlobPathBeginsWith != nil && *p.BlobPathBeginsWith != "" {
		typeProps.BlobPathBeginsWith = p.BlobPathBeginsWith
	}
	if p.BlobPathEndsWith != nil && *p.BlobPathEndsWith != "" {
		typeProps.BlobPathEndsWith = p.BlobPathEndsWith
	}

	return armdatafactory.TriggerResource{
		Properties: &armdatafactory.BlobEventsTrigger{
			Type:           to.Ptr("BlobEventsTrigger"),
			Description:    p.Description,
			Annotations:    dataFactoryTriggerAnnotations(p.Annotations),
			Pipelines:      dataFactoryTriggerPipelines(p.PipelineNames),
			TypeProperties: typeProps,
		},
	}
}

func (t *DataFactoryTriggerBlobEvent) buildPropertiesFromResult(res *armdatafactory.TriggerResource, rgName, factoryName string) map[string]any {
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

	trigger, ok := res.Properties.(*armdatafactory.BlobEventsTrigger)
	if !ok || trigger == nil {
		return props
	}
	if trigger.Description != nil && *trigger.Description != "" {
		props["description"] = *trigger.Description
	}
	if annotations := dataFactoryAnnotationStrings(trigger.Annotations); len(annotations) > 0 {
		props["annotations"] = annotations
	}
	if names := dataFactoryTriggerPipelineNames(trigger.Pipelines); len(names) > 0 {
		props["pipelineNames"] = names
	}
	// runtimeState is deliberately not read back and is not modelled: whether a
	// trigger is Started or Stopped is changed by BeginStart / BeginStop, not by
	// the definition, so surfacing it would report drift the moment an operator
	// started the trigger by hand.
	if trigger.TypeProperties == nil {
		return props
	}

	typeProps := trigger.TypeProperties
	if typeProps.Scope != nil && *typeProps.Scope != "" {
		props["scope"] = *typeProps.Scope
	}
	if len(typeProps.Events) > 0 {
		events := make([]string, 0, len(typeProps.Events))
		for _, event := range typeProps.Events {
			if event == nil || *event == "" {
				continue
			}
			events = append(events, canonicalizeEnum(string(*event),
				"Microsoft.Storage.BlobCreated", "Microsoft.Storage.BlobDeleted"))
		}
		if len(events) > 0 {
			props["events"] = events
		}
	}
	if typeProps.BlobPathBeginsWith != nil && *typeProps.BlobPathBeginsWith != "" {
		props["blobPathBeginsWith"] = *typeProps.BlobPathBeginsWith
	}
	if typeProps.BlobPathEndsWith != nil && *typeProps.BlobPathEndsWith != "" {
		props["blobPathEndsWith"] = *typeProps.BlobPathEndsWith
	}
	if typeProps.IgnoreEmptyBlobs != nil {
		props["ignoreEmptyBlobs"] = *typeProps.IgnoreEmptyBlobs
	}
	return props
}

func (t *DataFactoryTriggerBlobEvent) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props dataFactoryTriggerBlobEventProps
	if err := props.parse(request.Properties, request.Label); err != nil {
		return nil, err
	}

	result, err := t.api.CreateOrUpdate(ctx, props.ResourceGroupName, props.FactoryName, props.Name, props.params(), nil)
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
	propsJSON, err := json.Marshal(t.buildPropertiesFromResult(&result.TriggerResource,
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

func (t *DataFactoryTriggerBlobEvent) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, factoryName, name, err := dataFactoryChildIDParts(request.NativeID, "triggers")
	if err != nil {
		return nil, err
	}

	result, err := t.api.Get(ctx, rgName, factoryName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(t.buildPropertiesFromResult(&result.TriggerResource, rgName, factoryName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeDataFactoryTriggerBlobEvent,
		Properties:   string(propsJSON),
	}, nil
}

// Update reissues CreateOrUpdate: this API has no PATCH verb for triggers. The
// service refuses the call outright while the trigger is Started, which arrives as
// a 400 and is surfaced with the provider's own reason.
func (t *DataFactoryTriggerBlobEvent) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, factoryName, name, err := dataFactoryChildIDParts(request.NativeID, "triggers")
	if err != nil {
		return nil, err
	}

	var props dataFactoryTriggerBlobEventProps
	if err := props.parse(request.DesiredProperties, name); err != nil {
		return nil, err
	}

	result, err := t.api.CreateOrUpdate(ctx, rgName, factoryName, name, props.params(), nil)
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

	propsJSON, err := json.Marshal(t.buildPropertiesFromResult(&result.TriggerResource, rgName, factoryName))
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

// Delete is refused while the trigger is Started; that arrives as a 400 and is
// surfaced as a failure with the provider's own reason.
func (t *DataFactoryTriggerBlobEvent) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, factoryName, name, err := dataFactoryChildIDParts(request.NativeID, "triggers")
	if err != nil {
		return nil, err
	}

	if _, err := t.api.Delete(ctx, rgName, factoryName, name, nil); err != nil && !isDeleteSuccessError(err) {
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

// Status echoes success: CreateOrUpdate, Get and Delete are all synchronous, and
// the BeginX verbs are never called.
func (t *DataFactoryTriggerBlobEvent) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

// List requires both the resource group and the factory name: ARM has no
// subscription-wide listing for triggers.
//
// A factory's pager returns every trigger kind at once, so the results are filtered
// by discriminator: handing a ScheduleTrigger's ID to this provisioner would read it
// with the wrong shape.
func (t *DataFactoryTriggerBlobEvent) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	factoryName := request.AdditionalProperties["factoryName"]
	if rgName == "" || factoryName == "" {
		return &resource.ListResult{}, nil
	}

	var nativeIDs []string
	pager := t.api.NewListByFactoryPager(rgName, factoryName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list data factory triggers: %w", err)
		}
		nativeIDs = append(nativeIDs, dataFactoryTriggerIDsOfType(page.Value, "BlobEventsTrigger")...)
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
