// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/datafactory/armdatafactory"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeDataFactoryTriggerSchedule = "AZURE::DataFactory::TriggerSchedule"

// dataFactoryTriggersAPI is the armdatafactory surface both trigger types use.
//
// CreateOrUpdate, Get and Delete are synchronous. TriggersClient does have
// BeginStart, BeginStop, BeginSubscribeToEvents and BeginUnsubscribeFromEvents, and
// none of them is called from here: whether a trigger is running is service-managed
// state that a trigger definition does not own. A trigger this provisioner writes
// is created Stopped and stays Stopped until somebody starts it, which is also why
// it fires nothing and costs nothing.
type dataFactoryTriggersAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName string, factoryName string, triggerName string, trigger armdatafactory.TriggerResource, options *armdatafactory.TriggersClientCreateOrUpdateOptions) (armdatafactory.TriggersClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName string, factoryName string, triggerName string, options *armdatafactory.TriggersClientGetOptions) (armdatafactory.TriggersClientGetResponse, error)
	Delete(ctx context.Context, resourceGroupName string, factoryName string, triggerName string, options *armdatafactory.TriggersClientDeleteOptions) (armdatafactory.TriggersClientDeleteResponse, error)
	NewListByFactoryPager(resourceGroupName string, factoryName string, options *armdatafactory.TriggersClientListByFactoryOptions) *runtime.Pager[armdatafactory.TriggersClientListByFactoryResponse]
}

func init() {
	registry.Register(ResourceTypeDataFactoryTriggerSchedule, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &DataFactoryTriggerSchedule{
			api:    c.DataFactoryTriggersClient,
			config: cfg,
		}
	})
}

// DataFactoryTriggerSchedule is the provisioner for schedule triggers
// (Microsoft.DataFactory/factories/triggers, type ScheduleTrigger).
type DataFactoryTriggerSchedule struct {
	api    dataFactoryTriggersAPI
	config *config.Config
}

// dataFactoryTriggerScheduleProps mirrors
// schema/pkl/datafactory/datafactorytriggerschedule.pkl.
//
// The recurrence block is flattened into this property set rather than modelled as
// a nested class: ARM's ScheduleTriggerRecurrence is one required object with five
// scalars plus a second nested object of four lists, and flattening it keeps the
// scalars and the lists in one place with no sub-resource render path to reason
// about.
type dataFactoryTriggerScheduleProps struct {
	Name              string   `json:"name"`
	ResourceGroupName string   `json:"resourceGroupName"`
	FactoryName       string   `json:"factoryName"`
	Description       *string  `json:"description"`
	PipelineNames     []string `json:"pipelineNames"`
	Frequency         string   `json:"frequency"`
	Interval          *int32   `json:"interval"`
	StartTime         string   `json:"startTime"`
	EndTime           *string  `json:"endTime"`
	TimeZone          string   `json:"timeZone"`
	ScheduleHours     []int32  `json:"scheduleHours"`
	ScheduleMinutes   []int32  `json:"scheduleMinutes"`
	ScheduleWeekDays  []string `json:"scheduleWeekDays"`
	ScheduleMonthDays []int32  `json:"scheduleMonthDays"`
	Annotations       []string `json:"annotations"`
}

func (p *dataFactoryTriggerScheduleProps) parse(payload json.RawMessage, fallbackName string) error {
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
	if p.Frequency == "" {
		return fmt.Errorf("frequency is required")
	}
	if p.Interval == nil {
		return fmt.Errorf("interval is required")
	}
	if p.StartTime == "" {
		return fmt.Errorf("startTime is required")
	}
	if p.TimeZone == "" {
		return fmt.Errorf("timeZone is required")
	}
	return nil
}

// dataFactoryTriggerTime parses one of the recurrence's UTC RFC-3339 instants.
//
// startTime and timeZone are required in the schema rather than optional precisely
// because the service fills them in when they are omitted — startTime becomes the
// moment the trigger was created, which moves on every apply, and timeZone becomes
// "UTC". Requiring them keeps the recurrence fully caller-owned and leaves nothing
// for a read to disagree with.
func dataFactoryTriggerTime(field, value string) (*time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return nil, fmt.Errorf("%s must be an RFC-3339 instant: %w", field, err)
	}
	utc := parsed.UTC()
	return &utc, nil
}

// dataFactoryTriggerTimeString renders an instant the way the schema demands it be
// written: RFC-3339, in UTC, whole seconds.
//
// This is the drift guard on this type. ARM normalises the recurrence timestamps —
// it converts to UTC and does not preserve the offset or the sub-second precision
// of what was sent — so the read side has to normalise identically or a trigger
// nobody touched reports drift on every reconcile.
func dataFactoryTriggerTimeString(value *time.Time) (string, bool) {
	if value == nil || value.IsZero() {
		return "", false
	}
	return value.UTC().Format(time.RFC3339), true
}

// dataFactoryTriggerPipelines builds the pipeline references a trigger starts.
//
// Per-pipeline parameters are not modelled: they are free-form JSON keyed by
// pipeline, which a flat Listing of names cannot carry. A trigger with no pipelines
// at all is accepted by ARM and is left expressible — it fires nothing, which is a
// legitimate way to stage a trigger before its pipeline exists.
func dataFactoryTriggerPipelines(names []string) []*armdatafactory.TriggerPipelineReference {
	if len(names) == 0 {
		return nil
	}
	out := make([]*armdatafactory.TriggerPipelineReference, 0, len(names))
	for _, name := range names {
		if name == "" {
			continue
		}
		out = append(out, &armdatafactory.TriggerPipelineReference{
			PipelineReference: &armdatafactory.PipelineReference{
				Type:          to.Ptr(armdatafactory.PipelineReferenceTypePipelineReference),
				ReferenceName: to.Ptr(name),
			},
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// dataFactoryTriggerPipelineNames reads the pipeline references back as bare names.
func dataFactoryTriggerPipelineNames(pipelines []*armdatafactory.TriggerPipelineReference) []string {
	if len(pipelines) == 0 {
		return nil
	}
	out := make([]string, 0, len(pipelines))
	for _, p := range pipelines {
		if p == nil || p.PipelineReference == nil || p.PipelineReference.ReferenceName == nil {
			continue
		}
		if *p.PipelineReference.ReferenceName == "" {
			continue
		}
		out = append(out, *p.PipelineReference.ReferenceName)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// dataFactoryTriggerAnnotations widens the schema's Listing<String> to the free-form
// JSON list ARM models trigger annotations as.
func dataFactoryTriggerAnnotations(annotations []string) []any {
	if len(annotations) == 0 {
		return nil
	}
	out := make([]any, 0, len(annotations))
	for _, annotation := range annotations {
		out = append(out, annotation)
	}
	return out
}

// recurrenceSchedule builds the optional inner schedule. Returning nil leaves the
// block out entirely, which is what "recur every interval, no finer filter" means.
func (p dataFactoryTriggerScheduleProps) recurrenceSchedule() *armdatafactory.RecurrenceSchedule {
	schedule := &armdatafactory.RecurrenceSchedule{}
	empty := true
	for _, hour := range p.ScheduleHours {
		schedule.Hours = append(schedule.Hours, to.Ptr(hour))
		empty = false
	}
	for _, minute := range p.ScheduleMinutes {
		schedule.Minutes = append(schedule.Minutes, to.Ptr(minute))
		empty = false
	}
	for _, day := range p.ScheduleMonthDays {
		schedule.MonthDays = append(schedule.MonthDays, to.Ptr(day))
		empty = false
	}
	for _, weekDay := range p.ScheduleWeekDays {
		schedule.WeekDays = append(schedule.WeekDays, to.Ptr(armdatafactory.DaysOfWeek(weekDay)))
		empty = false
	}
	if empty {
		return nil
	}
	return schedule
}

// params builds the request body shared by create and update.
func (p dataFactoryTriggerScheduleProps) params() (armdatafactory.TriggerResource, error) {
	startTime, err := dataFactoryTriggerTime("startTime", p.StartTime)
	if err != nil {
		return armdatafactory.TriggerResource{}, err
	}

	recurrence := &armdatafactory.ScheduleTriggerRecurrence{
		Frequency: to.Ptr(armdatafactory.RecurrenceFrequency(p.Frequency)),
		Interval:  p.Interval,
		StartTime: startTime,
		TimeZone:  to.Ptr(p.TimeZone),
		Schedule:  p.recurrenceSchedule(),
	}
	if p.EndTime != nil && *p.EndTime != "" {
		endTime, err := dataFactoryTriggerTime("endTime", *p.EndTime)
		if err != nil {
			return armdatafactory.TriggerResource{}, err
		}
		recurrence.EndTime = endTime
	}

	return armdatafactory.TriggerResource{
		Properties: &armdatafactory.ScheduleTrigger{
			Type:        to.Ptr("ScheduleTrigger"),
			Description: p.Description,
			Annotations: dataFactoryTriggerAnnotations(p.Annotations),
			Pipelines:   dataFactoryTriggerPipelines(p.PipelineNames),
			TypeProperties: &armdatafactory.ScheduleTriggerTypeProperties{
				Recurrence: recurrence,
			},
		},
	}, nil
}

func (t *DataFactoryTriggerSchedule) buildPropertiesFromResult(res *armdatafactory.TriggerResource, rgName, factoryName string) map[string]any {
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

	trigger, ok := res.Properties.(*armdatafactory.ScheduleTrigger)
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
	if trigger.TypeProperties == nil || trigger.TypeProperties.Recurrence == nil {
		return props
	}

	recurrence := trigger.TypeProperties.Recurrence
	if recurrence.Frequency != nil {
		props["frequency"] = canonicalizeEnum(string(*recurrence.Frequency),
			"Minute", "Hour", "Day", "Week", "Month", "Year", "NotSpecified")
	}
	if recurrence.Interval != nil {
		props["interval"] = *recurrence.Interval
	}
	if v, ok := dataFactoryTriggerTimeString(recurrence.StartTime); ok {
		props["startTime"] = v
	}
	if v, ok := dataFactoryTriggerTimeString(recurrence.EndTime); ok {
		props["endTime"] = v
	}
	if recurrence.TimeZone != nil && *recurrence.TimeZone != "" {
		props["timeZone"] = *recurrence.TimeZone
	}
	if schedule := recurrence.Schedule; schedule != nil {
		if hours := dataFactoryInt32List(schedule.Hours); len(hours) > 0 {
			props["scheduleHours"] = hours
		}
		if minutes := dataFactoryInt32List(schedule.Minutes); len(minutes) > 0 {
			props["scheduleMinutes"] = minutes
		}
		if monthDays := dataFactoryInt32List(schedule.MonthDays); len(monthDays) > 0 {
			props["scheduleMonthDays"] = monthDays
		}
		if len(schedule.WeekDays) > 0 {
			weekDays := make([]string, 0, len(schedule.WeekDays))
			for _, day := range schedule.WeekDays {
				if day == nil || *day == "" {
					continue
				}
				weekDays = append(weekDays, canonicalizeEnum(string(*day),
					"Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"))
			}
			if len(weekDays) > 0 {
				props["scheduleWeekDays"] = weekDays
			}
		}
		// monthlyOccurrences is not modelled: it is a list of {day, occurrence}
		// objects, which the flattened recurrence has no place for.
	}
	return props
}

// dataFactoryInt32List narrows one of the recurrence schedule's []*int32 lists.
func dataFactoryInt32List(values []*int32) []int32 {
	if len(values) == 0 {
		return nil
	}
	out := make([]int32, 0, len(values))
	for _, v := range values {
		if v == nil {
			continue
		}
		out = append(out, *v)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (t *DataFactoryTriggerSchedule) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props dataFactoryTriggerScheduleProps
	if err := props.parse(request.Properties, request.Label); err != nil {
		return nil, err
	}
	params, err := props.params()
	if err != nil {
		return nil, err
	}

	result, err := t.api.CreateOrUpdate(ctx, props.ResourceGroupName, props.FactoryName, props.Name, params, nil)
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

func (t *DataFactoryTriggerSchedule) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
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
		ResourceType: ResourceTypeDataFactoryTriggerSchedule,
		Properties:   string(propsJSON),
	}, nil
}

// Update reissues CreateOrUpdate: this API has no PATCH verb for triggers. The
// service refuses the call outright while the trigger is Started, which arrives as
// a 400 and is surfaced with the provider's own reason.
func (t *DataFactoryTriggerSchedule) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, factoryName, name, err := dataFactoryChildIDParts(request.NativeID, "triggers")
	if err != nil {
		return nil, err
	}

	var props dataFactoryTriggerScheduleProps
	if err := props.parse(request.DesiredProperties, name); err != nil {
		return nil, err
	}
	params, err := props.params()
	if err != nil {
		return nil, err
	}

	result, err := t.api.CreateOrUpdate(ctx, rgName, factoryName, name, params, nil)
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
func (t *DataFactoryTriggerSchedule) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
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
func (t *DataFactoryTriggerSchedule) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
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
// by discriminator: handing a BlobEventsTrigger's ID to this provisioner would read
// it with the wrong shape.
func (t *DataFactoryTriggerSchedule) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
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
		nativeIDs = append(nativeIDs, dataFactoryTriggerIDsOfType(page.Value, "ScheduleTrigger")...)
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}

// dataFactoryTriggerIDsOfType keeps only the triggers of one ARM discriminator.
func dataFactoryTriggerIDsOfType(triggers []*armdatafactory.TriggerResource, armType string) []string {
	var out []string
	for _, trigger := range triggers {
		if trigger == nil || trigger.ID == nil || trigger.Properties == nil {
			continue
		}
		base := trigger.Properties.GetTrigger()
		if base == nil || base.Type == nil || *base.Type != armType {
			continue
		}
		out = append(out, *trigger.ID)
	}
	return out
}
