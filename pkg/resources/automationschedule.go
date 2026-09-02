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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/automation/armautomation"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeAutomationSchedule = "AZURE::Automation::Schedule"

// automationScheduleNoExpiryYear is the year ARM stamps on a schedule that was
// created without an expiryTime: it answers Get with
// 9999-12-31T23:59:59.9999999+00:00 rather than omitting the field. Echoing that
// sentinel back would report drift on every sync of a schedule that never
// declared an expiry, so the read path treats it as "unset".
const automationScheduleNoExpiryYear = 9999

// automationScheduleAPI is the armautomation surface used here. Singular client
// name (ScheduleClient); all four verbs are synchronous.
type automationScheduleAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName string, automationAccountName string, scheduleName string, parameters armautomation.ScheduleCreateOrUpdateParameters, options *armautomation.ScheduleClientCreateOrUpdateOptions) (armautomation.ScheduleClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName string, automationAccountName string, scheduleName string, options *armautomation.ScheduleClientGetOptions) (armautomation.ScheduleClientGetResponse, error)
	Update(ctx context.Context, resourceGroupName string, automationAccountName string, scheduleName string, parameters armautomation.ScheduleUpdateParameters, options *armautomation.ScheduleClientUpdateOptions) (armautomation.ScheduleClientUpdateResponse, error)
	Delete(ctx context.Context, resourceGroupName string, automationAccountName string, scheduleName string, options *armautomation.ScheduleClientDeleteOptions) (armautomation.ScheduleClientDeleteResponse, error)
	NewListByAutomationAccountPager(resourceGroupName string, automationAccountName string, options *armautomation.ScheduleClientListByAutomationAccountOptions) *runtime.Pager[armautomation.ScheduleClientListByAutomationAccountResponse]
}

func init() {
	registry.Register(ResourceTypeAutomationSchedule, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &AutomationSchedule{
			api:    c.AutomationScheduleClient,
			config: cfg,
		}
	})
}

// AutomationSchedule is the provisioner for schedules inside an Automation
// account (Microsoft.Automation/automationAccounts/schedules).
//
// Two service-normalisation traps shape the read path. ARM truncates startTime
// and expiryTime to the minute, so a forma that declares sub-minute precision
// reads back as drift; the schema documents whole minutes and the read re-emits
// RFC3339 in UTC so an offset-formatted response still compares equal. And a
// schedule created without an expiryTime is answered with a year-9999 sentinel
// rather than a null, which the read path drops (see
// automationScheduleNoExpiryYear).
//
// The advancedSchedule block (monthDays, weekDays, monthlyOccurrences) is not
// modelled: it is a nested object whose members ARM fills in from the frequency,
// and hasProviderDefault is a no-op inside a plain nested class, so those
// service-chosen members would read back as unexplained drift.
type AutomationSchedule struct {
	api    automationScheduleAPI
	config *config.Config
}

// automationScheduleProps mirrors schema/pkl/automation/automationschedule.pkl.
type automationScheduleProps struct {
	Name                  string `json:"name"`
	ResourceGroupName     string `json:"resourceGroupName"`
	AutomationAccountName string `json:"automationAccountName"`
	Frequency             string `json:"frequency"`
	StartTime             string `json:"startTime"`
	TimeZone              string `json:"timeZone"`
	IsEnabled             *bool  `json:"isEnabled"`
	Interval              *int64 `json:"interval"`
	ExpiryTime            string `json:"expiryTime"`
	Description           string `json:"description"`
}

func automationScheduleIDParts(resourceID string) (rgName, accountName, name string, err error) {
	return automationChildIDParts(resourceID, "schedules")
}

// automationScheduleInterval normalises the SDK's untyped interval into the
// integer the schema declares. ARM types it as `any` because the wire form is a
// bare JSON number, which the SDK hands back as a float64.
func automationScheduleInterval(raw any) (int64, bool) {
	switch v := raw.(type) {
	case nil:
		return 0, false
	case float64:
		return int64(v), true
	case float32:
		return int64(v), true
	case int:
		return int64(v), true
	case int32:
		return int64(v), true
	case int64:
		return v, true
	case json.Number:
		n, err := v.Int64()
		if err != nil {
			return 0, false
		}
		return n, true
	default:
		return 0, false
	}
}

func (s *AutomationSchedule) buildPropertiesFromResult(sch *armautomation.Schedule, rgName, accountName string) map[string]any {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	props["automationAccountName"] = accountName

	if sch.ID != nil {
		props["id"] = *sch.ID
	}
	if sch.Name != nil {
		props["name"] = *sch.Name
	}

	if p := sch.Properties; p != nil {
		if p.Frequency != nil {
			props["frequency"] = canonicalizeEnum(string(*p.Frequency),
				"OneTime", "Day", "Hour", "Week", "Month", "Minute")
		}
		if p.StartTime != nil {
			props["startTime"] = p.StartTime.UTC().Format(time.RFC3339)
		}
		if p.ExpiryTime != nil && p.ExpiryTime.UTC().Year() < automationScheduleNoExpiryYear {
			props["expiryTime"] = p.ExpiryTime.UTC().Format(time.RFC3339)
		}
		if p.TimeZone != nil {
			props["timeZone"] = *p.TimeZone
		}
		if p.IsEnabled != nil {
			props["isEnabled"] = *p.IsEnabled
		}
		if interval, ok := automationScheduleInterval(p.Interval); ok {
			props["interval"] = interval
		}
		if p.Description != nil && *p.Description != "" {
			props["description"] = *p.Description
		}
		// nextRun, startTimeOffsetMinutes, expiryTimeOffsetMinutes,
		// nextRunOffsetMinutes, creationTime and lastModifiedTime are
		// deliberately dropped: nextRun advances on every fired job and the rest
		// are derived or move on their own, so all of them would read back as
		// drift. advancedSchedule is dropped for the reason in the type doc.
	}

	return props
}

func (s *AutomationSchedule) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props automationScheduleProps
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	if props.AutomationAccountName == "" {
		return nil, fmt.Errorf("automationAccountName is required")
	}
	if props.Frequency == "" {
		return nil, fmt.Errorf("frequency is required")
	}
	if props.StartTime == "" {
		return nil, fmt.Errorf("startTime is required")
	}
	name := props.Name
	if name == "" {
		name = request.Label
	}
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}

	startTime, err := parseTime(props.StartTime)
	if err != nil {
		return nil, fmt.Errorf("startTime: %w", err)
	}

	createProps := &armautomation.ScheduleCreateOrUpdateProperties{
		Frequency: to.Ptr(armautomation.ScheduleFrequency(props.Frequency)),
		StartTime: to.Ptr(startTime),
	}
	if props.ExpiryTime != "" {
		expiryTime, err := parseTime(props.ExpiryTime)
		if err != nil {
			return nil, fmt.Errorf("expiryTime: %w", err)
		}
		createProps.ExpiryTime = to.Ptr(expiryTime)
	}
	if props.TimeZone != "" {
		createProps.TimeZone = to.Ptr(props.TimeZone)
	}
	if props.Interval != nil {
		createProps.Interval = *props.Interval
	}
	if props.Description != "" {
		createProps.Description = to.Ptr(props.Description)
	}

	params := armautomation.ScheduleCreateOrUpdateParameters{
		Name:       to.Ptr(name),
		Properties: createProps,
	}

	result, err := s.api.CreateOrUpdate(ctx, props.ResourceGroupName, props.AutomationAccountName, name, params, nil)
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
	if nativeID == "" {
		nativeID = automationChildNativeID(s.config.SubscriptionId, props.ResourceGroupName,
			props.AutomationAccountName, "schedules", name)
	}
	propsJSON, err := json.Marshal(s.buildPropertiesFromResult(&result.Schedule,
		props.ResourceGroupName, props.AutomationAccountName))
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

func (s *AutomationSchedule) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, accountName, name, err := automationScheduleIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := s.api.Get(ctx, rgName, accountName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(s.buildPropertiesFromResult(&result.Schedule, rgName, accountName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeAutomationSchedule,
		Properties:   string(propsJSON),
	}, nil
}

// Update is a synchronous PATCH, and ScheduleUpdateProperties carries only
// description and isEnabled. Everything about the recurrence itself — frequency,
// startTime, expiryTime, interval, timeZone — is createOnly: ARM has no verb
// that reschedules in place, so changing any of them replaces the schedule.
func (s *AutomationSchedule) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, accountName, name, err := automationScheduleIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props automationScheduleProps
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	updateProps := &armautomation.ScheduleUpdateProperties{
		IsEnabled: props.IsEnabled,
	}
	if props.Description != "" {
		updateProps.Description = to.Ptr(props.Description)
	}

	params := armautomation.ScheduleUpdateParameters{
		Name:       to.Ptr(name),
		Properties: updateProps,
	}

	result, err := s.api.Update(ctx, rgName, accountName, name, params, nil)
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

	propsJSON, err := json.Marshal(s.buildPropertiesFromResult(&result.Schedule, rgName, accountName))
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

func (s *AutomationSchedule) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, accountName, name, err := automationScheduleIDParts(request.NativeID)
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

// Status is never reached with real work to do: every schedule operation is
// synchronous.
func (s *AutomationSchedule) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

// List needs both the resource group and the automation account: ARM has no
// subscription-wide listing for schedules.
func (s *AutomationSchedule) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	accountName := request.AdditionalProperties["automationAccountName"]
	if rgName == "" || accountName == "" {
		return &resource.ListResult{}, nil
	}

	var nativeIDs []string
	pager := s.api.NewListByAutomationAccountPager(rgName, accountName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list automation schedules: %w", err)
		}
		for _, sch := range page.Value {
			if sch.ID != nil {
				nativeIDs = append(nativeIDs, *sch.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
