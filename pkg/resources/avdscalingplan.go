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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/desktopvirtualization/armdesktopvirtualization"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeAvdScalingPlan = "AZURE::DesktopVirtualization::ScalingPlan"

// avdScalingScheduleTimeLayout is the wall-clock form the schema carries for a
// schedule phase's start time.
const avdScalingScheduleTimeLayout = "15:04"

// avdScalingPlansAPI is the armdesktopvirtualization surface used here; all
// operations are synchronous. Note that the create verb is Create, not
// CreateOrUpdate — scaling plans are the one AVD type whose PUT is not
// upsert-shaped in the generated client.
type avdScalingPlansAPI interface {
	Create(ctx context.Context, resourceGroupName string, scalingPlanName string, scalingPlan armdesktopvirtualization.ScalingPlan, options *armdesktopvirtualization.ScalingPlansClientCreateOptions) (armdesktopvirtualization.ScalingPlansClientCreateResponse, error)
	Get(ctx context.Context, resourceGroupName string, scalingPlanName string, options *armdesktopvirtualization.ScalingPlansClientGetOptions) (armdesktopvirtualization.ScalingPlansClientGetResponse, error)
	Update(ctx context.Context, resourceGroupName string, scalingPlanName string, options *armdesktopvirtualization.ScalingPlansClientUpdateOptions) (armdesktopvirtualization.ScalingPlansClientUpdateResponse, error)
	Delete(ctx context.Context, resourceGroupName string, scalingPlanName string, options *armdesktopvirtualization.ScalingPlansClientDeleteOptions) (armdesktopvirtualization.ScalingPlansClientDeleteResponse, error)
	NewListByResourceGroupPager(resourceGroupName string, options *armdesktopvirtualization.ScalingPlansClientListByResourceGroupOptions) *runtime.Pager[armdesktopvirtualization.ScalingPlansClientListByResourceGroupResponse]
	NewListBySubscriptionPager(options *armdesktopvirtualization.ScalingPlansClientListBySubscriptionOptions) *runtime.Pager[armdesktopvirtualization.ScalingPlansClientListBySubscriptionResponse]
}

func init() {
	registry.Register(ResourceTypeAvdScalingPlan, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &AvdScalingPlan{api: c.AvdScalingPlansClient, config: cfg}
	})
}

// AvdScalingPlan is the provisioner for Azure Virtual Desktop scaling plans
// (Microsoft.DesktopVirtualization/scalingPlans).
//
// The pools a plan drives are a field, hostPoolReferences, not association
// resources: ARM stores the list on the plan.
type AvdScalingPlan struct {
	api    avdScalingPlansAPI
	config *config.Config
}

// avdScalingHostPoolReferenceProps mirrors the ScalingHostPoolReference class in
// schema/pkl/desktopvirtualization/avdscalingplan.pkl.
type avdScalingHostPoolReferenceProps struct {
	HostPoolArmPath    string `json:"hostPoolArmPath"`
	ScalingPlanEnabled *bool  `json:"scalingPlanEnabled"`
}

// avdScalingScheduleProps mirrors the ScalingSchedule class in
// schema/pkl/desktopvirtualization/avdscalingplan.pkl. Every field is required
// there, so every pointer here is expected to arrive set; the create path checks
// the ones ARM cannot infer.
type avdScalingScheduleProps struct {
	Name                           string   `json:"name"`
	DaysOfWeek                     []string `json:"daysOfWeek"`
	RampUpStartTime                string   `json:"rampUpStartTime"`
	RampUpLoadBalancingAlgorithm   string   `json:"rampUpLoadBalancingAlgorithm"`
	RampUpMinimumHostsPct          *int32   `json:"rampUpMinimumHostsPct"`
	RampUpCapacityThresholdPct     *int32   `json:"rampUpCapacityThresholdPct"`
	PeakStartTime                  string   `json:"peakStartTime"`
	PeakLoadBalancingAlgorithm     string   `json:"peakLoadBalancingAlgorithm"`
	RampDownStartTime              string   `json:"rampDownStartTime"`
	RampDownLoadBalancingAlgorithm string   `json:"rampDownLoadBalancingAlgorithm"`
	RampDownMinimumHostsPct        *int32   `json:"rampDownMinimumHostsPct"`
	RampDownCapacityThresholdPct   *int32   `json:"rampDownCapacityThresholdPct"`
	RampDownForceLogoffUsers       *bool    `json:"rampDownForceLogoffUsers"`
	RampDownWaitTimeMinutes        *int32   `json:"rampDownWaitTimeMinutes"`
	RampDownNotificationMessage    string   `json:"rampDownNotificationMessage"`
	RampDownStopHostsWhen          string   `json:"rampDownStopHostsWhen"`
	OffPeakStartTime               string   `json:"offPeakStartTime"`
	OffPeakLoadBalancingAlgorithm  string   `json:"offPeakLoadBalancingAlgorithm"`
}

// avdScalingPlanProps mirrors schema/pkl/desktopvirtualization/avdscalingplan.pkl.
type avdScalingPlanProps struct {
	Name               string                             `json:"name"`
	Location           string                             `json:"location"`
	ResourceGroupName  string                             `json:"resourceGroupName"`
	TimeZone           string                             `json:"timeZone"`
	HostPoolType       string                             `json:"hostPoolType"`
	HostPoolReferences []avdScalingHostPoolReferenceProps `json:"hostPoolReferences"`
	Schedules          []avdScalingScheduleProps          `json:"schedules"`
	ExclusionTag       string                             `json:"exclusionTag"`
	Description        string                             `json:"description"`
	FriendlyName       string                             `json:"friendlyName"`
}

func avdScalingPlanIDParts(resourceID string) (rgName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "scalingplans")
	if err != nil {
		return "", "", err
	}
	return rgName, names["scalingplans"], nil
}

// avdScheduleTime turns the schema's `HH:MM` wall-clock string into the
// timestamp the 2021-07-12 API carries.
//
// The date part of that timestamp is meaningless to the service — only the time
// of day is used — but it is re-serialised in the response, so a forma cannot
// declare an absolute instant and expect it back unchanged. Pinning the date to
// one fixed reference day makes the round trip exact, and it is the same
// hour/minute pair later API versions model natively.
func avdScheduleTime(field, value string) (*time.Time, error) {
	if value == "" {
		return nil, fmt.Errorf("%s is required", field)
	}
	parsed, err := time.Parse(avdScalingScheduleTimeLayout, value)
	if err != nil {
		return nil, fmt.Errorf("%s must be a HH:MM wall-clock time, got %q", field, value)
	}
	return to.Ptr(time.Date(2020, time.January, 1, parsed.Hour(), parsed.Minute(), 0, 0, time.UTC)), nil
}

// avdScheduleTimeOfDay is the read-path inverse of avdScheduleTime: it discards
// whatever date the service put on the timestamp and keeps the wall clock.
func avdScheduleTimeOfDay(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.UTC().Format(avdScalingScheduleTimeLayout)
}

// avdScalingSchedules builds the ARM schedule list. The schema marks every field
// required, so an empty one here is a bug rather than an omission, and is
// reported as such instead of being sent for ARM to reject opaquely.
func avdScalingSchedules(schedules []avdScalingScheduleProps) ([]*armdesktopvirtualization.ScalingSchedule, error) {
	if len(schedules) == 0 {
		return nil, fmt.Errorf("schedules is required")
	}
	out := make([]*armdesktopvirtualization.ScalingSchedule, 0, len(schedules))
	for i, s := range schedules {
		if s.Name == "" {
			return nil, fmt.Errorf("schedules[%d].name is required", i)
		}
		if len(s.DaysOfWeek) == 0 {
			return nil, fmt.Errorf("schedules[%d].daysOfWeek is required", i)
		}

		rampUpStart, err := avdScheduleTime(fmt.Sprintf("schedules[%d].rampUpStartTime", i), s.RampUpStartTime)
		if err != nil {
			return nil, err
		}
		peakStart, err := avdScheduleTime(fmt.Sprintf("schedules[%d].peakStartTime", i), s.PeakStartTime)
		if err != nil {
			return nil, err
		}
		rampDownStart, err := avdScheduleTime(fmt.Sprintf("schedules[%d].rampDownStartTime", i), s.RampDownStartTime)
		if err != nil {
			return nil, err
		}
		offPeakStart, err := avdScheduleTime(fmt.Sprintf("schedules[%d].offPeakStartTime", i), s.OffPeakStartTime)
		if err != nil {
			return nil, err
		}

		days := make([]*armdesktopvirtualization.ScalingScheduleDaysOfWeekItem, 0, len(s.DaysOfWeek))
		for _, day := range s.DaysOfWeek {
			days = append(days, to.Ptr(armdesktopvirtualization.ScalingScheduleDaysOfWeekItem(day)))
		}

		schedule := &armdesktopvirtualization.ScalingSchedule{
			Name:                         to.Ptr(s.Name),
			DaysOfWeek:                   days,
			RampUpStartTime:              rampUpStart,
			RampUpMinimumHostsPct:        s.RampUpMinimumHostsPct,
			RampUpCapacityThresholdPct:   s.RampUpCapacityThresholdPct,
			PeakStartTime:                peakStart,
			RampDownStartTime:            rampDownStart,
			RampDownMinimumHostsPct:      s.RampDownMinimumHostsPct,
			RampDownCapacityThresholdPct: s.RampDownCapacityThresholdPct,
			RampDownForceLogoffUsers:     s.RampDownForceLogoffUsers,
			RampDownWaitTimeMinutes:      s.RampDownWaitTimeMinutes,
			OffPeakStartTime:             offPeakStart,
		}
		if s.RampUpLoadBalancingAlgorithm != "" {
			schedule.RampUpLoadBalancingAlgorithm = to.Ptr(
				armdesktopvirtualization.SessionHostLoadBalancingAlgorithm(s.RampUpLoadBalancingAlgorithm))
		}
		if s.PeakLoadBalancingAlgorithm != "" {
			schedule.PeakLoadBalancingAlgorithm = to.Ptr(
				armdesktopvirtualization.SessionHostLoadBalancingAlgorithm(s.PeakLoadBalancingAlgorithm))
		}
		if s.RampDownLoadBalancingAlgorithm != "" {
			schedule.RampDownLoadBalancingAlgorithm = to.Ptr(
				armdesktopvirtualization.SessionHostLoadBalancingAlgorithm(s.RampDownLoadBalancingAlgorithm))
		}
		if s.OffPeakLoadBalancingAlgorithm != "" {
			schedule.OffPeakLoadBalancingAlgorithm = to.Ptr(
				armdesktopvirtualization.SessionHostLoadBalancingAlgorithm(s.OffPeakLoadBalancingAlgorithm))
		}
		if s.RampDownNotificationMessage != "" {
			schedule.RampDownNotificationMessage = to.Ptr(s.RampDownNotificationMessage)
		}
		if s.RampDownStopHostsWhen != "" {
			schedule.RampDownStopHostsWhen = to.Ptr(
				armdesktopvirtualization.StopHostsWhen(s.RampDownStopHostsWhen))
		}
		out = append(out, schedule)
	}
	return out, nil
}

// avdScalingHostPoolReferences builds the ARM hostPoolReferences list. Returns
// nil for an empty input so an unset list is omitted from the body rather than
// sent as an empty array.
func avdScalingHostPoolReferences(refs []avdScalingHostPoolReferenceProps) ([]*armdesktopvirtualization.ScalingHostPoolReference, error) {
	if len(refs) == 0 {
		return nil, nil
	}
	out := make([]*armdesktopvirtualization.ScalingHostPoolReference, 0, len(refs))
	for i, ref := range refs {
		if ref.HostPoolArmPath == "" {
			return nil, fmt.Errorf("hostPoolReferences[%d].hostPoolArmPath is required", i)
		}
		out = append(out, &armdesktopvirtualization.ScalingHostPoolReference{
			HostPoolArmPath:    to.Ptr(ref.HostPoolArmPath),
			ScalingPlanEnabled: ref.ScalingPlanEnabled,
		})
	}
	return out, nil
}

func (a *AvdScalingPlan) buildPropertiesFromResult(plan *armdesktopvirtualization.ScalingPlan, rgName string) map[string]any {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName

	if plan.ID != nil {
		props["id"] = *plan.ID
	}
	if plan.Name != nil {
		props["name"] = *plan.Name
	}
	if plan.Location != nil {
		props["location"] = normalizeAzureLocation(*plan.Location)
	}

	if p := plan.Properties; p != nil {
		if p.TimeZone != nil {
			props["timeZone"] = *p.TimeZone
		}
		if p.HostPoolType != nil {
			props["hostPoolType"] = canonicalizeEnum(string(*p.HostPoolType), "Pooled")
		}
		if p.ExclusionTag != nil && *p.ExclusionTag != "" {
			props["exclusionTag"] = *p.ExclusionTag
		}
		// ARM answers Get with "" for a description or friendly name that was
		// never set, and desired state carries the field absent — emitting the
		// empty string would report drift on every sync.
		if p.Description != nil && *p.Description != "" {
			props["description"] = *p.Description
		}
		if p.FriendlyName != nil && *p.FriendlyName != "" {
			props["friendlyName"] = *p.FriendlyName
		}

		refs := make([]map[string]any, 0, len(p.HostPoolReferences))
		for _, ref := range p.HostPoolReferences {
			if ref == nil {
				continue
			}
			entry := map[string]any{}
			if ref.HostPoolArmPath != nil {
				entry["hostPoolArmPath"] = *ref.HostPoolArmPath
			}
			if ref.ScalingPlanEnabled != nil {
				entry["scalingPlanEnabled"] = *ref.ScalingPlanEnabled
			}
			refs = append(refs, entry)
		}
		if len(refs) > 0 {
			props["hostPoolReferences"] = refs
		}

		schedules := make([]map[string]any, 0, len(p.Schedules))
		for _, s := range p.Schedules {
			if s == nil {
				continue
			}
			schedules = append(schedules, avdScalingScheduleToProps(s))
		}
		if len(schedules) > 0 {
			props["schedules"] = schedules
		}
		// objectId is deliberately dropped: internal service bookkeeping.
	}

	if tags := azureTagsToFormaeTags(plan.Tags); tags != nil {
		props["Tags"] = tags
	}

	return props
}

func avdScalingScheduleToProps(s *armdesktopvirtualization.ScalingSchedule) map[string]any {
	entry := map[string]any{}
	if s.Name != nil {
		entry["name"] = *s.Name
	}
	if len(s.DaysOfWeek) > 0 {
		days := make([]string, 0, len(s.DaysOfWeek))
		for _, day := range s.DaysOfWeek {
			if day != nil {
				days = append(days, string(*day))
			}
		}
		entry["daysOfWeek"] = days
	}
	if t := avdScheduleTimeOfDay(s.RampUpStartTime); t != "" {
		entry["rampUpStartTime"] = t
	}
	if s.RampUpLoadBalancingAlgorithm != nil {
		entry["rampUpLoadBalancingAlgorithm"] = canonicalizeEnum(
			string(*s.RampUpLoadBalancingAlgorithm), "BreadthFirst", "DepthFirst")
	}
	if s.RampUpMinimumHostsPct != nil {
		entry["rampUpMinimumHostsPct"] = *s.RampUpMinimumHostsPct
	}
	if s.RampUpCapacityThresholdPct != nil {
		entry["rampUpCapacityThresholdPct"] = *s.RampUpCapacityThresholdPct
	}
	if t := avdScheduleTimeOfDay(s.PeakStartTime); t != "" {
		entry["peakStartTime"] = t
	}
	if s.PeakLoadBalancingAlgorithm != nil {
		entry["peakLoadBalancingAlgorithm"] = canonicalizeEnum(
			string(*s.PeakLoadBalancingAlgorithm), "BreadthFirst", "DepthFirst")
	}
	if t := avdScheduleTimeOfDay(s.RampDownStartTime); t != "" {
		entry["rampDownStartTime"] = t
	}
	if s.RampDownLoadBalancingAlgorithm != nil {
		entry["rampDownLoadBalancingAlgorithm"] = canonicalizeEnum(
			string(*s.RampDownLoadBalancingAlgorithm), "BreadthFirst", "DepthFirst")
	}
	if s.RampDownMinimumHostsPct != nil {
		entry["rampDownMinimumHostsPct"] = *s.RampDownMinimumHostsPct
	}
	if s.RampDownCapacityThresholdPct != nil {
		entry["rampDownCapacityThresholdPct"] = *s.RampDownCapacityThresholdPct
	}
	if s.RampDownForceLogoffUsers != nil {
		entry["rampDownForceLogoffUsers"] = *s.RampDownForceLogoffUsers
	}
	if s.RampDownWaitTimeMinutes != nil {
		entry["rampDownWaitTimeMinutes"] = *s.RampDownWaitTimeMinutes
	}
	if s.RampDownNotificationMessage != nil {
		entry["rampDownNotificationMessage"] = *s.RampDownNotificationMessage
	}
	if s.RampDownStopHostsWhen != nil {
		entry["rampDownStopHostsWhen"] = canonicalizeEnum(
			string(*s.RampDownStopHostsWhen), "ZeroSessions", "ZeroActiveSessions")
	}
	if t := avdScheduleTimeOfDay(s.OffPeakStartTime); t != "" {
		entry["offPeakStartTime"] = t
	}
	if s.OffPeakLoadBalancingAlgorithm != nil {
		entry["offPeakLoadBalancingAlgorithm"] = canonicalizeEnum(
			string(*s.OffPeakLoadBalancingAlgorithm), "BreadthFirst", "DepthFirst")
	}
	return entry
}

func (a *AvdScalingPlan) armProperties(props *avdScalingPlanProps) (*armdesktopvirtualization.ScalingPlanProperties, error) {
	schedules, err := avdScalingSchedules(props.Schedules)
	if err != nil {
		return nil, err
	}
	refs, err := avdScalingHostPoolReferences(props.HostPoolReferences)
	if err != nil {
		return nil, err
	}

	out := &armdesktopvirtualization.ScalingPlanProperties{
		TimeZone:           to.Ptr(props.TimeZone),
		Schedules:          schedules,
		HostPoolReferences: refs,
	}
	if props.HostPoolType != "" {
		out.HostPoolType = to.Ptr(armdesktopvirtualization.HostPoolType(props.HostPoolType))
	}
	if props.ExclusionTag != "" {
		out.ExclusionTag = to.Ptr(props.ExclusionTag)
	}
	if props.Description != "" {
		out.Description = to.Ptr(props.Description)
	}
	if props.FriendlyName != "" {
		out.FriendlyName = to.Ptr(props.FriendlyName)
	}
	return out, nil
}

func (a *AvdScalingPlan) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props avdScalingPlanProps
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	if props.Location == "" {
		return nil, fmt.Errorf("location is required")
	}
	if props.TimeZone == "" {
		return nil, fmt.Errorf("timeZone is required")
	}
	name := props.Name
	if name == "" {
		name = request.Label
	}
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}

	planProps, err := a.armProperties(&props)
	if err != nil {
		return nil, err
	}

	params := armdesktopvirtualization.ScalingPlan{
		Location:   to.Ptr(props.Location),
		Properties: planProps,
	}
	if azureTags := formaeTagsToAzureTags(request.Properties); azureTags != nil {
		params.Tags = azureTags
	}

	result, err := a.api.Create(ctx, props.ResourceGroupName, name, params, nil)
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
	propsJSON, err := json.Marshal(a.buildPropertiesFromResult(&result.ScalingPlan, props.ResourceGroupName))
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

func (a *AvdScalingPlan) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, name, err := avdScalingPlanIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := a.api.Get(ctx, rgName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(a.buildPropertiesFromResult(&result.ScalingPlan, rgName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeAvdScalingPlan,
		Properties:   string(propsJSON),
	}, nil
}

// Update is a synchronous PATCH. Every mutable field is present in
// ScalingPlanPatchProperties, and the schedule list and host-pool references are
// sent whole so a removed schedule or a removed pool actually disappears.
func (a *AvdScalingPlan) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, name, err := avdScalingPlanIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props avdScalingPlanProps
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	planProps, err := a.armProperties(&props)
	if err != nil {
		return nil, err
	}

	patch := &armdesktopvirtualization.ScalingPlanPatch{
		Properties: &armdesktopvirtualization.ScalingPlanPatchProperties{
			TimeZone:           planProps.TimeZone,
			HostPoolType:       planProps.HostPoolType,
			HostPoolReferences: planProps.HostPoolReferences,
			Schedules:          planProps.Schedules,
			ExclusionTag:       planProps.ExclusionTag,
			Description:        planProps.Description,
			FriendlyName:       planProps.FriendlyName,
		},
	}
	if azureTags := formaeTagsToAzureTags(request.DesiredProperties); azureTags != nil {
		patch.Tags = azureTags
	}

	result, err := a.api.Update(ctx, rgName, name,
		&armdesktopvirtualization.ScalingPlansClientUpdateOptions{ScalingPlan: patch})
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

	propsJSON, err := json.Marshal(a.buildPropertiesFromResult(&result.ScalingPlan, rgName))
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

func (a *AvdScalingPlan) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, name, err := avdScalingPlanIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	if _, err := a.api.Delete(ctx, rgName, name, nil); err != nil && !isDeleteSuccessError(err) {
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

// Status is never reached with real work to do: armdesktopvirtualization exposes
// no LRO at all.
func (a *AvdScalingPlan) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

func (a *AvdScalingPlan) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]

	var nativeIDs []string

	if rgName != "" {
		pager := a.api.NewListByResourceGroupPager(rgName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list AVD scaling plans: %w", err)
			}
			for _, plan := range page.Value {
				if plan.ID != nil {
					nativeIDs = append(nativeIDs, *plan.ID)
				}
			}
		}
		return &resource.ListResult{NativeIDs: nativeIDs}, nil
	}

	pager := a.api.NewListBySubscriptionPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list AVD scaling plans: %w", err)
		}
		for _, plan := range page.Value {
			if plan.ID != nil {
				nativeIDs = append(nativeIDs, *plan.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
