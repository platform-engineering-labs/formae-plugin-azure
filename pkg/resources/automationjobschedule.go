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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/automation/armautomation"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeAutomationJobSchedule = "AZURE::Automation::JobSchedule"

// automationJobScheduleAPI is the armautomation surface used here. Note there is
// no Update verb and no CreateOrUpdate: the client offers Create only, which is
// the API telling you the resource is immutable.
type automationJobScheduleAPI interface {
	Create(ctx context.Context, resourceGroupName string, automationAccountName string, jobScheduleID string, parameters armautomation.JobScheduleCreateParameters, options *armautomation.JobScheduleClientCreateOptions) (armautomation.JobScheduleClientCreateResponse, error)
	Get(ctx context.Context, resourceGroupName string, automationAccountName string, jobScheduleID string, options *armautomation.JobScheduleClientGetOptions) (armautomation.JobScheduleClientGetResponse, error)
	Delete(ctx context.Context, resourceGroupName string, automationAccountName string, jobScheduleID string, options *armautomation.JobScheduleClientDeleteOptions) (armautomation.JobScheduleClientDeleteResponse, error)
	NewListByAutomationAccountPager(resourceGroupName string, automationAccountName string, options *armautomation.JobScheduleClientListByAutomationAccountOptions) *runtime.Pager[armautomation.JobScheduleClientListByAutomationAccountResponse]
}

func init() {
	registry.Register(ResourceTypeAutomationJobSchedule, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &AutomationJobSchedule{
			api:    c.AutomationJobScheduleClient,
			config: cfg,
		}
	})
}

// AutomationJobSchedule is the provisioner for the link between a runbook and a
// schedule (Microsoft.Automation/automationAccounts/jobSchedules).
//
// The resource is IMMUTABLE: armautomation exposes Create, Get and Delete and no
// Update at all, so every field is createOnly and any change replaces the link.
// Update therefore fails loudly rather than silently no-op'ing — the same shape
// AZURE::Authorization::RoleAssignment uses.
//
// Its name is a GUID chosen by the caller, not a friendly name: ARM uses the
// jobScheduleID both as the URL segment and as the resource name.
type AutomationJobSchedule struct {
	api    automationJobScheduleAPI
	config *config.Config
}

// automationJobScheduleProps mirrors
// schema/pkl/automation/automationjobschedule.pkl.
type automationJobScheduleProps struct {
	Name                  string `json:"name"`
	ResourceGroupName     string `json:"resourceGroupName"`
	AutomationAccountName string `json:"automationAccountName"`
	RunbookName           string `json:"runbookName"`
	ScheduleName          string `json:"scheduleName"`
	RunOn                 string `json:"runOn"`
}

func automationJobScheduleIDParts(resourceID string) (rgName, accountName, name string, err error) {
	return automationChildIDParts(resourceID, "jobschedules")
}

func (j *AutomationJobSchedule) buildPropertiesFromResult(js *armautomation.JobSchedule, rgName, accountName, name string) map[string]any {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	props["automationAccountName"] = accountName

	if js.ID != nil {
		props["id"] = *js.ID
	}
	// ARM leaves the envelope's name unset on this type and reports the GUID only
	// as properties.jobScheduleId, so fall back through both to the name parsed
	// out of the native ID.
	switch {
	case js.Name != nil && *js.Name != "":
		props["name"] = *js.Name
	case js.Properties != nil && js.Properties.JobScheduleID != nil && *js.Properties.JobScheduleID != "":
		props["name"] = *js.Properties.JobScheduleID
	case name != "":
		props["name"] = name
	}

	if p := js.Properties; p != nil {
		if p.Runbook != nil && p.Runbook.Name != nil {
			props["runbookName"] = *p.Runbook.Name
		}
		if p.Schedule != nil && p.Schedule.Name != nil {
			props["scheduleName"] = *p.Schedule.Name
		}
		if p.RunOn != nil && *p.RunOn != "" {
			props["runOn"] = *p.RunOn
		}
		if params := azureTagsToFormaeTags(p.Parameters); params != nil {
			props["parameters"] = params
		}
	}

	return props
}

func (j *AutomationJobSchedule) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props automationJobScheduleProps
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	if props.AutomationAccountName == "" {
		return nil, fmt.Errorf("automationAccountName is required")
	}
	if props.RunbookName == "" {
		return nil, fmt.Errorf("runbookName is required")
	}
	if props.ScheduleName == "" {
		return nil, fmt.Errorf("scheduleName is required")
	}
	name := props.Name
	if name == "" {
		name = request.Label
	}
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}

	createProps := &armautomation.JobScheduleCreateProperties{
		Runbook:  &armautomation.RunbookAssociationProperty{Name: to.Ptr(props.RunbookName)},
		Schedule: &armautomation.ScheduleAssociationProperty{Name: to.Ptr(props.ScheduleName)},
	}
	if props.RunOn != "" {
		createProps.RunOn = to.Ptr(props.RunOn)
	}

	var raw map[string]any
	if err := json.Unmarshal(request.Properties, &raw); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if jobParams := automationJobScheduleParameters(raw); jobParams != nil {
		createProps.Parameters = jobParams
	}

	// Automation acknowledges a jobSchedule delete before its index catches up, so
	// a create against the same GUID keeps returning 409 for a short while after.
	// The name here is a caller-supplied GUID rather than one ARM allocates, so the
	// re-apply in the OOB-delete phase always lands on the name just removed.
	var result armautomation.JobScheduleClientCreateResponse
	err := retryOnDeleteResidue(ctx, func() error {
		var attemptErr error
		result, attemptErr = j.api.Create(ctx, props.ResourceGroupName, props.AutomationAccountName, name,
			armautomation.JobScheduleCreateParameters{Properties: createProps}, nil)
		return attemptErr
	})
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
		nativeID = automationChildNativeID(j.config.SubscriptionId, props.ResourceGroupName,
			props.AutomationAccountName, "jobSchedules", name)
	}
	propsJSON, err := json.Marshal(j.buildPropertiesFromResult(&result.JobSchedule,
		props.ResourceGroupName, props.AutomationAccountName, name))
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

// automationJobScheduleParameters reads the entity-set shaped `parameters` list
// (`[{Key,Value}, ...]`) back into the flat map ARM expects. It reuses the same
// shape as the storage children's `metadata`, but cannot reuse
// metadataFromProperties: that helper is hard-wired to the "metadata" key.
func automationJobScheduleParameters(props map[string]any) map[string]*string {
	raw, ok := props["parameters"].([]any)
	if !ok || len(raw) == 0 {
		return nil
	}
	out := make(map[string]*string, len(raw))
	for _, entry := range raw {
		m, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		key, _ := m["Key"].(string)
		value, _ := m["Value"].(string)
		if key == "" {
			continue
		}
		v := value
		out[key] = &v
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (j *AutomationJobSchedule) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, accountName, name, err := automationJobScheduleIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := j.api.Get(ctx, rgName, accountName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(j.buildPropertiesFromResult(&result.JobSchedule, rgName, accountName, name))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeAutomationJobSchedule,
		Properties:   string(propsJSON),
	}, nil
}

// Update always fails: ARM has no update verb for a job schedule, so a changed
// field must be applied as a replace. Every field in the schema is createOnly,
// which is what drives core to plan the replace; this method exists only to
// refuse an update that somehow reaches it, with the cause in StatusMessage
// rather than a bare transition to Failed.
func (j *AutomationJobSchedule) Update(_ context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	const msg = "AZURE::Automation::JobSchedule is immutable: ARM exposes no update verb for jobSchedules. Change a createOnly field to replace it instead."
	return &resource.UpdateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationUpdate,
			OperationStatus: resource.OperationStatusFailure,
			NativeID:        request.NativeID,
			ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
			StatusMessage:   msg,
		},
	}, fmt.Errorf("%s", msg)
}

func (j *AutomationJobSchedule) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, accountName, name, err := automationJobScheduleIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	if _, err := j.api.Delete(ctx, rgName, accountName, name, nil); err != nil && !isDeleteSuccessError(err) {
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

// Status is never reached with real work to do: create and delete are both
// synchronous.
func (j *AutomationJobSchedule) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

// List needs both the resource group and the automation account: ARM has no
// subscription-wide listing for job schedules.
func (j *AutomationJobSchedule) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	accountName := request.AdditionalProperties["automationAccountName"]
	if rgName == "" || accountName == "" {
		return &resource.ListResult{}, nil
	}

	var nativeIDs []string
	pager := j.api.NewListByAutomationAccountPager(rgName, accountName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list automation job schedules: %w", err)
		}
		for _, js := range page.Value {
			if js.ID != nil {
				nativeIDs = append(nativeIDs, *js.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
