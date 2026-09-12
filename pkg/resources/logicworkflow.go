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

const ResourceTypeLogicWorkflow = "AZURE::Logic::Workflow"

// logicWorkflowsAPI is the armlogic surface used here.
//
// Every verb is synchronous: WorkflowsClient's only BeginX is BeginMove, which
// this provisioner does not use. Update exists but takes NO request body in
// api-version 2019-05-01 — it is a bare PATCH that carries nothing — so an
// update reissues CreateOrUpdate.
//
// Enable, Disable, ListCallbackURL, RegenerateAccessKey and the validate verbs
// are deliberately absent. state is part of the resource body, so it travels
// with the PUT; the callback URL and access keys are live credentials that must
// not reach resource state.
type logicWorkflowsAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName string, workflowName string, workflow armlogic.Workflow, options *armlogic.WorkflowsClientCreateOrUpdateOptions) (armlogic.WorkflowsClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName string, workflowName string, options *armlogic.WorkflowsClientGetOptions) (armlogic.WorkflowsClientGetResponse, error)
	Delete(ctx context.Context, resourceGroupName string, workflowName string, options *armlogic.WorkflowsClientDeleteOptions) (armlogic.WorkflowsClientDeleteResponse, error)
	NewListByResourceGroupPager(resourceGroupName string, options *armlogic.WorkflowsClientListByResourceGroupOptions) *runtime.Pager[armlogic.WorkflowsClientListByResourceGroupResponse]
	NewListBySubscriptionPager(options *armlogic.WorkflowsClientListBySubscriptionOptions) *runtime.Pager[armlogic.WorkflowsClientListBySubscriptionResponse]
}

func init() {
	registry.Register(ResourceTypeLogicWorkflow, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &LogicWorkflow{
			api:    c.LogicWorkflowsClient,
			config: cfg,
		}
	})
}

// LogicWorkflow is the provisioner for Logic Apps (Consumption) workflows
// (Microsoft.Logic/workflows).
//
// Triggers and actions are NOT separate resources: they live inside the
// definition document this resource carries, and armlogic exposes no create or
// delete verb for either (WorkflowTriggersClient is get / list / reset / run
// only). Terraform's azurerm_logic_app_trigger_* and azurerm_logic_app_action_*
// resources work by patching this parent.
type LogicWorkflow struct {
	api    logicWorkflowsAPI
	config *config.Config
}

// logicWorkflowProps mirrors schema/pkl/logic/logicworkflow.pkl.
type logicWorkflowProps struct {
	Name                 string  `json:"name"`
	Location             string  `json:"location"`
	ResourceGroupName    string  `json:"resourceGroupName"`
	Definition           string  `json:"definition"`
	State                *string `json:"state"`
	IntegrationAccountID *string `json:"integrationAccountId"`
}

func (p *logicWorkflowProps) parse(payload json.RawMessage, fallbackName string) error {
	if err := json.Unmarshal(payload, p); err != nil {
		return fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if p.ResourceGroupName == "" {
		return fmt.Errorf("resourceGroupName is required")
	}
	if p.Location == "" {
		return fmt.Errorf("location is required")
	}
	if p.Name == "" {
		p.Name = fallbackName
	}
	if p.Name == "" {
		return fmt.Errorf("name is required")
	}
	if p.Definition == "" {
		return fmt.Errorf("definition is required")
	}
	return nil
}

func logicWorkflowIDParts(resourceID string) (rgName, name string, err error) {
	rgName, names, err := armExactIDParts(resourceID, "workflows")
	if err != nil {
		return "", "", err
	}
	return rgName, names[0], nil
}

// params builds the request body shared by create and update.
//
// definition crosses the wire as a JSON string because the Workflow Definition
// Language is arbitrarily nested JSON no PKL class can describe. It is decoded
// here so a malformed document fails before any ARM call rather than as an
// opaque 400, and it must be an object: ARM rejects an array or a scalar with a
// message that names neither.
func (w *LogicWorkflow) params(props logicWorkflowProps, tagsSource json.RawMessage) (armlogic.Workflow, error) {
	var definition map[string]any
	if err := logicJSONDocument("definition", props.Definition, &definition); err != nil {
		return armlogic.Workflow{}, err
	}
	if len(definition) == 0 {
		return armlogic.Workflow{}, fmt.Errorf("definition must be a non-empty JSON object")
	}

	workflowProps := &armlogic.WorkflowProperties{Definition: definition}
	if props.State != nil && *props.State != "" {
		workflowProps.State = to.Ptr(armlogic.WorkflowState(*props.State))
	}
	if props.IntegrationAccountID != nil && *props.IntegrationAccountID != "" {
		workflowProps.IntegrationAccount = &armlogic.ResourceReference{ID: props.IntegrationAccountID}
	}

	workflow := armlogic.Workflow{
		Location:   to.Ptr(props.Location),
		Properties: workflowProps,
	}
	if azureTags := formaeTagsToAzureTags(tagsSource); azureTags != nil {
		workflow.Tags = azureTags
	}
	return workflow, nil
}

func (w *LogicWorkflow) buildPropertiesFromResult(workflow *armlogic.Workflow, rgName string) map[string]any {
	props := map[string]any{"resourceGroupName": rgName}

	if workflow.ID != nil {
		props["id"] = *workflow.ID
	}
	if workflow.Name != nil {
		props["name"] = *workflow.Name
	}
	if workflow.Location != nil {
		props["location"] = normalizeAzureLocation(*workflow.Location)
	}

	if p := workflow.Properties; p != nil {
		if p.State != nil {
			props["state"] = canonicalizeEnum(string(*p.State),
				"Enabled", "Disabled", "Suspended", "Completed", "Deleted", "NotSpecified")
		}
		if p.IntegrationAccount != nil && p.IntegrationAccount.ID != nil {
			props["integrationAccountId"] = *p.IntegrationAccount.ID
		}
		if p.AccessEndpoint != nil {
			props["accessEndpoint"] = *p.AccessEndpoint
		}
		// definition is declared writeOnly in the schema and is deliberately NOT
		// read back: ARM injects $schema, contentVersion and an empty parameters
		// block, normalises outputs and rewrites recurrence schedules into its own
		// canonical form, so the echo is not comparable against what was authored
		// and would report drift on a workflow nobody touched.
		//
		// version, provisioningState, createdTime, changedTime and the read-only
		// sku are not modelled and are not read back either: version moves on
		// every definition change, the timestamps move on their own, and none of
		// them is desired state.
		//
		// parameters, accessControl and endpointsConfiguration are not modelled
		// for the same reason as definition: a workflow authored in the portal
		// reads without them.
	}

	if tags := azureTagsToFormaeTags(workflow.Tags); tags != nil {
		props["Tags"] = tags
	}

	return props
}

func (w *LogicWorkflow) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props logicWorkflowProps
	if err := props.parse(request.Properties, request.Label); err != nil {
		return nil, err
	}
	params, err := w.params(props, request.Properties)
	if err != nil {
		return nil, err
	}

	result, err := w.api.CreateOrUpdate(ctx, props.ResourceGroupName, props.Name, params, nil)
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
	propsJSON, err := json.Marshal(w.buildPropertiesFromResult(&result.Workflow, props.ResourceGroupName))
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

func (w *LogicWorkflow) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, name, err := logicWorkflowIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := w.api.Get(ctx, rgName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(w.buildPropertiesFromResult(&result.Workflow, rgName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeLogicWorkflow,
		Properties:   string(propsJSON),
	}, nil
}

// Update reissues CreateOrUpdate. WorkflowsClient.Update is a bare PATCH that
// takes no request body in api-version 2019-05-01, so it cannot carry a changed
// definition, state or integration account.
func (w *LogicWorkflow) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, name, err := logicWorkflowIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props logicWorkflowProps
	if err := props.parse(request.DesiredProperties, name); err != nil {
		return nil, err
	}
	params, err := w.params(props, request.DesiredProperties)
	if err != nil {
		return nil, err
	}

	result, err := w.api.CreateOrUpdate(ctx, rgName, name, params, nil)
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

	propsJSON, err := json.Marshal(w.buildPropertiesFromResult(&result.Workflow, rgName))
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

func (w *LogicWorkflow) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, name, err := logicWorkflowIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	if _, err := w.api.Delete(ctx, rgName, name, nil); err != nil && !isDeleteSuccessError(err) {
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
func (w *LogicWorkflow) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

// List pages the resource group when discovery supplies one, and falls back to
// the subscription-wide pager otherwise. resourceGroupName IS supplied by the
// hint's listParam, so the fallback is only reached by a caller that asked for
// everything — it needs no subscriptionWideList entry.
func (w *LogicWorkflow) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]

	var nativeIDs []string

	if rgName != "" {
		pager := w.api.NewListByResourceGroupPager(rgName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list logic workflows: %w", err)
			}
			for _, workflow := range page.Value {
				if workflow != nil && workflow.ID != nil {
					nativeIDs = append(nativeIDs, *workflow.ID)
				}
			}
		}
		return &resource.ListResult{NativeIDs: nativeIDs}, nil
	}

	pager := w.api.NewListBySubscriptionPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list logic workflows: %w", err)
		}
		for _, workflow := range page.Value {
			if workflow != nil && workflow.ID != nil {
				nativeIDs = append(nativeIDs, *workflow.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
