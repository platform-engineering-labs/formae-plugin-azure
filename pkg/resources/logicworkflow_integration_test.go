// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/logic/armlogic"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testLogicWorkflowNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Logic/workflows/wf-1"

const testLogicWorkflowDefinition = `{"triggers":{"tick":{"type":"Recurrence","recurrence":{"frequency":"Day","interval":1}}},"actions":{}}`

func newTestLogicWorkflow(api logicWorkflowsAPI) *LogicWorkflow {
	return &LogicWorkflow{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func logicWorkflowDesired(state string) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":              "wf-1",
		"location":          "eastus",
		"resourceGroupName": "rg-1",
		"definition":        testLogicWorkflowDefinition,
		"state":             state,
	})
	return out
}

func TestLogicWorkflow_CRUD(t *testing.T) {
	// ARM's echo of the definition is deliberately NOT what was sent: it injects
	// $schema, contentVersion and an empty parameters block. The provider must
	// not read any of it back.
	workflowResult := armlogic.Workflow{
		ID:       to.Ptr(testLogicWorkflowNativeID),
		Name:     to.Ptr("wf-1"),
		Location: to.Ptr("East US"),
		Properties: &armlogic.WorkflowProperties{
			State:          to.Ptr(armlogic.WorkflowStateEnabled),
			AccessEndpoint: to.Ptr("https://prod-01.eastus.logic.azure.com/workflows/abc"),
			Version:        to.Ptr("08585000000000000000"),
			Definition: map[string]any{
				"$schema":        "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
				"contentVersion": "1.0.0.0",
				"parameters":     map[string]any{},
				"triggers": map[string]any{
					"tick": map[string]any{"type": "Recurrence"},
				},
				"actions":      map[string]any{},
				"outputs":      map[string]any{},
				"$connections": map[string]any{},
			},
			ProvisioningState: to.Ptr(armlogic.WorkflowProvisioningStateSucceeded),
			CreatedTime:       to.Ptr(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)),
			ChangedTime:       to.Ptr(time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)),
		},
	}

	var sentCreate armlogic.Workflow
	createCalls := 0
	deleteCalls := 0
	fake := &fakeLogicWorkflowsAPI{
		createOrUpdateFn: func(_ context.Context, rgName, name string, params armlogic.Workflow, _ *armlogic.WorkflowsClientCreateOrUpdateOptions) (armlogic.WorkflowsClientCreateOrUpdateResponse, error) {
			require.Equal(t, "rg-1", rgName)
			require.Equal(t, "wf-1", name)
			sentCreate = params
			createCalls++
			return armlogic.WorkflowsClientCreateOrUpdateResponse{Workflow: workflowResult}, nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armlogic.WorkflowsClientGetOptions) (armlogic.WorkflowsClientGetResponse, error) {
			return armlogic.WorkflowsClientGetResponse{Workflow: workflowResult}, nil
		},
		deleteFn: func(_ context.Context, _, _ string, _ *armlogic.WorkflowsClientDeleteOptions) (armlogic.WorkflowsClientDeleteResponse, error) {
			deleteCalls++
			return armlogic.WorkflowsClientDeleteResponse{}, nil
		},
		newListByResourceGroupPagerFn: func(_ string, _ *armlogic.WorkflowsClientListByResourceGroupOptions) *runtime.Pager[armlogic.WorkflowsClientListByResourceGroupResponse] {
			return runtime.NewPager(runtime.PagingHandler[armlogic.WorkflowsClientListByResourceGroupResponse]{
				More: func(_ armlogic.WorkflowsClientListByResourceGroupResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armlogic.WorkflowsClientListByResourceGroupResponse) (armlogic.WorkflowsClientListByResourceGroupResponse, error) {
					return armlogic.WorkflowsClientListByResourceGroupResponse{
						WorkflowListResult: armlogic.WorkflowListResult{
							Value: []*armlogic.Workflow{{ID: to.Ptr(testLogicWorkflowNativeID)}},
						},
					}, nil
				},
			})
		},
		newListBySubscriptionPagerFn: func(_ *armlogic.WorkflowsClientListBySubscriptionOptions) *runtime.Pager[armlogic.WorkflowsClientListBySubscriptionResponse] {
			return runtime.NewPager(runtime.PagingHandler[armlogic.WorkflowsClientListBySubscriptionResponse]{
				More: func(_ armlogic.WorkflowsClientListBySubscriptionResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armlogic.WorkflowsClientListBySubscriptionResponse) (armlogic.WorkflowsClientListBySubscriptionResponse, error) {
					return armlogic.WorkflowsClientListBySubscriptionResponse{
						WorkflowListResult: armlogic.WorkflowListResult{
							Value: []*armlogic.Workflow{{ID: to.Ptr(testLogicWorkflowNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestLogicWorkflow(fake)

	// Create is synchronous: WorkflowsClient's only BeginX is BeginMove, which
	// this provisioner does not use, so no resume token is ever produced.
	t.Run("Create_is_synchronous", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "wf-1",
			Properties: logicWorkflowDesired("Enabled"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testLogicWorkflowNativeID, got.ProgressResult.NativeID)
		require.Empty(t, got.ProgressResult.RequestID)

		require.Equal(t, "eastus", *sentCreate.Location)
		require.Equal(t, armlogic.WorkflowStateEnabled, *sentCreate.Properties.State)
		// The definition string is decoded into the untyped object ARM expects.
		definition, ok := sentCreate.Properties.Definition.(map[string]any)
		require.True(t, ok, "definition must reach the SDK as a JSON object")
		require.Contains(t, definition, "triggers")
	})

	t.Run("Create_requires_resource_group", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "wf-1", "location": "eastus", "definition": testLogicWorkflowDefinition})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "resourceGroupName is required")
	})

	t.Run("Create_requires_location", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "wf-1", "resourceGroupName": "rg-1", "definition": testLogicWorkflowDefinition})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "location is required")
	})

	t.Run("Create_requires_definition", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "wf-1", "location": "eastus", "resourceGroupName": "rg-1"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "definition is required")
	})

	// A malformed definition must fail before any ARM call rather than as an
	// opaque 400.
	t.Run("Create_rejects_invalid_definition_json", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "wf-1", "location": "eastus", "resourceGroupName": "rg-1",
			"definition": "{not json",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "definition is not valid JSON")
	})

	// ARM rejects an array or a scalar definition with a message naming neither,
	// so the shape is checked here rather than at the service.
	t.Run("Create_rejects_non_object_definition", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "wf-1", "location": "eastus", "resourceGroupName": "rg-1",
			"definition": `["triggers"]`,
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "definition is not valid JSON")
	})

	t.Run("Create_rejects_empty_definition_object", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "wf-1", "location": "eastus", "resourceGroupName": "rg-1",
			"definition": "{}",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "definition must be a non-empty JSON object")
	})

	// An omitted state must be left out of the body so ARM applies its own
	// default rather than receiving an empty string.
	t.Run("Create_without_state_sends_none", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "wf-1", "location": "eastus", "resourceGroupName": "rg-1",
			"definition": testLogicWorkflowDefinition,
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.Nil(t, sentCreate.Properties.State)
		require.Nil(t, sentCreate.Properties.IntegrationAccount)
	})

	t.Run("Create_with_integration_account", func(t *testing.T) {
		accountID := "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Logic/integrationAccounts/ia-1"
		props, _ := json.Marshal(map[string]any{
			"name": "wf-1", "location": "eastus", "resourceGroupName": "rg-1",
			"definition":           testLogicWorkflowDefinition,
			"integrationAccountId": accountID,
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.Equal(t, accountID, *sentCreate.Properties.IntegrationAccount.ID)
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testLogicWorkflowNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "wf-1", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		// ARM answers "East US"; desired state carries the compact form.
		require.Equal(t, "eastus", props["location"])
		require.Equal(t, "Enabled", props["state"])
		require.Equal(t, "https://prod-01.eastus.logic.azure.com/workflows/abc", props["accessEndpoint"])
	})

	// definition is writeOnly: ARM injects $schema, contentVersion and an empty
	// parameters block, so reading its echo back would report drift on a workflow
	// nobody touched. version and the timestamps move on their own.
	t.Run("Read_drops_definition_and_service_state", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testLogicWorkflowNativeID})
		require.NoError(t, err)
		for _, key := range []string{"definition", "version", "provisioningState", "createdTime", "changedTime", "$schema"} {
			require.NotContains(t, got.Properties, key)
		}
	})

	t.Run("Read_rejects_a_non_workflow_id", func(t *testing.T) {
		_, err := prov.Read(context.Background(), &resource.ReadRequest{
			NativeID: "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Logic/integrationAccounts/ia-1",
		})
		require.Error(t, err)
	})

	// Update reissues CreateOrUpdate: WorkflowsClient.Update is a bare PATCH that
	// takes no request body in 2019-05-01 and so cannot carry a new definition.
	t.Run("Update_reissues_create_or_update", func(t *testing.T) {
		before := createCalls
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testLogicWorkflowNativeID,
			DesiredProperties: logicWorkflowDesired("Disabled"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Empty(t, got.ProgressResult.RequestID)
		require.Equal(t, before+1, createCalls)
		require.Equal(t, armlogic.WorkflowStateDisabled, *sentCreate.Properties.State)
	})

	t.Run("Delete_is_synchronous", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testLogicWorkflowNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Empty(t, got.ProgressResult.RequestID)
		require.Equal(t, before+1, deleteCalls)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _ string, _ *armlogic.WorkflowsClientDeleteOptions) (armlogic.WorkflowsClientDeleteResponse, error) {
			return armlogic.WorkflowsClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testLogicWorkflowNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_resource_group", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testLogicWorkflowNativeID}, got.NativeIDs)
	})

	t.Run("List_falls_back_to_subscription", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Equal(t, []string{testLogicWorkflowNativeID}, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure_with_a_cause", func(t *testing.T) {
		fake.createOrUpdateFn = func(_ context.Context, _, _ string, _ armlogic.Workflow, _ *armlogic.WorkflowsClientCreateOrUpdateOptions) (armlogic.WorkflowsClientCreateOrUpdateResponse, error) {
			return armlogic.WorkflowsClientCreateOrUpdateResponse{}, &azcore.ResponseError{StatusCode: 409}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "wf-1", Properties: logicWorkflowDesired("Enabled"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.NotEmpty(t, got.ProgressResult.StatusMessage)
	})
}

func TestLogicWorkflow_ReadNotFound(t *testing.T) {
	fake := &fakeLogicWorkflowsAPI{
		getFn: func(_ context.Context, _, _ string, _ *armlogic.WorkflowsClientGetOptions) (armlogic.WorkflowsClientGetResponse, error) {
			return armlogic.WorkflowsClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestLogicWorkflow(fake).Read(context.Background(), &resource.ReadRequest{NativeID: testLogicWorkflowNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeLogicWorkflowsAPI struct {
	createOrUpdateFn              func(ctx context.Context, rgName, name string, params armlogic.Workflow, options *armlogic.WorkflowsClientCreateOrUpdateOptions) (armlogic.WorkflowsClientCreateOrUpdateResponse, error)
	getFn                         func(ctx context.Context, rgName, name string, options *armlogic.WorkflowsClientGetOptions) (armlogic.WorkflowsClientGetResponse, error)
	deleteFn                      func(ctx context.Context, rgName, name string, options *armlogic.WorkflowsClientDeleteOptions) (armlogic.WorkflowsClientDeleteResponse, error)
	newListByResourceGroupPagerFn func(rgName string, options *armlogic.WorkflowsClientListByResourceGroupOptions) *runtime.Pager[armlogic.WorkflowsClientListByResourceGroupResponse]
	newListBySubscriptionPagerFn  func(options *armlogic.WorkflowsClientListBySubscriptionOptions) *runtime.Pager[armlogic.WorkflowsClientListBySubscriptionResponse]
}

func (f *fakeLogicWorkflowsAPI) CreateOrUpdate(ctx context.Context, rgName, name string, params armlogic.Workflow, options *armlogic.WorkflowsClientCreateOrUpdateOptions) (armlogic.WorkflowsClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, name, params, options)
}

func (f *fakeLogicWorkflowsAPI) Get(ctx context.Context, rgName, name string, options *armlogic.WorkflowsClientGetOptions) (armlogic.WorkflowsClientGetResponse, error) {
	return f.getFn(ctx, rgName, name, options)
}

func (f *fakeLogicWorkflowsAPI) Delete(ctx context.Context, rgName, name string, options *armlogic.WorkflowsClientDeleteOptions) (armlogic.WorkflowsClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, name, options)
}

func (f *fakeLogicWorkflowsAPI) NewListByResourceGroupPager(rgName string, options *armlogic.WorkflowsClientListByResourceGroupOptions) *runtime.Pager[armlogic.WorkflowsClientListByResourceGroupResponse] {
	return f.newListByResourceGroupPagerFn(rgName, options)
}

func (f *fakeLogicWorkflowsAPI) NewListBySubscriptionPager(options *armlogic.WorkflowsClientListBySubscriptionOptions) *runtime.Pager[armlogic.WorkflowsClientListBySubscriptionResponse] {
	return f.newListBySubscriptionPagerFn(options)
}
