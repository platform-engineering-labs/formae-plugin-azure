// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const (
	testPolicyAssignmentScope    = "/subscriptions/sub-1/resourceGroups/rg-1"
	testPolicyAssignmentNativeID = testPolicyAssignmentScope + "/providers/Microsoft.Authorization/policyAssignments/pa1"
	testAssignedDefinitionID     = "/subscriptions/sub-1/providers/Microsoft.Authorization/policyDefinitions/pd1"
)

type fakePolicyAssignmentsAPI struct {
	createFn     func(ctx context.Context, scope, name string, parameters armpolicy.Assignment, options *armpolicy.AssignmentsClientCreateOptions) (armpolicy.AssignmentsClientCreateResponse, error)
	getFn        func(ctx context.Context, scope, name string, options *armpolicy.AssignmentsClientGetOptions) (armpolicy.AssignmentsClientGetResponse, error)
	deleteFn     func(ctx context.Context, scope, name string, options *armpolicy.AssignmentsClientDeleteOptions) (armpolicy.AssignmentsClientDeleteResponse, error)
	listPagerFn  func(options *armpolicy.AssignmentsClientListOptions) *runtime.Pager[armpolicy.AssignmentsClientListResponse]
	listForRGPFn func(rgName string, options *armpolicy.AssignmentsClientListForResourceGroupOptions) *runtime.Pager[armpolicy.AssignmentsClientListForResourceGroupResponse]
}

func (f *fakePolicyAssignmentsAPI) Create(ctx context.Context, scope, name string, parameters armpolicy.Assignment, options *armpolicy.AssignmentsClientCreateOptions) (armpolicy.AssignmentsClientCreateResponse, error) {
	return f.createFn(ctx, scope, name, parameters, options)
}

func (f *fakePolicyAssignmentsAPI) Get(ctx context.Context, scope, name string, options *armpolicy.AssignmentsClientGetOptions) (armpolicy.AssignmentsClientGetResponse, error) {
	return f.getFn(ctx, scope, name, options)
}

func (f *fakePolicyAssignmentsAPI) Delete(ctx context.Context, scope, name string, options *armpolicy.AssignmentsClientDeleteOptions) (armpolicy.AssignmentsClientDeleteResponse, error) {
	return f.deleteFn(ctx, scope, name, options)
}

func (f *fakePolicyAssignmentsAPI) NewListPager(options *armpolicy.AssignmentsClientListOptions) *runtime.Pager[armpolicy.AssignmentsClientListResponse] {
	return f.listPagerFn(options)
}

func (f *fakePolicyAssignmentsAPI) NewListForResourceGroupPager(rgName string, options *armpolicy.AssignmentsClientListForResourceGroupOptions) *runtime.Pager[armpolicy.AssignmentsClientListForResourceGroupResponse] {
	return f.listForRGPFn(rgName, options)
}

func newTestPolicyAssignment(api policyAssignmentsAPI) *PolicyAssignment {
	return &PolicyAssignment{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func policyAssignmentDesired(description string, notScopes []any) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":               "pa1",
		"scope":              testPolicyAssignmentScope,
		"policyDefinitionId": testAssignedDefinitionID,
		"displayName":        "audit resources outside eastus",
		"description":        description,
		"enforcementMode":    "DoNotEnforce",
		"notScopes":          notScopes,
		"nonComplianceMessages": []any{map[string]any{
			"message": "resources must live in eastus",
		}},
	})
	return out
}

func TestPolicyAssignment_CRUD(t *testing.T) {
	assignmentResult := armpolicy.Assignment{
		ID:   to.Ptr(testPolicyAssignmentNativeID),
		Name: to.Ptr("pa1"),
		Properties: &armpolicy.AssignmentProperties{
			PolicyDefinitionID: to.Ptr(testAssignedDefinitionID),
			DisplayName:        to.Ptr("audit resources outside eastus"),
			Description:        to.Ptr("conformance test assignment"),
			EnforcementMode:    to.Ptr(armpolicy.EnforcementModeDoNotEnforce),
			NonComplianceMessages: []*armpolicy.NonComplianceMessage{{
				Message: to.Ptr("resources must live in eastus"),
			}},
			// Unmodelled configuration plus the service's own view.
			Parameters: map[string]*armpolicy.ParameterValuesValue{
				"unmodelledParam": {Value: "x"},
			},
			Metadata:                   map[string]any{"createdBy": "unmodelled-metadata"},
			Scope:                      to.Ptr(testPolicyAssignmentScope),
			InstanceID:                 to.Ptr("instance-1"),
			AssignmentType:             to.Ptr(armpolicy.AssignmentTypeCustom),
			LatestDefinitionVersion:    to.Ptr("1.*.*"),
			EffectiveDefinitionVersion: to.Ptr("1.0.0"),
		},
	}

	var sentScope, sentName string
	var sent armpolicy.Assignment
	writeCalls := 0
	deleteCalls := 0
	fake := &fakePolicyAssignmentsAPI{
		createFn: func(_ context.Context, scope, name string, parameters armpolicy.Assignment, _ *armpolicy.AssignmentsClientCreateOptions) (armpolicy.AssignmentsClientCreateResponse, error) {
			sentScope, sentName, sent = scope, name, parameters
			writeCalls++
			return armpolicy.AssignmentsClientCreateResponse{Assignment: assignmentResult}, nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armpolicy.AssignmentsClientGetOptions) (armpolicy.AssignmentsClientGetResponse, error) {
			return armpolicy.AssignmentsClientGetResponse{Assignment: assignmentResult}, nil
		},
		deleteFn: func(_ context.Context, scope, name string, _ *armpolicy.AssignmentsClientDeleteOptions) (armpolicy.AssignmentsClientDeleteResponse, error) {
			sentScope, sentName = scope, name
			deleteCalls++
			return armpolicy.AssignmentsClientDeleteResponse{}, nil
		},
		listPagerFn: func(_ *armpolicy.AssignmentsClientListOptions) *runtime.Pager[armpolicy.AssignmentsClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armpolicy.AssignmentsClientListResponse]{
				More: func(_ armpolicy.AssignmentsClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armpolicy.AssignmentsClientListResponse) (armpolicy.AssignmentsClientListResponse, error) {
					return armpolicy.AssignmentsClientListResponse{
						AssignmentListResult: armpolicy.AssignmentListResult{
							Value: []*armpolicy.Assignment{
								{ID: to.Ptr(testPolicyAssignmentNativeID)},
								{ID: to.Ptr("/subscriptions/sub-1/providers/Microsoft.Authorization/policyAssignments/pa2")},
								// A nil entry must not panic the walk.
								nil,
							},
						},
					}, nil
				},
			})
		},
		listForRGPFn: func(rgName string, _ *armpolicy.AssignmentsClientListForResourceGroupOptions) *runtime.Pager[armpolicy.AssignmentsClientListForResourceGroupResponse] {
			require.Equal(t, "rg-1", rgName)
			return runtime.NewPager(runtime.PagingHandler[armpolicy.AssignmentsClientListForResourceGroupResponse]{
				More: func(_ armpolicy.AssignmentsClientListForResourceGroupResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armpolicy.AssignmentsClientListForResourceGroupResponse) (armpolicy.AssignmentsClientListForResourceGroupResponse, error) {
					return armpolicy.AssignmentsClientListForResourceGroupResponse{
						AssignmentListResult: armpolicy.AssignmentListResult{
							Value: []*armpolicy.Assignment{{ID: to.Ptr(testPolicyAssignmentNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestPolicyAssignment(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "pa1", Properties: policyAssignmentDesired("conformance test assignment", nil),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testPolicyAssignmentNativeID, got.ProgressResult.NativeID)

		// The scope addresses the resource; it is not part of the body.
		require.Equal(t, testPolicyAssignmentScope, sentScope)
		require.Equal(t, "pa1", sentName)
		require.Equal(t, testAssignedDefinitionID, *sent.Properties.PolicyDefinitionID)
		require.Equal(t, armpolicy.EnforcementModeDoNotEnforce, *sent.Properties.EnforcementMode)
		require.Equal(t, "resources must live in eastus", *sent.Properties.NonComplianceMessages[0].Message)
		require.Nil(t, sent.Properties.Scope)
		require.Nil(t, sent.Properties.Parameters)
	})

	t.Run("Create_requires_definition", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "pa1", "scope": testPolicyAssignmentScope})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "policyDefinitionId is required")
	})

	t.Run("Create_requires_scope", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "pa1", "policyDefinitionId": testAssignedDefinitionID})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "scope is required")
	})

	// An assignment that declares no messages must not carry an empty list.
	t.Run("Create_omits_unset_optionals", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "pa1", "scope": testPolicyAssignmentScope,
			"policyDefinitionId": testAssignedDefinitionID,
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.Nil(t, sent.Properties.NonComplianceMessages)
		require.Nil(t, sent.Properties.NotScopes)
		require.Nil(t, sent.Properties.EnforcementMode)
	})

	// ARM only reports this at PUT time, and its wording does not say what to do.
	t.Run("Create_rejects_several_messages_for_one_definition", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "pa1", "scope": testPolicyAssignmentScope,
			"policyDefinitionId": testAssignedDefinitionID,
			"nonComplianceMessages": []any{
				map[string]any{"message": "first"},
				map[string]any{"message": "second"},
			},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "only one nonComplianceMessage is allowed")
	})

	// An initiative may carry one message per referenced definition.
	t.Run("Create_allows_several_messages_with_reference_ids", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "pa1", "scope": testPolicyAssignmentScope,
			"policyDefinitionId": testAssignedDefinitionID,
			"nonComplianceMessages": []any{
				map[string]any{"message": "first", "policyDefinitionReferenceId": "ref-1"},
				map[string]any{"message": "second", "policyDefinitionReferenceId": "ref-2"},
			},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.Len(t, sent.Properties.NonComplianceMessages, 2)
		require.Equal(t, "ref-1", *sent.Properties.NonComplianceMessages[0].PolicyDefinitionReferenceID)
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testPolicyAssignmentNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "pa1", props["name"])
		// The scope comes off the native ID, not from the body's own echo.
		require.Equal(t, testPolicyAssignmentScope, props["scope"])
		require.Equal(t, testAssignedDefinitionID, props["policyDefinitionId"])
		require.Equal(t, "audit resources outside eastus", props["displayName"])
		require.Equal(t, "conformance test assignment", props["description"])
		require.Equal(t, "DoNotEnforce", props["enforcementMode"])

		messages := props["nonComplianceMessages"].([]any)
		message := messages[0].(map[string]any)
		require.Equal(t, "resources must live in eastus", message["message"])
		// Absent for a single definition, so it must not appear as "".
		require.NotContains(t, message, "policyDefinitionReferenceId")
	})

	t.Run("Read_drops_unmodelled_and_service_state", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testPolicyAssignmentNativeID})
		require.NoError(t, err)
		for _, key := range []string{
			"parameters", "unmodelledParam", "metadata", "unmodelled-metadata",
			"instanceId", "assignmentType", "latestDefinitionVersion",
			"effectiveDefinitionVersion", "systemData", "identity",
		} {
			require.NotContains(t, got.Properties, key)
		}
	})

	t.Run("IDParts_handles_any_scope_and_casing", func(t *testing.T) {
		scope, name, err := policyAssignmentIDParts(testPolicyAssignmentNativeID)
		require.NoError(t, err)
		require.Equal(t, testPolicyAssignmentScope, scope)
		require.Equal(t, "pa1", name)

		scope, name, err = policyAssignmentIDParts("/providers/Microsoft.Management/managementGroups/mg-1/providers/microsoft.authorization/policyassignments/pa3")
		require.NoError(t, err)
		require.Equal(t, "/providers/Microsoft.Management/managementGroups/mg-1", scope)
		require.Equal(t, "pa3", name)

		_, _, err = policyAssignmentIDParts("/subscriptions/sub-1/resourceGroups/rg-1")
		require.ErrorContains(t, err, "not a policy assignment resource ID")
	})

	// Create is the only write verb this API has.
	t.Run("Update_reissues_create", func(t *testing.T) {
		before := writeCalls
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID: testPolicyAssignmentNativeID,
			DesiredProperties: policyAssignmentDesired("conformance test assignment, revised",
				[]any{testPolicyAssignmentScope + "/providers/Microsoft.Storage/storageAccounts/exempt"}),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, writeCalls)
		require.Equal(t, "conformance test assignment, revised", *sent.Properties.Description)
		require.Len(t, sent.Properties.NotScopes, 1)
		require.Equal(t, testPolicyAssignmentScope, sentScope)
	})

	t.Run("Delete", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testPolicyAssignmentNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
		require.Equal(t, testPolicyAssignmentScope, sentScope)
		require.Equal(t, "pa1", sentName)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _ string, _ *armpolicy.AssignmentsClientDeleteOptions) (armpolicy.AssignmentsClientDeleteResponse, error) {
			return armpolicy.AssignmentsClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testPolicyAssignmentNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Status_is_always_success", func(t *testing.T) {
		got, err := prov.Status(context.Background(), &resource.StatusRequest{RequestID: "whatever"})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	// A resource-group scope has its own pager; anything broader falls back to the
	// subscription listing.
	t.Run("List_uses_resource_group_pager_for_group_scope", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"scope": testPolicyAssignmentScope},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testPolicyAssignmentNativeID}, got.NativeIDs)
	})

	t.Run("List_without_scope_is_subscription_wide", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 2)
	})

	// A scope naming an individual resource reaches past a group, and has no
	// group-level pager of its own.
	t.Run("ResourceGroupFromScope", func(t *testing.T) {
		require.Equal(t, "rg-1", policyAssignmentResourceGroupFromScope(testPolicyAssignmentScope))
		require.Equal(t, "rg-1", policyAssignmentResourceGroupFromScope("/subscriptions/sub-1/resourcegroups/rg-1"))
		require.Empty(t, policyAssignmentResourceGroupFromScope("/subscriptions/sub-1"))
		require.Empty(t, policyAssignmentResourceGroupFromScope(testPolicyAssignmentScope+"/providers/Microsoft.Storage/storageAccounts/sa1"))
		require.Empty(t, policyAssignmentResourceGroupFromScope("/providers/Microsoft.Management/managementGroups/mg-1"))
	})

	t.Run("Read_NotFound", func(t *testing.T) {
		fake.getFn = func(_ context.Context, _, _ string, _ *armpolicy.AssignmentsClientGetOptions) (armpolicy.AssignmentsClientGetResponse, error) {
			return armpolicy.AssignmentsClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testPolicyAssignmentNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
	})
}
