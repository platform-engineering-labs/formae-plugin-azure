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
	testPolicySetDefinitionNativeID = "/subscriptions/sub-1/providers/Microsoft.Authorization/policySetDefinitions/psd1"
	testIncludedDefinitionID        = "/subscriptions/sub-1/providers/Microsoft.Authorization/policyDefinitions/pd1"
)

type fakePolicySetDefinitionsAPI struct {
	createOrUpdateFn func(ctx context.Context, name string, parameters armpolicy.SetDefinition, options *armpolicy.SetDefinitionsClientCreateOrUpdateOptions) (armpolicy.SetDefinitionsClientCreateOrUpdateResponse, error)
	getFn            func(ctx context.Context, name string, options *armpolicy.SetDefinitionsClientGetOptions) (armpolicy.SetDefinitionsClientGetResponse, error)
	deleteFn         func(ctx context.Context, name string, options *armpolicy.SetDefinitionsClientDeleteOptions) (armpolicy.SetDefinitionsClientDeleteResponse, error)
	listPagerFn      func(options *armpolicy.SetDefinitionsClientListOptions) *runtime.Pager[armpolicy.SetDefinitionsClientListResponse]
}

func (f *fakePolicySetDefinitionsAPI) CreateOrUpdate(ctx context.Context, name string, parameters armpolicy.SetDefinition, options *armpolicy.SetDefinitionsClientCreateOrUpdateOptions) (armpolicy.SetDefinitionsClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, name, parameters, options)
}

func (f *fakePolicySetDefinitionsAPI) Get(ctx context.Context, name string, options *armpolicy.SetDefinitionsClientGetOptions) (armpolicy.SetDefinitionsClientGetResponse, error) {
	return f.getFn(ctx, name, options)
}

func (f *fakePolicySetDefinitionsAPI) Delete(ctx context.Context, name string, options *armpolicy.SetDefinitionsClientDeleteOptions) (armpolicy.SetDefinitionsClientDeleteResponse, error) {
	return f.deleteFn(ctx, name, options)
}

func (f *fakePolicySetDefinitionsAPI) NewListPager(options *armpolicy.SetDefinitionsClientListOptions) *runtime.Pager[armpolicy.SetDefinitionsClientListResponse] {
	return f.listPagerFn(options)
}

func newTestPolicySetDefinition(api policySetDefinitionsAPI) *PolicySetDefinition {
	return &PolicySetDefinition{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func policySetDefinitionDesired(displayName string, groupNames []any) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":        "psd1",
		"displayName": displayName,
		"description": "conformance test initiative",
		"policyDefinitions": []any{map[string]any{
			"policyDefinitionId":          testIncludedDefinitionID,
			"policyDefinitionReferenceId": "location-audit",
			"groupNames":                  groupNames,
		}},
		"policyDefinitionGroups": []any{map[string]any{
			"name":        "residency",
			"displayName": "Data residency",
		}},
	})
	return out
}

func TestPolicySetDefinition_CRUD(t *testing.T) {
	definitionResult := armpolicy.SetDefinition{
		ID:   to.Ptr(testPolicySetDefinitionNativeID),
		Name: to.Ptr("psd1"),
		Properties: &armpolicy.SetDefinitionProperties{
			DisplayName: to.Ptr("formae residency initiative"),
			Description: to.Ptr("conformance test initiative"),
			PolicyType:  to.Ptr(armpolicy.PolicyTypeCustom),
			PolicyDefinitions: []*armpolicy.DefinitionReference{{
				PolicyDefinitionID:          to.Ptr(testIncludedDefinitionID),
				PolicyDefinitionReferenceID: to.Ptr("location-audit"),
				GroupNames:                  []*string{to.Ptr("residency")},
				// Service's own view of the referenced definition's versioning.
				EffectiveDefinitionVersion: to.Ptr("1.0.0"),
				LatestDefinitionVersion:    to.Ptr("1.*.*"),
			}},
			PolicyDefinitionGroups: []*armpolicy.DefinitionGroup{{
				Name:        to.Ptr("residency"),
				DisplayName: to.Ptr("Data residency"),
			}},
			// Arbitrary JSON the schema does not model, plus service state.
			Parameters: map[string]*armpolicy.ParameterDefinitionsValue{
				"unmodelledParam": {Type: to.Ptr(armpolicy.ParameterTypeString)},
			},
			Metadata: map[string]any{"category": "unmodelled-metadata"},
			Version:  to.Ptr("1.0.0"),
		},
	}

	var sentName string
	var sent armpolicy.SetDefinition
	writeCalls := 0
	deleteCalls := 0
	fake := &fakePolicySetDefinitionsAPI{
		createOrUpdateFn: func(_ context.Context, name string, parameters armpolicy.SetDefinition, _ *armpolicy.SetDefinitionsClientCreateOrUpdateOptions) (armpolicy.SetDefinitionsClientCreateOrUpdateResponse, error) {
			sentName, sent = name, parameters
			writeCalls++
			return armpolicy.SetDefinitionsClientCreateOrUpdateResponse{SetDefinition: definitionResult}, nil
		},
		getFn: func(_ context.Context, _ string, _ *armpolicy.SetDefinitionsClientGetOptions) (armpolicy.SetDefinitionsClientGetResponse, error) {
			return armpolicy.SetDefinitionsClientGetResponse{SetDefinition: definitionResult}, nil
		},
		deleteFn: func(_ context.Context, name string, _ *armpolicy.SetDefinitionsClientDeleteOptions) (armpolicy.SetDefinitionsClientDeleteResponse, error) {
			sentName = name
			deleteCalls++
			return armpolicy.SetDefinitionsClientDeleteResponse{}, nil
		},
		listPagerFn: func(_ *armpolicy.SetDefinitionsClientListOptions) *runtime.Pager[armpolicy.SetDefinitionsClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armpolicy.SetDefinitionsClientListResponse]{
				More: func(_ armpolicy.SetDefinitionsClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armpolicy.SetDefinitionsClientListResponse) (armpolicy.SetDefinitionsClientListResponse, error) {
					return armpolicy.SetDefinitionsClientListResponse{
						SetDefinitionListResult: armpolicy.SetDefinitionListResult{
							Value: []*armpolicy.SetDefinition{
								{
									ID:         to.Ptr(testPolicySetDefinitionNativeID),
									Properties: &armpolicy.SetDefinitionProperties{PolicyType: to.Ptr(armpolicy.PolicyTypeCustom)},
								},
								// Built-in initiatives are read-only.
								{
									ID:         to.Ptr("/providers/Microsoft.Authorization/policySetDefinitions/builtin-1"),
									Properties: &armpolicy.SetDefinitionProperties{PolicyType: to.Ptr(armpolicy.PolicyTypeBuiltIn)},
								},
								// A nil entry must not panic the walk.
								nil,
							},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestPolicySetDefinition(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "psd1", Properties: policySetDefinitionDesired("formae residency initiative", []any{"residency"}),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testPolicySetDefinitionNativeID, got.ProgressResult.NativeID)

		require.Equal(t, "psd1", sentName)
		require.Equal(t, "formae residency initiative", *sent.Properties.DisplayName)
		require.Equal(t, armpolicy.PolicyTypeCustom, *sent.Properties.PolicyType)

		reference := sent.Properties.PolicyDefinitions[0]
		require.Equal(t, testIncludedDefinitionID, *reference.PolicyDefinitionID)
		require.Equal(t, "location-audit", *reference.PolicyDefinitionReferenceID)
		require.Equal(t, "residency", *reference.GroupNames[0])
		require.Equal(t, "residency", *sent.Properties.PolicyDefinitionGroups[0].Name)
		require.Nil(t, sent.Properties.Parameters)
	})

	t.Run("Create_requires_policy_definitions", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "psd1", "displayName": "x"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "policyDefinitions is required")
	})

	t.Run("Create_requires_definition_id_on_each_inclusion", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "psd1", "displayName": "x",
			"policyDefinitions": []any{map[string]any{"policyDefinitionReferenceId": "ref-1"}},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "policyDefinitionId is required")
	})

	// ARM rejects the whole initiative for this, reporting only a generic invalid
	// request, so the mismatch is caught before the call.
	t.Run("Create_rejects_undeclared_group_reference", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "psd1", "displayName": "x",
			"policyDefinitions": []any{map[string]any{
				"policyDefinitionId": testIncludedDefinitionID,
				"groupNames":         []any{"typo-group"},
			}},
			"policyDefinitionGroups": []any{map[string]any{"name": "residency"}},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, `undeclared group "typo-group"`)
	})

	t.Run("Create_allows_inclusion_without_groups", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "psd1", "displayName": "x",
			"policyDefinitions": []any{map[string]any{"policyDefinitionId": testIncludedDefinitionID}},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.Nil(t, sent.Properties.PolicyDefinitionGroups)
		require.Nil(t, sent.Properties.PolicyDefinitions[0].GroupNames)
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testPolicySetDefinitionNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "psd1", props["name"])
		require.Equal(t, "formae residency initiative", props["displayName"])
		require.Equal(t, "conformance test initiative", props["description"])
		require.Equal(t, "Custom", props["policyType"])

		references := props["policyDefinitions"].([]any)
		reference := references[0].(map[string]any)
		require.Equal(t, testIncludedDefinitionID, reference["policyDefinitionId"])
		require.Equal(t, "location-audit", reference["policyDefinitionReferenceId"])
		require.Equal(t, []any{"residency"}, reference["groupNames"])

		groups := props["policyDefinitionGroups"].([]any)
		group := groups[0].(map[string]any)
		require.Equal(t, "residency", group["name"])
		require.Equal(t, "Data residency", group["displayName"])
		// Absent on this group, so it must not appear as "".
		require.NotContains(t, group, "category")
	})

	t.Run("Read_drops_unmodelled_and_service_state", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testPolicySetDefinitionNativeID})
		require.NoError(t, err)
		for _, key := range []string{
			"parameters", "unmodelledParam", "metadata", "unmodelled-metadata",
			"version", "versions", "systemData", "effectiveDefinitionVersion",
			"latestDefinitionVersion",
		} {
			require.NotContains(t, got.Properties, key)
		}
	})

	t.Run("IDParts_rejects_other_resource_ids", func(t *testing.T) {
		name, err := policySetDefinitionIDParts(testPolicySetDefinitionNativeID)
		require.NoError(t, err)
		require.Equal(t, "psd1", name)

		// Casing varies by caller.
		name, err = policySetDefinitionIDParts("/subscriptions/sub-1/providers/microsoft.authorization/policysetdefinitions/psd2")
		require.NoError(t, err)
		require.Equal(t, "psd2", name)

		// A single policy definition must not be mistaken for an initiative.
		_, err = policySetDefinitionIDParts(testIncludedDefinitionID)
		require.ErrorContains(t, err, "not a policy set definition resource ID")
	})

	// CreateOrUpdate is the only write verb this API has.
	t.Run("Update_reissues_create_or_update", func(t *testing.T) {
		before := writeCalls
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testPolicySetDefinitionNativeID,
			DesiredProperties: policySetDefinitionDesired("formae residency initiative, revised", []any{"residency"}),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, writeCalls)
		require.Equal(t, "formae residency initiative, revised", *sent.Properties.DisplayName)
		require.Equal(t, "psd1", sentName)
	})

	t.Run("Delete", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testPolicySetDefinitionNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
		require.Equal(t, "psd1", sentName)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _ string, _ *armpolicy.SetDefinitionsClientDeleteOptions) (armpolicy.SetDefinitionsClientDeleteResponse, error) {
			return armpolicy.SetDefinitionsClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testPolicySetDefinitionNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Status_is_always_success", func(t *testing.T) {
		got, err := prov.Status(context.Background(), &resource.StatusRequest{RequestID: "whatever"})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_returns_only_custom_initiatives", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Equal(t, []string{testPolicySetDefinitionNativeID}, got.NativeIDs)
	})

	t.Run("Read_NotFound", func(t *testing.T) {
		fake.getFn = func(_ context.Context, _ string, _ *armpolicy.SetDefinitionsClientGetOptions) (armpolicy.SetDefinitionsClientGetResponse, error) {
			return armpolicy.SetDefinitionsClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testPolicySetDefinitionNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
	})
}
