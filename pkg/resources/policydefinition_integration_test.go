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
	testPolicyDefinitionNativeID = "/subscriptions/sub-1/providers/Microsoft.Authorization/policyDefinitions/pd1"
	// Compact, sorted-key form — the shape the provider canonicalises to.
	testPolicyRule = `{"if":{"field":"location","notEquals":"eastus"},"then":{"effect":"audit"}}`
)

type fakePolicyDefinitionsAPI struct {
	createOrUpdateFn func(ctx context.Context, name string, parameters armpolicy.Definition, options *armpolicy.DefinitionsClientCreateOrUpdateOptions) (armpolicy.DefinitionsClientCreateOrUpdateResponse, error)
	getFn            func(ctx context.Context, name string, options *armpolicy.DefinitionsClientGetOptions) (armpolicy.DefinitionsClientGetResponse, error)
	deleteFn         func(ctx context.Context, name string, options *armpolicy.DefinitionsClientDeleteOptions) (armpolicy.DefinitionsClientDeleteResponse, error)
	listPagerFn      func(options *armpolicy.DefinitionsClientListOptions) *runtime.Pager[armpolicy.DefinitionsClientListResponse]
}

func (f *fakePolicyDefinitionsAPI) CreateOrUpdate(ctx context.Context, name string, parameters armpolicy.Definition, options *armpolicy.DefinitionsClientCreateOrUpdateOptions) (armpolicy.DefinitionsClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, name, parameters, options)
}

func (f *fakePolicyDefinitionsAPI) Get(ctx context.Context, name string, options *armpolicy.DefinitionsClientGetOptions) (armpolicy.DefinitionsClientGetResponse, error) {
	return f.getFn(ctx, name, options)
}

func (f *fakePolicyDefinitionsAPI) Delete(ctx context.Context, name string, options *armpolicy.DefinitionsClientDeleteOptions) (armpolicy.DefinitionsClientDeleteResponse, error) {
	return f.deleteFn(ctx, name, options)
}

func (f *fakePolicyDefinitionsAPI) NewListPager(options *armpolicy.DefinitionsClientListOptions) *runtime.Pager[armpolicy.DefinitionsClientListResponse] {
	return f.listPagerFn(options)
}

func newTestPolicyDefinition(api policyDefinitionsAPI) *PolicyDefinition {
	return &PolicyDefinition{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func policyDefinitionDesired(displayName, rule string) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":        "pd1",
		"displayName": displayName,
		"description": "conformance test policy",
		"mode":        "Indexed",
		"policyRule":  rule,
	})
	return out
}

// policyRuleObject is what ARM echoes back: a decoded JSON document, not a string.
func policyRuleObject() any {
	var parsed any
	_ = json.Unmarshal([]byte(testPolicyRule), &parsed)
	return parsed
}

func TestPolicyDefinition_CRUD(t *testing.T) {
	definitionResult := armpolicy.Definition{
		ID:   to.Ptr(testPolicyDefinitionNativeID),
		Name: to.Ptr("pd1"),
		Properties: &armpolicy.DefinitionProperties{
			DisplayName: to.Ptr("audit resources outside eastus"),
			Description: to.Ptr("conformance test policy"),
			Mode:        to.Ptr("Indexed"),
			PolicyType:  to.Ptr(armpolicy.PolicyTypeCustom),
			PolicyRule:  policyRuleObject(),
			// Arbitrary JSON the schema does not model, plus service state.
			Parameters: map[string]*armpolicy.ParameterDefinitionsValue{
				"unmodelledParam": {Type: to.Ptr(armpolicy.ParameterTypeString)},
			},
			Metadata: map[string]any{"category": "unmodelled-metadata"},
			Version:  to.Ptr("1.0.0"),
		},
	}

	var sentName string
	var sent armpolicy.Definition
	writeCalls := 0
	deleteCalls := 0
	fake := &fakePolicyDefinitionsAPI{
		createOrUpdateFn: func(_ context.Context, name string, parameters armpolicy.Definition, _ *armpolicy.DefinitionsClientCreateOrUpdateOptions) (armpolicy.DefinitionsClientCreateOrUpdateResponse, error) {
			sentName, sent = name, parameters
			writeCalls++
			return armpolicy.DefinitionsClientCreateOrUpdateResponse{Definition: definitionResult}, nil
		},
		getFn: func(_ context.Context, _ string, _ *armpolicy.DefinitionsClientGetOptions) (armpolicy.DefinitionsClientGetResponse, error) {
			return armpolicy.DefinitionsClientGetResponse{Definition: definitionResult}, nil
		},
		deleteFn: func(_ context.Context, name string, _ *armpolicy.DefinitionsClientDeleteOptions) (armpolicy.DefinitionsClientDeleteResponse, error) {
			sentName = name
			deleteCalls++
			return armpolicy.DefinitionsClientDeleteResponse{}, nil
		},
		listPagerFn: func(_ *armpolicy.DefinitionsClientListOptions) *runtime.Pager[armpolicy.DefinitionsClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armpolicy.DefinitionsClientListResponse]{
				More: func(_ armpolicy.DefinitionsClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armpolicy.DefinitionsClientListResponse) (armpolicy.DefinitionsClientListResponse, error) {
					return armpolicy.DefinitionsClientListResponse{
						DefinitionListResult: armpolicy.DefinitionListResult{
							Value: []*armpolicy.Definition{
								{
									ID:         to.Ptr(testPolicyDefinitionNativeID),
									Properties: &armpolicy.DefinitionProperties{PolicyType: to.Ptr(armpolicy.PolicyTypeCustom)},
								},
								// Built-in and static definitions are read-only.
								{
									ID:         to.Ptr("/providers/Microsoft.Authorization/policyDefinitions/builtin-1"),
									Properties: &armpolicy.DefinitionProperties{PolicyType: to.Ptr(armpolicy.PolicyTypeBuiltIn)},
								},
								{
									ID:         to.Ptr("/providers/Microsoft.Authorization/policyDefinitions/static-1"),
									Properties: &armpolicy.DefinitionProperties{PolicyType: to.Ptr(armpolicy.PolicyTypeStatic)},
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
	prov := newTestPolicyDefinition(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "pd1", Properties: policyDefinitionDesired("audit resources outside eastus", testPolicyRule),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testPolicyDefinitionNativeID, got.ProgressResult.NativeID)

		require.Equal(t, "pd1", sentName)
		require.Equal(t, "audit resources outside eastus", *sent.Properties.DisplayName)
		require.Equal(t, "Indexed", *sent.Properties.Mode)
		// ARM only accepts Custom: built-in definitions are read-only.
		require.Equal(t, armpolicy.PolicyTypeCustom, *sent.Properties.PolicyType)

		// The rule must go out as a decoded document, not as a JSON string.
		rule, ok := sent.Properties.PolicyRule.(map[string]any)
		require.True(t, ok, "policyRule should be sent decoded, got %T", sent.Properties.PolicyRule)
		require.Contains(t, rule, "if")
		require.Contains(t, rule, "then")
	})

	t.Run("Create_requires_policy_rule", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "pd1", "displayName": "x"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "policyRule is required")
	})

	t.Run("Create_requires_display_name", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "pd1", "policyRule": testPolicyRule})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "displayName is required")
	})

	// A rule that is not JSON at all must be refused before the request goes out,
	// with a message that says which field is wrong.
	t.Run("Create_rejects_malformed_policy_rule", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "pd1", "displayName": "x", "policyRule": "{not json",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "policyRule is not valid JSON")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testPolicyDefinitionNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "pd1", props["name"])
		require.Equal(t, "audit resources outside eastus", props["displayName"])
		require.Equal(t, "conformance test policy", props["description"])
		require.Equal(t, "Indexed", props["mode"])
		require.Equal(t, "Custom", props["policyType"])
		// The decoded document must come back as the same canonical string that was
		// written, or every sync reports drift.
		require.Equal(t, testPolicyRule, props["policyRule"])
	})

	// Whatever spacing and key order the author used, the round trip has to land on
	// one canonical form.
	t.Run("Read_canonicalizes_regardless_of_input_formatting", func(t *testing.T) {
		messy := "{\n  \"then\" : { \"effect\": \"audit\" },\n  \"if\": {\n    \"notEquals\": \"eastus\",\n    \"field\": \"location\"\n  }\n}"
		canonical, _, err := canonicalJSON(messy)
		require.NoError(t, err)
		require.Equal(t, testPolicyRule, canonical)
	})

	t.Run("Read_drops_unmodelled_and_service_state", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testPolicyDefinitionNativeID})
		require.NoError(t, err)
		for _, key := range []string{
			"parameters", "unmodelledParam", "metadata", "unmodelled-metadata",
			"version", "versions", "systemData",
		} {
			require.NotContains(t, got.Properties, key)
		}
	})

	t.Run("IDParts_rejects_other_resource_ids", func(t *testing.T) {
		name, err := policyDefinitionIDParts(testPolicyDefinitionNativeID)
		require.NoError(t, err)
		require.Equal(t, "pd1", name)

		// Casing varies by caller.
		name, err = policyDefinitionIDParts("/subscriptions/sub-1/providers/microsoft.authorization/policydefinitions/pd2")
		require.NoError(t, err)
		require.Equal(t, "pd2", name)

		_, err = policyDefinitionIDParts("/subscriptions/sub-1/resourceGroups/rg-1")
		require.ErrorContains(t, err, "not a policy definition resource ID")
	})

	// CreateOrUpdate is the only write verb this API has.
	t.Run("Update_reissues_create_or_update", func(t *testing.T) {
		before := writeCalls
		revised := `{"if":{"field":"location","notEquals":"westus"},"then":{"effect":"deny"}}`
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testPolicyDefinitionNativeID,
			DesiredProperties: policyDefinitionDesired("audit resources outside westus", revised),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, writeCalls)
		require.Equal(t, "audit resources outside westus", *sent.Properties.DisplayName)

		rule := sent.Properties.PolicyRule.(map[string]any)
		require.Equal(t, "deny", rule["then"].(map[string]any)["effect"])
	})

	t.Run("Delete", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testPolicyDefinitionNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
		require.Equal(t, "pd1", sentName)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _ string, _ *armpolicy.DefinitionsClientDeleteOptions) (armpolicy.DefinitionsClientDeleteResponse, error) {
			return armpolicy.DefinitionsClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testPolicyDefinitionNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Status_is_always_success", func(t *testing.T) {
		got, err := prov.Status(context.Background(), &resource.StatusRequest{RequestID: "whatever"})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	// The subscription listing also carries built-in and static definitions, which
	// this provider cannot manage.
	t.Run("List_returns_only_custom_definitions", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Equal(t, []string{testPolicyDefinitionNativeID}, got.NativeIDs)
	})

	t.Run("Read_NotFound", func(t *testing.T) {
		fake.getFn = func(_ context.Context, _ string, _ *armpolicy.DefinitionsClientGetOptions) (armpolicy.DefinitionsClientGetResponse, error) {
			return armpolicy.DefinitionsClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testPolicyDefinitionNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
	})
}
