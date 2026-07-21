// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build integration

package resources

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v4"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testWAFNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/waf-1"

// fullWAFProps is a maximal property map used by both the round-trip test and
// the CRUD test. It exercises policySettings, a managed rule set, and a custom
// rule with nested matchConditions/matchVariables.
func fullWAFProps() map[string]any {
	return map[string]any{
		"resourceGroupName": "rg-1",
		"name":              "waf-1",
		"location":          "eastus",
		"policySettings": map[string]any{
			"state":                  "Enabled",
			"mode":                   "Prevention",
			"requestBodyCheck":       true,
			"maxRequestBodySizeInKb": 128,
		},
		"managedRules": map[string]any{
			"managedRuleSets": []map[string]any{
				{"ruleSetType": "OWASP", "ruleSetVersion": "3.2"},
			},
		},
		"customRules": []map[string]any{
			{
				"name":     "block-bad-ip",
				"priority": 100,
				"ruleType": "MatchRule",
				"action":   "Block",
				"matchConditions": []map[string]any{
					{
						"matchVariables": []map[string]any{
							{"variableName": "RemoteAddr"},
							{"variableName": "RequestHeaders", "selector": "User-Agent"},
						},
						"operator":         "IPMatch",
						"matchValues":      []any{"192.0.2.0/24", "198.51.100.10"},
						"negationConditon": false,
					},
				},
			},
		},
	}
}

func createWAFProps() json.RawMessage {
	props, _ := json.Marshal(fullWAFProps())
	return props
}

// TestWAFPolicy_MarshallerRoundTrip is the correctness gate for the two bespoke
// marshallers. It builds an armnetwork.WebApplicationFirewallPolicy from a full
// property map, then serializes it back, asserting managed rule sets and custom
// rules (with nested match conditions/variables) survive.
func TestWAFPolicy_MarshallerRoundTrip(t *testing.T) {
	var props map[string]any
	require.NoError(t, json.Unmarshal(createWAFProps(), &props))

	params, err := buildWAFPolicyParams(props, "eastus")
	require.NoError(t, err)
	params.ID = to.Ptr(testWAFNativeID)
	params.Name = to.Ptr("waf-1")

	raw, err := serializeWAFPolicyProperties(params, "rg-1", "waf-1")
	require.NoError(t, err)

	var got map[string]any
	require.NoError(t, json.Unmarshal(raw, &got))

	require.Equal(t, "waf-1", got["name"])
	require.Equal(t, "eastus", got["location"])
	require.Equal(t, testWAFNativeID, got["id"])
	require.Equal(t, "rg-1", got["resourceGroupName"])

	settings := got["policySettings"].(map[string]any)
	require.Equal(t, "Enabled", settings["state"])
	require.Equal(t, "Prevention", settings["mode"])
	require.Equal(t, true, settings["requestBodyCheck"])
	require.EqualValues(t, 128, settings["maxRequestBodySizeInKb"])

	managed := got["managedRules"].(map[string]any)
	sets := managed["managedRuleSets"].([]any)
	require.Len(t, sets, 1)
	set := sets[0].(map[string]any)
	require.Equal(t, "OWASP", set["ruleSetType"])
	require.Equal(t, "3.2", set["ruleSetVersion"])

	rules := got["customRules"].([]any)
	require.Len(t, rules, 1)
	rule := rules[0].(map[string]any)
	require.Equal(t, "block-bad-ip", rule["name"])
	require.EqualValues(t, 100, rule["priority"])
	require.Equal(t, "MatchRule", rule["ruleType"])
	require.Equal(t, "Block", rule["action"])

	conditions := rule["matchConditions"].([]any)
	require.Len(t, conditions, 1)
	cond := conditions[0].(map[string]any)
	require.Equal(t, "IPMatch", cond["operator"])
	require.Equal(t, false, cond["negationConditon"])

	vars := cond["matchVariables"].([]any)
	require.Len(t, vars, 2)
	require.Equal(t, "RemoteAddr", vars[0].(map[string]any)["variableName"])
	require.Equal(t, "RequestHeaders", vars[1].(map[string]any)["variableName"])
	require.Equal(t, "User-Agent", vars[1].(map[string]any)["selector"], "selector must round-trip")

	values := cond["matchValues"].([]any)
	require.Len(t, values, 2)
	require.Equal(t, "192.0.2.0/24", values[0])
	require.Equal(t, "198.51.100.10", values[1])
}

func TestWAFPolicy_CRUD(t *testing.T) {
	var builtProps map[string]any
	require.NoError(t, json.Unmarshal(createWAFProps(), &builtProps))
	built, err := buildWAFPolicyParams(builtProps, "eastus")
	require.NoError(t, err)
	built.ID = to.Ptr(testWAFNativeID)
	built.Name = to.Ptr("waf-1")
	built.Location = to.Ptr("eastus")

	createResp := armnetwork.WebApplicationFirewallPoliciesClientCreateOrUpdateResponse{WebApplicationFirewallPolicy: built}

	fake := &fakeWAFPoliciesAPI{
		createOrUpdateFn: func(_ context.Context, _, _ string, _ armnetwork.WebApplicationFirewallPolicy, _ *armnetwork.WebApplicationFirewallPoliciesClientCreateOrUpdateOptions) (armnetwork.WebApplicationFirewallPoliciesClientCreateOrUpdateResponse, error) {
			return createResp, nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armnetwork.WebApplicationFirewallPoliciesClientGetOptions) (armnetwork.WebApplicationFirewallPoliciesClientGetResponse, error) {
			return armnetwork.WebApplicationFirewallPoliciesClientGetResponse{WebApplicationFirewallPolicy: built}, nil
		},
		beginDeleteFn: func(_ context.Context, _, _ string, _ *armnetwork.WebApplicationFirewallPoliciesClientBeginDeleteOptions) (*runtime.Poller[armnetwork.WebApplicationFirewallPoliciesClientDeleteResponse], error) {
			return newDonePoller(armnetwork.WebApplicationFirewallPoliciesClientDeleteResponse{}), nil
		},
		newListAllPagerFn: func(_ *armnetwork.WebApplicationFirewallPoliciesClientListAllOptions) *runtime.Pager[armnetwork.WebApplicationFirewallPoliciesClientListAllResponse] {
			return runtime.NewPager(runtime.PagingHandler[armnetwork.WebApplicationFirewallPoliciesClientListAllResponse]{
				More: func(_ armnetwork.WebApplicationFirewallPoliciesClientListAllResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armnetwork.WebApplicationFirewallPoliciesClientListAllResponse) (armnetwork.WebApplicationFirewallPoliciesClientListAllResponse, error) {
					return armnetwork.WebApplicationFirewallPoliciesClientListAllResponse{
						WebApplicationFirewallPolicyListResult: armnetwork.WebApplicationFirewallPolicyListResult{
							Value: []*armnetwork.WebApplicationFirewallPolicy{{ID: to.Ptr(testWAFNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestWAFPolicy(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: createWAFProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testWAFNativeID, got.ProgressResult.NativeID)

		var props map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &props))
		require.Equal(t, "waf-1", props["name"])
		rules := props["customRules"].([]any)
		require.Len(t, rules, 1)
		require.Equal(t, "block-bad-ip", rules[0].(map[string]any)["name"])
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testWAFNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "waf-1", props["name"])
	})

	t.Run("Update", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{NativeID: testWAFNativeID, DesiredProperties: createWAFProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Delete", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testWAFNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _ string, _ *armnetwork.WebApplicationFirewallPoliciesClientBeginDeleteOptions) (*runtime.Poller[armnetwork.WebApplicationFirewallPoliciesClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testWAFNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{AdditionalProperties: map[string]string{}})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 1)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.createOrUpdateFn = func(_ context.Context, _, _ string, _ armnetwork.WebApplicationFirewallPolicy, _ *armnetwork.WebApplicationFirewallPoliciesClientCreateOrUpdateOptions) (armnetwork.WebApplicationFirewallPoliciesClientCreateOrUpdateResponse, error) {
			return armnetwork.WebApplicationFirewallPoliciesClientCreateOrUpdateResponse{}, &azcore.ResponseError{StatusCode: 403}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: createWAFProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

// --- Test helpers ---

func newTestWAFPolicy(api wafPoliciesAPI) *WebApplicationFirewallPolicy {
	return &WebApplicationFirewallPolicy{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

type fakeWAFPoliciesAPI struct {
	createOrUpdateFn  func(ctx context.Context, rgName, name string, params armnetwork.WebApplicationFirewallPolicy, opts *armnetwork.WebApplicationFirewallPoliciesClientCreateOrUpdateOptions) (armnetwork.WebApplicationFirewallPoliciesClientCreateOrUpdateResponse, error)
	getFn             func(ctx context.Context, rgName, name string, opts *armnetwork.WebApplicationFirewallPoliciesClientGetOptions) (armnetwork.WebApplicationFirewallPoliciesClientGetResponse, error)
	beginDeleteFn     func(ctx context.Context, rgName, name string, opts *armnetwork.WebApplicationFirewallPoliciesClientBeginDeleteOptions) (*runtime.Poller[armnetwork.WebApplicationFirewallPoliciesClientDeleteResponse], error)
	newListPagerFn    func(rgName string, opts *armnetwork.WebApplicationFirewallPoliciesClientListOptions) *runtime.Pager[armnetwork.WebApplicationFirewallPoliciesClientListResponse]
	newListAllPagerFn func(opts *armnetwork.WebApplicationFirewallPoliciesClientListAllOptions) *runtime.Pager[armnetwork.WebApplicationFirewallPoliciesClientListAllResponse]
}

func (f *fakeWAFPoliciesAPI) CreateOrUpdate(ctx context.Context, rgName, name string, params armnetwork.WebApplicationFirewallPolicy, opts *armnetwork.WebApplicationFirewallPoliciesClientCreateOrUpdateOptions) (armnetwork.WebApplicationFirewallPoliciesClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, name, params, opts)
}

func (f *fakeWAFPoliciesAPI) Get(ctx context.Context, rgName, name string, opts *armnetwork.WebApplicationFirewallPoliciesClientGetOptions) (armnetwork.WebApplicationFirewallPoliciesClientGetResponse, error) {
	return f.getFn(ctx, rgName, name, opts)
}

func (f *fakeWAFPoliciesAPI) BeginDelete(ctx context.Context, rgName, name string, opts *armnetwork.WebApplicationFirewallPoliciesClientBeginDeleteOptions) (*runtime.Poller[armnetwork.WebApplicationFirewallPoliciesClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, name, opts)
}

func (f *fakeWAFPoliciesAPI) NewListPager(rgName string, opts *armnetwork.WebApplicationFirewallPoliciesClientListOptions) *runtime.Pager[armnetwork.WebApplicationFirewallPoliciesClientListResponse] {
	return f.newListPagerFn(rgName, opts)
}

func (f *fakeWAFPoliciesAPI) NewListAllPager(opts *armnetwork.WebApplicationFirewallPoliciesClientListAllOptions) *runtime.Pager[armnetwork.WebApplicationFirewallPoliciesClientListAllResponse] {
	return f.newListAllPagerFn(opts)
}
