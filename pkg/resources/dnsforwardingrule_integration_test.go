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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/dnsresolver/armdnsresolver"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testForwardingRuleNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/dnsForwardingRulesets/ruleset-1/forwardingRules/rule-1"

func newTestForwardingRule(api dnsForwardingRulesAPI) *DNSForwardingRule {
	return &DNSForwardingRule{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func forwardingRuleDesired(state string) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":                     "rule-1",
		"resourceGroupName":        "rg-1",
		"dnsForwardingRulesetName": "ruleset-1",
		"domainName":               "contoso.com.",
		"targetDnsServers": []any{
			map[string]any{"ipAddress": "10.0.0.4", "port": 53},
			map[string]any{"ipAddress": "10.0.0.5", "port": 5353},
		},
		"forwardingRuleState": state,
	})
	return out
}

func TestDNSForwardingRule_CRUD(t *testing.T) {
	ruleResult := armdnsresolver.ForwardingRule{
		ID:   to.Ptr(testForwardingRuleNativeID),
		Name: to.Ptr("rule-1"),
		Properties: &armdnsresolver.ForwardingRuleProperties{
			DomainName:          to.Ptr("contoso.com."),
			ForwardingRuleState: to.Ptr(armdnsresolver.ForwardingRuleStateEnabled),
			ProvisioningState:   to.Ptr(armdnsresolver.ProvisioningStateSucceeded),
			TargetDNSServers: []*armdnsresolver.TargetDNSServer{
				{IPAddress: to.Ptr("10.0.0.4"), Port: to.Ptr(int32(53))},
				{IPAddress: to.Ptr("10.0.0.5"), Port: to.Ptr(int32(53))},
			},
		},
	}

	var sentCreate armdnsresolver.ForwardingRule
	var sentPatch armdnsresolver.ForwardingRulePatch
	var sawRuleset string
	deleteCalls := 0
	fake := &fakeForwardingRulesAPI{
		createOrUpdateFn: func(_ context.Context, _, rulesetName, name string, params armdnsresolver.ForwardingRule, _ *armdnsresolver.ForwardingRulesClientCreateOrUpdateOptions) (armdnsresolver.ForwardingRulesClientCreateOrUpdateResponse, error) {
			require.Equal(t, "rule-1", name)
			sawRuleset = rulesetName
			sentCreate = params
			return armdnsresolver.ForwardingRulesClientCreateOrUpdateResponse{ForwardingRule: ruleResult}, nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ *armdnsresolver.ForwardingRulesClientGetOptions) (armdnsresolver.ForwardingRulesClientGetResponse, error) {
			return armdnsresolver.ForwardingRulesClientGetResponse{ForwardingRule: ruleResult}, nil
		},
		updateFn: func(_ context.Context, _, _, _ string, params armdnsresolver.ForwardingRulePatch, _ *armdnsresolver.ForwardingRulesClientUpdateOptions) (armdnsresolver.ForwardingRulesClientUpdateResponse, error) {
			sentPatch = params
			return armdnsresolver.ForwardingRulesClientUpdateResponse{ForwardingRule: ruleResult}, nil
		},
		deleteFn: func(_ context.Context, _, _, _ string, _ *armdnsresolver.ForwardingRulesClientDeleteOptions) (armdnsresolver.ForwardingRulesClientDeleteResponse, error) {
			deleteCalls++
			return armdnsresolver.ForwardingRulesClientDeleteResponse{}, nil
		},
		newListPagerFn: func(_, _ string, _ *armdnsresolver.ForwardingRulesClientListOptions) *runtime.Pager[armdnsresolver.ForwardingRulesClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armdnsresolver.ForwardingRulesClientListResponse]{
				More: func(_ armdnsresolver.ForwardingRulesClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armdnsresolver.ForwardingRulesClientListResponse) (armdnsresolver.ForwardingRulesClientListResponse, error) {
					return armdnsresolver.ForwardingRulesClientListResponse{
						ForwardingRuleListResult: armdnsresolver.ForwardingRuleListResult{
							Value: []*armdnsresolver.ForwardingRule{{ID: to.Ptr(testForwardingRuleNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestForwardingRule(fake)

	// Create is synchronous: success comes back directly, with no resume token.
	t.Run("Create_is_synchronous", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "rule-1",
			Properties: forwardingRuleDesired("Enabled"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testForwardingRuleNativeID, got.ProgressResult.NativeID)
		require.Empty(t, got.ProgressResult.RequestID)

		require.Equal(t, "ruleset-1", sawRuleset)
		require.Equal(t, "contoso.com.", *sentCreate.Properties.DomainName)
		require.Equal(t, armdnsresolver.ForwardingRuleStateEnabled, *sentCreate.Properties.ForwardingRuleState)
		require.Len(t, sentCreate.Properties.TargetDNSServers, 2)
		require.Equal(t, "10.0.0.4", *sentCreate.Properties.TargetDNSServers[0].IPAddress)
		require.EqualValues(t, 53, *sentCreate.Properties.TargetDNSServers[0].Port)
		require.EqualValues(t, 5353, *sentCreate.Properties.TargetDNSServers[1].Port)
	})

	t.Run("Create_requires_domain_name", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "rule-1", "resourceGroupName": "rg-1", "dnsForwardingRulesetName": "ruleset-1",
			"targetDnsServers": []any{map[string]any{"ipAddress": "10.0.0.4"}},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "domainName is required")
	})

	t.Run("Create_requires_target_servers", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "rule-1", "resourceGroupName": "rg-1",
			"dnsForwardingRulesetName": "ruleset-1", "domainName": "contoso.com.",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "targetDnsServers is required")
	})

	t.Run("Create_requires_ruleset", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "rule-1", "resourceGroupName": "rg-1"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "dnsForwardingRulesetName is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testForwardingRuleNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "rule-1", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		// Both parents come from the native ID, not the response body.
		require.Equal(t, "ruleset-1", props["dnsForwardingRulesetName"])
		require.Equal(t, "contoso.com.", props["domainName"])
		require.Equal(t, "Enabled", props["forwardingRuleState"])

		servers := props["targetDnsServers"].([]any)
		require.Len(t, servers, 2)
		// Order is desired state: ARM tries the servers in the order given, so read
		// must not sort them.
		require.Equal(t, "10.0.0.4", servers[0].(map[string]any)["ipAddress"])
		require.Equal(t, "10.0.0.5", servers[1].(map[string]any)["ipAddress"])
	})

	t.Run("Read_drops_provisioning_state", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testForwardingRuleNativeID})
		require.NoError(t, err)
		require.NotContains(t, got.Properties, "provisioningState")
	})

	// The patch body carries the rule state and the target servers; domainName is
	// createOnly because ForwardingRulePatchProperties has no field for it.
	t.Run("Update_is_synchronous", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testForwardingRuleNativeID,
			DesiredProperties: forwardingRuleDesired("Disabled"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Empty(t, got.ProgressResult.RequestID)
		require.Equal(t, armdnsresolver.ForwardingRuleStateDisabled, *sentPatch.Properties.ForwardingRuleState)
		require.Len(t, sentPatch.Properties.TargetDNSServers, 2)
	})

	t.Run("Delete_is_synchronous", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testForwardingRuleNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Empty(t, got.ProgressResult.RequestID)
		require.Equal(t, before+1, deleteCalls)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _, _ string, _ *armdnsresolver.ForwardingRulesClientDeleteOptions) (armdnsresolver.ForwardingRulesClientDeleteResponse, error) {
			return armdnsresolver.ForwardingRulesClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testForwardingRuleNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_ruleset", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "dnsForwardingRulesetName": "ruleset-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testForwardingRuleNativeID}, got.NativeIDs)
	})

	t.Run("List_without_parents_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.createOrUpdateFn = func(_ context.Context, _, _, _ string, _ armdnsresolver.ForwardingRule, _ *armdnsresolver.ForwardingRulesClientCreateOrUpdateOptions) (armdnsresolver.ForwardingRulesClientCreateOrUpdateResponse, error) {
			return armdnsresolver.ForwardingRulesClientCreateOrUpdateResponse{}, &azcore.ResponseError{StatusCode: 409}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "rule-1", Properties: forwardingRuleDesired("Enabled"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

func TestDNSForwardingRule_ReadNotFound(t *testing.T) {
	fake := &fakeForwardingRulesAPI{
		getFn: func(_ context.Context, _, _, _ string, _ *armdnsresolver.ForwardingRulesClientGetOptions) (armdnsresolver.ForwardingRulesClientGetResponse, error) {
			return armdnsresolver.ForwardingRulesClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestForwardingRule(fake).Read(context.Background(), &resource.ReadRequest{NativeID: testForwardingRuleNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeForwardingRulesAPI struct {
	createOrUpdateFn func(ctx context.Context, rgName, rulesetName, name string, params armdnsresolver.ForwardingRule, options *armdnsresolver.ForwardingRulesClientCreateOrUpdateOptions) (armdnsresolver.ForwardingRulesClientCreateOrUpdateResponse, error)
	getFn            func(ctx context.Context, rgName, rulesetName, name string, options *armdnsresolver.ForwardingRulesClientGetOptions) (armdnsresolver.ForwardingRulesClientGetResponse, error)
	updateFn         func(ctx context.Context, rgName, rulesetName, name string, params armdnsresolver.ForwardingRulePatch, options *armdnsresolver.ForwardingRulesClientUpdateOptions) (armdnsresolver.ForwardingRulesClientUpdateResponse, error)
	deleteFn         func(ctx context.Context, rgName, rulesetName, name string, options *armdnsresolver.ForwardingRulesClientDeleteOptions) (armdnsresolver.ForwardingRulesClientDeleteResponse, error)
	newListPagerFn   func(rgName, rulesetName string, options *armdnsresolver.ForwardingRulesClientListOptions) *runtime.Pager[armdnsresolver.ForwardingRulesClientListResponse]
}

func (f *fakeForwardingRulesAPI) CreateOrUpdate(ctx context.Context, rgName, rulesetName, name string, params armdnsresolver.ForwardingRule, options *armdnsresolver.ForwardingRulesClientCreateOrUpdateOptions) (armdnsresolver.ForwardingRulesClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, rulesetName, name, params, options)
}

func (f *fakeForwardingRulesAPI) Get(ctx context.Context, rgName, rulesetName, name string, options *armdnsresolver.ForwardingRulesClientGetOptions) (armdnsresolver.ForwardingRulesClientGetResponse, error) {
	return f.getFn(ctx, rgName, rulesetName, name, options)
}

func (f *fakeForwardingRulesAPI) Update(ctx context.Context, rgName, rulesetName, name string, params armdnsresolver.ForwardingRulePatch, options *armdnsresolver.ForwardingRulesClientUpdateOptions) (armdnsresolver.ForwardingRulesClientUpdateResponse, error) {
	return f.updateFn(ctx, rgName, rulesetName, name, params, options)
}

func (f *fakeForwardingRulesAPI) Delete(ctx context.Context, rgName, rulesetName, name string, options *armdnsresolver.ForwardingRulesClientDeleteOptions) (armdnsresolver.ForwardingRulesClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, rulesetName, name, options)
}

func (f *fakeForwardingRulesAPI) NewListPager(rgName, rulesetName string, options *armdnsresolver.ForwardingRulesClientListOptions) *runtime.Pager[armdnsresolver.ForwardingRulesClientListResponse] {
	return f.newListPagerFn(rgName, rulesetName, options)
}

// port is a nested field, where hasProviderDefault is NOT honoured: ARM echoes the
// port it defaulted to and conformance then rejects it as "not expected and not a
// provider default". The schema therefore requires it — but an omitted port must
// still be left out of the request so ARM defaults it, rather than sent as 0.
func TestDNSForwardingRule_OmittedPortIsNotSentAsZero(t *testing.T) {
	servers := dnsTargetServers([]dnsTargetServerProps{{IPAddress: "10.0.0.4"}})
	require.Len(t, servers, 1)
	require.Nil(t, servers[0].Port)
}
