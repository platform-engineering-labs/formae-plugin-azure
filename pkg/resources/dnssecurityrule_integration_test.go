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

const (
	testSecurityRuleNativeID     = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/dnsResolverPolicies/policy-1/dnsSecurityRules/rule-1"
	testSecurityRuleDomainListID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/dnsResolverDomainLists/list-1"
)

func newTestSecurityRule(api dnsSecurityRulesAPI) *DNSSecurityRule {
	return &DNSSecurityRule{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func securityRuleDesired(state string) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":                     "rule-1",
		"location":                 "eastus",
		"resourceGroupName":        "rg-1",
		"dnsResolverPolicyName":    "policy-1",
		"action":                   map[string]any{"actionType": "Block"},
		"dnsResolverDomainListIds": []any{testSecurityRuleDomainListID},
		"priority":                 100,
		"dnsSecurityRuleState":     state,
		"Tags":                     []any{map[string]any{"Key": "env", "Value": "test"}},
	})
	return out
}

func TestDNSSecurityRule_CRUD(t *testing.T) {
	linkResult := armdnsresolver.DNSSecurityRule{
		ID:   to.Ptr(testSecurityRuleNativeID),
		Name: to.Ptr("rule-1"),
		Properties: &armdnsresolver.DNSSecurityRuleProperties{
			Action:                 &armdnsresolver.DNSSecurityRuleAction{ActionType: to.Ptr(armdnsresolver.ActionTypeBlock)},
			DNSResolverDomainLists: []*armdnsresolver.SubResource{{ID: to.Ptr(testSecurityRuleDomainListID)}},
			Priority:               to.Ptr(int32(100)),
			DNSSecurityRuleState:   to.Ptr(armdnsresolver.DNSSecurityRuleStateEnabled),
			ProvisioningState:      to.Ptr(armdnsresolver.ProvisioningStateSucceeded),
		},
	}

	var sentCreate armdnsresolver.DNSSecurityRule
	var sentPatch armdnsresolver.DNSSecurityRulePatch
	var sawPolicy string
	deleteCalls := 0
	fake := &fakeSecurityRulesAPI{
		beginCreateOrUpdateFn: func(_ context.Context, _, policyName, name string, params armdnsresolver.DNSSecurityRule, _ *armdnsresolver.DNSSecurityRulesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armdnsresolver.DNSSecurityRulesClientCreateOrUpdateResponse], error) {
			require.Equal(t, "rule-1", name)
			sawPolicy = policyName
			sentCreate = params
			return newDonePoller(armdnsresolver.DNSSecurityRulesClientCreateOrUpdateResponse{DNSSecurityRule: linkResult}), nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ *armdnsresolver.DNSSecurityRulesClientGetOptions) (armdnsresolver.DNSSecurityRulesClientGetResponse, error) {
			return armdnsresolver.DNSSecurityRulesClientGetResponse{DNSSecurityRule: linkResult}, nil
		},
		beginUpdateFn: func(_ context.Context, _, _, _ string, params armdnsresolver.DNSSecurityRulePatch, _ *armdnsresolver.DNSSecurityRulesClientBeginUpdateOptions) (*runtime.Poller[armdnsresolver.DNSSecurityRulesClientUpdateResponse], error) {
			sentPatch = params
			return newDonePoller(armdnsresolver.DNSSecurityRulesClientUpdateResponse{DNSSecurityRule: linkResult}), nil
		},
		beginDeleteFn: func(_ context.Context, _, _, _ string, _ *armdnsresolver.DNSSecurityRulesClientBeginDeleteOptions) (*runtime.Poller[armdnsresolver.DNSSecurityRulesClientDeleteResponse], error) {
			deleteCalls++
			return newDonePoller(armdnsresolver.DNSSecurityRulesClientDeleteResponse{}), nil
		},
		newListPagerFn: func(_, _ string, _ *armdnsresolver.DNSSecurityRulesClientListOptions) *runtime.Pager[armdnsresolver.DNSSecurityRulesClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armdnsresolver.DNSSecurityRulesClientListResponse]{
				More: func(_ armdnsresolver.DNSSecurityRulesClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armdnsresolver.DNSSecurityRulesClientListResponse) (armdnsresolver.DNSSecurityRulesClientListResponse, error) {
					return armdnsresolver.DNSSecurityRulesClientListResponse{
						DNSSecurityRuleListResult: armdnsresolver.DNSSecurityRuleListResult{
							Value: []*armdnsresolver.DNSSecurityRule{{ID: to.Ptr(testSecurityRuleNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestSecurityRule(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "rule-1",
			Properties: securityRuleDesired("Enabled"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testSecurityRuleNativeID, got.ProgressResult.NativeID)
		require.Equal(t, "policy-1", sawPolicy)
		require.Equal(t, armdnsresolver.ActionTypeBlock, *sentCreate.Properties.Action.ActionType)
		require.Len(t, sentCreate.Properties.DNSResolverDomainLists, 1)
		require.Equal(t, testSecurityRuleDomainListID, *sentCreate.Properties.DNSResolverDomainLists[0].ID)
		require.EqualValues(t, 100, *sentCreate.Properties.Priority)
	})

	t.Run("Create_requires_action", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "rule-1", "location": "eastus",
			"resourceGroupName": "rg-1", "dnsResolverPolicyName": "policy-1",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "action.actionType is required")
	})

	t.Run("Create_requires_policy", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "rule-1", "resourceGroupName": "rg-1",
			"action":                   map[string]any{"actionType": "Block"},
			"dnsResolverDomainListIds": []any{testSecurityRuleDomainListID},
			"priority":                 100,
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "dnsResolverPolicyName is required")
	})

	t.Run("Create_requires_domain_lists", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "rule-1", "location": "eastus", "resourceGroupName": "rg-1",
			"dnsResolverPolicyName": "policy-1",
			"action":                map[string]any{"actionType": "Block"},
			"priority":              100,
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "dnsResolverDomainListIds is required")
	})

	t.Run("Create_requires_priority", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "rule-1", "location": "eastus", "resourceGroupName": "rg-1",
			"dnsResolverPolicyName":    "policy-1",
			"action":                   map[string]any{"actionType": "Block"},
			"dnsResolverDomainListIds": []any{testSecurityRuleDomainListID},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "priority is required")
	})

	// An unset state must be left out of the request so ARM applies its own
	// default rather than receiving an empty string.
	t.Run("Create_without_state_sends_none", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "rule-1", "location": "eastus", "resourceGroupName": "rg-1",
			"dnsResolverPolicyName":    "policy-1",
			"action":                   map[string]any{"actionType": "Block"},
			"dnsResolverDomainListIds": []any{testSecurityRuleDomainListID},
			"priority":                 100,
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.Nil(t, sentCreate.Properties.DNSSecurityRuleState)
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testSecurityRuleNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "rule-1", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		// Both parents come from the native ID, not the response body.
		require.Equal(t, "policy-1", props["dnsResolverPolicyName"])
		require.Equal(t, map[string]any{"actionType": "Block"}, props["action"])
		require.Equal(t, []any{testSecurityRuleDomainListID}, props["dnsResolverDomainListIds"])
		require.EqualValues(t, 100, props["priority"])
		require.Equal(t, "Enabled", props["dnsSecurityRuleState"])

	})

	t.Run("Read_drops_provisioning_state", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testSecurityRuleNativeID})
		require.NoError(t, err)
		require.NotContains(t, got.Properties, "provisioningState")
	})

	// DNSSecurityRulePatchProperties carries the action, the domain lists, the
	// priority and the state, nested under "properties" the way ARM expects —
	// unlike the forwarding ruleset's patch model.
	t.Run("Update_sends_properties", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testSecurityRuleNativeID,
			DesiredProperties: securityRuleDesired("Disabled"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, armdnsresolver.DNSSecurityRuleStateDisabled, *sentPatch.Properties.DNSSecurityRuleState)
		require.Equal(t, armdnsresolver.ActionTypeBlock, *sentPatch.Properties.Action.ActionType)
		require.Len(t, sentPatch.Properties.DNSResolverDomainLists, 1)
		require.EqualValues(t, 100, *sentPatch.Properties.Priority)
	})

	t.Run("Delete", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testSecurityRuleNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _, _ string, _ *armdnsresolver.DNSSecurityRulesClientBeginDeleteOptions) (*runtime.Poller[armdnsresolver.DNSSecurityRulesClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testSecurityRuleNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_policy", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "dnsResolverPolicyName": "policy-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testSecurityRuleNativeID}, got.NativeIDs)
	})

	t.Run("List_without_parents_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _, _ string, _ armdnsresolver.DNSSecurityRule, _ *armdnsresolver.DNSSecurityRulesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armdnsresolver.DNSSecurityRulesClientCreateOrUpdateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 409}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "rule-1", Properties: securityRuleDesired("Enabled"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

func TestDNSSecurityRule_ReadNotFound(t *testing.T) {
	fake := &fakeSecurityRulesAPI{
		getFn: func(_ context.Context, _, _, _ string, _ *armdnsresolver.DNSSecurityRulesClientGetOptions) (armdnsresolver.DNSSecurityRulesClientGetResponse, error) {
			return armdnsresolver.DNSSecurityRulesClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestSecurityRule(fake).Read(context.Background(), &resource.ReadRequest{NativeID: testSecurityRuleNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeSecurityRulesAPI struct {
	beginCreateOrUpdateFn func(ctx context.Context, rgName, policyName, name string, params armdnsresolver.DNSSecurityRule, options *armdnsresolver.DNSSecurityRulesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armdnsresolver.DNSSecurityRulesClientCreateOrUpdateResponse], error)
	getFn                 func(ctx context.Context, rgName, policyName, name string, options *armdnsresolver.DNSSecurityRulesClientGetOptions) (armdnsresolver.DNSSecurityRulesClientGetResponse, error)
	beginUpdateFn         func(ctx context.Context, rgName, policyName, name string, params armdnsresolver.DNSSecurityRulePatch, options *armdnsresolver.DNSSecurityRulesClientBeginUpdateOptions) (*runtime.Poller[armdnsresolver.DNSSecurityRulesClientUpdateResponse], error)
	beginDeleteFn         func(ctx context.Context, rgName, policyName, name string, options *armdnsresolver.DNSSecurityRulesClientBeginDeleteOptions) (*runtime.Poller[armdnsresolver.DNSSecurityRulesClientDeleteResponse], error)
	newListPagerFn        func(rgName, policyName string, options *armdnsresolver.DNSSecurityRulesClientListOptions) *runtime.Pager[armdnsresolver.DNSSecurityRulesClientListResponse]
}

func (f *fakeSecurityRulesAPI) BeginCreateOrUpdate(ctx context.Context, rgName, policyName, name string, params armdnsresolver.DNSSecurityRule, options *armdnsresolver.DNSSecurityRulesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armdnsresolver.DNSSecurityRulesClientCreateOrUpdateResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, rgName, policyName, name, params, options)
}

func (f *fakeSecurityRulesAPI) Get(ctx context.Context, rgName, policyName, name string, options *armdnsresolver.DNSSecurityRulesClientGetOptions) (armdnsresolver.DNSSecurityRulesClientGetResponse, error) {
	return f.getFn(ctx, rgName, policyName, name, options)
}

func (f *fakeSecurityRulesAPI) BeginUpdate(ctx context.Context, rgName, policyName, name string, params armdnsresolver.DNSSecurityRulePatch, options *armdnsresolver.DNSSecurityRulesClientBeginUpdateOptions) (*runtime.Poller[armdnsresolver.DNSSecurityRulesClientUpdateResponse], error) {
	return f.beginUpdateFn(ctx, rgName, policyName, name, params, options)
}

func (f *fakeSecurityRulesAPI) BeginDelete(ctx context.Context, rgName, policyName, name string, options *armdnsresolver.DNSSecurityRulesClientBeginDeleteOptions) (*runtime.Poller[armdnsresolver.DNSSecurityRulesClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, policyName, name, options)
}

func (f *fakeSecurityRulesAPI) NewListPager(rgName, policyName string, options *armdnsresolver.DNSSecurityRulesClientListOptions) *runtime.Pager[armdnsresolver.DNSSecurityRulesClientListResponse] {
	return f.newListPagerFn(rgName, policyName, options)
}
