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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/relay/armrelay"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testRelayHCAuthRuleNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Relay/namespaces/relay1/hybridConnections/hc-1/authorizationRules/rule-1"

func newTestRelayHCAuthRule(api relayHybridConnectionAuthRulesAPI) *RelayHybridConnectionAuthorizationRule {
	return &RelayHybridConnectionAuthorizationRule{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func relayHCAuthRuleDesired(rights []string) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":                 "rule-1",
		"resourceGroupName":    "rg-1",
		"namespaceName":        "relay1",
		"hybridConnectionName": "hc-1",
		"rights":               rights,
	})
	return out
}

func TestRelayHybridConnectionAuthorizationRule_CRUD(t *testing.T) {
	ruleResult := armrelay.AuthorizationRule{
		ID:   to.Ptr(testRelayHCAuthRuleNativeID),
		Name: to.Ptr("rule-1"),
		Properties: &armrelay.AuthorizationRuleProperties{
			Rights: []*armrelay.AccessRights{
				to.Ptr(armrelay.AccessRightsListen),
				to.Ptr(armrelay.AccessRightsSend),
			},
		},
	}

	var sentRule armrelay.AuthorizationRule
	var sawNamespace string
	createCalls := 0
	deleteCalls := 0
	fake := &fakeRelayHCAuthRulesAPI{
		createOrUpdateFn: func(_ context.Context, _, namespaceName, hcName, name string, params armrelay.AuthorizationRule, _ *armrelay.HybridConnectionsClientCreateOrUpdateAuthorizationRuleOptions) (armrelay.HybridConnectionsClientCreateOrUpdateAuthorizationRuleResponse, error) {
			require.Equal(t, "rule-1", name)
			sawNamespace = namespaceName
			sentRule = params
			createCalls++
			return armrelay.HybridConnectionsClientCreateOrUpdateAuthorizationRuleResponse{AuthorizationRule: ruleResult}, nil
		},
		getFn: func(_ context.Context, _, _, _, _ string, _ *armrelay.HybridConnectionsClientGetAuthorizationRuleOptions) (armrelay.HybridConnectionsClientGetAuthorizationRuleResponse, error) {
			return armrelay.HybridConnectionsClientGetAuthorizationRuleResponse{AuthorizationRule: ruleResult}, nil
		},
		deleteFn: func(_ context.Context, _, _, _, _ string, _ *armrelay.HybridConnectionsClientDeleteAuthorizationRuleOptions) (armrelay.HybridConnectionsClientDeleteAuthorizationRuleResponse, error) {
			deleteCalls++
			return armrelay.HybridConnectionsClientDeleteAuthorizationRuleResponse{}, nil
		},
		newListPagerFn: func(_, _, _ string, _ *armrelay.HybridConnectionsClientListAuthorizationRulesOptions) *runtime.Pager[armrelay.HybridConnectionsClientListAuthorizationRulesResponse] {
			return runtime.NewPager(runtime.PagingHandler[armrelay.HybridConnectionsClientListAuthorizationRulesResponse]{
				More: func(_ armrelay.HybridConnectionsClientListAuthorizationRulesResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armrelay.HybridConnectionsClientListAuthorizationRulesResponse) (armrelay.HybridConnectionsClientListAuthorizationRulesResponse, error) {
					return armrelay.HybridConnectionsClientListAuthorizationRulesResponse{
						AuthorizationRuleListResult: armrelay.AuthorizationRuleListResult{
							Value: []*armrelay.AuthorizationRule{{ID: to.Ptr(testRelayHCAuthRuleNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestRelayHCAuthRule(fake)

	// Create is synchronous: success comes back directly, with no resume token.
	t.Run("Create_is_synchronous", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "rule-1",
			Properties: relayHCAuthRuleDesired([]string{"Listen", "Send"}),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testRelayHCAuthRuleNativeID, got.ProgressResult.NativeID)
		require.Empty(t, got.ProgressResult.RequestID)

		require.Equal(t, "relay1", sawNamespace)
		require.Len(t, sentRule.Properties.Rights, 2)
		require.Equal(t, armrelay.AccessRightsListen, *sentRule.Properties.Rights[0])
		require.Equal(t, armrelay.AccessRightsSend, *sentRule.Properties.Rights[1])
	})

	t.Run("Create_requires_rights", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "rule-1", "resourceGroupName": "rg-1",
			"namespaceName": "relay1", "hybridConnectionName": "hc-1",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "rights is required")
	})

	t.Run("Create_requires_hybrid_connection", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "rule-1", "resourceGroupName": "rg-1", "namespaceName": "relay1",
			"rights": []any{"Listen"},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "hybridConnectionName is required")
	})

	t.Run("Create_requires_namespace", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "rule-1", "resourceGroupName": "rg-1"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "namespaceName is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testRelayHCAuthRuleNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "rule-1", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		// Both parents come from the native ID, not the response body.
		require.Equal(t, "relay1", props["namespaceName"])
		require.Equal(t, "hc-1", props["hybridConnectionName"])
		// Order is echoed as ARM returns it, not sorted: sorting would make a
		// desired list written in another order look like drift.
		require.Equal(t, []any{"Listen", "Send"}, props["rights"])
	})

	// Keys and connection strings come from a separate ListKeys call and must not
	// reach state on any path.
	t.Run("keys_never_serialized", func(t *testing.T) {
		read, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testRelayHCAuthRuleNativeID})
		require.NoError(t, err)
		for _, key := range []string{"primaryKey", "secondaryKey", "primaryConnectionString", "secondaryConnectionString"} {
			require.NotContains(t, read.Properties, key)
		}
	})

	// No PATCH verb on this API: an update is another CreateOrUpdate, and rights is
	// the only property it can carry.
	t.Run("Update_reissues_create_or_update", func(t *testing.T) {
		before := createCalls
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testRelayHCAuthRuleNativeID,
			DesiredProperties: relayHCAuthRuleDesired([]string{"Listen", "Send", "Manage"}),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Empty(t, got.ProgressResult.RequestID)
		require.Equal(t, before+1, createCalls)
		require.Len(t, sentRule.Properties.Rights, 3)
		require.Equal(t, armrelay.AccessRightsManage, *sentRule.Properties.Rights[2])
	})

	t.Run("Delete_is_synchronous", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testRelayHCAuthRuleNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Empty(t, got.ProgressResult.RequestID)
		require.Equal(t, before+1, deleteCalls)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _, _, _ string, _ *armrelay.HybridConnectionsClientDeleteAuthorizationRuleOptions) (armrelay.HybridConnectionsClientDeleteAuthorizationRuleResponse, error) {
			return armrelay.HybridConnectionsClientDeleteAuthorizationRuleResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testRelayHCAuthRuleNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_hybrid_connection", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{
				"resourceGroupName": "rg-1", "namespaceName": "relay1", "hybridConnectionName": "hc-1",
			},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testRelayHCAuthRuleNativeID}, got.NativeIDs)
	})

	t.Run("List_without_parents_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.createOrUpdateFn = func(_ context.Context, _, _, _, _ string, _ armrelay.AuthorizationRule, _ *armrelay.HybridConnectionsClientCreateOrUpdateAuthorizationRuleOptions) (armrelay.HybridConnectionsClientCreateOrUpdateAuthorizationRuleResponse, error) {
			return armrelay.HybridConnectionsClientCreateOrUpdateAuthorizationRuleResponse{}, &azcore.ResponseError{StatusCode: 409}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "rule-1", Properties: relayHCAuthRuleDesired([]string{"Listen"}),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

func TestRelayHybridConnectionAuthorizationRule_ReadNotFound(t *testing.T) {
	fake := &fakeRelayHCAuthRulesAPI{
		getFn: func(_ context.Context, _, _, _, _ string, _ *armrelay.HybridConnectionsClientGetAuthorizationRuleOptions) (armrelay.HybridConnectionsClientGetAuthorizationRuleResponse, error) {
			return armrelay.HybridConnectionsClientGetAuthorizationRuleResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestRelayHCAuthRule(fake).Read(context.Background(), &resource.ReadRequest{NativeID: testRelayHCAuthRuleNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeRelayHCAuthRulesAPI struct {
	createOrUpdateFn func(ctx context.Context, rgName, namespaceName, hcName, name string, params armrelay.AuthorizationRule, options *armrelay.HybridConnectionsClientCreateOrUpdateAuthorizationRuleOptions) (armrelay.HybridConnectionsClientCreateOrUpdateAuthorizationRuleResponse, error)
	getFn            func(ctx context.Context, rgName, namespaceName, hcName, name string, options *armrelay.HybridConnectionsClientGetAuthorizationRuleOptions) (armrelay.HybridConnectionsClientGetAuthorizationRuleResponse, error)
	deleteFn         func(ctx context.Context, rgName, namespaceName, hcName, name string, options *armrelay.HybridConnectionsClientDeleteAuthorizationRuleOptions) (armrelay.HybridConnectionsClientDeleteAuthorizationRuleResponse, error)
	newListPagerFn   func(rgName, namespaceName, hcName string, options *armrelay.HybridConnectionsClientListAuthorizationRulesOptions) *runtime.Pager[armrelay.HybridConnectionsClientListAuthorizationRulesResponse]
}

func (f *fakeRelayHCAuthRulesAPI) CreateOrUpdateAuthorizationRule(ctx context.Context, rgName, namespaceName, hcName, name string, params armrelay.AuthorizationRule, options *armrelay.HybridConnectionsClientCreateOrUpdateAuthorizationRuleOptions) (armrelay.HybridConnectionsClientCreateOrUpdateAuthorizationRuleResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, namespaceName, hcName, name, params, options)
}

func (f *fakeRelayHCAuthRulesAPI) GetAuthorizationRule(ctx context.Context, rgName, namespaceName, hcName, name string, options *armrelay.HybridConnectionsClientGetAuthorizationRuleOptions) (armrelay.HybridConnectionsClientGetAuthorizationRuleResponse, error) {
	return f.getFn(ctx, rgName, namespaceName, hcName, name, options)
}

func (f *fakeRelayHCAuthRulesAPI) DeleteAuthorizationRule(ctx context.Context, rgName, namespaceName, hcName, name string, options *armrelay.HybridConnectionsClientDeleteAuthorizationRuleOptions) (armrelay.HybridConnectionsClientDeleteAuthorizationRuleResponse, error) {
	return f.deleteFn(ctx, rgName, namespaceName, hcName, name, options)
}

func (f *fakeRelayHCAuthRulesAPI) NewListAuthorizationRulesPager(rgName, namespaceName, hcName string, options *armrelay.HybridConnectionsClientListAuthorizationRulesOptions) *runtime.Pager[armrelay.HybridConnectionsClientListAuthorizationRulesResponse] {
	return f.newListPagerFn(rgName, namespaceName, hcName, options)
}
