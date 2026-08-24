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

const testRelayAuthRuleNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Relay/namespaces/relay1/authorizationRules/rule-1"

func newTestRelayAuthRule(api relayNamespaceAuthRulesAPI) *RelayNamespaceAuthorizationRule {
	return &RelayNamespaceAuthorizationRule{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func relayAuthRuleDesired(rights []string) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":              "rule-1",
		"resourceGroupName": "rg-1",
		"namespaceName":     "relay1",
		"rights":            rights,
	})
	return out
}

func TestRelayNamespaceAuthorizationRule_CRUD(t *testing.T) {
	ruleResult := armrelay.AuthorizationRule{
		ID:   to.Ptr(testRelayAuthRuleNativeID),
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
	fake := &fakeRelayAuthRulesAPI{
		createOrUpdateFn: func(_ context.Context, _, namespaceName, name string, params armrelay.AuthorizationRule, _ *armrelay.NamespacesClientCreateOrUpdateAuthorizationRuleOptions) (armrelay.NamespacesClientCreateOrUpdateAuthorizationRuleResponse, error) {
			require.Equal(t, "rule-1", name)
			sawNamespace = namespaceName
			sentRule = params
			createCalls++
			return armrelay.NamespacesClientCreateOrUpdateAuthorizationRuleResponse{AuthorizationRule: ruleResult}, nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ *armrelay.NamespacesClientGetAuthorizationRuleOptions) (armrelay.NamespacesClientGetAuthorizationRuleResponse, error) {
			return armrelay.NamespacesClientGetAuthorizationRuleResponse{AuthorizationRule: ruleResult}, nil
		},
		deleteFn: func(_ context.Context, _, _, _ string, _ *armrelay.NamespacesClientDeleteAuthorizationRuleOptions) (armrelay.NamespacesClientDeleteAuthorizationRuleResponse, error) {
			deleteCalls++
			return armrelay.NamespacesClientDeleteAuthorizationRuleResponse{}, nil
		},
		newListPagerFn: func(_, _ string, _ *armrelay.NamespacesClientListAuthorizationRulesOptions) *runtime.Pager[armrelay.NamespacesClientListAuthorizationRulesResponse] {
			return runtime.NewPager(runtime.PagingHandler[armrelay.NamespacesClientListAuthorizationRulesResponse]{
				More: func(_ armrelay.NamespacesClientListAuthorizationRulesResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armrelay.NamespacesClientListAuthorizationRulesResponse) (armrelay.NamespacesClientListAuthorizationRulesResponse, error) {
					return armrelay.NamespacesClientListAuthorizationRulesResponse{
						AuthorizationRuleListResult: armrelay.AuthorizationRuleListResult{
							Value: []*armrelay.AuthorizationRule{{ID: to.Ptr(testRelayAuthRuleNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestRelayAuthRule(fake)

	// Create is synchronous: success comes back directly, with no resume token.
	t.Run("Create_is_synchronous", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "rule-1",
			Properties: relayAuthRuleDesired([]string{"Listen", "Send"}),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testRelayAuthRuleNativeID, got.ProgressResult.NativeID)
		require.Empty(t, got.ProgressResult.RequestID)

		require.Equal(t, "relay1", sawNamespace)
		require.Len(t, sentRule.Properties.Rights, 2)
		require.Equal(t, armrelay.AccessRightsListen, *sentRule.Properties.Rights[0])
		require.Equal(t, armrelay.AccessRightsSend, *sentRule.Properties.Rights[1])
	})

	t.Run("Create_requires_rights", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "rule-1", "resourceGroupName": "rg-1", "namespaceName": "relay1",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "rights is required")
	})

	t.Run("Create_requires_namespace", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "rule-1", "resourceGroupName": "rg-1"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "namespaceName is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testRelayAuthRuleNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "rule-1", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		// Both parents come from the native ID, not the response body.
		require.Equal(t, "relay1", props["namespaceName"])
		// Order is echoed as ARM returns it, not sorted: sorting would make a
		// desired list written in another order look like drift.
		require.Equal(t, []any{"Listen", "Send"}, props["rights"])
	})

	// Keys and connection strings come from a separate ListKeys call and must not
	// reach state on any path.
	t.Run("keys_never_serialized", func(t *testing.T) {
		read, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testRelayAuthRuleNativeID})
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
			NativeID:          testRelayAuthRuleNativeID,
			DesiredProperties: relayAuthRuleDesired([]string{"Listen", "Send", "Manage"}),
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
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testRelayAuthRuleNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Empty(t, got.ProgressResult.RequestID)
		require.Equal(t, before+1, deleteCalls)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _, _ string, _ *armrelay.NamespacesClientDeleteAuthorizationRuleOptions) (armrelay.NamespacesClientDeleteAuthorizationRuleResponse, error) {
			return armrelay.NamespacesClientDeleteAuthorizationRuleResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testRelayAuthRuleNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_namespace", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "namespaceName": "relay1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testRelayAuthRuleNativeID}, got.NativeIDs)
	})

	t.Run("List_without_parents_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.createOrUpdateFn = func(_ context.Context, _, _, _ string, _ armrelay.AuthorizationRule, _ *armrelay.NamespacesClientCreateOrUpdateAuthorizationRuleOptions) (armrelay.NamespacesClientCreateOrUpdateAuthorizationRuleResponse, error) {
			return armrelay.NamespacesClientCreateOrUpdateAuthorizationRuleResponse{}, &azcore.ResponseError{StatusCode: 409}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "rule-1", Properties: relayAuthRuleDesired([]string{"Listen"}),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

func TestRelayNamespaceAuthorizationRule_ReadNotFound(t *testing.T) {
	fake := &fakeRelayAuthRulesAPI{
		getFn: func(_ context.Context, _, _, _ string, _ *armrelay.NamespacesClientGetAuthorizationRuleOptions) (armrelay.NamespacesClientGetAuthorizationRuleResponse, error) {
			return armrelay.NamespacesClientGetAuthorizationRuleResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestRelayAuthRule(fake).Read(context.Background(), &resource.ReadRequest{NativeID: testRelayAuthRuleNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeRelayAuthRulesAPI struct {
	createOrUpdateFn func(ctx context.Context, rgName, namespaceName, name string, params armrelay.AuthorizationRule, options *armrelay.NamespacesClientCreateOrUpdateAuthorizationRuleOptions) (armrelay.NamespacesClientCreateOrUpdateAuthorizationRuleResponse, error)
	getFn            func(ctx context.Context, rgName, namespaceName, name string, options *armrelay.NamespacesClientGetAuthorizationRuleOptions) (armrelay.NamespacesClientGetAuthorizationRuleResponse, error)
	deleteFn         func(ctx context.Context, rgName, namespaceName, name string, options *armrelay.NamespacesClientDeleteAuthorizationRuleOptions) (armrelay.NamespacesClientDeleteAuthorizationRuleResponse, error)
	newListPagerFn   func(rgName, namespaceName string, options *armrelay.NamespacesClientListAuthorizationRulesOptions) *runtime.Pager[armrelay.NamespacesClientListAuthorizationRulesResponse]
}

func (f *fakeRelayAuthRulesAPI) CreateOrUpdateAuthorizationRule(ctx context.Context, rgName, namespaceName, name string, params armrelay.AuthorizationRule, options *armrelay.NamespacesClientCreateOrUpdateAuthorizationRuleOptions) (armrelay.NamespacesClientCreateOrUpdateAuthorizationRuleResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, namespaceName, name, params, options)
}

func (f *fakeRelayAuthRulesAPI) GetAuthorizationRule(ctx context.Context, rgName, namespaceName, name string, options *armrelay.NamespacesClientGetAuthorizationRuleOptions) (armrelay.NamespacesClientGetAuthorizationRuleResponse, error) {
	return f.getFn(ctx, rgName, namespaceName, name, options)
}

func (f *fakeRelayAuthRulesAPI) DeleteAuthorizationRule(ctx context.Context, rgName, namespaceName, name string, options *armrelay.NamespacesClientDeleteAuthorizationRuleOptions) (armrelay.NamespacesClientDeleteAuthorizationRuleResponse, error) {
	return f.deleteFn(ctx, rgName, namespaceName, name, options)
}

func (f *fakeRelayAuthRulesAPI) NewListAuthorizationRulesPager(rgName, namespaceName string, options *armrelay.NamespacesClientListAuthorizationRulesOptions) *runtime.Pager[armrelay.NamespacesClientListAuthorizationRulesResponse] {
	return f.newListPagerFn(rgName, namespaceName, options)
}
