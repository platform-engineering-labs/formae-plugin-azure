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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/sql/armsql"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testSQLFirewallRuleNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Sql/servers/sql-1/firewallRules/rule-1"

func TestSqlFirewallRule_CRUD(t *testing.T) {
	ruleResult := armsql.FirewallRule{
		ID:   to.Ptr(testSQLFirewallRuleNativeID),
		Name: to.Ptr("rule-1"),
		Properties: &armsql.ServerFirewallRuleProperties{
			StartIPAddress: to.Ptr("0.0.0.0"),
			EndIPAddress:   to.Ptr("0.0.0.0"),
		},
	}

	fake := &fakeSQLFirewallRulesAPI{
		createOrUpdateFn: func(_ context.Context, _, _, _ string, _ armsql.FirewallRule, _ *armsql.FirewallRulesClientCreateOrUpdateOptions) (armsql.FirewallRulesClientCreateOrUpdateResponse, error) {
			return armsql.FirewallRulesClientCreateOrUpdateResponse{FirewallRule: ruleResult}, nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ *armsql.FirewallRulesClientGetOptions) (armsql.FirewallRulesClientGetResponse, error) {
			return armsql.FirewallRulesClientGetResponse{FirewallRule: ruleResult}, nil
		},
		deleteFn: func(_ context.Context, _, _, _ string, _ *armsql.FirewallRulesClientDeleteOptions) (armsql.FirewallRulesClientDeleteResponse, error) {
			return armsql.FirewallRulesClientDeleteResponse{}, nil
		},
		newListByServerPagerFn: func(_, _ string, _ *armsql.FirewallRulesClientListByServerOptions) *runtime.Pager[armsql.FirewallRulesClientListByServerResponse] {
			return runtime.NewPager(runtime.PagingHandler[armsql.FirewallRulesClientListByServerResponse]{
				More: func(_ armsql.FirewallRulesClientListByServerResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armsql.FirewallRulesClientListByServerResponse) (armsql.FirewallRulesClientListByServerResponse, error) {
					return armsql.FirewallRulesClientListByServerResponse{
						FirewallRuleListResult: armsql.FirewallRuleListResult{
							Value: []*armsql.FirewallRule{
								{ID: to.Ptr(testSQLFirewallRuleNativeID)},
								{ID: to.Ptr("/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Sql/servers/sql-1/firewallRules/rule-2")},
							},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestSqlFirewallRule(fake)

	t.Run("Create", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName": "rg-1",
			"serverName":        "sql-1",
			"name":              "rule-1",
			"startIpAddress":    "0.0.0.0",
			"endIpAddress":      "0.0.0.0",
		})
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "rule-1", Properties: props})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testSQLFirewallRuleNativeID, got.ProgressResult.NativeID)
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testSQLFirewallRuleNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "rule-1", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "sql-1", props["serverName"])
		require.Equal(t, "0.0.0.0", props["startIpAddress"])
		require.Equal(t, "0.0.0.0", props["endIpAddress"])
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _, _ string, _ *armsql.FirewallRulesClientDeleteOptions) (armsql.FirewallRulesClientDeleteResponse, error) {
			return armsql.FirewallRulesClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testSQLFirewallRuleNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "serverName": "sql-1"},
		})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 2)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.createOrUpdateFn = func(_ context.Context, _, _, _ string, _ armsql.FirewallRule, _ *armsql.FirewallRulesClientCreateOrUpdateOptions) (armsql.FirewallRulesClientCreateOrUpdateResponse, error) {
			return armsql.FirewallRulesClientCreateOrUpdateResponse{}, &azcore.ResponseError{StatusCode: 403}
		}
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName": "rg-1",
			"serverName":        "sql-1",
			"name":              "rule-1",
			"startIpAddress":    "0.0.0.0",
			"endIpAddress":      "0.0.0.0",
		})
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "rule-1", Properties: props})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

// --- Test helpers ---

func newTestSqlFirewallRule(api sqlFirewallRulesAPI) *SqlFirewallRule {
	return &SqlFirewallRule{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

type fakeSQLFirewallRulesAPI struct {
	createOrUpdateFn       func(ctx context.Context, resourceGroupName, serverName, firewallRuleName string, parameters armsql.FirewallRule, options *armsql.FirewallRulesClientCreateOrUpdateOptions) (armsql.FirewallRulesClientCreateOrUpdateResponse, error)
	getFn                  func(ctx context.Context, resourceGroupName, serverName, firewallRuleName string, options *armsql.FirewallRulesClientGetOptions) (armsql.FirewallRulesClientGetResponse, error)
	deleteFn               func(ctx context.Context, resourceGroupName, serverName, firewallRuleName string, options *armsql.FirewallRulesClientDeleteOptions) (armsql.FirewallRulesClientDeleteResponse, error)
	newListByServerPagerFn func(resourceGroupName, serverName string, options *armsql.FirewallRulesClientListByServerOptions) *runtime.Pager[armsql.FirewallRulesClientListByServerResponse]
}

func (f *fakeSQLFirewallRulesAPI) CreateOrUpdate(ctx context.Context, resourceGroupName, serverName, firewallRuleName string, parameters armsql.FirewallRule, options *armsql.FirewallRulesClientCreateOrUpdateOptions) (armsql.FirewallRulesClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, resourceGroupName, serverName, firewallRuleName, parameters, options)
}

func (f *fakeSQLFirewallRulesAPI) Get(ctx context.Context, resourceGroupName, serverName, firewallRuleName string, options *armsql.FirewallRulesClientGetOptions) (armsql.FirewallRulesClientGetResponse, error) {
	return f.getFn(ctx, resourceGroupName, serverName, firewallRuleName, options)
}

func (f *fakeSQLFirewallRulesAPI) Delete(ctx context.Context, resourceGroupName, serverName, firewallRuleName string, options *armsql.FirewallRulesClientDeleteOptions) (armsql.FirewallRulesClientDeleteResponse, error) {
	return f.deleteFn(ctx, resourceGroupName, serverName, firewallRuleName, options)
}

func (f *fakeSQLFirewallRulesAPI) NewListByServerPager(resourceGroupName, serverName string, options *armsql.FirewallRulesClientListByServerOptions) *runtime.Pager[armsql.FirewallRulesClientListByServerResponse] {
	return f.newListByServerPagerFn(resourceGroupName, serverName, options)
}
