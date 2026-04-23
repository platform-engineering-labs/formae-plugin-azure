// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/postgresql/armpostgresqlflexibleservers/v4"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testFWRuleNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.DBforPostgreSQL/flexibleServers/pg-1/firewallRules/allow-all"

func TestFirewallRule_CRUD(t *testing.T) {
	fake := &fakeFirewallRulesAPI{
		beginCreateOrUpdateFn: func(_ context.Context, _, _, _ string, _ armpostgresqlflexibleservers.FirewallRule, _ *armpostgresqlflexibleservers.FirewallRulesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armpostgresqlflexibleservers.FirewallRulesClientCreateOrUpdateResponse], error) {
			return newDoneCreateFirewallRulePoller(armpostgresqlflexibleservers.FirewallRulesClientCreateOrUpdateResponse{
				FirewallRule: armpostgresqlflexibleservers.FirewallRule{
					ID:   to.Ptr(testFWRuleNativeID),
					Name: to.Ptr("allow-all"),
					Properties: &armpostgresqlflexibleservers.FirewallRuleProperties{
						StartIPAddress: to.Ptr("0.0.0.0"),
						EndIPAddress:   to.Ptr("255.255.255.255"),
					},
				},
			}), nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ *armpostgresqlflexibleservers.FirewallRulesClientGetOptions) (armpostgresqlflexibleservers.FirewallRulesClientGetResponse, error) {
			return armpostgresqlflexibleservers.FirewallRulesClientGetResponse{
				FirewallRule: armpostgresqlflexibleservers.FirewallRule{
					ID:   to.Ptr(testFWRuleNativeID),
					Name: to.Ptr("allow-all"),
					Properties: &armpostgresqlflexibleservers.FirewallRuleProperties{
						StartIPAddress: to.Ptr("0.0.0.0"),
						EndIPAddress:   to.Ptr("255.255.255.255"),
					},
				},
			}, nil
		},
		beginDeleteFn: func(_ context.Context, _, _, _ string, _ *armpostgresqlflexibleservers.FirewallRulesClientBeginDeleteOptions) (*runtime.Poller[armpostgresqlflexibleservers.FirewallRulesClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		},
		newListByServerPagerFn: func(_, _ string, _ *armpostgresqlflexibleservers.FirewallRulesClientListByServerOptions) *runtime.Pager[armpostgresqlflexibleservers.FirewallRulesClientListByServerResponse] {
			return runtime.NewPager(runtime.PagingHandler[armpostgresqlflexibleservers.FirewallRulesClientListByServerResponse]{
				More: func(_ armpostgresqlflexibleservers.FirewallRulesClientListByServerResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armpostgresqlflexibleservers.FirewallRulesClientListByServerResponse) (armpostgresqlflexibleservers.FirewallRulesClientListByServerResponse, error) {
					return armpostgresqlflexibleservers.FirewallRulesClientListByServerResponse{
						FirewallRuleListResult: armpostgresqlflexibleservers.FirewallRuleListResult{
							Value: []*armpostgresqlflexibleservers.FirewallRule{{ID: to.Ptr(testFWRuleNativeID)}},
						},
					}, nil
				},
			})
		},
		newListFlexibleServersPagerFn: func(_ *armpostgresqlflexibleservers.ServersClientListOptions) *runtime.Pager[armpostgresqlflexibleservers.ServersClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armpostgresqlflexibleservers.ServersClientListResponse]{
				More: func(_ armpostgresqlflexibleservers.ServersClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armpostgresqlflexibleservers.ServersClientListResponse) (armpostgresqlflexibleservers.ServersClientListResponse, error) {
					return armpostgresqlflexibleservers.ServersClientListResponse{
						ServerListResult: armpostgresqlflexibleservers.ServerListResult{
							Value: []*armpostgresqlflexibleservers.Server{
								{ID: to.Ptr("/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.DBforPostgreSQL/flexibleServers/pg-1")},
							},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestFirewallRule(fake)

	t.Run("Create", func(t *testing.T) {
		props, _ := json.Marshal(map[string]interface{}{
			"resourceGroupName": "rg-1", "serverName": "pg-1", "name": "allow-all",
			"startIpAddress": "0.0.0.0", "endIpAddress": "255.255.255.255",
		})
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "allow-all", Properties: props})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testFWRuleNativeID, got.ProgressResult.NativeID)
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testFWRuleNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
		var props map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "allow-all", props["name"])
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testFWRuleNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "serverName": "pg-1"},
		})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 1)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _, _ string, _ armpostgresqlflexibleservers.FirewallRule, _ *armpostgresqlflexibleservers.FirewallRulesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armpostgresqlflexibleservers.FirewallRulesClientCreateOrUpdateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 403}
		}
		props, _ := json.Marshal(map[string]interface{}{
			"resourceGroupName": "rg-1", "serverName": "pg-1", "name": "allow-all",
			"startIpAddress": "0.0.0.0", "endIpAddress": "255.255.255.255",
		})
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "allow-all", Properties: props})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

// --- Test helpers ---

func newTestFirewallRule(api firewallRulesAPI) *FirewallRule {
	return &FirewallRule{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

// firewallRuleDoneHandler is a PollingHandler that reports Done() immediately and
// populates out from the stored response on Result().
type firewallRuleDoneHandler[T any] struct {
	resp T
}

func (h *firewallRuleDoneHandler[T]) Done() bool                                     { return true }
func (h *firewallRuleDoneHandler[T]) Poll(_ context.Context) (*http.Response, error) { return nil, nil }
func (h *firewallRuleDoneHandler[T]) Result(_ context.Context, out *T) error         { *out = h.resp; return nil }

func newDoneCreateFirewallRulePoller(resp armpostgresqlflexibleservers.FirewallRulesClientCreateOrUpdateResponse) *runtime.Poller[armpostgresqlflexibleservers.FirewallRulesClientCreateOrUpdateResponse] {
	p, err := runtime.NewPoller[armpostgresqlflexibleservers.FirewallRulesClientCreateOrUpdateResponse](nil, runtime.Pipeline{}, &runtime.NewPollerOptions[armpostgresqlflexibleservers.FirewallRulesClientCreateOrUpdateResponse]{
		Handler: &firewallRuleDoneHandler[armpostgresqlflexibleservers.FirewallRulesClientCreateOrUpdateResponse]{resp: resp},
	})
	if err != nil {
		panic(err)
	}
	return p
}

type fakeFirewallRulesAPI struct {
	beginCreateOrUpdateFn        func(ctx context.Context, rgName, serverName, ruleName string, params armpostgresqlflexibleservers.FirewallRule, opts *armpostgresqlflexibleservers.FirewallRulesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armpostgresqlflexibleservers.FirewallRulesClientCreateOrUpdateResponse], error)
	getFn                        func(ctx context.Context, rgName, serverName, ruleName string, opts *armpostgresqlflexibleservers.FirewallRulesClientGetOptions) (armpostgresqlflexibleservers.FirewallRulesClientGetResponse, error)
	beginDeleteFn                func(ctx context.Context, rgName, serverName, ruleName string, opts *armpostgresqlflexibleservers.FirewallRulesClientBeginDeleteOptions) (*runtime.Poller[armpostgresqlflexibleservers.FirewallRulesClientDeleteResponse], error)
	newListByServerPagerFn       func(rgName, serverName string, opts *armpostgresqlflexibleservers.FirewallRulesClientListByServerOptions) *runtime.Pager[armpostgresqlflexibleservers.FirewallRulesClientListByServerResponse]
	newListFlexibleServersPagerFn func(opts *armpostgresqlflexibleservers.ServersClientListOptions) *runtime.Pager[armpostgresqlflexibleservers.ServersClientListResponse]
	resumeCreatePollerFn         func(token string) (*runtime.Poller[armpostgresqlflexibleservers.FirewallRulesClientCreateOrUpdateResponse], error)
	resumeDeletePollerFn         func(token string) (*runtime.Poller[armpostgresqlflexibleservers.FirewallRulesClientDeleteResponse], error)
}

func (f *fakeFirewallRulesAPI) BeginCreateOrUpdate(ctx context.Context, rgName, serverName, ruleName string, params armpostgresqlflexibleservers.FirewallRule, opts *armpostgresqlflexibleservers.FirewallRulesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armpostgresqlflexibleservers.FirewallRulesClientCreateOrUpdateResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, rgName, serverName, ruleName, params, opts)
}

func (f *fakeFirewallRulesAPI) Get(ctx context.Context, rgName, serverName, ruleName string, opts *armpostgresqlflexibleservers.FirewallRulesClientGetOptions) (armpostgresqlflexibleservers.FirewallRulesClientGetResponse, error) {
	return f.getFn(ctx, rgName, serverName, ruleName, opts)
}

func (f *fakeFirewallRulesAPI) BeginDelete(ctx context.Context, rgName, serverName, ruleName string, opts *armpostgresqlflexibleservers.FirewallRulesClientBeginDeleteOptions) (*runtime.Poller[armpostgresqlflexibleservers.FirewallRulesClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, serverName, ruleName, opts)
}

func (f *fakeFirewallRulesAPI) NewListByServerPager(rgName, serverName string, opts *armpostgresqlflexibleservers.FirewallRulesClientListByServerOptions) *runtime.Pager[armpostgresqlflexibleservers.FirewallRulesClientListByServerResponse] {
	return f.newListByServerPagerFn(rgName, serverName, opts)
}

func (f *fakeFirewallRulesAPI) NewListFlexibleServersPager(opts *armpostgresqlflexibleservers.ServersClientListOptions) *runtime.Pager[armpostgresqlflexibleservers.ServersClientListResponse] {
	return f.newListFlexibleServersPagerFn(opts)
}

func (f *fakeFirewallRulesAPI) ResumeCreatePoller(token string) (*runtime.Poller[armpostgresqlflexibleservers.FirewallRulesClientCreateOrUpdateResponse], error) {
	return f.resumeCreatePollerFn(token)
}

func (f *fakeFirewallRulesAPI) ResumeDeletePoller(token string) (*runtime.Poller[armpostgresqlflexibleservers.FirewallRulesClientDeleteResponse], error) {
	return f.resumeDeletePollerFn(token)
}
