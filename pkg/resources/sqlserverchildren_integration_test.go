// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build integration

// Tests for the three name-scoped children of AZURE::Sql::Server added together:
// ServerDnsAlias, OutboundFirewallRule and VirtualNetworkRule. The first two have no
// writable ARM properties; the third does, and that difference is what these tests
// pin down.
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

const (
	testSQLAliasNativeID    = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Sql/servers/srv-1/dnsAliases/alias-1"
	testSQLOutboundNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Sql/servers/srv-1/outboundFirewallRules/storage.blob.core.windows.net"
	testSQLVnetRuleNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Sql/servers/srv-1/virtualNetworkRules/vnet-rule-1"
	testSQLSubnetID         = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/virtualNetworks/vnet-1/subnets/sql"
)

// --- ServerDnsAlias ---

func TestSqlServerDnsAlias_CRUD(t *testing.T) {
	model := armsql.ServerDNSAlias{
		ID:   to.Ptr(testSQLAliasNativeID),
		Name: to.Ptr("alias-1"),
		Properties: &armsql.ServerDNSAliasProperties{
			AzureDNSRecord: to.Ptr("alias-1.database.windows.net"),
		},
	}
	fake := &fakeSQLServerDNSAliasesAPI{
		beginCreateOrUpdateFn: func(_ context.Context, _, _, _ string, _ *armsql.ServerDNSAliasesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armsql.ServerDNSAliasesClientCreateOrUpdateResponse], error) {
			return newDonePoller(armsql.ServerDNSAliasesClientCreateOrUpdateResponse{ServerDNSAlias: model}), nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ *armsql.ServerDNSAliasesClientGetOptions) (armsql.ServerDNSAliasesClientGetResponse, error) {
			return armsql.ServerDNSAliasesClientGetResponse{ServerDNSAlias: model}, nil
		},
		beginDeleteFn: func(_ context.Context, _, _, _ string, _ *armsql.ServerDNSAliasesClientBeginDeleteOptions) (*runtime.Poller[armsql.ServerDNSAliasesClientDeleteResponse], error) {
			return newInProgressPoller[armsql.ServerDNSAliasesClientDeleteResponse](), nil
		},
		newListByServerPagerFn: func(_, _ string, _ *armsql.ServerDNSAliasesClientListByServerOptions) *runtime.Pager[armsql.ServerDNSAliasesClientListByServerResponse] {
			return runtime.NewPager(runtime.PagingHandler[armsql.ServerDNSAliasesClientListByServerResponse]{
				More: func(_ armsql.ServerDNSAliasesClientListByServerResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armsql.ServerDNSAliasesClientListByServerResponse) (armsql.ServerDNSAliasesClientListByServerResponse, error) {
					return armsql.ServerDNSAliasesClientListByServerResponse{
						ServerDNSAliasListResult: armsql.ServerDNSAliasListResult{
							Value: []*armsql.ServerDNSAlias{{ID: to.Ptr(testSQLAliasNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := &SqlServerDnsAlias{api: fake, config: &config.Config{SubscriptionId: "sub-1"}}

	mkProps := func() json.RawMessage {
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName": "rg-1", "serverName": "srv-1", "name": "alias-1",
		})
		return props
	}

	// The alias create carries no request body at all.
	t.Run("Create sends names only and surfaces the assigned hostname", func(t *testing.T) {
		var seenRG, seenServer, seenAlias string
		fake.beginCreateOrUpdateFn = func(_ context.Context, rg, srv, alias string, opts *armsql.ServerDNSAliasesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armsql.ServerDNSAliasesClientCreateOrUpdateResponse], error) {
			seenRG, seenServer, seenAlias = rg, srv, alias
			require.Nil(t, opts)
			return newDonePoller(armsql.ServerDNSAliasesClientCreateOrUpdateResponse{ServerDNSAlias: model}), nil
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testSQLAliasNativeID, got.ProgressResult.NativeID)
		require.Equal(t, []string{"rg-1", "srv-1", "alias-1"}, []string{seenRG, seenServer, seenAlias})

		var serialized map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &serialized))
		require.Equal(t, "alias-1", serialized["name"])
		require.Equal(t, "srv-1", serialized["serverName"])
		require.Equal(t, "alias-1.database.windows.net", serialized["azureDnsRecord"])
	})

	t.Run("Create requires serverName", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"resourceGroupName": "rg-1", "name": "alias-1"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "serverName is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testSQLAliasNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
		require.Equal(t, ResourceTypeSQLServerDNSAlias, got.ResourceType)
	})

	t.Run("Read_not_found", func(t *testing.T) {
		fake.getFn = func(_ context.Context, _, _, _ string, _ *armsql.ServerDNSAliasesClientGetOptions) (armsql.ServerDNSAliasesClientGetResponse, error) {
			return armsql.ServerDNSAliasesClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testSQLAliasNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)

		fake.getFn = func(_ context.Context, _, _, _ string, _ *armsql.ServerDNSAliasesClientGetOptions) (armsql.ServerDNSAliasesClientGetResponse, error) {
			return armsql.ServerDNSAliasesClientGetResponse{ServerDNSAlias: model}, nil
		}
	})

	// Nothing is writable, and repointing an alias is ARM's separate `acquire`
	// operation — Update must never write.
	t.Run("Update only re-reads, never writes", func(t *testing.T) {
		wrote := false
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _, _ string, _ *armsql.ServerDNSAliasesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armsql.ServerDNSAliasesClientCreateOrUpdateResponse], error) {
			wrote = true
			return newDonePoller(armsql.ServerDNSAliasesClientCreateOrUpdateResponse{ServerDNSAlias: model}), nil
		}
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID: testSQLAliasNativeID, DesiredProperties: mkProps(),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.False(t, wrote, "Update must not call BeginCreateOrUpdate")
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _, _ string, _ *armsql.ServerDNSAliasesClientBeginDeleteOptions) (*runtime.Poller[armsql.ServerDNSAliasesClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testSQLAliasNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_server", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "serverName": "srv-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testSQLAliasNativeID}, got.NativeIDs)
	})

	t.Run("IDParts", func(t *testing.T) {
		rg, srv, alias, err := sqlServerDNSAliasIDParts(testSQLAliasNativeID)
		require.NoError(t, err)
		require.Equal(t, []string{"rg-1", "srv-1", "alias-1"}, []string{rg, srv, alias})
		_, _, _, err = sqlServerDNSAliasIDParts(testSQLVnetRuleNativeID)
		require.Error(t, err)
	})
}

// --- OutboundFirewallRule ---

func TestSqlOutboundFirewallRule_CRUD(t *testing.T) {
	model := armsql.OutboundFirewallRule{
		ID:   to.Ptr(testSQLOutboundNativeID),
		Name: to.Ptr("storage.blob.core.windows.net"),
		Properties: &armsql.OutboundFirewallRuleProperties{
			ProvisioningState: to.Ptr("Succeeded"),
		},
	}
	fake := &fakeSQLOutboundFirewallRulesAPI{
		beginCreateOrUpdateFn: func(_ context.Context, _, _, _ string, _ armsql.OutboundFirewallRule, _ *armsql.OutboundFirewallRulesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armsql.OutboundFirewallRulesClientCreateOrUpdateResponse], error) {
			return newDonePoller(armsql.OutboundFirewallRulesClientCreateOrUpdateResponse{OutboundFirewallRule: model}), nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ *armsql.OutboundFirewallRulesClientGetOptions) (armsql.OutboundFirewallRulesClientGetResponse, error) {
			return armsql.OutboundFirewallRulesClientGetResponse{OutboundFirewallRule: model}, nil
		},
		beginDeleteFn: func(_ context.Context, _, _, _ string, _ *armsql.OutboundFirewallRulesClientBeginDeleteOptions) (*runtime.Poller[armsql.OutboundFirewallRulesClientDeleteResponse], error) {
			return newInProgressPoller[armsql.OutboundFirewallRulesClientDeleteResponse](), nil
		},
		newListByServerPagerFn: func(_, _ string, _ *armsql.OutboundFirewallRulesClientListByServerOptions) *runtime.Pager[armsql.OutboundFirewallRulesClientListByServerResponse] {
			return runtime.NewPager(runtime.PagingHandler[armsql.OutboundFirewallRulesClientListByServerResponse]{
				More: func(_ armsql.OutboundFirewallRulesClientListByServerResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armsql.OutboundFirewallRulesClientListByServerResponse) (armsql.OutboundFirewallRulesClientListByServerResponse, error) {
					return armsql.OutboundFirewallRulesClientListByServerResponse{
						OutboundFirewallRuleListResult: armsql.OutboundFirewallRuleListResult{
							Value: []*armsql.OutboundFirewallRule{{ID: to.Ptr(testSQLOutboundNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := &SqlOutboundFirewallRule{api: fake, config: &config.Config{SubscriptionId: "sub-1"}}

	mkProps := func() json.RawMessage {
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName": "rg-1", "serverName": "srv-1",
			"name": "storage.blob.core.windows.net",
		})
		return props
	}

	// The permitted destination IS the resource name — an FQDN, not a property.
	t.Run("Create passes the FQDN as the resource name", func(t *testing.T) {
		var seenFqdn string
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _, fqdn string, _ armsql.OutboundFirewallRule, _ *armsql.OutboundFirewallRulesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armsql.OutboundFirewallRulesClientCreateOrUpdateResponse], error) {
			seenFqdn = fqdn
			return newDonePoller(armsql.OutboundFirewallRulesClientCreateOrUpdateResponse{OutboundFirewallRule: model}), nil
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, "storage.blob.core.windows.net", seenFqdn)

		var serialized map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &serialized))
		require.Equal(t, "storage.blob.core.windows.net", serialized["name"])
		require.Equal(t, "srv-1", serialized["serverName"])
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testSQLOutboundNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
		require.Equal(t, ResourceTypeSQLOutboundFirewallRule, got.ResourceType)
	})

	t.Run("Update only re-reads, never writes", func(t *testing.T) {
		wrote := false
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _, _ string, _ armsql.OutboundFirewallRule, _ *armsql.OutboundFirewallRulesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armsql.OutboundFirewallRulesClientCreateOrUpdateResponse], error) {
			wrote = true
			return newDonePoller(armsql.OutboundFirewallRulesClientCreateOrUpdateResponse{OutboundFirewallRule: model}), nil
		}
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID: testSQLOutboundNativeID, DesiredProperties: mkProps(),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.False(t, wrote, "Update must not call BeginCreateOrUpdate")
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _, _ string, _ *armsql.OutboundFirewallRulesClientBeginDeleteOptions) (*runtime.Poller[armsql.OutboundFirewallRulesClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testSQLOutboundNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_server", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "serverName": "srv-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testSQLOutboundNativeID}, got.NativeIDs)
	})

	// The name is a dotted FQDN, which must survive ARM ID parsing intact.
	t.Run("IDParts keeps the dotted FQDN intact", func(t *testing.T) {
		rg, srv, fqdn, err := sqlOutboundFirewallRuleIDParts(testSQLOutboundNativeID)
		require.NoError(t, err)
		require.Equal(t, []string{"rg-1", "srv-1", "storage.blob.core.windows.net"}, []string{rg, srv, fqdn})
	})
}

// --- VirtualNetworkRule ---

func TestSqlVirtualNetworkRule_CRUD(t *testing.T) {
	model := armsql.VirtualNetworkRule{
		ID:   to.Ptr(testSQLVnetRuleNativeID),
		Name: to.Ptr("vnet-rule-1"),
		Properties: &armsql.VirtualNetworkRuleProperties{
			VirtualNetworkSubnetID:           to.Ptr(testSQLSubnetID),
			IgnoreMissingVnetServiceEndpoint: to.Ptr(true),
			State:                            to.Ptr(armsql.VirtualNetworkRuleStateReady),
		},
	}
	fake := &fakeSQLVirtualNetworkRulesAPI{
		beginCreateOrUpdateFn: func(_ context.Context, _, _, _ string, _ armsql.VirtualNetworkRule, _ *armsql.VirtualNetworkRulesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armsql.VirtualNetworkRulesClientCreateOrUpdateResponse], error) {
			return newDonePoller(armsql.VirtualNetworkRulesClientCreateOrUpdateResponse{VirtualNetworkRule: model}), nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ *armsql.VirtualNetworkRulesClientGetOptions) (armsql.VirtualNetworkRulesClientGetResponse, error) {
			return armsql.VirtualNetworkRulesClientGetResponse{VirtualNetworkRule: model}, nil
		},
		beginDeleteFn: func(_ context.Context, _, _, _ string, _ *armsql.VirtualNetworkRulesClientBeginDeleteOptions) (*runtime.Poller[armsql.VirtualNetworkRulesClientDeleteResponse], error) {
			return newInProgressPoller[armsql.VirtualNetworkRulesClientDeleteResponse](), nil
		},
		newListByServerPagerFn: func(_, _ string, _ *armsql.VirtualNetworkRulesClientListByServerOptions) *runtime.Pager[armsql.VirtualNetworkRulesClientListByServerResponse] {
			return runtime.NewPager(runtime.PagingHandler[armsql.VirtualNetworkRulesClientListByServerResponse]{
				More: func(_ armsql.VirtualNetworkRulesClientListByServerResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armsql.VirtualNetworkRulesClientListByServerResponse) (armsql.VirtualNetworkRulesClientListByServerResponse, error) {
					return armsql.VirtualNetworkRulesClientListByServerResponse{
						VirtualNetworkRuleListResult: armsql.VirtualNetworkRuleListResult{
							Value: []*armsql.VirtualNetworkRule{{ID: to.Ptr(testSQLVnetRuleNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := &SqlVirtualNetworkRule{api: fake, config: &config.Config{SubscriptionId: "sub-1"}}

	mkProps := func() json.RawMessage {
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName":                "rg-1",
			"serverName":                       "srv-1",
			"name":                             "vnet-rule-1",
			"virtualNetworkSubnetId":           testSQLSubnetID,
			"ignoreMissingVnetServiceEndpoint": true,
		})
		return props
	}

	t.Run("Create forwards the subnet reference", func(t *testing.T) {
		var seen armsql.VirtualNetworkRule
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _, _ string, params armsql.VirtualNetworkRule, _ *armsql.VirtualNetworkRulesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armsql.VirtualNetworkRulesClientCreateOrUpdateResponse], error) {
			seen = params
			return newDonePoller(armsql.VirtualNetworkRulesClientCreateOrUpdateResponse{VirtualNetworkRule: model}), nil
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testSQLSubnetID, *seen.Properties.VirtualNetworkSubnetID)
		require.Equal(t, true, *seen.Properties.IgnoreMissingVnetServiceEndpoint)

		var serialized map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &serialized))
		require.Equal(t, testSQLSubnetID, serialized["virtualNetworkSubnetId"])
		require.Equal(t, true, serialized["ignoreMissingVnetServiceEndpoint"])
		require.Equal(t, "Ready", serialized["state"])
	})

	t.Run("Create requires virtualNetworkSubnetId", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName": "rg-1", "serverName": "srv-1", "name": "vnet-rule-1",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "virtualNetworkSubnetId is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testSQLVnetRuleNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
		require.Equal(t, ResourceTypeSQLVirtualNetworkRule, got.ResourceType)
	})

	// Unlike its two siblings, this one has writable properties, so Update DOES write.
	t.Run("Update writes a full body", func(t *testing.T) {
		var seen armsql.VirtualNetworkRule
		wrote := false
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _, _ string, params armsql.VirtualNetworkRule, _ *armsql.VirtualNetworkRulesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armsql.VirtualNetworkRulesClientCreateOrUpdateResponse], error) {
			seen, wrote = params, true
			return newDonePoller(armsql.VirtualNetworkRulesClientCreateOrUpdateResponse{VirtualNetworkRule: model}), nil
		}
		desired, _ := json.Marshal(map[string]any{
			"virtualNetworkSubnetId":           testSQLSubnetID,
			"ignoreMissingVnetServiceEndpoint": false,
		})
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID: testSQLVnetRuleNativeID, DesiredProperties: desired,
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.True(t, wrote, "Update must call BeginCreateOrUpdate")
		require.Equal(t, false, *seen.Properties.IgnoreMissingVnetServiceEndpoint)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _, _ string, _ *armsql.VirtualNetworkRulesClientBeginDeleteOptions) (*runtime.Poller[armsql.VirtualNetworkRulesClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testSQLVnetRuleNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_server", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "serverName": "srv-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testSQLVnetRuleNativeID}, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _, _ string, _ armsql.VirtualNetworkRule, _ *armsql.VirtualNetworkRulesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armsql.VirtualNetworkRulesClientCreateOrUpdateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 403}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

// --- Fakes ---

type fakeSQLServerDNSAliasesAPI struct {
	beginCreateOrUpdateFn  func(ctx context.Context, rg, srv, alias string, opts *armsql.ServerDNSAliasesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armsql.ServerDNSAliasesClientCreateOrUpdateResponse], error)
	getFn                  func(ctx context.Context, rg, srv, alias string, opts *armsql.ServerDNSAliasesClientGetOptions) (armsql.ServerDNSAliasesClientGetResponse, error)
	beginDeleteFn          func(ctx context.Context, rg, srv, alias string, opts *armsql.ServerDNSAliasesClientBeginDeleteOptions) (*runtime.Poller[armsql.ServerDNSAliasesClientDeleteResponse], error)
	newListByServerPagerFn func(rg, srv string, opts *armsql.ServerDNSAliasesClientListByServerOptions) *runtime.Pager[armsql.ServerDNSAliasesClientListByServerResponse]
}

func (f *fakeSQLServerDNSAliasesAPI) BeginCreateOrUpdate(ctx context.Context, rg, srv, alias string, opts *armsql.ServerDNSAliasesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armsql.ServerDNSAliasesClientCreateOrUpdateResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, rg, srv, alias, opts)
}
func (f *fakeSQLServerDNSAliasesAPI) Get(ctx context.Context, rg, srv, alias string, opts *armsql.ServerDNSAliasesClientGetOptions) (armsql.ServerDNSAliasesClientGetResponse, error) {
	return f.getFn(ctx, rg, srv, alias, opts)
}
func (f *fakeSQLServerDNSAliasesAPI) BeginDelete(ctx context.Context, rg, srv, alias string, opts *armsql.ServerDNSAliasesClientBeginDeleteOptions) (*runtime.Poller[armsql.ServerDNSAliasesClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rg, srv, alias, opts)
}
func (f *fakeSQLServerDNSAliasesAPI) NewListByServerPager(rg, srv string, opts *armsql.ServerDNSAliasesClientListByServerOptions) *runtime.Pager[armsql.ServerDNSAliasesClientListByServerResponse] {
	return f.newListByServerPagerFn(rg, srv, opts)
}

type fakeSQLOutboundFirewallRulesAPI struct {
	beginCreateOrUpdateFn  func(ctx context.Context, rg, srv, fqdn string, params armsql.OutboundFirewallRule, opts *armsql.OutboundFirewallRulesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armsql.OutboundFirewallRulesClientCreateOrUpdateResponse], error)
	getFn                  func(ctx context.Context, rg, srv, fqdn string, opts *armsql.OutboundFirewallRulesClientGetOptions) (armsql.OutboundFirewallRulesClientGetResponse, error)
	beginDeleteFn          func(ctx context.Context, rg, srv, fqdn string, opts *armsql.OutboundFirewallRulesClientBeginDeleteOptions) (*runtime.Poller[armsql.OutboundFirewallRulesClientDeleteResponse], error)
	newListByServerPagerFn func(rg, srv string, opts *armsql.OutboundFirewallRulesClientListByServerOptions) *runtime.Pager[armsql.OutboundFirewallRulesClientListByServerResponse]
}

func (f *fakeSQLOutboundFirewallRulesAPI) BeginCreateOrUpdate(ctx context.Context, rg, srv, fqdn string, params armsql.OutboundFirewallRule, opts *armsql.OutboundFirewallRulesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armsql.OutboundFirewallRulesClientCreateOrUpdateResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, rg, srv, fqdn, params, opts)
}
func (f *fakeSQLOutboundFirewallRulesAPI) Get(ctx context.Context, rg, srv, fqdn string, opts *armsql.OutboundFirewallRulesClientGetOptions) (armsql.OutboundFirewallRulesClientGetResponse, error) {
	return f.getFn(ctx, rg, srv, fqdn, opts)
}
func (f *fakeSQLOutboundFirewallRulesAPI) BeginDelete(ctx context.Context, rg, srv, fqdn string, opts *armsql.OutboundFirewallRulesClientBeginDeleteOptions) (*runtime.Poller[armsql.OutboundFirewallRulesClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rg, srv, fqdn, opts)
}
func (f *fakeSQLOutboundFirewallRulesAPI) NewListByServerPager(rg, srv string, opts *armsql.OutboundFirewallRulesClientListByServerOptions) *runtime.Pager[armsql.OutboundFirewallRulesClientListByServerResponse] {
	return f.newListByServerPagerFn(rg, srv, opts)
}

type fakeSQLVirtualNetworkRulesAPI struct {
	beginCreateOrUpdateFn  func(ctx context.Context, rg, srv, name string, params armsql.VirtualNetworkRule, opts *armsql.VirtualNetworkRulesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armsql.VirtualNetworkRulesClientCreateOrUpdateResponse], error)
	getFn                  func(ctx context.Context, rg, srv, name string, opts *armsql.VirtualNetworkRulesClientGetOptions) (armsql.VirtualNetworkRulesClientGetResponse, error)
	beginDeleteFn          func(ctx context.Context, rg, srv, name string, opts *armsql.VirtualNetworkRulesClientBeginDeleteOptions) (*runtime.Poller[armsql.VirtualNetworkRulesClientDeleteResponse], error)
	newListByServerPagerFn func(rg, srv string, opts *armsql.VirtualNetworkRulesClientListByServerOptions) *runtime.Pager[armsql.VirtualNetworkRulesClientListByServerResponse]
}

func (f *fakeSQLVirtualNetworkRulesAPI) BeginCreateOrUpdate(ctx context.Context, rg, srv, name string, params armsql.VirtualNetworkRule, opts *armsql.VirtualNetworkRulesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armsql.VirtualNetworkRulesClientCreateOrUpdateResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, rg, srv, name, params, opts)
}
func (f *fakeSQLVirtualNetworkRulesAPI) Get(ctx context.Context, rg, srv, name string, opts *armsql.VirtualNetworkRulesClientGetOptions) (armsql.VirtualNetworkRulesClientGetResponse, error) {
	return f.getFn(ctx, rg, srv, name, opts)
}
func (f *fakeSQLVirtualNetworkRulesAPI) BeginDelete(ctx context.Context, rg, srv, name string, opts *armsql.VirtualNetworkRulesClientBeginDeleteOptions) (*runtime.Poller[armsql.VirtualNetworkRulesClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rg, srv, name, opts)
}
func (f *fakeSQLVirtualNetworkRulesAPI) NewListByServerPager(rg, srv string, opts *armsql.VirtualNetworkRulesClientListByServerOptions) *runtime.Pager[armsql.VirtualNetworkRulesClientListByServerResponse] {
	return f.newListByServerPagerFn(rg, srv, opts)
}
