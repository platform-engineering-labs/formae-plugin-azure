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
	testDNSForwardingRulesetNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/dnsForwardingRulesets/ruleset-1"
	testRulesetOutboundEndpointID    = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/dnsResolvers/resolver-1/outboundEndpoints/outbound-1"
)

func newTestDNSForwardingRuleset(api dnsForwardingRulesetsAPI) *DNSForwardingRuleset {
	return &DNSForwardingRuleset{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func rulesetDesired(tagValue string) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":                           "ruleset-1",
		"location":                       "eastus",
		"resourceGroupName":              "rg-1",
		"dnsResolverOutboundEndpointIds": []any{testRulesetOutboundEndpointID},
		"Tags":                           []any{map[string]any{"Key": "env", "Value": tagValue}},
	})
	return out
}

func TestDNSForwardingRuleset_CRUD(t *testing.T) {
	resolverResult := armdnsresolver.DNSForwardingRuleset{
		ID:       to.Ptr(testDNSForwardingRulesetNativeID),
		Name:     to.Ptr("ruleset-1"),
		Location: to.Ptr("East US"),
		Properties: &armdnsresolver.DNSForwardingRulesetProperties{
			DNSResolverOutboundEndpoints: []*armdnsresolver.SubResource{{ID: to.Ptr(testRulesetOutboundEndpointID)}},
			ProvisioningState:            to.Ptr(armdnsresolver.ProvisioningStateSucceeded),
			ResourceGUID:                 to.Ptr("11111111-2222-3333-4444-555555555555"),
		},
		Tags: map[string]*string{"env": to.Ptr("test")},
	}

	var sentCreate armdnsresolver.DNSForwardingRuleset
	var sentPatch armdnsresolver.DNSForwardingRulesetPatch
	deleteCalls := 0
	fake := &fakeDNSForwardingRulesetsAPI{
		beginCreateOrUpdateFn: func(_ context.Context, _, name string, params armdnsresolver.DNSForwardingRuleset, _ *armdnsresolver.DNSForwardingRulesetsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armdnsresolver.DNSForwardingRulesetsClientCreateOrUpdateResponse], error) {
			require.Equal(t, "ruleset-1", name)
			sentCreate = params
			return newDonePoller(armdnsresolver.DNSForwardingRulesetsClientCreateOrUpdateResponse{DNSForwardingRuleset: resolverResult}), nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armdnsresolver.DNSForwardingRulesetsClientGetOptions) (armdnsresolver.DNSForwardingRulesetsClientGetResponse, error) {
			return armdnsresolver.DNSForwardingRulesetsClientGetResponse{DNSForwardingRuleset: resolverResult}, nil
		},
		beginUpdateFn: func(_ context.Context, _, _ string, params armdnsresolver.DNSForwardingRulesetPatch, _ *armdnsresolver.DNSForwardingRulesetsClientBeginUpdateOptions) (*runtime.Poller[armdnsresolver.DNSForwardingRulesetsClientUpdateResponse], error) {
			sentPatch = params
			return newDonePoller(armdnsresolver.DNSForwardingRulesetsClientUpdateResponse{DNSForwardingRuleset: resolverResult}), nil
		},
		beginDeleteFn: func(_ context.Context, _, _ string, _ *armdnsresolver.DNSForwardingRulesetsClientBeginDeleteOptions) (*runtime.Poller[armdnsresolver.DNSForwardingRulesetsClientDeleteResponse], error) {
			deleteCalls++
			return newDonePoller(armdnsresolver.DNSForwardingRulesetsClientDeleteResponse{}), nil
		},
		newListPagerFn: func(_ *armdnsresolver.DNSForwardingRulesetsClientListOptions) *runtime.Pager[armdnsresolver.DNSForwardingRulesetsClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armdnsresolver.DNSForwardingRulesetsClientListResponse]{
				More: func(_ armdnsresolver.DNSForwardingRulesetsClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armdnsresolver.DNSForwardingRulesetsClientListResponse) (armdnsresolver.DNSForwardingRulesetsClientListResponse, error) {
					return armdnsresolver.DNSForwardingRulesetsClientListResponse{
						DNSForwardingRulesetListResult: armdnsresolver.DNSForwardingRulesetListResult{
							Value: []*armdnsresolver.DNSForwardingRuleset{
								{ID: to.Ptr(testDNSForwardingRulesetNativeID)},
								{ID: to.Ptr("/subscriptions/sub-1/resourceGroups/rg-2/providers/Microsoft.Network/dnsForwardingRulesets/ruleset-2")},
							},
						},
					}, nil
				},
			})
		},
		newListByResourceGroupPagerFn: func(_ string, _ *armdnsresolver.DNSForwardingRulesetsClientListByResourceGroupOptions) *runtime.Pager[armdnsresolver.DNSForwardingRulesetsClientListByResourceGroupResponse] {
			return runtime.NewPager(runtime.PagingHandler[armdnsresolver.DNSForwardingRulesetsClientListByResourceGroupResponse]{
				More: func(_ armdnsresolver.DNSForwardingRulesetsClientListByResourceGroupResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armdnsresolver.DNSForwardingRulesetsClientListByResourceGroupResponse) (armdnsresolver.DNSForwardingRulesetsClientListByResourceGroupResponse, error) {
					return armdnsresolver.DNSForwardingRulesetsClientListByResourceGroupResponse{
						DNSForwardingRulesetListResult: armdnsresolver.DNSForwardingRulesetListResult{
							Value: []*armdnsresolver.DNSForwardingRuleset{{ID: to.Ptr(testDNSForwardingRulesetNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestDNSForwardingRuleset(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "ruleset-1",
			Properties: rulesetDesired("test"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testDNSForwardingRulesetNativeID, got.ProgressResult.NativeID)
		require.Len(t, sentCreate.Properties.DNSResolverOutboundEndpoints, 1)
		require.Equal(t, testRulesetOutboundEndpointID, *sentCreate.Properties.DNSResolverOutboundEndpoints[0].ID)
		require.Equal(t, "test", *sentCreate.Tags["env"])
	})

	t.Run("Create_requires_virtual_network", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "ruleset-1", "location": "eastus", "resourceGroupName": "rg-1",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "dnsResolverOutboundEndpointIds is required")
	})

	t.Run("Create_requires_location", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "ruleset-1", "resourceGroupName": "rg-1",
			"dnsResolverOutboundEndpointIds": []any{testRulesetOutboundEndpointID},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "location is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testDNSForwardingRulesetNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "ruleset-1", props["name"])
		// ARM returns "East US"; read must normalise or desired state drifts.
		require.Equal(t, "eastus", props["location"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, []any{testRulesetOutboundEndpointID}, props["dnsResolverOutboundEndpointIds"])
	})

	// provisioningState and resourceGuid are service bookkeeping, not desired
	// state: surfacing them would only ever read back as noise.
	t.Run("Read_drops_service_bookkeeping", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testDNSForwardingRulesetNativeID})
		require.NoError(t, err)
		require.NotContains(t, got.Properties, "provisioningState")
		require.NotContains(t, got.Properties, "resourceGuid")
		require.NotContains(t, got.Properties, "resourceGUID")
	})

	// The patch must carry tags ONLY. DNSForwardingRulesetPatch has a
	// DNSResolverOutboundEndpoints field, but the SDK marshals it at the top level
	// of the body and ARM answers InvalidRequestContent ("Could not find member
	// 'dnsResolverOutboundEndpoints' on object of type 'ResourceDefinition'"),
	// failing every update. The list is createOnly in the schema for that reason.
	t.Run("Update_sends_tags", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testDNSForwardingRulesetNativeID,
			DesiredProperties: rulesetDesired("updated"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, "updated", *sentPatch.Tags["env"])
		require.Nil(t, sentPatch.DNSResolverOutboundEndpoints)
	})

	t.Run("Delete", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testDNSForwardingRulesetNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _ string, _ *armdnsresolver.DNSForwardingRulesetsClientBeginDeleteOptions) (*runtime.Poller[armdnsresolver.DNSForwardingRulesetsClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testDNSForwardingRulesetNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_resource_group", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testDNSForwardingRulesetNativeID}, got.NativeIDs)
	})

	t.Run("List_without_group_is_subscription_wide", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 2)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, _ armdnsresolver.DNSForwardingRuleset, _ *armdnsresolver.DNSForwardingRulesetsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armdnsresolver.DNSForwardingRulesetsClientCreateOrUpdateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 409}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "ruleset-1", Properties: rulesetDesired("test"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

func TestDNSForwardingRuleset_ReadNotFound(t *testing.T) {
	fake := &fakeDNSForwardingRulesetsAPI{
		getFn: func(_ context.Context, _, _ string, _ *armdnsresolver.DNSForwardingRulesetsClientGetOptions) (armdnsresolver.DNSForwardingRulesetsClientGetResponse, error) {
			return armdnsresolver.DNSForwardingRulesetsClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestDNSForwardingRuleset(fake).Read(context.Background(), &resource.ReadRequest{NativeID: testDNSForwardingRulesetNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeDNSForwardingRulesetsAPI struct {
	beginCreateOrUpdateFn         func(ctx context.Context, rgName, name string, params armdnsresolver.DNSForwardingRuleset, options *armdnsresolver.DNSForwardingRulesetsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armdnsresolver.DNSForwardingRulesetsClientCreateOrUpdateResponse], error)
	getFn                         func(ctx context.Context, rgName, name string, options *armdnsresolver.DNSForwardingRulesetsClientGetOptions) (armdnsresolver.DNSForwardingRulesetsClientGetResponse, error)
	beginUpdateFn                 func(ctx context.Context, rgName, name string, params armdnsresolver.DNSForwardingRulesetPatch, options *armdnsresolver.DNSForwardingRulesetsClientBeginUpdateOptions) (*runtime.Poller[armdnsresolver.DNSForwardingRulesetsClientUpdateResponse], error)
	beginDeleteFn                 func(ctx context.Context, rgName, name string, options *armdnsresolver.DNSForwardingRulesetsClientBeginDeleteOptions) (*runtime.Poller[armdnsresolver.DNSForwardingRulesetsClientDeleteResponse], error)
	newListPagerFn                func(options *armdnsresolver.DNSForwardingRulesetsClientListOptions) *runtime.Pager[armdnsresolver.DNSForwardingRulesetsClientListResponse]
	newListByResourceGroupPagerFn func(rgName string, options *armdnsresolver.DNSForwardingRulesetsClientListByResourceGroupOptions) *runtime.Pager[armdnsresolver.DNSForwardingRulesetsClientListByResourceGroupResponse]
}

func (f *fakeDNSForwardingRulesetsAPI) BeginCreateOrUpdate(ctx context.Context, rgName, name string, params armdnsresolver.DNSForwardingRuleset, options *armdnsresolver.DNSForwardingRulesetsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armdnsresolver.DNSForwardingRulesetsClientCreateOrUpdateResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, rgName, name, params, options)
}

func (f *fakeDNSForwardingRulesetsAPI) Get(ctx context.Context, rgName, name string, options *armdnsresolver.DNSForwardingRulesetsClientGetOptions) (armdnsresolver.DNSForwardingRulesetsClientGetResponse, error) {
	return f.getFn(ctx, rgName, name, options)
}

func (f *fakeDNSForwardingRulesetsAPI) BeginUpdate(ctx context.Context, rgName, name string, params armdnsresolver.DNSForwardingRulesetPatch, options *armdnsresolver.DNSForwardingRulesetsClientBeginUpdateOptions) (*runtime.Poller[armdnsresolver.DNSForwardingRulesetsClientUpdateResponse], error) {
	return f.beginUpdateFn(ctx, rgName, name, params, options)
}

func (f *fakeDNSForwardingRulesetsAPI) BeginDelete(ctx context.Context, rgName, name string, options *armdnsresolver.DNSForwardingRulesetsClientBeginDeleteOptions) (*runtime.Poller[armdnsresolver.DNSForwardingRulesetsClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, name, options)
}

func (f *fakeDNSForwardingRulesetsAPI) NewListPager(options *armdnsresolver.DNSForwardingRulesetsClientListOptions) *runtime.Pager[armdnsresolver.DNSForwardingRulesetsClientListResponse] {
	return f.newListPagerFn(options)
}

func (f *fakeDNSForwardingRulesetsAPI) NewListByResourceGroupPager(rgName string, options *armdnsresolver.DNSForwardingRulesetsClientListByResourceGroupOptions) *runtime.Pager[armdnsresolver.DNSForwardingRulesetsClientListByResourceGroupResponse] {
	return f.newListByResourceGroupPagerFn(rgName, options)
}
