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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v4"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testFirewallPolicyNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/firewallPolicies/fp1"

func newTestFirewallPolicy(api networkFirewallPoliciesAPI) *NetworkFirewallPolicy {
	return &NetworkFirewallPolicy{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func firewallPolicyDesired(threatIntelMode string) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":              "fp1",
		"location":          "eastus",
		"resourceGroupName": "rg-1",
		"skuTier":           "Standard",
		"threatIntelMode":   threatIntelMode,
		"dnsSettings": map[string]any{
			"enableProxy": true,
			"servers":     []any{"10.0.0.4"},
		},
		"Tags": []any{map[string]any{"Key": "env", "Value": "test"}},
	})
	return out
}

func TestNetworkFirewallPolicy_CRUD(t *testing.T) {
	policyResult := armnetwork.FirewallPolicy{
		ID:       to.Ptr(testFirewallPolicyNativeID),
		Name:     to.Ptr("fp1"),
		Location: to.Ptr("East US"),
		Properties: &armnetwork.FirewallPolicyPropertiesFormat{
			SKU:             &armnetwork.FirewallPolicySKU{Tier: to.Ptr(armnetwork.FirewallPolicySKUTierStandard)},
			ThreatIntelMode: to.Ptr(armnetwork.AzureFirewallThreatIntelModeAlert),
			DNSSettings: &armnetwork.DNSSettings{
				EnableProxy: to.Ptr(true),
				Servers:     []*string{to.Ptr("10.0.0.4")},
			},
			// Unmodelled configuration, plus ARM's back-references to other resources.
			IntrusionDetection: &armnetwork.FirewallPolicyIntrusionDetection{
				Mode: to.Ptr(armnetwork.FirewallPolicyIntrusionDetectionStateTypeAlert),
			},
			Snat:              &armnetwork.FirewallPolicySNAT{PrivateRanges: []*string{to.Ptr("IANAPrivateRanges")}},
			ProvisioningState: to.Ptr(armnetwork.ProvisioningStateSucceeded),
			RuleCollectionGroups: []*armnetwork.SubResource{{
				ID: to.Ptr(testFirewallPolicyNativeID + "/ruleCollectionGroups/rcg1"),
			}},
		},
		Tags: map[string]*string{"env": to.Ptr("test")},
	}

	var sent armnetwork.FirewallPolicy
	createCalls := 0
	deleteCalls := 0
	fake := &fakeFirewallPoliciesAPI{
		beginCreateOrUpdateFn: func(_ context.Context, rgName, name string, params armnetwork.FirewallPolicy, _ *armnetwork.FirewallPoliciesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.FirewallPoliciesClientCreateOrUpdateResponse], error) {
			require.Equal(t, "rg-1", rgName)
			require.Equal(t, "fp1", name)
			sent = params
			createCalls++
			return newDonePoller(armnetwork.FirewallPoliciesClientCreateOrUpdateResponse{FirewallPolicy: policyResult}), nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armnetwork.FirewallPoliciesClientGetOptions) (armnetwork.FirewallPoliciesClientGetResponse, error) {
			return armnetwork.FirewallPoliciesClientGetResponse{FirewallPolicy: policyResult}, nil
		},
		beginDeleteFn: func(_ context.Context, _, _ string, _ *armnetwork.FirewallPoliciesClientBeginDeleteOptions) (*runtime.Poller[armnetwork.FirewallPoliciesClientDeleteResponse], error) {
			deleteCalls++
			return newDonePoller(armnetwork.FirewallPoliciesClientDeleteResponse{}), nil
		},
		newListPagerFn: func(_ string, _ *armnetwork.FirewallPoliciesClientListOptions) *runtime.Pager[armnetwork.FirewallPoliciesClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armnetwork.FirewallPoliciesClientListResponse]{
				More: func(_ armnetwork.FirewallPoliciesClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armnetwork.FirewallPoliciesClientListResponse) (armnetwork.FirewallPoliciesClientListResponse, error) {
					return armnetwork.FirewallPoliciesClientListResponse{
						FirewallPolicyListResult: armnetwork.FirewallPolicyListResult{
							Value: []*armnetwork.FirewallPolicy{{ID: to.Ptr(testFirewallPolicyNativeID)}},
						},
					}, nil
				},
			})
		},
		newListAllPagerFn: func(_ *armnetwork.FirewallPoliciesClientListAllOptions) *runtime.Pager[armnetwork.FirewallPoliciesClientListAllResponse] {
			return runtime.NewPager(runtime.PagingHandler[armnetwork.FirewallPoliciesClientListAllResponse]{
				More: func(_ armnetwork.FirewallPoliciesClientListAllResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armnetwork.FirewallPoliciesClientListAllResponse) (armnetwork.FirewallPoliciesClientListAllResponse, error) {
					return armnetwork.FirewallPoliciesClientListAllResponse{
						FirewallPolicyListResult: armnetwork.FirewallPolicyListResult{
							Value: []*armnetwork.FirewallPolicy{
								{ID: to.Ptr(testFirewallPolicyNativeID)},
								{ID: to.Ptr("/subscriptions/sub-1/resourceGroups/rg-2/providers/Microsoft.Network/firewallPolicies/fp2")},
							},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestFirewallPolicy(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "fp1", Properties: firewallPolicyDesired("Alert"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testFirewallPolicyNativeID, got.ProgressResult.NativeID)

		require.Equal(t, "eastus", *sent.Location)
		require.Equal(t, armnetwork.FirewallPolicySKUTierStandard, *sent.Properties.SKU.Tier)
		require.Equal(t, armnetwork.AzureFirewallThreatIntelModeAlert, *sent.Properties.ThreatIntelMode)
		require.True(t, *sent.Properties.DNSSettings.EnableProxy)
		require.Len(t, sent.Properties.DNSSettings.Servers, 1)
		require.Equal(t, "test", *sent.Tags["env"])
		// Unmodelled configuration must never be sent.
		require.Nil(t, sent.Properties.IntrusionDetection)
		require.Nil(t, sent.Properties.Snat)
	})

	t.Run("Create_requires_location", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "fp1", "resourceGroupName": "rg-1"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "location is required")
	})

	t.Run("Create_requires_resource_group", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "fp1", "location": "eastus"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "resourceGroupName is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testFirewallPolicyNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "fp1", props["name"])
		// ARM returns "East US"; read must normalise or desired state drifts.
		require.Equal(t, "eastus", props["location"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "Standard", props["skuTier"])
		require.Equal(t, "Alert", props["threatIntelMode"])

		dns := props["dnsSettings"].(map[string]any)
		require.Equal(t, true, dns["enableProxy"])
		require.Equal(t, []any{"10.0.0.4"}, dns["servers"])
	})

	// Unmodelled configuration and ARM's back-references to other resources must not
	// reach state: rule collection groups are their own resources, and a field the
	// schema cannot express would read as drift on every sync.
	t.Run("Read_drops_unmodelled_and_backrefs", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testFirewallPolicyNativeID})
		require.NoError(t, err)
		for _, key := range []string{
			"intrusionDetection", "snat", "sql", "transportSecurity",
			"explicitProxySettings", "basePolicy", "provisioningState",
			"ruleCollectionGroups", "childPolicies", "firewalls",
		} {
			require.NotContains(t, got.Properties, key)
		}
		require.NotContains(t, got.Properties, "IANAPrivateRanges")
	})

	// The SDK's only update verb is UpdateTags, which cannot change threatIntelMode,
	// so an update is another CreateOrUpdate.
	t.Run("Update_reissues_create_or_update", func(t *testing.T) {
		before := createCalls
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testFirewallPolicyNativeID,
			DesiredProperties: firewallPolicyDesired("Deny"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, createCalls)
		require.Equal(t, armnetwork.AzureFirewallThreatIntelModeDeny, *sent.Properties.ThreatIntelMode)
		// Location must ride along: a PUT without it is rejected.
		require.Equal(t, "eastus", *sent.Location)
	})

	t.Run("Delete", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testFirewallPolicyNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _ string, _ *armnetwork.FirewallPoliciesClientBeginDeleteOptions) (*runtime.Poller[armnetwork.FirewallPoliciesClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testFirewallPolicyNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_resource_group", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testFirewallPolicyNativeID}, got.NativeIDs)
	})

	t.Run("List_without_group_is_subscription_wide", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 2)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, _ armnetwork.FirewallPolicy, _ *armnetwork.FirewallPoliciesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.FirewallPoliciesClientCreateOrUpdateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 409}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "fp1", Properties: firewallPolicyDesired("Alert"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

// The native ID reported for an in-flight create must match the path ARM returns.
func TestNetworkFirewallPolicy_PendingCreateReportsRealNativeID(t *testing.T) {
	fake := &fakeFirewallPoliciesAPI{
		beginCreateOrUpdateFn: func(_ context.Context, _, _ string, _ armnetwork.FirewallPolicy, _ *armnetwork.FirewallPoliciesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.FirewallPoliciesClientCreateOrUpdateResponse], error) {
			return newPendingPoller[armnetwork.FirewallPoliciesClientCreateOrUpdateResponse](), nil
		},
	}
	got, err := newTestFirewallPolicy(fake).Create(context.Background(), &resource.CreateRequest{
		Label: "fp1", Properties: firewallPolicyDesired("Alert"),
	})
	require.NoError(t, err)
	require.Equal(t, resource.OperationStatusInProgress, got.ProgressResult.OperationStatus)
	require.Equal(t, testFirewallPolicyNativeID, got.ProgressResult.NativeID)
}

func TestNetworkFirewallPolicy_ReadNotFound(t *testing.T) {
	fake := &fakeFirewallPoliciesAPI{
		getFn: func(_ context.Context, _, _ string, _ *armnetwork.FirewallPoliciesClientGetOptions) (armnetwork.FirewallPoliciesClientGetResponse, error) {
			return armnetwork.FirewallPoliciesClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestFirewallPolicy(fake).Read(context.Background(), &resource.ReadRequest{NativeID: testFirewallPolicyNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeFirewallPoliciesAPI struct {
	beginCreateOrUpdateFn func(ctx context.Context, rgName, name string, params armnetwork.FirewallPolicy, options *armnetwork.FirewallPoliciesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.FirewallPoliciesClientCreateOrUpdateResponse], error)
	getFn                 func(ctx context.Context, rgName, name string, options *armnetwork.FirewallPoliciesClientGetOptions) (armnetwork.FirewallPoliciesClientGetResponse, error)
	beginDeleteFn         func(ctx context.Context, rgName, name string, options *armnetwork.FirewallPoliciesClientBeginDeleteOptions) (*runtime.Poller[armnetwork.FirewallPoliciesClientDeleteResponse], error)
	newListPagerFn        func(rgName string, options *armnetwork.FirewallPoliciesClientListOptions) *runtime.Pager[armnetwork.FirewallPoliciesClientListResponse]
	newListAllPagerFn     func(options *armnetwork.FirewallPoliciesClientListAllOptions) *runtime.Pager[armnetwork.FirewallPoliciesClientListAllResponse]
}

func (f *fakeFirewallPoliciesAPI) BeginCreateOrUpdate(ctx context.Context, rgName, name string, params armnetwork.FirewallPolicy, options *armnetwork.FirewallPoliciesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.FirewallPoliciesClientCreateOrUpdateResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, rgName, name, params, options)
}

func (f *fakeFirewallPoliciesAPI) Get(ctx context.Context, rgName, name string, options *armnetwork.FirewallPoliciesClientGetOptions) (armnetwork.FirewallPoliciesClientGetResponse, error) {
	return f.getFn(ctx, rgName, name, options)
}

func (f *fakeFirewallPoliciesAPI) BeginDelete(ctx context.Context, rgName, name string, options *armnetwork.FirewallPoliciesClientBeginDeleteOptions) (*runtime.Poller[armnetwork.FirewallPoliciesClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, name, options)
}

func (f *fakeFirewallPoliciesAPI) NewListPager(rgName string, options *armnetwork.FirewallPoliciesClientListOptions) *runtime.Pager[armnetwork.FirewallPoliciesClientListResponse] {
	return f.newListPagerFn(rgName, options)
}

func (f *fakeFirewallPoliciesAPI) NewListAllPager(options *armnetwork.FirewallPoliciesClientListAllOptions) *runtime.Pager[armnetwork.FirewallPoliciesClientListAllResponse] {
	return f.newListAllPagerFn(options)
}
