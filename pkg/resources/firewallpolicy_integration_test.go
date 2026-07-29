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

const testFirewallPolicyNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/firewallPolicies/fwp-1"

func TestFirewallPolicy_CRUD(t *testing.T) {
	model := armnetwork.FirewallPolicy{
		ID:       to.Ptr(testFirewallPolicyNativeID),
		Name:     to.Ptr("fwp-1"),
		Location: to.Ptr("eastus"),
		Etag:     to.Ptr("W/\"etag-1\""),
		Properties: &armnetwork.FirewallPolicyPropertiesFormat{
			SKU:             &armnetwork.FirewallPolicySKU{Tier: to.Ptr(armnetwork.FirewallPolicySKUTierStandard)},
			ThreatIntelMode: to.Ptr(armnetwork.AzureFirewallThreatIntelModeAlert),
			DNSSettings: &armnetwork.DNSSettings{
				EnableProxy: to.Ptr(true),
				Servers:     []*string{to.Ptr("168.63.129.16")},
			},
			// Read-only ARM output with no schema field.
			ProvisioningState:    to.Ptr(armnetwork.ProvisioningStateSucceeded),
			Size:                 to.Ptr("0.5MB"),
			RuleCollectionGroups: []*armnetwork.SubResource{{ID: to.Ptr(testFirewallPolicyNativeID + "/ruleCollectionGroups/rcg-1")}},
			Firewalls:            []*armnetwork.SubResource{{ID: to.Ptr("/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/azureFirewalls/fw-1")}},
		},
		Tags: map[string]*string{"Environment": to.Ptr("test")},
	}
	fake := &fakeFirewallPoliciesAPI{
		beginCreateOrUpdateFn: func(_ context.Context, _, _ string, _ armnetwork.FirewallPolicy, _ *armnetwork.FirewallPoliciesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.FirewallPoliciesClientCreateOrUpdateResponse], error) {
			return newDonePoller(armnetwork.FirewallPoliciesClientCreateOrUpdateResponse{FirewallPolicy: model}), nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armnetwork.FirewallPoliciesClientGetOptions) (armnetwork.FirewallPoliciesClientGetResponse, error) {
			return armnetwork.FirewallPoliciesClientGetResponse{FirewallPolicy: model}, nil
		},
		beginDeleteFn: func(_ context.Context, _, _ string, _ *armnetwork.FirewallPoliciesClientBeginDeleteOptions) (*runtime.Poller[armnetwork.FirewallPoliciesClientDeleteResponse], error) {
			return newInProgressPoller[armnetwork.FirewallPoliciesClientDeleteResponse](), nil
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
							Value: []*armnetwork.FirewallPolicy{{ID: to.Ptr(testFirewallPolicyNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestFirewallPolicy(fake)

	mkProps := func() json.RawMessage {
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName": "rg-1",
			"name":              "fwp-1",
			"location":          "eastus",
			"sku":               map[string]any{"tier": "Standard"},
			"threatIntelMode":   "Alert",
			"dnsSettings": map[string]any{
				"enableProxy": true,
				"servers":     []any{"168.63.129.16"},
			},
			"Tags": []map[string]string{{"Key": "Environment", "Value": "test"}},
		})
		return props
	}

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testFirewallPolicyNativeID, got.ProgressResult.NativeID)

		var serialized map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &serialized))
		require.Equal(t, "fwp-1", serialized["name"])
		require.Equal(t, map[string]any{"tier": "Standard"}, serialized["sku"])
		require.Equal(t, "Alert", serialized["threatIntelMode"])
		require.Equal(t, map[string]any{
			"enableProxy": true,
			"servers":     []any{"168.63.129.16"},
		}, serialized["dnsSettings"])
	})

	// ruleCollectionGroups / firewalls / provisioningState / size are read-only ARM
	// back-references with no schema field; conformance Verify rejects extras.
	t.Run("Serialize_omits_unmodelled_readonly_fields", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testFirewallPolicyNativeID})
		require.NoError(t, err)
		var serialized map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &serialized))
		require.NotContains(t, serialized, "ruleCollectionGroups")
		require.NotContains(t, serialized, "firewalls")
		require.NotContains(t, serialized, "provisioningState")
		require.NotContains(t, serialized, "size")
		require.NotContains(t, serialized, "etag")
	})

	t.Run("Create_forwards_params_to_ARM", func(t *testing.T) {
		var seen armnetwork.FirewallPolicy
		var seenRG, seenName string
		fake.beginCreateOrUpdateFn = func(_ context.Context, rg, name string, params armnetwork.FirewallPolicy, _ *armnetwork.FirewallPoliciesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.FirewallPoliciesClientCreateOrUpdateResponse], error) {
			seen, seenRG, seenName = params, rg, name
			return newDonePoller(armnetwork.FirewallPoliciesClientCreateOrUpdateResponse{FirewallPolicy: model}), nil
		}
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName": "rg-1",
			"name":              "fwp-1",
			"location":          "eastus",
			"sku":               map[string]any{"tier": "Premium"},
			"threatIntelMode":   "Deny",
			"basePolicyId":      "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/firewallPolicies/parent",
			"dnsSettings": map[string]any{
				"enableProxy": true,
				"servers":     []any{"10.0.0.4", "10.0.0.5"},
			},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.Equal(t, "rg-1", seenRG)
		require.Equal(t, "fwp-1", seenName)
		require.Equal(t, armnetwork.FirewallPolicySKUTierPremium, *seen.Properties.SKU.Tier)
		require.Equal(t, armnetwork.AzureFirewallThreatIntelModeDeny, *seen.Properties.ThreatIntelMode)
		require.Contains(t, *seen.Properties.BasePolicy.ID, "firewallPolicies/parent")
		require.True(t, *seen.Properties.DNSSettings.EnableProxy)
		// DNS resolution order is significant, so the list is NOT sorted.
		require.Len(t, seen.Properties.DNSSettings.Servers, 2)
		require.Equal(t, "10.0.0.4", *seen.Properties.DNSSettings.Servers[0])
		require.Equal(t, "10.0.0.5", *seen.Properties.DNSSettings.Servers[1])

		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, _ armnetwork.FirewallPolicy, _ *armnetwork.FirewallPoliciesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.FirewallPoliciesClientCreateOrUpdateResponse], error) {
			return newDonePoller(armnetwork.FirewallPoliciesClientCreateOrUpdateResponse{FirewallPolicy: model}), nil
		}
	})

	t.Run("Create_requires_location", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"resourceGroupName": "rg-1", "name": "fwp-1"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "location is required")
	})

	t.Run("Create_requires_resourceGroupName", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "fwp-1", "location": "eastus"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "resourceGroupName is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testFirewallPolicyNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
		require.Equal(t, ResourceTypeFirewallPolicy, got.ResourceType)
	})

	t.Run("Read_not_found", func(t *testing.T) {
		fake.getFn = func(_ context.Context, _, _ string, _ *armnetwork.FirewallPoliciesClientGetOptions) (armnetwork.FirewallPoliciesClientGetResponse, error) {
			return armnetwork.FirewallPoliciesClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testFirewallPolicyNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)

		fake.getFn = func(_ context.Context, _, _ string, _ *armnetwork.FirewallPoliciesClientGetOptions) (armnetwork.FirewallPoliciesClientGetResponse, error) {
			return armnetwork.FirewallPoliciesClientGetResponse{FirewallPolicy: model}, nil
		}
	})

	// UpdateTags accepts tags only, so threatIntelMode has to ride the full-body PUT.
	t.Run("Update_sends_full_body_put", func(t *testing.T) {
		var seen armnetwork.FirewallPolicy
		var seenRG, seenName string
		fake.beginCreateOrUpdateFn = func(_ context.Context, rg, name string, params armnetwork.FirewallPolicy, _ *armnetwork.FirewallPoliciesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.FirewallPoliciesClientCreateOrUpdateResponse], error) {
			seen, seenRG, seenName = params, rg, name
			return newDonePoller(armnetwork.FirewallPoliciesClientCreateOrUpdateResponse{FirewallPolicy: model}), nil
		}
		desired, _ := json.Marshal(map[string]any{
			// Wrong parents in the payload — the native ID must win.
			"resourceGroupName": "wrong-rg",
			"name":              "wrong-name",
			"location":          "eastus",
			"sku":               map[string]any{"tier": "Standard"},
			"threatIntelMode":   "Deny",
			"Tags":              []map[string]string{{"Key": "Environment", "Value": "updated"}},
		})
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testFirewallPolicyNativeID,
			DesiredProperties: desired,
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, "rg-1", seenRG)
		require.Equal(t, "fwp-1", seenName)
		require.Equal(t, armnetwork.AzureFirewallThreatIntelModeDeny, *seen.Properties.ThreatIntelMode)
		require.Equal(t, "updated", *seen.Tags["Environment"])
	})

	t.Run("Delete_in_progress_returns_lro_request_id", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testFirewallPolicyNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusInProgress, got.ProgressResult.OperationStatus)
		reqID, err := decodeLROStatus(got.ProgressResult.RequestID)
		require.NoError(t, err)
		require.Equal(t, lroOpDelete, reqID.OperationType)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _ string, _ *armnetwork.FirewallPoliciesClientBeginDeleteOptions) (*runtime.Poller[armnetwork.FirewallPoliciesClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testFirewallPolicyNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Status_rejects_unknown_operation", func(t *testing.T) {
		reqID, err := encodeLROStart("bogus", "token", testFirewallPolicyNativeID)
		require.NoError(t, err)
		got, err := prov.Status(context.Background(), &resource.StatusRequest{RequestID: reqID})
		require.Error(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_resource_group", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testFirewallPolicyNativeID}, got.NativeIDs)
	})

	t.Run("List_all", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Equal(t, []string{testFirewallPolicyNativeID}, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, _ armnetwork.FirewallPolicy, _ *armnetwork.FirewallPoliciesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.FirewallPoliciesClientCreateOrUpdateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 403}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

func TestFirewallPolicyIDParts(t *testing.T) {
	rg, name, err := firewallPolicyIDParts(testFirewallPolicyNativeID)
	require.NoError(t, err)
	require.Equal(t, "rg-1", rg)
	require.Equal(t, "fwp-1", name)

	// A rule collection group nests under a policy — the exact chain check rejects it.
	_, _, err = firewallPolicyIDParts(testFirewallPolicyNativeID + "/ruleCollectionGroups/rcg-1")
	require.Error(t, err)
}

// --- Test helpers ---

func newTestFirewallPolicy(api firewallPoliciesAPI) *FirewallPolicy {
	return &FirewallPolicy{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

type fakeFirewallPoliciesAPI struct {
	beginCreateOrUpdateFn func(ctx context.Context, rgName, name string, params armnetwork.FirewallPolicy, opts *armnetwork.FirewallPoliciesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.FirewallPoliciesClientCreateOrUpdateResponse], error)
	getFn                 func(ctx context.Context, rgName, name string, opts *armnetwork.FirewallPoliciesClientGetOptions) (armnetwork.FirewallPoliciesClientGetResponse, error)
	beginDeleteFn         func(ctx context.Context, rgName, name string, opts *armnetwork.FirewallPoliciesClientBeginDeleteOptions) (*runtime.Poller[armnetwork.FirewallPoliciesClientDeleteResponse], error)
	newListPagerFn        func(rgName string, opts *armnetwork.FirewallPoliciesClientListOptions) *runtime.Pager[armnetwork.FirewallPoliciesClientListResponse]
	newListAllPagerFn     func(opts *armnetwork.FirewallPoliciesClientListAllOptions) *runtime.Pager[armnetwork.FirewallPoliciesClientListAllResponse]
}

func (f *fakeFirewallPoliciesAPI) BeginCreateOrUpdate(ctx context.Context, rgName, name string, params armnetwork.FirewallPolicy, opts *armnetwork.FirewallPoliciesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.FirewallPoliciesClientCreateOrUpdateResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, rgName, name, params, opts)
}

func (f *fakeFirewallPoliciesAPI) Get(ctx context.Context, rgName, name string, opts *armnetwork.FirewallPoliciesClientGetOptions) (armnetwork.FirewallPoliciesClientGetResponse, error) {
	return f.getFn(ctx, rgName, name, opts)
}

func (f *fakeFirewallPoliciesAPI) BeginDelete(ctx context.Context, rgName, name string, opts *armnetwork.FirewallPoliciesClientBeginDeleteOptions) (*runtime.Poller[armnetwork.FirewallPoliciesClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, name, opts)
}

func (f *fakeFirewallPoliciesAPI) NewListPager(rgName string, opts *armnetwork.FirewallPoliciesClientListOptions) *runtime.Pager[armnetwork.FirewallPoliciesClientListResponse] {
	return f.newListPagerFn(rgName, opts)
}

func (f *fakeFirewallPoliciesAPI) NewListAllPager(opts *armnetwork.FirewallPoliciesClientListAllOptions) *runtime.Pager[armnetwork.FirewallPoliciesClientListAllResponse] {
	return f.newListAllPagerFn(opts)
}
