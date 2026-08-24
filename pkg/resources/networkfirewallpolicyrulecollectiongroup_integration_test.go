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

const testRuleCollectionGroupNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/firewallPolicies/fp1/ruleCollectionGroups/rcg1"

type fakeFirewallRuleCollectionGroupsAPI struct {
	beginCreateOrUpdateFn func(ctx context.Context, rgName, policyName, name string, params armnetwork.FirewallPolicyRuleCollectionGroup, options *armnetwork.FirewallPolicyRuleCollectionGroupsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.FirewallPolicyRuleCollectionGroupsClientCreateOrUpdateResponse], error)
	getFn                 func(ctx context.Context, rgName, policyName, name string, options *armnetwork.FirewallPolicyRuleCollectionGroupsClientGetOptions) (armnetwork.FirewallPolicyRuleCollectionGroupsClientGetResponse, error)
	beginDeleteFn         func(ctx context.Context, rgName, policyName, name string, options *armnetwork.FirewallPolicyRuleCollectionGroupsClientBeginDeleteOptions) (*runtime.Poller[armnetwork.FirewallPolicyRuleCollectionGroupsClientDeleteResponse], error)
	newListPagerFn        func(rgName, policyName string, options *armnetwork.FirewallPolicyRuleCollectionGroupsClientListOptions) *runtime.Pager[armnetwork.FirewallPolicyRuleCollectionGroupsClientListResponse]
}

func (f *fakeFirewallRuleCollectionGroupsAPI) BeginCreateOrUpdate(ctx context.Context, rgName, policyName, name string, params armnetwork.FirewallPolicyRuleCollectionGroup, options *armnetwork.FirewallPolicyRuleCollectionGroupsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.FirewallPolicyRuleCollectionGroupsClientCreateOrUpdateResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, rgName, policyName, name, params, options)
}

func (f *fakeFirewallRuleCollectionGroupsAPI) Get(ctx context.Context, rgName, policyName, name string, options *armnetwork.FirewallPolicyRuleCollectionGroupsClientGetOptions) (armnetwork.FirewallPolicyRuleCollectionGroupsClientGetResponse, error) {
	return f.getFn(ctx, rgName, policyName, name, options)
}

func (f *fakeFirewallRuleCollectionGroupsAPI) BeginDelete(ctx context.Context, rgName, policyName, name string, options *armnetwork.FirewallPolicyRuleCollectionGroupsClientBeginDeleteOptions) (*runtime.Poller[armnetwork.FirewallPolicyRuleCollectionGroupsClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, policyName, name, options)
}

func (f *fakeFirewallRuleCollectionGroupsAPI) NewListPager(rgName, policyName string, options *armnetwork.FirewallPolicyRuleCollectionGroupsClientListOptions) *runtime.Pager[armnetwork.FirewallPolicyRuleCollectionGroupsClientListResponse] {
	return f.newListPagerFn(rgName, policyName, options)
}

func newTestRuleCollectionGroup(api networkFirewallRuleCollectionGroupsAPI, policies networkFirewallPoliciesAPI) *NetworkFirewallPolicyRuleCollectionGroup {
	return &NetworkFirewallPolicyRuleCollectionGroup{
		api:      api,
		policies: policies,
		config:   &config.Config{SubscriptionId: "sub-1"},
	}
}

// policyInState is the parent lookup the delete settle phase makes.
func policyInState(state armnetwork.ProvisioningState) *fakeFirewallPoliciesAPI {
	return &fakeFirewallPoliciesAPI{
		getFn: func(_ context.Context, _, _ string, _ *armnetwork.FirewallPoliciesClientGetOptions) (armnetwork.FirewallPoliciesClientGetResponse, error) {
			return armnetwork.FirewallPoliciesClientGetResponse{
				FirewallPolicy: armnetwork.FirewallPolicy{
					Properties: &armnetwork.FirewallPolicyPropertiesFormat{ProvisioningState: to.Ptr(state)},
				},
			}, nil
		},
	}
}

func ruleCollectionGroupDesired(ports []any) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":               "rcg1",
		"resourceGroupName":  "rg-1",
		"firewallPolicyName": "fp1",
		"priority":           300,
		"ruleCollections": []any{map[string]any{
			"name":     "allow-web",
			"priority": 400,
			"action":   "Allow",
			"networkRules": []any{map[string]any{
				"name":                 "https",
				"description":          "outbound https",
				"ipProtocols":          []any{"TCP"},
				"sourceAddresses":      []any{"10.0.0.0/24"},
				"destinationAddresses": []any{"*"},
				"destinationPorts":     ports,
			}},
		}},
	})
	return out
}

func TestNetworkFirewallPolicyRuleCollectionGroup_CRUD(t *testing.T) {
	groupResult := armnetwork.FirewallPolicyRuleCollectionGroup{
		ID:   to.Ptr(testRuleCollectionGroupNativeID),
		Name: to.Ptr("rcg1"),
		Properties: &armnetwork.FirewallPolicyRuleCollectionGroupProperties{
			Priority: to.Ptr(int32(300)),
			RuleCollections: []armnetwork.FirewallPolicyRuleCollectionClassification{
				&armnetwork.FirewallPolicyFilterRuleCollection{
					RuleCollectionType: to.Ptr(armnetwork.FirewallPolicyRuleCollectionTypeFirewallPolicyFilterRuleCollection),
					Name:               to.Ptr("allow-web"),
					Priority:           to.Ptr(int32(400)),
					Action: &armnetwork.FirewallPolicyFilterRuleCollectionAction{
						Type: to.Ptr(armnetwork.FirewallPolicyFilterRuleCollectionActionTypeAllow),
					},
					Rules: []armnetwork.FirewallPolicyRuleClassification{
						&armnetwork.Rule{
							RuleType:             to.Ptr(armnetwork.FirewallPolicyRuleTypeNetworkRule),
							Name:                 to.Ptr("https"),
							Description:          to.Ptr("outbound https"),
							IPProtocols:          []*armnetwork.FirewallPolicyRuleNetworkProtocol{to.Ptr(armnetwork.FirewallPolicyRuleNetworkProtocolTCP)},
							SourceAddresses:      []*string{to.Ptr("10.0.0.0/24")},
							DestinationAddresses: []*string{to.Ptr("*")},
							DestinationPorts:     []*string{to.Ptr("443")},
						},
					},
				},
			},
			// Service state, never desired state.
			ProvisioningState: to.Ptr(armnetwork.ProvisioningStateSucceeded),
			Size:              to.Ptr("236B"),
		},
		Etag: to.Ptr("W/\"etag\""),
	}

	var sent armnetwork.FirewallPolicyRuleCollectionGroup
	createCalls := 0
	deleteCalls := 0
	fake := &fakeFirewallRuleCollectionGroupsAPI{
		beginCreateOrUpdateFn: func(_ context.Context, rgName, policyName, name string, params armnetwork.FirewallPolicyRuleCollectionGroup, _ *armnetwork.FirewallPolicyRuleCollectionGroupsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.FirewallPolicyRuleCollectionGroupsClientCreateOrUpdateResponse], error) {
			require.Equal(t, "rg-1", rgName)
			require.Equal(t, "fp1", policyName)
			require.Equal(t, "rcg1", name)
			sent = params
			createCalls++
			return newDonePoller(armnetwork.FirewallPolicyRuleCollectionGroupsClientCreateOrUpdateResponse{FirewallPolicyRuleCollectionGroup: groupResult}), nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ *armnetwork.FirewallPolicyRuleCollectionGroupsClientGetOptions) (armnetwork.FirewallPolicyRuleCollectionGroupsClientGetResponse, error) {
			return armnetwork.FirewallPolicyRuleCollectionGroupsClientGetResponse{FirewallPolicyRuleCollectionGroup: groupResult}, nil
		},
		beginDeleteFn: func(_ context.Context, _, _, _ string, _ *armnetwork.FirewallPolicyRuleCollectionGroupsClientBeginDeleteOptions) (*runtime.Poller[armnetwork.FirewallPolicyRuleCollectionGroupsClientDeleteResponse], error) {
			deleteCalls++
			return newDonePoller(armnetwork.FirewallPolicyRuleCollectionGroupsClientDeleteResponse{}), nil
		},
		newListPagerFn: func(_, _ string, _ *armnetwork.FirewallPolicyRuleCollectionGroupsClientListOptions) *runtime.Pager[armnetwork.FirewallPolicyRuleCollectionGroupsClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armnetwork.FirewallPolicyRuleCollectionGroupsClientListResponse]{
				More: func(_ armnetwork.FirewallPolicyRuleCollectionGroupsClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armnetwork.FirewallPolicyRuleCollectionGroupsClientListResponse) (armnetwork.FirewallPolicyRuleCollectionGroupsClientListResponse, error) {
					return armnetwork.FirewallPolicyRuleCollectionGroupsClientListResponse{
						FirewallPolicyRuleCollectionGroupListResult: armnetwork.FirewallPolicyRuleCollectionGroupListResult{
							Value: []*armnetwork.FirewallPolicyRuleCollectionGroup{{ID: to.Ptr(testRuleCollectionGroupNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestRuleCollectionGroup(fake, policyInState(armnetwork.ProvisioningStateSucceeded))

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "rcg1", Properties: ruleCollectionGroupDesired([]any{"443"}),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testRuleCollectionGroupNativeID, got.ProgressResult.NativeID)

		require.Equal(t, int32(300), *sent.Properties.Priority)
		require.Len(t, sent.Properties.RuleCollections, 1)

		filter := sent.Properties.RuleCollections[0].(*armnetwork.FirewallPolicyFilterRuleCollection)
		// ARM rejects a collection without its discriminator.
		require.Equal(t, armnetwork.FirewallPolicyRuleCollectionTypeFirewallPolicyFilterRuleCollection, *filter.RuleCollectionType)
		require.Equal(t, "allow-web", *filter.Name)
		require.Equal(t, int32(400), *filter.Priority)
		require.Equal(t, armnetwork.FirewallPolicyFilterRuleCollectionActionTypeAllow, *filter.Action.Type)

		rule := filter.Rules[0].(*armnetwork.Rule)
		require.Equal(t, armnetwork.FirewallPolicyRuleTypeNetworkRule, *rule.RuleType)
		require.Equal(t, "https", *rule.Name)
		require.Equal(t, "outbound https", *rule.Description)
		require.Equal(t, armnetwork.FirewallPolicyRuleNetworkProtocolTCP, *rule.IPProtocols[0])
		require.Equal(t, "10.0.0.0/24", *rule.SourceAddresses[0])
		require.Equal(t, "*", *rule.DestinationAddresses[0])
		require.Equal(t, "443", *rule.DestinationPorts[0])
	})

	t.Run("Create_requires_firewall_policy", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "rcg1", "resourceGroupName": "rg-1"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "firewallPolicyName is required")
	})

	t.Run("Create_requires_rule_collections", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "rcg1", "resourceGroupName": "rg-1", "firewallPolicyName": "fp1", "priority": 300,
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "ruleCollections is required")
	})

	// The native ID reported while the LRO is still running must match the path ARM
	// actually assigns, or the resource is orphaned once it completes.
	t.Run("PendingCreateReportsRealNativeID", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _, _ string, _ armnetwork.FirewallPolicyRuleCollectionGroup, _ *armnetwork.FirewallPolicyRuleCollectionGroupsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.FirewallPolicyRuleCollectionGroupsClientCreateOrUpdateResponse], error) {
			return newPendingPoller[armnetwork.FirewallPolicyRuleCollectionGroupsClientCreateOrUpdateResponse](), nil
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "rcg1", Properties: ruleCollectionGroupDesired([]any{"443"}),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusInProgress, got.ProgressResult.OperationStatus)
		require.Equal(t, testRuleCollectionGroupNativeID, got.ProgressResult.NativeID)
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testRuleCollectionGroupNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "rcg1", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "fp1", props["firewallPolicyName"])
		require.EqualValues(t, 300, props["priority"])

		collections := props["ruleCollections"].([]any)
		require.Len(t, collections, 1)
		collection := collections[0].(map[string]any)
		require.Equal(t, "allow-web", collection["name"])
		require.EqualValues(t, 400, collection["priority"])
		require.Equal(t, "Allow", collection["action"])

		rules := collection["networkRules"].([]any)
		rule := rules[0].(map[string]any)
		require.Equal(t, "https", rule["name"])
		require.Equal(t, []any{"TCP"}, rule["ipProtocols"])
		require.Equal(t, []any{"10.0.0.0/24"}, rule["sourceAddresses"])
		require.Equal(t, []any{"443"}, rule["destinationPorts"])
	})

	t.Run("Read_drops_service_state", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testRuleCollectionGroupNativeID})
		require.NoError(t, err)
		for _, key := range []string{"provisioningState", "size", "etag", "ruleCollectionType", "ruleType"} {
			require.NotContains(t, got.Properties, key)
		}
	})

	// NAT collections and application rules are outside this schema. Reading them
	// back would produce drift on every sync, so they are skipped entirely.
	t.Run("Read_skips_unmodelled_collection_shapes", func(t *testing.T) {
		fake.getFn = func(_ context.Context, _, _, _ string, _ *armnetwork.FirewallPolicyRuleCollectionGroupsClientGetOptions) (armnetwork.FirewallPolicyRuleCollectionGroupsClientGetResponse, error) {
			return armnetwork.FirewallPolicyRuleCollectionGroupsClientGetResponse{
				FirewallPolicyRuleCollectionGroup: armnetwork.FirewallPolicyRuleCollectionGroup{
					ID:   to.Ptr(testRuleCollectionGroupNativeID),
					Name: to.Ptr("rcg1"),
					Properties: &armnetwork.FirewallPolicyRuleCollectionGroupProperties{
						Priority: to.Ptr(int32(300)),
						RuleCollections: []armnetwork.FirewallPolicyRuleCollectionClassification{
							&armnetwork.FirewallPolicyNatRuleCollection{
								RuleCollectionType: to.Ptr(armnetwork.FirewallPolicyRuleCollectionTypeFirewallPolicyNatRuleCollection),
								Name:               to.Ptr("dnat"),
								Priority:           to.Ptr(int32(200)),
							},
							// A filter collection holding only application rules has
							// nothing expressible, so it is dropped too.
							&armnetwork.FirewallPolicyFilterRuleCollection{
								RuleCollectionType: to.Ptr(armnetwork.FirewallPolicyRuleCollectionTypeFirewallPolicyFilterRuleCollection),
								Name:               to.Ptr("app-only"),
								Priority:           to.Ptr(int32(500)),
								Rules: []armnetwork.FirewallPolicyRuleClassification{
									&armnetwork.ApplicationRule{
										RuleType:        to.Ptr(armnetwork.FirewallPolicyRuleTypeApplicationRule),
										Name:            to.Ptr("allow-github"),
										TargetFqdns:     []*string{to.Ptr("github.com")},
										SourceAddresses: []*string{to.Ptr("10.0.0.0/24")},
									},
								},
							},
						},
					},
				},
			}, nil
		}
		defer func() {
			fake.getFn = func(_ context.Context, _, _, _ string, _ *armnetwork.FirewallPolicyRuleCollectionGroupsClientGetOptions) (armnetwork.FirewallPolicyRuleCollectionGroupsClientGetResponse, error) {
				return armnetwork.FirewallPolicyRuleCollectionGroupsClientGetResponse{FirewallPolicyRuleCollectionGroup: groupResult}, nil
			}
		}()

		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testRuleCollectionGroupNativeID})
		require.NoError(t, err)
		require.NotContains(t, got.Properties, "dnat")
		require.NotContains(t, got.Properties, "app-only")
		require.NotContains(t, got.Properties, "github.com")
		require.NotContains(t, got.Properties, "ruleCollections")
	})

	// There is no PATCH verb for this type, so Update re-PUTs the whole group.
	t.Run("Update_reissues_create_or_update", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _, _ string, params armnetwork.FirewallPolicyRuleCollectionGroup, _ *armnetwork.FirewallPolicyRuleCollectionGroupsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.FirewallPolicyRuleCollectionGroupsClientCreateOrUpdateResponse], error) {
			sent = params
			createCalls++
			return newDonePoller(armnetwork.FirewallPolicyRuleCollectionGroupsClientCreateOrUpdateResponse{FirewallPolicyRuleCollectionGroup: groupResult}), nil
		}
		before := createCalls
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testRuleCollectionGroupNativeID,
			DesiredProperties: ruleCollectionGroupDesired([]any{"443", "8443"}),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, createCalls)

		filter := sent.Properties.RuleCollections[0].(*armnetwork.FirewallPolicyFilterRuleCollection)
		rule := filter.Rules[0].(*armnetwork.Rule)
		require.Len(t, rule.DestinationPorts, 2)
		require.Equal(t, "8443", *rule.DestinationPorts[1])
	})

	// ARM answers this DELETE synchronously but leaves the parent policy Updating, so
	// the delete is only reported complete after a settle phase.
	t.Run("Delete_waits_for_parent_to_settle", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testRuleCollectionGroupNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusInProgress, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)

		reqID, err := decodeLROStatus(got.ProgressResult.RequestID)
		require.NoError(t, err)
		require.Equal(t, rcgOpDeleteSettle, reqID.OperationType)

		status, err := prov.Status(context.Background(), &resource.StatusRequest{
			RequestID: got.ProgressResult.RequestID, NativeID: testRuleCollectionGroupNativeID,
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, status.ProgressResult.OperationStatus)
	})

	// Deleting the policy while it is still Updating is rejected with
	// FirewallPolicyDeleteNotAllowedWhenUpdatingOrDeleting, so keep waiting.
	t.Run("Delete_settle_pending_while_parent_updating", func(t *testing.T) {
		waiting := newTestRuleCollectionGroup(fake, policyInState(armnetwork.ProvisioningStateUpdating))
		settleID, err := encodeLROStart(rcgOpDeleteSettle, "", testRuleCollectionGroupNativeID)
		require.NoError(t, err)

		status, err := waiting.Status(context.Background(), &resource.StatusRequest{
			RequestID: settleID, NativeID: testRuleCollectionGroupNativeID,
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusInProgress, status.ProgressResult.OperationStatus)
	})

	// A parent that is already gone cannot block anything.
	t.Run("Delete_settle_succeeds_when_parent_missing", func(t *testing.T) {
		gone := newTestRuleCollectionGroup(fake, &fakeFirewallPoliciesAPI{
			getFn: func(_ context.Context, _, _ string, _ *armnetwork.FirewallPoliciesClientGetOptions) (armnetwork.FirewallPoliciesClientGetResponse, error) {
				return armnetwork.FirewallPoliciesClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
			},
		})
		settleID, err := encodeLROStart(rcgOpDeleteSettle, "", testRuleCollectionGroupNativeID)
		require.NoError(t, err)

		status, err := gone.Status(context.Background(), &resource.StatusRequest{
			RequestID: settleID, NativeID: testRuleCollectionGroupNativeID,
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, status.ProgressResult.OperationStatus)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _, _ string, _ *armnetwork.FirewallPolicyRuleCollectionGroupsClientBeginDeleteOptions) (*runtime.Poller[armnetwork.FirewallPolicyRuleCollectionGroupsClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testRuleCollectionGroupNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "firewallPolicyName": "fp1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testRuleCollectionGroupNativeID}, got.NativeIDs)
	})

	// ARM offers no subscription-wide listing, so without both scoping properties
	// there is nothing to enumerate.
	t.Run("List_without_scope_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})
}
