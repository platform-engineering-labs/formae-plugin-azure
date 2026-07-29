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

const testRuleCollectionGroupNativeID = testFirewallPolicyNativeID + "/ruleCollectionGroups/rcg-1"

// networkRuleCollection mirrors what ARM returns: the SDK has already resolved the
// polymorphic union into concrete *armnetwork.Rule / *armnetwork.ApplicationRule.
func fwpModelGroup() armnetwork.FirewallPolicyRuleCollectionGroup {
	return armnetwork.FirewallPolicyRuleCollectionGroup{
		ID:   to.Ptr(testRuleCollectionGroupNativeID),
		Name: to.Ptr("rcg-1"),
		Etag: to.Ptr("W/\"etag-1\""),
		Properties: &armnetwork.FirewallPolicyRuleCollectionGroupProperties{
			Priority: to.Ptr(int32(200)),
			RuleCollections: []armnetwork.FirewallPolicyRuleCollectionClassification{
				&armnetwork.FirewallPolicyFilterRuleCollection{
					RuleCollectionType: to.Ptr(armnetwork.FirewallPolicyRuleCollectionTypeFirewallPolicyFilterRuleCollection),
					Name:               to.Ptr("allow-network"),
					Priority:           to.Ptr(int32(300)),
					Action: &armnetwork.FirewallPolicyFilterRuleCollectionAction{
						Type: to.Ptr(armnetwork.FirewallPolicyFilterRuleCollectionActionTypeAllow),
					},
					Rules: []armnetwork.FirewallPolicyRuleClassification{
						&armnetwork.Rule{
							RuleType:             to.Ptr(armnetwork.FirewallPolicyRuleTypeNetworkRule),
							Name:                 to.Ptr("allow-https-out"),
							IPProtocols:          []*armnetwork.FirewallPolicyRuleNetworkProtocol{to.Ptr(armnetwork.FirewallPolicyRuleNetworkProtocolTCP)},
							SourceAddresses:      []*string{to.Ptr("10.40.0.0/16")},
							DestinationAddresses: []*string{to.Ptr("*")},
							DestinationPorts:     []*string{to.Ptr("443")},
						},
					},
				},
				&armnetwork.FirewallPolicyFilterRuleCollection{
					RuleCollectionType: to.Ptr(armnetwork.FirewallPolicyRuleCollectionTypeFirewallPolicyFilterRuleCollection),
					Name:               to.Ptr("allow-application"),
					Priority:           to.Ptr(int32(400)),
					Action: &armnetwork.FirewallPolicyFilterRuleCollectionAction{
						Type: to.Ptr(armnetwork.FirewallPolicyFilterRuleCollectionActionTypeAllow),
					},
					Rules: []armnetwork.FirewallPolicyRuleClassification{
						&armnetwork.ApplicationRule{
							RuleType: to.Ptr(armnetwork.FirewallPolicyRuleTypeApplicationRule),
							Name:     to.Ptr("allow-microsoft"),
							Protocols: []*armnetwork.FirewallPolicyRuleApplicationProtocol{{
								ProtocolType: to.Ptr(armnetwork.FirewallPolicyRuleApplicationProtocolTypeHTTPS),
								Port:         to.Ptr(int32(443)),
							}},
							SourceAddresses: []*string{to.Ptr("10.40.0.0/16")},
							TargetFqdns:     []*string{to.Ptr("*.microsoft.com")},
						},
					},
				},
			},
			// Read-only ARM output with no schema field.
			ProvisioningState: to.Ptr(armnetwork.ProvisioningStateSucceeded),
			Size:              to.Ptr("1.2MB"),
		},
	}
}

func TestFirewallPolicyRuleCollectionGroup_CRUD(t *testing.T) {
	model := fwpModelGroup()
	fake := &fakeRuleCollectionGroupsAPI{
		beginCreateOrUpdateFn: func(_ context.Context, _, _, _ string, _ armnetwork.FirewallPolicyRuleCollectionGroup, _ *armnetwork.FirewallPolicyRuleCollectionGroupsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.FirewallPolicyRuleCollectionGroupsClientCreateOrUpdateResponse], error) {
			return newDonePoller(armnetwork.FirewallPolicyRuleCollectionGroupsClientCreateOrUpdateResponse{FirewallPolicyRuleCollectionGroup: model}), nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ *armnetwork.FirewallPolicyRuleCollectionGroupsClientGetOptions) (armnetwork.FirewallPolicyRuleCollectionGroupsClientGetResponse, error) {
			return armnetwork.FirewallPolicyRuleCollectionGroupsClientGetResponse{FirewallPolicyRuleCollectionGroup: model}, nil
		},
		beginDeleteFn: func(_ context.Context, _, _, _ string, _ *armnetwork.FirewallPolicyRuleCollectionGroupsClientBeginDeleteOptions) (*runtime.Poller[armnetwork.FirewallPolicyRuleCollectionGroupsClientDeleteResponse], error) {
			return newInProgressPoller[armnetwork.FirewallPolicyRuleCollectionGroupsClientDeleteResponse](), nil
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
		getPolicyFn: func(_ context.Context, _, _ string, _ *armnetwork.FirewallPoliciesClientGetOptions) (armnetwork.FirewallPoliciesClientGetResponse, error) {
			return armnetwork.FirewallPoliciesClientGetResponse{FirewallPolicy: armnetwork.FirewallPolicy{
				Properties: &armnetwork.FirewallPolicyPropertiesFormat{
					ProvisioningState: to.Ptr(armnetwork.ProvisioningStateSucceeded),
				},
			}}, nil
		},
		newListAllPoliciesPagerFn: func(_ *armnetwork.FirewallPoliciesClientListAllOptions) *runtime.Pager[armnetwork.FirewallPoliciesClientListAllResponse] {
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
	prov := newTestRuleCollectionGroup(fake)

	networkRule := map[string]any{
		"ruleType":             "NetworkRule",
		"name":                 "allow-https-out",
		"ipProtocols":          []any{"TCP"},
		"sourceAddresses":      []any{"10.40.0.0/16"},
		"destinationAddresses": []any{"*"},
		"destinationPorts":     []any{"443"},
	}
	applicationRule := map[string]any{
		"ruleType":        "ApplicationRule",
		"name":            "allow-microsoft",
		"protocols":       []any{map[string]any{"protocolType": "Https", "port": 443}},
		"sourceAddresses": []any{"10.40.0.0/16"},
		"targetFqdns":     []any{"*.microsoft.com"},
	}
	mkProps := func() json.RawMessage {
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName":  "rg-1",
			"firewallPolicyName": "fwp-1",
			"name":               "rcg-1",
			"priority":           200,
			"ruleCollections": []any{
				map[string]any{
					"ruleCollectionType": "FirewallPolicyFilterRuleCollection",
					"name":               "allow-network",
					"priority":           300,
					"action":             map[string]any{"type": "Allow"},
					"rules":              []any{networkRule},
				},
				map[string]any{
					"ruleCollectionType": "FirewallPolicyFilterRuleCollection",
					"name":               "allow-application",
					"priority":           400,
					"action":             map[string]any{"type": "Allow"},
					"rules":              []any{applicationRule},
				},
			},
		})
		return props
	}

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testRuleCollectionGroupNativeID, got.ProgressResult.NativeID)
	})

	// The union round-trip is the whole risk in this resource: ARM hands back
	// interface values, and serialize has to discriminate them back into the same
	// shape the forma declared.
	t.Run("Serialize_round_trips_the_rule_union", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testRuleCollectionGroupNativeID})
		require.NoError(t, err)
		var serialized map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &serialized))

		require.Equal(t, "rg-1", serialized["resourceGroupName"])
		require.Equal(t, "fwp-1", serialized["firewallPolicyName"])
		require.Equal(t, float64(200), serialized["priority"])

		collections := serialized["ruleCollections"].([]any)
		require.Len(t, collections, 2)

		net := collections[0].(map[string]any)
		require.Equal(t, "FirewallPolicyFilterRuleCollection", net["ruleCollectionType"])
		require.Equal(t, "allow-network", net["name"])
		require.Equal(t, float64(300), net["priority"])
		require.Equal(t, map[string]any{"type": "Allow"}, net["action"])
		netRules := net["rules"].([]any)
		require.Len(t, netRules, 1)
		require.Equal(t, map[string]any{
			"ruleType":             "NetworkRule",
			"name":                 "allow-https-out",
			"ipProtocols":          []any{"TCP"},
			"sourceAddresses":      []any{"10.40.0.0/16"},
			"destinationAddresses": []any{"*"},
			"destinationPorts":     []any{"443"},
		}, netRules[0])

		app := collections[1].(map[string]any)
		appRules := app["rules"].([]any)
		require.Len(t, appRules, 1)
		require.Equal(t, map[string]any{
			"ruleType":        "ApplicationRule",
			"name":            "allow-microsoft",
			"protocols":       []any{map[string]any{"protocolType": "Https", "port": float64(443)}},
			"sourceAddresses": []any{"10.40.0.0/16"},
			"targetFqdns":     []any{"*.microsoft.com"},
		}, appRules[0])

		require.NotContains(t, serialized, "provisioningState")
		require.NotContains(t, serialized, "size")
		require.NotContains(t, serialized, "etag")
	})

	t.Run("Create_builds_concrete_union_types", func(t *testing.T) {
		var seen armnetwork.FirewallPolicyRuleCollectionGroup
		var seenRG, seenPolicy, seenName string
		fake.beginCreateOrUpdateFn = func(_ context.Context, rg, policy, name string, params armnetwork.FirewallPolicyRuleCollectionGroup, _ *armnetwork.FirewallPolicyRuleCollectionGroupsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.FirewallPolicyRuleCollectionGroupsClientCreateOrUpdateResponse], error) {
			seen, seenRG, seenPolicy, seenName = params, rg, policy, name
			return newDonePoller(armnetwork.FirewallPolicyRuleCollectionGroupsClientCreateOrUpdateResponse{FirewallPolicyRuleCollectionGroup: model}), nil
		}
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, "rg-1", seenRG)
		require.Equal(t, "fwp-1", seenPolicy)
		require.Equal(t, "rcg-1", seenName)
		require.Equal(t, int32(200), *seen.Properties.Priority)
		require.Len(t, seen.Properties.RuleCollections, 2)

		netCollection, ok := seen.Properties.RuleCollections[0].(*armnetwork.FirewallPolicyFilterRuleCollection)
		require.True(t, ok, "first collection must be a filter collection")
		require.Equal(t, armnetwork.FirewallPolicyFilterRuleCollectionActionTypeAllow, *netCollection.Action.Type)
		netRule, ok := netCollection.Rules[0].(*armnetwork.Rule)
		require.True(t, ok, "network rule must build as *armnetwork.Rule")
		require.Equal(t, armnetwork.FirewallPolicyRuleTypeNetworkRule, *netRule.RuleType)
		require.Equal(t, armnetwork.FirewallPolicyRuleNetworkProtocolTCP, *netRule.IPProtocols[0])
		require.Equal(t, "443", *netRule.DestinationPorts[0])

		appCollection := seen.Properties.RuleCollections[1].(*armnetwork.FirewallPolicyFilterRuleCollection)
		appRule, ok := appCollection.Rules[0].(*armnetwork.ApplicationRule)
		require.True(t, ok, "application rule must build as *armnetwork.ApplicationRule")
		require.Equal(t, armnetwork.FirewallPolicyRuleApplicationProtocolTypeHTTPS, *appRule.Protocols[0].ProtocolType)
		require.Equal(t, int32(443), *appRule.Protocols[0].Port)
		require.Equal(t, "*.microsoft.com", *appRule.TargetFqdns[0])

		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _, _ string, _ armnetwork.FirewallPolicyRuleCollectionGroup, _ *armnetwork.FirewallPolicyRuleCollectionGroupsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.FirewallPolicyRuleCollectionGroupsClientCreateOrUpdateResponse], error) {
			return newDonePoller(armnetwork.FirewallPolicyRuleCollectionGroupsClientCreateOrUpdateResponse{FirewallPolicyRuleCollectionGroup: model}), nil
		}
	})

	// An unsupported union member must fail loudly rather than be silently dropped —
	// a dropped NAT collection would look like a successful apply that did nothing.
	t.Run("Create_rejects_nat_rule_collection", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName":  "rg-1",
			"firewallPolicyName": "fwp-1",
			"name":               "rcg-1",
			"priority":           200,
			"ruleCollections": []any{
				map[string]any{
					"ruleCollectionType": "FirewallPolicyNatRuleCollection",
					"name":               "dnat",
					"priority":           300,
				},
			},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "unsupported ruleCollectionType")
		require.ErrorContains(t, err, "FirewallPolicyNatRuleCollection")
	})

	t.Run("Create_rejects_unknown_rule_type", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName":  "rg-1",
			"firewallPolicyName": "fwp-1",
			"name":               "rcg-1",
			"priority":           200,
			"ruleCollections": []any{
				map[string]any{
					"ruleCollectionType": "FirewallPolicyFilterRuleCollection",
					"name":               "c1",
					"priority":           300,
					"action":             map[string]any{"type": "Allow"},
					"rules":              []any{map[string]any{"ruleType": "NatRule", "name": "r1"}},
				},
			},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "unsupported ruleType")
	})

	t.Run("Create_requires_priority", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName": "rg-1", "firewallPolicyName": "fwp-1", "name": "rcg-1",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "priority is required")
	})

	t.Run("Create_requires_firewallPolicyName", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"resourceGroupName": "rg-1", "name": "rcg-1", "priority": 200})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "firewallPolicyName is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testRuleCollectionGroupNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
		require.Equal(t, ResourceTypeFirewallPolicyRuleCollectionGroup, got.ResourceType)
	})

	t.Run("Read_not_found", func(t *testing.T) {
		fake.getFn = func(_ context.Context, _, _, _ string, _ *armnetwork.FirewallPolicyRuleCollectionGroupsClientGetOptions) (armnetwork.FirewallPolicyRuleCollectionGroupsClientGetResponse, error) {
			return armnetwork.FirewallPolicyRuleCollectionGroupsClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testRuleCollectionGroupNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)

		fake.getFn = func(_ context.Context, _, _, _ string, _ *armnetwork.FirewallPolicyRuleCollectionGroupsClientGetOptions) (armnetwork.FirewallPolicyRuleCollectionGroupsClientGetResponse, error) {
			return armnetwork.FirewallPolicyRuleCollectionGroupsClientGetResponse{FirewallPolicyRuleCollectionGroup: model}, nil
		}
	})

	// No PATCH verb: the PUT replaces the entire rule set, and parents come from the
	// native ID.
	t.Run("Update_replaces_whole_rule_set", func(t *testing.T) {
		var seen armnetwork.FirewallPolicyRuleCollectionGroup
		var seenRG, seenPolicy, seenName string
		fake.beginCreateOrUpdateFn = func(_ context.Context, rg, policy, name string, params armnetwork.FirewallPolicyRuleCollectionGroup, _ *armnetwork.FirewallPolicyRuleCollectionGroupsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.FirewallPolicyRuleCollectionGroupsClientCreateOrUpdateResponse], error) {
			seen, seenRG, seenPolicy, seenName = params, rg, policy, name
			return newDonePoller(armnetwork.FirewallPolicyRuleCollectionGroupsClientCreateOrUpdateResponse{FirewallPolicyRuleCollectionGroup: model}), nil
		}
		desired, _ := json.Marshal(map[string]any{
			// Wrong parents in the payload — the native ID must win.
			"resourceGroupName":  "wrong-rg",
			"firewallPolicyName": "wrong-policy",
			"name":               "wrong-name",
			"priority":           200,
			"ruleCollections": []any{
				map[string]any{
					"ruleCollectionType": "FirewallPolicyFilterRuleCollection",
					"name":               "allow-network",
					"priority":           300,
					"action":             map[string]any{"type": "Allow"},
					"rules": []any{map[string]any{
						"ruleType":             "NetworkRule",
						"name":                 "allow-https-out",
						"ipProtocols":          []any{"TCP"},
						"sourceAddresses":      []any{"10.40.0.0/16"},
						"destinationAddresses": []any{"*"},
						"destinationPorts":     []any{"443", "80"},
					}},
				},
			},
		})
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testRuleCollectionGroupNativeID,
			DesiredProperties: desired,
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, "rg-1", seenRG)
		require.Equal(t, "fwp-1", seenPolicy)
		require.Equal(t, "rcg-1", seenName)
		// One collection now, not two — the PUT is the complete desired state.
		require.Len(t, seen.Properties.RuleCollections, 1)
		rule := seen.Properties.RuleCollections[0].(*armnetwork.FirewallPolicyFilterRuleCollection).Rules[0].(*armnetwork.Rule)
		require.Len(t, rule.DestinationPorts, 2)
	})

	t.Run("Delete_in_progress_returns_lro_request_id", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testRuleCollectionGroupNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusInProgress, got.ProgressResult.OperationStatus)
		reqID, err := decodeLROStatus(got.ProgressResult.RequestID)
		require.NoError(t, err)
		require.Equal(t, lroOpDelete, reqID.OperationType)
	})

	// A terminal poller cannot produce a resume token, so a synchronous delete has to
	// hand back a tokenless request ID — otherwise ResumeToken() errors and the whole
	// delete fails on what was actually a success.
	t.Run("Delete_completed_synchronously_still_waits_on_parent", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _, _ string, _ *armnetwork.FirewallPolicyRuleCollectionGroupsClientBeginDeleteOptions) (*runtime.Poller[armnetwork.FirewallPolicyRuleCollectionGroupsClientDeleteResponse], error) {
			return newDonePoller(armnetwork.FirewallPolicyRuleCollectionGroupsClientDeleteResponse{}), nil
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testRuleCollectionGroupNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusInProgress, got.ProgressResult.OperationStatus)
		reqID, err := decodeLROStatus(got.ProgressResult.RequestID)
		require.NoError(t, err)
		require.Equal(t, lroOpDeleteSettleParent, reqID.OperationType)
		require.Empty(t, reqID.ResumeToken)

		// Status on that request ID goes straight to the parent check, no poller.
		status, err := prov.Status(context.Background(), &resource.StatusRequest{RequestID: got.ProgressResult.RequestID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, status.ProgressResult.OperationStatus)

		fake.beginDeleteFn = func(_ context.Context, _, _, _ string, _ *armnetwork.FirewallPolicyRuleCollectionGroupsClientBeginDeleteOptions) (*runtime.Poller[armnetwork.FirewallPolicyRuleCollectionGroupsClientDeleteResponse], error) {
			return newInProgressPoller[armnetwork.FirewallPolicyRuleCollectionGroupsClientDeleteResponse](), nil
		}
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _, _ string, _ *armnetwork.FirewallPolicyRuleCollectionGroupsClientBeginDeleteOptions) (*runtime.Poller[armnetwork.FirewallPolicyRuleCollectionGroupsClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testRuleCollectionGroupNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Status_rejects_unknown_operation", func(t *testing.T) {
		reqID, err := encodeLROStart("bogus", "token", testRuleCollectionGroupNativeID)
		require.NoError(t, err)
		got, err := prov.Status(context.Background(), &resource.StatusRequest{RequestID: reqID})
		require.Error(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_policy", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "firewallPolicyName": "fwp-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testRuleCollectionGroupNativeID}, got.NativeIDs)
	})

	// Rule collection groups cannot be listed subscription-wide, so discovery walks
	// every policy.
	t.Run("List_all_walks_policies", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Equal(t, []string{testRuleCollectionGroupNativeID}, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _, _ string, _ armnetwork.FirewallPolicyRuleCollectionGroup, _ *armnetwork.FirewallPolicyRuleCollectionGroupsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.FirewallPolicyRuleCollectionGroupsClientCreateOrUpdateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 403}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

// Deleting a group drives the parent policy into Updating, and ARM refuses to delete
// a policy in that state (FirewallPolicyDeleteNotAllowedWhenUpdatingOrDeleting). The
// child's delete therefore has to stay InProgress until the parent settles, or a
// teardown of policy + group in one apply fails on the parent.
func TestFirewallPolicyRuleCollectionGroup_DeleteWaitsForParentPolicy(t *testing.T) {
	fake := &fakeRuleCollectionGroupsAPI{}
	prov := newTestRuleCollectionGroup(fake)
	reqID := &lroRequestID{NativeID: testRuleCollectionGroupNativeID}
	request := &resource.StatusRequest{RequestID: "req-1"}

	t.Run("parent still updating keeps the delete in progress", func(t *testing.T) {
		fake.getPolicyFn = func(_ context.Context, rg, policy string, _ *armnetwork.FirewallPoliciesClientGetOptions) (armnetwork.FirewallPoliciesClientGetResponse, error) {
			require.Equal(t, "rg-1", rg)
			require.Equal(t, "fwp-1", policy)
			return armnetwork.FirewallPoliciesClientGetResponse{FirewallPolicy: armnetwork.FirewallPolicy{
				Properties: &armnetwork.FirewallPolicyPropertiesFormat{
					ProvisioningState: to.Ptr(armnetwork.ProvisioningStateUpdating),
				},
			}}, nil
		}
		got := prov.verifyParentPolicySettled(context.Background(), request, reqID)
		require.Equal(t, resource.OperationStatusInProgress, got.ProgressResult.OperationStatus)
	})

	t.Run("settled parent completes the delete", func(t *testing.T) {
		fake.getPolicyFn = func(_ context.Context, _, _ string, _ *armnetwork.FirewallPoliciesClientGetOptions) (armnetwork.FirewallPoliciesClientGetResponse, error) {
			return armnetwork.FirewallPoliciesClientGetResponse{FirewallPolicy: armnetwork.FirewallPolicy{
				Properties: &armnetwork.FirewallPolicyPropertiesFormat{
					ProvisioningState: to.Ptr(armnetwork.ProvisioningStateSucceeded),
				},
			}}, nil
		}
		got := prov.verifyParentPolicySettled(context.Background(), request, reqID)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	// A policy that is already gone means the child is gone too — do not hang.
	t.Run("unreadable parent completes the delete", func(t *testing.T) {
		fake.getPolicyFn = func(_ context.Context, _, _ string, _ *armnetwork.FirewallPoliciesClientGetOptions) (armnetwork.FirewallPoliciesClientGetResponse, error) {
			return armnetwork.FirewallPoliciesClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got := prov.verifyParentPolicySettled(context.Background(), request, reqID)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})
}

// A NAT collection returned by ARM is skipped rather than mis-shaped, so Read
// reports drift instead of inventing a filter collection.
func TestSerializeFirewallRuleCollections_SkipsNatCollection(t *testing.T) {
	collections := []armnetwork.FirewallPolicyRuleCollectionClassification{
		&armnetwork.FirewallPolicyNatRuleCollection{
			RuleCollectionType: to.Ptr(armnetwork.FirewallPolicyRuleCollectionTypeFirewallPolicyNatRuleCollection),
			Name:               to.Ptr("dnat"),
			Priority:           to.Ptr(int32(300)),
		},
	}
	require.Nil(t, serializeFirewallRuleCollections(collections))
}

func TestFirewallPolicyRuleCollectionGroupIDParts(t *testing.T) {
	rg, policy, name, err := firewallPolicyRuleCollectionGroupIDParts(testRuleCollectionGroupNativeID)
	require.NoError(t, err)
	require.Equal(t, "rg-1", rg)
	require.Equal(t, "fwp-1", policy)
	require.Equal(t, "rcg-1", name)

	// A bare policy ID has no rule collection group segment.
	_, _, _, err = firewallPolicyRuleCollectionGroupIDParts(testFirewallPolicyNativeID)
	require.Error(t, err)
}

// --- Test helpers ---

func newTestRuleCollectionGroup(api firewallPolicyRuleCollectionGroupsAPI) *FirewallPolicyRuleCollectionGroup {
	return &FirewallPolicyRuleCollectionGroup{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

type fakeRuleCollectionGroupsAPI struct {
	beginCreateOrUpdateFn     func(ctx context.Context, rgName, policyName, name string, params armnetwork.FirewallPolicyRuleCollectionGroup, opts *armnetwork.FirewallPolicyRuleCollectionGroupsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.FirewallPolicyRuleCollectionGroupsClientCreateOrUpdateResponse], error)
	getFn                     func(ctx context.Context, rgName, policyName, name string, opts *armnetwork.FirewallPolicyRuleCollectionGroupsClientGetOptions) (armnetwork.FirewallPolicyRuleCollectionGroupsClientGetResponse, error)
	beginDeleteFn             func(ctx context.Context, rgName, policyName, name string, opts *armnetwork.FirewallPolicyRuleCollectionGroupsClientBeginDeleteOptions) (*runtime.Poller[armnetwork.FirewallPolicyRuleCollectionGroupsClientDeleteResponse], error)
	newListPagerFn            func(rgName, policyName string, opts *armnetwork.FirewallPolicyRuleCollectionGroupsClientListOptions) *runtime.Pager[armnetwork.FirewallPolicyRuleCollectionGroupsClientListResponse]
	newListAllPoliciesPagerFn func(opts *armnetwork.FirewallPoliciesClientListAllOptions) *runtime.Pager[armnetwork.FirewallPoliciesClientListAllResponse]
	getPolicyFn               func(ctx context.Context, rgName, policyName string, opts *armnetwork.FirewallPoliciesClientGetOptions) (armnetwork.FirewallPoliciesClientGetResponse, error)
}

func (f *fakeRuleCollectionGroupsAPI) BeginCreateOrUpdate(ctx context.Context, rgName, policyName, name string, params armnetwork.FirewallPolicyRuleCollectionGroup, opts *armnetwork.FirewallPolicyRuleCollectionGroupsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.FirewallPolicyRuleCollectionGroupsClientCreateOrUpdateResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, rgName, policyName, name, params, opts)
}

func (f *fakeRuleCollectionGroupsAPI) Get(ctx context.Context, rgName, policyName, name string, opts *armnetwork.FirewallPolicyRuleCollectionGroupsClientGetOptions) (armnetwork.FirewallPolicyRuleCollectionGroupsClientGetResponse, error) {
	return f.getFn(ctx, rgName, policyName, name, opts)
}

func (f *fakeRuleCollectionGroupsAPI) BeginDelete(ctx context.Context, rgName, policyName, name string, opts *armnetwork.FirewallPolicyRuleCollectionGroupsClientBeginDeleteOptions) (*runtime.Poller[armnetwork.FirewallPolicyRuleCollectionGroupsClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, policyName, name, opts)
}

func (f *fakeRuleCollectionGroupsAPI) NewListPager(rgName, policyName string, opts *armnetwork.FirewallPolicyRuleCollectionGroupsClientListOptions) *runtime.Pager[armnetwork.FirewallPolicyRuleCollectionGroupsClientListResponse] {
	return f.newListPagerFn(rgName, policyName, opts)
}

func (f *fakeRuleCollectionGroupsAPI) NewListAllPoliciesPager(opts *armnetwork.FirewallPoliciesClientListAllOptions) *runtime.Pager[armnetwork.FirewallPoliciesClientListAllResponse] {
	return f.newListAllPoliciesPagerFn(opts)
}

func (f *fakeRuleCollectionGroupsAPI) GetPolicy(ctx context.Context, rgName, policyName string, opts *armnetwork.FirewallPoliciesClientGetOptions) (armnetwork.FirewallPoliciesClientGetResponse, error) {
	return f.getPolicyFn(ctx, rgName, policyName, opts)
}
