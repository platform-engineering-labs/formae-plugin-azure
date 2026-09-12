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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/alertsmanagement/armalertsmanagement"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

// The ARM type is actionRules even though the product is "alert processing rule".
const testAlertProcessingRuleActionGroupNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.AlertsManagement/actionRules/apr-ag"

const testAlertProcessingRuleSuppressionNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.AlertsManagement/actionRules/apr-sup"

const testAlertProcessingRuleScope = "/subscriptions/sub-1/resourceGroups/rg-1"

const testAlertProcessingActionGroupID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Insights/actionGroups/ag1"

// fakeAlertProcessingRulesAPI backs both alert-processing-rule resource types: they
// share one ARM type and one SDK client.
type fakeAlertProcessingRulesAPI struct {
	createFn      func(ctx context.Context, rgName, name string, body armalertsmanagement.AlertProcessingRule, options *armalertsmanagement.AlertProcessingRulesClientCreateOrUpdateOptions) (armalertsmanagement.AlertProcessingRulesClientCreateOrUpdateResponse, error)
	getFn         func(ctx context.Context, rgName, name string, options *armalertsmanagement.AlertProcessingRulesClientGetByNameOptions) (armalertsmanagement.AlertProcessingRulesClientGetByNameResponse, error)
	deleteFn      func(ctx context.Context, rgName, name string, options *armalertsmanagement.AlertProcessingRulesClientDeleteOptions) (armalertsmanagement.AlertProcessingRulesClientDeleteResponse, error)
	listByGroupFn func(rgName string, options *armalertsmanagement.AlertProcessingRulesClientListByResourceGroupOptions) *runtime.Pager[armalertsmanagement.AlertProcessingRulesClientListByResourceGroupResponse]
	listBySubFn   func(options *armalertsmanagement.AlertProcessingRulesClientListBySubscriptionOptions) *runtime.Pager[armalertsmanagement.AlertProcessingRulesClientListBySubscriptionResponse]
}

func (f *fakeAlertProcessingRulesAPI) CreateOrUpdate(ctx context.Context, rgName, name string, body armalertsmanagement.AlertProcessingRule, options *armalertsmanagement.AlertProcessingRulesClientCreateOrUpdateOptions) (armalertsmanagement.AlertProcessingRulesClientCreateOrUpdateResponse, error) {
	return f.createFn(ctx, rgName, name, body, options)
}

func (f *fakeAlertProcessingRulesAPI) GetByName(ctx context.Context, rgName, name string, options *armalertsmanagement.AlertProcessingRulesClientGetByNameOptions) (armalertsmanagement.AlertProcessingRulesClientGetByNameResponse, error) {
	return f.getFn(ctx, rgName, name, options)
}

func (f *fakeAlertProcessingRulesAPI) Delete(ctx context.Context, rgName, name string, options *armalertsmanagement.AlertProcessingRulesClientDeleteOptions) (armalertsmanagement.AlertProcessingRulesClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, name, options)
}

func (f *fakeAlertProcessingRulesAPI) NewListByResourceGroupPager(rgName string, options *armalertsmanagement.AlertProcessingRulesClientListByResourceGroupOptions) *runtime.Pager[armalertsmanagement.AlertProcessingRulesClientListByResourceGroupResponse] {
	return f.listByGroupFn(rgName, options)
}

func (f *fakeAlertProcessingRulesAPI) NewListBySubscriptionPager(options *armalertsmanagement.AlertProcessingRulesClientListBySubscriptionOptions) *runtime.Pager[armalertsmanagement.AlertProcessingRulesClientListBySubscriptionResponse] {
	return f.listBySubFn(options)
}

// alertProcessingRuleMixedListing is what ARM hands back for the shared type: one
// rule of each flavour. Each resource type's List has to return only its own.
func alertProcessingRuleMixedListing() []*armalertsmanagement.AlertProcessingRule {
	return []*armalertsmanagement.AlertProcessingRule{
		{
			ID: to.Ptr(testAlertProcessingRuleActionGroupNativeID),
			Properties: &armalertsmanagement.AlertProcessingRuleProperties{
				Actions: []armalertsmanagement.ActionClassification{
					&armalertsmanagement.AddActionGroups{
						ActionType:     to.Ptr(armalertsmanagement.ActionTypeAddActionGroups),
						ActionGroupIDs: []*string{to.Ptr(testAlertProcessingActionGroupID)},
					},
				},
			},
		},
		{
			ID: to.Ptr(testAlertProcessingRuleSuppressionNativeID),
			Properties: &armalertsmanagement.AlertProcessingRuleProperties{
				Actions: []armalertsmanagement.ActionClassification{
					&armalertsmanagement.RemoveAllActionGroups{
						ActionType: to.Ptr(armalertsmanagement.ActionTypeRemoveAllActionGroups),
					},
				},
			},
		},
		// A nil entry must not panic the walk.
		nil,
	}
}

func alertProcessingRuleListPagers(fake *fakeAlertProcessingRulesAPI) {
	fake.listByGroupFn = func(_ string, _ *armalertsmanagement.AlertProcessingRulesClientListByResourceGroupOptions) *runtime.Pager[armalertsmanagement.AlertProcessingRulesClientListByResourceGroupResponse] {
		return runtime.NewPager(runtime.PagingHandler[armalertsmanagement.AlertProcessingRulesClientListByResourceGroupResponse]{
			More: func(_ armalertsmanagement.AlertProcessingRulesClientListByResourceGroupResponse) bool { return false },
			Fetcher: func(_ context.Context, _ *armalertsmanagement.AlertProcessingRulesClientListByResourceGroupResponse) (armalertsmanagement.AlertProcessingRulesClientListByResourceGroupResponse, error) {
				return armalertsmanagement.AlertProcessingRulesClientListByResourceGroupResponse{
					AlertProcessingRulesList: armalertsmanagement.AlertProcessingRulesList{Value: alertProcessingRuleMixedListing()},
				}, nil
			},
		})
	}
	fake.listBySubFn = func(_ *armalertsmanagement.AlertProcessingRulesClientListBySubscriptionOptions) *runtime.Pager[armalertsmanagement.AlertProcessingRulesClientListBySubscriptionResponse] {
		return runtime.NewPager(runtime.PagingHandler[armalertsmanagement.AlertProcessingRulesClientListBySubscriptionResponse]{
			More: func(_ armalertsmanagement.AlertProcessingRulesClientListBySubscriptionResponse) bool { return false },
			Fetcher: func(_ context.Context, _ *armalertsmanagement.AlertProcessingRulesClientListBySubscriptionResponse) (armalertsmanagement.AlertProcessingRulesClientListBySubscriptionResponse, error) {
				return armalertsmanagement.AlertProcessingRulesClientListBySubscriptionResponse{
					AlertProcessingRulesList: armalertsmanagement.AlertProcessingRulesList{Value: alertProcessingRuleMixedListing()},
				}, nil
			},
		})
	}
}

func newTestAlertProcessingRuleActionGroup(api alertProcessingRulesAPI) *AlertProcessingRuleActionGroup {
	return &AlertProcessingRuleActionGroup{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func alertProcessingRuleActionGroupDesired(description string) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":              "apr-ag",
		"resourceGroupName": "rg-1",
		"location":          "Global",
		"scopes":            []string{testAlertProcessingRuleScope},
		"actionGroupIds":    []string{testAlertProcessingActionGroupID},
		"description":       description,
		"enabled":           true,
		"conditions": []any{
			map[string]any{"field": "Severity", "operator": "Equals", "values": []string{"Sev4"}},
		},
		"Tags": []any{map[string]any{"Key": "env", "Value": "test"}},
	})
	return out
}

func TestAlertProcessingRuleActionGroup_CRUD(t *testing.T) {
	ruleResult := armalertsmanagement.AlertProcessingRule{
		ID:   to.Ptr(testAlertProcessingRuleActionGroupNativeID),
		Name: to.Ptr("apr-ag"),
		// Alert processing rules are global; ARM echoes the literal, not a region.
		Location: to.Ptr("Global"),
		Properties: &armalertsmanagement.AlertProcessingRuleProperties{
			Scopes:      []*string{to.Ptr(testAlertProcessingRuleScope)},
			Description: to.Ptr("page the on-call"),
			Enabled:     to.Ptr(true),
			Conditions: []*armalertsmanagement.Condition{
				{
					Field:    to.Ptr(armalertsmanagement.FieldSeverity),
					Operator: to.Ptr(armalertsmanagement.OperatorEquals),
					Values:   []*string{to.Ptr("Sev4")},
				},
			},
			Actions: []armalertsmanagement.ActionClassification{
				&armalertsmanagement.AddActionGroups{
					ActionType:     to.Ptr(armalertsmanagement.ActionTypeAddActionGroups),
					ActionGroupIDs: []*string{to.Ptr(testAlertProcessingActionGroupID)},
				},
			},
		},
		Tags: map[string]*string{"env": to.Ptr("test")},
	}

	var sent armalertsmanagement.AlertProcessingRule
	writeCalls := 0
	deleteCalls := 0
	fake := &fakeAlertProcessingRulesAPI{
		createFn: func(_ context.Context, rgName, name string, body armalertsmanagement.AlertProcessingRule, _ *armalertsmanagement.AlertProcessingRulesClientCreateOrUpdateOptions) (armalertsmanagement.AlertProcessingRulesClientCreateOrUpdateResponse, error) {
			require.Equal(t, "rg-1", rgName)
			require.Equal(t, "apr-ag", name)
			sent = body
			writeCalls++
			return armalertsmanagement.AlertProcessingRulesClientCreateOrUpdateResponse{AlertProcessingRule: ruleResult}, nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armalertsmanagement.AlertProcessingRulesClientGetByNameOptions) (armalertsmanagement.AlertProcessingRulesClientGetByNameResponse, error) {
			return armalertsmanagement.AlertProcessingRulesClientGetByNameResponse{AlertProcessingRule: ruleResult}, nil
		},
		deleteFn: func(_ context.Context, _, _ string, _ *armalertsmanagement.AlertProcessingRulesClientDeleteOptions) (armalertsmanagement.AlertProcessingRulesClientDeleteResponse, error) {
			deleteCalls++
			return armalertsmanagement.AlertProcessingRulesClientDeleteResponse{}, nil
		},
	}
	alertProcessingRuleListPagers(fake)
	prov := newTestAlertProcessingRuleActionGroup(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "apr-ag", Properties: alertProcessingRuleActionGroupDesired("page the on-call"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testAlertProcessingRuleActionGroupNativeID, got.ProgressResult.NativeID)

		require.Equal(t, "Global", *sent.Location)
		require.Equal(t, testAlertProcessingRuleScope, *sent.Properties.Scopes[0])
		require.Equal(t, "page the on-call", *sent.Properties.Description)
		require.True(t, *sent.Properties.Enabled)
		require.Len(t, sent.Properties.Conditions, 1)
		require.Equal(t, armalertsmanagement.FieldSeverity, *sent.Properties.Conditions[0].Field)

		require.Len(t, sent.Properties.Actions, 1)
		add, ok := sent.Properties.Actions[0].(*armalertsmanagement.AddActionGroups)
		require.True(t, ok, "the action-group flavour must send AddActionGroups")
		require.Equal(t, testAlertProcessingActionGroupID, *add.ActionGroupIDs[0])
		require.Equal(t, "test", *sent.Tags["env"])
	})

	t.Run("Create_requires_a_scope", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "apr-ag", "resourceGroupName": "rg-1", "location": "Global",
			"actionGroupIds": []string{testAlertProcessingActionGroupID},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "at least one scope is required")
	})

	t.Run("Create_requires_an_action_group", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "apr-ag", "resourceGroupName": "rg-1", "location": "Global",
			"scopes": []string{testAlertProcessingRuleScope},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "at least one actionGroupId is required")
	})

	t.Run("Create_failure_carries_the_provider_error", func(t *testing.T) {
		fake.createFn = func(_ context.Context, _, _ string, _ armalertsmanagement.AlertProcessingRule, _ *armalertsmanagement.AlertProcessingRulesClientCreateOrUpdateOptions) (armalertsmanagement.AlertProcessingRulesClientCreateOrUpdateResponse, error) {
			return armalertsmanagement.AlertProcessingRulesClientCreateOrUpdateResponse{}, &azcore.ResponseError{
				StatusCode: 400, ErrorCode: "BadArgumentError",
			}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "apr-ag", Properties: alertProcessingRuleActionGroupDesired("page the on-call"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.Contains(t, got.ProgressResult.StatusMessage, "BadArgumentError")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testAlertProcessingRuleActionGroupNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "apr-ag", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "Global", props["location"])
		require.Equal(t, []any{testAlertProcessingRuleScope}, props["scopes"])
		require.Equal(t, []any{testAlertProcessingActionGroupID}, props["actionGroupIds"])
		require.Equal(t, "page the on-call", props["description"])
		require.Equal(t, true, props["enabled"])
		conditions := props["conditions"].([]any)
		require.Len(t, conditions, 1)
		require.Equal(t, "Severity", conditions[0].(map[string]any)["field"])
		// The schedule block is only modelled on the suppression flavour.
		require.NotContains(t, props, "schedule")
	})

	t.Run("Update_reissues_create", func(t *testing.T) {
		fake.createFn = func(_ context.Context, _, _ string, body armalertsmanagement.AlertProcessingRule, _ *armalertsmanagement.AlertProcessingRulesClientCreateOrUpdateOptions) (armalertsmanagement.AlertProcessingRulesClientCreateOrUpdateResponse, error) {
			sent = body
			writeCalls++
			return armalertsmanagement.AlertProcessingRulesClientCreateOrUpdateResponse{AlertProcessingRule: ruleResult}, nil
		}
		before := writeCalls
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testAlertProcessingRuleActionGroupNativeID,
			DesiredProperties: alertProcessingRuleActionGroupDesired("page the on-call, revised"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, writeCalls)
		require.Equal(t, "page the on-call, revised", *sent.Properties.Description)
		// Location must ride along: a PUT without it is rejected.
		require.Equal(t, "Global", *sent.Location)
	})

	t.Run("Delete", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testAlertProcessingRuleActionGroupNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _ string, _ *armalertsmanagement.AlertProcessingRulesClientDeleteOptions) (armalertsmanagement.AlertProcessingRulesClientDeleteResponse, error) {
			return armalertsmanagement.AlertProcessingRulesClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testAlertProcessingRuleActionGroupNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Status_is_always_success", func(t *testing.T) {
		got, err := prov.Status(context.Background(), &resource.StatusRequest{RequestID: "whatever"})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	// Both resource types live under Microsoft.AlertsManagement/actionRules, so a
	// listing that did not filter by action type would hand discovery the
	// suppression rule's id as an action-group rule.
	t.Run("List_by_resource_group_returns_only_AddActionGroups_rules", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testAlertProcessingRuleActionGroupNativeID}, got.NativeIDs)
	})

	t.Run("List_without_group_is_subscription_wide_and_still_filtered", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Equal(t, []string{testAlertProcessingRuleActionGroupNativeID}, got.NativeIDs)
	})

	t.Run("Read_NotFound", func(t *testing.T) {
		fake.getFn = func(_ context.Context, _, _ string, _ *armalertsmanagement.AlertProcessingRulesClientGetByNameOptions) (armalertsmanagement.AlertProcessingRulesClientGetByNameResponse, error) {
			return armalertsmanagement.AlertProcessingRulesClientGetByNameResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testAlertProcessingRuleActionGroupNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
	})
}
