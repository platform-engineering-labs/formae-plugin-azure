// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/alertsmanagement/armalertsmanagement"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

func newTestAlertProcessingRuleSuppression(api alertProcessingRulesAPI) *AlertProcessingRuleSuppression {
	return &AlertProcessingRuleSuppression{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func alertProcessingRuleSuppressionDesired(effectiveUntil string) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":              "apr-sup",
		"resourceGroupName": "rg-1",
		"location":          "Global",
		"scopes":            []string{testAlertProcessingRuleScope},
		"description":       "maintenance window",
		"enabled":           true,
		"conditions": []any{
			map[string]any{"field": "Severity", "operator": "Equals", "values": []string{"Sev4"}},
		},
		"schedule": map[string]any{
			// ISO-8601 WITHOUT a timezone suffix - ARM rejects a trailing Z.
			"effectiveFrom":  "2030-01-01T00:00:00",
			"effectiveUntil": effectiveUntil,
			"timeZone":       "UTC",
		},
		"Tags": []any{map[string]any{"Key": "env", "Value": "test"}},
	})
	return out
}

func TestAlertProcessingRuleSuppression_CRUD(t *testing.T) {
	ruleResult := armalertsmanagement.AlertProcessingRule{
		ID:       to.Ptr(testAlertProcessingRuleSuppressionNativeID),
		Name:     to.Ptr("apr-sup"),
		Location: to.Ptr("Global"),
		Properties: &armalertsmanagement.AlertProcessingRuleProperties{
			Scopes:      []*string{to.Ptr(testAlertProcessingRuleScope)},
			Description: to.Ptr("maintenance window"),
			Enabled:     to.Ptr(true),
			Conditions: []*armalertsmanagement.Condition{
				{
					Field:    to.Ptr(armalertsmanagement.FieldSeverity),
					Operator: to.Ptr(armalertsmanagement.OperatorEquals),
					Values:   []*string{to.Ptr("Sev4")},
				},
			},
			Schedule: &armalertsmanagement.Schedule{
				EffectiveFrom:  to.Ptr("2030-01-01T00:00:00"),
				EffectiveUntil: to.Ptr("2030-01-02T00:00:00"),
				TimeZone:       to.Ptr("UTC"),
			},
			Actions: []armalertsmanagement.ActionClassification{
				&armalertsmanagement.RemoveAllActionGroups{
					ActionType: to.Ptr(armalertsmanagement.ActionTypeRemoveAllActionGroups),
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
			require.Equal(t, "apr-sup", name)
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
	prov := newTestAlertProcessingRuleSuppression(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "apr-sup", Properties: alertProcessingRuleSuppressionDesired("2030-01-02T00:00:00"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testAlertProcessingRuleSuppressionNativeID, got.ProgressResult.NativeID)

		require.Equal(t, "Global", *sent.Location)
		require.Len(t, sent.Properties.Actions, 1)
		_, ok := sent.Properties.Actions[0].(*armalertsmanagement.RemoveAllActionGroups)
		require.True(t, ok, "the suppression flavour must send RemoveAllActionGroups")
		require.Equal(t, "2030-01-01T00:00:00", *sent.Properties.Schedule.EffectiveFrom)
		require.Equal(t, "UTC", *sent.Properties.Schedule.TimeZone)
	})

	t.Run("Create_without_a_schedule_sends_none", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "apr-sup", "resourceGroupName": "rg-1", "location": "Global",
			"scopes": []string{testAlertProcessingRuleScope},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.Nil(t, sent.Properties.Schedule)
	})

	t.Run("Create_requires_a_scope", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "apr-sup", "resourceGroupName": "rg-1", "location": "Global",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "at least one scope is required")
	})

	t.Run("Create_failure_carries_the_provider_error", func(t *testing.T) {
		fake.createFn = func(_ context.Context, _, _ string, _ armalertsmanagement.AlertProcessingRule, _ *armalertsmanagement.AlertProcessingRulesClientCreateOrUpdateOptions) (armalertsmanagement.AlertProcessingRulesClientCreateOrUpdateResponse, error) {
			return armalertsmanagement.AlertProcessingRulesClientCreateOrUpdateResponse{}, &azcore.ResponseError{
				StatusCode: 400, ErrorCode: "BadArgumentError",
			}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "apr-sup", Properties: alertProcessingRuleSuppressionDesired("2030-01-02T00:00:00"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.Contains(t, got.ProgressResult.StatusMessage, "BadArgumentError")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testAlertProcessingRuleSuppressionNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "apr-sup", props["name"])
		require.Equal(t, "Global", props["location"])
		require.Equal(t, []any{testAlertProcessingRuleScope}, props["scopes"])
		require.Equal(t, "maintenance window", props["description"])
		require.Equal(t, map[string]any{
			"effectiveFrom":  "2030-01-01T00:00:00",
			"effectiveUntil": "2030-01-02T00:00:00",
			"timeZone":       "UTC",
		}, props["schedule"])
		// actionGroupIds belongs to the AddActionGroups flavour.
		require.NotContains(t, props, "actionGroupIds")
	})

	t.Run("Update_reissues_create", func(t *testing.T) {
		fake.createFn = func(_ context.Context, _, _ string, body armalertsmanagement.AlertProcessingRule, _ *armalertsmanagement.AlertProcessingRulesClientCreateOrUpdateOptions) (armalertsmanagement.AlertProcessingRulesClientCreateOrUpdateResponse, error) {
			sent = body
			writeCalls++
			return armalertsmanagement.AlertProcessingRulesClientCreateOrUpdateResponse{AlertProcessingRule: ruleResult}, nil
		}
		before := writeCalls
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testAlertProcessingRuleSuppressionNativeID,
			DesiredProperties: alertProcessingRuleSuppressionDesired("2030-01-03T00:00:00"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, writeCalls)
		require.Equal(t, "2030-01-03T00:00:00", *sent.Properties.Schedule.EffectiveUntil)
		require.Equal(t, "Global", *sent.Location)
	})

	t.Run("Delete", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testAlertProcessingRuleSuppressionNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _ string, _ *armalertsmanagement.AlertProcessingRulesClientDeleteOptions) (armalertsmanagement.AlertProcessingRulesClientDeleteResponse, error) {
			return armalertsmanagement.AlertProcessingRulesClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testAlertProcessingRuleSuppressionNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Status_is_always_success", func(t *testing.T) {
		got, err := prov.Status(context.Background(), &resource.StatusRequest{RequestID: "whatever"})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_returns_only_RemoveAllActionGroups_rules", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testAlertProcessingRuleSuppressionNativeID}, got.NativeIDs)

		got, err = prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Equal(t, []string{testAlertProcessingRuleSuppressionNativeID}, got.NativeIDs)
	})

	t.Run("Read_NotFound", func(t *testing.T) {
		fake.getFn = func(_ context.Context, _, _ string, _ *armalertsmanagement.AlertProcessingRulesClientGetByNameOptions) (armalertsmanagement.AlertProcessingRulesClientGetByNameResponse, error) {
			return armalertsmanagement.AlertProcessingRulesClientGetByNameResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testAlertProcessingRuleSuppressionNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
	})
}
