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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/servicebus/armservicebus"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testSBRuleNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.ServiceBus/namespaces/sb1/topics/topic-1/subscriptions/subscr-1/rules/rule-1"

func newTestSBRule(api serviceBusRulesAPI) *ServiceBusRule {
	return &ServiceBusRule{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func sbRuleDesired(sqlExpression string) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":              "rule-1",
		"resourceGroupName": "rg-1",
		"namespaceName":     "sb1",
		"topicName":         "topic-1",
		"subscriptionName":  "subscr-1",
		"filterType":        "SqlFilter",
		"sqlFilter":         map[string]any{"sqlExpression": sqlExpression},
		"action":            map[string]any{"sqlExpression": "SET priority = 'low'"},
	})
	return out
}

func TestServiceBusRule_CRUD(t *testing.T) {
	var sent armservicebus.Rule
	var sawPath []string
	echo := func(params armservicebus.Rule) armservicebus.Rule {
		params.ID = to.Ptr(testSBRuleNativeID)
		params.Name = to.Ptr("rule-1")
		return params
	}

	createCalls := 0
	deleteCalls := 0
	fake := &fakeSBRulesAPI{
		createOrUpdateFn: func(_ context.Context, rgName, namespaceName, topicName, subscriptionName, name string, params armservicebus.Rule, _ *armservicebus.RulesClientCreateOrUpdateOptions) (armservicebus.RulesClientCreateOrUpdateResponse, error) {
			sawPath = []string{rgName, namespaceName, topicName, subscriptionName, name}
			sent = params
			createCalls++
			return armservicebus.RulesClientCreateOrUpdateResponse{Rule: echo(params)}, nil
		},
		getFn: func(_ context.Context, _, _, _, _, _ string, _ *armservicebus.RulesClientGetOptions) (armservicebus.RulesClientGetResponse, error) {
			return armservicebus.RulesClientGetResponse{Rule: echo(sent)}, nil
		},
		deleteFn: func(_ context.Context, _, _, _, _, _ string, _ *armservicebus.RulesClientDeleteOptions) (armservicebus.RulesClientDeleteResponse, error) {
			deleteCalls++
			return armservicebus.RulesClientDeleteResponse{}, nil
		},
		newListPagerFn: func(_, _, _, _ string, _ *armservicebus.RulesClientListBySubscriptionsOptions) *runtime.Pager[armservicebus.RulesClientListBySubscriptionsResponse] {
			return runtime.NewPager(runtime.PagingHandler[armservicebus.RulesClientListBySubscriptionsResponse]{
				More: func(_ armservicebus.RulesClientListBySubscriptionsResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armservicebus.RulesClientListBySubscriptionsResponse) (armservicebus.RulesClientListBySubscriptionsResponse, error) {
					return armservicebus.RulesClientListBySubscriptionsResponse{
						RuleListResult: armservicebus.RuleListResult{
							Value: []*armservicebus.Rule{{ID: to.Ptr(testSBRuleNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestSBRule(fake)

	t.Run("Create_is_synchronous", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "rule-1", Properties: sbRuleDesired("priority = 'high'"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testSBRuleNativeID, got.ProgressResult.NativeID)
		require.Empty(t, got.ProgressResult.RequestID)

		// All four parents are threaded through in order.
		require.Equal(t, []string{"rg-1", "sb1", "topic-1", "subscr-1", "rule-1"}, sawPath)

		require.Equal(t, armservicebus.FilterTypeSQLFilter, *sent.Properties.FilterType)
		require.Equal(t, "priority = 'high'", *sent.Properties.SQLFilter.SQLExpression)
		require.Equal(t, "SET priority = 'low'", *sent.Properties.Action.SQLExpression)
		// The correlation filter must not be sent alongside a SQL filter.
		require.Nil(t, sent.Properties.CorrelationFilter)
	})

	t.Run("Create_requires_sql_expression_for_sql_filter", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "rule-1", "resourceGroupName": "rg-1", "namespaceName": "sb1",
			"topicName": "topic-1", "subscriptionName": "subscr-1", "filterType": "SqlFilter",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "sqlFilter.sqlExpression is required")
	})

	t.Run("Create_requires_correlation_filter_for_correlation_type", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "rule-1", "resourceGroupName": "rg-1", "namespaceName": "sb1",
			"topicName": "topic-1", "subscriptionName": "subscr-1",
			"filterType": "CorrelationFilter",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "correlationFilter is required")
	})

	t.Run("Create_requires_subscription", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "rule-1", "resourceGroupName": "rg-1",
			"namespaceName": "sb1", "topicName": "topic-1",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "subscriptionName is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testSBRuleNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "rule-1", props["name"])
		// All four parents come from the native ID, not the response body.
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "sb1", props["namespaceName"])
		require.Equal(t, "topic-1", props["topicName"])
		require.Equal(t, "subscr-1", props["subscriptionName"])
		require.Equal(t, "SqlFilter", props["filterType"])
		require.Equal(t, "priority = 'high'", props["sqlFilter"].(map[string]any)["sqlExpression"])
		require.Equal(t, "SET priority = 'low'", props["action"].(map[string]any)["sqlExpression"])
	})

	t.Run("Update_reissues_create_or_update", func(t *testing.T) {
		before := createCalls
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testSBRuleNativeID,
			DesiredProperties: sbRuleDesired("priority = 'low'"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Empty(t, got.ProgressResult.RequestID)
		require.Equal(t, before+1, createCalls)
		require.Equal(t, "priority = 'low'", *sent.Properties.SQLFilter.SQLExpression)
	})

	t.Run("Delete_is_synchronous", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testSBRuleNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _, _, _, _ string, _ *armservicebus.RulesClientDeleteOptions) (armservicebus.RulesClientDeleteResponse, error) {
			return armservicebus.RulesClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testSBRuleNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_subscription", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{
				"resourceGroupName": "rg-1", "namespaceName": "sb1",
				"topicName": "topic-1", "subscriptionName": "subscr-1",
			},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testSBRuleNativeID}, got.NativeIDs)
	})

	t.Run("List_without_parents_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.createOrUpdateFn = func(_ context.Context, _, _, _, _, _ string, _ armservicebus.Rule, _ *armservicebus.RulesClientCreateOrUpdateOptions) (armservicebus.RulesClientCreateOrUpdateResponse, error) {
			return armservicebus.RulesClientCreateOrUpdateResponse{}, &azcore.ResponseError{StatusCode: 409}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "rule-1", Properties: sbRuleDesired("priority = 'high'"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

// A correlation filter sends only the properties that were set, and must not drag a
// SQL filter along with it.
func TestServiceBusRule_CorrelationFilter(t *testing.T) {
	var sent armservicebus.Rule
	fake := &fakeSBRulesAPI{
		createOrUpdateFn: func(_ context.Context, _, _, _, _, _ string, params armservicebus.Rule, _ *armservicebus.RulesClientCreateOrUpdateOptions) (armservicebus.RulesClientCreateOrUpdateResponse, error) {
			sent = params
			params.ID = to.Ptr(testSBRuleNativeID)
			return armservicebus.RulesClientCreateOrUpdateResponse{Rule: params}, nil
		},
	}

	props, _ := json.Marshal(map[string]any{
		"name": "rule-1", "resourceGroupName": "rg-1", "namespaceName": "sb1",
		"topicName": "topic-1", "subscriptionName": "subscr-1",
		"filterType":        "CorrelationFilter",
		"correlationFilter": map[string]any{"label": "orders", "correlationId": "emea"},
	})
	got, err := newTestSBRule(fake).Create(context.Background(), &resource.CreateRequest{Properties: props})
	require.NoError(t, err)
	require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)

	require.Equal(t, armservicebus.FilterTypeCorrelationFilter, *sent.Properties.FilterType)
	require.Equal(t, "orders", *sent.Properties.CorrelationFilter.Label)
	require.Equal(t, "emea", *sent.Properties.CorrelationFilter.CorrelationID)
	// Unset correlation properties stay nil rather than being sent as empty strings.
	require.Nil(t, sent.Properties.CorrelationFilter.To)
	require.Nil(t, sent.Properties.SQLFilter)

	var out map[string]any
	require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &out))
	filter := out["correlationFilter"].(map[string]any)
	require.Equal(t, "orders", filter["label"])
	require.NotContains(t, filter, "to")
}

// ARM echoes compatibilityLevel and requiresPreprocessing on both filter kinds and
// on the action. Neither is modelled, and reading them back would show as drift on
// every sync.
func TestServiceBusRule_ReadDropsFilterProviderDefaults(t *testing.T) {
	fake := &fakeSBRulesAPI{
		getFn: func(_ context.Context, _, _, _, _, _ string, _ *armservicebus.RulesClientGetOptions) (armservicebus.RulesClientGetResponse, error) {
			return armservicebus.RulesClientGetResponse{Rule: armservicebus.Rule{
				ID:   to.Ptr(testSBRuleNativeID),
				Name: to.Ptr("rule-1"),
				Properties: &armservicebus.Ruleproperties{
					FilterType: to.Ptr(armservicebus.FilterTypeSQLFilter),
					SQLFilter: &armservicebus.SQLFilter{
						SQLExpression:         to.Ptr("1=1"),
						CompatibilityLevel:    to.Ptr(int32(20)),
						RequiresPreprocessing: to.Ptr(true),
					},
					Action: &armservicebus.Action{
						SQLExpression:      to.Ptr("SET x = 1"),
						CompatibilityLevel: to.Ptr(int32(20)),
					},
				},
			}}, nil
		},
	}
	got, err := newTestSBRule(fake).Read(context.Background(), &resource.ReadRequest{NativeID: testSBRuleNativeID})
	require.NoError(t, err)
	require.NotContains(t, got.Properties, "compatibilityLevel")
	require.NotContains(t, got.Properties, "requiresPreprocessing")
	require.Contains(t, got.Properties, "1=1")
}

func TestServiceBusRule_ReadNotFound(t *testing.T) {
	fake := &fakeSBRulesAPI{
		getFn: func(_ context.Context, _, _, _, _, _ string, _ *armservicebus.RulesClientGetOptions) (armservicebus.RulesClientGetResponse, error) {
			return armservicebus.RulesClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestSBRule(fake).Read(context.Background(), &resource.ReadRequest{NativeID: testSBRuleNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeSBRulesAPI struct {
	createOrUpdateFn func(ctx context.Context, rgName, namespaceName, topicName, subscriptionName, name string, params armservicebus.Rule, options *armservicebus.RulesClientCreateOrUpdateOptions) (armservicebus.RulesClientCreateOrUpdateResponse, error)
	getFn            func(ctx context.Context, rgName, namespaceName, topicName, subscriptionName, name string, options *armservicebus.RulesClientGetOptions) (armservicebus.RulesClientGetResponse, error)
	deleteFn         func(ctx context.Context, rgName, namespaceName, topicName, subscriptionName, name string, options *armservicebus.RulesClientDeleteOptions) (armservicebus.RulesClientDeleteResponse, error)
	newListPagerFn   func(rgName, namespaceName, topicName, subscriptionName string, options *armservicebus.RulesClientListBySubscriptionsOptions) *runtime.Pager[armservicebus.RulesClientListBySubscriptionsResponse]
}

func (f *fakeSBRulesAPI) CreateOrUpdate(ctx context.Context, rgName, namespaceName, topicName, subscriptionName, name string, params armservicebus.Rule, options *armservicebus.RulesClientCreateOrUpdateOptions) (armservicebus.RulesClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, namespaceName, topicName, subscriptionName, name, params, options)
}

func (f *fakeSBRulesAPI) Get(ctx context.Context, rgName, namespaceName, topicName, subscriptionName, name string, options *armservicebus.RulesClientGetOptions) (armservicebus.RulesClientGetResponse, error) {
	return f.getFn(ctx, rgName, namespaceName, topicName, subscriptionName, name, options)
}

func (f *fakeSBRulesAPI) Delete(ctx context.Context, rgName, namespaceName, topicName, subscriptionName, name string, options *armservicebus.RulesClientDeleteOptions) (armservicebus.RulesClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, namespaceName, topicName, subscriptionName, name, options)
}

func (f *fakeSBRulesAPI) NewListBySubscriptionsPager(rgName, namespaceName, topicName, subscriptionName string, options *armservicebus.RulesClientListBySubscriptionsOptions) *runtime.Pager[armservicebus.RulesClientListBySubscriptionsResponse] {
	return f.newListPagerFn(rgName, namespaceName, topicName, subscriptionName, options)
}
