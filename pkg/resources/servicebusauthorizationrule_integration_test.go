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

const (
	testSBAuthRuleNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.ServiceBus/namespaces/ns-1/AuthorizationRules/app-send"
	testSBRootRuleNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.ServiceBus/namespaces/ns-1/AuthorizationRules/RootManageSharedAccessKey"
)

func newTestServiceBusAuthorizationRule(api serviceBusAuthorizationRulesAPI) *ServiceBusAuthorizationRule {
	return &ServiceBusAuthorizationRule{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func sbAuthRuleDesired(rights ...string) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":              "app-send",
		"resourceGroupName": "rg-1",
		"namespaceName":     "ns-1",
		"rights":            rights,
	})
	return out
}

func TestServiceBusAuthorizationRule_CRUD(t *testing.T) {
	var sent armservicebus.SBAuthorizationRule
	echo := func(params armservicebus.SBAuthorizationRule) armservicebus.SBAuthorizationRule {
		params.ID = to.Ptr(testSBAuthRuleNativeID)
		params.Name = to.Ptr("app-send")
		return params
	}

	fake := &fakeSBAuthRulesAPI{
		createOrUpdateFn: func(_ context.Context, _, _, name string, params armservicebus.SBAuthorizationRule, _ *armservicebus.NamespacesClientCreateOrUpdateAuthorizationRuleOptions) (armservicebus.NamespacesClientCreateOrUpdateAuthorizationRuleResponse, error) {
			require.Equal(t, "app-send", name)
			sent = params
			return armservicebus.NamespacesClientCreateOrUpdateAuthorizationRuleResponse{SBAuthorizationRule: echo(params)}, nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ *armservicebus.NamespacesClientGetAuthorizationRuleOptions) (armservicebus.NamespacesClientGetAuthorizationRuleResponse, error) {
			return armservicebus.NamespacesClientGetAuthorizationRuleResponse{SBAuthorizationRule: echo(sent)}, nil
		},
		deleteFn: func(_ context.Context, _, _, _ string, _ *armservicebus.NamespacesClientDeleteAuthorizationRuleOptions) (armservicebus.NamespacesClientDeleteAuthorizationRuleResponse, error) {
			return armservicebus.NamespacesClientDeleteAuthorizationRuleResponse{}, nil
		},
		listFn: func(_, _ string, _ *armservicebus.NamespacesClientListAuthorizationRulesOptions) *runtime.Pager[armservicebus.NamespacesClientListAuthorizationRulesResponse] {
			return runtime.NewPager(runtime.PagingHandler[armservicebus.NamespacesClientListAuthorizationRulesResponse]{
				More: func(_ armservicebus.NamespacesClientListAuthorizationRulesResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armservicebus.NamespacesClientListAuthorizationRulesResponse) (armservicebus.NamespacesClientListAuthorizationRulesResponse, error) {
					return armservicebus.NamespacesClientListAuthorizationRulesResponse{
						SBAuthorizationRuleListResult: armservicebus.SBAuthorizationRuleListResult{
							Value: []*armservicebus.SBAuthorizationRule{
								{ID: to.Ptr(testSBAuthRuleNativeID), Name: to.Ptr("app-send")},
								{ID: to.Ptr(testSBRootRuleNativeID), Name: to.Ptr("RootManageSharedAccessKey")},
							},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestServiceBusAuthorizationRule(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "app-send", Properties: sbAuthRuleDesired("Listen")})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testSBAuthRuleNativeID, got.ProgressResult.NativeID)

		require.Len(t, sent.Properties.Rights, 1)
		require.Equal(t, armservicebus.AccessRightsListen, *sent.Properties.Rights[0])

		var props map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &props))
		require.Equal(t, []any{"Listen"}, props["rights"])
		// Keys are never surfaced: they come from a separate ListKeys call.
		require.NotContains(t, props, "primaryKey")
		require.NotContains(t, props, "primaryConnectionString")
	})

	t.Run("Create_requires_rights", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "app-send", "resourceGroupName": "rg-1", "namespaceName": "ns-1", "rights": []string{},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.Error(t, err)
	})

	t.Run("Create_requires_namespaceName", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "app-send", "resourceGroupName": "rg-1", "rights": []string{"Listen"},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.Error(t, err)
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testSBAuthRuleNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "app-send", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "ns-1", props["namespaceName"])
	})

	t.Run("Update_replaces_rights", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testSBAuthRuleNativeID,
			DesiredProperties: sbAuthRuleDesired("Listen", "Send"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testSBAuthRuleNativeID, got.ProgressResult.NativeID)
		require.Len(t, sent.Properties.Rights, 2)

		var props map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &props))
		require.Equal(t, []any{"Listen", "Send"}, props["rights"])
	})

	t.Run("Delete", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testSBAuthRuleNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _, _ string, _ *armservicebus.NamespacesClientDeleteAuthorizationRuleOptions) (armservicebus.NamespacesClientDeleteAuthorizationRuleResponse, error) {
			return armservicebus.NamespacesClientDeleteAuthorizationRuleResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testSBAuthRuleNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	// Azure creates RootManageSharedAccessKey implicitly with every namespace;
	// discovery must not import a rule formae cannot own.
	t.Run("List_filters_the_implicit_root_rule", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "namespaceName": "ns-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testSBAuthRuleNativeID}, got.NativeIDs)
	})

	t.Run("List_without_parent_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.createOrUpdateFn = func(_ context.Context, _, _, _ string, _ armservicebus.SBAuthorizationRule, _ *armservicebus.NamespacesClientCreateOrUpdateAuthorizationRuleOptions) (armservicebus.NamespacesClientCreateOrUpdateAuthorizationRuleResponse, error) {
			return armservicebus.NamespacesClientCreateOrUpdateAuthorizationRuleResponse{}, &azcore.ResponseError{StatusCode: 403}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "app-send", Properties: sbAuthRuleDesired("Listen")})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

func TestServiceBusAuthorizationRule_ReadNotFound(t *testing.T) {
	fake := &fakeSBAuthRulesAPI{
		getFn: func(_ context.Context, _, _, _ string, _ *armservicebus.NamespacesClientGetAuthorizationRuleOptions) (armservicebus.NamespacesClientGetAuthorizationRuleResponse, error) {
			return armservicebus.NamespacesClientGetAuthorizationRuleResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestServiceBusAuthorizationRule(fake).Read(context.Background(), &resource.ReadRequest{NativeID: testSBAuthRuleNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeSBAuthRulesAPI struct {
	createOrUpdateFn func(ctx context.Context, rgName, namespaceName, name string, parameters armservicebus.SBAuthorizationRule, options *armservicebus.NamespacesClientCreateOrUpdateAuthorizationRuleOptions) (armservicebus.NamespacesClientCreateOrUpdateAuthorizationRuleResponse, error)
	getFn            func(ctx context.Context, rgName, namespaceName, name string, options *armservicebus.NamespacesClientGetAuthorizationRuleOptions) (armservicebus.NamespacesClientGetAuthorizationRuleResponse, error)
	deleteFn         func(ctx context.Context, rgName, namespaceName, name string, options *armservicebus.NamespacesClientDeleteAuthorizationRuleOptions) (armservicebus.NamespacesClientDeleteAuthorizationRuleResponse, error)
	listFn           func(rgName, namespaceName string, options *armservicebus.NamespacesClientListAuthorizationRulesOptions) *runtime.Pager[armservicebus.NamespacesClientListAuthorizationRulesResponse]
}

func (f *fakeSBAuthRulesAPI) CreateOrUpdateAuthorizationRule(ctx context.Context, rgName, namespaceName, name string, parameters armservicebus.SBAuthorizationRule, options *armservicebus.NamespacesClientCreateOrUpdateAuthorizationRuleOptions) (armservicebus.NamespacesClientCreateOrUpdateAuthorizationRuleResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, namespaceName, name, parameters, options)
}

func (f *fakeSBAuthRulesAPI) GetAuthorizationRule(ctx context.Context, rgName, namespaceName, name string, options *armservicebus.NamespacesClientGetAuthorizationRuleOptions) (armservicebus.NamespacesClientGetAuthorizationRuleResponse, error) {
	return f.getFn(ctx, rgName, namespaceName, name, options)
}

func (f *fakeSBAuthRulesAPI) DeleteAuthorizationRule(ctx context.Context, rgName, namespaceName, name string, options *armservicebus.NamespacesClientDeleteAuthorizationRuleOptions) (armservicebus.NamespacesClientDeleteAuthorizationRuleResponse, error) {
	return f.deleteFn(ctx, rgName, namespaceName, name, options)
}

func (f *fakeSBAuthRulesAPI) NewListAuthorizationRulesPager(rgName, namespaceName string, options *armservicebus.NamespacesClientListAuthorizationRulesOptions) *runtime.Pager[armservicebus.NamespacesClientListAuthorizationRulesResponse] {
	return f.listFn(rgName, namespaceName, options)
}
