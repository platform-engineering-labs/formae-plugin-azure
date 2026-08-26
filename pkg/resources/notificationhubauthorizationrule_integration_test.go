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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/notificationhubs/armnotificationhubs"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testNHAuthRuleNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.NotificationHubs/namespaces/nh1/notificationHubs/hub-1/authorizationRules/rule-1"

func newTestNHAuthRule(api notificationHubAuthRulesAPI) *NotificationHubAuthorizationRule {
	return &NotificationHubAuthorizationRule{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func nhAuthRuleDesired(rights []string) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":                "rule-1",
		"resourceGroupName":   "rg-1",
		"namespaceName":       "nh1",
		"notificationHubName": "hub-1",
		"rights":              rights,
	})
	return out
}

func TestNotificationHubAuthorizationRule_CRUD(t *testing.T) {
	ruleResult := armnotificationhubs.SharedAccessAuthorizationRuleResource{
		ID:   to.Ptr(testNHAuthRuleNativeID),
		Name: to.Ptr("rule-1"),
		Properties: &armnotificationhubs.SharedAccessAuthorizationRuleProperties{
			Rights: []*armnotificationhubs.AccessRights{
				to.Ptr(armnotificationhubs.AccessRightsListen),
				to.Ptr(armnotificationhubs.AccessRightsSend),
			},
			// This ARM type returns the keys inline from Get, unlike the Relay rules.
			PrimaryKey:   to.Ptr("super-secret-primary"),
			SecondaryKey: to.Ptr("super-secret-secondary"),
			KeyName:      to.Ptr("rule-1"),
			Revision:     to.Ptr(int32(3)),
			CreatedTime:  to.Ptr("2026-01-01T00:00:00Z"),
			ModifiedTime: to.Ptr("2026-02-01T00:00:00Z"),
		},
	}

	var sentRule armnotificationhubs.SharedAccessAuthorizationRuleCreateOrUpdateParameters
	var sawNamespace string
	createCalls := 0
	deleteCalls := 0
	fake := &fakeNHAuthRulesAPI{
		createOrUpdateFn: func(_ context.Context, _, namespaceName, hubName, name string, params armnotificationhubs.SharedAccessAuthorizationRuleCreateOrUpdateParameters, _ *armnotificationhubs.ClientCreateOrUpdateAuthorizationRuleOptions) (armnotificationhubs.ClientCreateOrUpdateAuthorizationRuleResponse, error) {
			require.Equal(t, "rule-1", name)
			sawNamespace = namespaceName
			sentRule = params
			createCalls++
			return armnotificationhubs.ClientCreateOrUpdateAuthorizationRuleResponse{SharedAccessAuthorizationRuleResource: ruleResult}, nil
		},
		getFn: func(_ context.Context, _, _, _, _ string, _ *armnotificationhubs.ClientGetAuthorizationRuleOptions) (armnotificationhubs.ClientGetAuthorizationRuleResponse, error) {
			return armnotificationhubs.ClientGetAuthorizationRuleResponse{SharedAccessAuthorizationRuleResource: ruleResult}, nil
		},
		deleteFn: func(_ context.Context, _, _, _, _ string, _ *armnotificationhubs.ClientDeleteAuthorizationRuleOptions) (armnotificationhubs.ClientDeleteAuthorizationRuleResponse, error) {
			deleteCalls++
			return armnotificationhubs.ClientDeleteAuthorizationRuleResponse{}, nil
		},
		newListPagerFn: func(_, _, _ string, _ *armnotificationhubs.ClientListAuthorizationRulesOptions) *runtime.Pager[armnotificationhubs.ClientListAuthorizationRulesResponse] {
			return runtime.NewPager(runtime.PagingHandler[armnotificationhubs.ClientListAuthorizationRulesResponse]{
				More: func(_ armnotificationhubs.ClientListAuthorizationRulesResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armnotificationhubs.ClientListAuthorizationRulesResponse) (armnotificationhubs.ClientListAuthorizationRulesResponse, error) {
					return armnotificationhubs.ClientListAuthorizationRulesResponse{
						SharedAccessAuthorizationRuleListResult: armnotificationhubs.SharedAccessAuthorizationRuleListResult{
							Value: []*armnotificationhubs.SharedAccessAuthorizationRuleResource{{ID: to.Ptr(testNHAuthRuleNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestNHAuthRule(fake)

	// Create is synchronous: success comes back directly, with no resume token.
	t.Run("Create_is_synchronous", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "rule-1",
			Properties: nhAuthRuleDesired([]string{"Listen", "Send"}),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testNHAuthRuleNativeID, got.ProgressResult.NativeID)
		require.Empty(t, got.ProgressResult.RequestID)

		require.Equal(t, "nh1", sawNamespace)
		require.Len(t, sentRule.Properties.Rights, 2)
		require.Equal(t, armnotificationhubs.AccessRightsListen, *sentRule.Properties.Rights[0])
		require.Equal(t, armnotificationhubs.AccessRightsSend, *sentRule.Properties.Rights[1])
	})

	t.Run("Create_requires_rights", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "rule-1", "resourceGroupName": "rg-1",
			"namespaceName": "nh1", "notificationHubName": "hub-1",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "rights is required")
	})

	t.Run("Create_requires_hub", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "rule-1", "resourceGroupName": "rg-1", "namespaceName": "nh1",
			"rights": []any{"Listen"},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "notificationHubName is required")
	})

	t.Run("Create_requires_namespace", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "rule-1", "resourceGroupName": "rg-1"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "namespaceName is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testNHAuthRuleNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "rule-1", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		// Both parents come from the native ID, not the response body.
		require.Equal(t, "nh1", props["namespaceName"])
		require.Equal(t, "hub-1", props["notificationHubName"])
		// Order is echoed as ARM returns it, not sorted: sorting would make a
		// desired list written in another order look like drift.
		require.Equal(t, []any{"Listen", "Send"}, props["rights"])
	})

	// ARM returns the keys INLINE from Get for this type. They are live credentials,
	// so read must strip them — along with the service bookkeeping beside them.
	t.Run("keys_never_serialized", func(t *testing.T) {
		read, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testNHAuthRuleNativeID})
		require.NoError(t, err)
		require.NotContains(t, read.Properties, "super-secret-primary")
		require.NotContains(t, read.Properties, "super-secret-secondary")
		for _, key := range []string{
			"primaryKey", "secondaryKey", "keyName", "revision",
			"createdTime", "modifiedTime", "claimType", "claimValue",
		} {
			require.NotContains(t, read.Properties, key)
		}
	})

	// No PATCH verb on this API: an update is another CreateOrUpdate, and rights is
	// the only property it can carry.
	t.Run("Update_reissues_create_or_update", func(t *testing.T) {
		before := createCalls
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testNHAuthRuleNativeID,
			DesiredProperties: nhAuthRuleDesired([]string{"Listen", "Send", "Manage"}),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Empty(t, got.ProgressResult.RequestID)
		require.Equal(t, before+1, createCalls)
		require.Len(t, sentRule.Properties.Rights, 3)
		require.Equal(t, armnotificationhubs.AccessRightsManage, *sentRule.Properties.Rights[2])
	})

	t.Run("Delete_is_synchronous", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testNHAuthRuleNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Empty(t, got.ProgressResult.RequestID)
		require.Equal(t, before+1, deleteCalls)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _, _, _ string, _ *armnotificationhubs.ClientDeleteAuthorizationRuleOptions) (armnotificationhubs.ClientDeleteAuthorizationRuleResponse, error) {
			return armnotificationhubs.ClientDeleteAuthorizationRuleResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testNHAuthRuleNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_hub", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{
				"resourceGroupName": "rg-1", "namespaceName": "nh1", "notificationHubName": "hub-1",
			},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testNHAuthRuleNativeID}, got.NativeIDs)
	})

	t.Run("List_without_parents_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.createOrUpdateFn = func(_ context.Context, _, _, _, _ string, _ armnotificationhubs.SharedAccessAuthorizationRuleCreateOrUpdateParameters, _ *armnotificationhubs.ClientCreateOrUpdateAuthorizationRuleOptions) (armnotificationhubs.ClientCreateOrUpdateAuthorizationRuleResponse, error) {
			return armnotificationhubs.ClientCreateOrUpdateAuthorizationRuleResponse{}, &azcore.ResponseError{StatusCode: 409}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "rule-1", Properties: nhAuthRuleDesired([]string{"Listen"}),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

func TestNotificationHubAuthorizationRule_ReadNotFound(t *testing.T) {
	fake := &fakeNHAuthRulesAPI{
		getFn: func(_ context.Context, _, _, _, _ string, _ *armnotificationhubs.ClientGetAuthorizationRuleOptions) (armnotificationhubs.ClientGetAuthorizationRuleResponse, error) {
			return armnotificationhubs.ClientGetAuthorizationRuleResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestNHAuthRule(fake).Read(context.Background(), &resource.ReadRequest{NativeID: testNHAuthRuleNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeNHAuthRulesAPI struct {
	createOrUpdateFn func(ctx context.Context, rgName, namespaceName, hubName, name string, params armnotificationhubs.SharedAccessAuthorizationRuleCreateOrUpdateParameters, options *armnotificationhubs.ClientCreateOrUpdateAuthorizationRuleOptions) (armnotificationhubs.ClientCreateOrUpdateAuthorizationRuleResponse, error)
	getFn            func(ctx context.Context, rgName, namespaceName, hubName, name string, options *armnotificationhubs.ClientGetAuthorizationRuleOptions) (armnotificationhubs.ClientGetAuthorizationRuleResponse, error)
	deleteFn         func(ctx context.Context, rgName, namespaceName, hubName, name string, options *armnotificationhubs.ClientDeleteAuthorizationRuleOptions) (armnotificationhubs.ClientDeleteAuthorizationRuleResponse, error)
	newListPagerFn   func(rgName, namespaceName, hubName string, options *armnotificationhubs.ClientListAuthorizationRulesOptions) *runtime.Pager[armnotificationhubs.ClientListAuthorizationRulesResponse]
}

func (f *fakeNHAuthRulesAPI) CreateOrUpdateAuthorizationRule(ctx context.Context, rgName, namespaceName, hubName, name string, params armnotificationhubs.SharedAccessAuthorizationRuleCreateOrUpdateParameters, options *armnotificationhubs.ClientCreateOrUpdateAuthorizationRuleOptions) (armnotificationhubs.ClientCreateOrUpdateAuthorizationRuleResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, namespaceName, hubName, name, params, options)
}

func (f *fakeNHAuthRulesAPI) GetAuthorizationRule(ctx context.Context, rgName, namespaceName, hubName, name string, options *armnotificationhubs.ClientGetAuthorizationRuleOptions) (armnotificationhubs.ClientGetAuthorizationRuleResponse, error) {
	return f.getFn(ctx, rgName, namespaceName, hubName, name, options)
}

func (f *fakeNHAuthRulesAPI) DeleteAuthorizationRule(ctx context.Context, rgName, namespaceName, hubName, name string, options *armnotificationhubs.ClientDeleteAuthorizationRuleOptions) (armnotificationhubs.ClientDeleteAuthorizationRuleResponse, error) {
	return f.deleteFn(ctx, rgName, namespaceName, hubName, name, options)
}

func (f *fakeNHAuthRulesAPI) NewListAuthorizationRulesPager(rgName, namespaceName, hubName string, options *armnotificationhubs.ClientListAuthorizationRulesOptions) *runtime.Pager[armnotificationhubs.ClientListAuthorizationRulesResponse] {
	return f.newListPagerFn(rgName, namespaceName, hubName, options)
}
