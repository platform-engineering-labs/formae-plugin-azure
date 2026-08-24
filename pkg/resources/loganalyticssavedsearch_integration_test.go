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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/operationalinsights/armoperationalinsights"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testSavedSearchNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.OperationalInsights/workspaces/ws1/savedSearches/ss1"

type fakeSavedSearchesAPI struct {
	createOrUpdateFn  func(ctx context.Context, rgName, workspaceName, searchID string, params armoperationalinsights.SavedSearch, options *armoperationalinsights.SavedSearchesClientCreateOrUpdateOptions) (armoperationalinsights.SavedSearchesClientCreateOrUpdateResponse, error)
	getFn             func(ctx context.Context, rgName, workspaceName, searchID string, options *armoperationalinsights.SavedSearchesClientGetOptions) (armoperationalinsights.SavedSearchesClientGetResponse, error)
	deleteFn          func(ctx context.Context, rgName, workspaceName, searchID string, options *armoperationalinsights.SavedSearchesClientDeleteOptions) (armoperationalinsights.SavedSearchesClientDeleteResponse, error)
	listByWorkspaceFn func(ctx context.Context, rgName, workspaceName string, options *armoperationalinsights.SavedSearchesClientListByWorkspaceOptions) (armoperationalinsights.SavedSearchesClientListByWorkspaceResponse, error)
}

func (f *fakeSavedSearchesAPI) CreateOrUpdate(ctx context.Context, rgName, workspaceName, searchID string, params armoperationalinsights.SavedSearch, options *armoperationalinsights.SavedSearchesClientCreateOrUpdateOptions) (armoperationalinsights.SavedSearchesClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, workspaceName, searchID, params, options)
}

func (f *fakeSavedSearchesAPI) Get(ctx context.Context, rgName, workspaceName, searchID string, options *armoperationalinsights.SavedSearchesClientGetOptions) (armoperationalinsights.SavedSearchesClientGetResponse, error) {
	return f.getFn(ctx, rgName, workspaceName, searchID, options)
}

func (f *fakeSavedSearchesAPI) Delete(ctx context.Context, rgName, workspaceName, searchID string, options *armoperationalinsights.SavedSearchesClientDeleteOptions) (armoperationalinsights.SavedSearchesClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, workspaceName, searchID, options)
}

func (f *fakeSavedSearchesAPI) ListByWorkspace(ctx context.Context, rgName, workspaceName string, options *armoperationalinsights.SavedSearchesClientListByWorkspaceOptions) (armoperationalinsights.SavedSearchesClientListByWorkspaceResponse, error) {
	return f.listByWorkspaceFn(ctx, rgName, workspaceName, options)
}

func newTestSavedSearch(api logAnalyticsSavedSearchesAPI) *LogAnalyticsSavedSearch {
	return &LogAnalyticsSavedSearch{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func savedSearchDesired(displayName, query string) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":              "ss1",
		"resourceGroupName": "rg-1",
		"workspaceName":     "ws1",
		"category":          "conformance",
		"displayName":       displayName,
		"query":             query,
	})
	return out
}

func TestLogAnalyticsSavedSearch_CRUD(t *testing.T) {
	searchResult := armoperationalinsights.SavedSearch{
		ID:   to.Ptr(testSavedSearchNativeID),
		Name: to.Ptr("ss1"),
		Properties: &armoperationalinsights.SavedSearchProperties{
			Category:    to.Ptr("conformance"),
			DisplayName: to.Ptr("heartbeat by computer"),
			Query:       to.Ptr("Heartbeat | summarize count() by Computer"),
			Version:     to.Ptr(int64(2)),
			// ARM echoes these as empty strings for a plain saved search.
			FunctionAlias:      to.Ptr(""),
			FunctionParameters: to.Ptr(""),
			// A saved-search-specific name/value list, not ARM resource tags.
			Tags: []*armoperationalinsights.Tag{{Name: to.Ptr("searchTagName"), Value: to.Ptr("unmodelled-tag-value")}},
		},
		Etag: to.Ptr("*"),
	}

	var sent armoperationalinsights.SavedSearch
	writeCalls := 0
	deleteCalls := 0
	fake := &fakeSavedSearchesAPI{
		createOrUpdateFn: func(_ context.Context, rgName, workspaceName, searchID string, params armoperationalinsights.SavedSearch, _ *armoperationalinsights.SavedSearchesClientCreateOrUpdateOptions) (armoperationalinsights.SavedSearchesClientCreateOrUpdateResponse, error) {
			require.Equal(t, "rg-1", rgName)
			require.Equal(t, "ws1", workspaceName)
			require.Equal(t, "ss1", searchID)
			sent = params
			writeCalls++
			return armoperationalinsights.SavedSearchesClientCreateOrUpdateResponse{SavedSearch: searchResult}, nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ *armoperationalinsights.SavedSearchesClientGetOptions) (armoperationalinsights.SavedSearchesClientGetResponse, error) {
			return armoperationalinsights.SavedSearchesClientGetResponse{SavedSearch: searchResult}, nil
		},
		deleteFn: func(_ context.Context, _, _, _ string, _ *armoperationalinsights.SavedSearchesClientDeleteOptions) (armoperationalinsights.SavedSearchesClientDeleteResponse, error) {
			deleteCalls++
			return armoperationalinsights.SavedSearchesClientDeleteResponse{}, nil
		},
		listByWorkspaceFn: func(_ context.Context, _, _ string, _ *armoperationalinsights.SavedSearchesClientListByWorkspaceOptions) (armoperationalinsights.SavedSearchesClientListByWorkspaceResponse, error) {
			return armoperationalinsights.SavedSearchesClientListByWorkspaceResponse{
				SavedSearchesListResult: armoperationalinsights.SavedSearchesListResult{
					Value: []*armoperationalinsights.SavedSearch{
						{ID: to.Ptr(testSavedSearchNativeID)},
						// A nil entry must not panic the walk.
						nil,
					},
				},
			}, nil
		},
	}
	prov := newTestSavedSearch(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "ss1", Properties: savedSearchDesired("heartbeat by computer", "Heartbeat | summarize count() by Computer"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testSavedSearchNativeID, got.ProgressResult.NativeID)

		require.Equal(t, "conformance", *sent.Properties.Category)
		require.Equal(t, "heartbeat by computer", *sent.Properties.DisplayName)
		require.Equal(t, "Heartbeat | summarize count() by Computer", *sent.Properties.Query)
		require.Nil(t, sent.Properties.FunctionAlias)
		require.Nil(t, sent.Properties.Tags)
	})

	t.Run("Create_requires_query", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "ss1", "resourceGroupName": "rg-1", "workspaceName": "ws1",
			"category": "conformance", "displayName": "x",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "query is required")
	})

	t.Run("Create_requires_workspace", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "ss1", "resourceGroupName": "rg-1"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "workspaceName is required")
	})

	t.Run("Create_sends_function_fields_when_set", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "ss1", "resourceGroupName": "rg-1", "workspaceName": "ws1",
			"category": "conformance", "displayName": "x", "query": "Heartbeat",
			"functionAlias": "recent_heartbeats", "functionParameters": "window:timespan = 1h",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.Equal(t, "recent_heartbeats", *sent.Properties.FunctionAlias)
		require.Equal(t, "window:timespan = 1h", *sent.Properties.FunctionParameters)
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testSavedSearchNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "ss1", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "ws1", props["workspaceName"])
		require.Equal(t, "conformance", props["category"])
		require.Equal(t, "heartbeat by computer", props["displayName"])
		require.Equal(t, "Heartbeat | summarize count() by Computer", props["query"])
		require.EqualValues(t, 2, props["version"])
	})

	// ARM echoes the function fields as empty strings. Reporting them as set would
	// drift against a fixture that never declared them.
	t.Run("Read_omits_empty_function_fields", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testSavedSearchNativeID})
		require.NoError(t, err)
		for _, key := range []string{"functionAlias", "functionParameters", "etag", "searchTagName", "unmodelled-tag-value"} {
			require.NotContains(t, got.Properties, key)
		}
	})

	// CreateOrUpdate is the only write verb this API has.
	t.Run("Update_reissues_create_or_update", func(t *testing.T) {
		before := writeCalls
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testSavedSearchNativeID,
			DesiredProperties: savedSearchDesired("heartbeat by os", "Heartbeat | summarize count() by OSType"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, writeCalls)
		require.Equal(t, "heartbeat by os", *sent.Properties.DisplayName)
		require.Equal(t, "Heartbeat | summarize count() by OSType", *sent.Properties.Query)
	})

	t.Run("Delete", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testSavedSearchNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _, _ string, _ *armoperationalinsights.SavedSearchesClientDeleteOptions) (armoperationalinsights.SavedSearchesClientDeleteResponse, error) {
			return armoperationalinsights.SavedSearchesClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testSavedSearchNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	// Every write is synchronous, so a status request can only concern a finished
	// operation.
	t.Run("Status_is_always_success", func(t *testing.T) {
		got, err := prov.Status(context.Background(), &resource.StatusRequest{RequestID: "whatever"})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, "whatever", got.ProgressResult.RequestID)
	})

	t.Run("List", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "workspaceName": "ws1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testSavedSearchNativeID}, got.NativeIDs)
	})

	t.Run("List_without_workspace_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})

	t.Run("Read_NotFound", func(t *testing.T) {
		fake.getFn = func(_ context.Context, _, _, _ string, _ *armoperationalinsights.SavedSearchesClientGetOptions) (armoperationalinsights.SavedSearchesClientGetResponse, error) {
			return armoperationalinsights.SavedSearchesClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testSavedSearchNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
	})
}
