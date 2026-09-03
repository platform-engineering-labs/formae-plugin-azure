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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/operationalinsights/armoperationalinsights"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testDataSourceWindowsEventNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.OperationalInsights/workspaces/ws1/dataSources/ds-we-1"

// fakeLogAnalyticsDataSourcesAPI is shared by BOTH data source test files: one ARM
// client backs every `kind`, so there is one fake for all of them.
type fakeLogAnalyticsDataSourcesAPI struct {
	createOrUpdateFn func(ctx context.Context, rgName, workspaceName, sourceName string, params armoperationalinsights.DataSource, options *armoperationalinsights.DataSourcesClientCreateOrUpdateOptions) (armoperationalinsights.DataSourcesClientCreateOrUpdateResponse, error)
	getFn            func(ctx context.Context, rgName, workspaceName, sourceName string, options *armoperationalinsights.DataSourcesClientGetOptions) (armoperationalinsights.DataSourcesClientGetResponse, error)
	deleteFn         func(ctx context.Context, rgName, workspaceName, sourceName string, options *armoperationalinsights.DataSourcesClientDeleteOptions) (armoperationalinsights.DataSourcesClientDeleteResponse, error)
	listPagerFn      func(rgName, workspaceName, filter string, options *armoperationalinsights.DataSourcesClientListByWorkspaceOptions) *runtime.Pager[armoperationalinsights.DataSourcesClientListByWorkspaceResponse]
}

func (f *fakeLogAnalyticsDataSourcesAPI) CreateOrUpdate(ctx context.Context, rgName, workspaceName, sourceName string, params armoperationalinsights.DataSource, options *armoperationalinsights.DataSourcesClientCreateOrUpdateOptions) (armoperationalinsights.DataSourcesClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, workspaceName, sourceName, params, options)
}

func (f *fakeLogAnalyticsDataSourcesAPI) Get(ctx context.Context, rgName, workspaceName, sourceName string, options *armoperationalinsights.DataSourcesClientGetOptions) (armoperationalinsights.DataSourcesClientGetResponse, error) {
	return f.getFn(ctx, rgName, workspaceName, sourceName, options)
}

func (f *fakeLogAnalyticsDataSourcesAPI) Delete(ctx context.Context, rgName, workspaceName, sourceName string, options *armoperationalinsights.DataSourcesClientDeleteOptions) (armoperationalinsights.DataSourcesClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, workspaceName, sourceName, options)
}

func (f *fakeLogAnalyticsDataSourcesAPI) NewListByWorkspacePager(rgName, workspaceName, filter string, options *armoperationalinsights.DataSourcesClientListByWorkspaceOptions) *runtime.Pager[armoperationalinsights.DataSourcesClientListByWorkspaceResponse] {
	return f.listPagerFn(rgName, workspaceName, filter, options)
}

// dataSourceListPager returns a one-page pager over the given IDs, with a nil
// entry appended so the caller's walk is proven not to panic on one.
func dataSourceListPager(ids ...string) *runtime.Pager[armoperationalinsights.DataSourcesClientListByWorkspaceResponse] {
	values := make([]*armoperationalinsights.DataSource, 0, len(ids)+1)
	for _, id := range ids {
		values = append(values, &armoperationalinsights.DataSource{ID: to.Ptr(id)})
	}
	values = append(values, nil)
	return runtime.NewPager(runtime.PagingHandler[armoperationalinsights.DataSourcesClientListByWorkspaceResponse]{
		More: func(_ armoperationalinsights.DataSourcesClientListByWorkspaceResponse) bool { return false },
		Fetcher: func(_ context.Context, _ *armoperationalinsights.DataSourcesClientListByWorkspaceResponse) (armoperationalinsights.DataSourcesClientListByWorkspaceResponse, error) {
			return armoperationalinsights.DataSourcesClientListByWorkspaceResponse{
				DataSourceListResult: armoperationalinsights.DataSourceListResult{Value: values},
			}, nil
		},
	})
}

func newTestDataSourceWindowsEvent(api logAnalyticsDataSourcesAPI) *LogAnalyticsDataSourceWindowsEvent {
	return &LogAnalyticsDataSourceWindowsEvent{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func dataSourceWindowsEventDesired(eventTypes []any) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":              "ds-we-1",
		"resourceGroupName": "rg-1",
		"workspaceName":     "ws1",
		"eventLogName":      "Application",
		"eventTypes":        eventTypes,
	})
	return out
}

func TestLogAnalyticsDataSourceWindowsEvent_CRUD(t *testing.T) {
	sourceResult := armoperationalinsights.DataSource{
		ID:   to.Ptr(testDataSourceWindowsEventNativeID),
		Name: to.Ptr("ds-we-1"),
		Kind: to.Ptr(armoperationalinsights.DataSourceKindWindowsEvent),
		// ARM answers with the untyped blob it stored, and encoding/json hands it
		// back as map[string]any.
		Properties: map[string]any{
			"eventLogName": "Application",
			"eventTypes": []any{
				map[string]any{"eventType": "Error"},
			},
		},
		// Service state.
		Etag: to.Ptr(`W/"datetime'2026-08-21T12:00:00Z'"`),
	}

	var sent armoperationalinsights.DataSource
	var sentFilter string
	writeCalls := 0
	deleteCalls := 0
	fake := &fakeLogAnalyticsDataSourcesAPI{
		createOrUpdateFn: func(_ context.Context, rgName, workspaceName, sourceName string, params armoperationalinsights.DataSource, _ *armoperationalinsights.DataSourcesClientCreateOrUpdateOptions) (armoperationalinsights.DataSourcesClientCreateOrUpdateResponse, error) {
			require.Equal(t, "rg-1", rgName)
			require.Equal(t, "ws1", workspaceName)
			require.Equal(t, "ds-we-1", sourceName)
			sent = params
			writeCalls++
			return armoperationalinsights.DataSourcesClientCreateOrUpdateResponse{DataSource: sourceResult}, nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ *armoperationalinsights.DataSourcesClientGetOptions) (armoperationalinsights.DataSourcesClientGetResponse, error) {
			return armoperationalinsights.DataSourcesClientGetResponse{DataSource: sourceResult}, nil
		},
		deleteFn: func(_ context.Context, _, _, _ string, _ *armoperationalinsights.DataSourcesClientDeleteOptions) (armoperationalinsights.DataSourcesClientDeleteResponse, error) {
			deleteCalls++
			return armoperationalinsights.DataSourcesClientDeleteResponse{}, nil
		},
		listPagerFn: func(_, _, filter string, _ *armoperationalinsights.DataSourcesClientListByWorkspaceOptions) *runtime.Pager[armoperationalinsights.DataSourcesClientListByWorkspaceResponse] {
			sentFilter = filter
			return dataSourceListPager(testDataSourceWindowsEventNativeID)
		},
	}
	prov := newTestDataSourceWindowsEvent(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "ds-we-1", Properties: dataSourceWindowsEventDesired([]any{"Error"}),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testDataSourceWindowsEventNativeID, got.ProgressResult.NativeID)

		// The kind is fixed by the resource type, not by the caller.
		require.Equal(t, armoperationalinsights.DataSourceKindWindowsEvent, *sent.Kind)

		blob, ok := sent.Properties.(map[string]any)
		require.True(t, ok)
		require.Equal(t, "Application", blob["eventLogName"])
		// ARM wants a list of single-key objects, not a list of strings.
		require.Equal(t, []any{map[string]any{"eventType": "Error"}}, blob["eventTypes"])
	})

	t.Run("Create_requires_event_log_name", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "ds-we-1", "resourceGroupName": "rg-1", "workspaceName": "ws1",
			"eventTypes": []any{"Error"},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "eventLogName is required")
	})

	t.Run("Create_requires_event_types", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "ds-we-1", "resourceGroupName": "rg-1", "workspaceName": "ws1",
			"eventLogName": "Application",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "eventTypes is required")
	})

	t.Run("Create_requires_workspace", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "ds-we-1", "resourceGroupName": "rg-1",
			"eventLogName": "Application", "eventTypes": []any{"Error"},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "workspaceName is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testDataSourceWindowsEventNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
		require.Equal(t, ResourceTypeLogAnalyticsDataSourceWindowsEvent, got.ResourceType)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "ds-we-1", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "ws1", props["workspaceName"])
		require.Equal(t, "Application", props["eventLogName"])
		// The nested single-key objects are flattened back to plain severities.
		require.Equal(t, []any{"Error"}, props["eventTypes"])
	})

	// The etag and the kind would read as drift forever: kind is not a field, and
	// the etag changes on every write.
	t.Run("Read_drops_service_state", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testDataSourceWindowsEventNativeID})
		require.NoError(t, err)
		for _, key := range []string{"etag", "kind", "WindowsEvent"} {
			require.NotContains(t, got.Properties, key)
		}
	})

	// ARM stores whatever casing it was handed; desired state carries the enum's.
	t.Run("Read_canonicalizes_event_type_casing", func(t *testing.T) {
		fake.getFn = func(_ context.Context, _, _, _ string, _ *armoperationalinsights.DataSourcesClientGetOptions) (armoperationalinsights.DataSourcesClientGetResponse, error) {
			lowered := sourceResult
			lowered.Properties = map[string]any{
				"eventLogName": "Application",
				"eventTypes":   []any{map[string]any{"eventType": "error"}},
			}
			return armoperationalinsights.DataSourcesClientGetResponse{DataSource: lowered}, nil
		}
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testDataSourceWindowsEventNativeID})
		require.NoError(t, err)
		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, []any{"Error"}, props["eventTypes"])

		fake.getFn = func(_ context.Context, _, _, _ string, _ *armoperationalinsights.DataSourcesClientGetOptions) (armoperationalinsights.DataSourcesClientGetResponse, error) {
			return armoperationalinsights.DataSourcesClientGetResponse{DataSource: sourceResult}, nil
		}
	})

	// A body ARM never sent, or sent as something other than an object, must not
	// panic the read.
	t.Run("Read_tolerates_missing_properties_blob", func(t *testing.T) {
		fake.getFn = func(_ context.Context, _, _, _ string, _ *armoperationalinsights.DataSourcesClientGetOptions) (armoperationalinsights.DataSourcesClientGetResponse, error) {
			return armoperationalinsights.DataSourcesClientGetResponse{
				DataSource: armoperationalinsights.DataSource{
					ID:         to.Ptr(testDataSourceWindowsEventNativeID),
					Name:       to.Ptr("ds-we-1"),
					Properties: "not-an-object",
				},
			}, nil
		}
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testDataSourceWindowsEventNativeID})
		require.NoError(t, err)
		require.NotContains(t, got.Properties, "eventLogName")

		fake.getFn = func(_ context.Context, _, _, _ string, _ *armoperationalinsights.DataSourcesClientGetOptions) (armoperationalinsights.DataSourcesClientGetResponse, error) {
			return armoperationalinsights.DataSourcesClientGetResponse{DataSource: sourceResult}, nil
		}
	})

	// CreateOrUpdate is the only write verb this API has.
	t.Run("Update_reissues_create_or_update", func(t *testing.T) {
		before := writeCalls
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testDataSourceWindowsEventNativeID,
			DesiredProperties: dataSourceWindowsEventDesired([]any{"Error", "Warning"}),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, writeCalls)

		blob := sent.Properties.(map[string]any)
		require.Len(t, blob["eventTypes"], 2)
	})

	t.Run("Delete", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testDataSourceWindowsEventNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _, _ string, _ *armoperationalinsights.DataSourcesClientDeleteOptions) (armoperationalinsights.DataSourcesClientDeleteResponse, error) {
			return armoperationalinsights.DataSourcesClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testDataSourceWindowsEventNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Status_is_always_success", func(t *testing.T) {
		got, err := prov.Status(context.Background(), &resource.StatusRequest{RequestID: "whatever"})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	// The filter is what stops this type enumerating the other kinds that share
	// the dataSources collection, and ARM rejects the call without one.
	t.Run("List_filters_by_kind", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "workspaceName": "ws1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testDataSourceWindowsEventNativeID}, got.NativeIDs)
		// ARM rejects the `kind='WindowsEvent'` spelling with a 400 that reads
		// "Must specify a valid kind filter". This assertion is what let that
		// bug ship green: it pinned the broken form. Only `kind eq '...'` works.
		require.Equal(t, "kind eq 'WindowsEvent'", sentFilter)
	})

	t.Run("List_without_workspace_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})

	t.Run("Read_NotFound", func(t *testing.T) {
		fake.getFn = func(_ context.Context, _, _, _ string, _ *armoperationalinsights.DataSourcesClientGetOptions) (armoperationalinsights.DataSourcesClientGetResponse, error) {
			return armoperationalinsights.DataSourcesClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testDataSourceWindowsEventNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
	})

	// A failed write must carry the provider's own message, not just a code.
	t.Run("Create_failure_reports_the_provider_error", func(t *testing.T) {
		fake.createOrUpdateFn = func(_ context.Context, _, _, _ string, _ armoperationalinsights.DataSource, _ *armoperationalinsights.DataSourcesClientCreateOrUpdateOptions) (armoperationalinsights.DataSourcesClientCreateOrUpdateResponse, error) {
			return armoperationalinsights.DataSourcesClientCreateOrUpdateResponse{}, &azcore.ResponseError{StatusCode: 400}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "ds-we-1", Properties: dataSourceWindowsEventDesired([]any{"Error"}),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.Equal(t, resource.OperationErrorCodeInvalidRequest, got.ProgressResult.ErrorCode)
		require.NotEmpty(t, got.ProgressResult.StatusMessage)
	})
}
