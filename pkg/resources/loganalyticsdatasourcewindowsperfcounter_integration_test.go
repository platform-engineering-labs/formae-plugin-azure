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

const testDataSourceWindowsPerfCounterNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.OperationalInsights/workspaces/ws1/dataSources/ds-wpc-1"

// fakeLogAnalyticsDataSourcesAPI and dataSourceListPager live in
// loganalyticsdatasourcewindowsevent_integration_test.go: one ARM client backs
// every data source kind, so the fake is shared.

func newTestDataSourceWindowsPerfCounter(api logAnalyticsDataSourcesAPI) *LogAnalyticsDataSourceWindowsPerfCounter {
	return &LogAnalyticsDataSourceWindowsPerfCounter{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func dataSourceWindowsPerfCounterDesired(intervalSeconds int) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":              "ds-wpc-1",
		"resourceGroupName": "rg-1",
		"workspaceName":     "ws1",
		"objectName":        "Processor",
		"instanceName":      "_Total",
		"counterName":       "% Processor Time",
		"intervalSeconds":   intervalSeconds,
	})
	return out
}

func TestLogAnalyticsDataSourceWindowsPerfCounter_CRUD(t *testing.T) {
	sourceResult := armoperationalinsights.DataSource{
		ID:   to.Ptr(testDataSourceWindowsPerfCounterNativeID),
		Name: to.Ptr("ds-wpc-1"),
		Kind: to.Ptr(armoperationalinsights.DataSourceKindWindowsPerformanceCounter),
		// ARM answers with the untyped blob it stored; numbers arrive as float64
		// through encoding/json, which is the case the read path must handle.
		Properties: map[string]any{
			"objectName":      "Processor",
			"instanceName":    "_Total",
			"counterName":     "% Processor Time",
			"intervalSeconds": float64(60),
		},
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
			require.Equal(t, "ds-wpc-1", sourceName)
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
			return dataSourceListPager(testDataSourceWindowsPerfCounterNativeID)
		},
	}
	prov := newTestDataSourceWindowsPerfCounter(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "ds-wpc-1", Properties: dataSourceWindowsPerfCounterDesired(60),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testDataSourceWindowsPerfCounterNativeID, got.ProgressResult.NativeID)

		// The kind is fixed by the resource type, not by the caller.
		require.Equal(t, armoperationalinsights.DataSourceKindWindowsPerformanceCounter, *sent.Kind)

		blob, ok := sent.Properties.(map[string]any)
		require.True(t, ok)
		require.Equal(t, "Processor", blob["objectName"])
		require.Equal(t, "_Total", blob["instanceName"])
		require.Equal(t, "% Processor Time", blob["counterName"])
		require.Equal(t, int64(60), blob["intervalSeconds"])
	})

	t.Run("Create_requires_object_name", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "ds-wpc-1", "resourceGroupName": "rg-1", "workspaceName": "ws1",
			"instanceName": "_Total", "counterName": "% Processor Time", "intervalSeconds": 60,
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "objectName is required")
	})

	t.Run("Create_requires_counter_name", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "ds-wpc-1", "resourceGroupName": "rg-1", "workspaceName": "ws1",
			"objectName": "Processor", "instanceName": "_Total", "intervalSeconds": 60,
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "counterName is required")
	})

	// A zero interval would sample continuously; ARM has no meaningful default
	// here, so the handler refuses it rather than sending 0.
	t.Run("Create_requires_interval", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "ds-wpc-1", "resourceGroupName": "rg-1", "workspaceName": "ws1",
			"objectName": "Processor", "instanceName": "_Total", "counterName": "% Processor Time",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "intervalSeconds is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testDataSourceWindowsPerfCounterNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
		require.Equal(t, ResourceTypeLogAnalyticsDataSourceWindowsPerfCounter, got.ResourceType)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "ds-wpc-1", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "ws1", props["workspaceName"])
		require.Equal(t, "Processor", props["objectName"])
		require.Equal(t, "_Total", props["instanceName"])
		require.Equal(t, "% Processor Time", props["counterName"])
		// A float64 from the wire must come back out as a plain number, not 6e+01.
		require.Equal(t, float64(60), props["intervalSeconds"])
	})

	t.Run("Read_drops_service_state", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testDataSourceWindowsPerfCounterNativeID})
		require.NoError(t, err)
		for _, key := range []string{"etag", "kind", "WindowsPerformanceCounter"} {
			require.NotContains(t, got.Properties, key)
		}
	})

	// CreateOrUpdate is the only write verb this API has.
	t.Run("Update_reissues_create_or_update", func(t *testing.T) {
		before := writeCalls
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testDataSourceWindowsPerfCounterNativeID,
			DesiredProperties: dataSourceWindowsPerfCounterDesired(300),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, writeCalls)

		blob := sent.Properties.(map[string]any)
		require.Equal(t, int64(300), blob["intervalSeconds"])
	})

	t.Run("Delete", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testDataSourceWindowsPerfCounterNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _, _ string, _ *armoperationalinsights.DataSourcesClientDeleteOptions) (armoperationalinsights.DataSourcesClientDeleteResponse, error) {
			return armoperationalinsights.DataSourcesClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testDataSourceWindowsPerfCounterNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Status_is_always_success", func(t *testing.T) {
		got, err := prov.Status(context.Background(), &resource.StatusRequest{RequestID: "whatever"})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	// Two formae types share one ARM collection; the filter is what keeps them
	// from claiming each other's resources during discovery.
	t.Run("List_filters_by_kind", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "workspaceName": "ws1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testDataSourceWindowsPerfCounterNativeID}, got.NativeIDs)
		require.Equal(t, "kind='WindowsPerformanceCounter'", sentFilter)
	})

	t.Run("List_without_resource_group_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"workspaceName": "ws1"},
		})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})

	t.Run("Read_NotFound", func(t *testing.T) {
		fake.getFn = func(_ context.Context, _, _, _ string, _ *armoperationalinsights.DataSourcesClientGetOptions) (armoperationalinsights.DataSourcesClientGetResponse, error) {
			return armoperationalinsights.DataSourcesClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testDataSourceWindowsPerfCounterNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
	})

	t.Run("Update_failure_reports_the_provider_error", func(t *testing.T) {
		fake.createOrUpdateFn = func(_ context.Context, _, _, _ string, _ armoperationalinsights.DataSource, _ *armoperationalinsights.DataSourcesClientCreateOrUpdateOptions) (armoperationalinsights.DataSourcesClientCreateOrUpdateResponse, error) {
			return armoperationalinsights.DataSourcesClientCreateOrUpdateResponse{}, &azcore.ResponseError{StatusCode: 403}
		}
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testDataSourceWindowsPerfCounterNativeID,
			DesiredProperties: dataSourceWindowsPerfCounterDesired(60),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.Equal(t, resource.OperationErrorCodeAccessDenied, got.ProgressResult.ErrorCode)
		require.NotEmpty(t, got.ProgressResult.StatusMessage)
	})
}
