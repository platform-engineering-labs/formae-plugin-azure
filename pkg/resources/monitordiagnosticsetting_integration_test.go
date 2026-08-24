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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/monitor/armmonitor"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const (
	testDiagTargetID    = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Storage/storageAccounts/sa1"
	testDiagWorkspaceID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.OperationalInsights/workspaces/law-1"
	// ARM echoes the provider segment back lowercase, which the parser must tolerate.
	testDiagNativeID = testDiagTargetID + "/providers/microsoft.insights/diagnosticSettings/ds-1"
)

func newTestMonitorDiagnosticSetting(api monitorDiagnosticSettingsAPI) *MonitorDiagnosticSetting {
	return &MonitorDiagnosticSetting{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func diagSettingDesired(categories ...string) []byte {
	metrics := make([]map[string]any, 0, len(categories))
	for _, c := range categories {
		metrics = append(metrics, map[string]any{"category": c})
	}
	out, _ := json.Marshal(map[string]any{
		"name":             "ds-1",
		"targetResourceId": testDiagTargetID,
		"workspaceId":      testDiagWorkspaceID,
		"metrics":          metrics,
	})
	return out
}

func TestMonitorDiagnosticSetting_IDRoundTrip(t *testing.T) {
	t.Run("compose", func(t *testing.T) {
		require.Equal(t,
			testDiagTargetID+"/providers/Microsoft.Insights/diagnosticSettings/ds-1",
			diagnosticSettingNativeID(testDiagTargetID, "ds-1"))
	})

	t.Run("parse_is_case_insensitive", func(t *testing.T) {
		for _, id := range []string{
			testDiagTargetID + "/providers/microsoft.insights/diagnosticSettings/ds-1",
			testDiagTargetID + "/providers/Microsoft.Insights/diagnosticSettings/ds-1",
			testDiagTargetID + "/providers/MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS/ds-1",
		} {
			target, name, err := parseDiagnosticSettingID(id)
			require.NoError(t, err)
			require.Equal(t, testDiagTargetID, target)
			require.Equal(t, "ds-1", name)
		}
	})

	t.Run("parse_rejects_non_extension_ids", func(t *testing.T) {
		for _, id := range []string{
			testDiagTargetID,
			"",
			testDiagTargetID + "/providers/microsoft.insights/diagnosticSettings/",
			testDiagTargetID + "/providers/microsoft.insights/diagnosticSettings/a/b",
		} {
			_, _, err := parseDiagnosticSettingID(id)
			require.Error(t, err, "id %q should not parse", id)
		}
	})
}

func TestMonitorDiagnosticSetting_CRUD(t *testing.T) {
	var sentURI, sentName string
	var sent armmonitor.DiagnosticSettingsResource
	echo := func(params armmonitor.DiagnosticSettingsResource) armmonitor.DiagnosticSettingsResource {
		params.ID = to.Ptr(testDiagNativeID)
		params.Name = to.Ptr("ds-1")
		return params
	}

	fake := &fakeDiagnosticSettingsAPI{
		createOrUpdateFn: func(_ context.Context, resourceURI, name string, params armmonitor.DiagnosticSettingsResource, _ *armmonitor.DiagnosticSettingsClientCreateOrUpdateOptions) (armmonitor.DiagnosticSettingsClientCreateOrUpdateResponse, error) {
			sentURI, sentName, sent = resourceURI, name, params
			return armmonitor.DiagnosticSettingsClientCreateOrUpdateResponse{DiagnosticSettingsResource: echo(params)}, nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armmonitor.DiagnosticSettingsClientGetOptions) (armmonitor.DiagnosticSettingsClientGetResponse, error) {
			return armmonitor.DiagnosticSettingsClientGetResponse{DiagnosticSettingsResource: echo(sent)}, nil
		},
		deleteFn: func(_ context.Context, _, _ string, _ *armmonitor.DiagnosticSettingsClientDeleteOptions) (armmonitor.DiagnosticSettingsClientDeleteResponse, error) {
			return armmonitor.DiagnosticSettingsClientDeleteResponse{}, nil
		},
		newListPagerFn: func(_ string, _ *armmonitor.DiagnosticSettingsClientListOptions) *runtime.Pager[armmonitor.DiagnosticSettingsClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armmonitor.DiagnosticSettingsClientListResponse]{
				More: func(_ armmonitor.DiagnosticSettingsClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armmonitor.DiagnosticSettingsClientListResponse) (armmonitor.DiagnosticSettingsClientListResponse, error) {
					return armmonitor.DiagnosticSettingsClientListResponse{
						DiagnosticSettingsResourceCollection: armmonitor.DiagnosticSettingsResourceCollection{
							Value: []*armmonitor.DiagnosticSettingsResource{{ID: to.Ptr(testDiagNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestMonitorDiagnosticSetting(fake)

	t.Run("Create_scopes_call_to_target", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "ds-1", Properties: diagSettingDesired("Transaction")})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testDiagNativeID, got.ProgressResult.NativeID)

		// The target resource id is the ARM scope, not a resource-group argument.
		require.Equal(t, testDiagTargetID, sentURI)
		require.Equal(t, "ds-1", sentName)
		require.Equal(t, testDiagWorkspaceID, *sent.Properties.WorkspaceID)
		require.Len(t, sent.Properties.Metrics, 1)
		require.Equal(t, "Transaction", *sent.Properties.Metrics[0].Category)

		var props map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &props))
		require.Equal(t, testDiagTargetID, props["targetResourceId"])
	})

	t.Run("Create_requires_targetResourceId", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "ds-1", "workspaceId": testDiagWorkspaceID})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.Error(t, err)
	})

	// A setting with no destination is accepted by neither ARM nor this handler.
	t.Run("Create_requires_a_destination", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "ds-1", "targetResourceId": testDiagTargetID,
			"metrics": []map[string]any{{"category": "Transaction"}},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.Error(t, err)
	})

	t.Run("Create_requires_a_category", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "ds-1", "targetResourceId": testDiagTargetID, "workspaceId": testDiagWorkspaceID,
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.Error(t, err)
	})

	// ARM rejects a log entry carrying both category and categoryGroup.
	t.Run("Create_sends_only_categoryGroup_when_both_set", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "ds-1", "targetResourceId": testDiagTargetID, "workspaceId": testDiagWorkspaceID,
			"logs": []map[string]any{{"category": "StorageRead", "categoryGroup": "allLogs"}},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "ds-1", Properties: props})
		require.NoError(t, err)
		require.Len(t, sent.Properties.Logs, 1)
		require.Equal(t, "allLogs", *sent.Properties.Logs[0].CategoryGroup)
		require.Nil(t, sent.Properties.Logs[0].Category)
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testDiagNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "ds-1", props["name"])
		require.Equal(t, testDiagTargetID, props["targetResourceId"])
	})

	t.Run("Update_adds_a_routed_category_and_keeps_native_id", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testDiagNativeID,
			DesiredProperties: diagSettingDesired("Transaction", "Capacity"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testDiagNativeID, got.ProgressResult.NativeID)
		require.Len(t, sent.Properties.Metrics, 2)
		require.Equal(t, "Capacity", *sent.Properties.Metrics[1].Category)
	})

	t.Run("Delete", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testDiagNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _ string, _ *armmonitor.DiagnosticSettingsClientDeleteOptions) (armmonitor.DiagnosticSettingsClientDeleteResponse, error) {
			return armmonitor.DiagnosticSettingsClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testDiagNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_target", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"targetResourceId": testDiagTargetID},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testDiagNativeID}, got.NativeIDs)
	})

	// There is no subscription-wide list for diagnostic settings, so no target
	// means no results rather than an error.
	t.Run("List_without_target_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.createOrUpdateFn = func(_ context.Context, _, _ string, _ armmonitor.DiagnosticSettingsResource, _ *armmonitor.DiagnosticSettingsClientCreateOrUpdateOptions) (armmonitor.DiagnosticSettingsClientCreateOrUpdateResponse, error) {
			return armmonitor.DiagnosticSettingsClientCreateOrUpdateResponse{}, &azcore.ResponseError{StatusCode: 400}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "ds-1", Properties: diagSettingDesired("Transaction")})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

// ARM echoes back every category the target supports, disabling the ones that were
// not requested. Read must drop those, or a subset declaration drifts forever —
// this is exactly what failed conformance [Sync] with "expected 1, got 2".
func TestMonitorDiagnosticSetting_ReadDropsDisabledCategories(t *testing.T) {
	fake := &fakeDiagnosticSettingsAPI{
		getFn: func(_ context.Context, _, _ string, _ *armmonitor.DiagnosticSettingsClientGetOptions) (armmonitor.DiagnosticSettingsClientGetResponse, error) {
			return armmonitor.DiagnosticSettingsClientGetResponse{
				DiagnosticSettingsResource: armmonitor.DiagnosticSettingsResource{
					ID:   to.Ptr(testDiagNativeID),
					Name: to.Ptr("ds-1"),
					Properties: &armmonitor.DiagnosticSettings{
						WorkspaceID: to.Ptr(testDiagWorkspaceID),
						Metrics: []*armmonitor.MetricSettings{
							{Category: to.Ptr("Transaction"), Enabled: to.Ptr(true)},
							{Category: to.Ptr("Capacity"), Enabled: to.Ptr(false)},
						},
						Logs: []*armmonitor.LogSettings{
							{CategoryGroup: to.Ptr("audit"), Enabled: to.Ptr(false)},
						},
					},
				},
			}, nil
		},
	}
	got, err := newTestMonitorDiagnosticSetting(fake).Read(context.Background(), &resource.ReadRequest{NativeID: testDiagNativeID})
	require.NoError(t, err)

	var props map[string]any
	require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
	metrics := props["metrics"].([]any)
	require.Len(t, metrics, 1)
	require.Equal(t, "Transaction", metrics[0].(map[string]any)["category"])
	// The only log category came back disabled, so no logs key at all.
	require.NotContains(t, props, "logs")
	// No enabled flag is surfaced: presence in the list is the routing signal.
	require.NotContains(t, metrics[0].(map[string]any), "enabled")
}

func TestMonitorDiagnosticSetting_ReadNotFound(t *testing.T) {
	fake := &fakeDiagnosticSettingsAPI{
		getFn: func(_ context.Context, _, _ string, _ *armmonitor.DiagnosticSettingsClientGetOptions) (armmonitor.DiagnosticSettingsClientGetResponse, error) {
			return armmonitor.DiagnosticSettingsClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestMonitorDiagnosticSetting(fake).Read(context.Background(), &resource.ReadRequest{NativeID: testDiagNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeDiagnosticSettingsAPI struct {
	createOrUpdateFn func(ctx context.Context, resourceURI, name string, parameters armmonitor.DiagnosticSettingsResource, options *armmonitor.DiagnosticSettingsClientCreateOrUpdateOptions) (armmonitor.DiagnosticSettingsClientCreateOrUpdateResponse, error)
	getFn            func(ctx context.Context, resourceURI, name string, options *armmonitor.DiagnosticSettingsClientGetOptions) (armmonitor.DiagnosticSettingsClientGetResponse, error)
	deleteFn         func(ctx context.Context, resourceURI, name string, options *armmonitor.DiagnosticSettingsClientDeleteOptions) (armmonitor.DiagnosticSettingsClientDeleteResponse, error)
	newListPagerFn   func(resourceURI string, options *armmonitor.DiagnosticSettingsClientListOptions) *runtime.Pager[armmonitor.DiagnosticSettingsClientListResponse]
}

func (f *fakeDiagnosticSettingsAPI) CreateOrUpdate(ctx context.Context, resourceURI, name string, parameters armmonitor.DiagnosticSettingsResource, options *armmonitor.DiagnosticSettingsClientCreateOrUpdateOptions) (armmonitor.DiagnosticSettingsClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, resourceURI, name, parameters, options)
}

func (f *fakeDiagnosticSettingsAPI) Get(ctx context.Context, resourceURI, name string, options *armmonitor.DiagnosticSettingsClientGetOptions) (armmonitor.DiagnosticSettingsClientGetResponse, error) {
	return f.getFn(ctx, resourceURI, name, options)
}

func (f *fakeDiagnosticSettingsAPI) Delete(ctx context.Context, resourceURI, name string, options *armmonitor.DiagnosticSettingsClientDeleteOptions) (armmonitor.DiagnosticSettingsClientDeleteResponse, error) {
	return f.deleteFn(ctx, resourceURI, name, options)
}

func (f *fakeDiagnosticSettingsAPI) NewListPager(resourceURI string, options *armmonitor.DiagnosticSettingsClientListOptions) *runtime.Pager[armmonitor.DiagnosticSettingsClientListResponse] {
	return f.newListPagerFn(resourceURI, options)
}
