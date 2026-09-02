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

const testLogAnalyticsTableNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.OperationalInsights/workspaces/ws1/tables/Heartbeat"

type fakeLogAnalyticsTablesAPI struct {
	getFn       func(ctx context.Context, rgName, workspaceName, tableName string, options *armoperationalinsights.TablesClientGetOptions) (armoperationalinsights.TablesClientGetResponse, error)
	updateFn    func(ctx context.Context, rgName, workspaceName, tableName string, params armoperationalinsights.Table, options *armoperationalinsights.TablesClientUpdateOptions) (armoperationalinsights.TablesClientUpdateResponse, error)
	listPagerFn func(rgName, workspaceName string, options *armoperationalinsights.TablesClientListByWorkspaceOptions) *runtime.Pager[armoperationalinsights.TablesClientListByWorkspaceResponse]
}

func (f *fakeLogAnalyticsTablesAPI) Get(ctx context.Context, rgName, workspaceName, tableName string, options *armoperationalinsights.TablesClientGetOptions) (armoperationalinsights.TablesClientGetResponse, error) {
	return f.getFn(ctx, rgName, workspaceName, tableName, options)
}

func (f *fakeLogAnalyticsTablesAPI) Update(ctx context.Context, rgName, workspaceName, tableName string, params armoperationalinsights.Table, options *armoperationalinsights.TablesClientUpdateOptions) (armoperationalinsights.TablesClientUpdateResponse, error) {
	return f.updateFn(ctx, rgName, workspaceName, tableName, params, options)
}

func (f *fakeLogAnalyticsTablesAPI) NewListByWorkspacePager(rgName, workspaceName string, options *armoperationalinsights.TablesClientListByWorkspaceOptions) *runtime.Pager[armoperationalinsights.TablesClientListByWorkspaceResponse] {
	return f.listPagerFn(rgName, workspaceName, options)
}

func newTestLogAnalyticsTable(api logAnalyticsTablesAPI) *LogAnalyticsTable {
	return &LogAnalyticsTable{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func logAnalyticsTableDesired(retentionInDays int) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":              "Heartbeat",
		"resourceGroupName": "rg-1",
		"workspaceName":     "ws1",
		"retentionInDays":   retentionInDays,
	})
	return out
}

func TestLogAnalyticsTable_CRUD(t *testing.T) {
	tableResult := armoperationalinsights.Table{
		ID:   to.Ptr(testLogAnalyticsTableNativeID),
		Name: to.Ptr("Heartbeat"),
		Properties: &armoperationalinsights.TableProperties{
			RetentionInDays: to.Ptr(int32(60)),
		},
	}

	var sent armoperationalinsights.Table
	patchCalls := 0
	fake := &fakeLogAnalyticsTablesAPI{
		getFn: func(_ context.Context, _, _, _ string, _ *armoperationalinsights.TablesClientGetOptions) (armoperationalinsights.TablesClientGetResponse, error) {
			return armoperationalinsights.TablesClientGetResponse{Table: tableResult}, nil
		},
		updateFn: func(_ context.Context, rgName, workspaceName, tableName string, params armoperationalinsights.Table, _ *armoperationalinsights.TablesClientUpdateOptions) (armoperationalinsights.TablesClientUpdateResponse, error) {
			require.Equal(t, "rg-1", rgName)
			require.Equal(t, "ws1", workspaceName)
			require.Equal(t, "Heartbeat", tableName)
			sent = params
			patchCalls++
			return armoperationalinsights.TablesClientUpdateResponse{Table: tableResult}, nil
		},
		listPagerFn: func(_, _ string, _ *armoperationalinsights.TablesClientListByWorkspaceOptions) *runtime.Pager[armoperationalinsights.TablesClientListByWorkspaceResponse] {
			return runtime.NewPager(runtime.PagingHandler[armoperationalinsights.TablesClientListByWorkspaceResponse]{
				More: func(_ armoperationalinsights.TablesClientListByWorkspaceResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armoperationalinsights.TablesClientListByWorkspaceResponse) (armoperationalinsights.TablesClientListByWorkspaceResponse, error) {
					return armoperationalinsights.TablesClientListByWorkspaceResponse{
						TablesListResult: armoperationalinsights.TablesListResult{
							Value: []*armoperationalinsights.Table{
								{ID: to.Ptr(testLogAnalyticsTableNativeID)},
								// Every table the workspace has is enumerated,
								// built-in ones included: ARM offers no filter.
								{ID: to.Ptr("/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.OperationalInsights/workspaces/ws1/tables/Usage")},
								// A nil entry must not panic the walk.
								nil,
							},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestLogAnalyticsTable(fake)

	// The tables API has no PUT: create is the same PATCH as update, against a
	// table the workspace already has.
	t.Run("Create_adopts_the_table_with_a_patch", func(t *testing.T) {
		before := patchCalls
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "Heartbeat", Properties: logAnalyticsTableDesired(60),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testLogAnalyticsTableNativeID, got.ProgressResult.NativeID)
		require.Equal(t, before+1, patchCalls)
		require.Equal(t, int32(60), *sent.Properties.RetentionInDays)
	})

	t.Run("Create_requires_retention", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "Heartbeat", "resourceGroupName": "rg-1", "workspaceName": "ws1",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "retentionInDays is required")
	})

	t.Run("Create_requires_workspace", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "Heartbeat", "resourceGroupName": "rg-1", "retentionInDays": 60,
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "workspaceName is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testLogAnalyticsTableNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
		require.Equal(t, ResourceTypeLogAnalyticsTable, got.ResourceType)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "Heartbeat", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "ws1", props["workspaceName"])
		require.Equal(t, float64(60), props["retentionInDays"])
	})

	t.Run("Update", func(t *testing.T) {
		before := patchCalls
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testLogAnalyticsTableNativeID,
			DesiredProperties: logAnalyticsTableDesired(90),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, patchCalls)
		require.Equal(t, int32(90), *sent.Properties.RetentionInDays)
	})

	// Delete cannot remove the table — ARM has no DELETE here — so it must send an
	// explicit JSON null, which is the only thing that resets the table to the
	// workspace default. A plain nil *int32 would be dropped from the body and the
	// retention would silently stay where it was.
	t.Run("Delete_resets_retention_with_an_explicit_null", func(t *testing.T) {
		before := patchCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testLogAnalyticsTableNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, patchCalls)

		require.True(t, azcore.IsNullValue(sent.Properties.RetentionInDays))
		body, err := json.Marshal(sent.Properties)
		require.NoError(t, err)
		require.JSONEq(t, `{"retentionInDays":null}`, string(body))
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.updateFn = func(_ context.Context, _, _, _ string, _ armoperationalinsights.Table, _ *armoperationalinsights.TablesClientUpdateOptions) (armoperationalinsights.TablesClientUpdateResponse, error) {
			return armoperationalinsights.TablesClientUpdateResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testLogAnalyticsTableNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Delete_failure_reports_the_provider_error", func(t *testing.T) {
		fake.updateFn = func(_ context.Context, _, _, _ string, _ armoperationalinsights.Table, _ *armoperationalinsights.TablesClientUpdateOptions) (armoperationalinsights.TablesClientUpdateResponse, error) {
			return armoperationalinsights.TablesClientUpdateResponse{}, &azcore.ResponseError{StatusCode: 403}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testLogAnalyticsTableNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.Equal(t, resource.OperationErrorCodeAccessDenied, got.ProgressResult.ErrorCode)
		require.NotEmpty(t, got.ProgressResult.StatusMessage)
	})

	t.Run("Status_is_always_success", func(t *testing.T) {
		got, err := prov.Status(context.Background(), &resource.StatusRequest{RequestID: "whatever"})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "workspaceName": "ws1"},
		})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 2)
		require.Equal(t, testLogAnalyticsTableNativeID, got.NativeIDs[0])
	})

	t.Run("List_without_workspace_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})

	t.Run("Read_NotFound", func(t *testing.T) {
		fake.getFn = func(_ context.Context, _, _, _ string, _ *armoperationalinsights.TablesClientGetOptions) (armoperationalinsights.TablesClientGetResponse, error) {
			return armoperationalinsights.TablesClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testLogAnalyticsTableNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
	})

	t.Run("Create_failure_reports_the_provider_error", func(t *testing.T) {
		fake.updateFn = func(_ context.Context, _, _, _ string, _ armoperationalinsights.Table, _ *armoperationalinsights.TablesClientUpdateOptions) (armoperationalinsights.TablesClientUpdateResponse, error) {
			return armoperationalinsights.TablesClientUpdateResponse{}, &azcore.ResponseError{StatusCode: 400}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "Heartbeat", Properties: logAnalyticsTableDesired(60),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.Equal(t, resource.OperationErrorCodeInvalidRequest, got.ProgressResult.ErrorCode)
		require.NotEmpty(t, got.ProgressResult.StatusMessage)
	})
}
