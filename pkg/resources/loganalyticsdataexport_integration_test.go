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

const (
	testDataExportNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.OperationalInsights/workspaces/ws1/dataExports/de1"
	testDataExportDestID   = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Storage/storageAccounts/sa1"
)

type fakeDataExportsAPI struct {
	createOrUpdateFn func(ctx context.Context, rgName, workspaceName, exportName string, params armoperationalinsights.DataExport, options *armoperationalinsights.DataExportsClientCreateOrUpdateOptions) (armoperationalinsights.DataExportsClientCreateOrUpdateResponse, error)
	getFn            func(ctx context.Context, rgName, workspaceName, exportName string, options *armoperationalinsights.DataExportsClientGetOptions) (armoperationalinsights.DataExportsClientGetResponse, error)
	deleteFn         func(ctx context.Context, rgName, workspaceName, exportName string, options *armoperationalinsights.DataExportsClientDeleteOptions) (armoperationalinsights.DataExportsClientDeleteResponse, error)
	listPagerFn      func(rgName, workspaceName string, options *armoperationalinsights.DataExportsClientListByWorkspaceOptions) *runtime.Pager[armoperationalinsights.DataExportsClientListByWorkspaceResponse]
}

func (f *fakeDataExportsAPI) CreateOrUpdate(ctx context.Context, rgName, workspaceName, exportName string, params armoperationalinsights.DataExport, options *armoperationalinsights.DataExportsClientCreateOrUpdateOptions) (armoperationalinsights.DataExportsClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, workspaceName, exportName, params, options)
}

func (f *fakeDataExportsAPI) Get(ctx context.Context, rgName, workspaceName, exportName string, options *armoperationalinsights.DataExportsClientGetOptions) (armoperationalinsights.DataExportsClientGetResponse, error) {
	return f.getFn(ctx, rgName, workspaceName, exportName, options)
}

func (f *fakeDataExportsAPI) Delete(ctx context.Context, rgName, workspaceName, exportName string, options *armoperationalinsights.DataExportsClientDeleteOptions) (armoperationalinsights.DataExportsClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, workspaceName, exportName, options)
}

func (f *fakeDataExportsAPI) NewListByWorkspacePager(rgName, workspaceName string, options *armoperationalinsights.DataExportsClientListByWorkspaceOptions) *runtime.Pager[armoperationalinsights.DataExportsClientListByWorkspaceResponse] {
	return f.listPagerFn(rgName, workspaceName, options)
}

func newTestDataExport(api logAnalyticsDataExportsAPI) *LogAnalyticsDataExport {
	return &LogAnalyticsDataExport{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func dataExportDesired(tables []any, enable bool) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":                  "de1",
		"resourceGroupName":     "rg-1",
		"workspaceName":         "ws1",
		"tableNames":            tables,
		"destinationResourceId": testDataExportDestID,
		"enable":                enable,
	})
	return out
}

func TestLogAnalyticsDataExport_CRUD(t *testing.T) {
	exportResult := armoperationalinsights.DataExport{
		ID:   to.Ptr(testDataExportNativeID),
		Name: to.Ptr("de1"),
		Properties: &armoperationalinsights.DataExportProperties{
			TableNames: []*string{to.Ptr("Heartbeat")},
			Enable:     to.Ptr(true),
			Destination: &armoperationalinsights.Destination{
				ResourceID: to.Ptr(testDataExportDestID),
				// Derived by the service from the resource ID; the schema cannot
				// express it.
				Type: to.Ptr(armoperationalinsights.TypeStorageAccount),
			},
			// Service state.
			DataExportID:     to.Ptr("d2b3ee1c-1111-2222-3333-444455556666"),
			CreatedDate:      to.Ptr("Thu, 21 Aug 2026 12:00:00 GMT"),
			LastModifiedDate: to.Ptr("Thu, 21 Aug 2026 12:00:00 GMT"),
		},
	}

	var sent armoperationalinsights.DataExport
	writeCalls := 0
	deleteCalls := 0
	fake := &fakeDataExportsAPI{
		createOrUpdateFn: func(_ context.Context, rgName, workspaceName, exportName string, params armoperationalinsights.DataExport, _ *armoperationalinsights.DataExportsClientCreateOrUpdateOptions) (armoperationalinsights.DataExportsClientCreateOrUpdateResponse, error) {
			require.Equal(t, "rg-1", rgName)
			require.Equal(t, "ws1", workspaceName)
			require.Equal(t, "de1", exportName)
			sent = params
			writeCalls++
			return armoperationalinsights.DataExportsClientCreateOrUpdateResponse{DataExport: exportResult}, nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ *armoperationalinsights.DataExportsClientGetOptions) (armoperationalinsights.DataExportsClientGetResponse, error) {
			return armoperationalinsights.DataExportsClientGetResponse{DataExport: exportResult}, nil
		},
		deleteFn: func(_ context.Context, _, _, _ string, _ *armoperationalinsights.DataExportsClientDeleteOptions) (armoperationalinsights.DataExportsClientDeleteResponse, error) {
			deleteCalls++
			return armoperationalinsights.DataExportsClientDeleteResponse{}, nil
		},
		listPagerFn: func(_, _ string, _ *armoperationalinsights.DataExportsClientListByWorkspaceOptions) *runtime.Pager[armoperationalinsights.DataExportsClientListByWorkspaceResponse] {
			return runtime.NewPager(runtime.PagingHandler[armoperationalinsights.DataExportsClientListByWorkspaceResponse]{
				More: func(_ armoperationalinsights.DataExportsClientListByWorkspaceResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armoperationalinsights.DataExportsClientListByWorkspaceResponse) (armoperationalinsights.DataExportsClientListByWorkspaceResponse, error) {
					return armoperationalinsights.DataExportsClientListByWorkspaceResponse{
						DataExportListResult: armoperationalinsights.DataExportListResult{
							Value: []*armoperationalinsights.DataExport{
								{ID: to.Ptr(testDataExportNativeID)},
								// A nil entry must not panic the walk.
								nil,
							},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestDataExport(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "de1", Properties: dataExportDesired([]any{"Heartbeat"}, true),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testDataExportNativeID, got.ProgressResult.NativeID)

		require.Equal(t, "Heartbeat", *sent.Properties.TableNames[0])
		require.Equal(t, testDataExportDestID, *sent.Properties.Destination.ResourceID)
		require.True(t, *sent.Properties.Enable)
		// ARM rejects an empty metadata block on a storage account destination.
		require.Nil(t, sent.Properties.Destination.MetaData)
		// The destination type is the service's to decide.
		require.Nil(t, sent.Properties.Destination.Type)
	})

	t.Run("Create_requires_tables", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "de1", "resourceGroupName": "rg-1", "workspaceName": "ws1",
			"destinationResourceId": testDataExportDestID,
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "tableNames is required")
	})

	t.Run("Create_requires_destination", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "de1", "resourceGroupName": "rg-1", "workspaceName": "ws1",
			"tableNames": []any{"Heartbeat"},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "destinationResourceId is required")
	})

	// An event hub destination is the only one that takes a hub name.
	t.Run("Create_sends_event_hub_metadata", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "de1", "resourceGroupName": "rg-1", "workspaceName": "ws1",
			"tableNames":            []any{"Heartbeat"},
			"destinationResourceId": "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.EventHub/namespaces/ehns1",
			"eventHubName":          "logs",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.Equal(t, "logs", *sent.Properties.Destination.MetaData.EventHubName)
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testDataExportNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "de1", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "ws1", props["workspaceName"])
		require.Equal(t, []any{"Heartbeat"}, props["tableNames"])
		require.Equal(t, testDataExportDestID, props["destinationResourceId"])
		require.Equal(t, true, props["enable"])
	})

	// Service state and the derived destination type would read as drift forever.
	t.Run("Read_drops_service_state", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testDataExportNativeID})
		require.NoError(t, err)
		for _, key := range []string{"dataExportId", "createdDate", "lastModifiedDate", "StorageAccount"} {
			require.NotContains(t, got.Properties, key)
		}
		// No event hub on a storage destination: absent, not "".
		require.NotContains(t, got.Properties, "eventHubName")
	})

	// CreateOrUpdate is the only write verb this API has.
	t.Run("Update_reissues_create_or_update", func(t *testing.T) {
		before := writeCalls
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testDataExportNativeID,
			DesiredProperties: dataExportDesired([]any{"Heartbeat", "Usage"}, false),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, writeCalls)
		require.Len(t, sent.Properties.TableNames, 2)
		require.False(t, *sent.Properties.Enable)
	})

	t.Run("Delete", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testDataExportNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _, _ string, _ *armoperationalinsights.DataExportsClientDeleteOptions) (armoperationalinsights.DataExportsClientDeleteResponse, error) {
			return armoperationalinsights.DataExportsClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testDataExportNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
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
		require.Equal(t, []string{testDataExportNativeID}, got.NativeIDs)
	})

	t.Run("List_without_workspace_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})

	t.Run("Read_NotFound", func(t *testing.T) {
		fake.getFn = func(_ context.Context, _, _, _ string, _ *armoperationalinsights.DataExportsClientGetOptions) (armoperationalinsights.DataExportsClientGetResponse, error) {
			return armoperationalinsights.DataExportsClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testDataExportNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
	})
}
