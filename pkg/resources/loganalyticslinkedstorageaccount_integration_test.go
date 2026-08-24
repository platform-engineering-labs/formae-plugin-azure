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
	// ARM lower-cases the data source type in the resource ID it hands back.
	testLinkedStorageNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.OperationalInsights/workspaces/ws1/linkedStorageAccounts/customlogs"
	testLinkedStorageAccount1 = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Storage/storageAccounts/sa1"
	testLinkedStorageAccount2 = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Storage/storageAccounts/sa2"
)

type fakeLinkedStorageAccountsAPI struct {
	createOrUpdateFn func(ctx context.Context, rgName, workspaceName string, dataSourceType armoperationalinsights.DataSourceType, params armoperationalinsights.LinkedStorageAccountsResource, options *armoperationalinsights.LinkedStorageAccountsClientCreateOrUpdateOptions) (armoperationalinsights.LinkedStorageAccountsClientCreateOrUpdateResponse, error)
	getFn            func(ctx context.Context, rgName, workspaceName string, dataSourceType armoperationalinsights.DataSourceType, options *armoperationalinsights.LinkedStorageAccountsClientGetOptions) (armoperationalinsights.LinkedStorageAccountsClientGetResponse, error)
	deleteFn         func(ctx context.Context, rgName, workspaceName string, dataSourceType armoperationalinsights.DataSourceType, options *armoperationalinsights.LinkedStorageAccountsClientDeleteOptions) (armoperationalinsights.LinkedStorageAccountsClientDeleteResponse, error)
	listPagerFn      func(rgName, workspaceName string, options *armoperationalinsights.LinkedStorageAccountsClientListByWorkspaceOptions) *runtime.Pager[armoperationalinsights.LinkedStorageAccountsClientListByWorkspaceResponse]
}

func (f *fakeLinkedStorageAccountsAPI) CreateOrUpdate(ctx context.Context, rgName, workspaceName string, dataSourceType armoperationalinsights.DataSourceType, params armoperationalinsights.LinkedStorageAccountsResource, options *armoperationalinsights.LinkedStorageAccountsClientCreateOrUpdateOptions) (armoperationalinsights.LinkedStorageAccountsClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, workspaceName, dataSourceType, params, options)
}

func (f *fakeLinkedStorageAccountsAPI) Get(ctx context.Context, rgName, workspaceName string, dataSourceType armoperationalinsights.DataSourceType, options *armoperationalinsights.LinkedStorageAccountsClientGetOptions) (armoperationalinsights.LinkedStorageAccountsClientGetResponse, error) {
	return f.getFn(ctx, rgName, workspaceName, dataSourceType, options)
}

func (f *fakeLinkedStorageAccountsAPI) Delete(ctx context.Context, rgName, workspaceName string, dataSourceType armoperationalinsights.DataSourceType, options *armoperationalinsights.LinkedStorageAccountsClientDeleteOptions) (armoperationalinsights.LinkedStorageAccountsClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, workspaceName, dataSourceType, options)
}

func (f *fakeLinkedStorageAccountsAPI) NewListByWorkspacePager(rgName, workspaceName string, options *armoperationalinsights.LinkedStorageAccountsClientListByWorkspaceOptions) *runtime.Pager[armoperationalinsights.LinkedStorageAccountsClientListByWorkspaceResponse] {
	return f.listPagerFn(rgName, workspaceName, options)
}

func newTestLinkedStorageAccount(api logAnalyticsLinkedStorageAccountsAPI) *LogAnalyticsLinkedStorageAccount {
	return &LogAnalyticsLinkedStorageAccount{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func linkedStorageDesired(ids []any) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":              "CustomLogs",
		"resourceGroupName": "rg-1",
		"workspaceName":     "ws1",
		"storageAccountIds": ids,
	})
	return out
}

func TestLogAnalyticsLinkedStorageAccount_CRUD(t *testing.T) {
	linkResult := armoperationalinsights.LinkedStorageAccountsResource{
		ID:   to.Ptr(testLinkedStorageNativeID),
		Name: to.Ptr("CustomLogs"),
		Properties: &armoperationalinsights.LinkedStorageAccountsProperties{
			DataSourceType:    to.Ptr(armoperationalinsights.DataSourceTypeCustomLogs),
			StorageAccountIDs: []*string{to.Ptr(testLinkedStorageAccount1)},
		},
	}

	var sentType armoperationalinsights.DataSourceType
	var sent armoperationalinsights.LinkedStorageAccountsResource
	writeCalls := 0
	deleteCalls := 0
	fake := &fakeLinkedStorageAccountsAPI{
		createOrUpdateFn: func(_ context.Context, rgName, workspaceName string, dataSourceType armoperationalinsights.DataSourceType, params armoperationalinsights.LinkedStorageAccountsResource, _ *armoperationalinsights.LinkedStorageAccountsClientCreateOrUpdateOptions) (armoperationalinsights.LinkedStorageAccountsClientCreateOrUpdateResponse, error) {
			require.Equal(t, "rg-1", rgName)
			require.Equal(t, "ws1", workspaceName)
			sentType = dataSourceType
			sent = params
			writeCalls++
			return armoperationalinsights.LinkedStorageAccountsClientCreateOrUpdateResponse{LinkedStorageAccountsResource: linkResult}, nil
		},
		getFn: func(_ context.Context, _, _ string, _ armoperationalinsights.DataSourceType, _ *armoperationalinsights.LinkedStorageAccountsClientGetOptions) (armoperationalinsights.LinkedStorageAccountsClientGetResponse, error) {
			return armoperationalinsights.LinkedStorageAccountsClientGetResponse{LinkedStorageAccountsResource: linkResult}, nil
		},
		deleteFn: func(_ context.Context, _, _ string, dataSourceType armoperationalinsights.DataSourceType, _ *armoperationalinsights.LinkedStorageAccountsClientDeleteOptions) (armoperationalinsights.LinkedStorageAccountsClientDeleteResponse, error) {
			sentType = dataSourceType
			deleteCalls++
			return armoperationalinsights.LinkedStorageAccountsClientDeleteResponse{}, nil
		},
		listPagerFn: func(_, _ string, _ *armoperationalinsights.LinkedStorageAccountsClientListByWorkspaceOptions) *runtime.Pager[armoperationalinsights.LinkedStorageAccountsClientListByWorkspaceResponse] {
			return runtime.NewPager(runtime.PagingHandler[armoperationalinsights.LinkedStorageAccountsClientListByWorkspaceResponse]{
				More: func(_ armoperationalinsights.LinkedStorageAccountsClientListByWorkspaceResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armoperationalinsights.LinkedStorageAccountsClientListByWorkspaceResponse) (armoperationalinsights.LinkedStorageAccountsClientListByWorkspaceResponse, error) {
					return armoperationalinsights.LinkedStorageAccountsClientListByWorkspaceResponse{
						LinkedStorageAccountsListResult: armoperationalinsights.LinkedStorageAccountsListResult{
							Value: []*armoperationalinsights.LinkedStorageAccountsResource{
								{ID: to.Ptr(testLinkedStorageNativeID)},
								// A nil entry must not panic the walk.
								nil,
							},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestLinkedStorageAccount(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "CustomLogs", Properties: linkedStorageDesired([]any{testLinkedStorageAccount1}),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testLinkedStorageNativeID, got.ProgressResult.NativeID)

		// The data source type addresses the resource; the body carries only the IDs.
		require.Equal(t, armoperationalinsights.DataSourceTypeCustomLogs, sentType)
		require.Equal(t, testLinkedStorageAccount1, *sent.Properties.StorageAccountIDs[0])
		require.Nil(t, sent.Properties.DataSourceType)
	})

	t.Run("Create_requires_storage_accounts", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "CustomLogs", "resourceGroupName": "rg-1", "workspaceName": "ws1",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "storageAccountIds is required")
	})

	t.Run("Create_requires_workspace", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "CustomLogs", "resourceGroupName": "rg-1"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "workspaceName is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testLinkedStorageNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "ws1", props["workspaceName"])
		require.Equal(t, []any{testLinkedStorageAccount1}, props["storageAccountIds"])
		// Desired state says CustomLogs; ARM's lower-cased path segment must not drift.
		require.Equal(t, "CustomLogs", props["name"])
	})

	// ARM may answer with the type lower-cased in the body too.
	t.Run("Read_canonicalizes_lowercase_type", func(t *testing.T) {
		fake.getFn = func(_ context.Context, _, _ string, _ armoperationalinsights.DataSourceType, _ *armoperationalinsights.LinkedStorageAccountsClientGetOptions) (armoperationalinsights.LinkedStorageAccountsClientGetResponse, error) {
			return armoperationalinsights.LinkedStorageAccountsClientGetResponse{
				LinkedStorageAccountsResource: armoperationalinsights.LinkedStorageAccountsResource{
					ID:   to.Ptr(testLinkedStorageNativeID),
					Name: to.Ptr("customlogs"),
					Properties: &armoperationalinsights.LinkedStorageAccountsProperties{
						DataSourceType:    to.Ptr(armoperationalinsights.DataSourceType("customlogs")),
						StorageAccountIDs: []*string{to.Ptr(testLinkedStorageAccount1)},
					},
				},
			}, nil
		}
		defer func() {
			fake.getFn = func(_ context.Context, _, _ string, _ armoperationalinsights.DataSourceType, _ *armoperationalinsights.LinkedStorageAccountsClientGetOptions) (armoperationalinsights.LinkedStorageAccountsClientGetResponse, error) {
				return armoperationalinsights.LinkedStorageAccountsClientGetResponse{LinkedStorageAccountsResource: linkResult}, nil
			}
		}()

		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testLinkedStorageNativeID})
		require.NoError(t, err)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "CustomLogs", props["name"])
	})

	// The type comes off the native ID, lower-cased by ARM, and has to be sent back
	// in the casing the API expects.
	t.Run("Update_reissues_create_or_update", func(t *testing.T) {
		before := writeCalls
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testLinkedStorageNativeID,
			DesiredProperties: linkedStorageDesired([]any{testLinkedStorageAccount1, testLinkedStorageAccount2}),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, writeCalls)
		require.Equal(t, armoperationalinsights.DataSourceTypeCustomLogs, sentType)
		require.Len(t, sent.Properties.StorageAccountIDs, 2)
	})

	t.Run("Delete", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testLinkedStorageNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
		require.Equal(t, armoperationalinsights.DataSourceTypeCustomLogs, sentType)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _ string, _ armoperationalinsights.DataSourceType, _ *armoperationalinsights.LinkedStorageAccountsClientDeleteOptions) (armoperationalinsights.LinkedStorageAccountsClientDeleteResponse, error) {
			return armoperationalinsights.LinkedStorageAccountsClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testLinkedStorageNativeID})
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
		require.Equal(t, []string{testLinkedStorageNativeID}, got.NativeIDs)
	})

	t.Run("List_without_workspace_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})

	t.Run("Read_NotFound", func(t *testing.T) {
		fake.getFn = func(_ context.Context, _, _ string, _ armoperationalinsights.DataSourceType, _ *armoperationalinsights.LinkedStorageAccountsClientGetOptions) (armoperationalinsights.LinkedStorageAccountsClientGetResponse, error) {
			return armoperationalinsights.LinkedStorageAccountsClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testLinkedStorageNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
	})
}
