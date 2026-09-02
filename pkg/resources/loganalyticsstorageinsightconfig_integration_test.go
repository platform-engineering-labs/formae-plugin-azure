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
	testStorageInsightNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.OperationalInsights/workspaces/ws1/storageInsightConfigs/si-1"
	testStorageInsightAccount  = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Storage/storageAccounts/sa1"
)

type fakeStorageInsightConfigsAPI struct {
	createOrUpdateFn func(ctx context.Context, rgName, workspaceName, insightName string, params armoperationalinsights.StorageInsight, options *armoperationalinsights.StorageInsightConfigsClientCreateOrUpdateOptions) (armoperationalinsights.StorageInsightConfigsClientCreateOrUpdateResponse, error)
	getFn            func(ctx context.Context, rgName, workspaceName, insightName string, options *armoperationalinsights.StorageInsightConfigsClientGetOptions) (armoperationalinsights.StorageInsightConfigsClientGetResponse, error)
	deleteFn         func(ctx context.Context, rgName, workspaceName, insightName string, options *armoperationalinsights.StorageInsightConfigsClientDeleteOptions) (armoperationalinsights.StorageInsightConfigsClientDeleteResponse, error)
	listPagerFn      func(rgName, workspaceName string, options *armoperationalinsights.StorageInsightConfigsClientListByWorkspaceOptions) *runtime.Pager[armoperationalinsights.StorageInsightConfigsClientListByWorkspaceResponse]
}

func (f *fakeStorageInsightConfigsAPI) CreateOrUpdate(ctx context.Context, rgName, workspaceName, insightName string, params armoperationalinsights.StorageInsight, options *armoperationalinsights.StorageInsightConfigsClientCreateOrUpdateOptions) (armoperationalinsights.StorageInsightConfigsClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, workspaceName, insightName, params, options)
}

func (f *fakeStorageInsightConfigsAPI) Get(ctx context.Context, rgName, workspaceName, insightName string, options *armoperationalinsights.StorageInsightConfigsClientGetOptions) (armoperationalinsights.StorageInsightConfigsClientGetResponse, error) {
	return f.getFn(ctx, rgName, workspaceName, insightName, options)
}

func (f *fakeStorageInsightConfigsAPI) Delete(ctx context.Context, rgName, workspaceName, insightName string, options *armoperationalinsights.StorageInsightConfigsClientDeleteOptions) (armoperationalinsights.StorageInsightConfigsClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, workspaceName, insightName, options)
}

func (f *fakeStorageInsightConfigsAPI) NewListByWorkspacePager(rgName, workspaceName string, options *armoperationalinsights.StorageInsightConfigsClientListByWorkspaceOptions) *runtime.Pager[armoperationalinsights.StorageInsightConfigsClientListByWorkspaceResponse] {
	return f.listPagerFn(rgName, workspaceName, options)
}

func newTestStorageInsightConfig(api logAnalyticsStorageInsightConfigsAPI) *LogAnalyticsStorageInsightConfig {
	return &LogAnalyticsStorageInsightConfig{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func storageInsightDesired(containers, tables []any) []byte {
	props := map[string]any{
		"name":              "si-1",
		"resourceGroupName": "rg-1",
		"workspaceName":     "ws1",
		"storageAccountId":  testStorageInsightAccount,
		"storageAccountKey": "c3VwZXItc2VjcmV0LWtleQ==",
	}
	if containers != nil {
		props["containers"] = containers
	}
	if tables != nil {
		props["tables"] = tables
	}
	out, _ := json.Marshal(props)
	return out
}

func TestLogAnalyticsStorageInsightConfig_CRUD(t *testing.T) {
	insightResult := armoperationalinsights.StorageInsight{
		ID:   to.Ptr(testStorageInsightNativeID),
		Name: to.Ptr("si-1"),
		// Service state.
		ETag: to.Ptr(`W/"datetime'2026-08-21T12:00:00Z'"`),
		Properties: &armoperationalinsights.StorageInsightProperties{
			StorageAccount: &armoperationalinsights.StorageAccount{
				ID: to.Ptr(testStorageInsightAccount),
				// ARM never returns the real key; when it echoes anything at all
				// it is a mask, which must not reach state either.
				Key: to.Ptr("*"),
			},
			Containers: []*string{to.Ptr("wad-iis-logfiles")},
			// The service's own verdict on the connection, not configuration.
			Status: &armoperationalinsights.StorageInsightStatus{
				State: to.Ptr(armoperationalinsights.StorageInsightStateOK),
			},
		},
	}

	var sent armoperationalinsights.StorageInsight
	writeCalls := 0
	deleteCalls := 0
	fake := &fakeStorageInsightConfigsAPI{
		createOrUpdateFn: func(_ context.Context, rgName, workspaceName, insightName string, params armoperationalinsights.StorageInsight, _ *armoperationalinsights.StorageInsightConfigsClientCreateOrUpdateOptions) (armoperationalinsights.StorageInsightConfigsClientCreateOrUpdateResponse, error) {
			require.Equal(t, "rg-1", rgName)
			require.Equal(t, "ws1", workspaceName)
			require.Equal(t, "si-1", insightName)
			sent = params
			writeCalls++
			return armoperationalinsights.StorageInsightConfigsClientCreateOrUpdateResponse{StorageInsight: insightResult}, nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ *armoperationalinsights.StorageInsightConfigsClientGetOptions) (armoperationalinsights.StorageInsightConfigsClientGetResponse, error) {
			return armoperationalinsights.StorageInsightConfigsClientGetResponse{StorageInsight: insightResult}, nil
		},
		deleteFn: func(_ context.Context, _, _, _ string, _ *armoperationalinsights.StorageInsightConfigsClientDeleteOptions) (armoperationalinsights.StorageInsightConfigsClientDeleteResponse, error) {
			deleteCalls++
			return armoperationalinsights.StorageInsightConfigsClientDeleteResponse{}, nil
		},
		listPagerFn: func(_, _ string, _ *armoperationalinsights.StorageInsightConfigsClientListByWorkspaceOptions) *runtime.Pager[armoperationalinsights.StorageInsightConfigsClientListByWorkspaceResponse] {
			return runtime.NewPager(runtime.PagingHandler[armoperationalinsights.StorageInsightConfigsClientListByWorkspaceResponse]{
				More: func(_ armoperationalinsights.StorageInsightConfigsClientListByWorkspaceResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armoperationalinsights.StorageInsightConfigsClientListByWorkspaceResponse) (armoperationalinsights.StorageInsightConfigsClientListByWorkspaceResponse, error) {
					return armoperationalinsights.StorageInsightConfigsClientListByWorkspaceResponse{
						StorageInsightListResult: armoperationalinsights.StorageInsightListResult{
							Value: []*armoperationalinsights.StorageInsight{
								{ID: to.Ptr(testStorageInsightNativeID)},
								// A nil entry must not panic the walk.
								nil,
							},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestStorageInsightConfig(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "si-1", Properties: storageInsightDesired([]any{"wad-iis-logfiles"}, nil),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testStorageInsightNativeID, got.ProgressResult.NativeID)

		require.Equal(t, testStorageInsightAccount, *sent.Properties.StorageAccount.ID)
		require.Equal(t, "c3VwZXItc2VjcmV0LWtleQ==", *sent.Properties.StorageAccount.Key)
		require.Len(t, sent.Properties.Containers, 1)
		// Nothing was declared, so nothing is sent: an empty list would read back
		// as an empty list and drift against a config that never set it.
		require.Nil(t, sent.Properties.Tables)
	})

	t.Run("Create_requires_storage_account_id", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "si-1", "resourceGroupName": "rg-1", "workspaceName": "ws1",
			"storageAccountKey": "c3VwZXItc2VjcmV0LWtleQ==",
			"containers":        []any{"wad-iis-logfiles"},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "storageAccountId is required")
	})

	// ARM rejects a body without the key, so the handler refuses before the call.
	t.Run("Create_requires_storage_account_key", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "si-1", "resourceGroupName": "rg-1", "workspaceName": "ws1",
			"storageAccountId": testStorageInsightAccount,
			"containers":       []any{"wad-iis-logfiles"},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "storageAccountKey is required")
	})

	// A config that names neither containers nor tables reads nothing at all.
	t.Run("Create_requires_containers_or_tables", func(t *testing.T) {
		_, err := prov.Create(context.Background(), &resource.CreateRequest{
			Properties: storageInsightDesired(nil, nil),
		})
		require.ErrorContains(t, err, "at least one of containers or tables is required")
	})

	t.Run("Create_accepts_tables_alone", func(t *testing.T) {
		_, err := prov.Create(context.Background(), &resource.CreateRequest{
			Properties: storageInsightDesired(nil, []any{"WADWindowsEventLogsTable"}),
		})
		require.NoError(t, err)
		require.Len(t, sent.Properties.Tables, 1)
		require.Nil(t, sent.Properties.Containers)
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testStorageInsightNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
		require.Equal(t, ResourceTypeLogAnalyticsStorageInsightConfig, got.ResourceType)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "si-1", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "ws1", props["workspaceName"])
		require.Equal(t, testStorageInsightAccount, props["storageAccountId"])
		require.Equal(t, []any{"wad-iis-logfiles"}, props["containers"])
		// Not declared, so absent rather than [].
		require.NotContains(t, props, "tables")
	})

	// The key is write-only: whatever ARM echoes must never reach resource state.
	t.Run("Read_never_surfaces_the_account_key", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testStorageInsightNativeID})
		require.NoError(t, err)
		require.NotContains(t, got.Properties, "storageAccountKey")
		for _, key := range []string{"eTag", "etag", "status", "OK"} {
			require.NotContains(t, got.Properties, key)
		}
	})

	// CreateOrUpdate is the only write verb this API has, and the key rides along
	// on every update because ARM rejects a body without it.
	t.Run("Update_reissues_create_or_update_with_the_key", func(t *testing.T) {
		before := writeCalls
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testStorageInsightNativeID,
			DesiredProperties: storageInsightDesired([]any{"wad-iis-logfiles"}, []any{"WADWindowsEventLogsTable"}),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, writeCalls)
		require.Equal(t, "c3VwZXItc2VjcmV0LWtleQ==", *sent.Properties.StorageAccount.Key)
		require.Len(t, sent.Properties.Tables, 1)
	})

	t.Run("Delete", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testStorageInsightNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _, _ string, _ *armoperationalinsights.StorageInsightConfigsClientDeleteOptions) (armoperationalinsights.StorageInsightConfigsClientDeleteResponse, error) {
			return armoperationalinsights.StorageInsightConfigsClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testStorageInsightNativeID})
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
		require.Equal(t, []string{testStorageInsightNativeID}, got.NativeIDs)
	})

	t.Run("List_without_workspace_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})

	t.Run("Read_NotFound", func(t *testing.T) {
		fake.getFn = func(_ context.Context, _, _, _ string, _ *armoperationalinsights.StorageInsightConfigsClientGetOptions) (armoperationalinsights.StorageInsightConfigsClientGetResponse, error) {
			return armoperationalinsights.StorageInsightConfigsClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testStorageInsightNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
	})

	t.Run("Create_failure_reports_the_provider_error", func(t *testing.T) {
		fake.createOrUpdateFn = func(_ context.Context, _, _, _ string, _ armoperationalinsights.StorageInsight, _ *armoperationalinsights.StorageInsightConfigsClientCreateOrUpdateOptions) (armoperationalinsights.StorageInsightConfigsClientCreateOrUpdateResponse, error) {
			return armoperationalinsights.StorageInsightConfigsClientCreateOrUpdateResponse{}, &azcore.ResponseError{StatusCode: 400}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "si-1", Properties: storageInsightDesired([]any{"wad-iis-logfiles"}, nil),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.Equal(t, resource.OperationErrorCodeInvalidRequest, got.ProgressResult.ErrorCode)
		require.NotEmpty(t, got.ProgressResult.StatusMessage)
	})
}
