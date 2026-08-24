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

const testLogAnalyticsWorkspaceNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.OperationalInsights/workspaces/law-1"

func newTestLogAnalyticsWorkspace(api logAnalyticsWorkspacesAPI) *LogAnalyticsWorkspace {
	return &LogAnalyticsWorkspace{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func lawDesired(retentionDays int, quotaGb float64) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":                            "law-1",
		"location":                        "eastus",
		"resourceGroupName":               "rg-1",
		"sku":                             map[string]any{"name": "PerGB2018"},
		"retentionInDays":                 retentionDays,
		"dailyQuotaGb":                    quotaGb,
		"publicNetworkAccessForIngestion": "Enabled",
		"publicNetworkAccessForQuery":     "Enabled",
	})
	return out
}

func TestLogAnalyticsWorkspace_CRUD(t *testing.T) {
	wsResult := armoperationalinsights.Workspace{
		ID:       to.Ptr(testLogAnalyticsWorkspaceNativeID),
		Name:     to.Ptr("law-1"),
		Location: to.Ptr("East US"),
		Properties: &armoperationalinsights.WorkspaceProperties{
			SKU:                             &armoperationalinsights.WorkspaceSKU{Name: to.Ptr(armoperationalinsights.WorkspaceSKUNameEnumPerGB2018)},
			RetentionInDays:                 to.Ptr(int32(30)),
			WorkspaceCapping:                &armoperationalinsights.WorkspaceCapping{DailyQuotaGb: to.Ptr(float64(1))},
			PublicNetworkAccessForIngestion: to.Ptr(armoperationalinsights.PublicNetworkAccessTypeEnabled),
			PublicNetworkAccessForQuery:     to.Ptr(armoperationalinsights.PublicNetworkAccessTypeEnabled),
			CustomerID:                      to.Ptr("11111111-2222-3333-4444-555555555555"),
		},
	}

	var sentCreate armoperationalinsights.Workspace
	var sentPatch armoperationalinsights.WorkspacePatch
	var deleteOpts *armoperationalinsights.WorkspacesClientBeginDeleteOptions
	fake := &fakeLogAnalyticsWorkspacesAPI{
		beginCreateOrUpdateFn: func(_ context.Context, _, _ string, params armoperationalinsights.Workspace, _ *armoperationalinsights.WorkspacesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armoperationalinsights.WorkspacesClientCreateOrUpdateResponse], error) {
			sentCreate = params
			return newDonePoller(armoperationalinsights.WorkspacesClientCreateOrUpdateResponse{Workspace: wsResult}), nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armoperationalinsights.WorkspacesClientGetOptions) (armoperationalinsights.WorkspacesClientGetResponse, error) {
			return armoperationalinsights.WorkspacesClientGetResponse{Workspace: wsResult}, nil
		},
		updateFn: func(_ context.Context, _, _ string, params armoperationalinsights.WorkspacePatch, _ *armoperationalinsights.WorkspacesClientUpdateOptions) (armoperationalinsights.WorkspacesClientUpdateResponse, error) {
			sentPatch = params
			return armoperationalinsights.WorkspacesClientUpdateResponse{Workspace: wsResult}, nil
		},
		beginDeleteFn: func(_ context.Context, _, _ string, options *armoperationalinsights.WorkspacesClientBeginDeleteOptions) (*runtime.Poller[armoperationalinsights.WorkspacesClientDeleteResponse], error) {
			deleteOpts = options
			return newDonePoller(armoperationalinsights.WorkspacesClientDeleteResponse{}), nil
		},
		newListPagerFn: func(_ *armoperationalinsights.WorkspacesClientListOptions) *runtime.Pager[armoperationalinsights.WorkspacesClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armoperationalinsights.WorkspacesClientListResponse]{
				More: func(_ armoperationalinsights.WorkspacesClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armoperationalinsights.WorkspacesClientListResponse) (armoperationalinsights.WorkspacesClientListResponse, error) {
					return armoperationalinsights.WorkspacesClientListResponse{
						WorkspaceListResult: armoperationalinsights.WorkspaceListResult{
							Value: []*armoperationalinsights.Workspace{
								{ID: to.Ptr(testLogAnalyticsWorkspaceNativeID)},
								{ID: to.Ptr("/subscriptions/sub-1/resourceGroups/rg-2/providers/Microsoft.OperationalInsights/workspaces/law-2")},
							},
						},
					}, nil
				},
			})
		},
		newListByResourceGroupPagerFn: func(_ string, _ *armoperationalinsights.WorkspacesClientListByResourceGroupOptions) *runtime.Pager[armoperationalinsights.WorkspacesClientListByResourceGroupResponse] {
			return runtime.NewPager(runtime.PagingHandler[armoperationalinsights.WorkspacesClientListByResourceGroupResponse]{
				More: func(_ armoperationalinsights.WorkspacesClientListByResourceGroupResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armoperationalinsights.WorkspacesClientListByResourceGroupResponse) (armoperationalinsights.WorkspacesClientListByResourceGroupResponse, error) {
					return armoperationalinsights.WorkspacesClientListByResourceGroupResponse{
						WorkspaceListResult: armoperationalinsights.WorkspaceListResult{
							Value: []*armoperationalinsights.Workspace{
								{ID: to.Ptr(testLogAnalyticsWorkspaceNativeID)},
							},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestLogAnalyticsWorkspace(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "law-1", Properties: lawDesired(30, 1)})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testLogAnalyticsWorkspaceNativeID, got.ProgressResult.NativeID)

		require.Equal(t, armoperationalinsights.WorkspaceSKUNameEnumPerGB2018, *sentCreate.Properties.SKU.Name)
		require.EqualValues(t, 30, *sentCreate.Properties.RetentionInDays)
		require.EqualValues(t, 1, *sentCreate.Properties.WorkspaceCapping.DailyQuotaGb)

		var props map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &props))
		require.Equal(t, "eastus", props["location"])
		require.Equal(t, "11111111-2222-3333-4444-555555555555", props["customerId"])
		// Shared keys come from a separate SharedKeys call and must never reach state.
		require.NotContains(t, props, "primarySharedKey")
		require.NotContains(t, props, "secondarySharedKey")
	})

	t.Run("Create_requires_location", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "law-1", "resourceGroupName": "rg-1"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.Error(t, err)
	})

	t.Run("Create_requires_resourceGroupName", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "law-1", "location": "eastus"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.Error(t, err)
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testLogAnalyticsWorkspaceNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "law-1", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "eastus", props["location"])
		require.EqualValues(t, 30, props["retentionInDays"])
		require.EqualValues(t, 1, props["dailyQuotaGb"])
		require.Equal(t, "Enabled", props["publicNetworkAccessForIngestion"])
		sku := props["sku"].(map[string]any)
		require.Equal(t, "PerGB2018", sku["name"])
	})

	// Update is a synchronous PATCH, so it must return Success directly rather than
	// InProgress with a resume token.
	t.Run("Update_is_synchronous", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testLogAnalyticsWorkspaceNativeID,
			DesiredProperties: lawDesired(90, 5),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testLogAnalyticsWorkspaceNativeID, got.ProgressResult.NativeID)
		require.Empty(t, got.ProgressResult.RequestID)
		require.EqualValues(t, 90, *sentPatch.Properties.RetentionInDays)
		require.EqualValues(t, 5, *sentPatch.Properties.WorkspaceCapping.DailyQuotaGb)
	})

	// Force would make the delete unrecoverable; the handler must never set it.
	t.Run("Delete_does_not_force", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testLogAnalyticsWorkspaceNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Nil(t, deleteOpts)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _ string, _ *armoperationalinsights.WorkspacesClientBeginDeleteOptions) (*runtime.Poller[armoperationalinsights.WorkspacesClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testLogAnalyticsWorkspaceNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_resource_group", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testLogAnalyticsWorkspaceNativeID}, got.NativeIDs)
	})

	t.Run("List_without_group_is_subscription_wide", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 2)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, _ armoperationalinsights.Workspace, _ *armoperationalinsights.WorkspacesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armoperationalinsights.WorkspacesClientCreateOrUpdateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 409}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "law-1", Properties: lawDesired(30, 1)})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

func TestLogAnalyticsWorkspace_ReadNotFound(t *testing.T) {
	fake := &fakeLogAnalyticsWorkspacesAPI{
		getFn: func(_ context.Context, _, _ string, _ *armoperationalinsights.WorkspacesClientGetOptions) (armoperationalinsights.WorkspacesClientGetResponse, error) {
			return armoperationalinsights.WorkspacesClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestLogAnalyticsWorkspace(fake).Read(context.Background(), &resource.ReadRequest{NativeID: testLogAnalyticsWorkspaceNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeLogAnalyticsWorkspacesAPI struct {
	beginCreateOrUpdateFn         func(ctx context.Context, rgName, wsName string, parameters armoperationalinsights.Workspace, options *armoperationalinsights.WorkspacesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armoperationalinsights.WorkspacesClientCreateOrUpdateResponse], error)
	getFn                         func(ctx context.Context, rgName, wsName string, options *armoperationalinsights.WorkspacesClientGetOptions) (armoperationalinsights.WorkspacesClientGetResponse, error)
	updateFn                      func(ctx context.Context, rgName, wsName string, parameters armoperationalinsights.WorkspacePatch, options *armoperationalinsights.WorkspacesClientUpdateOptions) (armoperationalinsights.WorkspacesClientUpdateResponse, error)
	beginDeleteFn                 func(ctx context.Context, rgName, wsName string, options *armoperationalinsights.WorkspacesClientBeginDeleteOptions) (*runtime.Poller[armoperationalinsights.WorkspacesClientDeleteResponse], error)
	newListPagerFn                func(options *armoperationalinsights.WorkspacesClientListOptions) *runtime.Pager[armoperationalinsights.WorkspacesClientListResponse]
	newListByResourceGroupPagerFn func(rgName string, options *armoperationalinsights.WorkspacesClientListByResourceGroupOptions) *runtime.Pager[armoperationalinsights.WorkspacesClientListByResourceGroupResponse]
}

func (f *fakeLogAnalyticsWorkspacesAPI) BeginCreateOrUpdate(ctx context.Context, rgName, wsName string, parameters armoperationalinsights.Workspace, options *armoperationalinsights.WorkspacesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armoperationalinsights.WorkspacesClientCreateOrUpdateResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, rgName, wsName, parameters, options)
}

func (f *fakeLogAnalyticsWorkspacesAPI) Get(ctx context.Context, rgName, wsName string, options *armoperationalinsights.WorkspacesClientGetOptions) (armoperationalinsights.WorkspacesClientGetResponse, error) {
	return f.getFn(ctx, rgName, wsName, options)
}

func (f *fakeLogAnalyticsWorkspacesAPI) Update(ctx context.Context, rgName, wsName string, parameters armoperationalinsights.WorkspacePatch, options *armoperationalinsights.WorkspacesClientUpdateOptions) (armoperationalinsights.WorkspacesClientUpdateResponse, error) {
	return f.updateFn(ctx, rgName, wsName, parameters, options)
}

func (f *fakeLogAnalyticsWorkspacesAPI) BeginDelete(ctx context.Context, rgName, wsName string, options *armoperationalinsights.WorkspacesClientBeginDeleteOptions) (*runtime.Poller[armoperationalinsights.WorkspacesClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, wsName, options)
}

func (f *fakeLogAnalyticsWorkspacesAPI) NewListPager(options *armoperationalinsights.WorkspacesClientListOptions) *runtime.Pager[armoperationalinsights.WorkspacesClientListResponse] {
	return f.newListPagerFn(options)
}

func (f *fakeLogAnalyticsWorkspacesAPI) NewListByResourceGroupPager(rgName string, options *armoperationalinsights.WorkspacesClientListByResourceGroupOptions) *runtime.Pager[armoperationalinsights.WorkspacesClientListByResourceGroupResponse] {
	return f.newListByResourceGroupPagerFn(rgName, options)
}
