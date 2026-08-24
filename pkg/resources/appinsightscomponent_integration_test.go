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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/applicationinsights/armapplicationinsights"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const (
	testAppInsightsNativeID    = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Insights/components/ai-1"
	testAppInsightsWorkspaceID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.OperationalInsights/workspaces/law-1"
)

func newTestAppInsightsComponent(api appInsightsComponentsAPI) *AppInsightsComponent {
	return &AppInsightsComponent{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func appInsightsDesired(retentionDays int32) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":                "ai-1",
		"location":            "eastus",
		"resourceGroupName":   "rg-1",
		"workspaceResourceId": testAppInsightsWorkspaceID,
		"applicationType":     "web",
		"kind":                "web",
		"retentionInDays":     retentionDays,
	})
	return out
}

func TestAppInsightsComponent_CRUD(t *testing.T) {
	// The service returns the ingestion credentials on every read; the handler must
	// drop them rather than write them into state.
	compResult := armapplicationinsights.Component{
		ID:       to.Ptr(testAppInsightsNativeID),
		Name:     to.Ptr("ai-1"),
		Location: to.Ptr("East US"),
		Kind:     to.Ptr("web"),
		Properties: &armapplicationinsights.ComponentProperties{
			ApplicationType:     to.Ptr(armapplicationinsights.ApplicationTypeWeb),
			IngestionMode:       to.Ptr(armapplicationinsights.IngestionModeLogAnalytics),
			WorkspaceResourceID: to.Ptr(testAppInsightsWorkspaceID),
			RetentionInDays:     to.Ptr(int32(30)),
			AppID:               to.Ptr("11111111-2222-3333-4444-555555555555"),
			InstrumentationKey:  to.Ptr("SUPER-SECRET-IKEY"),
			ConnectionString:    to.Ptr("InstrumentationKey=SUPER-SECRET-IKEY;IngestionEndpoint=https://eastus-0.in.applicationinsights.azure.com/"),
		},
	}

	var sent armapplicationinsights.Component
	fake := &fakeAppInsightsComponentsAPI{
		createOrUpdateFn: func(_ context.Context, _, name string, params armapplicationinsights.Component, _ *armapplicationinsights.ComponentsClientCreateOrUpdateOptions) (armapplicationinsights.ComponentsClientCreateOrUpdateResponse, error) {
			require.Equal(t, "ai-1", name)
			sent = params
			return armapplicationinsights.ComponentsClientCreateOrUpdateResponse{Component: compResult}, nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armapplicationinsights.ComponentsClientGetOptions) (armapplicationinsights.ComponentsClientGetResponse, error) {
			return armapplicationinsights.ComponentsClientGetResponse{Component: compResult}, nil
		},
		deleteFn: func(_ context.Context, _, _ string, _ *armapplicationinsights.ComponentsClientDeleteOptions) (armapplicationinsights.ComponentsClientDeleteResponse, error) {
			return armapplicationinsights.ComponentsClientDeleteResponse{}, nil
		},
		newListPagerFn: func(_ *armapplicationinsights.ComponentsClientListOptions) *runtime.Pager[armapplicationinsights.ComponentsClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armapplicationinsights.ComponentsClientListResponse]{
				More: func(_ armapplicationinsights.ComponentsClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armapplicationinsights.ComponentsClientListResponse) (armapplicationinsights.ComponentsClientListResponse, error) {
					return armapplicationinsights.ComponentsClientListResponse{
						ComponentListResult: armapplicationinsights.ComponentListResult{
							Value: []*armapplicationinsights.Component{
								{ID: to.Ptr(testAppInsightsNativeID)},
								{ID: to.Ptr("/subscriptions/sub-1/resourceGroups/rg-2/providers/Microsoft.Insights/components/ai-2")},
							},
						},
					}, nil
				},
			})
		},
		newListByResourceGroupPagerFn: func(_ string, _ *armapplicationinsights.ComponentsClientListByResourceGroupOptions) *runtime.Pager[armapplicationinsights.ComponentsClientListByResourceGroupResponse] {
			return runtime.NewPager(runtime.PagingHandler[armapplicationinsights.ComponentsClientListByResourceGroupResponse]{
				More: func(_ armapplicationinsights.ComponentsClientListByResourceGroupResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armapplicationinsights.ComponentsClientListByResourceGroupResponse) (armapplicationinsights.ComponentsClientListByResourceGroupResponse, error) {
					return armapplicationinsights.ComponentsClientListByResourceGroupResponse{
						ComponentListResult: armapplicationinsights.ComponentListResult{
							Value: []*armapplicationinsights.Component{{ID: to.Ptr(testAppInsightsNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestAppInsightsComponent(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "ai-1", Properties: appInsightsDesired(30)})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testAppInsightsNativeID, got.ProgressResult.NativeID)

		// Workspace-based ingestion is the default: classic components are retired.
		require.Equal(t, armapplicationinsights.IngestionModeLogAnalytics, *sent.Properties.IngestionMode)
		require.Equal(t, testAppInsightsWorkspaceID, *sent.Properties.WorkspaceResourceID)
		require.Equal(t, armapplicationinsights.ApplicationTypeWeb, *sent.Properties.ApplicationType)
	})

	t.Run("Create_requires_workspaceResourceId", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "ai-1", "location": "eastus", "resourceGroupName": "rg-1",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "workspaceResourceId is required")
	})

	t.Run("Create_requires_location", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "ai-1", "resourceGroupName": "rg-1", "workspaceResourceId": testAppInsightsWorkspaceID,
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.Error(t, err)
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testAppInsightsNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "ai-1", props["name"])
		require.Equal(t, "eastus", props["location"])
		require.Equal(t, "LogAnalytics", props["ingestionMode"])
		require.Equal(t, testAppInsightsWorkspaceID, props["workspaceResourceId"])
		// appId is a query-API identifier, not a credential, so it is surfaced.
		require.Equal(t, "11111111-2222-3333-4444-555555555555", props["appId"])
	})

	// Ingestion credentials must never reach resource state, on any code path.
	t.Run("credentials_never_serialized", func(t *testing.T) {
		read, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testAppInsightsNativeID})
		require.NoError(t, err)
		created, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "ai-1", Properties: appInsightsDesired(30)})
		require.NoError(t, err)
		updated, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID: testAppInsightsNativeID, DesiredProperties: appInsightsDesired(90),
		})
		require.NoError(t, err)

		for _, payload := range []string{
			read.Properties,
			string(created.ProgressResult.ResourceProperties),
			string(updated.ProgressResult.ResourceProperties),
		} {
			require.NotContains(t, payload, "SUPER-SECRET-IKEY")
			require.NotContains(t, payload, "instrumentationKey")
			require.NotContains(t, payload, "connectionString")
		}
	})

	t.Run("Update_keeps_native_id", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testAppInsightsNativeID,
			DesiredProperties: appInsightsDesired(90),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testAppInsightsNativeID, got.ProgressResult.NativeID)
		require.EqualValues(t, 90, *sent.Properties.RetentionInDays)
	})

	t.Run("Delete", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testAppInsightsNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _ string, _ *armapplicationinsights.ComponentsClientDeleteOptions) (armapplicationinsights.ComponentsClientDeleteResponse, error) {
			return armapplicationinsights.ComponentsClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testAppInsightsNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_resource_group", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testAppInsightsNativeID}, got.NativeIDs)
	})

	t.Run("List_without_group_is_subscription_wide", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 2)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.createOrUpdateFn = func(_ context.Context, _, _ string, _ armapplicationinsights.Component, _ *armapplicationinsights.ComponentsClientCreateOrUpdateOptions) (armapplicationinsights.ComponentsClientCreateOrUpdateResponse, error) {
			return armapplicationinsights.ComponentsClientCreateOrUpdateResponse{}, &azcore.ResponseError{StatusCode: 400}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "ai-1", Properties: appInsightsDesired(30)})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

func TestAppInsightsComponent_ReadNotFound(t *testing.T) {
	fake := &fakeAppInsightsComponentsAPI{
		getFn: func(_ context.Context, _, _ string, _ *armapplicationinsights.ComponentsClientGetOptions) (armapplicationinsights.ComponentsClientGetResponse, error) {
			return armapplicationinsights.ComponentsClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestAppInsightsComponent(fake).Read(context.Background(), &resource.ReadRequest{NativeID: testAppInsightsNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeAppInsightsComponentsAPI struct {
	createOrUpdateFn              func(ctx context.Context, rgName, name string, params armapplicationinsights.Component, options *armapplicationinsights.ComponentsClientCreateOrUpdateOptions) (armapplicationinsights.ComponentsClientCreateOrUpdateResponse, error)
	getFn                         func(ctx context.Context, rgName, name string, options *armapplicationinsights.ComponentsClientGetOptions) (armapplicationinsights.ComponentsClientGetResponse, error)
	deleteFn                      func(ctx context.Context, rgName, name string, options *armapplicationinsights.ComponentsClientDeleteOptions) (armapplicationinsights.ComponentsClientDeleteResponse, error)
	newListPagerFn                func(options *armapplicationinsights.ComponentsClientListOptions) *runtime.Pager[armapplicationinsights.ComponentsClientListResponse]
	newListByResourceGroupPagerFn func(rgName string, options *armapplicationinsights.ComponentsClientListByResourceGroupOptions) *runtime.Pager[armapplicationinsights.ComponentsClientListByResourceGroupResponse]
}

func (f *fakeAppInsightsComponentsAPI) CreateOrUpdate(ctx context.Context, rgName, name string, params armapplicationinsights.Component, options *armapplicationinsights.ComponentsClientCreateOrUpdateOptions) (armapplicationinsights.ComponentsClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, name, params, options)
}

func (f *fakeAppInsightsComponentsAPI) Get(ctx context.Context, rgName, name string, options *armapplicationinsights.ComponentsClientGetOptions) (armapplicationinsights.ComponentsClientGetResponse, error) {
	return f.getFn(ctx, rgName, name, options)
}

func (f *fakeAppInsightsComponentsAPI) Delete(ctx context.Context, rgName, name string, options *armapplicationinsights.ComponentsClientDeleteOptions) (armapplicationinsights.ComponentsClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, name, options)
}

func (f *fakeAppInsightsComponentsAPI) NewListPager(options *armapplicationinsights.ComponentsClientListOptions) *runtime.Pager[armapplicationinsights.ComponentsClientListResponse] {
	return f.newListPagerFn(options)
}

func (f *fakeAppInsightsComponentsAPI) NewListByResourceGroupPager(rgName string, options *armapplicationinsights.ComponentsClientListByResourceGroupOptions) *runtime.Pager[armapplicationinsights.ComponentsClientListByResourceGroupResponse] {
	return f.newListByResourceGroupPagerFn(rgName, options)
}
