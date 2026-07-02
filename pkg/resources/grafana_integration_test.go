// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build integration

package resources

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/dashboard/armdashboard"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testGrafanaNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Dashboard/grafana/mygrafana"

func TestGrafana_CRUD(t *testing.T) {
	fake := &fakeGrafanaAPI{
		beginCreateFn: func(_ context.Context, _, workspaceName string, params armdashboard.ManagedGrafana, _ *armdashboard.GrafanaClientBeginCreateOptions) (*runtime.Poller[armdashboard.GrafanaClientCreateResponse], error) {
			return newDonePoller(armdashboard.GrafanaClientCreateResponse{
				ManagedGrafana: armdashboard.ManagedGrafana{
					ID:       to.Ptr(testGrafanaNativeID),
					Name:     to.Ptr(workspaceName),
					Location: params.Location,
					SKU:      params.SKU,
					Properties: &armdashboard.ManagedGrafanaProperties{
						APIKey:   params.Properties.APIKey,
						Endpoint: to.Ptr("https://mygrafana.grafana.azure.com"),
					},
				},
			}), nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armdashboard.GrafanaClientGetOptions) (armdashboard.GrafanaClientGetResponse, error) {
			return armdashboard.GrafanaClientGetResponse{
				ManagedGrafana: armdashboard.ManagedGrafana{
					ID:       to.Ptr(testGrafanaNativeID),
					Name:     to.Ptr("mygrafana"),
					Location: to.Ptr("eastus"),
					SKU:      &armdashboard.ResourceSKU{Name: to.Ptr("Standard")},
					Properties: &armdashboard.ManagedGrafanaProperties{
						APIKey:              to.Ptr(armdashboard.APIKeyDisabled),
						PublicNetworkAccess: to.Ptr(armdashboard.PublicNetworkAccessEnabled),
						Endpoint:            to.Ptr("https://mygrafana.grafana.azure.com"),
					},
				},
			}, nil
		},
		updateFn: func(_ context.Context, _, workspaceName string, params armdashboard.ManagedGrafanaUpdateParameters, _ *armdashboard.GrafanaClientUpdateOptions) (armdashboard.GrafanaClientUpdateResponse, error) {
			return armdashboard.GrafanaClientUpdateResponse{
				ManagedGrafana: armdashboard.ManagedGrafana{
					ID:       to.Ptr(testGrafanaNativeID),
					Name:     to.Ptr(workspaceName),
					Location: to.Ptr("eastus"),
					SKU:      &armdashboard.ResourceSKU{Name: to.Ptr("Standard")},
					Properties: &armdashboard.ManagedGrafanaProperties{
						APIKey: params.Properties.APIKey,
					},
				},
			}, nil
		},
		beginDeleteFn: func(_ context.Context, _, _ string, _ *armdashboard.GrafanaClientBeginDeleteOptions) (*runtime.Poller[armdashboard.GrafanaClientDeleteResponse], error) {
			return newDonePoller(armdashboard.GrafanaClientDeleteResponse{}), nil
		},
		listByResourceGroupFn: func(_ string, _ *armdashboard.GrafanaClientListByResourceGroupOptions) *runtime.Pager[armdashboard.GrafanaClientListByResourceGroupResponse] {
			return runtime.NewPager(runtime.PagingHandler[armdashboard.GrafanaClientListByResourceGroupResponse]{
				More: func(_ armdashboard.GrafanaClientListByResourceGroupResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armdashboard.GrafanaClientListByResourceGroupResponse) (armdashboard.GrafanaClientListByResourceGroupResponse, error) {
					return armdashboard.GrafanaClientListByResourceGroupResponse{
						ManagedGrafanaListResponse: armdashboard.ManagedGrafanaListResponse{
							Value: []*armdashboard.ManagedGrafana{
								{ID: to.Ptr(testGrafanaNativeID)},
								{ID: to.Ptr("/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Dashboard/grafana/other")},
							},
						},
					}, nil
				},
			})
		},
		listFn: func(_ *armdashboard.GrafanaClientListOptions) *runtime.Pager[armdashboard.GrafanaClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armdashboard.GrafanaClientListResponse]{
				More: func(_ armdashboard.GrafanaClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armdashboard.GrafanaClientListResponse) (armdashboard.GrafanaClientListResponse, error) {
					return armdashboard.GrafanaClientListResponse{
						ManagedGrafanaListResponse: armdashboard.ManagedGrafanaListResponse{
							Value: []*armdashboard.ManagedGrafana{{ID: to.Ptr(testGrafanaNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestGrafana(fake)

	t.Run("Create", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName": "rg-1", "name": "mygrafana",
			"location": "eastus", "sku": map[string]any{"name": "Standard"},
			"apiKey": "Disabled",
		})
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "mygrafana", Properties: props})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testGrafanaNativeID, got.ProgressResult.NativeID)
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testGrafanaNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "mygrafana", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "eastus", props["location"])
	})

	t.Run("Update_keeps_native_id", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"sku":    map[string]any{"name": "Standard"},
			"apiKey": "Enabled",
		})
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID: testGrafanaNativeID, DesiredProperties: props,
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testGrafanaNativeID, got.ProgressResult.NativeID)
	})

	t.Run("Delete", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testGrafanaNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _ string, _ *armdashboard.GrafanaClientBeginDeleteOptions) (*runtime.Poller[armdashboard.GrafanaClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testGrafanaNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 2)
		require.Equal(t, testGrafanaNativeID, got.NativeIDs[0])
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.beginCreateFn = func(_ context.Context, _, _ string, _ armdashboard.ManagedGrafana, _ *armdashboard.GrafanaClientBeginCreateOptions) (*runtime.Poller[armdashboard.GrafanaClientCreateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 403}
		}
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName": "rg-1", "name": "mygrafana",
			"location": "eastus", "sku": map[string]any{"name": "Standard"},
		})
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

// --- Test helpers ---

func newTestGrafana(api grafanaAPI) *Grafana {
	return &Grafana{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

type fakeGrafanaAPI struct {
	beginCreateFn         func(ctx context.Context, resourceGroupName string, workspaceName string, requestBodyParameters armdashboard.ManagedGrafana, options *armdashboard.GrafanaClientBeginCreateOptions) (*runtime.Poller[armdashboard.GrafanaClientCreateResponse], error)
	getFn                 func(ctx context.Context, resourceGroupName string, workspaceName string, options *armdashboard.GrafanaClientGetOptions) (armdashboard.GrafanaClientGetResponse, error)
	updateFn              func(ctx context.Context, resourceGroupName string, workspaceName string, requestBodyParameters armdashboard.ManagedGrafanaUpdateParameters, options *armdashboard.GrafanaClientUpdateOptions) (armdashboard.GrafanaClientUpdateResponse, error)
	beginDeleteFn         func(ctx context.Context, resourceGroupName string, workspaceName string, options *armdashboard.GrafanaClientBeginDeleteOptions) (*runtime.Poller[armdashboard.GrafanaClientDeleteResponse], error)
	listByResourceGroupFn func(resourceGroupName string, options *armdashboard.GrafanaClientListByResourceGroupOptions) *runtime.Pager[armdashboard.GrafanaClientListByResourceGroupResponse]
	listFn                func(options *armdashboard.GrafanaClientListOptions) *runtime.Pager[armdashboard.GrafanaClientListResponse]
}

func (f *fakeGrafanaAPI) BeginCreate(ctx context.Context, resourceGroupName string, workspaceName string, requestBodyParameters armdashboard.ManagedGrafana, options *armdashboard.GrafanaClientBeginCreateOptions) (*runtime.Poller[armdashboard.GrafanaClientCreateResponse], error) {
	return f.beginCreateFn(ctx, resourceGroupName, workspaceName, requestBodyParameters, options)
}

func (f *fakeGrafanaAPI) Get(ctx context.Context, resourceGroupName string, workspaceName string, options *armdashboard.GrafanaClientGetOptions) (armdashboard.GrafanaClientGetResponse, error) {
	return f.getFn(ctx, resourceGroupName, workspaceName, options)
}

func (f *fakeGrafanaAPI) Update(ctx context.Context, resourceGroupName string, workspaceName string, requestBodyParameters armdashboard.ManagedGrafanaUpdateParameters, options *armdashboard.GrafanaClientUpdateOptions) (armdashboard.GrafanaClientUpdateResponse, error) {
	return f.updateFn(ctx, resourceGroupName, workspaceName, requestBodyParameters, options)
}

func (f *fakeGrafanaAPI) BeginDelete(ctx context.Context, resourceGroupName string, workspaceName string, options *armdashboard.GrafanaClientBeginDeleteOptions) (*runtime.Poller[armdashboard.GrafanaClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, resourceGroupName, workspaceName, options)
}

func (f *fakeGrafanaAPI) NewListByResourceGroupPager(resourceGroupName string, options *armdashboard.GrafanaClientListByResourceGroupOptions) *runtime.Pager[armdashboard.GrafanaClientListByResourceGroupResponse] {
	return f.listByResourceGroupFn(resourceGroupName, options)
}

func (f *fakeGrafanaAPI) NewListPager(options *armdashboard.GrafanaClientListOptions) *runtime.Pager[armdashboard.GrafanaClientListResponse] {
	return f.listFn(options)
}
