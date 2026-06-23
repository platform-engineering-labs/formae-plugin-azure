// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build integration

package resources

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/dashboard/armdashboard"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testGrafanaMPENativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Dashboard/grafana/ws-1/managedPrivateEndpoints/mpe-1"

func TestGrafanaManagedPrivateEndpoint_CRUD(t *testing.T) {
	model := func() armdashboard.ManagedPrivateEndpointModel {
		return armdashboard.ManagedPrivateEndpointModel{
			ID:       to.Ptr(testGrafanaMPENativeID),
			Name:     to.Ptr("mpe-1"),
			Location: to.Ptr("eastus"),
			Properties: &armdashboard.ManagedPrivateEndpointModelProperties{
				PrivateLinkResourceID:     to.Ptr("/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Storage/storageAccounts/sa1"),
				PrivateLinkResourceRegion: to.Ptr("eastus"),
				GroupIDs:                  []*string{to.Ptr("blob")},
				RequestMessage:            to.Ptr("please approve"),
			},
		}
	}

	fake := &fakeGrafanaManagedPrivateEndpointsAPI{
		beginCreateFn: func(_ context.Context, _, _, _ string, _ armdashboard.ManagedPrivateEndpointModel, _ *armdashboard.ManagedPrivateEndpointsClientBeginCreateOptions) (*runtime.Poller[armdashboard.ManagedPrivateEndpointsClientCreateResponse], error) {
			return newDonePoller(armdashboard.ManagedPrivateEndpointsClientCreateResponse{ManagedPrivateEndpointModel: model()}), nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ *armdashboard.ManagedPrivateEndpointsClientGetOptions) (armdashboard.ManagedPrivateEndpointsClientGetResponse, error) {
			return armdashboard.ManagedPrivateEndpointsClientGetResponse{ManagedPrivateEndpointModel: model()}, nil
		},
		beginUpdateFn: func(_ context.Context, _, _, _ string, params armdashboard.ManagedPrivateEndpointUpdateParameters, _ *armdashboard.ManagedPrivateEndpointsClientBeginUpdateOptions) (*runtime.Poller[armdashboard.ManagedPrivateEndpointsClientUpdateResponse], error) {
			m := model()
			m.Tags = params.Tags
			return newDonePoller(armdashboard.ManagedPrivateEndpointsClientUpdateResponse{ManagedPrivateEndpointModel: m}), nil
		},
		beginDeleteFn: func(_ context.Context, _, _, _ string, _ *armdashboard.ManagedPrivateEndpointsClientBeginDeleteOptions) (*runtime.Poller[armdashboard.ManagedPrivateEndpointsClientDeleteResponse], error) {
			return newPendingGrafanaMPEDeletePoller(), nil
		},
		newListPagerFn: func(_, _ string, _ *armdashboard.ManagedPrivateEndpointsClientListOptions) *runtime.Pager[armdashboard.ManagedPrivateEndpointsClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armdashboard.ManagedPrivateEndpointsClientListResponse]{
				More: func(_ armdashboard.ManagedPrivateEndpointsClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armdashboard.ManagedPrivateEndpointsClientListResponse) (armdashboard.ManagedPrivateEndpointsClientListResponse, error) {
					return armdashboard.ManagedPrivateEndpointsClientListResponse{
						ManagedPrivateEndpointModelListResponse: armdashboard.ManagedPrivateEndpointModelListResponse{
							Value: []*armdashboard.ManagedPrivateEndpointModel{{ID: to.Ptr(testGrafanaMPENativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestGrafanaManagedPrivateEndpoint(fake)

	createProps := func() json.RawMessage {
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName":     "rg-1",
			"workspaceName":         "ws-1",
			"name":                  "mpe-1",
			"location":              "eastus",
			"privateLinkResourceId": "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Storage/storageAccounts/sa1",
			"groupIds":              []any{"blob"},
			"requestMessage":        "please approve",
		})
		return props
	}

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "mpe-1", Properties: createProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testGrafanaMPENativeID, got.ProgressResult.NativeID)
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testGrafanaMPENativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "mpe-1", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "ws-1", props["workspaceName"])
		require.Equal(t, "eastus", props["location"])
	})

	t.Run("Update_keeps_native_id", func(t *testing.T) {
		desired, _ := json.Marshal(map[string]any{
			"Tags": []map[string]string{{"Key": "Environment", "Value": "updated"}},
		})
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{NativeID: testGrafanaMPENativeID, DesiredProperties: desired})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testGrafanaMPENativeID, got.ProgressResult.NativeID)
	})

	t.Run("Delete", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testGrafanaMPENativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusInProgress, got.ProgressResult.OperationStatus)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _, _ string, _ *armdashboard.ManagedPrivateEndpointsClientBeginDeleteOptions) (*runtime.Poller[armdashboard.ManagedPrivateEndpointsClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testGrafanaMPENativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "workspaceName": "ws-1"},
		})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 1)
		require.Equal(t, testGrafanaMPENativeID, got.NativeIDs[0])
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.beginCreateFn = func(_ context.Context, _, _, _ string, _ armdashboard.ManagedPrivateEndpointModel, _ *armdashboard.ManagedPrivateEndpointsClientBeginCreateOptions) (*runtime.Poller[armdashboard.ManagedPrivateEndpointsClientCreateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 403}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: createProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

// --- Test helpers ---

func newTestGrafanaManagedPrivateEndpoint(api grafanaManagedPrivateEndpointsAPI) *GrafanaManagedPrivateEndpoint {
	return &GrafanaManagedPrivateEndpoint{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

type grafanaMPEPendingHandler[T any] struct{}

func (h *grafanaMPEPendingHandler[T]) Done() bool { return false }
func (h *grafanaMPEPendingHandler[T]) Poll(_ context.Context) (*http.Response, error) {
	return nil, nil
}
func (h *grafanaMPEPendingHandler[T]) Result(_ context.Context, _ *T) error { return nil }

func newPendingGrafanaMPEDeletePoller() *runtime.Poller[armdashboard.ManagedPrivateEndpointsClientDeleteResponse] {
	p, err := runtime.NewPoller[armdashboard.ManagedPrivateEndpointsClientDeleteResponse](nil, runtime.Pipeline{}, &runtime.NewPollerOptions[armdashboard.ManagedPrivateEndpointsClientDeleteResponse]{
		Handler: &grafanaMPEPendingHandler[armdashboard.ManagedPrivateEndpointsClientDeleteResponse]{},
	})
	if err != nil {
		panic(err)
	}
	return p
}

type fakeGrafanaManagedPrivateEndpointsAPI struct {
	beginCreateFn  func(ctx context.Context, rgName, workspaceName, mpeName string, params armdashboard.ManagedPrivateEndpointModel, opts *armdashboard.ManagedPrivateEndpointsClientBeginCreateOptions) (*runtime.Poller[armdashboard.ManagedPrivateEndpointsClientCreateResponse], error)
	getFn          func(ctx context.Context, rgName, workspaceName, mpeName string, opts *armdashboard.ManagedPrivateEndpointsClientGetOptions) (armdashboard.ManagedPrivateEndpointsClientGetResponse, error)
	beginUpdateFn  func(ctx context.Context, rgName, workspaceName, mpeName string, params armdashboard.ManagedPrivateEndpointUpdateParameters, opts *armdashboard.ManagedPrivateEndpointsClientBeginUpdateOptions) (*runtime.Poller[armdashboard.ManagedPrivateEndpointsClientUpdateResponse], error)
	beginDeleteFn  func(ctx context.Context, rgName, workspaceName, mpeName string, opts *armdashboard.ManagedPrivateEndpointsClientBeginDeleteOptions) (*runtime.Poller[armdashboard.ManagedPrivateEndpointsClientDeleteResponse], error)
	newListPagerFn func(rgName, workspaceName string, opts *armdashboard.ManagedPrivateEndpointsClientListOptions) *runtime.Pager[armdashboard.ManagedPrivateEndpointsClientListResponse]
}

func (f *fakeGrafanaManagedPrivateEndpointsAPI) BeginCreate(ctx context.Context, rgName, workspaceName, mpeName string, params armdashboard.ManagedPrivateEndpointModel, opts *armdashboard.ManagedPrivateEndpointsClientBeginCreateOptions) (*runtime.Poller[armdashboard.ManagedPrivateEndpointsClientCreateResponse], error) {
	return f.beginCreateFn(ctx, rgName, workspaceName, mpeName, params, opts)
}

func (f *fakeGrafanaManagedPrivateEndpointsAPI) Get(ctx context.Context, rgName, workspaceName, mpeName string, opts *armdashboard.ManagedPrivateEndpointsClientGetOptions) (armdashboard.ManagedPrivateEndpointsClientGetResponse, error) {
	return f.getFn(ctx, rgName, workspaceName, mpeName, opts)
}

func (f *fakeGrafanaManagedPrivateEndpointsAPI) BeginUpdate(ctx context.Context, rgName, workspaceName, mpeName string, params armdashboard.ManagedPrivateEndpointUpdateParameters, opts *armdashboard.ManagedPrivateEndpointsClientBeginUpdateOptions) (*runtime.Poller[armdashboard.ManagedPrivateEndpointsClientUpdateResponse], error) {
	return f.beginUpdateFn(ctx, rgName, workspaceName, mpeName, params, opts)
}

func (f *fakeGrafanaManagedPrivateEndpointsAPI) BeginDelete(ctx context.Context, rgName, workspaceName, mpeName string, opts *armdashboard.ManagedPrivateEndpointsClientBeginDeleteOptions) (*runtime.Poller[armdashboard.ManagedPrivateEndpointsClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, workspaceName, mpeName, opts)
}

func (f *fakeGrafanaManagedPrivateEndpointsAPI) NewListPager(rgName, workspaceName string, opts *armdashboard.ManagedPrivateEndpointsClientListOptions) *runtime.Pager[armdashboard.ManagedPrivateEndpointsClientListResponse] {
	return f.newListPagerFn(rgName, workspaceName, opts)
}
