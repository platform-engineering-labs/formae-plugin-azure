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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v4"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testRouteTableNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/routeTables/rt-1"

func routeTableGetResponse() armnetwork.RouteTablesClientGetResponse {
	hop := armnetwork.RouteNextHopTypeVirtualAppliance
	return armnetwork.RouteTablesClientGetResponse{
		RouteTable: armnetwork.RouteTable{
			ID:       to.Ptr(testRouteTableNativeID),
			Name:     to.Ptr("rt-1"),
			Location: to.Ptr("eastus"),
			Properties: &armnetwork.RouteTablePropertiesFormat{
				DisableBgpRoutePropagation: to.Ptr(false),
				Routes: []*armnetwork.Route{
					{
						Name: to.Ptr("to-appliance"),
						Properties: &armnetwork.RoutePropertiesFormat{
							AddressPrefix:    to.Ptr("10.1.0.0/16"),
							NextHopType:      &hop,
							NextHopIPAddress: to.Ptr("10.0.0.4"),
						},
					},
				},
			},
		},
	}
}

func TestRouteTable_CRUD(t *testing.T) {
	fake := &fakeRouteTablesAPI{
		beginCreateOrUpdateFn: func(_ context.Context, _, _ string, _ armnetwork.RouteTable, _ *armnetwork.RouteTablesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.RouteTablesClientCreateOrUpdateResponse], error) {
			hop := armnetwork.RouteNextHopTypeVirtualAppliance
			return newDoneRouteTablePoller(armnetwork.RouteTablesClientCreateOrUpdateResponse{
				RouteTable: armnetwork.RouteTable{
					ID:       to.Ptr(testRouteTableNativeID),
					Name:     to.Ptr("rt-1"),
					Location: to.Ptr("eastus"),
					Properties: &armnetwork.RouteTablePropertiesFormat{
						DisableBgpRoutePropagation: to.Ptr(false),
						Routes: []*armnetwork.Route{
							{
								Name: to.Ptr("to-appliance"),
								Properties: &armnetwork.RoutePropertiesFormat{
									AddressPrefix:    to.Ptr("10.1.0.0/16"),
									NextHopType:      &hop,
									NextHopIPAddress: to.Ptr("10.0.0.4"),
								},
							},
						},
					},
				},
			}), nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armnetwork.RouteTablesClientGetOptions) (armnetwork.RouteTablesClientGetResponse, error) {
			return routeTableGetResponse(), nil
		},
		beginDeleteFn: func(_ context.Context, _, _ string, _ *armnetwork.RouteTablesClientBeginDeleteOptions) (*runtime.Poller[armnetwork.RouteTablesClientDeleteResponse], error) {
			return newPendingDeleteRouteTablePoller(), nil
		},
		newListPagerFn: func(_ string, _ *armnetwork.RouteTablesClientListOptions) *runtime.Pager[armnetwork.RouteTablesClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armnetwork.RouteTablesClientListResponse]{
				More: func(_ armnetwork.RouteTablesClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armnetwork.RouteTablesClientListResponse) (armnetwork.RouteTablesClientListResponse, error) {
					return armnetwork.RouteTablesClientListResponse{
						RouteTableListResult: armnetwork.RouteTableListResult{
							Value: []*armnetwork.RouteTable{{ID: to.Ptr(testRouteTableNativeID)}},
						},
					}, nil
				},
			})
		},
		newListAllPagerFn: func(_ *armnetwork.RouteTablesClientListAllOptions) *runtime.Pager[armnetwork.RouteTablesClientListAllResponse] {
			return runtime.NewPager(runtime.PagingHandler[armnetwork.RouteTablesClientListAllResponse]{
				More: func(_ armnetwork.RouteTablesClientListAllResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armnetwork.RouteTablesClientListAllResponse) (armnetwork.RouteTablesClientListAllResponse, error) {
					return armnetwork.RouteTablesClientListAllResponse{
						RouteTableListResult: armnetwork.RouteTableListResult{
							Value: []*armnetwork.RouteTable{{ID: to.Ptr(testRouteTableNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestRouteTable(fake)

	t.Run("Create", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName": "rg-1", "location": "eastus", "name": "rt-1",
			"routes": []map[string]any{
				{"name": "to-appliance", "addressPrefix": "10.1.0.0/16", "nextHopType": "VirtualAppliance", "nextHopIpAddress": "10.0.0.4"},
			},
		})
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "test-rt", Properties: props})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testRouteTableNativeID, got.ProgressResult.NativeID)
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testRouteTableNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "rt-1", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "eastus", props["location"])

		routes, ok := props["routes"].([]any)
		require.True(t, ok)
		require.Len(t, routes, 1)
	})

	t.Run("Update_keeps_native_id", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName": "rg-1", "location": "eastus", "name": "rt-1",
			"disableBgpRoutePropagation": true,
		})
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID: testRouteTableNativeID, DesiredProperties: props,
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testRouteTableNativeID, got.ProgressResult.NativeID)
	})

	t.Run("Delete", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testRouteTableNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusInProgress, got.ProgressResult.OperationStatus)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _ string, _ *armnetwork.RouteTablesClientBeginDeleteOptions) (*runtime.Poller[armnetwork.RouteTablesClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testRouteTableNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Delete_done_poller_is_success", func(t *testing.T) {
		// A delete Azure completes synchronously yields a terminal poller;
		// ResumeToken errors on those, so the Done() fast path must return Success.
		fake.beginDeleteFn = func(_ context.Context, _, _ string, _ *armnetwork.RouteTablesClientBeginDeleteOptions) (*runtime.Poller[armnetwork.RouteTablesClientDeleteResponse], error) {
			return newDonePoller(armnetwork.RouteTablesClientDeleteResponse{}), nil
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testRouteTableNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 1)
		require.Equal(t, testRouteTableNativeID, got.NativeIDs[0])
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, _ armnetwork.RouteTable, _ *armnetwork.RouteTablesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.RouteTablesClientCreateOrUpdateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 403}
		}
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName": "rg-1", "location": "eastus", "name": "rt-1",
		})
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.Equal(t, resource.OperationErrorCodeAccessDenied, got.ProgressResult.ErrorCode)
	})
}

// --- Test helpers ---

func newTestRouteTable(api routeTablesAPI) *RouteTable {
	return &RouteTable{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

// routeTableDoneHandler reports Done() immediately and populates out on Result().
type routeTableDoneHandler[T any] struct {
	resp T
}

func (h *routeTableDoneHandler[T]) Done() bool                                     { return true }
func (h *routeTableDoneHandler[T]) Poll(_ context.Context) (*http.Response, error) { return nil, nil }
func (h *routeTableDoneHandler[T]) Result(_ context.Context, out *T) error         { *out = h.resp; return nil }

func newDoneRouteTablePoller(resp armnetwork.RouteTablesClientCreateOrUpdateResponse) *runtime.Poller[armnetwork.RouteTablesClientCreateOrUpdateResponse] {
	p, err := runtime.NewPoller[armnetwork.RouteTablesClientCreateOrUpdateResponse](nil, runtime.Pipeline{}, &runtime.NewPollerOptions[armnetwork.RouteTablesClientCreateOrUpdateResponse]{
		Handler: &routeTableDoneHandler[armnetwork.RouteTablesClientCreateOrUpdateResponse]{resp: resp},
	})
	if err != nil {
		panic(err)
	}
	return p
}

// routeTablePendingHandler reports Done() as false so ResumeToken() works.
type routeTablePendingHandler[T any] struct{}

func (h *routeTablePendingHandler[T]) Done() bool { return false }
func (h *routeTablePendingHandler[T]) Poll(_ context.Context) (*http.Response, error) {
	return nil, nil
}
func (h *routeTablePendingHandler[T]) Result(_ context.Context, _ *T) error { return nil }

func newPendingDeleteRouteTablePoller() *runtime.Poller[armnetwork.RouteTablesClientDeleteResponse] {
	p, err := runtime.NewPoller[armnetwork.RouteTablesClientDeleteResponse](nil, runtime.Pipeline{}, &runtime.NewPollerOptions[armnetwork.RouteTablesClientDeleteResponse]{
		Handler: &routeTablePendingHandler[armnetwork.RouteTablesClientDeleteResponse]{},
	})
	if err != nil {
		panic(err)
	}
	return p
}

type fakeRouteTablesAPI struct {
	beginCreateOrUpdateFn func(ctx context.Context, rgName, routeTableName string, params armnetwork.RouteTable, opts *armnetwork.RouteTablesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.RouteTablesClientCreateOrUpdateResponse], error)
	getFn                 func(ctx context.Context, rgName, routeTableName string, opts *armnetwork.RouteTablesClientGetOptions) (armnetwork.RouteTablesClientGetResponse, error)
	beginDeleteFn         func(ctx context.Context, rgName, routeTableName string, opts *armnetwork.RouteTablesClientBeginDeleteOptions) (*runtime.Poller[armnetwork.RouteTablesClientDeleteResponse], error)
	newListPagerFn        func(rgName string, opts *armnetwork.RouteTablesClientListOptions) *runtime.Pager[armnetwork.RouteTablesClientListResponse]
	newListAllPagerFn     func(opts *armnetwork.RouteTablesClientListAllOptions) *runtime.Pager[armnetwork.RouteTablesClientListAllResponse]
}

func (f *fakeRouteTablesAPI) BeginCreateOrUpdate(ctx context.Context, rgName, routeTableName string, params armnetwork.RouteTable, opts *armnetwork.RouteTablesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.RouteTablesClientCreateOrUpdateResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, rgName, routeTableName, params, opts)
}

func (f *fakeRouteTablesAPI) Get(ctx context.Context, rgName, routeTableName string, opts *armnetwork.RouteTablesClientGetOptions) (armnetwork.RouteTablesClientGetResponse, error) {
	return f.getFn(ctx, rgName, routeTableName, opts)
}

func (f *fakeRouteTablesAPI) BeginDelete(ctx context.Context, rgName, routeTableName string, opts *armnetwork.RouteTablesClientBeginDeleteOptions) (*runtime.Poller[armnetwork.RouteTablesClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, routeTableName, opts)
}

func (f *fakeRouteTablesAPI) NewListPager(rgName string, opts *armnetwork.RouteTablesClientListOptions) *runtime.Pager[armnetwork.RouteTablesClientListResponse] {
	return f.newListPagerFn(rgName, opts)
}

func (f *fakeRouteTablesAPI) NewListAllPager(opts *armnetwork.RouteTablesClientListAllOptions) *runtime.Pager[armnetwork.RouteTablesClientListAllResponse] {
	return f.newListAllPagerFn(opts)
}
