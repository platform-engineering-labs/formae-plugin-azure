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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/cdn/armcdn/v2"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testCdnRouteNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Cdn/profiles/afd-1/afdEndpoints/ep-1/routes/route-1"
const testCdnRouteOriginGroupID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Cdn/profiles/afd-1/originGroups/og-1"

func fullCdnRouteProps() map[string]any {
	return map[string]any{
		"resourceGroupName":   "rg-1",
		"profileName":         "afd-1",
		"endpointName":        "ep-1",
		"name":                "route-1",
		"originGroupId":       testCdnRouteOriginGroupID,
		"patternsToMatch":     []any{"/*", "/api/*"},
		"supportedProtocols":  []any{"Http", "Https"},
		"forwardingProtocol":  "MatchRequest",
		"linkToDefaultDomain": "Enabled",
		"httpsRedirect":       "Enabled",
		"enabledState":        "Enabled",
	}
}

func createCdnRouteProps() json.RawMessage {
	props, _ := json.Marshal(fullCdnRouteProps())
	return props
}

// TestCdnRoute_MarshallerRoundTrip verifies the OriginGroup ARM-id reference,
// patternsToMatch and supportedProtocols lists survive build -> serialize.
func TestCdnRoute_MarshallerRoundTrip(t *testing.T) {
	var props map[string]any
	require.NoError(t, json.Unmarshal(createCdnRouteProps(), &props))

	params := buildCdnRouteParams(props)
	params.ID = to.Ptr(testCdnRouteNativeID)
	params.Name = to.Ptr("route-1")

	raw, err := serializeCdnRouteProperties(params, "rg-1", "afd-1", "ep-1", "route-1")
	require.NoError(t, err)

	var got map[string]any
	require.NoError(t, json.Unmarshal(raw, &got))

	require.Equal(t, "route-1", got["name"])
	require.Equal(t, testCdnRouteOriginGroupID, got["originGroupId"], "origin group ref must round-trip as a full ARM id")
	patterns := got["patternsToMatch"].([]any)
	require.ElementsMatch(t, []any{"/*", "/api/*"}, patterns)
	protos := got["supportedProtocols"].([]any)
	require.ElementsMatch(t, []any{"Http", "Https"}, protos)
	require.Equal(t, "MatchRequest", got["forwardingProtocol"])
	require.Equal(t, "Enabled", got["linkToDefaultDomain"])
	require.Equal(t, "Enabled", got["httpsRedirect"])
}

func TestCdnRoute_CRUD(t *testing.T) {
	var builtProps map[string]any
	require.NoError(t, json.Unmarshal(createCdnRouteProps(), &builtProps))
	built := buildCdnRouteParams(builtProps)
	built.ID = to.Ptr(testCdnRouteNativeID)
	built.Name = to.Ptr("route-1")

	doneResult := armcdn.RoutesClientCreateResponse{Route: built}

	fake := &fakeCdnRoutesAPI{
		beginCreateFn: func(_ context.Context, _, _, _, _ string, _ armcdn.Route, _ *armcdn.RoutesClientBeginCreateOptions) (*runtime.Poller[armcdn.RoutesClientCreateResponse], error) {
			return newDonePoller(doneResult), nil
		},
		getFn: func(_ context.Context, _, _, _, _ string, _ *armcdn.RoutesClientGetOptions) (armcdn.RoutesClientGetResponse, error) {
			return armcdn.RoutesClientGetResponse{Route: built}, nil
		},
		beginDeleteFn: func(_ context.Context, _, _, _, _ string, _ *armcdn.RoutesClientBeginDeleteOptions) (*runtime.Poller[armcdn.RoutesClientDeleteResponse], error) {
			return newInProgressPoller[armcdn.RoutesClientDeleteResponse](), nil
		},
		newListByEndpointPagerFn: func(_, _, _ string, _ *armcdn.RoutesClientListByEndpointOptions) *runtime.Pager[armcdn.RoutesClientListByEndpointResponse] {
			return runtime.NewPager(runtime.PagingHandler[armcdn.RoutesClientListByEndpointResponse]{
				More: func(_ armcdn.RoutesClientListByEndpointResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armcdn.RoutesClientListByEndpointResponse) (armcdn.RoutesClientListByEndpointResponse, error) {
					return armcdn.RoutesClientListByEndpointResponse{
						RouteListResult: armcdn.RouteListResult{Value: []*armcdn.Route{{ID: to.Ptr(testCdnRouteNativeID)}}},
					}, nil
				},
			})
		},
	}
	prov := newTestCdnRoute(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: createCdnRouteProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testCdnRouteNativeID, got.ProgressResult.NativeID)
		var props map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &props))
		require.Equal(t, testCdnRouteOriginGroupID, props["originGroupId"])
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testCdnRouteNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "ep-1", props["endpointName"])
	})

	t.Run("Update", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{NativeID: testCdnRouteNativeID, DesiredProperties: createCdnRouteProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Delete", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testCdnRouteNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusInProgress, got.ProgressResult.OperationStatus)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _, _, _ string, _ *armcdn.RoutesClientBeginDeleteOptions) (*runtime.Poller[armcdn.RoutesClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testCdnRouteNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "profileName": "afd-1", "endpointName": "ep-1"}})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 1)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.beginCreateFn = func(_ context.Context, _, _, _, _ string, _ armcdn.Route, _ *armcdn.RoutesClientBeginCreateOptions) (*runtime.Poller[armcdn.RoutesClientCreateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 403}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: createCdnRouteProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

// --- Test helpers ---

func newTestCdnRoute(api cdnRoutesAPI) *CdnRoute {
	return &CdnRoute{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

type fakeCdnRoutesAPI struct {
	beginCreateFn            func(ctx context.Context, rgName, profileName, endpointName, routeName string, route armcdn.Route, opts *armcdn.RoutesClientBeginCreateOptions) (*runtime.Poller[armcdn.RoutesClientCreateResponse], error)
	getFn                    func(ctx context.Context, rgName, profileName, endpointName, routeName string, opts *armcdn.RoutesClientGetOptions) (armcdn.RoutesClientGetResponse, error)
	beginDeleteFn            func(ctx context.Context, rgName, profileName, endpointName, routeName string, opts *armcdn.RoutesClientBeginDeleteOptions) (*runtime.Poller[armcdn.RoutesClientDeleteResponse], error)
	newListByEndpointPagerFn func(rgName, profileName, endpointName string, opts *armcdn.RoutesClientListByEndpointOptions) *runtime.Pager[armcdn.RoutesClientListByEndpointResponse]
}

func (f *fakeCdnRoutesAPI) BeginCreate(ctx context.Context, rgName, profileName, endpointName, routeName string, route armcdn.Route, opts *armcdn.RoutesClientBeginCreateOptions) (*runtime.Poller[armcdn.RoutesClientCreateResponse], error) {
	return f.beginCreateFn(ctx, rgName, profileName, endpointName, routeName, route, opts)
}

func (f *fakeCdnRoutesAPI) Get(ctx context.Context, rgName, profileName, endpointName, routeName string, opts *armcdn.RoutesClientGetOptions) (armcdn.RoutesClientGetResponse, error) {
	return f.getFn(ctx, rgName, profileName, endpointName, routeName, opts)
}

func (f *fakeCdnRoutesAPI) BeginDelete(ctx context.Context, rgName, profileName, endpointName, routeName string, opts *armcdn.RoutesClientBeginDeleteOptions) (*runtime.Poller[armcdn.RoutesClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, profileName, endpointName, routeName, opts)
}

func (f *fakeCdnRoutesAPI) NewListByEndpointPager(rgName, profileName, endpointName string, opts *armcdn.RoutesClientListByEndpointOptions) *runtime.Pager[armcdn.RoutesClientListByEndpointResponse] {
	return f.newListByEndpointPagerFn(rgName, profileName, endpointName, opts)
}
