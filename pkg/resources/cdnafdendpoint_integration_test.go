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

const testCdnEndpointNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Cdn/profiles/afd-1/afdEndpoints/ep-1"

func fullCdnEndpointProps() map[string]any {
	return map[string]any{
		"resourceGroupName": "rg-1",
		"profileName":       "afd-1",
		"name":              "ep-1",
		"location":          "global",
		"enabledState":      "Enabled",
	}
}

func createCdnEndpointProps() json.RawMessage {
	props, _ := json.Marshal(fullCdnEndpointProps())
	return props
}

func TestCdnAFDEndpoint_CRUD(t *testing.T) {
	var builtProps map[string]any
	require.NoError(t, json.Unmarshal(createCdnEndpointProps(), &builtProps))
	built := buildCdnAFDEndpointParams(builtProps, "global")
	built.ID = to.Ptr(testCdnEndpointNativeID)
	built.Name = to.Ptr("ep-1")
	built.Properties.HostName = to.Ptr("ep-1.z01.azurefd.net")

	doneResult := armcdn.AFDEndpointsClientCreateResponse{AFDEndpoint: built}

	fake := &fakeCdnAFDEndpointsAPI{
		beginCreateFn: func(_ context.Context, _, _, _ string, _ armcdn.AFDEndpoint, _ *armcdn.AFDEndpointsClientBeginCreateOptions) (*runtime.Poller[armcdn.AFDEndpointsClientCreateResponse], error) {
			return newDonePoller(doneResult), nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ *armcdn.AFDEndpointsClientGetOptions) (armcdn.AFDEndpointsClientGetResponse, error) {
			return armcdn.AFDEndpointsClientGetResponse{AFDEndpoint: built}, nil
		},
		beginDeleteFn: func(_ context.Context, _, _, _ string, _ *armcdn.AFDEndpointsClientBeginDeleteOptions) (*runtime.Poller[armcdn.AFDEndpointsClientDeleteResponse], error) {
			return newInProgressPoller[armcdn.AFDEndpointsClientDeleteResponse](), nil
		},
		newListByProfilePagerFn: func(_, _ string, _ *armcdn.AFDEndpointsClientListByProfileOptions) *runtime.Pager[armcdn.AFDEndpointsClientListByProfileResponse] {
			return runtime.NewPager(runtime.PagingHandler[armcdn.AFDEndpointsClientListByProfileResponse]{
				More: func(_ armcdn.AFDEndpointsClientListByProfileResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armcdn.AFDEndpointsClientListByProfileResponse) (armcdn.AFDEndpointsClientListByProfileResponse, error) {
					return armcdn.AFDEndpointsClientListByProfileResponse{
						AFDEndpointListResult: armcdn.AFDEndpointListResult{Value: []*armcdn.AFDEndpoint{{ID: to.Ptr(testCdnEndpointNativeID)}}},
					}, nil
				},
			})
		},
	}
	prov := newTestCdnAFDEndpoint(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: createCdnEndpointProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testCdnEndpointNativeID, got.ProgressResult.NativeID)
		var props map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &props))
		require.Equal(t, "ep-1", props["name"])
		require.Equal(t, "Enabled", props["enabledState"])
		require.Equal(t, "ep-1.z01.azurefd.net", props["hostName"], "hostName must round-trip as read-only output")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testCdnEndpointNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "afd-1", props["profileName"])
	})

	t.Run("Update", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{NativeID: testCdnEndpointNativeID, DesiredProperties: createCdnEndpointProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Delete", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testCdnEndpointNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusInProgress, got.ProgressResult.OperationStatus)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _, _ string, _ *armcdn.AFDEndpointsClientBeginDeleteOptions) (*runtime.Poller[armcdn.AFDEndpointsClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testCdnEndpointNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "profileName": "afd-1"}})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 1)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.beginCreateFn = func(_ context.Context, _, _, _ string, _ armcdn.AFDEndpoint, _ *armcdn.AFDEndpointsClientBeginCreateOptions) (*runtime.Poller[armcdn.AFDEndpointsClientCreateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 403}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: createCdnEndpointProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

// --- Test helpers ---

func newTestCdnAFDEndpoint(api cdnAFDEndpointsAPI) *CdnAFDEndpoint {
	return &CdnAFDEndpoint{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

type fakeCdnAFDEndpointsAPI struct {
	beginCreateFn           func(ctx context.Context, rgName, profileName, endpointName string, endpoint armcdn.AFDEndpoint, opts *armcdn.AFDEndpointsClientBeginCreateOptions) (*runtime.Poller[armcdn.AFDEndpointsClientCreateResponse], error)
	getFn                   func(ctx context.Context, rgName, profileName, endpointName string, opts *armcdn.AFDEndpointsClientGetOptions) (armcdn.AFDEndpointsClientGetResponse, error)
	beginDeleteFn           func(ctx context.Context, rgName, profileName, endpointName string, opts *armcdn.AFDEndpointsClientBeginDeleteOptions) (*runtime.Poller[armcdn.AFDEndpointsClientDeleteResponse], error)
	newListByProfilePagerFn func(rgName, profileName string, opts *armcdn.AFDEndpointsClientListByProfileOptions) *runtime.Pager[armcdn.AFDEndpointsClientListByProfileResponse]
}

func (f *fakeCdnAFDEndpointsAPI) BeginCreate(ctx context.Context, rgName, profileName, endpointName string, endpoint armcdn.AFDEndpoint, opts *armcdn.AFDEndpointsClientBeginCreateOptions) (*runtime.Poller[armcdn.AFDEndpointsClientCreateResponse], error) {
	return f.beginCreateFn(ctx, rgName, profileName, endpointName, endpoint, opts)
}

func (f *fakeCdnAFDEndpointsAPI) Get(ctx context.Context, rgName, profileName, endpointName string, opts *armcdn.AFDEndpointsClientGetOptions) (armcdn.AFDEndpointsClientGetResponse, error) {
	return f.getFn(ctx, rgName, profileName, endpointName, opts)
}

func (f *fakeCdnAFDEndpointsAPI) BeginDelete(ctx context.Context, rgName, profileName, endpointName string, opts *armcdn.AFDEndpointsClientBeginDeleteOptions) (*runtime.Poller[armcdn.AFDEndpointsClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, profileName, endpointName, opts)
}

func (f *fakeCdnAFDEndpointsAPI) NewListByProfilePager(rgName, profileName string, opts *armcdn.AFDEndpointsClientListByProfileOptions) *runtime.Pager[armcdn.AFDEndpointsClientListByProfileResponse] {
	return f.newListByProfilePagerFn(rgName, profileName, opts)
}
