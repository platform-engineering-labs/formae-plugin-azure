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

const testCdnOriginNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Cdn/profiles/afd-1/originGroups/og-1/origins/orig-1"

func fullCdnOriginProps() map[string]any {
	return map[string]any{
		"resourceGroupName": "rg-1",
		"profileName":       "afd-1",
		"originGroupName":   "og-1",
		"name":              "orig-1",
		"hostName":          "backend.example.com",
		"httpPort":          80,
		"httpsPort":         443,
		"originHostHeader":  "backend.example.com",
		"priority":          1,
		"weight":            500,
		"enabledState":      "Enabled",
	}
}

func createCdnOriginProps() json.RawMessage {
	props, _ := json.Marshal(fullCdnOriginProps())
	return props
}

// TestCdnAFDOrigin_MarshallerRoundTrip verifies origin scalar fields survive
// build -> serialize with no drift.
func TestCdnAFDOrigin_MarshallerRoundTrip(t *testing.T) {
	var props map[string]any
	require.NoError(t, json.Unmarshal(createCdnOriginProps(), &props))

	params := buildCdnAFDOriginParams(props)
	params.ID = to.Ptr(testCdnOriginNativeID)
	params.Name = to.Ptr("orig-1")

	raw, err := serializeCdnAFDOriginProperties(params, "rg-1", "afd-1", "og-1", "orig-1")
	require.NoError(t, err)

	var got map[string]any
	require.NoError(t, json.Unmarshal(raw, &got))

	require.Equal(t, "orig-1", got["name"])
	require.Equal(t, "og-1", got["originGroupName"])
	require.Equal(t, "backend.example.com", got["hostName"])
	require.EqualValues(t, 80, got["httpPort"])
	require.EqualValues(t, 443, got["httpsPort"])
	require.Equal(t, "backend.example.com", got["originHostHeader"])
	require.EqualValues(t, 1, got["priority"])
	require.EqualValues(t, 500, got["weight"])
	require.Equal(t, "Enabled", got["enabledState"])
}

func TestCdnAFDOrigin_CRUD(t *testing.T) {
	var builtProps map[string]any
	require.NoError(t, json.Unmarshal(createCdnOriginProps(), &builtProps))
	built := buildCdnAFDOriginParams(builtProps)
	built.ID = to.Ptr(testCdnOriginNativeID)
	built.Name = to.Ptr("orig-1")

	doneResult := armcdn.AFDOriginsClientCreateResponse{AFDOrigin: built}

	fake := &fakeCdnAFDOriginsAPI{
		beginCreateFn: func(_ context.Context, _, _, _, _ string, _ armcdn.AFDOrigin, _ *armcdn.AFDOriginsClientBeginCreateOptions) (*runtime.Poller[armcdn.AFDOriginsClientCreateResponse], error) {
			return newDonePoller(doneResult), nil
		},
		getFn: func(_ context.Context, _, _, _, _ string, _ *armcdn.AFDOriginsClientGetOptions) (armcdn.AFDOriginsClientGetResponse, error) {
			return armcdn.AFDOriginsClientGetResponse{AFDOrigin: built}, nil
		},
		beginDeleteFn: func(_ context.Context, _, _, _, _ string, _ *armcdn.AFDOriginsClientBeginDeleteOptions) (*runtime.Poller[armcdn.AFDOriginsClientDeleteResponse], error) {
			return newInProgressPoller[armcdn.AFDOriginsClientDeleteResponse](), nil
		},
		newListByOriginGroupPagerFn: func(_, _, _ string, _ *armcdn.AFDOriginsClientListByOriginGroupOptions) *runtime.Pager[armcdn.AFDOriginsClientListByOriginGroupResponse] {
			return runtime.NewPager(runtime.PagingHandler[armcdn.AFDOriginsClientListByOriginGroupResponse]{
				More: func(_ armcdn.AFDOriginsClientListByOriginGroupResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armcdn.AFDOriginsClientListByOriginGroupResponse) (armcdn.AFDOriginsClientListByOriginGroupResponse, error) {
					return armcdn.AFDOriginsClientListByOriginGroupResponse{
						AFDOriginListResult: armcdn.AFDOriginListResult{Value: []*armcdn.AFDOrigin{{ID: to.Ptr(testCdnOriginNativeID)}}},
					}, nil
				},
			})
		},
	}
	prov := newTestCdnAFDOrigin(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: createCdnOriginProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testCdnOriginNativeID, got.ProgressResult.NativeID)
		var props map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &props))
		require.Equal(t, "backend.example.com", props["hostName"])
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testCdnOriginNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "og-1", props["originGroupName"])
	})

	t.Run("Update", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{NativeID: testCdnOriginNativeID, DesiredProperties: createCdnOriginProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Delete", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testCdnOriginNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusInProgress, got.ProgressResult.OperationStatus)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _, _, _ string, _ *armcdn.AFDOriginsClientBeginDeleteOptions) (*runtime.Poller[armcdn.AFDOriginsClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testCdnOriginNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "profileName": "afd-1", "originGroupName": "og-1"}})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 1)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.beginCreateFn = func(_ context.Context, _, _, _, _ string, _ armcdn.AFDOrigin, _ *armcdn.AFDOriginsClientBeginCreateOptions) (*runtime.Poller[armcdn.AFDOriginsClientCreateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 403}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: createCdnOriginProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

// --- Test helpers ---

func newTestCdnAFDOrigin(api cdnAFDOriginsAPI) *CdnAFDOrigin {
	return &CdnAFDOrigin{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

type fakeCdnAFDOriginsAPI struct {
	beginCreateFn               func(ctx context.Context, rgName, profileName, originGroupName, originName string, origin armcdn.AFDOrigin, opts *armcdn.AFDOriginsClientBeginCreateOptions) (*runtime.Poller[armcdn.AFDOriginsClientCreateResponse], error)
	getFn                       func(ctx context.Context, rgName, profileName, originGroupName, originName string, opts *armcdn.AFDOriginsClientGetOptions) (armcdn.AFDOriginsClientGetResponse, error)
	beginDeleteFn               func(ctx context.Context, rgName, profileName, originGroupName, originName string, opts *armcdn.AFDOriginsClientBeginDeleteOptions) (*runtime.Poller[armcdn.AFDOriginsClientDeleteResponse], error)
	newListByOriginGroupPagerFn func(rgName, profileName, originGroupName string, opts *armcdn.AFDOriginsClientListByOriginGroupOptions) *runtime.Pager[armcdn.AFDOriginsClientListByOriginGroupResponse]
}

func (f *fakeCdnAFDOriginsAPI) BeginCreate(ctx context.Context, rgName, profileName, originGroupName, originName string, origin armcdn.AFDOrigin, opts *armcdn.AFDOriginsClientBeginCreateOptions) (*runtime.Poller[armcdn.AFDOriginsClientCreateResponse], error) {
	return f.beginCreateFn(ctx, rgName, profileName, originGroupName, originName, origin, opts)
}

func (f *fakeCdnAFDOriginsAPI) Get(ctx context.Context, rgName, profileName, originGroupName, originName string, opts *armcdn.AFDOriginsClientGetOptions) (armcdn.AFDOriginsClientGetResponse, error) {
	return f.getFn(ctx, rgName, profileName, originGroupName, originName, opts)
}

func (f *fakeCdnAFDOriginsAPI) BeginDelete(ctx context.Context, rgName, profileName, originGroupName, originName string, opts *armcdn.AFDOriginsClientBeginDeleteOptions) (*runtime.Poller[armcdn.AFDOriginsClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, profileName, originGroupName, originName, opts)
}

func (f *fakeCdnAFDOriginsAPI) NewListByOriginGroupPager(rgName, profileName, originGroupName string, opts *armcdn.AFDOriginsClientListByOriginGroupOptions) *runtime.Pager[armcdn.AFDOriginsClientListByOriginGroupResponse] {
	return f.newListByOriginGroupPagerFn(rgName, profileName, originGroupName, opts)
}
