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

const testCdnOriginGroupNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Cdn/profiles/afd-1/originGroups/og-1"

func fullCdnOriginGroupProps() map[string]any {
	return map[string]any{
		"resourceGroupName": "rg-1",
		"profileName":       "afd-1",
		"name":              "og-1",
		"loadBalancingSettings": map[string]any{
			"sampleSize":                      4,
			"successfulSamplesRequired":       3,
			"additionalLatencyInMilliseconds": 50,
		},
		"healthProbeSettings": map[string]any{
			"probePath":              "/healthz",
			"probeRequestType":       "GET",
			"probeProtocol":          "Https",
			"probeIntervalInSeconds": 100,
		},
	}
}

func createCdnOriginGroupProps() json.RawMessage {
	props, _ := json.Marshal(fullCdnOriginGroupProps())
	return props
}

// TestCdnAFDOriginGroup_MarshallerRoundTrip verifies loadBalancingSettings and
// healthProbeSettings survive build -> serialize with no drift.
func TestCdnAFDOriginGroup_MarshallerRoundTrip(t *testing.T) {
	var props map[string]any
	require.NoError(t, json.Unmarshal(createCdnOriginGroupProps(), &props))

	params := buildCdnAFDOriginGroupParams(props)
	params.ID = to.Ptr(testCdnOriginGroupNativeID)
	params.Name = to.Ptr("og-1")

	raw, err := serializeCdnAFDOriginGroupProperties(params, "rg-1", "afd-1", "og-1")
	require.NoError(t, err)

	var got map[string]any
	require.NoError(t, json.Unmarshal(raw, &got))

	require.Equal(t, "og-1", got["name"])
	require.Equal(t, "afd-1", got["profileName"])

	lb := got["loadBalancingSettings"].(map[string]any)
	require.EqualValues(t, 4, lb["sampleSize"])
	require.EqualValues(t, 3, lb["successfulSamplesRequired"])
	require.EqualValues(t, 50, lb["additionalLatencyInMilliseconds"])

	hp := got["healthProbeSettings"].(map[string]any)
	require.Equal(t, "/healthz", hp["probePath"])
	require.Equal(t, "GET", hp["probeRequestType"])
	require.Equal(t, "Https", hp["probeProtocol"])
	require.EqualValues(t, 100, hp["probeIntervalInSeconds"])
}

func TestCdnAFDOriginGroup_CRUD(t *testing.T) {
	var builtProps map[string]any
	require.NoError(t, json.Unmarshal(createCdnOriginGroupProps(), &builtProps))
	built := buildCdnAFDOriginGroupParams(builtProps)
	built.ID = to.Ptr(testCdnOriginGroupNativeID)
	built.Name = to.Ptr("og-1")

	doneResult := armcdn.AFDOriginGroupsClientCreateResponse{AFDOriginGroup: built}

	fake := &fakeCdnAFDOriginGroupsAPI{
		beginCreateFn: func(_ context.Context, _, _, _ string, _ armcdn.AFDOriginGroup, _ *armcdn.AFDOriginGroupsClientBeginCreateOptions) (*runtime.Poller[armcdn.AFDOriginGroupsClientCreateResponse], error) {
			return newDonePoller(doneResult), nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ *armcdn.AFDOriginGroupsClientGetOptions) (armcdn.AFDOriginGroupsClientGetResponse, error) {
			return armcdn.AFDOriginGroupsClientGetResponse{AFDOriginGroup: built}, nil
		},
		beginDeleteFn: func(_ context.Context, _, _, _ string, _ *armcdn.AFDOriginGroupsClientBeginDeleteOptions) (*runtime.Poller[armcdn.AFDOriginGroupsClientDeleteResponse], error) {
			return newInProgressPoller[armcdn.AFDOriginGroupsClientDeleteResponse](), nil
		},
		newListByProfilePagerFn: func(_, _ string, _ *armcdn.AFDOriginGroupsClientListByProfileOptions) *runtime.Pager[armcdn.AFDOriginGroupsClientListByProfileResponse] {
			return runtime.NewPager(runtime.PagingHandler[armcdn.AFDOriginGroupsClientListByProfileResponse]{
				More: func(_ armcdn.AFDOriginGroupsClientListByProfileResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armcdn.AFDOriginGroupsClientListByProfileResponse) (armcdn.AFDOriginGroupsClientListByProfileResponse, error) {
					return armcdn.AFDOriginGroupsClientListByProfileResponse{
						AFDOriginGroupListResult: armcdn.AFDOriginGroupListResult{Value: []*armcdn.AFDOriginGroup{{ID: to.Ptr(testCdnOriginGroupNativeID)}}},
					}, nil
				},
			})
		},
	}
	prov := newTestCdnAFDOriginGroup(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: createCdnOriginGroupProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testCdnOriginGroupNativeID, got.ProgressResult.NativeID)
		var props map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &props))
		require.Equal(t, "og-1", props["name"])
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testCdnOriginGroupNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "/healthz", props["healthProbeSettings"].(map[string]any)["probePath"])
	})

	t.Run("Update", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{NativeID: testCdnOriginGroupNativeID, DesiredProperties: createCdnOriginGroupProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Delete", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testCdnOriginGroupNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusInProgress, got.ProgressResult.OperationStatus)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _, _ string, _ *armcdn.AFDOriginGroupsClientBeginDeleteOptions) (*runtime.Poller[armcdn.AFDOriginGroupsClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testCdnOriginGroupNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "profileName": "afd-1"}})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 1)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.beginCreateFn = func(_ context.Context, _, _, _ string, _ armcdn.AFDOriginGroup, _ *armcdn.AFDOriginGroupsClientBeginCreateOptions) (*runtime.Poller[armcdn.AFDOriginGroupsClientCreateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 403}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: createCdnOriginGroupProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

// --- Test helpers ---

func newTestCdnAFDOriginGroup(api cdnAFDOriginGroupsAPI) *CdnAFDOriginGroup {
	return &CdnAFDOriginGroup{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

type fakeCdnAFDOriginGroupsAPI struct {
	beginCreateFn           func(ctx context.Context, rgName, profileName, originGroupName string, originGroup armcdn.AFDOriginGroup, opts *armcdn.AFDOriginGroupsClientBeginCreateOptions) (*runtime.Poller[armcdn.AFDOriginGroupsClientCreateResponse], error)
	getFn                   func(ctx context.Context, rgName, profileName, originGroupName string, opts *armcdn.AFDOriginGroupsClientGetOptions) (armcdn.AFDOriginGroupsClientGetResponse, error)
	beginDeleteFn           func(ctx context.Context, rgName, profileName, originGroupName string, opts *armcdn.AFDOriginGroupsClientBeginDeleteOptions) (*runtime.Poller[armcdn.AFDOriginGroupsClientDeleteResponse], error)
	newListByProfilePagerFn func(rgName, profileName string, opts *armcdn.AFDOriginGroupsClientListByProfileOptions) *runtime.Pager[armcdn.AFDOriginGroupsClientListByProfileResponse]
}

func (f *fakeCdnAFDOriginGroupsAPI) BeginCreate(ctx context.Context, rgName, profileName, originGroupName string, originGroup armcdn.AFDOriginGroup, opts *armcdn.AFDOriginGroupsClientBeginCreateOptions) (*runtime.Poller[armcdn.AFDOriginGroupsClientCreateResponse], error) {
	return f.beginCreateFn(ctx, rgName, profileName, originGroupName, originGroup, opts)
}

func (f *fakeCdnAFDOriginGroupsAPI) Get(ctx context.Context, rgName, profileName, originGroupName string, opts *armcdn.AFDOriginGroupsClientGetOptions) (armcdn.AFDOriginGroupsClientGetResponse, error) {
	return f.getFn(ctx, rgName, profileName, originGroupName, opts)
}

func (f *fakeCdnAFDOriginGroupsAPI) BeginDelete(ctx context.Context, rgName, profileName, originGroupName string, opts *armcdn.AFDOriginGroupsClientBeginDeleteOptions) (*runtime.Poller[armcdn.AFDOriginGroupsClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, profileName, originGroupName, opts)
}

func (f *fakeCdnAFDOriginGroupsAPI) NewListByProfilePager(rgName, profileName string, opts *armcdn.AFDOriginGroupsClientListByProfileOptions) *runtime.Pager[armcdn.AFDOriginGroupsClientListByProfileResponse] {
	return f.newListByProfilePagerFn(rgName, profileName, opts)
}
