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

const testCdnProfileNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Cdn/profiles/afd-1"

func fullCdnProfileProps() map[string]any {
	return map[string]any{
		"resourceGroupName":            "rg-1",
		"name":                         "afd-1",
		"location":                     "global",
		"sku":                          map[string]any{"name": "Standard_AzureFrontDoor"},
		"originResponseTimeoutSeconds": 60,
	}
}

func createCdnProfileProps() json.RawMessage {
	props, _ := json.Marshal(fullCdnProfileProps())
	return props
}

func TestCdnProfile_CRUD(t *testing.T) {
	var builtProps map[string]any
	require.NoError(t, json.Unmarshal(createCdnProfileProps(), &builtProps))
	built := buildCdnProfileParams(builtProps, "global")
	built.ID = to.Ptr(testCdnProfileNativeID)
	built.Name = to.Ptr("afd-1")

	doneResult := armcdn.ProfilesClientCreateResponse{Profile: built}

	fake := &fakeCdnProfilesAPI{
		beginCreateFn: func(_ context.Context, _, _ string, _ armcdn.Profile, _ *armcdn.ProfilesClientBeginCreateOptions) (*runtime.Poller[armcdn.ProfilesClientCreateResponse], error) {
			return newDonePoller(doneResult), nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armcdn.ProfilesClientGetOptions) (armcdn.ProfilesClientGetResponse, error) {
			return armcdn.ProfilesClientGetResponse{Profile: built}, nil
		},
		beginDeleteFn: func(_ context.Context, _, _ string, _ *armcdn.ProfilesClientBeginDeleteOptions) (*runtime.Poller[armcdn.ProfilesClientDeleteResponse], error) {
			return newInProgressPoller[armcdn.ProfilesClientDeleteResponse](), nil
		},
		newListPagerFn: func(_ *armcdn.ProfilesClientListOptions) *runtime.Pager[armcdn.ProfilesClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armcdn.ProfilesClientListResponse]{
				More: func(_ armcdn.ProfilesClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armcdn.ProfilesClientListResponse) (armcdn.ProfilesClientListResponse, error) {
					return armcdn.ProfilesClientListResponse{
						ProfileListResult: armcdn.ProfileListResult{Value: []*armcdn.Profile{{ID: to.Ptr(testCdnProfileNativeID)}}},
					}, nil
				},
			})
		},
	}
	prov := newTestCdnProfile(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: createCdnProfileProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testCdnProfileNativeID, got.ProgressResult.NativeID)
		var props map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &props))
		require.Equal(t, "afd-1", props["name"])
		require.Equal(t, "Standard_AzureFrontDoor", props["sku"].(map[string]any)["name"])
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testCdnProfileNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "afd-1", props["name"])
	})

	t.Run("Update", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{NativeID: testCdnProfileNativeID, DesiredProperties: createCdnProfileProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Delete", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testCdnProfileNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusInProgress, got.ProgressResult.OperationStatus)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _ string, _ *armcdn.ProfilesClientBeginDeleteOptions) (*runtime.Poller[armcdn.ProfilesClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testCdnProfileNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{AdditionalProperties: map[string]string{}})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 1)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.beginCreateFn = func(_ context.Context, _, _ string, _ armcdn.Profile, _ *armcdn.ProfilesClientBeginCreateOptions) (*runtime.Poller[armcdn.ProfilesClientCreateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 403}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: createCdnProfileProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

// --- Test helpers ---

func newTestCdnProfile(api cdnProfilesAPI) *CdnProfile {
	return &CdnProfile{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

type fakeCdnProfilesAPI struct {
	beginCreateFn                 func(ctx context.Context, rgName, profileName string, profile armcdn.Profile, opts *armcdn.ProfilesClientBeginCreateOptions) (*runtime.Poller[armcdn.ProfilesClientCreateResponse], error)
	getFn                         func(ctx context.Context, rgName, profileName string, opts *armcdn.ProfilesClientGetOptions) (armcdn.ProfilesClientGetResponse, error)
	beginDeleteFn                 func(ctx context.Context, rgName, profileName string, opts *armcdn.ProfilesClientBeginDeleteOptions) (*runtime.Poller[armcdn.ProfilesClientDeleteResponse], error)
	newListPagerFn                func(opts *armcdn.ProfilesClientListOptions) *runtime.Pager[armcdn.ProfilesClientListResponse]
	newListByResourceGroupPagerFn func(rgName string, opts *armcdn.ProfilesClientListByResourceGroupOptions) *runtime.Pager[armcdn.ProfilesClientListByResourceGroupResponse]
}

func (f *fakeCdnProfilesAPI) BeginCreate(ctx context.Context, rgName, profileName string, profile armcdn.Profile, opts *armcdn.ProfilesClientBeginCreateOptions) (*runtime.Poller[armcdn.ProfilesClientCreateResponse], error) {
	return f.beginCreateFn(ctx, rgName, profileName, profile, opts)
}

func (f *fakeCdnProfilesAPI) Get(ctx context.Context, rgName, profileName string, opts *armcdn.ProfilesClientGetOptions) (armcdn.ProfilesClientGetResponse, error) {
	return f.getFn(ctx, rgName, profileName, opts)
}

func (f *fakeCdnProfilesAPI) BeginDelete(ctx context.Context, rgName, profileName string, opts *armcdn.ProfilesClientBeginDeleteOptions) (*runtime.Poller[armcdn.ProfilesClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, profileName, opts)
}

func (f *fakeCdnProfilesAPI) NewListPager(opts *armcdn.ProfilesClientListOptions) *runtime.Pager[armcdn.ProfilesClientListResponse] {
	return f.newListPagerFn(opts)
}

func (f *fakeCdnProfilesAPI) NewListByResourceGroupPager(rgName string, opts *armcdn.ProfilesClientListByResourceGroupOptions) *runtime.Pager[armcdn.ProfilesClientListByResourceGroupResponse] {
	return f.newListByResourceGroupPagerFn(rgName, opts)
}
