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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/signalr/armsignalr"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testSignalRNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.SignalRService/signalR/sig-1"

func newTestSignalR(api signalRAPI) *SignalR {
	return &SignalR{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func signalRDesired(serviceMode string, capacity int32) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":                "sig-1",
		"location":            "eastus",
		"resourceGroupName":   "rg-1",
		"sku":                 map[string]any{"name": "Standard_S1", "capacity": capacity},
		"kind":                "SignalR",
		"serviceMode":         serviceMode,
		"publicNetworkAccess": "Enabled",
	})
	return out
}

func TestSignalR_CRUD(t *testing.T) {
	// ARM returns EVERY feature flag it knows about, not just the one that was set.
	sigResult := armsignalr.ResourceInfo{
		ID:       to.Ptr(testSignalRNativeID),
		Name:     to.Ptr("sig-1"),
		Location: to.Ptr("East US"),
		Kind:     to.Ptr(armsignalr.ServiceKindSignalR),
		SKU: &armsignalr.ResourceSKU{
			Name:     to.Ptr("Standard_S1"),
			Capacity: to.Ptr(int32(1)),
		},
		Properties: &armsignalr.Properties{
			HostName:            to.Ptr("sig-1.service.signalr.net"),
			PublicNetworkAccess: to.Ptr("Enabled"),
			Features: []*armsignalr.Feature{
				{Flag: to.Ptr(armsignalr.FeatureFlagsServiceMode), Value: to.Ptr("Default")},
				{Flag: to.Ptr(armsignalr.FeatureFlagsEnableConnectivityLogs), Value: to.Ptr("false")},
				{Flag: to.Ptr(armsignalr.FeatureFlagsEnableMessagingLogs), Value: to.Ptr("false")},
				{Flag: to.Ptr(armsignalr.FeatureFlagsEnableLiveTrace), Value: to.Ptr("false")},
			},
		},
	}

	var sentCreate, sentUpdate armsignalr.ResourceInfo
	fake := &fakeSignalRAPI{
		beginCreateOrUpdateFn: func(_ context.Context, _, name string, params armsignalr.ResourceInfo, _ *armsignalr.ClientBeginCreateOrUpdateOptions) (*runtime.Poller[armsignalr.ClientCreateOrUpdateResponse], error) {
			require.Equal(t, "sig-1", name)
			sentCreate = params
			return newDonePoller(armsignalr.ClientCreateOrUpdateResponse{ResourceInfo: sigResult}), nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armsignalr.ClientGetOptions) (armsignalr.ClientGetResponse, error) {
			return armsignalr.ClientGetResponse{ResourceInfo: sigResult}, nil
		},
		beginUpdateFn: func(_ context.Context, _, _ string, params armsignalr.ResourceInfo, _ *armsignalr.ClientBeginUpdateOptions) (*runtime.Poller[armsignalr.ClientUpdateResponse], error) {
			sentUpdate = params
			return newDonePoller(armsignalr.ClientUpdateResponse{ResourceInfo: sigResult}), nil
		},
		beginDeleteFn: func(_ context.Context, _, _ string, _ *armsignalr.ClientBeginDeleteOptions) (*runtime.Poller[armsignalr.ClientDeleteResponse], error) {
			return newDonePoller(armsignalr.ClientDeleteResponse{}), nil
		},
		newListBySubscriptionPagerFn: func(_ *armsignalr.ClientListBySubscriptionOptions) *runtime.Pager[armsignalr.ClientListBySubscriptionResponse] {
			return runtime.NewPager(runtime.PagingHandler[armsignalr.ClientListBySubscriptionResponse]{
				More: func(_ armsignalr.ClientListBySubscriptionResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armsignalr.ClientListBySubscriptionResponse) (armsignalr.ClientListBySubscriptionResponse, error) {
					return armsignalr.ClientListBySubscriptionResponse{
						ResourceInfoList: armsignalr.ResourceInfoList{
							Value: []*armsignalr.ResourceInfo{
								{ID: to.Ptr(testSignalRNativeID)},
								{ID: to.Ptr("/subscriptions/sub-1/resourceGroups/rg-2/providers/Microsoft.SignalRService/signalR/sig-2")},
							},
						},
					}, nil
				},
			})
		},
		newListByResourceGroupPagerFn: func(_ string, _ *armsignalr.ClientListByResourceGroupOptions) *runtime.Pager[armsignalr.ClientListByResourceGroupResponse] {
			return runtime.NewPager(runtime.PagingHandler[armsignalr.ClientListByResourceGroupResponse]{
				More: func(_ armsignalr.ClientListByResourceGroupResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armsignalr.ClientListByResourceGroupResponse) (armsignalr.ClientListByResourceGroupResponse, error) {
					return armsignalr.ClientListByResourceGroupResponse{
						ResourceInfoList: armsignalr.ResourceInfoList{
							Value: []*armsignalr.ResourceInfo{{ID: to.Ptr(testSignalRNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestSignalR(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "sig-1", Properties: signalRDesired("Default", 1)})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testSignalRNativeID, got.ProgressResult.NativeID)

		require.Equal(t, "Standard_S1", *sentCreate.SKU.Name)
		require.EqualValues(t, 1, *sentCreate.SKU.Capacity)
		// Only ServiceMode is ever sent; the log flags are not modelled.
		require.Len(t, sentCreate.Properties.Features, 1)
		require.Equal(t, armsignalr.FeatureFlagsServiceMode, *sentCreate.Properties.Features[0].Flag)
		require.Equal(t, "Default", *sentCreate.Properties.Features[0].Value)
	})

	// The service returns four flags; only serviceMode may reach state, or a
	// one-entry desired state would drift against a four-entry read forever.
	t.Run("Read_extracts_only_serviceMode", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testSignalRNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "Default", props["serviceMode"])
		require.NotContains(t, props, "features")
		require.NotContains(t, props, "enableConnectivityLogs")
		require.Equal(t, "sig-1.service.signalr.net", props["hostName"])
		require.Equal(t, "eastus", props["location"])
	})

	t.Run("Create_requires_sku", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "sig-1", "location": "eastus", "resourceGroupName": "rg-1",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "sku.name is required")
	})

	t.Run("Create_floors_capacity", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "sig-1", "location": "eastus", "resourceGroupName": "rg-1",
			"sku": map[string]any{"name": "Standard_S1"},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "sig-1", Properties: props})
		require.NoError(t, err)
		require.EqualValues(t, 1, *sentCreate.SKU.Capacity)
	})

	t.Run("Create_omits_features_when_serviceMode_unset", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "sig-1", "location": "eastus", "resourceGroupName": "rg-1",
			"sku": map[string]any{"name": "Standard_S1", "capacity": 1},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "sig-1", Properties: props})
		require.NoError(t, err)
		require.Empty(t, sentCreate.Properties.Features)
	})

	t.Run("keys_never_serialized", func(t *testing.T) {
		read, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testSignalRNativeID})
		require.NoError(t, err)
		for _, key := range []string{"primaryKey", "secondaryKey", "connectionString", "accessKey"} {
			require.NotContains(t, read.Properties, key)
		}
	})

	t.Run("Update_uses_update_verb", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testSignalRNativeID,
			DesiredProperties: signalRDesired("Serverless", 2),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testSignalRNativeID, got.ProgressResult.NativeID)
		require.EqualValues(t, 2, *sentUpdate.SKU.Capacity)
		require.Equal(t, "Serverless", *sentUpdate.Properties.Features[0].Value)
	})

	t.Run("Delete", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testSignalRNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _ string, _ *armsignalr.ClientBeginDeleteOptions) (*runtime.Poller[armsignalr.ClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testSignalRNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_resource_group", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testSignalRNativeID}, got.NativeIDs)
	})

	t.Run("List_without_group_is_subscription_wide", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 2)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, _ armsignalr.ResourceInfo, _ *armsignalr.ClientBeginCreateOrUpdateOptions) (*runtime.Poller[armsignalr.ClientCreateOrUpdateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 409}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "sig-1", Properties: signalRDesired("Default", 1)})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

func TestSignalR_ReadNotFound(t *testing.T) {
	fake := &fakeSignalRAPI{
		getFn: func(_ context.Context, _, _ string, _ *armsignalr.ClientGetOptions) (armsignalr.ClientGetResponse, error) {
			return armsignalr.ClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestSignalR(fake).Read(context.Background(), &resource.ReadRequest{NativeID: testSignalRNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeSignalRAPI struct {
	beginCreateOrUpdateFn         func(ctx context.Context, rgName, name string, params armsignalr.ResourceInfo, options *armsignalr.ClientBeginCreateOrUpdateOptions) (*runtime.Poller[armsignalr.ClientCreateOrUpdateResponse], error)
	getFn                         func(ctx context.Context, rgName, name string, options *armsignalr.ClientGetOptions) (armsignalr.ClientGetResponse, error)
	beginUpdateFn                 func(ctx context.Context, rgName, name string, params armsignalr.ResourceInfo, options *armsignalr.ClientBeginUpdateOptions) (*runtime.Poller[armsignalr.ClientUpdateResponse], error)
	beginDeleteFn                 func(ctx context.Context, rgName, name string, options *armsignalr.ClientBeginDeleteOptions) (*runtime.Poller[armsignalr.ClientDeleteResponse], error)
	newListBySubscriptionPagerFn  func(options *armsignalr.ClientListBySubscriptionOptions) *runtime.Pager[armsignalr.ClientListBySubscriptionResponse]
	newListByResourceGroupPagerFn func(rgName string, options *armsignalr.ClientListByResourceGroupOptions) *runtime.Pager[armsignalr.ClientListByResourceGroupResponse]
}

func (f *fakeSignalRAPI) BeginCreateOrUpdate(ctx context.Context, rgName, name string, params armsignalr.ResourceInfo, options *armsignalr.ClientBeginCreateOrUpdateOptions) (*runtime.Poller[armsignalr.ClientCreateOrUpdateResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, rgName, name, params, options)
}

func (f *fakeSignalRAPI) Get(ctx context.Context, rgName, name string, options *armsignalr.ClientGetOptions) (armsignalr.ClientGetResponse, error) {
	return f.getFn(ctx, rgName, name, options)
}

func (f *fakeSignalRAPI) BeginUpdate(ctx context.Context, rgName, name string, params armsignalr.ResourceInfo, options *armsignalr.ClientBeginUpdateOptions) (*runtime.Poller[armsignalr.ClientUpdateResponse], error) {
	return f.beginUpdateFn(ctx, rgName, name, params, options)
}

func (f *fakeSignalRAPI) BeginDelete(ctx context.Context, rgName, name string, options *armsignalr.ClientBeginDeleteOptions) (*runtime.Poller[armsignalr.ClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, name, options)
}

func (f *fakeSignalRAPI) NewListBySubscriptionPager(options *armsignalr.ClientListBySubscriptionOptions) *runtime.Pager[armsignalr.ClientListBySubscriptionResponse] {
	return f.newListBySubscriptionPagerFn(options)
}

func (f *fakeSignalRAPI) NewListByResourceGroupPager(rgName string, options *armsignalr.ClientListByResourceGroupOptions) *runtime.Pager[armsignalr.ClientListByResourceGroupResponse] {
	return f.newListByResourceGroupPagerFn(rgName, options)
}
