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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/webpubsub/armwebpubsub"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testWebPubSubNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.SignalRService/webPubSub/wps-1"

func newTestWebPubSub(api webPubSubAPI) *WebPubSub {
	return &WebPubSub{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func webPubSubDesired(disableAadAuth bool, capacity int32) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":                "wps-1",
		"location":            "eastus",
		"resourceGroupName":   "rg-1",
		"sku":                 map[string]any{"name": "Standard_S1", "capacity": capacity},
		"kind":                "WebPubSub",
		"disableAadAuth":      disableAadAuth,
		"publicNetworkAccess": "Enabled",
	})
	return out
}

func TestWebPubSub_CRUD(t *testing.T) {
	// Unlike SignalR this API has no features list, so there is no flag array to
	// filter on read.
	wpsResult := armwebpubsub.ResourceInfo{
		ID:       to.Ptr(testWebPubSubNativeID),
		Name:     to.Ptr("wps-1"),
		Location: to.Ptr("East US"),
		Kind:     to.Ptr(armwebpubsub.ServiceKindWebPubSub),
		SKU: &armwebpubsub.ResourceSKU{
			Name:     to.Ptr("Standard_S1"),
			Capacity: to.Ptr(int32(1)),
		},
		Properties: &armwebpubsub.Properties{
			HostName:            to.Ptr("wps-1.webpubsub.azure.com"),
			PublicNetworkAccess: to.Ptr("Enabled"),
			DisableAADAuth:      to.Ptr(false),
		},
	}

	var sentCreate, sentUpdate armwebpubsub.ResourceInfo
	fake := &fakeWebPubSubAPI{
		beginCreateOrUpdateFn: func(_ context.Context, _, name string, params armwebpubsub.ResourceInfo, _ *armwebpubsub.ClientBeginCreateOrUpdateOptions) (*runtime.Poller[armwebpubsub.ClientCreateOrUpdateResponse], error) {
			require.Equal(t, "wps-1", name)
			sentCreate = params
			return newDonePoller(armwebpubsub.ClientCreateOrUpdateResponse{ResourceInfo: wpsResult}), nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armwebpubsub.ClientGetOptions) (armwebpubsub.ClientGetResponse, error) {
			return armwebpubsub.ClientGetResponse{ResourceInfo: wpsResult}, nil
		},
		beginUpdateFn: func(_ context.Context, _, _ string, params armwebpubsub.ResourceInfo, _ *armwebpubsub.ClientBeginUpdateOptions) (*runtime.Poller[armwebpubsub.ClientUpdateResponse], error) {
			sentUpdate = params
			return newDonePoller(armwebpubsub.ClientUpdateResponse{ResourceInfo: wpsResult}), nil
		},
		beginDeleteFn: func(_ context.Context, _, _ string, _ *armwebpubsub.ClientBeginDeleteOptions) (*runtime.Poller[armwebpubsub.ClientDeleteResponse], error) {
			return newDonePoller(armwebpubsub.ClientDeleteResponse{}), nil
		},
		newListBySubscriptionPagerFn: func(_ *armwebpubsub.ClientListBySubscriptionOptions) *runtime.Pager[armwebpubsub.ClientListBySubscriptionResponse] {
			return runtime.NewPager(runtime.PagingHandler[armwebpubsub.ClientListBySubscriptionResponse]{
				More: func(_ armwebpubsub.ClientListBySubscriptionResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armwebpubsub.ClientListBySubscriptionResponse) (armwebpubsub.ClientListBySubscriptionResponse, error) {
					return armwebpubsub.ClientListBySubscriptionResponse{
						ResourceInfoList: armwebpubsub.ResourceInfoList{
							Value: []*armwebpubsub.ResourceInfo{
								{ID: to.Ptr(testWebPubSubNativeID)},
								{ID: to.Ptr("/subscriptions/sub-1/resourceGroups/rg-2/providers/Microsoft.SignalRService/webPubSub/wps-2")},
							},
						},
					}, nil
				},
			})
		},
		newListByResourceGroupPagerFn: func(_ string, _ *armwebpubsub.ClientListByResourceGroupOptions) *runtime.Pager[armwebpubsub.ClientListByResourceGroupResponse] {
			return runtime.NewPager(runtime.PagingHandler[armwebpubsub.ClientListByResourceGroupResponse]{
				More: func(_ armwebpubsub.ClientListByResourceGroupResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armwebpubsub.ClientListByResourceGroupResponse) (armwebpubsub.ClientListByResourceGroupResponse, error) {
					return armwebpubsub.ClientListByResourceGroupResponse{
						ResourceInfoList: armwebpubsub.ResourceInfoList{
							Value: []*armwebpubsub.ResourceInfo{{ID: to.Ptr(testWebPubSubNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestWebPubSub(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "wps-1", Properties: webPubSubDesired(false, 1)})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testWebPubSubNativeID, got.ProgressResult.NativeID)

		require.Equal(t, "Standard_S1", *sentCreate.SKU.Name)
		require.EqualValues(t, 1, *sentCreate.SKU.Capacity)
		require.Equal(t, "WebPubSub", string(*sentCreate.Kind))
		require.False(t, *sentCreate.Properties.DisableAADAuth)
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testWebPubSubNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "wps-1", props["name"])
		require.Equal(t, "eastus", props["location"])
		require.Equal(t, "wps-1.webpubsub.azure.com", props["hostName"])
		require.Equal(t, "WebPubSub", props["kind"])
		require.Equal(t, false, props["disableAadAuth"])
	})

	t.Run("Create_requires_sku", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "wps-1", "location": "eastus", "resourceGroupName": "rg-1",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "sku.name is required")
	})

	t.Run("Create_floors_capacity", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "wps-1", "location": "eastus", "resourceGroupName": "rg-1",
			"sku": map[string]any{"name": "Standard_S1"},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "wps-1", Properties: props})
		require.NoError(t, err)
		require.EqualValues(t, 1, *sentCreate.SKU.Capacity)
	})

	t.Run("keys_never_serialized", func(t *testing.T) {
		read, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testWebPubSubNativeID})
		require.NoError(t, err)
		for _, key := range []string{"primaryKey", "secondaryKey", "connectionString", "accessKey"} {
			require.NotContains(t, read.Properties, key)
		}
	})

	t.Run("Update_uses_update_verb", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testWebPubSubNativeID,
			DesiredProperties: webPubSubDesired(true, 2),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testWebPubSubNativeID, got.ProgressResult.NativeID)
		require.EqualValues(t, 2, *sentUpdate.SKU.Capacity)
		require.True(t, *sentUpdate.Properties.DisableAADAuth)
	})

	t.Run("Delete", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testWebPubSubNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _ string, _ *armwebpubsub.ClientBeginDeleteOptions) (*runtime.Poller[armwebpubsub.ClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testWebPubSubNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_resource_group", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testWebPubSubNativeID}, got.NativeIDs)
	})

	t.Run("List_without_group_is_subscription_wide", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 2)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, _ armwebpubsub.ResourceInfo, _ *armwebpubsub.ClientBeginCreateOrUpdateOptions) (*runtime.Poller[armwebpubsub.ClientCreateOrUpdateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 409}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "wps-1", Properties: webPubSubDesired(false, 1)})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

func TestWebPubSub_ReadNotFound(t *testing.T) {
	fake := &fakeWebPubSubAPI{
		getFn: func(_ context.Context, _, _ string, _ *armwebpubsub.ClientGetOptions) (armwebpubsub.ClientGetResponse, error) {
			return armwebpubsub.ClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestWebPubSub(fake).Read(context.Background(), &resource.ReadRequest{NativeID: testWebPubSubNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeWebPubSubAPI struct {
	beginCreateOrUpdateFn         func(ctx context.Context, rgName, name string, params armwebpubsub.ResourceInfo, options *armwebpubsub.ClientBeginCreateOrUpdateOptions) (*runtime.Poller[armwebpubsub.ClientCreateOrUpdateResponse], error)
	getFn                         func(ctx context.Context, rgName, name string, options *armwebpubsub.ClientGetOptions) (armwebpubsub.ClientGetResponse, error)
	beginUpdateFn                 func(ctx context.Context, rgName, name string, params armwebpubsub.ResourceInfo, options *armwebpubsub.ClientBeginUpdateOptions) (*runtime.Poller[armwebpubsub.ClientUpdateResponse], error)
	beginDeleteFn                 func(ctx context.Context, rgName, name string, options *armwebpubsub.ClientBeginDeleteOptions) (*runtime.Poller[armwebpubsub.ClientDeleteResponse], error)
	newListBySubscriptionPagerFn  func(options *armwebpubsub.ClientListBySubscriptionOptions) *runtime.Pager[armwebpubsub.ClientListBySubscriptionResponse]
	newListByResourceGroupPagerFn func(rgName string, options *armwebpubsub.ClientListByResourceGroupOptions) *runtime.Pager[armwebpubsub.ClientListByResourceGroupResponse]
}

func (f *fakeWebPubSubAPI) BeginCreateOrUpdate(ctx context.Context, rgName, name string, params armwebpubsub.ResourceInfo, options *armwebpubsub.ClientBeginCreateOrUpdateOptions) (*runtime.Poller[armwebpubsub.ClientCreateOrUpdateResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, rgName, name, params, options)
}

func (f *fakeWebPubSubAPI) Get(ctx context.Context, rgName, name string, options *armwebpubsub.ClientGetOptions) (armwebpubsub.ClientGetResponse, error) {
	return f.getFn(ctx, rgName, name, options)
}

func (f *fakeWebPubSubAPI) BeginUpdate(ctx context.Context, rgName, name string, params armwebpubsub.ResourceInfo, options *armwebpubsub.ClientBeginUpdateOptions) (*runtime.Poller[armwebpubsub.ClientUpdateResponse], error) {
	return f.beginUpdateFn(ctx, rgName, name, params, options)
}

func (f *fakeWebPubSubAPI) BeginDelete(ctx context.Context, rgName, name string, options *armwebpubsub.ClientBeginDeleteOptions) (*runtime.Poller[armwebpubsub.ClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, name, options)
}

func (f *fakeWebPubSubAPI) NewListBySubscriptionPager(options *armwebpubsub.ClientListBySubscriptionOptions) *runtime.Pager[armwebpubsub.ClientListBySubscriptionResponse] {
	return f.newListBySubscriptionPagerFn(options)
}

func (f *fakeWebPubSubAPI) NewListByResourceGroupPager(rgName string, options *armwebpubsub.ClientListByResourceGroupOptions) *runtime.Pager[armwebpubsub.ClientListByResourceGroupResponse] {
	return f.newListByResourceGroupPagerFn(rgName, options)
}
