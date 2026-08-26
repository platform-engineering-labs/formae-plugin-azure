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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/redis/armredis/v3"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testRedisNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Cache/redis/redis-1"

func newTestRedis(api redisAPI) *Redis {
	return &Redis{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func redisDesired(capacity int32) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":              "redis-1",
		"location":          "eastus",
		"resourceGroupName": "rg-1",
		"sku":               map[string]any{"name": "Basic", "family": "C", "capacity": capacity},
		"enableNonSslPort":  false,
		"minimumTlsVersion": "1.2",
	})
	return out
}

func TestRedis_CRUD(t *testing.T) {
	// ARM returns the access keys INLINE on a Redis read, unlike most services.
	redisResult := armredis.ResourceInfo{
		ID:       to.Ptr(testRedisNativeID),
		Name:     to.Ptr("redis-1"),
		Location: to.Ptr("East US"),
		Properties: &armredis.Properties{
			SKU: &armredis.SKU{
				Name:     to.Ptr(armredis.SKUNameBasic),
				Family:   to.Ptr(armredis.SKUFamilyC),
				Capacity: to.Ptr(int32(0)),
			},
			EnableNonSSLPort:    to.Ptr(false),
			MinimumTLSVersion:   to.Ptr(armredis.TLSVersion("1.2")),
			PublicNetworkAccess: to.Ptr(armredis.PublicNetworkAccessEnabled),
			HostName:            to.Ptr("redis-1.redis.cache.windows.net"),
			SSLPort:             to.Ptr(int32(6380)),
			AccessKeys: &armredis.AccessKeys{
				PrimaryKey:   to.Ptr("SUPER-SECRET-PRIMARY"),
				SecondaryKey: to.Ptr("SUPER-SECRET-SECONDARY"),
			},
		},
	}

	var sentCreate armredis.CreateParameters
	var sentUpdate armredis.UpdateParameters
	fake := &fakeRedisAPI{
		beginCreateFn: func(_ context.Context, _, name string, params armredis.CreateParameters, _ *armredis.ClientBeginCreateOptions) (*runtime.Poller[armredis.ClientCreateResponse], error) {
			require.Equal(t, "redis-1", name)
			sentCreate = params
			return newDonePoller(armredis.ClientCreateResponse{ResourceInfo: redisResult}), nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armredis.ClientGetOptions) (armredis.ClientGetResponse, error) {
			return armredis.ClientGetResponse{ResourceInfo: redisResult}, nil
		},
		beginUpdateFn: func(_ context.Context, _, _ string, params armredis.UpdateParameters, _ *armredis.ClientBeginUpdateOptions) (*runtime.Poller[armredis.ClientUpdateResponse], error) {
			sentUpdate = params
			return newDonePoller(armredis.ClientUpdateResponse{ResourceInfo: redisResult}), nil
		},
		beginDeleteFn: func(_ context.Context, _, _ string, _ *armredis.ClientBeginDeleteOptions) (*runtime.Poller[armredis.ClientDeleteResponse], error) {
			return newDonePoller(armredis.ClientDeleteResponse{}), nil
		},
		newListBySubscriptionPagerFn: func(_ *armredis.ClientListBySubscriptionOptions) *runtime.Pager[armredis.ClientListBySubscriptionResponse] {
			return runtime.NewPager(runtime.PagingHandler[armredis.ClientListBySubscriptionResponse]{
				More: func(_ armredis.ClientListBySubscriptionResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armredis.ClientListBySubscriptionResponse) (armredis.ClientListBySubscriptionResponse, error) {
					return armredis.ClientListBySubscriptionResponse{
						ListResult: armredis.ListResult{
							Value: []*armredis.ResourceInfo{
								{ID: to.Ptr(testRedisNativeID)},
								{ID: to.Ptr("/subscriptions/sub-1/resourceGroups/rg-2/providers/Microsoft.Cache/redis/redis-2")},
							},
						},
					}, nil
				},
			})
		},
		newListByResourceGroupPagerFn: func(_ string, _ *armredis.ClientListByResourceGroupOptions) *runtime.Pager[armredis.ClientListByResourceGroupResponse] {
			return runtime.NewPager(runtime.PagingHandler[armredis.ClientListByResourceGroupResponse]{
				More: func(_ armredis.ClientListByResourceGroupResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armredis.ClientListByResourceGroupResponse) (armredis.ClientListByResourceGroupResponse, error) {
					return armredis.ClientListByResourceGroupResponse{
						ListResult: armredis.ListResult{
							Value: []*armredis.ResourceInfo{{ID: to.Ptr(testRedisNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestRedis(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "redis-1", Properties: redisDesired(0)})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testRedisNativeID, got.ProgressResult.NativeID)

		require.Equal(t, armredis.SKUNameBasic, *sentCreate.Properties.SKU.Name)
		require.Equal(t, armredis.SKUFamilyC, *sentCreate.Properties.SKU.Family)
		require.EqualValues(t, 0, *sentCreate.Properties.SKU.Capacity)
		require.False(t, *sentCreate.Properties.EnableNonSSLPort)
	})

	t.Run("Create_requires_sku", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "redis-1", "location": "eastus", "resourceGroupName": "rg-1",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "sku.name and sku.family are required")
	})

	t.Run("Create_requires_location", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "redis-1", "resourceGroupName": "rg-1",
			"sku": map[string]any{"name": "Basic", "family": "C", "capacity": 0},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "location is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testRedisNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "redis-1", props["name"])
		require.Equal(t, "eastus", props["location"])
		require.Equal(t, "redis-1.redis.cache.windows.net", props["hostName"])
		require.EqualValues(t, 6380, props["sslPort"])
		sku := props["sku"].(map[string]any)
		require.Equal(t, "Basic", sku["name"])
		require.Equal(t, "C", sku["family"])
	})

	// Redis is unusual: ARM returns primary/secondary keys inline on the read, so
	// the handler has to actively strip them rather than simply not fetching them.
	t.Run("inline_access_keys_never_serialized", func(t *testing.T) {
		read, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testRedisNativeID})
		require.NoError(t, err)
		created, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "redis-1", Properties: redisDesired(0)})
		require.NoError(t, err)
		for _, payload := range []string{read.Properties, string(created.ProgressResult.ResourceProperties)} {
			require.NotContains(t, payload, "SUPER-SECRET-PRIMARY")
			require.NotContains(t, payload, "SUPER-SECRET-SECONDARY")
			require.NotContains(t, payload, "accessKeys")
			require.NotContains(t, payload, "primaryKey")
		}
	})

	t.Run("Update_scales_sku_in_place", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testRedisNativeID,
			DesiredProperties: redisDesired(1),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testRedisNativeID, got.ProgressResult.NativeID)
		require.EqualValues(t, 1, *sentUpdate.Properties.SKU.Capacity)
	})

	t.Run("Delete", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testRedisNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _ string, _ *armredis.ClientBeginDeleteOptions) (*runtime.Poller[armredis.ClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testRedisNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_resource_group", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testRedisNativeID}, got.NativeIDs)
	})

	t.Run("List_without_group_is_subscription_wide", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 2)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.beginCreateFn = func(_ context.Context, _, _ string, _ armredis.CreateParameters, _ *armredis.ClientBeginCreateOptions) (*runtime.Poller[armredis.ClientCreateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 409}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "redis-1", Properties: redisDesired(0)})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

func TestRedis_ReadCanonicalizesCasing(t *testing.T) {
	fake := &fakeRedisAPI{
		getFn: func(_ context.Context, _, _ string, _ *armredis.ClientGetOptions) (armredis.ClientGetResponse, error) {
			return armredis.ClientGetResponse{ResourceInfo: armredis.ResourceInfo{
				ID:       to.Ptr(testRedisNativeID),
				Name:     to.Ptr("redis-1"),
				Location: to.Ptr("East US"),
				Properties: &armredis.Properties{
					SKU: &armredis.SKU{
						Name:     to.Ptr(armredis.SKUName("basic")),
						Family:   to.Ptr(armredis.SKUFamily("c")),
						Capacity: to.Ptr(int32(0)),
					},
					PublicNetworkAccess: to.Ptr(armredis.PublicNetworkAccess("enabled")),
				},
			}}, nil
		},
	}
	got, err := newTestRedis(fake).Read(context.Background(), &resource.ReadRequest{NativeID: testRedisNativeID})
	require.NoError(t, err)

	var props map[string]any
	require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
	sku := props["sku"].(map[string]any)
	require.Equal(t, "Basic", sku["name"])
	require.Equal(t, "C", sku["family"])
	require.Equal(t, "Enabled", props["publicNetworkAccess"])
}

func TestRedis_ReadNotFound(t *testing.T) {
	fake := &fakeRedisAPI{
		getFn: func(_ context.Context, _, _ string, _ *armredis.ClientGetOptions) (armredis.ClientGetResponse, error) {
			return armredis.ClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestRedis(fake).Read(context.Background(), &resource.ReadRequest{NativeID: testRedisNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeRedisAPI struct {
	beginCreateFn                 func(ctx context.Context, rgName, name string, params armredis.CreateParameters, options *armredis.ClientBeginCreateOptions) (*runtime.Poller[armredis.ClientCreateResponse], error)
	getFn                         func(ctx context.Context, rgName, name string, options *armredis.ClientGetOptions) (armredis.ClientGetResponse, error)
	beginUpdateFn                 func(ctx context.Context, rgName, name string, params armredis.UpdateParameters, options *armredis.ClientBeginUpdateOptions) (*runtime.Poller[armredis.ClientUpdateResponse], error)
	beginDeleteFn                 func(ctx context.Context, rgName, name string, options *armredis.ClientBeginDeleteOptions) (*runtime.Poller[armredis.ClientDeleteResponse], error)
	newListBySubscriptionPagerFn  func(options *armredis.ClientListBySubscriptionOptions) *runtime.Pager[armredis.ClientListBySubscriptionResponse]
	newListByResourceGroupPagerFn func(rgName string, options *armredis.ClientListByResourceGroupOptions) *runtime.Pager[armredis.ClientListByResourceGroupResponse]
}

func (f *fakeRedisAPI) BeginCreate(ctx context.Context, rgName, name string, params armredis.CreateParameters, options *armredis.ClientBeginCreateOptions) (*runtime.Poller[armredis.ClientCreateResponse], error) {
	return f.beginCreateFn(ctx, rgName, name, params, options)
}

func (f *fakeRedisAPI) Get(ctx context.Context, rgName, name string, options *armredis.ClientGetOptions) (armredis.ClientGetResponse, error) {
	return f.getFn(ctx, rgName, name, options)
}

func (f *fakeRedisAPI) BeginUpdate(ctx context.Context, rgName, name string, params armredis.UpdateParameters, options *armredis.ClientBeginUpdateOptions) (*runtime.Poller[armredis.ClientUpdateResponse], error) {
	return f.beginUpdateFn(ctx, rgName, name, params, options)
}

func (f *fakeRedisAPI) BeginDelete(ctx context.Context, rgName, name string, options *armredis.ClientBeginDeleteOptions) (*runtime.Poller[armredis.ClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, name, options)
}

func (f *fakeRedisAPI) NewListBySubscriptionPager(options *armredis.ClientListBySubscriptionOptions) *runtime.Pager[armredis.ClientListBySubscriptionResponse] {
	return f.newListBySubscriptionPagerFn(options)
}

func (f *fakeRedisAPI) NewListByResourceGroupPager(rgName string, options *armredis.ClientListByResourceGroupOptions) *runtime.Pager[armredis.ClientListByResourceGroupResponse] {
	return f.newListByResourceGroupPagerFn(rgName, options)
}
