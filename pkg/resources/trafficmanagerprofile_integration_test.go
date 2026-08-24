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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/trafficmanager/armtrafficmanager"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testTMProfileNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/trafficManagerProfiles/tm-1"

func newTestTrafficManagerProfile(api trafficManagerProfilesAPI) *TrafficManagerProfile {
	return &TrafficManagerProfile{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func tmDesired(method, protocol string, ttl int64) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":                 "tm-1",
		"resourceGroupName":    "rg-1",
		"location":             "global",
		"trafficRoutingMethod": method,
		"dnsConfig":            map[string]any{"relativeName": "fpsdt-tm-1", "ttl": ttl},
		"monitorConfig": map[string]any{
			"protocol": protocol, "port": 80, "path": "/",
			"intervalInSeconds": 30, "timeoutInSeconds": 10, "toleratedNumberOfFailures": 3,
		},
		"profileStatus": "Enabled",
	})
	return out
}

func TestTrafficManagerProfile_CRUD(t *testing.T) {
	tmResult := armtrafficmanager.Profile{
		ID:       to.Ptr(testTMProfileNativeID),
		Name:     to.Ptr("tm-1"),
		Location: to.Ptr("global"),
		Properties: &armtrafficmanager.ProfileProperties{
			TrafficRoutingMethod: to.Ptr(armtrafficmanager.TrafficRoutingMethodPriority),
			ProfileStatus:        to.Ptr(armtrafficmanager.ProfileStatusEnabled),
			DNSConfig: &armtrafficmanager.DNSConfig{
				RelativeName: to.Ptr("fpsdt-tm-1"),
				TTL:          to.Ptr(int64(60)),
				Fqdn:         to.Ptr("fpsdt-tm-1.trafficmanager.net"),
			},
			MonitorConfig: &armtrafficmanager.MonitorConfig{
				Protocol:                  to.Ptr(armtrafficmanager.MonitorProtocolHTTP),
				Port:                      to.Ptr(int64(80)),
				Path:                      to.Ptr("/"),
				IntervalInSeconds:         to.Ptr(int64(30)),
				TimeoutInSeconds:          to.Ptr(int64(10)),
				ToleratedNumberOfFailures: to.Ptr(int64(3)),
			},
		},
	}

	var sent armtrafficmanager.Profile
	fake := &fakeTMProfilesAPI{
		createOrUpdateFn: func(_ context.Context, _, name string, params armtrafficmanager.Profile, _ *armtrafficmanager.ProfilesClientCreateOrUpdateOptions) (armtrafficmanager.ProfilesClientCreateOrUpdateResponse, error) {
			require.Equal(t, "tm-1", name)
			sent = params
			return armtrafficmanager.ProfilesClientCreateOrUpdateResponse{Profile: tmResult}, nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armtrafficmanager.ProfilesClientGetOptions) (armtrafficmanager.ProfilesClientGetResponse, error) {
			return armtrafficmanager.ProfilesClientGetResponse{Profile: tmResult}, nil
		},
		deleteFn: func(_ context.Context, _, _ string, _ *armtrafficmanager.ProfilesClientDeleteOptions) (armtrafficmanager.ProfilesClientDeleteResponse, error) {
			return armtrafficmanager.ProfilesClientDeleteResponse{}, nil
		},
		newListBySubscriptionPagerFn: func(_ *armtrafficmanager.ProfilesClientListBySubscriptionOptions) *runtime.Pager[armtrafficmanager.ProfilesClientListBySubscriptionResponse] {
			return runtime.NewPager(runtime.PagingHandler[armtrafficmanager.ProfilesClientListBySubscriptionResponse]{
				More: func(_ armtrafficmanager.ProfilesClientListBySubscriptionResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armtrafficmanager.ProfilesClientListBySubscriptionResponse) (armtrafficmanager.ProfilesClientListBySubscriptionResponse, error) {
					return armtrafficmanager.ProfilesClientListBySubscriptionResponse{
						ProfileListResult: armtrafficmanager.ProfileListResult{
							Value: []*armtrafficmanager.Profile{
								{ID: to.Ptr(testTMProfileNativeID)},
								{ID: to.Ptr("/subscriptions/sub-1/resourceGroups/rg-2/providers/Microsoft.Network/trafficManagerProfiles/tm-2")},
							},
						},
					}, nil
				},
			})
		},
		newListByResourceGroupPagerFn: func(_ string, _ *armtrafficmanager.ProfilesClientListByResourceGroupOptions) *runtime.Pager[armtrafficmanager.ProfilesClientListByResourceGroupResponse] {
			return runtime.NewPager(runtime.PagingHandler[armtrafficmanager.ProfilesClientListByResourceGroupResponse]{
				More: func(_ armtrafficmanager.ProfilesClientListByResourceGroupResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armtrafficmanager.ProfilesClientListByResourceGroupResponse) (armtrafficmanager.ProfilesClientListByResourceGroupResponse, error) {
					return armtrafficmanager.ProfilesClientListByResourceGroupResponse{
						ProfileListResult: armtrafficmanager.ProfileListResult{
							Value: []*armtrafficmanager.Profile{{ID: to.Ptr(testTMProfileNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestTrafficManagerProfile(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "tm-1", Properties: tmDesired("Priority", "HTTP", 60)})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testTMProfileNativeID, got.ProgressResult.NativeID)

		// Traffic Manager is global: ARM rejects a region here.
		require.Equal(t, "global", *sent.Location)
		require.Equal(t, armtrafficmanager.TrafficRoutingMethodPriority, *sent.Properties.TrafficRoutingMethod)
		require.Equal(t, "fpsdt-tm-1", *sent.Properties.DNSConfig.RelativeName)
		require.Equal(t, "/", *sent.Properties.MonitorConfig.Path)

		var props map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &props))
		require.Equal(t, "fpsdt-tm-1.trafficmanager.net", props["fqdn"])
	})

	t.Run("Create_defaults_location_to_global", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "tm-1", "resourceGroupName": "rg-1", "trafficRoutingMethod": "Priority",
			"dnsConfig": map[string]any{"relativeName": "fpsdt-tm-1"},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "tm-1", Properties: props})
		require.NoError(t, err)
		require.Equal(t, "global", *sent.Location)
	})

	// A TCP probe has no path, and ARM rejects one if sent.
	t.Run("Create_omits_path_for_tcp_probe", func(t *testing.T) {
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "tm-1", Properties: tmDesired("Priority", "TCP", 60)})
		require.NoError(t, err)
		require.Equal(t, armtrafficmanager.MonitorProtocolTCP, *sent.Properties.MonitorConfig.Protocol)
		require.Nil(t, sent.Properties.MonitorConfig.Path)
	})

	t.Run("Create_requires_relativeName", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "tm-1", "resourceGroupName": "rg-1", "trafficRoutingMethod": "Priority",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "dnsConfig.relativeName is required")
	})

	t.Run("Create_requires_routing_method", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "tm-1", "resourceGroupName": "rg-1",
			"dnsConfig": map[string]any{"relativeName": "fpsdt-tm-1"},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "trafficRoutingMethod is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testTMProfileNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "tm-1", props["name"])
		require.Equal(t, "global", props["location"])
		require.Equal(t, "Priority", props["trafficRoutingMethod"])
		dns := props["dnsConfig"].(map[string]any)
		require.Equal(t, "fpsdt-tm-1", dns["relativeName"])
		require.EqualValues(t, 60, dns["ttl"])
		mon := props["monitorConfig"].(map[string]any)
		require.Equal(t, "HTTP", mon["protocol"])
	})

	t.Run("Update_keeps_native_id", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testTMProfileNativeID,
			DesiredProperties: tmDesired("Weighted", "HTTP", 300),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testTMProfileNativeID, got.ProgressResult.NativeID)
		require.Equal(t, armtrafficmanager.TrafficRoutingMethodWeighted, *sent.Properties.TrafficRoutingMethod)
		require.EqualValues(t, 300, *sent.Properties.DNSConfig.TTL)
	})

	t.Run("Delete", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testTMProfileNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _ string, _ *armtrafficmanager.ProfilesClientDeleteOptions) (armtrafficmanager.ProfilesClientDeleteResponse, error) {
			return armtrafficmanager.ProfilesClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testTMProfileNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_resource_group", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testTMProfileNativeID}, got.NativeIDs)
	})

	t.Run("List_without_group_is_subscription_wide", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 2)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.createOrUpdateFn = func(_ context.Context, _, _ string, _ armtrafficmanager.Profile, _ *armtrafficmanager.ProfilesClientCreateOrUpdateOptions) (armtrafficmanager.ProfilesClientCreateOrUpdateResponse, error) {
			return armtrafficmanager.ProfilesClientCreateOrUpdateResponse{}, &azcore.ResponseError{StatusCode: 409}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "tm-1", Properties: tmDesired("Priority", "HTTP", 60)})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

func TestTrafficManagerProfile_ReadNotFound(t *testing.T) {
	fake := &fakeTMProfilesAPI{
		getFn: func(_ context.Context, _, _ string, _ *armtrafficmanager.ProfilesClientGetOptions) (armtrafficmanager.ProfilesClientGetResponse, error) {
			return armtrafficmanager.ProfilesClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestTrafficManagerProfile(fake).Read(context.Background(), &resource.ReadRequest{NativeID: testTMProfileNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeTMProfilesAPI struct {
	createOrUpdateFn              func(ctx context.Context, rgName, name string, params armtrafficmanager.Profile, options *armtrafficmanager.ProfilesClientCreateOrUpdateOptions) (armtrafficmanager.ProfilesClientCreateOrUpdateResponse, error)
	getFn                         func(ctx context.Context, rgName, name string, options *armtrafficmanager.ProfilesClientGetOptions) (armtrafficmanager.ProfilesClientGetResponse, error)
	deleteFn                      func(ctx context.Context, rgName, name string, options *armtrafficmanager.ProfilesClientDeleteOptions) (armtrafficmanager.ProfilesClientDeleteResponse, error)
	newListBySubscriptionPagerFn  func(options *armtrafficmanager.ProfilesClientListBySubscriptionOptions) *runtime.Pager[armtrafficmanager.ProfilesClientListBySubscriptionResponse]
	newListByResourceGroupPagerFn func(rgName string, options *armtrafficmanager.ProfilesClientListByResourceGroupOptions) *runtime.Pager[armtrafficmanager.ProfilesClientListByResourceGroupResponse]
}

func (f *fakeTMProfilesAPI) CreateOrUpdate(ctx context.Context, rgName, name string, params armtrafficmanager.Profile, options *armtrafficmanager.ProfilesClientCreateOrUpdateOptions) (armtrafficmanager.ProfilesClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, name, params, options)
}

func (f *fakeTMProfilesAPI) Get(ctx context.Context, rgName, name string, options *armtrafficmanager.ProfilesClientGetOptions) (armtrafficmanager.ProfilesClientGetResponse, error) {
	return f.getFn(ctx, rgName, name, options)
}

func (f *fakeTMProfilesAPI) Delete(ctx context.Context, rgName, name string, options *armtrafficmanager.ProfilesClientDeleteOptions) (armtrafficmanager.ProfilesClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, name, options)
}

func (f *fakeTMProfilesAPI) NewListBySubscriptionPager(options *armtrafficmanager.ProfilesClientListBySubscriptionOptions) *runtime.Pager[armtrafficmanager.ProfilesClientListBySubscriptionResponse] {
	return f.newListBySubscriptionPagerFn(options)
}

func (f *fakeTMProfilesAPI) NewListByResourceGroupPager(rgName string, options *armtrafficmanager.ProfilesClientListByResourceGroupOptions) *runtime.Pager[armtrafficmanager.ProfilesClientListByResourceGroupResponse] {
	return f.newListByResourceGroupPagerFn(rgName, options)
}
