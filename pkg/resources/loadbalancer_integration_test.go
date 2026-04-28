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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v4"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testLBNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/loadBalancers/lb-1"
const testLBPipID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/publicIPAddresses/pip-1"

func TestLoadBalancer_CRUD(t *testing.T) {
	standardSKU := armnetwork.LoadBalancerSKUNameStandard
	standardTier := armnetwork.LoadBalancerSKUTierRegional
	tcp := armnetwork.TransportProtocolTCP
	tcpProbe := armnetwork.ProbeProtocolTCP

	donePollerResult := armnetwork.LoadBalancersClientCreateOrUpdateResponse{
		LoadBalancer: armnetwork.LoadBalancer{
			ID:       to.Ptr(testLBNativeID),
			Name:     to.Ptr("lb-1"),
			Location: to.Ptr("eastus"),
			SKU: &armnetwork.LoadBalancerSKU{
				Name: &standardSKU,
				Tier: &standardTier,
			},
			Properties: &armnetwork.LoadBalancerPropertiesFormat{
				FrontendIPConfigurations: []*armnetwork.FrontendIPConfiguration{
					{
						Name: to.Ptr("fe-1"),
						Properties: &armnetwork.FrontendIPConfigurationPropertiesFormat{
							PublicIPAddress: &armnetwork.PublicIPAddress{ID: to.Ptr(testLBPipID)},
						},
					},
				},
				BackendAddressPools: []*armnetwork.BackendAddressPool{
					{Name: to.Ptr("be-1")},
				},
				Probes: []*armnetwork.Probe{
					{
						Name: to.Ptr("hp-1"),
						Properties: &armnetwork.ProbePropertiesFormat{
							Protocol: &tcpProbe,
							Port:     to.Ptr[int32](80),
						},
					},
				},
				LoadBalancingRules: []*armnetwork.LoadBalancingRule{
					{
						Name: to.Ptr("rule-1"),
						Properties: &armnetwork.LoadBalancingRulePropertiesFormat{
							FrontendIPConfiguration: &armnetwork.SubResource{ID: to.Ptr(testLBNativeID + "/frontendIPConfigurations/fe-1")},
							BackendAddressPool:      &armnetwork.SubResource{ID: to.Ptr(testLBNativeID + "/backendAddressPools/be-1")},
							Probe:                   &armnetwork.SubResource{ID: to.Ptr(testLBNativeID + "/probes/hp-1")},
							Protocol:                &tcp,
							FrontendPort:            to.Ptr[int32](80),
							BackendPort:             to.Ptr[int32](80),
						},
					},
				},
			},
		},
	}

	fake := &fakeLoadBalancersAPI{
		beginCreateOrUpdateFn: func(_ context.Context, _, _ string, _ armnetwork.LoadBalancer, _ *armnetwork.LoadBalancersClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.LoadBalancersClientCreateOrUpdateResponse], error) {
			return newDonePoller(donePollerResult), nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armnetwork.LoadBalancersClientGetOptions) (armnetwork.LoadBalancersClientGetResponse, error) {
			return armnetwork.LoadBalancersClientGetResponse{LoadBalancer: donePollerResult.LoadBalancer}, nil
		},
		beginDeleteFn: func(_ context.Context, _, _ string, _ *armnetwork.LoadBalancersClientBeginDeleteOptions) (*runtime.Poller[armnetwork.LoadBalancersClientDeleteResponse], error) {
			return newInProgressPoller[armnetwork.LoadBalancersClientDeleteResponse](), nil
		},
		newListAllPagerFn: func(_ *armnetwork.LoadBalancersClientListAllOptions) *runtime.Pager[armnetwork.LoadBalancersClientListAllResponse] {
			return runtime.NewPager(runtime.PagingHandler[armnetwork.LoadBalancersClientListAllResponse]{
				More: func(_ armnetwork.LoadBalancersClientListAllResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armnetwork.LoadBalancersClientListAllResponse) (armnetwork.LoadBalancersClientListAllResponse, error) {
					return armnetwork.LoadBalancersClientListAllResponse{
						LoadBalancerListResult: armnetwork.LoadBalancerListResult{
							Value: []*armnetwork.LoadBalancer{{ID: to.Ptr(testLBNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestLoadBalancer(fake)

	createProps := func() json.RawMessage {
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName": "rg-1",
			"name":              "lb-1",
			"location":          "eastus",
			"sku":               map[string]any{"name": "Standard", "tier": "Regional"},
			"frontendIPConfigurations": []map[string]any{
				{"name": "fe-1", "publicIPAddressId": testLBPipID},
			},
			"backendAddressPools": []map[string]any{{"name": "be-1"}},
			"probes": []map[string]any{
				{"name": "hp-1", "protocol": "Tcp", "port": 80},
			},
			"loadBalancingRules": []map[string]any{
				{
					"name":                        "rule-1",
					"frontendIPConfigurationName": "fe-1",
					"backendAddressPoolName":      "be-1",
					"probeName":                   "hp-1",
					"protocol":                    "Tcp",
					"frontendPort":                80,
					"backendPort":                 80,
				},
			},
		})
		return props
	}

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: createProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testLBNativeID, got.ProgressResult.NativeID)

		var props map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &props))
		require.Equal(t, "lb-1", props["name"])
		rules, ok := props["loadBalancingRules"].([]any)
		require.True(t, ok, "loadBalancingRules should round-trip")
		require.Len(t, rules, 1)
		rule0 := rules[0].(map[string]any)
		require.Equal(t, "fe-1", rule0["frontendIPConfigurationName"])
		require.Equal(t, "be-1", rule0["backendAddressPoolName"])
		require.Equal(t, "hp-1", rule0["probeName"])
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testLBNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "lb-1", props["name"])
	})

	t.Run("Delete", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testLBNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusInProgress, got.ProgressResult.OperationStatus)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _ string, _ *armnetwork.LoadBalancersClientBeginDeleteOptions) (*runtime.Poller[armnetwork.LoadBalancersClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testLBNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{},
		})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 1)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, _ armnetwork.LoadBalancer, _ *armnetwork.LoadBalancersClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.LoadBalancersClientCreateOrUpdateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 403}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: createProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

// --- Test helpers ---

func newTestLoadBalancer(api loadBalancersAPI) *LoadBalancer {
	return &LoadBalancer{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

type fakeLoadBalancersAPI struct {
	beginCreateOrUpdateFn func(ctx context.Context, rgName, lbName string, params armnetwork.LoadBalancer, opts *armnetwork.LoadBalancersClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.LoadBalancersClientCreateOrUpdateResponse], error)
	getFn                 func(ctx context.Context, rgName, lbName string, opts *armnetwork.LoadBalancersClientGetOptions) (armnetwork.LoadBalancersClientGetResponse, error)
	beginDeleteFn         func(ctx context.Context, rgName, lbName string, opts *armnetwork.LoadBalancersClientBeginDeleteOptions) (*runtime.Poller[armnetwork.LoadBalancersClientDeleteResponse], error)
	newListPagerFn        func(rgName string, opts *armnetwork.LoadBalancersClientListOptions) *runtime.Pager[armnetwork.LoadBalancersClientListResponse]
	newListAllPagerFn     func(opts *armnetwork.LoadBalancersClientListAllOptions) *runtime.Pager[armnetwork.LoadBalancersClientListAllResponse]
}

func (f *fakeLoadBalancersAPI) BeginCreateOrUpdate(ctx context.Context, rgName, lbName string, params armnetwork.LoadBalancer, opts *armnetwork.LoadBalancersClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.LoadBalancersClientCreateOrUpdateResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, rgName, lbName, params, opts)
}

func (f *fakeLoadBalancersAPI) Get(ctx context.Context, rgName, lbName string, opts *armnetwork.LoadBalancersClientGetOptions) (armnetwork.LoadBalancersClientGetResponse, error) {
	return f.getFn(ctx, rgName, lbName, opts)
}

func (f *fakeLoadBalancersAPI) BeginDelete(ctx context.Context, rgName, lbName string, opts *armnetwork.LoadBalancersClientBeginDeleteOptions) (*runtime.Poller[armnetwork.LoadBalancersClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, lbName, opts)
}

func (f *fakeLoadBalancersAPI) NewListPager(rgName string, opts *armnetwork.LoadBalancersClientListOptions) *runtime.Pager[armnetwork.LoadBalancersClientListResponse] {
	return f.newListPagerFn(rgName, opts)
}

func (f *fakeLoadBalancersAPI) NewListAllPager(opts *armnetwork.LoadBalancersClientListAllOptions) *runtime.Pager[armnetwork.LoadBalancersClientListAllResponse] {
	return f.newListAllPagerFn(opts)
}
