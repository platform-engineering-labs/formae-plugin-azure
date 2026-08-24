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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/dnsresolver/armdnsresolver"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const (
	testInboundEndpointNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/dnsResolvers/resolver-1/inboundEndpoints/inbound-1"
	testInboundEndpointSubnetID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/virtualNetworks/vnet-1/subnets/resolver-subnet"
)

func newTestInboundEndpoint(api dnsResolverInboundEndpointsAPI) *DNSResolverInboundEndpoint {
	return &DNSResolverInboundEndpoint{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func inboundEndpointDesired(tagValue string) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":              "inbound-1",
		"location":          "eastus",
		"resourceGroupName": "rg-1",
		"dnsResolverName":   "resolver-1",
		"ipConfigurations": []any{map[string]any{
			"subnetId":                  testInboundEndpointSubnetID,
			"privateIpAllocationMethod": "Dynamic",
		}},
		"Tags": []any{map[string]any{"Key": "env", "Value": tagValue}},
	})
	return out
}

func TestDNSResolverInboundEndpoint_CRUD(t *testing.T) {
	endpointResult := armdnsresolver.InboundEndpoint{
		ID:       to.Ptr(testInboundEndpointNativeID),
		Name:     to.Ptr("inbound-1"),
		Location: to.Ptr("East US"),
		Properties: &armdnsresolver.InboundEndpointProperties{
			IPConfigurations: []*armdnsresolver.IPConfiguration{{
				Subnet:                    &armdnsresolver.SubResource{ID: to.Ptr(testInboundEndpointSubnetID)},
				PrivateIPAddress:          to.Ptr("10.0.1.4"),
				PrivateIPAllocationMethod: to.Ptr(armdnsresolver.IPAllocationMethodDynamic),
			}},
			ProvisioningState: to.Ptr(armdnsresolver.ProvisioningStateSucceeded),
			ResourceGUID:      to.Ptr("11111111-2222-3333-4444-555555555555"),
		},
		Tags: map[string]*string{"env": to.Ptr("test")},
	}

	var sentCreate armdnsresolver.InboundEndpoint
	var sentPatch armdnsresolver.InboundEndpointPatch
	var sawResolverName string
	deleteCalls := 0
	fake := &fakeInboundEndpointsAPI{
		beginCreateOrUpdateFn: func(_ context.Context, _, resolverName, name string, params armdnsresolver.InboundEndpoint, _ *armdnsresolver.InboundEndpointsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armdnsresolver.InboundEndpointsClientCreateOrUpdateResponse], error) {
			require.Equal(t, "inbound-1", name)
			sawResolverName = resolverName
			sentCreate = params
			return newDonePoller(armdnsresolver.InboundEndpointsClientCreateOrUpdateResponse{InboundEndpoint: endpointResult}), nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ *armdnsresolver.InboundEndpointsClientGetOptions) (armdnsresolver.InboundEndpointsClientGetResponse, error) {
			return armdnsresolver.InboundEndpointsClientGetResponse{InboundEndpoint: endpointResult}, nil
		},
		beginUpdateFn: func(_ context.Context, _, _, _ string, params armdnsresolver.InboundEndpointPatch, _ *armdnsresolver.InboundEndpointsClientBeginUpdateOptions) (*runtime.Poller[armdnsresolver.InboundEndpointsClientUpdateResponse], error) {
			sentPatch = params
			return newDonePoller(armdnsresolver.InboundEndpointsClientUpdateResponse{InboundEndpoint: endpointResult}), nil
		},
		beginDeleteFn: func(_ context.Context, _, _, _ string, _ *armdnsresolver.InboundEndpointsClientBeginDeleteOptions) (*runtime.Poller[armdnsresolver.InboundEndpointsClientDeleteResponse], error) {
			deleteCalls++
			return newDonePoller(armdnsresolver.InboundEndpointsClientDeleteResponse{}), nil
		},
		newListPagerFn: func(_, _ string, _ *armdnsresolver.InboundEndpointsClientListOptions) *runtime.Pager[armdnsresolver.InboundEndpointsClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armdnsresolver.InboundEndpointsClientListResponse]{
				More: func(_ armdnsresolver.InboundEndpointsClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armdnsresolver.InboundEndpointsClientListResponse) (armdnsresolver.InboundEndpointsClientListResponse, error) {
					return armdnsresolver.InboundEndpointsClientListResponse{
						InboundEndpointListResult: armdnsresolver.InboundEndpointListResult{
							Value: []*armdnsresolver.InboundEndpoint{{ID: to.Ptr(testInboundEndpointNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestInboundEndpoint(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "inbound-1",
			Properties: inboundEndpointDesired("test"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testInboundEndpointNativeID, got.ProgressResult.NativeID)
		require.Equal(t, "resolver-1", sawResolverName)
		require.Len(t, sentCreate.Properties.IPConfigurations, 1)
		require.Equal(t, testInboundEndpointSubnetID, *sentCreate.Properties.IPConfigurations[0].Subnet.ID)
		require.Equal(t, armdnsresolver.IPAllocationMethodDynamic, *sentCreate.Properties.IPConfigurations[0].PrivateIPAllocationMethod)
		// privateIpAddress was not requested, so it must not be sent: ARM rejects a
		// static address on a Dynamic allocation.
		require.Nil(t, sentCreate.Properties.IPConfigurations[0].PrivateIPAddress)
	})

	t.Run("Create_requires_ip_configurations", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "inbound-1", "location": "eastus",
			"resourceGroupName": "rg-1", "dnsResolverName": "resolver-1",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "ipConfigurations is required")
	})

	t.Run("Create_requires_subnet", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "inbound-1", "location": "eastus",
			"resourceGroupName": "rg-1", "dnsResolverName": "resolver-1",
			"ipConfigurations": []any{map[string]any{"privateIpAllocationMethod": "Dynamic"}},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "subnetId is required")
	})

	t.Run("Create_requires_resolver", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "inbound-1", "location": "eastus", "resourceGroupName": "rg-1",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "dnsResolverName is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testInboundEndpointNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "inbound-1", props["name"])
		// ARM returns "East US"; read must normalise or desired state drifts.
		require.Equal(t, "eastus", props["location"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		// The parent resolver name comes from the native ID, not the response body.
		require.Equal(t, "resolver-1", props["dnsResolverName"])

		ipConfigs := props["ipConfigurations"].([]any)
		require.Len(t, ipConfigs, 1)
		cfg := ipConfigs[0].(map[string]any)
		require.Equal(t, testInboundEndpointSubnetID, cfg["subnetId"])
		require.Equal(t, "Dynamic", cfg["privateIpAllocationMethod"])
		// Dynamically allocated: the address belongs in the top-level output, not
		// inside the ipConfiguration (see below).
		require.NotContains(t, cfg, "privateIpAddress")
		require.Equal(t, []any{"10.0.1.4"}, props["privateIpAddresses"])
	})

	t.Run("Read_drops_service_bookkeeping", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testInboundEndpointNativeID})
		require.NoError(t, err)
		require.NotContains(t, got.Properties, "provisioningState")
		require.NotContains(t, got.Properties, "resourceGuid")
	})

	// InboundEndpointPatch carries tags and nothing else, so a tag change is the
	// only in-place update this resource has.
	t.Run("Update_sends_tags", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testInboundEndpointNativeID,
			DesiredProperties: inboundEndpointDesired("updated"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, "updated", *sentPatch.Tags["env"])
	})

	t.Run("Delete", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testInboundEndpointNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _, _ string, _ *armdnsresolver.InboundEndpointsClientBeginDeleteOptions) (*runtime.Poller[armdnsresolver.InboundEndpointsClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testInboundEndpointNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_resolver", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "dnsResolverName": "resolver-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testInboundEndpointNativeID}, got.NativeIDs)
	})

	// ARM has no subscription-wide listing here: without both parents there is
	// nothing to page, so List must return empty rather than error.
	t.Run("List_without_parents_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _, _ string, _ armdnsresolver.InboundEndpoint, _ *armdnsresolver.InboundEndpointsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armdnsresolver.InboundEndpointsClientCreateOrUpdateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 409}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "inbound-1", Properties: inboundEndpointDesired("test"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

func TestDNSResolverInboundEndpoint_ReadNotFound(t *testing.T) {
	fake := &fakeInboundEndpointsAPI{
		getFn: func(_ context.Context, _, _, _ string, _ *armdnsresolver.InboundEndpointsClientGetOptions) (armdnsresolver.InboundEndpointsClientGetResponse, error) {
			return armdnsresolver.InboundEndpointsClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestInboundEndpoint(fake).Read(context.Background(), &resource.ReadRequest{NativeID: testInboundEndpointNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeInboundEndpointsAPI struct {
	beginCreateOrUpdateFn func(ctx context.Context, rgName, resolverName, name string, params armdnsresolver.InboundEndpoint, options *armdnsresolver.InboundEndpointsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armdnsresolver.InboundEndpointsClientCreateOrUpdateResponse], error)
	getFn                 func(ctx context.Context, rgName, resolverName, name string, options *armdnsresolver.InboundEndpointsClientGetOptions) (armdnsresolver.InboundEndpointsClientGetResponse, error)
	beginUpdateFn         func(ctx context.Context, rgName, resolverName, name string, params armdnsresolver.InboundEndpointPatch, options *armdnsresolver.InboundEndpointsClientBeginUpdateOptions) (*runtime.Poller[armdnsresolver.InboundEndpointsClientUpdateResponse], error)
	beginDeleteFn         func(ctx context.Context, rgName, resolverName, name string, options *armdnsresolver.InboundEndpointsClientBeginDeleteOptions) (*runtime.Poller[armdnsresolver.InboundEndpointsClientDeleteResponse], error)
	newListPagerFn        func(rgName, resolverName string, options *armdnsresolver.InboundEndpointsClientListOptions) *runtime.Pager[armdnsresolver.InboundEndpointsClientListResponse]
}

func (f *fakeInboundEndpointsAPI) BeginCreateOrUpdate(ctx context.Context, rgName, resolverName, name string, params armdnsresolver.InboundEndpoint, options *armdnsresolver.InboundEndpointsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armdnsresolver.InboundEndpointsClientCreateOrUpdateResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, rgName, resolverName, name, params, options)
}

func (f *fakeInboundEndpointsAPI) Get(ctx context.Context, rgName, resolverName, name string, options *armdnsresolver.InboundEndpointsClientGetOptions) (armdnsresolver.InboundEndpointsClientGetResponse, error) {
	return f.getFn(ctx, rgName, resolverName, name, options)
}

func (f *fakeInboundEndpointsAPI) BeginUpdate(ctx context.Context, rgName, resolverName, name string, params armdnsresolver.InboundEndpointPatch, options *armdnsresolver.InboundEndpointsClientBeginUpdateOptions) (*runtime.Poller[armdnsresolver.InboundEndpointsClientUpdateResponse], error) {
	return f.beginUpdateFn(ctx, rgName, resolverName, name, params, options)
}

func (f *fakeInboundEndpointsAPI) BeginDelete(ctx context.Context, rgName, resolverName, name string, options *armdnsresolver.InboundEndpointsClientBeginDeleteOptions) (*runtime.Poller[armdnsresolver.InboundEndpointsClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, resolverName, name, options)
}

func (f *fakeInboundEndpointsAPI) NewListPager(rgName, resolverName string, options *armdnsresolver.InboundEndpointsClientListOptions) *runtime.Pager[armdnsresolver.InboundEndpointsClientListResponse] {
	return f.newListPagerFn(rgName, resolverName, options)
}

// With Static allocation the caller chose the address, so echoing it back inside
// the ipConfiguration matches desired state. With Dynamic allocation ARM chose it
// and echoing it there fails conformance [Verify] ("not expected and not a
// provider default"), because hasProviderDefault is not honoured on fields of a
// nested class — only on top-level resource fields. Either way the effective
// address is reported through the top-level privateIpAddresses output.
func TestDNSResolverInboundEndpoint_StaticAddressIsEchoed(t *testing.T) {
	fake := &fakeInboundEndpointsAPI{
		getFn: func(_ context.Context, _, _, _ string, _ *armdnsresolver.InboundEndpointsClientGetOptions) (armdnsresolver.InboundEndpointsClientGetResponse, error) {
			return armdnsresolver.InboundEndpointsClientGetResponse{InboundEndpoint: armdnsresolver.InboundEndpoint{
				ID:   to.Ptr(testInboundEndpointNativeID),
				Name: to.Ptr("inbound-1"),
				Properties: &armdnsresolver.InboundEndpointProperties{
					IPConfigurations: []*armdnsresolver.IPConfiguration{{
						Subnet:                    &armdnsresolver.SubResource{ID: to.Ptr(testInboundEndpointSubnetID)},
						PrivateIPAddress:          to.Ptr("10.0.1.9"),
						PrivateIPAllocationMethod: to.Ptr(armdnsresolver.IPAllocationMethodStatic),
					}},
				},
			}}, nil
		},
	}
	got, err := newTestInboundEndpoint(fake).Read(context.Background(), &resource.ReadRequest{NativeID: testInboundEndpointNativeID})
	require.NoError(t, err)

	var props map[string]any
	require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
	cfg := props["ipConfigurations"].([]any)[0].(map[string]any)
	require.Equal(t, "10.0.1.9", cfg["privateIpAddress"])
	require.Equal(t, []any{"10.0.1.9"}, props["privateIpAddresses"])
}
