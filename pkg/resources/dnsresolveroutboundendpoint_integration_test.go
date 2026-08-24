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
	testOutboundEndpointNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/dnsResolvers/resolver-1/outboundEndpoints/outbound-1"
	testOutboundEndpointSubnetID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/virtualNetworks/vnet-1/subnets/resolver-subnet"
)

func newTestOutboundEndpoint(api dnsResolverOutboundEndpointsAPI) *DNSResolverOutboundEndpoint {
	return &DNSResolverOutboundEndpoint{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func outboundEndpointDesired(tagValue string) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":              "outbound-1",
		"location":          "eastus",
		"resourceGroupName": "rg-1",
		"dnsResolverName":   "resolver-1",
		"subnetId":          testOutboundEndpointSubnetID,
		"Tags":              []any{map[string]any{"Key": "env", "Value": tagValue}},
	})
	return out
}

func TestDNSResolverOutboundEndpoint_CRUD(t *testing.T) {
	endpointResult := armdnsresolver.OutboundEndpoint{
		ID:       to.Ptr(testOutboundEndpointNativeID),
		Name:     to.Ptr("outbound-1"),
		Location: to.Ptr("East US"),
		Properties: &armdnsresolver.OutboundEndpointProperties{
			Subnet:            &armdnsresolver.SubResource{ID: to.Ptr(testOutboundEndpointSubnetID)},
			ProvisioningState: to.Ptr(armdnsresolver.ProvisioningStateSucceeded),
			ResourceGUID:      to.Ptr("11111111-2222-3333-4444-555555555555"),
		},
		Tags: map[string]*string{"env": to.Ptr("test")},
	}

	var sentCreate armdnsresolver.OutboundEndpoint
	var sentPatch armdnsresolver.OutboundEndpointPatch
	var sawResolverName string
	deleteCalls := 0
	fake := &fakeOutboundEndpointsAPI{
		beginCreateOrUpdateFn: func(_ context.Context, _, resolverName, name string, params armdnsresolver.OutboundEndpoint, _ *armdnsresolver.OutboundEndpointsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armdnsresolver.OutboundEndpointsClientCreateOrUpdateResponse], error) {
			require.Equal(t, "outbound-1", name)
			sawResolverName = resolverName
			sentCreate = params
			return newDonePoller(armdnsresolver.OutboundEndpointsClientCreateOrUpdateResponse{OutboundEndpoint: endpointResult}), nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ *armdnsresolver.OutboundEndpointsClientGetOptions) (armdnsresolver.OutboundEndpointsClientGetResponse, error) {
			return armdnsresolver.OutboundEndpointsClientGetResponse{OutboundEndpoint: endpointResult}, nil
		},
		beginUpdateFn: func(_ context.Context, _, _, _ string, params armdnsresolver.OutboundEndpointPatch, _ *armdnsresolver.OutboundEndpointsClientBeginUpdateOptions) (*runtime.Poller[armdnsresolver.OutboundEndpointsClientUpdateResponse], error) {
			sentPatch = params
			return newDonePoller(armdnsresolver.OutboundEndpointsClientUpdateResponse{OutboundEndpoint: endpointResult}), nil
		},
		beginDeleteFn: func(_ context.Context, _, _, _ string, _ *armdnsresolver.OutboundEndpointsClientBeginDeleteOptions) (*runtime.Poller[armdnsresolver.OutboundEndpointsClientDeleteResponse], error) {
			deleteCalls++
			return newDonePoller(armdnsresolver.OutboundEndpointsClientDeleteResponse{}), nil
		},
		newListPagerFn: func(_, _ string, _ *armdnsresolver.OutboundEndpointsClientListOptions) *runtime.Pager[armdnsresolver.OutboundEndpointsClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armdnsresolver.OutboundEndpointsClientListResponse]{
				More: func(_ armdnsresolver.OutboundEndpointsClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armdnsresolver.OutboundEndpointsClientListResponse) (armdnsresolver.OutboundEndpointsClientListResponse, error) {
					return armdnsresolver.OutboundEndpointsClientListResponse{
						OutboundEndpointListResult: armdnsresolver.OutboundEndpointListResult{
							Value: []*armdnsresolver.OutboundEndpoint{{ID: to.Ptr(testOutboundEndpointNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestOutboundEndpoint(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "outbound-1",
			Properties: outboundEndpointDesired("test"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testOutboundEndpointNativeID, got.ProgressResult.NativeID)
		require.Equal(t, "resolver-1", sawResolverName)
		require.Equal(t, testOutboundEndpointSubnetID, *sentCreate.Properties.Subnet.ID)
	})

	t.Run("Create_requires_subnet", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "outbound-1", "location": "eastus",
			"resourceGroupName": "rg-1", "dnsResolverName": "resolver-1",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "subnetId is required")
	})

	t.Run("Create_requires_resolver", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "outbound-1", "location": "eastus", "resourceGroupName": "rg-1",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "dnsResolverName is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testOutboundEndpointNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "outbound-1", props["name"])
		// ARM returns "East US"; read must normalise or desired state drifts.
		require.Equal(t, "eastus", props["location"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		// The parent resolver name comes from the native ID, not the response body.
		require.Equal(t, "resolver-1", props["dnsResolverName"])

		require.Equal(t, testOutboundEndpointSubnetID, props["subnetId"])
	})

	t.Run("Read_drops_service_bookkeeping", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testOutboundEndpointNativeID})
		require.NoError(t, err)
		require.NotContains(t, got.Properties, "provisioningState")
		require.NotContains(t, got.Properties, "resourceGuid")
	})

	// OutboundEndpointPatch carries tags and nothing else, so a tag change is the
	// only in-place update this resource has.
	t.Run("Update_sends_tags", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testOutboundEndpointNativeID,
			DesiredProperties: outboundEndpointDesired("updated"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, "updated", *sentPatch.Tags["env"])
	})

	t.Run("Delete", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testOutboundEndpointNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _, _ string, _ *armdnsresolver.OutboundEndpointsClientBeginDeleteOptions) (*runtime.Poller[armdnsresolver.OutboundEndpointsClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testOutboundEndpointNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_resolver", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "dnsResolverName": "resolver-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testOutboundEndpointNativeID}, got.NativeIDs)
	})

	// ARM has no subscription-wide listing here: without both parents there is
	// nothing to page, so List must return empty rather than error.
	t.Run("List_without_parents_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _, _ string, _ armdnsresolver.OutboundEndpoint, _ *armdnsresolver.OutboundEndpointsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armdnsresolver.OutboundEndpointsClientCreateOrUpdateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 409}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "outbound-1", Properties: outboundEndpointDesired("test"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

func TestDNSResolverOutboundEndpoint_ReadNotFound(t *testing.T) {
	fake := &fakeOutboundEndpointsAPI{
		getFn: func(_ context.Context, _, _, _ string, _ *armdnsresolver.OutboundEndpointsClientGetOptions) (armdnsresolver.OutboundEndpointsClientGetResponse, error) {
			return armdnsresolver.OutboundEndpointsClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestOutboundEndpoint(fake).Read(context.Background(), &resource.ReadRequest{NativeID: testOutboundEndpointNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeOutboundEndpointsAPI struct {
	beginCreateOrUpdateFn func(ctx context.Context, rgName, resolverName, name string, params armdnsresolver.OutboundEndpoint, options *armdnsresolver.OutboundEndpointsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armdnsresolver.OutboundEndpointsClientCreateOrUpdateResponse], error)
	getFn                 func(ctx context.Context, rgName, resolverName, name string, options *armdnsresolver.OutboundEndpointsClientGetOptions) (armdnsresolver.OutboundEndpointsClientGetResponse, error)
	beginUpdateFn         func(ctx context.Context, rgName, resolverName, name string, params armdnsresolver.OutboundEndpointPatch, options *armdnsresolver.OutboundEndpointsClientBeginUpdateOptions) (*runtime.Poller[armdnsresolver.OutboundEndpointsClientUpdateResponse], error)
	beginDeleteFn         func(ctx context.Context, rgName, resolverName, name string, options *armdnsresolver.OutboundEndpointsClientBeginDeleteOptions) (*runtime.Poller[armdnsresolver.OutboundEndpointsClientDeleteResponse], error)
	newListPagerFn        func(rgName, resolverName string, options *armdnsresolver.OutboundEndpointsClientListOptions) *runtime.Pager[armdnsresolver.OutboundEndpointsClientListResponse]
}

func (f *fakeOutboundEndpointsAPI) BeginCreateOrUpdate(ctx context.Context, rgName, resolverName, name string, params armdnsresolver.OutboundEndpoint, options *armdnsresolver.OutboundEndpointsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armdnsresolver.OutboundEndpointsClientCreateOrUpdateResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, rgName, resolverName, name, params, options)
}

func (f *fakeOutboundEndpointsAPI) Get(ctx context.Context, rgName, resolverName, name string, options *armdnsresolver.OutboundEndpointsClientGetOptions) (armdnsresolver.OutboundEndpointsClientGetResponse, error) {
	return f.getFn(ctx, rgName, resolverName, name, options)
}

func (f *fakeOutboundEndpointsAPI) BeginUpdate(ctx context.Context, rgName, resolverName, name string, params armdnsresolver.OutboundEndpointPatch, options *armdnsresolver.OutboundEndpointsClientBeginUpdateOptions) (*runtime.Poller[armdnsresolver.OutboundEndpointsClientUpdateResponse], error) {
	return f.beginUpdateFn(ctx, rgName, resolverName, name, params, options)
}

func (f *fakeOutboundEndpointsAPI) BeginDelete(ctx context.Context, rgName, resolverName, name string, options *armdnsresolver.OutboundEndpointsClientBeginDeleteOptions) (*runtime.Poller[armdnsresolver.OutboundEndpointsClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, resolverName, name, options)
}

func (f *fakeOutboundEndpointsAPI) NewListPager(rgName, resolverName string, options *armdnsresolver.OutboundEndpointsClientListOptions) *runtime.Pager[armdnsresolver.OutboundEndpointsClientListResponse] {
	return f.newListPagerFn(rgName, resolverName, options)
}
