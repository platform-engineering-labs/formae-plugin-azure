// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v4"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testSubnetNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/virtualNetworks/vnet-1/subnets/subnet-1"

func TestSubnet_CRUD(t *testing.T) {
	fake := &fakeSubnetsAPI{
		beginCreateOrUpdateFn: func(_ context.Context, _, _, _ string, _ armnetwork.Subnet, _ *armnetwork.SubnetsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.SubnetsClientCreateOrUpdateResponse], error) {
			return newDoneCreateSubnetPoller(armnetwork.SubnetsClientCreateOrUpdateResponse{
				Subnet: armnetwork.Subnet{
					ID:   to.Ptr(testSubnetNativeID),
					Name: to.Ptr("subnet-1"),
					Properties: &armnetwork.SubnetPropertiesFormat{
						AddressPrefix: to.Ptr("10.0.1.0/24"),
					},
				},
			}), nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ *armnetwork.SubnetsClientGetOptions) (armnetwork.SubnetsClientGetResponse, error) {
			return armnetwork.SubnetsClientGetResponse{
				Subnet: armnetwork.Subnet{
					ID:   to.Ptr(testSubnetNativeID),
					Name: to.Ptr("subnet-1"),
					Properties: &armnetwork.SubnetPropertiesFormat{
						AddressPrefix: to.Ptr("10.0.1.0/24"),
					},
				},
			}, nil
		},
		beginDeleteFn: func(_ context.Context, _, _, _ string, _ *armnetwork.SubnetsClientBeginDeleteOptions) (*runtime.Poller[armnetwork.SubnetsClientDeleteResponse], error) {
			return newPendingDeleteSubnetPoller(), nil
		},
		newListPagerFn: func(_, _ string, _ *armnetwork.SubnetsClientListOptions) *runtime.Pager[armnetwork.SubnetsClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armnetwork.SubnetsClientListResponse]{
				More: func(_ armnetwork.SubnetsClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armnetwork.SubnetsClientListResponse) (armnetwork.SubnetsClientListResponse, error) {
					return armnetwork.SubnetsClientListResponse{
						SubnetListResult: armnetwork.SubnetListResult{
							Value: []*armnetwork.Subnet{{ID: to.Ptr(testSubnetNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestSubnet(fake)

	t.Run("Create", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName": "rg-1", "virtualNetworkName": "vnet-1",
			"name": "subnet-1", "addressPrefix": "10.0.1.0/24",
		})
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testSubnetNativeID, got.ProgressResult.NativeID)
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testSubnetNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "subnet-1", props["name"])
	})

	t.Run("Delete", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testSubnetNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusInProgress, got.ProgressResult.OperationStatus)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _, _ string, _ *armnetwork.SubnetsClientBeginDeleteOptions) (*runtime.Poller[armnetwork.SubnetsClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testSubnetNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "virtualNetworkName": "vnet-1"},
		})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 1)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _, _ string, _ armnetwork.Subnet, _ *armnetwork.SubnetsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.SubnetsClientCreateOrUpdateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 403}
		}
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName": "rg-1", "virtualNetworkName": "vnet-1",
			"name": "subnet-1", "addressPrefix": "10.0.1.0/24",
		})
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

// Delegated subnets are the prerequisite for DNS resolver endpoints, NetApp
// volumes and App Service vnet integration, so the delegation must survive both
// the create body and the read-back.
func TestSubnet_DelegationsRoundTrip(t *testing.T) {
	const subnetID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/virtualNetworks/vnet-1/subnets/subnet-1"

	var sent armnetwork.Subnet
	fake := &fakeSubnetsAPI{
		beginCreateOrUpdateFn: func(_ context.Context, _, _, _ string, params armnetwork.Subnet, _ *armnetwork.SubnetsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.SubnetsClientCreateOrUpdateResponse], error) {
			sent = params
			return newDoneCreateSubnetPoller(armnetwork.SubnetsClientCreateOrUpdateResponse{Subnet: armnetwork.Subnet{
				ID:   to.Ptr(subnetID),
				Name: to.Ptr("subnet-1"),
				Properties: &armnetwork.SubnetPropertiesFormat{
					AddressPrefix: to.Ptr("10.0.1.0/28"),
					Delegations: []*armnetwork.Delegation{{
						Name: to.Ptr("dnsresolver"),
						Properties: &armnetwork.ServiceDelegationPropertiesFormat{
							ServiceName: to.Ptr("Microsoft.Network/dnsResolvers"),
						},
					}},
				},
			}}), nil
		},
	}

	props, _ := json.Marshal(map[string]any{
		"name":               "subnet-1",
		"resourceGroupName":  "rg-1",
		"virtualNetworkName": "vnet-1",
		"addressPrefix":      "10.0.1.0/28",
		"delegations": []any{map[string]any{
			"name":        "dnsresolver",
			"serviceName": "Microsoft.Network/dnsResolvers",
		}},
	})
	got, err := newTestSubnet(fake).Create(context.Background(), &resource.CreateRequest{Properties: props})
	require.NoError(t, err)

	require.Len(t, sent.Properties.Delegations, 1)
	require.Equal(t, "dnsresolver", *sent.Properties.Delegations[0].Name)
	// serviceName goes out verbatim: ARM echoes back the exact casing it was given.
	require.Equal(t, "Microsoft.Network/dnsResolvers", *sent.Properties.Delegations[0].Properties.ServiceName)

	var out map[string]any
	require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &out))
	delegations := out["delegations"].([]any)
	require.Len(t, delegations, 1)
	require.Equal(t, "Microsoft.Network/dnsResolvers", delegations[0].(map[string]any)["serviceName"])
}

// An undelegated subnet must not grow an empty delegations key, or every plain
// subnet would read back as drifting.
func TestSubnet_NoDelegationsStaysAbsent(t *testing.T) {
	fake := &fakeSubnetsAPI{
		getFn: func(_ context.Context, _, _, _ string, _ *armnetwork.SubnetsClientGetOptions) (armnetwork.SubnetsClientGetResponse, error) {
			return armnetwork.SubnetsClientGetResponse{Subnet: armnetwork.Subnet{
				ID:         to.Ptr("/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/virtualNetworks/vnet-1/subnets/subnet-1"),
				Name:       to.Ptr("subnet-1"),
				Properties: &armnetwork.SubnetPropertiesFormat{AddressPrefix: to.Ptr("10.0.0.0/24")},
			}}, nil
		},
	}
	got, err := newTestSubnet(fake).Read(context.Background(), &resource.ReadRequest{
		NativeID: "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/virtualNetworks/vnet-1/subnets/subnet-1",
	})
	require.NoError(t, err)
	require.NotContains(t, got.Properties, "delegations")
}

// --- Test helpers ---

func newTestSubnet(api subnetsAPI) *Subnet {
	return &Subnet{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

// subnetDoneHandler is a PollingHandler that reports Done() immediately and populates
// out from the stored response on Result().
type subnetDoneHandler[T any] struct {
	resp T
}

func (h *subnetDoneHandler[T]) Done() bool                                     { return true }
func (h *subnetDoneHandler[T]) Poll(_ context.Context) (*http.Response, error) { return nil, nil }
func (h *subnetDoneHandler[T]) Result(_ context.Context, out *T) error         { *out = h.resp; return nil }

func newDoneCreateSubnetPoller(resp armnetwork.SubnetsClientCreateOrUpdateResponse) *runtime.Poller[armnetwork.SubnetsClientCreateOrUpdateResponse] {
	p, err := runtime.NewPoller[armnetwork.SubnetsClientCreateOrUpdateResponse](nil, runtime.Pipeline{}, &runtime.NewPollerOptions[armnetwork.SubnetsClientCreateOrUpdateResponse]{
		Handler: &subnetDoneHandler[armnetwork.SubnetsClientCreateOrUpdateResponse]{resp: resp},
	})
	if err != nil {
		panic(err)
	}
	return p
}

// subnetPendingHandler is a PollingHandler that reports Done() as false so ResumeToken() works.
type subnetPendingHandler[T any] struct{}

func (h *subnetPendingHandler[T]) Done() bool                                     { return false }
func (h *subnetPendingHandler[T]) Poll(_ context.Context) (*http.Response, error) { return nil, nil }
func (h *subnetPendingHandler[T]) Result(_ context.Context, _ *T) error           { return nil }

func newPendingDeleteSubnetPoller() *runtime.Poller[armnetwork.SubnetsClientDeleteResponse] {
	p, err := runtime.NewPoller[armnetwork.SubnetsClientDeleteResponse](nil, runtime.Pipeline{}, &runtime.NewPollerOptions[armnetwork.SubnetsClientDeleteResponse]{
		Handler: &subnetPendingHandler[armnetwork.SubnetsClientDeleteResponse]{},
	})
	if err != nil {
		panic(err)
	}
	return p
}

type fakeSubnetsAPI struct {
	beginCreateOrUpdateFn  func(ctx context.Context, rgName, vnetName, subnetName string, params armnetwork.Subnet, opts *armnetwork.SubnetsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.SubnetsClientCreateOrUpdateResponse], error)
	getFn                  func(ctx context.Context, rgName, vnetName, subnetName string, opts *armnetwork.SubnetsClientGetOptions) (armnetwork.SubnetsClientGetResponse, error)
	beginDeleteFn          func(ctx context.Context, rgName, vnetName, subnetName string, opts *armnetwork.SubnetsClientBeginDeleteOptions) (*runtime.Poller[armnetwork.SubnetsClientDeleteResponse], error)
	newListPagerFn         func(rgName, vnetName string, opts *armnetwork.SubnetsClientListOptions) *runtime.Pager[armnetwork.SubnetsClientListResponse]
	newListAllVNetsPagerFn func(opts *armnetwork.VirtualNetworksClientListAllOptions) *runtime.Pager[armnetwork.VirtualNetworksClientListAllResponse]
}

func (f *fakeSubnetsAPI) BeginCreateOrUpdate(ctx context.Context, rgName, vnetName, subnetName string, params armnetwork.Subnet, opts *armnetwork.SubnetsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.SubnetsClientCreateOrUpdateResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, rgName, vnetName, subnetName, params, opts)
}

func (f *fakeSubnetsAPI) Get(ctx context.Context, rgName, vnetName, subnetName string, opts *armnetwork.SubnetsClientGetOptions) (armnetwork.SubnetsClientGetResponse, error) {
	return f.getFn(ctx, rgName, vnetName, subnetName, opts)
}

func (f *fakeSubnetsAPI) BeginDelete(ctx context.Context, rgName, vnetName, subnetName string, opts *armnetwork.SubnetsClientBeginDeleteOptions) (*runtime.Poller[armnetwork.SubnetsClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, vnetName, subnetName, opts)
}

func (f *fakeSubnetsAPI) NewListPager(rgName, vnetName string, opts *armnetwork.SubnetsClientListOptions) *runtime.Pager[armnetwork.SubnetsClientListResponse] {
	return f.newListPagerFn(rgName, vnetName, opts)
}

func (f *fakeSubnetsAPI) NewListAllVNetsPager(opts *armnetwork.VirtualNetworksClientListAllOptions) *runtime.Pager[armnetwork.VirtualNetworksClientListAllResponse] {
	return f.newListAllVNetsPagerFn(opts)
}
