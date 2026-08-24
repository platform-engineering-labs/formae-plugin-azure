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
	testPolicyVNetLinkNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/dnsResolverPolicies/policy-1/virtualNetworkLinks/link-1"
	testPolicyVNetLinkVnetID   = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/virtualNetworks/vnet-1"
)

func newTestPolicyVNetLink(api dnsResolverPolicyVNetLinksAPI) *DNSResolverPolicyVNetLink {
	return &DNSResolverPolicyVNetLink{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func policyVNetLinkDesired(tagValue string) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":                  "link-1",
		"location":              "eastus",
		"resourceGroupName":     "rg-1",
		"dnsResolverPolicyName": "policy-1",
		"virtualNetworkId":      testPolicyVNetLinkVnetID,
		"Tags":                  []any{map[string]any{"Key": "env", "Value": tagValue}},
	})
	return out
}

func TestDNSResolverPolicyVNetLink_CRUD(t *testing.T) {
	endpointResult := armdnsresolver.PolicyVirtualNetworkLink{
		ID:       to.Ptr(testPolicyVNetLinkNativeID),
		Name:     to.Ptr("link-1"),
		Location: to.Ptr("East US"),
		Properties: &armdnsresolver.PolicyVirtualNetworkLinkProperties{
			VirtualNetwork:    &armdnsresolver.SubResource{ID: to.Ptr(testPolicyVNetLinkVnetID)},
			ProvisioningState: to.Ptr(armdnsresolver.ProvisioningStateSucceeded),
		},
		Tags: map[string]*string{"env": to.Ptr("test")},
	}

	var sentCreate armdnsresolver.PolicyVirtualNetworkLink
	var sentPatch armdnsresolver.PolicyVirtualNetworkLinkPatch
	var sawPolicyName string
	deleteCalls := 0
	fake := &fakePolicyVNetLinksAPI{
		beginCreateOrUpdateFn: func(_ context.Context, _, policyName, name string, params armdnsresolver.PolicyVirtualNetworkLink, _ *armdnsresolver.PolicyVirtualNetworkLinksClientBeginCreateOrUpdateOptions) (*runtime.Poller[armdnsresolver.PolicyVirtualNetworkLinksClientCreateOrUpdateResponse], error) {
			require.Equal(t, "link-1", name)
			sawPolicyName = policyName
			sentCreate = params
			return newDonePoller(armdnsresolver.PolicyVirtualNetworkLinksClientCreateOrUpdateResponse{PolicyVirtualNetworkLink: endpointResult}), nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ *armdnsresolver.PolicyVirtualNetworkLinksClientGetOptions) (armdnsresolver.PolicyVirtualNetworkLinksClientGetResponse, error) {
			return armdnsresolver.PolicyVirtualNetworkLinksClientGetResponse{PolicyVirtualNetworkLink: endpointResult}, nil
		},
		beginUpdateFn: func(_ context.Context, _, _, _ string, params armdnsresolver.PolicyVirtualNetworkLinkPatch, _ *armdnsresolver.PolicyVirtualNetworkLinksClientBeginUpdateOptions) (*runtime.Poller[armdnsresolver.PolicyVirtualNetworkLinksClientUpdateResponse], error) {
			sentPatch = params
			return newDonePoller(armdnsresolver.PolicyVirtualNetworkLinksClientUpdateResponse{PolicyVirtualNetworkLink: endpointResult}), nil
		},
		beginDeleteFn: func(_ context.Context, _, _, _ string, _ *armdnsresolver.PolicyVirtualNetworkLinksClientBeginDeleteOptions) (*runtime.Poller[armdnsresolver.PolicyVirtualNetworkLinksClientDeleteResponse], error) {
			deleteCalls++
			return newDonePoller(armdnsresolver.PolicyVirtualNetworkLinksClientDeleteResponse{}), nil
		},
		newListPagerFn: func(_, _ string, _ *armdnsresolver.PolicyVirtualNetworkLinksClientListOptions) *runtime.Pager[armdnsresolver.PolicyVirtualNetworkLinksClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armdnsresolver.PolicyVirtualNetworkLinksClientListResponse]{
				More: func(_ armdnsresolver.PolicyVirtualNetworkLinksClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armdnsresolver.PolicyVirtualNetworkLinksClientListResponse) (armdnsresolver.PolicyVirtualNetworkLinksClientListResponse, error) {
					return armdnsresolver.PolicyVirtualNetworkLinksClientListResponse{
						PolicyVirtualNetworkLinkListResult: armdnsresolver.PolicyVirtualNetworkLinkListResult{
							Value: []*armdnsresolver.PolicyVirtualNetworkLink{{ID: to.Ptr(testPolicyVNetLinkNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestPolicyVNetLink(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "link-1",
			Properties: policyVNetLinkDesired("test"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testPolicyVNetLinkNativeID, got.ProgressResult.NativeID)
		require.Equal(t, "policy-1", sawPolicyName)
		require.Equal(t, testPolicyVNetLinkVnetID, *sentCreate.Properties.VirtualNetwork.ID)
	})

	t.Run("Create_requires_virtual_network", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "link-1", "location": "eastus",
			"resourceGroupName": "rg-1", "dnsResolverPolicyName": "policy-1",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "virtualNetworkId is required")
	})

	t.Run("Create_requires_policy", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "link-1", "location": "eastus", "resourceGroupName": "rg-1",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "dnsResolverPolicyName is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testPolicyVNetLinkNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "link-1", props["name"])
		// ARM returns "East US"; read must normalise or desired state drifts.
		require.Equal(t, "eastus", props["location"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		// The parent resolver name comes from the native ID, not the response body.
		require.Equal(t, "policy-1", props["dnsResolverPolicyName"])

		require.Equal(t, testPolicyVNetLinkVnetID, props["virtualNetworkId"])
	})

	t.Run("Read_drops_service_bookkeeping", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testPolicyVNetLinkNativeID})
		require.NoError(t, err)
		require.NotContains(t, got.Properties, "provisioningState")
		require.NotContains(t, got.Properties, "resourceGuid")
	})

	// PolicyVirtualNetworkLinkPatch carries tags and nothing else, so a tag change is the
	// only in-place update this resource has.
	t.Run("Update_sends_tags", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testPolicyVNetLinkNativeID,
			DesiredProperties: policyVNetLinkDesired("updated"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, "updated", *sentPatch.Tags["env"])
	})

	t.Run("Delete", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testPolicyVNetLinkNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _, _ string, _ *armdnsresolver.PolicyVirtualNetworkLinksClientBeginDeleteOptions) (*runtime.Poller[armdnsresolver.PolicyVirtualNetworkLinksClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testPolicyVNetLinkNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_policy", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "dnsResolverPolicyName": "policy-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testPolicyVNetLinkNativeID}, got.NativeIDs)
	})

	// ARM has no subscription-wide listing here: without both parents there is
	// nothing to page, so List must return empty rather than error.
	t.Run("List_without_parents_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _, _ string, _ armdnsresolver.PolicyVirtualNetworkLink, _ *armdnsresolver.PolicyVirtualNetworkLinksClientBeginCreateOrUpdateOptions) (*runtime.Poller[armdnsresolver.PolicyVirtualNetworkLinksClientCreateOrUpdateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 409}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "link-1", Properties: policyVNetLinkDesired("test"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

func TestDNSResolverPolicyVNetLink_ReadNotFound(t *testing.T) {
	fake := &fakePolicyVNetLinksAPI{
		getFn: func(_ context.Context, _, _, _ string, _ *armdnsresolver.PolicyVirtualNetworkLinksClientGetOptions) (armdnsresolver.PolicyVirtualNetworkLinksClientGetResponse, error) {
			return armdnsresolver.PolicyVirtualNetworkLinksClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestPolicyVNetLink(fake).Read(context.Background(), &resource.ReadRequest{NativeID: testPolicyVNetLinkNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakePolicyVNetLinksAPI struct {
	beginCreateOrUpdateFn func(ctx context.Context, rgName, policyName, name string, params armdnsresolver.PolicyVirtualNetworkLink, options *armdnsresolver.PolicyVirtualNetworkLinksClientBeginCreateOrUpdateOptions) (*runtime.Poller[armdnsresolver.PolicyVirtualNetworkLinksClientCreateOrUpdateResponse], error)
	getFn                 func(ctx context.Context, rgName, policyName, name string, options *armdnsresolver.PolicyVirtualNetworkLinksClientGetOptions) (armdnsresolver.PolicyVirtualNetworkLinksClientGetResponse, error)
	beginUpdateFn         func(ctx context.Context, rgName, policyName, name string, params armdnsresolver.PolicyVirtualNetworkLinkPatch, options *armdnsresolver.PolicyVirtualNetworkLinksClientBeginUpdateOptions) (*runtime.Poller[armdnsresolver.PolicyVirtualNetworkLinksClientUpdateResponse], error)
	beginDeleteFn         func(ctx context.Context, rgName, policyName, name string, options *armdnsresolver.PolicyVirtualNetworkLinksClientBeginDeleteOptions) (*runtime.Poller[armdnsresolver.PolicyVirtualNetworkLinksClientDeleteResponse], error)
	newListPagerFn        func(rgName, policyName string, options *armdnsresolver.PolicyVirtualNetworkLinksClientListOptions) *runtime.Pager[armdnsresolver.PolicyVirtualNetworkLinksClientListResponse]
}

func (f *fakePolicyVNetLinksAPI) BeginCreateOrUpdate(ctx context.Context, rgName, policyName, name string, params armdnsresolver.PolicyVirtualNetworkLink, options *armdnsresolver.PolicyVirtualNetworkLinksClientBeginCreateOrUpdateOptions) (*runtime.Poller[armdnsresolver.PolicyVirtualNetworkLinksClientCreateOrUpdateResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, rgName, policyName, name, params, options)
}

func (f *fakePolicyVNetLinksAPI) Get(ctx context.Context, rgName, policyName, name string, options *armdnsresolver.PolicyVirtualNetworkLinksClientGetOptions) (armdnsresolver.PolicyVirtualNetworkLinksClientGetResponse, error) {
	return f.getFn(ctx, rgName, policyName, name, options)
}

func (f *fakePolicyVNetLinksAPI) BeginUpdate(ctx context.Context, rgName, policyName, name string, params armdnsresolver.PolicyVirtualNetworkLinkPatch, options *armdnsresolver.PolicyVirtualNetworkLinksClientBeginUpdateOptions) (*runtime.Poller[armdnsresolver.PolicyVirtualNetworkLinksClientUpdateResponse], error) {
	return f.beginUpdateFn(ctx, rgName, policyName, name, params, options)
}

func (f *fakePolicyVNetLinksAPI) BeginDelete(ctx context.Context, rgName, policyName, name string, options *armdnsresolver.PolicyVirtualNetworkLinksClientBeginDeleteOptions) (*runtime.Poller[armdnsresolver.PolicyVirtualNetworkLinksClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, policyName, name, options)
}

func (f *fakePolicyVNetLinksAPI) NewListPager(rgName, policyName string, options *armdnsresolver.PolicyVirtualNetworkLinksClientListOptions) *runtime.Pager[armdnsresolver.PolicyVirtualNetworkLinksClientListResponse] {
	return f.newListPagerFn(rgName, policyName, options)
}

// The native ID reported for an in-flight create must match the one ARM will
// return, or core tracks a resource that does not exist. The child segment is
// "virtualNetworkLinks" under "dnsResolverPolicies" — the same child name the
// forwarding ruleset's links use, not a "policyVirtualNetworkLinks" segment.
func TestDNSResolverPolicyVNetLink_PendingCreateReportsRealNativeID(t *testing.T) {
	fake := &fakePolicyVNetLinksAPI{
		beginCreateOrUpdateFn: func(_ context.Context, _, _, _ string, _ armdnsresolver.PolicyVirtualNetworkLink, _ *armdnsresolver.PolicyVirtualNetworkLinksClientBeginCreateOrUpdateOptions) (*runtime.Poller[armdnsresolver.PolicyVirtualNetworkLinksClientCreateOrUpdateResponse], error) {
			return newPendingPoller[armdnsresolver.PolicyVirtualNetworkLinksClientCreateOrUpdateResponse](), nil
		},
	}
	got, err := newTestPolicyVNetLink(fake).Create(context.Background(), &resource.CreateRequest{
		Label: "link-1", Properties: policyVNetLinkDesired("test"),
	})
	require.NoError(t, err)
	require.Equal(t, resource.OperationStatusInProgress, got.ProgressResult.OperationStatus)
	require.Equal(t, testPolicyVNetLinkNativeID, got.ProgressResult.NativeID)
}
