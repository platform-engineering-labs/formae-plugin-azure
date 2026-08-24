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
	testVNetLinkNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/dnsForwardingRulesets/ruleset-1/virtualNetworkLinks/link-1"
	testVNetLinkVnetID   = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/virtualNetworks/vnet-1"
)

func newTestVNetLink(api dnsForwardingRulesetVNetLinksAPI) *DNSForwardingRulesetVNetLink {
	return &DNSForwardingRulesetVNetLink{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func vnetLinkDesired(metadataValue string) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":                     "link-1",
		"resourceGroupName":        "rg-1",
		"dnsForwardingRulesetName": "ruleset-1",
		"virtualNetworkId":         testVNetLinkVnetID,
		"metadata":                 []any{map[string]any{"Key": "owner", "Value": metadataValue}},
	})
	return out
}

func TestDNSForwardingRulesetVNetLink_CRUD(t *testing.T) {
	linkResult := armdnsresolver.VirtualNetworkLink{
		ID:   to.Ptr(testVNetLinkNativeID),
		Name: to.Ptr("link-1"),
		Properties: &armdnsresolver.VirtualNetworkLinkProperties{
			VirtualNetwork:    &armdnsresolver.SubResource{ID: to.Ptr(testVNetLinkVnetID)},
			Metadata:          map[string]*string{"owner": to.Ptr("platform")},
			ProvisioningState: to.Ptr(armdnsresolver.ProvisioningStateSucceeded),
		},
	}

	var sentCreate armdnsresolver.VirtualNetworkLink
	var sentPatch armdnsresolver.VirtualNetworkLinkPatch
	var sawRuleset string
	deleteCalls := 0
	fake := &fakeVNetLinksAPI{
		beginCreateOrUpdateFn: func(_ context.Context, _, rulesetName, name string, params armdnsresolver.VirtualNetworkLink, _ *armdnsresolver.VirtualNetworkLinksClientBeginCreateOrUpdateOptions) (*runtime.Poller[armdnsresolver.VirtualNetworkLinksClientCreateOrUpdateResponse], error) {
			require.Equal(t, "link-1", name)
			sawRuleset = rulesetName
			sentCreate = params
			return newDonePoller(armdnsresolver.VirtualNetworkLinksClientCreateOrUpdateResponse{VirtualNetworkLink: linkResult}), nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ *armdnsresolver.VirtualNetworkLinksClientGetOptions) (armdnsresolver.VirtualNetworkLinksClientGetResponse, error) {
			return armdnsresolver.VirtualNetworkLinksClientGetResponse{VirtualNetworkLink: linkResult}, nil
		},
		beginUpdateFn: func(_ context.Context, _, _, _ string, params armdnsresolver.VirtualNetworkLinkPatch, _ *armdnsresolver.VirtualNetworkLinksClientBeginUpdateOptions) (*runtime.Poller[armdnsresolver.VirtualNetworkLinksClientUpdateResponse], error) {
			sentPatch = params
			return newDonePoller(armdnsresolver.VirtualNetworkLinksClientUpdateResponse{VirtualNetworkLink: linkResult}), nil
		},
		beginDeleteFn: func(_ context.Context, _, _, _ string, _ *armdnsresolver.VirtualNetworkLinksClientBeginDeleteOptions) (*runtime.Poller[armdnsresolver.VirtualNetworkLinksClientDeleteResponse], error) {
			deleteCalls++
			return newDonePoller(armdnsresolver.VirtualNetworkLinksClientDeleteResponse{}), nil
		},
		newListPagerFn: func(_, _ string, _ *armdnsresolver.VirtualNetworkLinksClientListOptions) *runtime.Pager[armdnsresolver.VirtualNetworkLinksClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armdnsresolver.VirtualNetworkLinksClientListResponse]{
				More: func(_ armdnsresolver.VirtualNetworkLinksClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armdnsresolver.VirtualNetworkLinksClientListResponse) (armdnsresolver.VirtualNetworkLinksClientListResponse, error) {
					return armdnsresolver.VirtualNetworkLinksClientListResponse{
						VirtualNetworkLinkListResult: armdnsresolver.VirtualNetworkLinkListResult{
							Value: []*armdnsresolver.VirtualNetworkLink{{ID: to.Ptr(testVNetLinkNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestVNetLink(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "link-1",
			Properties: vnetLinkDesired("platform"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testVNetLinkNativeID, got.ProgressResult.NativeID)
		require.Equal(t, "ruleset-1", sawRuleset)
		require.Equal(t, testVNetLinkVnetID, *sentCreate.Properties.VirtualNetwork.ID)
		require.Equal(t, "platform", *sentCreate.Properties.Metadata["owner"])
	})

	t.Run("Create_requires_virtual_network", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "link-1", "resourceGroupName": "rg-1", "dnsForwardingRulesetName": "ruleset-1",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "virtualNetworkId is required")
	})

	t.Run("Create_requires_ruleset", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "link-1", "resourceGroupName": "rg-1", "virtualNetworkId": testVNetLinkVnetID,
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "dnsForwardingRulesetName is required")
	})

	// Metadata is absent far more often than not; an empty set must be left out of
	// the request rather than sent as an empty map, which would clear it.
	t.Run("Create_without_metadata_sends_none", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "link-1", "resourceGroupName": "rg-1",
			"dnsForwardingRulesetName": "ruleset-1", "virtualNetworkId": testVNetLinkVnetID,
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.Nil(t, sentCreate.Properties.Metadata)
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testVNetLinkNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "link-1", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		// Both parents come from the native ID, not the response body.
		require.Equal(t, "ruleset-1", props["dnsForwardingRulesetName"])
		require.Equal(t, testVNetLinkVnetID, props["virtualNetworkId"])
		// Key/Value entity-set shape, matching the schema's indexField.
		require.Equal(t, []any{map[string]any{"Key": "owner", "Value": "platform"}}, props["metadata"])
	})

	t.Run("Read_drops_provisioning_state", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testVNetLinkNativeID})
		require.NoError(t, err)
		require.NotContains(t, got.Properties, "provisioningState")
	})

	// VirtualNetworkLinkPatchProperties carries metadata and nothing else, so a
	// metadata change is the only in-place update this resource has. Unlike the
	// ruleset's patch model this one nests under "properties" correctly, so ARM
	// accepts it.
	t.Run("Update_sends_metadata", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testVNetLinkNativeID,
			DesiredProperties: vnetLinkDesired("networking"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, "networking", *sentPatch.Properties.Metadata["owner"])
	})

	t.Run("Delete", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testVNetLinkNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _, _ string, _ *armdnsresolver.VirtualNetworkLinksClientBeginDeleteOptions) (*runtime.Poller[armdnsresolver.VirtualNetworkLinksClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testVNetLinkNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_ruleset", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "dnsForwardingRulesetName": "ruleset-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testVNetLinkNativeID}, got.NativeIDs)
	})

	t.Run("List_without_parents_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _, _ string, _ armdnsresolver.VirtualNetworkLink, _ *armdnsresolver.VirtualNetworkLinksClientBeginCreateOrUpdateOptions) (*runtime.Poller[armdnsresolver.VirtualNetworkLinksClientCreateOrUpdateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 409}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "link-1", Properties: vnetLinkDesired("platform"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

func TestDNSForwardingRulesetVNetLink_ReadNotFound(t *testing.T) {
	fake := &fakeVNetLinksAPI{
		getFn: func(_ context.Context, _, _, _ string, _ *armdnsresolver.VirtualNetworkLinksClientGetOptions) (armdnsresolver.VirtualNetworkLinksClientGetResponse, error) {
			return armdnsresolver.VirtualNetworkLinksClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestVNetLink(fake).Read(context.Background(), &resource.ReadRequest{NativeID: testVNetLinkNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeVNetLinksAPI struct {
	beginCreateOrUpdateFn func(ctx context.Context, rgName, rulesetName, name string, params armdnsresolver.VirtualNetworkLink, options *armdnsresolver.VirtualNetworkLinksClientBeginCreateOrUpdateOptions) (*runtime.Poller[armdnsresolver.VirtualNetworkLinksClientCreateOrUpdateResponse], error)
	getFn                 func(ctx context.Context, rgName, rulesetName, name string, options *armdnsresolver.VirtualNetworkLinksClientGetOptions) (armdnsresolver.VirtualNetworkLinksClientGetResponse, error)
	beginUpdateFn         func(ctx context.Context, rgName, rulesetName, name string, params armdnsresolver.VirtualNetworkLinkPatch, options *armdnsresolver.VirtualNetworkLinksClientBeginUpdateOptions) (*runtime.Poller[armdnsresolver.VirtualNetworkLinksClientUpdateResponse], error)
	beginDeleteFn         func(ctx context.Context, rgName, rulesetName, name string, options *armdnsresolver.VirtualNetworkLinksClientBeginDeleteOptions) (*runtime.Poller[armdnsresolver.VirtualNetworkLinksClientDeleteResponse], error)
	newListPagerFn        func(rgName, rulesetName string, options *armdnsresolver.VirtualNetworkLinksClientListOptions) *runtime.Pager[armdnsresolver.VirtualNetworkLinksClientListResponse]
}

func (f *fakeVNetLinksAPI) BeginCreateOrUpdate(ctx context.Context, rgName, rulesetName, name string, params armdnsresolver.VirtualNetworkLink, options *armdnsresolver.VirtualNetworkLinksClientBeginCreateOrUpdateOptions) (*runtime.Poller[armdnsresolver.VirtualNetworkLinksClientCreateOrUpdateResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, rgName, rulesetName, name, params, options)
}

func (f *fakeVNetLinksAPI) Get(ctx context.Context, rgName, rulesetName, name string, options *armdnsresolver.VirtualNetworkLinksClientGetOptions) (armdnsresolver.VirtualNetworkLinksClientGetResponse, error) {
	return f.getFn(ctx, rgName, rulesetName, name, options)
}

func (f *fakeVNetLinksAPI) BeginUpdate(ctx context.Context, rgName, rulesetName, name string, params armdnsresolver.VirtualNetworkLinkPatch, options *armdnsresolver.VirtualNetworkLinksClientBeginUpdateOptions) (*runtime.Poller[armdnsresolver.VirtualNetworkLinksClientUpdateResponse], error) {
	return f.beginUpdateFn(ctx, rgName, rulesetName, name, params, options)
}

func (f *fakeVNetLinksAPI) BeginDelete(ctx context.Context, rgName, rulesetName, name string, options *armdnsresolver.VirtualNetworkLinksClientBeginDeleteOptions) (*runtime.Poller[armdnsresolver.VirtualNetworkLinksClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, rulesetName, name, options)
}

func (f *fakeVNetLinksAPI) NewListPager(rgName, rulesetName string, options *armdnsresolver.VirtualNetworkLinksClientListOptions) *runtime.Pager[armdnsresolver.VirtualNetworkLinksClientListResponse] {
	return f.newListPagerFn(rgName, rulesetName, options)
}
