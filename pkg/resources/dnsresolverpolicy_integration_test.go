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
	testPolicyNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/dnsResolverPolicies/policy-1"
)

func newTestDNSResolverPolicy(api dnsResolverPoliciesAPI) *DNSResolverPolicy {
	return &DNSResolverPolicy{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func policyDesired(tagValue string) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":              "policy-1",
		"location":          "eastus",
		"resourceGroupName": "rg-1",
		"Tags":              []any{map[string]any{"Key": "env", "Value": tagValue}},
	})
	return out
}

func TestDNSResolverPolicy_CRUD(t *testing.T) {
	resolverResult := armdnsresolver.Policy{
		ID:       to.Ptr(testPolicyNativeID),
		Name:     to.Ptr("policy-1"),
		Location: to.Ptr("East US"),
		Tags:     map[string]*string{"env": to.Ptr("test")},
	}

	var sentCreate armdnsresolver.Policy
	var sentPatch armdnsresolver.PolicyPatch
	deleteCalls := 0
	fake := &fakeDNSResolverPolicysAPI{
		beginCreateOrUpdateFn: func(_ context.Context, _, name string, params armdnsresolver.Policy, _ *armdnsresolver.PoliciesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armdnsresolver.PoliciesClientCreateOrUpdateResponse], error) {
			require.Equal(t, "policy-1", name)
			sentCreate = params
			return newDonePoller(armdnsresolver.PoliciesClientCreateOrUpdateResponse{Policy: resolverResult}), nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armdnsresolver.PoliciesClientGetOptions) (armdnsresolver.PoliciesClientGetResponse, error) {
			return armdnsresolver.PoliciesClientGetResponse{Policy: resolverResult}, nil
		},
		beginUpdateFn: func(_ context.Context, _, _ string, params armdnsresolver.PolicyPatch, _ *armdnsresolver.PoliciesClientBeginUpdateOptions) (*runtime.Poller[armdnsresolver.PoliciesClientUpdateResponse], error) {
			sentPatch = params
			return newDonePoller(armdnsresolver.PoliciesClientUpdateResponse{Policy: resolverResult}), nil
		},
		beginDeleteFn: func(_ context.Context, _, _ string, _ *armdnsresolver.PoliciesClientBeginDeleteOptions) (*runtime.Poller[armdnsresolver.PoliciesClientDeleteResponse], error) {
			deleteCalls++
			return newDonePoller(armdnsresolver.PoliciesClientDeleteResponse{}), nil
		},
		newListPagerFn: func(_ *armdnsresolver.PoliciesClientListOptions) *runtime.Pager[armdnsresolver.PoliciesClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armdnsresolver.PoliciesClientListResponse]{
				More: func(_ armdnsresolver.PoliciesClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armdnsresolver.PoliciesClientListResponse) (armdnsresolver.PoliciesClientListResponse, error) {
					return armdnsresolver.PoliciesClientListResponse{
						PolicyListResult: armdnsresolver.PolicyListResult{
							Value: []*armdnsresolver.Policy{
								{ID: to.Ptr(testPolicyNativeID)},
								{ID: to.Ptr("/subscriptions/sub-1/resourceGroups/rg-2/providers/Microsoft.Network/dnsResolverPolicies/policy-2")},
							},
						},
					}, nil
				},
			})
		},
		newListByResourceGroupPagerFn: func(_ string, _ *armdnsresolver.PoliciesClientListByResourceGroupOptions) *runtime.Pager[armdnsresolver.PoliciesClientListByResourceGroupResponse] {
			return runtime.NewPager(runtime.PagingHandler[armdnsresolver.PoliciesClientListByResourceGroupResponse]{
				More: func(_ armdnsresolver.PoliciesClientListByResourceGroupResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armdnsresolver.PoliciesClientListByResourceGroupResponse) (armdnsresolver.PoliciesClientListByResourceGroupResponse, error) {
					return armdnsresolver.PoliciesClientListByResourceGroupResponse{
						PolicyListResult: armdnsresolver.PolicyListResult{
							Value: []*armdnsresolver.Policy{{ID: to.Ptr(testPolicyNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestDNSResolverPolicy(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "policy-1",
			Properties: policyDesired("test"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testPolicyNativeID, got.ProgressResult.NativeID)
		require.Equal(t, "test", *sentCreate.Tags["env"])
	})

	t.Run("Create_requires_location", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "policy-1", "resourceGroupName": "rg-1",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "location is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testPolicyNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "policy-1", props["name"])
		// ARM returns "East US"; read must normalise or desired state drifts.
		require.Equal(t, "eastus", props["location"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
	})

	// provisioningState and resourceGuid are service bookkeeping, not desired
	// state: surfacing them would only ever read back as noise.
	t.Run("Read_drops_service_bookkeeping", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testPolicyNativeID})
		require.NoError(t, err)
		require.NotContains(t, got.Properties, "provisioningState")
		require.NotContains(t, got.Properties, "resourceGuid")
		require.NotContains(t, got.Properties, "resourceGUID")
	})

	// armdnsresolver.PolicyPatch carries tags and nothing else, so a tag change is the
	// only in-place update this resource has.
	t.Run("Update_sends_tags", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testPolicyNativeID,
			DesiredProperties: policyDesired("updated"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, "updated", *sentPatch.Tags["env"])
	})

	t.Run("Delete", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testPolicyNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _ string, _ *armdnsresolver.PoliciesClientBeginDeleteOptions) (*runtime.Poller[armdnsresolver.PoliciesClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testPolicyNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_resource_group", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testPolicyNativeID}, got.NativeIDs)
	})

	t.Run("List_without_group_is_subscription_wide", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 2)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, _ armdnsresolver.Policy, _ *armdnsresolver.PoliciesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armdnsresolver.PoliciesClientCreateOrUpdateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 409}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "policy-1", Properties: policyDesired("test"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

func TestDNSResolverPolicy_ReadNotFound(t *testing.T) {
	fake := &fakeDNSResolverPolicysAPI{
		getFn: func(_ context.Context, _, _ string, _ *armdnsresolver.PoliciesClientGetOptions) (armdnsresolver.PoliciesClientGetResponse, error) {
			return armdnsresolver.PoliciesClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestDNSResolverPolicy(fake).Read(context.Background(), &resource.ReadRequest{NativeID: testPolicyNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeDNSResolverPolicysAPI struct {
	beginCreateOrUpdateFn         func(ctx context.Context, rgName, name string, params armdnsresolver.Policy, options *armdnsresolver.PoliciesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armdnsresolver.PoliciesClientCreateOrUpdateResponse], error)
	getFn                         func(ctx context.Context, rgName, name string, options *armdnsresolver.PoliciesClientGetOptions) (armdnsresolver.PoliciesClientGetResponse, error)
	beginUpdateFn                 func(ctx context.Context, rgName, name string, params armdnsresolver.PolicyPatch, options *armdnsresolver.PoliciesClientBeginUpdateOptions) (*runtime.Poller[armdnsresolver.PoliciesClientUpdateResponse], error)
	beginDeleteFn                 func(ctx context.Context, rgName, name string, options *armdnsresolver.PoliciesClientBeginDeleteOptions) (*runtime.Poller[armdnsresolver.PoliciesClientDeleteResponse], error)
	newListPagerFn                func(options *armdnsresolver.PoliciesClientListOptions) *runtime.Pager[armdnsresolver.PoliciesClientListResponse]
	newListByResourceGroupPagerFn func(rgName string, options *armdnsresolver.PoliciesClientListByResourceGroupOptions) *runtime.Pager[armdnsresolver.PoliciesClientListByResourceGroupResponse]
}

func (f *fakeDNSResolverPolicysAPI) BeginCreateOrUpdate(ctx context.Context, rgName, name string, params armdnsresolver.Policy, options *armdnsresolver.PoliciesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armdnsresolver.PoliciesClientCreateOrUpdateResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, rgName, name, params, options)
}

func (f *fakeDNSResolverPolicysAPI) Get(ctx context.Context, rgName, name string, options *armdnsresolver.PoliciesClientGetOptions) (armdnsresolver.PoliciesClientGetResponse, error) {
	return f.getFn(ctx, rgName, name, options)
}

func (f *fakeDNSResolverPolicysAPI) BeginUpdate(ctx context.Context, rgName, name string, params armdnsresolver.PolicyPatch, options *armdnsresolver.PoliciesClientBeginUpdateOptions) (*runtime.Poller[armdnsresolver.PoliciesClientUpdateResponse], error) {
	return f.beginUpdateFn(ctx, rgName, name, params, options)
}

func (f *fakeDNSResolverPolicysAPI) BeginDelete(ctx context.Context, rgName, name string, options *armdnsresolver.PoliciesClientBeginDeleteOptions) (*runtime.Poller[armdnsresolver.PoliciesClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, name, options)
}

func (f *fakeDNSResolverPolicysAPI) NewListPager(options *armdnsresolver.PoliciesClientListOptions) *runtime.Pager[armdnsresolver.PoliciesClientListResponse] {
	return f.newListPagerFn(options)
}

func (f *fakeDNSResolverPolicysAPI) NewListByResourceGroupPager(rgName string, options *armdnsresolver.PoliciesClientListByResourceGroupOptions) *runtime.Pager[armdnsresolver.PoliciesClientListByResourceGroupResponse] {
	return f.newListByResourceGroupPagerFn(rgName, options)
}
