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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/dataprotection/armdataprotection/v3"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testResourceGuardNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.DataProtection/resourceGuards/guard-1"

func newTestResourceGuard(api resourceGuardsAPI) *ResourceGuard {
	return &ResourceGuard{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func resourceGuardDesired(exclusions ...string) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":                                "guard-1",
		"location":                            "eastus",
		"resourceGroupName":                   "rg-1",
		"vaultCriticalOperationExclusionList": exclusions,
	})
	return out
}

func TestResourceGuard_CRUD(t *testing.T) {
	guardResult := armdataprotection.ResourceGuardResource{
		ID:       to.Ptr(testResourceGuardNativeID),
		Name:     to.Ptr("guard-1"),
		Location: to.Ptr("East US"),
		Properties: &armdataprotection.ResourceGuard{
			VaultCriticalOperationExclusionList: []*string{to.Ptr("Microsoft.RecoveryServices/vaults/backupconfig/write")},
			ProvisioningState:                   to.Ptr(armdataprotection.ProvisioningStateSucceeded),
			// Read-only fields the schema deliberately does not model.
			AllowAutoApprovals: to.Ptr(true),
			Description:        to.Ptr("some service text"),
		},
	}

	var sent armdataprotection.ResourceGuardResource
	fake := &fakeResourceGuardsAPI{
		putFn: func(_ context.Context, rgName, name string, params armdataprotection.ResourceGuardResource, _ *armdataprotection.ResourceGuardsClientPutOptions) (armdataprotection.ResourceGuardsClientPutResponse, error) {
			require.Equal(t, "rg-1", rgName)
			require.Equal(t, "guard-1", name)
			sent = params
			return armdataprotection.ResourceGuardsClientPutResponse{ResourceGuardResource: guardResult}, nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armdataprotection.ResourceGuardsClientGetOptions) (armdataprotection.ResourceGuardsClientGetResponse, error) {
			return armdataprotection.ResourceGuardsClientGetResponse{ResourceGuardResource: guardResult}, nil
		},
		deleteFn: func(_ context.Context, _, _ string, _ *armdataprotection.ResourceGuardsClientDeleteOptions) (armdataprotection.ResourceGuardsClientDeleteResponse, error) {
			return armdataprotection.ResourceGuardsClientDeleteResponse{}, nil
		},
		newGetResourcesInSubscriptionPagerFn: func(_ *armdataprotection.ResourceGuardsClientGetResourcesInSubscriptionOptions) *runtime.Pager[armdataprotection.ResourceGuardsClientGetResourcesInSubscriptionResponse] {
			return runtime.NewPager(runtime.PagingHandler[armdataprotection.ResourceGuardsClientGetResourcesInSubscriptionResponse]{
				More: func(_ armdataprotection.ResourceGuardsClientGetResourcesInSubscriptionResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armdataprotection.ResourceGuardsClientGetResourcesInSubscriptionResponse) (armdataprotection.ResourceGuardsClientGetResourcesInSubscriptionResponse, error) {
					return armdataprotection.ResourceGuardsClientGetResourcesInSubscriptionResponse{
						ResourceGuardResourceList: armdataprotection.ResourceGuardResourceList{
							Value: []*armdataprotection.ResourceGuardResource{
								{ID: to.Ptr(testResourceGuardNativeID)},
								{ID: to.Ptr("/subscriptions/sub-1/resourceGroups/rg-2/providers/Microsoft.DataProtection/resourceGuards/guard-2")},
							},
						},
					}, nil
				},
			})
		},
		newGetResourcesInResourceGroupPagerFn: func(_ string, _ *armdataprotection.ResourceGuardsClientGetResourcesInResourceGroupOptions) *runtime.Pager[armdataprotection.ResourceGuardsClientGetResourcesInResourceGroupResponse] {
			return runtime.NewPager(runtime.PagingHandler[armdataprotection.ResourceGuardsClientGetResourcesInResourceGroupResponse]{
				More: func(_ armdataprotection.ResourceGuardsClientGetResourcesInResourceGroupResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armdataprotection.ResourceGuardsClientGetResourcesInResourceGroupResponse) (armdataprotection.ResourceGuardsClientGetResourcesInResourceGroupResponse, error) {
					return armdataprotection.ResourceGuardsClientGetResourcesInResourceGroupResponse{
						ResourceGuardResourceList: armdataprotection.ResourceGuardResourceList{
							Value: []*armdataprotection.ResourceGuardResource{{ID: to.Ptr(testResourceGuardNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestResourceGuard(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "guard-1",
			Properties: resourceGuardDesired("Microsoft.RecoveryServices/vaults/backupconfig/write"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testResourceGuardNativeID, got.ProgressResult.NativeID)
		require.Len(t, sent.Properties.VaultCriticalOperationExclusionList, 1)
		require.Equal(t, "Microsoft.RecoveryServices/vaults/backupconfig/write", *sent.Properties.VaultCriticalOperationExclusionList[0])
	})

	t.Run("Create_requires_location", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "guard-1", "resourceGroupName": "rg-1"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "location is required")
	})

	t.Run("Create_requires_resource_group", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "guard-1", "location": "eastus"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "resourceGroupName is required")
	})

	t.Run("Read_drops_unmodelled_readonly_fields", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testResourceGuardNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "guard-1", props["name"])
		require.Equal(t, "eastus", props["location"])
		require.Equal(t, "Succeeded", props["provisioningState"])
		require.Equal(t, []any{"Microsoft.RecoveryServices/vaults/backupconfig/write"}, props["vaultCriticalOperationExclusionList"])
		require.NotContains(t, props, "allowAutoApprovals")
		require.NotContains(t, props, "description")
	})

	// ARM's PATCH body for a Resource Guard carries only tags, so an exclusion
	// list change has to go back through PUT.
	t.Run("Update_uses_put", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testResourceGuardNativeID,
			DesiredProperties: resourceGuardDesired("Microsoft.RecoveryServices/vaults/backupPolicies/delete"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testResourceGuardNativeID, got.ProgressResult.NativeID)
		require.Equal(t, "Microsoft.RecoveryServices/vaults/backupPolicies/delete", *sent.Properties.VaultCriticalOperationExclusionList[0])
	})

	t.Run("Delete", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testResourceGuardNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _ string, _ *armdataprotection.ResourceGuardsClientDeleteOptions) (armdataprotection.ResourceGuardsClientDeleteResponse, error) {
			return armdataprotection.ResourceGuardsClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testResourceGuardNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_resource_group", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testResourceGuardNativeID}, got.NativeIDs)
	})

	t.Run("List_without_group_is_subscription_wide", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 2)
	})

	t.Run("Azure_error_maps_to_failure_with_message", func(t *testing.T) {
		fake.putFn = func(_ context.Context, _, _ string, _ armdataprotection.ResourceGuardResource, _ *armdataprotection.ResourceGuardsClientPutOptions) (armdataprotection.ResourceGuardsClientPutResponse, error) {
			return armdataprotection.ResourceGuardsClientPutResponse{}, &azcore.ResponseError{StatusCode: 400, ErrorCode: "InvalidCriticalOperation"}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "guard-1", Properties: resourceGuardDesired("nonsense")})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.Equal(t, resource.OperationErrorCodeInvalidRequest, got.ProgressResult.ErrorCode)
		require.Contains(t, got.ProgressResult.StatusMessage, "InvalidCriticalOperation")
	})
}

func TestResourceGuard_ReadNotFound(t *testing.T) {
	fake := &fakeResourceGuardsAPI{
		getFn: func(_ context.Context, _, _ string, _ *armdataprotection.ResourceGuardsClientGetOptions) (armdataprotection.ResourceGuardsClientGetResponse, error) {
			return armdataprotection.ResourceGuardsClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestResourceGuard(fake).Read(context.Background(), &resource.ReadRequest{NativeID: testResourceGuardNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeResourceGuardsAPI struct {
	putFn                                 func(ctx context.Context, rgName, name string, params armdataprotection.ResourceGuardResource, options *armdataprotection.ResourceGuardsClientPutOptions) (armdataprotection.ResourceGuardsClientPutResponse, error)
	getFn                                 func(ctx context.Context, rgName, name string, options *armdataprotection.ResourceGuardsClientGetOptions) (armdataprotection.ResourceGuardsClientGetResponse, error)
	deleteFn                              func(ctx context.Context, rgName, name string, options *armdataprotection.ResourceGuardsClientDeleteOptions) (armdataprotection.ResourceGuardsClientDeleteResponse, error)
	newGetResourcesInSubscriptionPagerFn  func(options *armdataprotection.ResourceGuardsClientGetResourcesInSubscriptionOptions) *runtime.Pager[armdataprotection.ResourceGuardsClientGetResourcesInSubscriptionResponse]
	newGetResourcesInResourceGroupPagerFn func(rgName string, options *armdataprotection.ResourceGuardsClientGetResourcesInResourceGroupOptions) *runtime.Pager[armdataprotection.ResourceGuardsClientGetResourcesInResourceGroupResponse]
}

func (f *fakeResourceGuardsAPI) Put(ctx context.Context, rgName, name string, params armdataprotection.ResourceGuardResource, options *armdataprotection.ResourceGuardsClientPutOptions) (armdataprotection.ResourceGuardsClientPutResponse, error) {
	return f.putFn(ctx, rgName, name, params, options)
}

func (f *fakeResourceGuardsAPI) Get(ctx context.Context, rgName, name string, options *armdataprotection.ResourceGuardsClientGetOptions) (armdataprotection.ResourceGuardsClientGetResponse, error) {
	return f.getFn(ctx, rgName, name, options)
}

func (f *fakeResourceGuardsAPI) Delete(ctx context.Context, rgName, name string, options *armdataprotection.ResourceGuardsClientDeleteOptions) (armdataprotection.ResourceGuardsClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, name, options)
}

func (f *fakeResourceGuardsAPI) NewGetResourcesInSubscriptionPager(options *armdataprotection.ResourceGuardsClientGetResourcesInSubscriptionOptions) *runtime.Pager[armdataprotection.ResourceGuardsClientGetResourcesInSubscriptionResponse] {
	return f.newGetResourcesInSubscriptionPagerFn(options)
}

func (f *fakeResourceGuardsAPI) NewGetResourcesInResourceGroupPager(rgName string, options *armdataprotection.ResourceGuardsClientGetResourcesInResourceGroupOptions) *runtime.Pager[armdataprotection.ResourceGuardsClientGetResourcesInResourceGroupResponse] {
	return f.newGetResourcesInResourceGroupPagerFn(rgName, options)
}
