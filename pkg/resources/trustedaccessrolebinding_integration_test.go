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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerservice/armcontainerservice/v4"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testTARBNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.ContainerService/managedClusters/aks-1/trustedAccessRoleBindings/binding-1"

func TestTrustedAccessRoleBinding_CRUD(t *testing.T) {
	fake := &fakeTrustedAccessRoleBindingsAPI{
		beginCreateOrUpdateFn: func(_ context.Context, _, _, _ string, _ armcontainerservice.TrustedAccessRoleBinding, _ *armcontainerservice.TrustedAccessRoleBindingsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armcontainerservice.TrustedAccessRoleBindingsClientCreateOrUpdateResponse], error) {
			return newDonePoller(armcontainerservice.TrustedAccessRoleBindingsClientCreateOrUpdateResponse{
				TrustedAccessRoleBinding: armcontainerservice.TrustedAccessRoleBinding{
					ID:   to.Ptr(testTARBNativeID),
					Name: to.Ptr("binding-1"),
					Properties: &armcontainerservice.TrustedAccessRoleBindingProperties{
						SourceResourceID: to.Ptr("/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.KeyVault/vaults/kv-1"),
						Roles:            []*string{to.Ptr("Microsoft.KeyVault/vaults/reader")},
					},
				},
			}), nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ *armcontainerservice.TrustedAccessRoleBindingsClientGetOptions) (armcontainerservice.TrustedAccessRoleBindingsClientGetResponse, error) {
			return armcontainerservice.TrustedAccessRoleBindingsClientGetResponse{
				TrustedAccessRoleBinding: armcontainerservice.TrustedAccessRoleBinding{
					ID:   to.Ptr(testTARBNativeID),
					Name: to.Ptr("binding-1"),
					Properties: &armcontainerservice.TrustedAccessRoleBindingProperties{
						SourceResourceID: to.Ptr("/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.KeyVault/vaults/kv-1"),
						Roles:            []*string{to.Ptr("Microsoft.KeyVault/vaults/reader")},
					},
				},
			}, nil
		},
		beginDeleteFn: func(_ context.Context, _, _, _ string, _ *armcontainerservice.TrustedAccessRoleBindingsClientBeginDeleteOptions) (*runtime.Poller[armcontainerservice.TrustedAccessRoleBindingsClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		},
		newListPagerFn: func(_, _ string, _ *armcontainerservice.TrustedAccessRoleBindingsClientListOptions) *runtime.Pager[armcontainerservice.TrustedAccessRoleBindingsClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armcontainerservice.TrustedAccessRoleBindingsClientListResponse]{
				More: func(_ armcontainerservice.TrustedAccessRoleBindingsClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armcontainerservice.TrustedAccessRoleBindingsClientListResponse) (armcontainerservice.TrustedAccessRoleBindingsClientListResponse, error) {
					return armcontainerservice.TrustedAccessRoleBindingsClientListResponse{
						TrustedAccessRoleBindingListResult: armcontainerservice.TrustedAccessRoleBindingListResult{
							Value: []*armcontainerservice.TrustedAccessRoleBinding{
								{ID: to.Ptr(testTARBNativeID)},
								{ID: to.Ptr("/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.ContainerService/managedClusters/aks-1/trustedAccessRoleBindings/binding-2")},
							},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestTrustedAccessRoleBinding(fake)

	t.Run("Create", func(t *testing.T) {
		props, _ := json.Marshal(map[string]interface{}{
			"resourceGroupName": "rg-1",
			"clusterName":       "aks-1",
			"name":              "binding-1",
			"sourceResourceId":  "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.KeyVault/vaults/kv-1",
			"roles":             []string{"Microsoft.KeyVault/vaults/reader"},
		})
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "binding-1", Properties: props})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testTARBNativeID, got.ProgressResult.NativeID)
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testTARBNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
		var props map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "binding-1", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "aks-1", props["clusterName"])
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testTARBNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "clusterName": "aks-1"},
		})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 2)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _, _ string, _ armcontainerservice.TrustedAccessRoleBinding, _ *armcontainerservice.TrustedAccessRoleBindingsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armcontainerservice.TrustedAccessRoleBindingsClientCreateOrUpdateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 403}
		}
		props, _ := json.Marshal(map[string]interface{}{
			"resourceGroupName": "rg-1",
			"clusterName":       "aks-1",
			"name":              "binding-1",
			"sourceResourceId":  "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.KeyVault/vaults/kv-1",
		})
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

// --- Test helpers ---

func newTestTrustedAccessRoleBinding(api trustedAccessRoleBindingsAPI) *TrustedAccessRoleBinding {
	return &TrustedAccessRoleBinding{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

type fakeTrustedAccessRoleBindingsAPI struct {
	beginCreateOrUpdateFn func(ctx context.Context, rgName, clusterName, bindingName string, params armcontainerservice.TrustedAccessRoleBinding, opts *armcontainerservice.TrustedAccessRoleBindingsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armcontainerservice.TrustedAccessRoleBindingsClientCreateOrUpdateResponse], error)
	getFn                 func(ctx context.Context, rgName, clusterName, bindingName string, opts *armcontainerservice.TrustedAccessRoleBindingsClientGetOptions) (armcontainerservice.TrustedAccessRoleBindingsClientGetResponse, error)
	beginDeleteFn         func(ctx context.Context, rgName, clusterName, bindingName string, opts *armcontainerservice.TrustedAccessRoleBindingsClientBeginDeleteOptions) (*runtime.Poller[armcontainerservice.TrustedAccessRoleBindingsClientDeleteResponse], error)
	newListPagerFn        func(rgName, clusterName string, opts *armcontainerservice.TrustedAccessRoleBindingsClientListOptions) *runtime.Pager[armcontainerservice.TrustedAccessRoleBindingsClientListResponse]
	resumeCreatePollerFn  func(token string) (*runtime.Poller[armcontainerservice.TrustedAccessRoleBindingsClientCreateOrUpdateResponse], error)
	resumeDeletePollerFn  func(token string) (*runtime.Poller[armcontainerservice.TrustedAccessRoleBindingsClientDeleteResponse], error)
}

func (f *fakeTrustedAccessRoleBindingsAPI) BeginCreateOrUpdate(ctx context.Context, rgName, clusterName, bindingName string, params armcontainerservice.TrustedAccessRoleBinding, opts *armcontainerservice.TrustedAccessRoleBindingsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armcontainerservice.TrustedAccessRoleBindingsClientCreateOrUpdateResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, rgName, clusterName, bindingName, params, opts)
}

func (f *fakeTrustedAccessRoleBindingsAPI) Get(ctx context.Context, rgName, clusterName, bindingName string, opts *armcontainerservice.TrustedAccessRoleBindingsClientGetOptions) (armcontainerservice.TrustedAccessRoleBindingsClientGetResponse, error) {
	return f.getFn(ctx, rgName, clusterName, bindingName, opts)
}

func (f *fakeTrustedAccessRoleBindingsAPI) BeginDelete(ctx context.Context, rgName, clusterName, bindingName string, opts *armcontainerservice.TrustedAccessRoleBindingsClientBeginDeleteOptions) (*runtime.Poller[armcontainerservice.TrustedAccessRoleBindingsClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, clusterName, bindingName, opts)
}

func (f *fakeTrustedAccessRoleBindingsAPI) NewListPager(rgName, clusterName string, opts *armcontainerservice.TrustedAccessRoleBindingsClientListOptions) *runtime.Pager[armcontainerservice.TrustedAccessRoleBindingsClientListResponse] {
	return f.newListPagerFn(rgName, clusterName, opts)
}

func (f *fakeTrustedAccessRoleBindingsAPI) ResumeCreatePoller(token string) (*runtime.Poller[armcontainerservice.TrustedAccessRoleBindingsClientCreateOrUpdateResponse], error) {
	return f.resumeCreatePollerFn(token)
}

func (f *fakeTrustedAccessRoleBindingsAPI) ResumeDeletePoller(token string) (*runtime.Poller[armcontainerservice.TrustedAccessRoleBindingsClientDeleteResponse], error) {
	return f.resumeDeletePollerFn(token)
}
