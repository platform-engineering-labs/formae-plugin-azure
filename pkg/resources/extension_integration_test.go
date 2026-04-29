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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/kubernetesconfiguration/armkubernetesconfiguration"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testExtNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.ContainerService/managedClusters/aks-1/providers/Microsoft.KubernetesConfiguration/extensions/my-ext"

func TestExtension_CRUD(t *testing.T) {
	fake := &fakeExtensionsAPI{
		beginCreateFn: func(_ context.Context, _, _, _, _, _ string, _ armkubernetesconfiguration.Extension, _ *armkubernetesconfiguration.ExtensionsClientBeginCreateOptions) (*runtime.Poller[armkubernetesconfiguration.ExtensionsClientCreateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 409}
		},
		getFn: func(_ context.Context, _, _, _, _, _ string, _ *armkubernetesconfiguration.ExtensionsClientGetOptions) (armkubernetesconfiguration.ExtensionsClientGetResponse, error) {
			return armkubernetesconfiguration.ExtensionsClientGetResponse{
				Extension: armkubernetesconfiguration.Extension{
					ID:   to.Ptr(testExtNativeID),
					Name: to.Ptr("my-ext"),
					Properties: &armkubernetesconfiguration.ExtensionProperties{
						ExtensionType:           to.Ptr("microsoft.flux"),
						AutoUpgradeMinorVersion: to.Ptr(true),
						ReleaseTrain:            to.Ptr("Stable"),
					},
				},
			}, nil
		},
		beginDeleteFn: func(_ context.Context, _, _, _, _, _ string, _ *armkubernetesconfiguration.ExtensionsClientBeginDeleteOptions) (*runtime.Poller[armkubernetesconfiguration.ExtensionsClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		},
		newListPagerFn: func(_, _, _, _ string, _ *armkubernetesconfiguration.ExtensionsClientListOptions) *runtime.Pager[armkubernetesconfiguration.ExtensionsClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armkubernetesconfiguration.ExtensionsClientListResponse]{
				More: func(_ armkubernetesconfiguration.ExtensionsClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armkubernetesconfiguration.ExtensionsClientListResponse) (armkubernetesconfiguration.ExtensionsClientListResponse, error) {
					return armkubernetesconfiguration.ExtensionsClientListResponse{
						ExtensionsList: armkubernetesconfiguration.ExtensionsList{
							Value: []*armkubernetesconfiguration.Extension{{ID: to.Ptr(testExtNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestExtension(fake)

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testExtNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
		var props map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "my-ext", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "aks-1", props["clusterName"])
		require.Equal(t, "microsoft.flux", props["extensionType"])
	})

	t.Run("Read_NotFound", func(t *testing.T) {
		fake.getFn = func(_ context.Context, _, _, _, _, _ string, _ *armkubernetesconfiguration.ExtensionsClientGetOptions) (armkubernetesconfiguration.ExtensionsClientGetResponse, error) {
			return armkubernetesconfiguration.ExtensionsClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testExtNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testExtNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "clusterName": "aks-1"},
		})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 1)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.beginCreateFn = func(_ context.Context, _, _, _, _, _ string, _ armkubernetesconfiguration.Extension, _ *armkubernetesconfiguration.ExtensionsClientBeginCreateOptions) (*runtime.Poller[armkubernetesconfiguration.ExtensionsClientCreateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 403}
		}
		props, _ := json.Marshal(map[string]interface{}{"resourceGroupName": "rg-1", "clusterName": "aks-1", "name": "x", "extensionType": "microsoft.flux"})
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

// --- Test helpers ---

func newTestExtension(api extensionsAPI) *Extension {
	return &Extension{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

type fakeExtensionsAPI struct {
	beginCreateFn  func(ctx context.Context, resourceGroupName string, clusterRp string, clusterResourceName string, clusterName string, extensionName string, extension armkubernetesconfiguration.Extension, options *armkubernetesconfiguration.ExtensionsClientBeginCreateOptions) (*runtime.Poller[armkubernetesconfiguration.ExtensionsClientCreateResponse], error)
	getFn          func(ctx context.Context, resourceGroupName string, clusterRp string, clusterResourceName string, clusterName string, extensionName string, options *armkubernetesconfiguration.ExtensionsClientGetOptions) (armkubernetesconfiguration.ExtensionsClientGetResponse, error)
	beginUpdateFn  func(ctx context.Context, resourceGroupName string, clusterRp string, clusterResourceName string, clusterName string, extensionName string, patchExtension armkubernetesconfiguration.PatchExtension, options *armkubernetesconfiguration.ExtensionsClientBeginUpdateOptions) (*runtime.Poller[armkubernetesconfiguration.ExtensionsClientUpdateResponse], error)
	beginDeleteFn  func(ctx context.Context, resourceGroupName string, clusterRp string, clusterResourceName string, clusterName string, extensionName string, options *armkubernetesconfiguration.ExtensionsClientBeginDeleteOptions) (*runtime.Poller[armkubernetesconfiguration.ExtensionsClientDeleteResponse], error)
	newListPagerFn func(resourceGroupName string, clusterRp string, clusterResourceName string, clusterName string, options *armkubernetesconfiguration.ExtensionsClientListOptions) *runtime.Pager[armkubernetesconfiguration.ExtensionsClientListResponse]
}

func (f *fakeExtensionsAPI) BeginCreate(ctx context.Context, resourceGroupName string, clusterRp string, clusterResourceName string, clusterName string, extensionName string, extension armkubernetesconfiguration.Extension, options *armkubernetesconfiguration.ExtensionsClientBeginCreateOptions) (*runtime.Poller[armkubernetesconfiguration.ExtensionsClientCreateResponse], error) {
	return f.beginCreateFn(ctx, resourceGroupName, clusterRp, clusterResourceName, clusterName, extensionName, extension, options)
}

func (f *fakeExtensionsAPI) Get(ctx context.Context, resourceGroupName string, clusterRp string, clusterResourceName string, clusterName string, extensionName string, options *armkubernetesconfiguration.ExtensionsClientGetOptions) (armkubernetesconfiguration.ExtensionsClientGetResponse, error) {
	return f.getFn(ctx, resourceGroupName, clusterRp, clusterResourceName, clusterName, extensionName, options)
}

func (f *fakeExtensionsAPI) BeginUpdate(ctx context.Context, resourceGroupName string, clusterRp string, clusterResourceName string, clusterName string, extensionName string, patchExtension armkubernetesconfiguration.PatchExtension, options *armkubernetesconfiguration.ExtensionsClientBeginUpdateOptions) (*runtime.Poller[armkubernetesconfiguration.ExtensionsClientUpdateResponse], error) {
	return f.beginUpdateFn(ctx, resourceGroupName, clusterRp, clusterResourceName, clusterName, extensionName, patchExtension, options)
}

func (f *fakeExtensionsAPI) BeginDelete(ctx context.Context, resourceGroupName string, clusterRp string, clusterResourceName string, clusterName string, extensionName string, options *armkubernetesconfiguration.ExtensionsClientBeginDeleteOptions) (*runtime.Poller[armkubernetesconfiguration.ExtensionsClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, resourceGroupName, clusterRp, clusterResourceName, clusterName, extensionName, options)
}

func (f *fakeExtensionsAPI) NewListPager(resourceGroupName string, clusterRp string, clusterResourceName string, clusterName string, options *armkubernetesconfiguration.ExtensionsClientListOptions) *runtime.Pager[armkubernetesconfiguration.ExtensionsClientListResponse] {
	return f.newListPagerFn(resourceGroupName, clusterRp, clusterResourceName, clusterName, options)
}
