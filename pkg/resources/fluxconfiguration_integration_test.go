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

const testFluxNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.ContainerService/managedClusters/aks-1/providers/Microsoft.KubernetesConfiguration/fluxConfigurations/flux-app"

func TestFluxConfiguration_CRUD(t *testing.T) {
	fake := &fakeFluxConfigurationsAPI{
		beginCreateOrUpdateFn: func(_ context.Context, _, _, _, _, _ string, _ armkubernetesconfiguration.FluxConfiguration, _ *armkubernetesconfiguration.FluxConfigurationsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armkubernetesconfiguration.FluxConfigurationsClientCreateOrUpdateResponse], error) {
			return newDonePoller(armkubernetesconfiguration.FluxConfigurationsClientCreateOrUpdateResponse{
				FluxConfiguration: armkubernetesconfiguration.FluxConfiguration{
					ID:   to.Ptr(testFluxNativeID),
					Name: to.Ptr("flux-app"),
					Properties: &armkubernetesconfiguration.FluxConfigurationProperties{
						SourceKind: to.Ptr(armkubernetesconfiguration.SourceKindTypeGitRepository),
						Namespace:  to.Ptr("flux-system"),
					},
				},
			}), nil
		},
		getFn: func(_ context.Context, _, _, _, _, _ string, _ *armkubernetesconfiguration.FluxConfigurationsClientGetOptions) (armkubernetesconfiguration.FluxConfigurationsClientGetResponse, error) {
			return armkubernetesconfiguration.FluxConfigurationsClientGetResponse{
				FluxConfiguration: armkubernetesconfiguration.FluxConfiguration{
					ID:   to.Ptr(testFluxNativeID),
					Name: to.Ptr("flux-app"),
					Properties: &armkubernetesconfiguration.FluxConfigurationProperties{
						SourceKind: to.Ptr(armkubernetesconfiguration.SourceKindTypeGitRepository),
						Namespace:  to.Ptr("flux-system"),
					},
				},
			}, nil
		},
		beginDeleteFn: func(_ context.Context, _, _, _, _, _ string, _ *armkubernetesconfiguration.FluxConfigurationsClientBeginDeleteOptions) (*runtime.Poller[armkubernetesconfiguration.FluxConfigurationsClientDeleteResponse], error) {
			return newInProgressPoller[armkubernetesconfiguration.FluxConfigurationsClientDeleteResponse](), nil
		},
		newListPagerFn: func(_, _, _, _ string, _ *armkubernetesconfiguration.FluxConfigurationsClientListOptions) *runtime.Pager[armkubernetesconfiguration.FluxConfigurationsClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armkubernetesconfiguration.FluxConfigurationsClientListResponse]{
				More: func(_ armkubernetesconfiguration.FluxConfigurationsClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armkubernetesconfiguration.FluxConfigurationsClientListResponse) (armkubernetesconfiguration.FluxConfigurationsClientListResponse, error) {
					return armkubernetesconfiguration.FluxConfigurationsClientListResponse{
						FluxConfigurationsList: armkubernetesconfiguration.FluxConfigurationsList{
							Value: []*armkubernetesconfiguration.FluxConfiguration{{ID: to.Ptr(testFluxNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestFluxConfiguration(fake)

	t.Run("Create", func(t *testing.T) {
		props, _ := json.Marshal(map[string]interface{}{
			"resourceGroupName": "rg-1", "clusterName": "aks-1", "name": "flux-app",
			"sourceKind": "GitRepository",
		})
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testFluxNativeID, got.ProgressResult.NativeID)
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testFluxNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
		var props map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "flux-app", props["name"])
	})

	t.Run("Delete", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testFluxNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusInProgress, got.ProgressResult.OperationStatus)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _, _, _, _ string, _ *armkubernetesconfiguration.FluxConfigurationsClientBeginDeleteOptions) (*runtime.Poller[armkubernetesconfiguration.FluxConfigurationsClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testFluxNativeID})
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
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _, _, _, _ string, _ armkubernetesconfiguration.FluxConfiguration, _ *armkubernetesconfiguration.FluxConfigurationsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armkubernetesconfiguration.FluxConfigurationsClientCreateOrUpdateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 403}
		}
		props, _ := json.Marshal(map[string]interface{}{"resourceGroupName": "rg-1", "clusterName": "aks-1", "name": "x", "sourceKind": "GitRepository"})
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

// --- Test helpers ---

func newTestFluxConfiguration(api fluxConfigurationsAPI) *FluxConfiguration {
	return &FluxConfiguration{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

type fakeFluxConfigurationsAPI struct {
	beginCreateOrUpdateFn func(ctx context.Context, resourceGroupName string, clusterRp string, clusterResourceName string, clusterName string, fluxConfigurationName string, fluxConfiguration armkubernetesconfiguration.FluxConfiguration, options *armkubernetesconfiguration.FluxConfigurationsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armkubernetesconfiguration.FluxConfigurationsClientCreateOrUpdateResponse], error)
	getFn                 func(ctx context.Context, resourceGroupName string, clusterRp string, clusterResourceName string, clusterName string, fluxConfigurationName string, options *armkubernetesconfiguration.FluxConfigurationsClientGetOptions) (armkubernetesconfiguration.FluxConfigurationsClientGetResponse, error)
	beginDeleteFn         func(ctx context.Context, resourceGroupName string, clusterRp string, clusterResourceName string, clusterName string, fluxConfigurationName string, options *armkubernetesconfiguration.FluxConfigurationsClientBeginDeleteOptions) (*runtime.Poller[armkubernetesconfiguration.FluxConfigurationsClientDeleteResponse], error)
	newListPagerFn        func(resourceGroupName string, clusterRp string, clusterResourceName string, clusterName string, options *armkubernetesconfiguration.FluxConfigurationsClientListOptions) *runtime.Pager[armkubernetesconfiguration.FluxConfigurationsClientListResponse]
}

func (f *fakeFluxConfigurationsAPI) BeginCreateOrUpdate(ctx context.Context, resourceGroupName string, clusterRp string, clusterResourceName string, clusterName string, fluxConfigurationName string, fluxConfiguration armkubernetesconfiguration.FluxConfiguration, options *armkubernetesconfiguration.FluxConfigurationsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armkubernetesconfiguration.FluxConfigurationsClientCreateOrUpdateResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, resourceGroupName, clusterRp, clusterResourceName, clusterName, fluxConfigurationName, fluxConfiguration, options)
}

func (f *fakeFluxConfigurationsAPI) Get(ctx context.Context, resourceGroupName string, clusterRp string, clusterResourceName string, clusterName string, fluxConfigurationName string, options *armkubernetesconfiguration.FluxConfigurationsClientGetOptions) (armkubernetesconfiguration.FluxConfigurationsClientGetResponse, error) {
	return f.getFn(ctx, resourceGroupName, clusterRp, clusterResourceName, clusterName, fluxConfigurationName, options)
}

func (f *fakeFluxConfigurationsAPI) BeginDelete(ctx context.Context, resourceGroupName string, clusterRp string, clusterResourceName string, clusterName string, fluxConfigurationName string, options *armkubernetesconfiguration.FluxConfigurationsClientBeginDeleteOptions) (*runtime.Poller[armkubernetesconfiguration.FluxConfigurationsClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, resourceGroupName, clusterRp, clusterResourceName, clusterName, fluxConfigurationName, options)
}

func (f *fakeFluxConfigurationsAPI) NewListPager(resourceGroupName string, clusterRp string, clusterResourceName string, clusterName string, options *armkubernetesconfiguration.FluxConfigurationsClientListOptions) *runtime.Pager[armkubernetesconfiguration.FluxConfigurationsClientListResponse] {
	return f.newListPagerFn(resourceGroupName, clusterRp, clusterResourceName, clusterName, options)
}
