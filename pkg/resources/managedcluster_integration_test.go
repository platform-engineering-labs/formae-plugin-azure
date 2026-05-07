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

const testMCClusterNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.ContainerService/managedClusters/aks-1"

func TestManagedCluster_CRUD(t *testing.T) {
	fake := &fakeManagedClustersAPI{
		beginCreateOrUpdateFn: func(_ context.Context, _, _ string, _ armcontainerservice.ManagedCluster, _ *armcontainerservice.ManagedClustersClientBeginCreateOrUpdateOptions) (*runtime.Poller[armcontainerservice.ManagedClustersClientCreateOrUpdateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 403}
		},
		getFn: func(_ context.Context, _, _ string, _ *armcontainerservice.ManagedClustersClientGetOptions) (armcontainerservice.ManagedClustersClientGetResponse, error) {
			return armcontainerservice.ManagedClustersClientGetResponse{
				ManagedCluster: armcontainerservice.ManagedCluster{
					ID:       to.Ptr(testMCClusterNativeID),
					Name:     to.Ptr("aks-1"),
					Location: to.Ptr("eastus"),
					Properties: &armcontainerservice.ManagedClusterProperties{
						KubernetesVersion: to.Ptr("1.29.0"),
						DNSPrefix:         to.Ptr("aks-1-dns"),
						Fqdn:              to.Ptr("aks-1-dns-abcd1234.hcp.eastus.azmk8s.io"),
						EnableRBAC:        to.Ptr(true),
					},
					SKU: &armcontainerservice.ManagedClusterSKU{
						Name: to.Ptr(armcontainerservice.ManagedClusterSKUNameBase),
						Tier: to.Ptr(armcontainerservice.ManagedClusterSKUTierFree),
					},
					Identity: &armcontainerservice.ManagedClusterIdentity{
						Type: to.Ptr(armcontainerservice.ResourceIdentityTypeSystemAssigned),
					},
				},
			}, nil
		},
		beginDeleteFn: func(_ context.Context, _, _ string, _ *armcontainerservice.ManagedClustersClientBeginDeleteOptions) (*runtime.Poller[armcontainerservice.ManagedClustersClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		},
		newListByResourceGroupPagerFn: func(_ string, _ *armcontainerservice.ManagedClustersClientListByResourceGroupOptions) *runtime.Pager[armcontainerservice.ManagedClustersClientListByResourceGroupResponse] {
			return runtime.NewPager(runtime.PagingHandler[armcontainerservice.ManagedClustersClientListByResourceGroupResponse]{
				More: func(_ armcontainerservice.ManagedClustersClientListByResourceGroupResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armcontainerservice.ManagedClustersClientListByResourceGroupResponse) (armcontainerservice.ManagedClustersClientListByResourceGroupResponse, error) {
					return armcontainerservice.ManagedClustersClientListByResourceGroupResponse{
						ManagedClusterListResult: armcontainerservice.ManagedClusterListResult{
							Value: []*armcontainerservice.ManagedCluster{
								{ID: to.Ptr(testMCClusterNativeID)},
								{ID: to.Ptr("/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.ContainerService/managedClusters/aks-2")},
							},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestManagedCluster(fake)

	t.Run("Create", func(t *testing.T) {
		props, _ := json.Marshal(map[string]interface{}{
			"resourceGroupName": "rg-1",
			"location":          "eastus",
			"name":              "aks-1",
		})
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "test-cluster", Properties: props})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.Equal(t, resource.OperationErrorCodeAccessDenied, got.ProgressResult.ErrorCode)
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testMCClusterNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
		var props map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "aks-1", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "eastus", props["location"])
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _ string, _ *armcontainerservice.ManagedClustersClientBeginDeleteOptions) (*runtime.Poller[armcontainerservice.ManagedClustersClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testMCClusterNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 2)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, _ armcontainerservice.ManagedCluster, _ *armcontainerservice.ManagedClustersClientBeginCreateOrUpdateOptions) (*runtime.Poller[armcontainerservice.ManagedClustersClientCreateOrUpdateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 403}
		}
		props, _ := json.Marshal(map[string]interface{}{"resourceGroupName": "rg-1", "location": "eastus", "name": "x"})
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

// --- Test helpers ---

func newTestManagedCluster(api managedClustersAPI) *ManagedCluster {
	return &ManagedCluster{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

type fakeManagedClustersAPI struct {
	beginCreateOrUpdateFn         func(ctx context.Context, rgName, clusterName string, params armcontainerservice.ManagedCluster, opts *armcontainerservice.ManagedClustersClientBeginCreateOrUpdateOptions) (*runtime.Poller[armcontainerservice.ManagedClustersClientCreateOrUpdateResponse], error)
	getFn                         func(ctx context.Context, rgName, clusterName string, opts *armcontainerservice.ManagedClustersClientGetOptions) (armcontainerservice.ManagedClustersClientGetResponse, error)
	beginDeleteFn                 func(ctx context.Context, rgName, clusterName string, opts *armcontainerservice.ManagedClustersClientBeginDeleteOptions) (*runtime.Poller[armcontainerservice.ManagedClustersClientDeleteResponse], error)
	newListByResourceGroupPagerFn func(rgName string, opts *armcontainerservice.ManagedClustersClientListByResourceGroupOptions) *runtime.Pager[armcontainerservice.ManagedClustersClientListByResourceGroupResponse]
	resumeCreatePollerFn          func(token string) (*runtime.Poller[armcontainerservice.ManagedClustersClientCreateOrUpdateResponse], error)
	resumeDeletePollerFn          func(token string) (*runtime.Poller[armcontainerservice.ManagedClustersClientDeleteResponse], error)
	listClusterAdminCredentialsFn func(ctx context.Context, rgName, clusterName string, opts *armcontainerservice.ManagedClustersClientListClusterAdminCredentialsOptions) (armcontainerservice.ManagedClustersClientListClusterAdminCredentialsResponse, error)
}

func (f *fakeManagedClustersAPI) BeginCreateOrUpdate(ctx context.Context, rgName, clusterName string, params armcontainerservice.ManagedCluster, opts *armcontainerservice.ManagedClustersClientBeginCreateOrUpdateOptions) (*runtime.Poller[armcontainerservice.ManagedClustersClientCreateOrUpdateResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, rgName, clusterName, params, opts)
}

func (f *fakeManagedClustersAPI) Get(ctx context.Context, rgName, clusterName string, opts *armcontainerservice.ManagedClustersClientGetOptions) (armcontainerservice.ManagedClustersClientGetResponse, error) {
	return f.getFn(ctx, rgName, clusterName, opts)
}

func (f *fakeManagedClustersAPI) BeginDelete(ctx context.Context, rgName, clusterName string, opts *armcontainerservice.ManagedClustersClientBeginDeleteOptions) (*runtime.Poller[armcontainerservice.ManagedClustersClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, clusterName, opts)
}

func (f *fakeManagedClustersAPI) NewListByResourceGroupPager(rgName string, opts *armcontainerservice.ManagedClustersClientListByResourceGroupOptions) *runtime.Pager[armcontainerservice.ManagedClustersClientListByResourceGroupResponse] {
	return f.newListByResourceGroupPagerFn(rgName, opts)
}

func (f *fakeManagedClustersAPI) ListClusterAdminCredentials(ctx context.Context, rgName, clusterName string, opts *armcontainerservice.ManagedClustersClientListClusterAdminCredentialsOptions) (armcontainerservice.ManagedClustersClientListClusterAdminCredentialsResponse, error) {
	if f.listClusterAdminCredentialsFn != nil {
		return f.listClusterAdminCredentialsFn(ctx, rgName, clusterName, opts)
	}
	return armcontainerservice.ManagedClustersClientListClusterAdminCredentialsResponse{}, nil
}

func (f *fakeManagedClustersAPI) ResumeCreatePoller(token string) (*runtime.Poller[armcontainerservice.ManagedClustersClientCreateOrUpdateResponse], error) {
	return f.resumeCreatePollerFn(token)
}

func (f *fakeManagedClustersAPI) ResumeDeletePoller(token string) (*runtime.Poller[armcontainerservice.ManagedClustersClientDeleteResponse], error) {
	return f.resumeDeletePollerFn(token)
}
