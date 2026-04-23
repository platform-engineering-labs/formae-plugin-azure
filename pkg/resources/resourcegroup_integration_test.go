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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testRGNativeID = "/subscriptions/sub-1/resourceGroups/rg-1"

func TestResourceGroup_CRUD(t *testing.T) {
	fake := &fakeResourceGroupsAPI{
		createOrUpdateFn: func(_ context.Context, _ string, _ armresources.ResourceGroup, _ *armresources.ResourceGroupsClientCreateOrUpdateOptions) (armresources.ResourceGroupsClientCreateOrUpdateResponse, error) {
			return armresources.ResourceGroupsClientCreateOrUpdateResponse{
				ResourceGroup: armresources.ResourceGroup{
					ID:       to.Ptr(testRGNativeID),
					Name:     to.Ptr("rg-1"),
					Location: to.Ptr("eastus"),
				},
			}, nil
		},
		getFn: func(_ context.Context, _ string, _ *armresources.ResourceGroupsClientGetOptions) (armresources.ResourceGroupsClientGetResponse, error) {
			return armresources.ResourceGroupsClientGetResponse{
				ResourceGroup: armresources.ResourceGroup{
					ID:       to.Ptr(testRGNativeID),
					Name:     to.Ptr("rg-1"),
					Location: to.Ptr("eastus"),
				},
			}, nil
		},
		beginDeleteFn: func(_ context.Context, _ string, _ *armresources.ResourceGroupsClientBeginDeleteOptions) (*runtime.Poller[armresources.ResourceGroupsClientDeleteResponse], error) {
			return newDonePoller(armresources.ResourceGroupsClientDeleteResponse{}), nil
		},
		newListPagerFn: func(_ *armresources.ResourceGroupsClientListOptions) *runtime.Pager[armresources.ResourceGroupsClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armresources.ResourceGroupsClientListResponse]{
				More: func(_ armresources.ResourceGroupsClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armresources.ResourceGroupsClientListResponse) (armresources.ResourceGroupsClientListResponse, error) {
					return armresources.ResourceGroupsClientListResponse{
						ResourceGroupListResult: armresources.ResourceGroupListResult{
							Value: []*armresources.ResourceGroup{{ID: to.Ptr(testRGNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestResourceGroup(fake)

	t.Run("Create", func(t *testing.T) {
		props, _ := json.Marshal(map[string]interface{}{
			"name": "rg-1", "location": "eastus",
		})
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testRGNativeID, got.ProgressResult.NativeID)
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testRGNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
		var props map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "rg-1", props["name"])
	})

	t.Run("Delete", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testRGNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _ string, _ *armresources.ResourceGroupsClientBeginDeleteOptions) (*runtime.Poller[armresources.ResourceGroupsClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testRGNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 1)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.createOrUpdateFn = func(_ context.Context, _ string, _ armresources.ResourceGroup, _ *armresources.ResourceGroupsClientCreateOrUpdateOptions) (armresources.ResourceGroupsClientCreateOrUpdateResponse, error) {
			return armresources.ResourceGroupsClientCreateOrUpdateResponse{}, &azcore.ResponseError{StatusCode: 403}
		}
		props, _ := json.Marshal(map[string]interface{}{"name": "rg-1", "location": "eastus"})
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

// --- Test helpers ---

func newTestResourceGroup(api resourceGroupsAPI) *ResourceGroup {
	return &ResourceGroup{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

type fakeResourceGroupsAPI struct {
	createOrUpdateFn     func(ctx context.Context, resourceGroupName string, parameters armresources.ResourceGroup, options *armresources.ResourceGroupsClientCreateOrUpdateOptions) (armresources.ResourceGroupsClientCreateOrUpdateResponse, error)
	getFn                func(ctx context.Context, resourceGroupName string, options *armresources.ResourceGroupsClientGetOptions) (armresources.ResourceGroupsClientGetResponse, error)
	beginDeleteFn        func(ctx context.Context, resourceGroupName string, options *armresources.ResourceGroupsClientBeginDeleteOptions) (*runtime.Poller[armresources.ResourceGroupsClientDeleteResponse], error)
	newListPagerFn       func(options *armresources.ResourceGroupsClientListOptions) *runtime.Pager[armresources.ResourceGroupsClientListResponse]
	resumeDeletePollerFn func(token string) (*runtime.Poller[armresources.ResourceGroupsClientDeleteResponse], error)
}

func (f *fakeResourceGroupsAPI) CreateOrUpdate(ctx context.Context, resourceGroupName string, parameters armresources.ResourceGroup, options *armresources.ResourceGroupsClientCreateOrUpdateOptions) (armresources.ResourceGroupsClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, resourceGroupName, parameters, options)
}

func (f *fakeResourceGroupsAPI) Get(ctx context.Context, resourceGroupName string, options *armresources.ResourceGroupsClientGetOptions) (armresources.ResourceGroupsClientGetResponse, error) {
	return f.getFn(ctx, resourceGroupName, options)
}

func (f *fakeResourceGroupsAPI) BeginDelete(ctx context.Context, resourceGroupName string, options *armresources.ResourceGroupsClientBeginDeleteOptions) (*runtime.Poller[armresources.ResourceGroupsClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, resourceGroupName, options)
}

func (f *fakeResourceGroupsAPI) NewListPager(options *armresources.ResourceGroupsClientListOptions) *runtime.Pager[armresources.ResourceGroupsClientListResponse] {
	return f.newListPagerFn(options)
}

func (f *fakeResourceGroupsAPI) ResumeDeletePoller(token string) (*runtime.Poller[armresources.ResourceGroupsClientDeleteResponse], error) {
	return f.resumeDeletePollerFn(token)
}
