// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build integration

package resources

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/eventhub/armeventhub"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testEHNamespaceNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.EventHub/namespaces/my-ehns"

func TestEventHubNamespace_CRUD(t *testing.T) {
	fake := &fakeEventHubNamespacesAPI{
		beginCreateOrUpdateFn: func(_ context.Context, _, namespaceName string, params armeventhub.EHNamespace, _ *armeventhub.NamespacesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armeventhub.NamespacesClientCreateOrUpdateResponse], error) {
			return newDonePoller(armeventhub.NamespacesClientCreateOrUpdateResponse{
				EHNamespace: armeventhub.EHNamespace{
					ID:       to.Ptr(testEHNamespaceNativeID),
					Name:     to.Ptr(namespaceName),
					Location: params.Location,
					SKU:      params.SKU,
					Tags:     params.Tags,
					Properties: &armeventhub.EHNamespaceProperties{
						ZoneRedundant: to.Ptr(true),
					},
				},
			}), nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armeventhub.NamespacesClientGetOptions) (armeventhub.NamespacesClientGetResponse, error) {
			return armeventhub.NamespacesClientGetResponse{
				EHNamespace: armeventhub.EHNamespace{
					ID:       to.Ptr(testEHNamespaceNativeID),
					Name:     to.Ptr("my-ehns"),
					Location: to.Ptr("eastus"),
					SKU: &armeventhub.SKU{
						Name: to.Ptr(armeventhub.SKUNameStandard),
						Tier: to.Ptr(armeventhub.SKUTierStandard),
					},
				},
			}, nil
		},
		updateFn: func(_ context.Context, _, _ string, params armeventhub.EHNamespace, _ *armeventhub.NamespacesClientUpdateOptions) (armeventhub.NamespacesClientUpdateResponse, error) {
			return armeventhub.NamespacesClientUpdateResponse{
				EHNamespace: armeventhub.EHNamespace{
					ID:       to.Ptr(testEHNamespaceNativeID),
					Name:     to.Ptr("my-ehns"),
					Location: to.Ptr("eastus"),
					SKU:      params.SKU,
					Tags:     params.Tags,
				},
			}, nil
		},
		beginDeleteFn: func(_ context.Context, _, _ string, _ *armeventhub.NamespacesClientBeginDeleteOptions) (*runtime.Poller[armeventhub.NamespacesClientDeleteResponse], error) {
			return newDonePoller(armeventhub.NamespacesClientDeleteResponse{}), nil
		},
		listByResourceGroupFn: func(_ string, _ *armeventhub.NamespacesClientListByResourceGroupOptions) *runtime.Pager[armeventhub.NamespacesClientListByResourceGroupResponse] {
			return runtime.NewPager(runtime.PagingHandler[armeventhub.NamespacesClientListByResourceGroupResponse]{
				More: func(_ armeventhub.NamespacesClientListByResourceGroupResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armeventhub.NamespacesClientListByResourceGroupResponse) (armeventhub.NamespacesClientListByResourceGroupResponse, error) {
					return armeventhub.NamespacesClientListByResourceGroupResponse{
						EHNamespaceListResult: armeventhub.EHNamespaceListResult{
							Value: []*armeventhub.EHNamespace{
								{ID: to.Ptr(testEHNamespaceNativeID)},
								{ID: to.Ptr("/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.EventHub/namespaces/other-ehns")},
							},
						},
					}, nil
				},
			})
		},
		listFn: func(_ *armeventhub.NamespacesClientListOptions) *runtime.Pager[armeventhub.NamespacesClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armeventhub.NamespacesClientListResponse]{
				More: func(_ armeventhub.NamespacesClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armeventhub.NamespacesClientListResponse) (armeventhub.NamespacesClientListResponse, error) {
					return armeventhub.NamespacesClientListResponse{
						EHNamespaceListResult: armeventhub.EHNamespaceListResult{
							Value: []*armeventhub.EHNamespace{{ID: to.Ptr(testEHNamespaceNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestEventHubNamespace(fake)

	createProps, _ := json.Marshal(map[string]any{
		"resourceGroupName": "rg-1",
		"location":          "eastus",
		"name":              "my-ehns",
		"sku":               map[string]any{"name": "Standard", "tier": "Standard"},
		"zoneRedundant":     true,
	})

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "my-ehns", Properties: createProps})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testEHNamespaceNativeID, got.ProgressResult.NativeID)

		var serialized map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &serialized))
		require.Equal(t, "my-ehns", serialized["name"])
		sku := serialized["sku"].(map[string]any)
		require.Equal(t, "Standard", sku["name"])
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testEHNamespaceNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var serialized map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &serialized))
		require.Equal(t, "my-ehns", serialized["name"])
		require.Equal(t, "rg-1", serialized["resourceGroupName"])
		require.Equal(t, "eastus", serialized["location"])
	})

	t.Run("Update_keeps_native_id", func(t *testing.T) {
		updateProps, _ := json.Marshal(map[string]any{
			"resourceGroupName": "rg-1",
			"location":          "eastus",
			"name":              "my-ehns",
			"sku":               map[string]any{"name": "Standard", "tier": "Standard"},
			"Tags": []map[string]string{
				{"Key": "Environment", "Value": "updated"},
			},
		})
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{NativeID: testEHNamespaceNativeID, DesiredProperties: updateProps})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testEHNamespaceNativeID, got.ProgressResult.NativeID)
	})

	t.Run("Delete", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testEHNamespaceNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _ string, _ *armeventhub.NamespacesClientBeginDeleteOptions) (*runtime.Poller[armeventhub.NamespacesClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testEHNamespaceNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 2)
		require.Equal(t, testEHNamespaceNativeID, got.NativeIDs[0])
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, _ armeventhub.EHNamespace, _ *armeventhub.NamespacesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armeventhub.NamespacesClientCreateOrUpdateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 403}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "my-ehns", Properties: createProps})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

// --- Test helpers ---

func newTestEventHubNamespace(api eventHubNamespacesAPI) *EventHubNamespace {
	return &EventHubNamespace{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

type fakeEventHubNamespacesAPI struct {
	beginCreateOrUpdateFn func(ctx context.Context, resourceGroupName string, namespaceName string, parameters armeventhub.EHNamespace, options *armeventhub.NamespacesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armeventhub.NamespacesClientCreateOrUpdateResponse], error)
	getFn                 func(ctx context.Context, resourceGroupName string, namespaceName string, options *armeventhub.NamespacesClientGetOptions) (armeventhub.NamespacesClientGetResponse, error)
	updateFn              func(ctx context.Context, resourceGroupName string, namespaceName string, parameters armeventhub.EHNamespace, options *armeventhub.NamespacesClientUpdateOptions) (armeventhub.NamespacesClientUpdateResponse, error)
	beginDeleteFn         func(ctx context.Context, resourceGroupName string, namespaceName string, options *armeventhub.NamespacesClientBeginDeleteOptions) (*runtime.Poller[armeventhub.NamespacesClientDeleteResponse], error)
	listByResourceGroupFn func(resourceGroupName string, options *armeventhub.NamespacesClientListByResourceGroupOptions) *runtime.Pager[armeventhub.NamespacesClientListByResourceGroupResponse]
	listFn                func(options *armeventhub.NamespacesClientListOptions) *runtime.Pager[armeventhub.NamespacesClientListResponse]
}

func (f *fakeEventHubNamespacesAPI) BeginCreateOrUpdate(ctx context.Context, resourceGroupName string, namespaceName string, parameters armeventhub.EHNamespace, options *armeventhub.NamespacesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armeventhub.NamespacesClientCreateOrUpdateResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, resourceGroupName, namespaceName, parameters, options)
}

func (f *fakeEventHubNamespacesAPI) Get(ctx context.Context, resourceGroupName string, namespaceName string, options *armeventhub.NamespacesClientGetOptions) (armeventhub.NamespacesClientGetResponse, error) {
	return f.getFn(ctx, resourceGroupName, namespaceName, options)
}

func (f *fakeEventHubNamespacesAPI) Update(ctx context.Context, resourceGroupName string, namespaceName string, parameters armeventhub.EHNamespace, options *armeventhub.NamespacesClientUpdateOptions) (armeventhub.NamespacesClientUpdateResponse, error) {
	return f.updateFn(ctx, resourceGroupName, namespaceName, parameters, options)
}

func (f *fakeEventHubNamespacesAPI) BeginDelete(ctx context.Context, resourceGroupName string, namespaceName string, options *armeventhub.NamespacesClientBeginDeleteOptions) (*runtime.Poller[armeventhub.NamespacesClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, resourceGroupName, namespaceName, options)
}

func (f *fakeEventHubNamespacesAPI) NewListByResourceGroupPager(resourceGroupName string, options *armeventhub.NamespacesClientListByResourceGroupOptions) *runtime.Pager[armeventhub.NamespacesClientListByResourceGroupResponse] {
	return f.listByResourceGroupFn(resourceGroupName, options)
}

func (f *fakeEventHubNamespacesAPI) NewListPager(options *armeventhub.NamespacesClientListOptions) *runtime.Pager[armeventhub.NamespacesClientListResponse] {
	return f.listFn(options)
}
