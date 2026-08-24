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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/monitor/armmonitor"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const (
	testScopedResourceNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Insights/privateLinkScopes/ampls1/scopedResources/link1"
	testScopedWorkspaceID      = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.OperationalInsights/workspaces/ws1"
)

type fakeScopedResourcesAPI struct {
	beginCreateOrUpdateFn func(ctx context.Context, rgName, scopeName, name string, params armmonitor.ScopedResource, options *armmonitor.PrivateLinkScopedResourcesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armmonitor.PrivateLinkScopedResourcesClientCreateOrUpdateResponse], error)
	getFn                 func(ctx context.Context, rgName, scopeName, name string, options *armmonitor.PrivateLinkScopedResourcesClientGetOptions) (armmonitor.PrivateLinkScopedResourcesClientGetResponse, error)
	beginDeleteFn         func(ctx context.Context, rgName, scopeName, name string, options *armmonitor.PrivateLinkScopedResourcesClientBeginDeleteOptions) (*runtime.Poller[armmonitor.PrivateLinkScopedResourcesClientDeleteResponse], error)
	listPagerFn           func(rgName, scopeName string, options *armmonitor.PrivateLinkScopedResourcesClientListByPrivateLinkScopeOptions) *runtime.Pager[armmonitor.PrivateLinkScopedResourcesClientListByPrivateLinkScopeResponse]
}

func (f *fakeScopedResourcesAPI) BeginCreateOrUpdate(ctx context.Context, rgName, scopeName, name string, params armmonitor.ScopedResource, options *armmonitor.PrivateLinkScopedResourcesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armmonitor.PrivateLinkScopedResourcesClientCreateOrUpdateResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, rgName, scopeName, name, params, options)
}

func (f *fakeScopedResourcesAPI) Get(ctx context.Context, rgName, scopeName, name string, options *armmonitor.PrivateLinkScopedResourcesClientGetOptions) (armmonitor.PrivateLinkScopedResourcesClientGetResponse, error) {
	return f.getFn(ctx, rgName, scopeName, name, options)
}

func (f *fakeScopedResourcesAPI) BeginDelete(ctx context.Context, rgName, scopeName, name string, options *armmonitor.PrivateLinkScopedResourcesClientBeginDeleteOptions) (*runtime.Poller[armmonitor.PrivateLinkScopedResourcesClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, scopeName, name, options)
}

func (f *fakeScopedResourcesAPI) NewListByPrivateLinkScopePager(rgName, scopeName string, options *armmonitor.PrivateLinkScopedResourcesClientListByPrivateLinkScopeOptions) *runtime.Pager[armmonitor.PrivateLinkScopedResourcesClientListByPrivateLinkScopeResponse] {
	return f.listPagerFn(rgName, scopeName, options)
}

func newTestScopedResource(api monitorPrivateLinkScopedResourcesAPI) *MonitorPrivateLinkScopedResource {
	return &MonitorPrivateLinkScopedResource{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func scopedResourceDesired(linkedID string) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":              "link1",
		"resourceGroupName": "rg-1",
		"scopeName":         "ampls1",
		"linkedResourceId":  linkedID,
	})
	return out
}

func TestMonitorPrivateLinkScopedResource_CRUD(t *testing.T) {
	scopedResult := armmonitor.ScopedResource{
		ID:   to.Ptr(testScopedResourceNativeID),
		Name: to.Ptr("link1"),
		Properties: &armmonitor.ScopedResourceProperties{
			LinkedResourceID: to.Ptr(testScopedWorkspaceID),
			// All three are derived by the service from the linked resource, or plain
			// service state. None can be set, so none may reach desired state.
			Kind:                 to.Ptr(armmonitor.ScopedResourceKind("Resource")),
			SubscriptionLocation: to.Ptr("eastus"),
			ProvisioningState:    to.Ptr(armmonitor.ScopedResourceProvisioningStateSucceeded),
		},
	}

	var sent armmonitor.ScopedResource
	createCalls := 0
	deleteCalls := 0
	fake := &fakeScopedResourcesAPI{
		beginCreateOrUpdateFn: func(_ context.Context, rgName, scopeName, name string, params armmonitor.ScopedResource, _ *armmonitor.PrivateLinkScopedResourcesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armmonitor.PrivateLinkScopedResourcesClientCreateOrUpdateResponse], error) {
			require.Equal(t, "rg-1", rgName)
			require.Equal(t, "ampls1", scopeName)
			require.Equal(t, "link1", name)
			sent = params
			createCalls++
			return newDonePoller(armmonitor.PrivateLinkScopedResourcesClientCreateOrUpdateResponse{ScopedResource: scopedResult}), nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ *armmonitor.PrivateLinkScopedResourcesClientGetOptions) (armmonitor.PrivateLinkScopedResourcesClientGetResponse, error) {
			return armmonitor.PrivateLinkScopedResourcesClientGetResponse{ScopedResource: scopedResult}, nil
		},
		beginDeleteFn: func(_ context.Context, _, _, _ string, _ *armmonitor.PrivateLinkScopedResourcesClientBeginDeleteOptions) (*runtime.Poller[armmonitor.PrivateLinkScopedResourcesClientDeleteResponse], error) {
			deleteCalls++
			return newDonePoller(armmonitor.PrivateLinkScopedResourcesClientDeleteResponse{}), nil
		},
		listPagerFn: func(_, _ string, _ *armmonitor.PrivateLinkScopedResourcesClientListByPrivateLinkScopeOptions) *runtime.Pager[armmonitor.PrivateLinkScopedResourcesClientListByPrivateLinkScopeResponse] {
			return runtime.NewPager(runtime.PagingHandler[armmonitor.PrivateLinkScopedResourcesClientListByPrivateLinkScopeResponse]{
				More: func(_ armmonitor.PrivateLinkScopedResourcesClientListByPrivateLinkScopeResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armmonitor.PrivateLinkScopedResourcesClientListByPrivateLinkScopeResponse) (armmonitor.PrivateLinkScopedResourcesClientListByPrivateLinkScopeResponse, error) {
					return armmonitor.PrivateLinkScopedResourcesClientListByPrivateLinkScopeResponse{
						ScopedResourceListResult: armmonitor.ScopedResourceListResult{
							Value: []*armmonitor.ScopedResource{
								{ID: to.Ptr(testScopedResourceNativeID)},
								// A nil entry must not panic the walk.
								nil,
							},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestScopedResource(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "link1", Properties: scopedResourceDesired(testScopedWorkspaceID),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testScopedResourceNativeID, got.ProgressResult.NativeID)

		require.Equal(t, testScopedWorkspaceID, *sent.Properties.LinkedResourceID)
		// Service-derived fields must not be asserted by the caller.
		require.Nil(t, sent.Properties.Kind)
		require.Nil(t, sent.Properties.SubscriptionLocation)
	})

	t.Run("Create_requires_linked_resource", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "link1", "resourceGroupName": "rg-1", "scopeName": "ampls1",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "linkedResourceId is required")
	})

	t.Run("Create_requires_scope", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "link1", "resourceGroupName": "rg-1"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "scopeName is required")
	})

	// The native ID reported while the LRO is still running must match the path ARM
	// actually assigns, or the resource is orphaned once it completes.
	t.Run("PendingCreateReportsRealNativeID", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _, _ string, _ armmonitor.ScopedResource, _ *armmonitor.PrivateLinkScopedResourcesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armmonitor.PrivateLinkScopedResourcesClientCreateOrUpdateResponse], error) {
			return newPendingPoller[armmonitor.PrivateLinkScopedResourcesClientCreateOrUpdateResponse](), nil
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "link1", Properties: scopedResourceDesired(testScopedWorkspaceID),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusInProgress, got.ProgressResult.OperationStatus)
		require.Equal(t, testScopedResourceNativeID, got.ProgressResult.NativeID)
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testScopedResourceNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "link1", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		// Both the scope name and the group come off the native ID.
		require.Equal(t, "ampls1", props["scopeName"])
		require.Equal(t, testScopedWorkspaceID, props["linkedResourceId"])
	})

	t.Run("Read_drops_service_derived_fields", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testScopedResourceNativeID})
		require.NoError(t, err)
		for _, key := range []string{"kind", "subscriptionLocation", "provisioningState", "systemData"} {
			require.NotContains(t, got.Properties, key)
		}
	})

	t.Run("Delete", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testScopedResourceNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
	})

	t.Run("PendingDeleteReportsInProgress", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _, _ string, _ *armmonitor.PrivateLinkScopedResourcesClientBeginDeleteOptions) (*runtime.Poller[armmonitor.PrivateLinkScopedResourcesClientDeleteResponse], error) {
			return newPendingPoller[armmonitor.PrivateLinkScopedResourcesClientDeleteResponse](), nil
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testScopedResourceNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusInProgress, got.ProgressResult.OperationStatus)

		reqID, err := decodeLROStatus(got.ProgressResult.RequestID)
		require.NoError(t, err)
		require.Equal(t, lroOpDelete, reqID.OperationType)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _, _ string, _ *armmonitor.PrivateLinkScopedResourcesClientBeginDeleteOptions) (*runtime.Poller[armmonitor.PrivateLinkScopedResourcesClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testScopedResourceNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "scopeName": "ampls1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testScopedResourceNativeID}, got.NativeIDs)
	})

	t.Run("List_without_scope_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})

	t.Run("Read_NotFound", func(t *testing.T) {
		fake.getFn = func(_ context.Context, _, _, _ string, _ *armmonitor.PrivateLinkScopedResourcesClientGetOptions) (armmonitor.PrivateLinkScopedResourcesClientGetResponse, error) {
			return armmonitor.PrivateLinkScopedResourcesClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testScopedResourceNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
	})
}
