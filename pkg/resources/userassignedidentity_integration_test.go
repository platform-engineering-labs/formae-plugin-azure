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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/msi/armmsi"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testUAINativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.ManagedIdentity/userAssignedIdentities/my-identity"

func TestUserAssignedIdentity_CRUD(t *testing.T) {
	fake := &fakeUserAssignedIdentitiesAPI{
		createOrUpdateFn: func(_ context.Context, _, _ string, _ armmsi.Identity, _ *armmsi.UserAssignedIdentitiesClientCreateOrUpdateOptions) (armmsi.UserAssignedIdentitiesClientCreateOrUpdateResponse, error) {
			return armmsi.UserAssignedIdentitiesClientCreateOrUpdateResponse{
				Identity: armmsi.Identity{
					ID:       to.Ptr(testUAINativeID),
					Name:     to.Ptr("my-identity"),
					Location: to.Ptr("eastus"),
					Properties: &armmsi.UserAssignedIdentityProperties{
						PrincipalID: to.Ptr("principal-123"),
						ClientID:    to.Ptr("client-456"),
						TenantID:    to.Ptr("tenant-789"),
					},
				},
			}, nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armmsi.UserAssignedIdentitiesClientGetOptions) (armmsi.UserAssignedIdentitiesClientGetResponse, error) {
			return armmsi.UserAssignedIdentitiesClientGetResponse{
				Identity: armmsi.Identity{
					ID:       to.Ptr(testUAINativeID),
					Name:     to.Ptr("my-identity"),
					Location: to.Ptr("eastus"),
					Properties: &armmsi.UserAssignedIdentityProperties{
						PrincipalID: to.Ptr("principal-123"),
						ClientID:    to.Ptr("client-456"),
						TenantID:    to.Ptr("tenant-789"),
					},
				},
			}, nil
		},
		updateFn: func(_ context.Context, _, _ string, _ armmsi.IdentityUpdate, _ *armmsi.UserAssignedIdentitiesClientUpdateOptions) (armmsi.UserAssignedIdentitiesClientUpdateResponse, error) {
			return armmsi.UserAssignedIdentitiesClientUpdateResponse{
				Identity: armmsi.Identity{
					ID:       to.Ptr(testUAINativeID),
					Name:     to.Ptr("my-identity"),
					Location: to.Ptr("eastus"),
					Properties: &armmsi.UserAssignedIdentityProperties{
						PrincipalID: to.Ptr("principal-123"),
					},
				},
			}, nil
		},
		deleteFn: func(_ context.Context, _, _ string, _ *armmsi.UserAssignedIdentitiesClientDeleteOptions) (armmsi.UserAssignedIdentitiesClientDeleteResponse, error) {
			return armmsi.UserAssignedIdentitiesClientDeleteResponse{}, nil
		},
		listByResourceGroupFn: func(_ string, _ *armmsi.UserAssignedIdentitiesClientListByResourceGroupOptions) *runtime.Pager[armmsi.UserAssignedIdentitiesClientListByResourceGroupResponse] {
			return runtime.NewPager(runtime.PagingHandler[armmsi.UserAssignedIdentitiesClientListByResourceGroupResponse]{
				More: func(_ armmsi.UserAssignedIdentitiesClientListByResourceGroupResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armmsi.UserAssignedIdentitiesClientListByResourceGroupResponse) (armmsi.UserAssignedIdentitiesClientListByResourceGroupResponse, error) {
					return armmsi.UserAssignedIdentitiesClientListByResourceGroupResponse{
						UserAssignedIdentitiesListResult: armmsi.UserAssignedIdentitiesListResult{
							Value: []*armmsi.Identity{
								{ID: to.Ptr(testUAINativeID)},
								{ID: to.Ptr("/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.ManagedIdentity/userAssignedIdentities/other-identity")},
							},
						},
					}, nil
				},
			})
		},
		listBySubscriptionFn: func(_ *armmsi.UserAssignedIdentitiesClientListBySubscriptionOptions) *runtime.Pager[armmsi.UserAssignedIdentitiesClientListBySubscriptionResponse] {
			return runtime.NewPager(runtime.PagingHandler[armmsi.UserAssignedIdentitiesClientListBySubscriptionResponse]{
				More: func(_ armmsi.UserAssignedIdentitiesClientListBySubscriptionResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armmsi.UserAssignedIdentitiesClientListBySubscriptionResponse) (armmsi.UserAssignedIdentitiesClientListBySubscriptionResponse, error) {
					return armmsi.UserAssignedIdentitiesClientListBySubscriptionResponse{
						UserAssignedIdentitiesListResult: armmsi.UserAssignedIdentitiesListResult{
							Value: []*armmsi.Identity{{ID: to.Ptr(testUAINativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestUserAssignedIdentity(fake)

	t.Run("Create", func(t *testing.T) {
		props, _ := json.Marshal(map[string]interface{}{
			"resourceGroupName": "rg-1", "name": "my-identity", "location": "eastus",
		})
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "test-uai", Properties: props})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testUAINativeID, got.ProgressResult.NativeID)
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testUAINativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var serialized map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &serialized))
		require.Equal(t, "my-identity", serialized["name"])
		require.Equal(t, "rg-1", serialized["resourceGroupName"])
		require.Equal(t, "eastus", serialized["location"])
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _ string, _ *armmsi.UserAssignedIdentitiesClientDeleteOptions) (armmsi.UserAssignedIdentitiesClientDeleteResponse, error) {
			return armmsi.UserAssignedIdentitiesClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testUAINativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 2)
		require.Equal(t, testUAINativeID, got.NativeIDs[0])
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.createOrUpdateFn = func(_ context.Context, _, _ string, _ armmsi.Identity, _ *armmsi.UserAssignedIdentitiesClientCreateOrUpdateOptions) (armmsi.UserAssignedIdentitiesClientCreateOrUpdateResponse, error) {
			return armmsi.UserAssignedIdentitiesClientCreateOrUpdateResponse{}, &azcore.ResponseError{StatusCode: 409}
		}
		props, _ := json.Marshal(map[string]interface{}{
			"resourceGroupName": "rg-1", "name": "my-identity", "location": "eastus",
		})
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

// --- Test helpers ---

func newTestUserAssignedIdentity(api userAssignedIdentitiesAPI) *UserAssignedIdentity {
	return &UserAssignedIdentity{api: api, config: nil}
}

type fakeUserAssignedIdentitiesAPI struct {
	createOrUpdateFn      func(ctx context.Context, rgName, resourceName string, params armmsi.Identity, opts *armmsi.UserAssignedIdentitiesClientCreateOrUpdateOptions) (armmsi.UserAssignedIdentitiesClientCreateOrUpdateResponse, error)
	getFn                 func(ctx context.Context, rgName, resourceName string, opts *armmsi.UserAssignedIdentitiesClientGetOptions) (armmsi.UserAssignedIdentitiesClientGetResponse, error)
	updateFn              func(ctx context.Context, rgName, resourceName string, params armmsi.IdentityUpdate, opts *armmsi.UserAssignedIdentitiesClientUpdateOptions) (armmsi.UserAssignedIdentitiesClientUpdateResponse, error)
	deleteFn              func(ctx context.Context, rgName, resourceName string, opts *armmsi.UserAssignedIdentitiesClientDeleteOptions) (armmsi.UserAssignedIdentitiesClientDeleteResponse, error)
	listByResourceGroupFn func(rgName string, opts *armmsi.UserAssignedIdentitiesClientListByResourceGroupOptions) *runtime.Pager[armmsi.UserAssignedIdentitiesClientListByResourceGroupResponse]
	listBySubscriptionFn  func(opts *armmsi.UserAssignedIdentitiesClientListBySubscriptionOptions) *runtime.Pager[armmsi.UserAssignedIdentitiesClientListBySubscriptionResponse]
}

func (f *fakeUserAssignedIdentitiesAPI) CreateOrUpdate(ctx context.Context, rgName, resourceName string, params armmsi.Identity, opts *armmsi.UserAssignedIdentitiesClientCreateOrUpdateOptions) (armmsi.UserAssignedIdentitiesClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, resourceName, params, opts)
}

func (f *fakeUserAssignedIdentitiesAPI) Get(ctx context.Context, rgName, resourceName string, opts *armmsi.UserAssignedIdentitiesClientGetOptions) (armmsi.UserAssignedIdentitiesClientGetResponse, error) {
	return f.getFn(ctx, rgName, resourceName, opts)
}

func (f *fakeUserAssignedIdentitiesAPI) Update(ctx context.Context, rgName, resourceName string, params armmsi.IdentityUpdate, opts *armmsi.UserAssignedIdentitiesClientUpdateOptions) (armmsi.UserAssignedIdentitiesClientUpdateResponse, error) {
	return f.updateFn(ctx, rgName, resourceName, params, opts)
}

func (f *fakeUserAssignedIdentitiesAPI) Delete(ctx context.Context, rgName, resourceName string, opts *armmsi.UserAssignedIdentitiesClientDeleteOptions) (armmsi.UserAssignedIdentitiesClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, resourceName, opts)
}

func (f *fakeUserAssignedIdentitiesAPI) NewListByResourceGroupPager(rgName string, opts *armmsi.UserAssignedIdentitiesClientListByResourceGroupOptions) *runtime.Pager[armmsi.UserAssignedIdentitiesClientListByResourceGroupResponse] {
	return f.listByResourceGroupFn(rgName, opts)
}

func (f *fakeUserAssignedIdentitiesAPI) NewListBySubscriptionPager(opts *armmsi.UserAssignedIdentitiesClientListBySubscriptionOptions) *runtime.Pager[armmsi.UserAssignedIdentitiesClientListBySubscriptionResponse] {
	return f.listBySubscriptionFn(opts)
}
