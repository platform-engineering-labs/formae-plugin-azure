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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v4"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testNetworkManagerNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/networkManagers/nm-1"

func newTestNetworkManager(api networkManagersAPI) *NetworkManager {
	return &NetworkManager{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

func networkManagerDesired(description string) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":                        "nm-1",
		"location":                    "eastus",
		"resourceGroupName":           "rg-1",
		"networkManagerScopeAccesses": []any{"Connectivity", "SecurityAdmin"},
		"networkManagerScopes": map[string]any{
			"subscriptions": []any{"/subscriptions/sub-1"},
		},
		"description": description,
		"Tags":        []any{map[string]any{"Key": "env", "Value": "test"}},
	})
	return out
}

func TestNetworkManager_CRUD(t *testing.T) {
	managerResult := armnetwork.Manager{
		ID:       to.Ptr(testNetworkManagerNativeID),
		Name:     to.Ptr("nm-1"),
		Location: to.Ptr("East US"),
		Properties: &armnetwork.ManagerProperties{
			Description: to.Ptr("conformance"),
			NetworkManagerScopeAccesses: []*armnetwork.ConfigurationType{
				to.Ptr(armnetwork.ConfigurationTypeConnectivity),
				to.Ptr(armnetwork.ConfigurationTypeSecurityAdmin),
			},
			NetworkManagerScopes: &armnetwork.ManagerPropertiesNetworkManagerScopes{
				Subscriptions: []*string{to.Ptr("/subscriptions/sub-1")},
			},
			ProvisioningState: to.Ptr(armnetwork.ProvisioningStateSucceeded),
			ResourceGUID:      to.Ptr("00000000-0000-0000-0000-000000000000"),
		},
		Tags: map[string]*string{"env": to.Ptr("test")},
	}

	var sent armnetwork.Manager
	var sawForce *bool
	deleteCalls := 0
	fake := &fakeNetworkManagersAPI{
		createOrUpdateFn: func(_ context.Context, rgName, name string, params armnetwork.Manager, _ *armnetwork.ManagersClientCreateOrUpdateOptions) (armnetwork.ManagersClientCreateOrUpdateResponse, error) {
			require.Equal(t, "rg-1", rgName)
			require.Equal(t, "nm-1", name)
			sent = params
			return armnetwork.ManagersClientCreateOrUpdateResponse{Manager: managerResult}, nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armnetwork.ManagersClientGetOptions) (armnetwork.ManagersClientGetResponse, error) {
			return armnetwork.ManagersClientGetResponse{Manager: managerResult}, nil
		},
		beginDeleteFn: func(_ context.Context, _, _ string, options *armnetwork.ManagersClientBeginDeleteOptions) (*runtime.Poller[armnetwork.ManagersClientDeleteResponse], error) {
			deleteCalls++
			if options != nil {
				sawForce = options.Force
			}
			return newDonePoller(armnetwork.ManagersClientDeleteResponse{}), nil
		},
		newListPagerFn: func(_ string, _ *armnetwork.ManagersClientListOptions) *runtime.Pager[armnetwork.ManagersClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armnetwork.ManagersClientListResponse]{
				More: func(_ armnetwork.ManagersClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armnetwork.ManagersClientListResponse) (armnetwork.ManagersClientListResponse, error) {
					return armnetwork.ManagersClientListResponse{
						ManagerListResult: armnetwork.ManagerListResult{
							Value: []*armnetwork.Manager{{ID: to.Ptr(testNetworkManagerNativeID)}},
						},
					}, nil
				},
			})
		},
		newListBySubscriptionPagerFn: func(_ *armnetwork.ManagersClientListBySubscriptionOptions) *runtime.Pager[armnetwork.ManagersClientListBySubscriptionResponse] {
			return runtime.NewPager(runtime.PagingHandler[armnetwork.ManagersClientListBySubscriptionResponse]{
				More: func(_ armnetwork.ManagersClientListBySubscriptionResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armnetwork.ManagersClientListBySubscriptionResponse) (armnetwork.ManagersClientListBySubscriptionResponse, error) {
					return armnetwork.ManagersClientListBySubscriptionResponse{
						ManagerListResult: armnetwork.ManagerListResult{
							Value: []*armnetwork.Manager{{ID: to.Ptr(testNetworkManagerNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestNetworkManager(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "nm-1",
			Properties: networkManagerDesired("conformance"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testNetworkManagerNativeID, got.ProgressResult.NativeID)
		require.Equal(t, "eastus", *sent.Location)
		require.Len(t, sent.Properties.NetworkManagerScopeAccesses, 2)
		require.Equal(t, armnetwork.ConfigurationTypeConnectivity, *sent.Properties.NetworkManagerScopeAccesses[0])
		require.Equal(t, []*string{to.Ptr("/subscriptions/sub-1")}, sent.Properties.NetworkManagerScopes.Subscriptions)
		require.Equal(t, "conformance", *sent.Properties.Description)
		require.Equal(t, "test", *sent.Tags["env"])
	})

	// Management group scope is not modelled at all, so nothing can put one in
	// the request body — the field does not exist on the schema class.
	t.Run("Create_never_sends_management_groups", func(t *testing.T) {
		require.Nil(t, sent.Properties.NetworkManagerScopes.ManagementGroups)
	})

	t.Run("Create_requires_resource_group", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "nm-1", "location": "eastus"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "resourceGroupName is required")
	})

	t.Run("Create_requires_location", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "nm-1", "resourceGroupName": "rg-1"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "location is required")
	})

	t.Run("Create_requires_scope_accesses", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "nm-1", "location": "eastus", "resourceGroupName": "rg-1",
			"networkManagerScopes": map[string]any{"subscriptions": []any{"/subscriptions/sub-1"}},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "networkManagerScopeAccesses is required")
	})

	t.Run("Create_requires_subscription_scope", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "nm-1", "location": "eastus", "resourceGroupName": "rg-1",
			"networkManagerScopeAccesses": []any{"Connectivity"},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "networkManagerScopes.subscriptions is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testNetworkManagerNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "nm-1", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "eastus", props["location"])
		require.Equal(t, []any{"Connectivity", "SecurityAdmin"}, props["networkManagerScopeAccesses"])
		require.Equal(t, map[string]any{"subscriptions": []any{"/subscriptions/sub-1"}}, props["networkManagerScopes"])
		require.Equal(t, "conformance", props["description"])
	})

	t.Run("Read_drops_service_owned_fields", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testNetworkManagerNativeID})
		require.NoError(t, err)
		require.NotContains(t, got.Properties, "provisioningState")
		require.NotContains(t, got.Properties, "resourceGuid")
	})

	t.Run("Update_reissues_create_or_update", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testNetworkManagerNativeID,
			DesiredProperties: networkManagerDesired("redescribed"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, "redescribed", *sent.Properties.Description)
	})

	// Force is the only way past ARM's refusal to delete a manager that still
	// owns a deployed configuration.
	t.Run("Delete_sends_force", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testNetworkManagerNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
		require.NotNil(t, sawForce)
		require.True(t, *sawForce)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _ string, _ *armnetwork.ManagersClientBeginDeleteOptions) (*runtime.Poller[armnetwork.ManagersClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testNetworkManagerNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_resource_group", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testNetworkManagerNativeID}, got.NativeIDs)
	})

	t.Run("List_without_resource_group_falls_back_to_subscription", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Equal(t, []string{testNetworkManagerNativeID}, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure_with_message", func(t *testing.T) {
		fake.createOrUpdateFn = func(_ context.Context, _, _ string, _ armnetwork.Manager, _ *armnetwork.ManagersClientCreateOrUpdateOptions) (armnetwork.ManagersClientCreateOrUpdateResponse, error) {
			return armnetwork.ManagersClientCreateOrUpdateResponse{}, &azcore.ResponseError{StatusCode: 409}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "nm-1", Properties: networkManagerDesired("conformance"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.NotEmpty(t, got.ProgressResult.StatusMessage)
	})
}

func TestNetworkManager_ReadNotFound(t *testing.T) {
	fake := &fakeNetworkManagersAPI{
		getFn: func(_ context.Context, _, _ string, _ *armnetwork.ManagersClientGetOptions) (armnetwork.ManagersClientGetResponse, error) {
			return armnetwork.ManagersClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestNetworkManager(fake).Read(context.Background(),
		&resource.ReadRequest{NativeID: testNetworkManagerNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeNetworkManagersAPI struct {
	createOrUpdateFn             func(ctx context.Context, rgName, name string, params armnetwork.Manager, options *armnetwork.ManagersClientCreateOrUpdateOptions) (armnetwork.ManagersClientCreateOrUpdateResponse, error)
	getFn                        func(ctx context.Context, rgName, name string, options *armnetwork.ManagersClientGetOptions) (armnetwork.ManagersClientGetResponse, error)
	beginDeleteFn                func(ctx context.Context, rgName, name string, options *armnetwork.ManagersClientBeginDeleteOptions) (*runtime.Poller[armnetwork.ManagersClientDeleteResponse], error)
	newListPagerFn               func(rgName string, options *armnetwork.ManagersClientListOptions) *runtime.Pager[armnetwork.ManagersClientListResponse]
	newListBySubscriptionPagerFn func(options *armnetwork.ManagersClientListBySubscriptionOptions) *runtime.Pager[armnetwork.ManagersClientListBySubscriptionResponse]
}

func (f *fakeNetworkManagersAPI) CreateOrUpdate(ctx context.Context, rgName, name string, params armnetwork.Manager, options *armnetwork.ManagersClientCreateOrUpdateOptions) (armnetwork.ManagersClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, name, params, options)
}

func (f *fakeNetworkManagersAPI) Get(ctx context.Context, rgName, name string, options *armnetwork.ManagersClientGetOptions) (armnetwork.ManagersClientGetResponse, error) {
	return f.getFn(ctx, rgName, name, options)
}

func (f *fakeNetworkManagersAPI) BeginDelete(ctx context.Context, rgName, name string, options *armnetwork.ManagersClientBeginDeleteOptions) (*runtime.Poller[armnetwork.ManagersClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, name, options)
}

func (f *fakeNetworkManagersAPI) NewListPager(rgName string, options *armnetwork.ManagersClientListOptions) *runtime.Pager[armnetwork.ManagersClientListResponse] {
	return f.newListPagerFn(rgName, options)
}

func (f *fakeNetworkManagersAPI) NewListBySubscriptionPager(options *armnetwork.ManagersClientListBySubscriptionOptions) *runtime.Pager[armnetwork.ManagersClientListBySubscriptionResponse] {
	return f.newListBySubscriptionPagerFn(options)
}
