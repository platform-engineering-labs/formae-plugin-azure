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

const (
	testConnectivityConfigNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/networkManagers/nm-1/connectivityConfigurations/config-1"
	testConnectivityGroupID        = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/networkManagers/nm-1/networkGroups/group-1"
	testConnectivityHubID          = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/virtualNetworks/hub-vnet"
)

func newTestConnectivityConfiguration(api networkManagerConnectivityConfigurationsAPI) *NetworkManagerConnectivityConfiguration {
	return &NetworkManagerConnectivityConfiguration{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

func connectivityConfigDesired(overrides map[string]any) []byte {
	props := map[string]any{
		"name":                 "config-1",
		"resourceGroupName":    "rg-1",
		"networkManagerName":   "nm-1",
		"connectivityTopology": "Mesh",
		"appliesToGroups": []any{map[string]any{
			"networkGroupId":    testConnectivityGroupID,
			"groupConnectivity": "None",
			"isGlobal":          "False",
		}},
		"description": "conformance",
	}
	for k, v := range overrides {
		if v == nil {
			delete(props, k)
			continue
		}
		props[k] = v
	}
	out, _ := json.Marshal(props)
	return out
}

func TestNetworkManagerConnectivityConfiguration_CRUD(t *testing.T) {
	configResult := armnetwork.ConnectivityConfiguration{
		ID:   to.Ptr(testConnectivityConfigNativeID),
		Name: to.Ptr("config-1"),
		Properties: &armnetwork.ConnectivityConfigurationProperties{
			ConnectivityTopology: to.Ptr(armnetwork.ConnectivityTopologyMesh),
			AppliesToGroups: []*armnetwork.ConnectivityGroupItem{{
				NetworkGroupID:    to.Ptr(testConnectivityGroupID),
				GroupConnectivity: to.Ptr(armnetwork.GroupConnectivityNone),
				IsGlobal:          to.Ptr(armnetwork.IsGlobalFalse),
				UseHubGateway:     to.Ptr(armnetwork.UseHubGatewayFalse),
			}},
			IsGlobal:              to.Ptr(armnetwork.IsGlobalFalse),
			DeleteExistingPeering: to.Ptr(armnetwork.DeleteExistingPeeringFalse),
			Description:           to.Ptr("conformance"),
			ProvisioningState:     to.Ptr(armnetwork.ProvisioningStateSucceeded),
			ResourceGUID:          to.Ptr("00000000-0000-0000-0000-000000000000"),
		},
	}

	var sent armnetwork.ConnectivityConfiguration
	var sawForce *bool
	deleteCalls := 0
	fake := &fakeConnectivityConfigurationsAPI{
		createOrUpdateFn: func(_ context.Context, rgName, managerName, name string, params armnetwork.ConnectivityConfiguration, _ *armnetwork.ConnectivityConfigurationsClientCreateOrUpdateOptions) (armnetwork.ConnectivityConfigurationsClientCreateOrUpdateResponse, error) {
			require.Equal(t, "rg-1", rgName)
			require.Equal(t, "nm-1", managerName)
			require.Equal(t, "config-1", name)
			sent = params
			return armnetwork.ConnectivityConfigurationsClientCreateOrUpdateResponse{ConnectivityConfiguration: configResult}, nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ *armnetwork.ConnectivityConfigurationsClientGetOptions) (armnetwork.ConnectivityConfigurationsClientGetResponse, error) {
			return armnetwork.ConnectivityConfigurationsClientGetResponse{ConnectivityConfiguration: configResult}, nil
		},
		beginDeleteFn: func(_ context.Context, _, _, _ string, options *armnetwork.ConnectivityConfigurationsClientBeginDeleteOptions) (*runtime.Poller[armnetwork.ConnectivityConfigurationsClientDeleteResponse], error) {
			deleteCalls++
			if options != nil {
				sawForce = options.Force
			}
			return newDonePoller(armnetwork.ConnectivityConfigurationsClientDeleteResponse{}), nil
		},
		newListPagerFn: func(_, _ string, _ *armnetwork.ConnectivityConfigurationsClientListOptions) *runtime.Pager[armnetwork.ConnectivityConfigurationsClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armnetwork.ConnectivityConfigurationsClientListResponse]{
				More: func(_ armnetwork.ConnectivityConfigurationsClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armnetwork.ConnectivityConfigurationsClientListResponse) (armnetwork.ConnectivityConfigurationsClientListResponse, error) {
					return armnetwork.ConnectivityConfigurationsClientListResponse{
						ConnectivityConfigurationListResult: armnetwork.ConnectivityConfigurationListResult{
							Value: []*armnetwork.ConnectivityConfiguration{{ID: to.Ptr(testConnectivityConfigNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestConnectivityConfiguration(fake)

	t.Run("Create_mesh", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "config-1",
			Properties: connectivityConfigDesired(nil),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testConnectivityConfigNativeID, got.ProgressResult.NativeID)
		require.Equal(t, armnetwork.ConnectivityTopologyMesh, *sent.Properties.ConnectivityTopology)
		require.Len(t, sent.Properties.AppliesToGroups, 1)
		require.Equal(t, testConnectivityGroupID, *sent.Properties.AppliesToGroups[0].NetworkGroupID)
		require.Equal(t, armnetwork.GroupConnectivityNone, *sent.Properties.AppliesToGroups[0].GroupConnectivity)
		require.Equal(t, armnetwork.IsGlobalFalse, *sent.Properties.AppliesToGroups[0].IsGlobal)
		// An unset flag is left out of the body so ARM applies its own default.
		require.Nil(t, sent.Properties.AppliesToGroups[0].UseHubGateway)
		require.Nil(t, sent.Properties.Hubs)
	})

	t.Run("Create_hub_and_spoke", func(t *testing.T) {
		_, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "config-1",
			Properties: connectivityConfigDesired(map[string]any{
				"connectivityTopology": "HubAndSpoke",
				"hubs": []any{map[string]any{
					"resourceId":   testConnectivityHubID,
					"resourceType": "Microsoft.Network/virtualNetworks",
				}},
			}),
		})
		require.NoError(t, err)
		require.Len(t, sent.Properties.Hubs, 1)
		require.Equal(t, testConnectivityHubID, *sent.Properties.Hubs[0].ResourceID)
	})

	// ARM answers both of these with a generic BadRequest that names neither
	// side, so the pairing is checked before the call.
	t.Run("Create_hub_and_spoke_requires_a_hub", func(t *testing.T) {
		_, err := prov.Create(context.Background(), &resource.CreateRequest{
			Properties: connectivityConfigDesired(map[string]any{"connectivityTopology": "HubAndSpoke"}),
		})
		require.ErrorContains(t, err, "hubs is required for the HubAndSpoke topology")
	})

	t.Run("Create_mesh_rejects_a_hub", func(t *testing.T) {
		_, err := prov.Create(context.Background(), &resource.CreateRequest{
			Properties: connectivityConfigDesired(map[string]any{
				"hubs": []any{map[string]any{
					"resourceId":   testConnectivityHubID,
					"resourceType": "Microsoft.Network/virtualNetworks",
				}},
			}),
		})
		require.ErrorContains(t, err, "hubs must be empty for the Mesh topology")
	})

	t.Run("Create_requires_applies_to_groups", func(t *testing.T) {
		_, err := prov.Create(context.Background(), &resource.CreateRequest{
			Properties: connectivityConfigDesired(map[string]any{"appliesToGroups": nil}),
		})
		require.ErrorContains(t, err, "appliesToGroups is required")
	})

	t.Run("Create_requires_manager", func(t *testing.T) {
		_, err := prov.Create(context.Background(), &resource.CreateRequest{
			Properties: connectivityConfigDesired(map[string]any{"networkManagerName": nil}),
		})
		require.ErrorContains(t, err, "networkManagerName is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testConnectivityConfigNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "config-1", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "nm-1", props["networkManagerName"])
		require.Equal(t, "Mesh", props["connectivityTopology"])
		require.Equal(t, "False", props["isGlobal"])
		require.Equal(t, "False", props["deleteExistingPeering"])
		require.Equal(t, []any{map[string]any{
			"networkGroupId":    testConnectivityGroupID,
			"groupConnectivity": "None",
			"isGlobal":          "False",
			"useHubGateway":     "False",
		}}, props["appliesToGroups"])
		require.NotContains(t, got.Properties, "provisioningState")
	})

	t.Run("Update", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testConnectivityConfigNativeID,
			DesiredProperties: connectivityConfigDesired(map[string]any{"description": "redescribed"}),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, "redescribed", *sent.Properties.Description)
	})

	t.Run("Delete_sends_force", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testConnectivityConfigNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
		require.NotNil(t, sawForce)
		require.True(t, *sawForce)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _, _ string, _ *armnetwork.ConnectivityConfigurationsClientBeginDeleteOptions) (*runtime.Poller[armnetwork.ConnectivityConfigurationsClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testConnectivityConfigNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_manager", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "networkManagerName": "nm-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testConnectivityConfigNativeID}, got.NativeIDs)
	})

	t.Run("List_without_parents_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure_with_message", func(t *testing.T) {
		fake.createOrUpdateFn = func(_ context.Context, _, _, _ string, _ armnetwork.ConnectivityConfiguration, _ *armnetwork.ConnectivityConfigurationsClientCreateOrUpdateOptions) (armnetwork.ConnectivityConfigurationsClientCreateOrUpdateResponse, error) {
			return armnetwork.ConnectivityConfigurationsClientCreateOrUpdateResponse{}, &azcore.ResponseError{StatusCode: 409}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "config-1", Properties: connectivityConfigDesired(nil),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.NotEmpty(t, got.ProgressResult.StatusMessage)
	})
}

func TestNetworkManagerConnectivityConfiguration_ReadNotFound(t *testing.T) {
	fake := &fakeConnectivityConfigurationsAPI{
		getFn: func(_ context.Context, _, _, _ string, _ *armnetwork.ConnectivityConfigurationsClientGetOptions) (armnetwork.ConnectivityConfigurationsClientGetResponse, error) {
			return armnetwork.ConnectivityConfigurationsClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestConnectivityConfiguration(fake).Read(context.Background(),
		&resource.ReadRequest{NativeID: testConnectivityConfigNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeConnectivityConfigurationsAPI struct {
	createOrUpdateFn func(ctx context.Context, rgName, managerName, name string, params armnetwork.ConnectivityConfiguration, options *armnetwork.ConnectivityConfigurationsClientCreateOrUpdateOptions) (armnetwork.ConnectivityConfigurationsClientCreateOrUpdateResponse, error)
	getFn            func(ctx context.Context, rgName, managerName, name string, options *armnetwork.ConnectivityConfigurationsClientGetOptions) (armnetwork.ConnectivityConfigurationsClientGetResponse, error)
	beginDeleteFn    func(ctx context.Context, rgName, managerName, name string, options *armnetwork.ConnectivityConfigurationsClientBeginDeleteOptions) (*runtime.Poller[armnetwork.ConnectivityConfigurationsClientDeleteResponse], error)
	newListPagerFn   func(rgName, managerName string, options *armnetwork.ConnectivityConfigurationsClientListOptions) *runtime.Pager[armnetwork.ConnectivityConfigurationsClientListResponse]
}

func (f *fakeConnectivityConfigurationsAPI) CreateOrUpdate(ctx context.Context, rgName, managerName, name string, params armnetwork.ConnectivityConfiguration, options *armnetwork.ConnectivityConfigurationsClientCreateOrUpdateOptions) (armnetwork.ConnectivityConfigurationsClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, managerName, name, params, options)
}

func (f *fakeConnectivityConfigurationsAPI) Get(ctx context.Context, rgName, managerName, name string, options *armnetwork.ConnectivityConfigurationsClientGetOptions) (armnetwork.ConnectivityConfigurationsClientGetResponse, error) {
	return f.getFn(ctx, rgName, managerName, name, options)
}

func (f *fakeConnectivityConfigurationsAPI) BeginDelete(ctx context.Context, rgName, managerName, name string, options *armnetwork.ConnectivityConfigurationsClientBeginDeleteOptions) (*runtime.Poller[armnetwork.ConnectivityConfigurationsClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, managerName, name, options)
}

func (f *fakeConnectivityConfigurationsAPI) NewListPager(rgName, managerName string, options *armnetwork.ConnectivityConfigurationsClientListOptions) *runtime.Pager[armnetwork.ConnectivityConfigurationsClientListResponse] {
	return f.newListPagerFn(rgName, managerName, options)
}
