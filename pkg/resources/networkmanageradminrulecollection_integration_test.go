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
	testAdminRuleCollectionNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/networkManagers/nm-1/securityAdminConfigurations/config-1/ruleCollections/collection-1"
	testAdminRuleCollectionGroupID  = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/networkManagers/nm-1/networkGroups/group-1"
)

func newTestAdminRuleCollection(api networkManagerAdminRuleCollectionsAPI) *NetworkManagerAdminRuleCollection {
	return &NetworkManagerAdminRuleCollection{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

func adminRuleCollectionDesired(description string, groups []any) []byte {
	props := map[string]any{
		"name":                           "collection-1",
		"resourceGroupName":              "rg-1",
		"networkManagerName":             "nm-1",
		"securityAdminConfigurationName": "config-1",
		"description":                    description,
	}
	if groups != nil {
		props["appliesToGroups"] = groups
	}
	out, _ := json.Marshal(props)
	return out
}

func TestNetworkManagerAdminRuleCollection_CRUD(t *testing.T) {
	collectionResult := armnetwork.AdminRuleCollection{
		ID:   to.Ptr(testAdminRuleCollectionNativeID),
		Name: to.Ptr("collection-1"),
		Properties: &armnetwork.AdminRuleCollectionPropertiesFormat{
			AppliesToGroups: []*armnetwork.ManagerSecurityGroupItem{
				{NetworkGroupID: to.Ptr(testAdminRuleCollectionGroupID)},
			},
			Description:       to.Ptr("conformance"),
			ProvisioningState: to.Ptr(armnetwork.ProvisioningStateSucceeded),
			ResourceGUID:      to.Ptr("00000000-0000-0000-0000-000000000000"),
		},
	}
	defaultGroups := []any{map[string]any{"networkGroupId": testAdminRuleCollectionGroupID}}

	var sent armnetwork.AdminRuleCollection
	var sawConfig string
	var sawForce *bool
	deleteCalls := 0
	fake := &fakeAdminRuleCollectionsAPI{
		createOrUpdateFn: func(_ context.Context, rgName, managerName, configName, name string, params armnetwork.AdminRuleCollection, _ *armnetwork.AdminRuleCollectionsClientCreateOrUpdateOptions) (armnetwork.AdminRuleCollectionsClientCreateOrUpdateResponse, error) {
			require.Equal(t, "rg-1", rgName)
			require.Equal(t, "nm-1", managerName)
			require.Equal(t, "collection-1", name)
			sawConfig = configName
			sent = params
			return armnetwork.AdminRuleCollectionsClientCreateOrUpdateResponse{AdminRuleCollection: collectionResult}, nil
		},
		getFn: func(_ context.Context, _, _, _, _ string, _ *armnetwork.AdminRuleCollectionsClientGetOptions) (armnetwork.AdminRuleCollectionsClientGetResponse, error) {
			return armnetwork.AdminRuleCollectionsClientGetResponse{AdminRuleCollection: collectionResult}, nil
		},
		beginDeleteFn: func(_ context.Context, _, _, _, _ string, options *armnetwork.AdminRuleCollectionsClientBeginDeleteOptions) (*runtime.Poller[armnetwork.AdminRuleCollectionsClientDeleteResponse], error) {
			deleteCalls++
			if options != nil {
				sawForce = options.Force
			}
			return newDonePoller(armnetwork.AdminRuleCollectionsClientDeleteResponse{}), nil
		},
		newListPagerFn: func(_, _, _ string, _ *armnetwork.AdminRuleCollectionsClientListOptions) *runtime.Pager[armnetwork.AdminRuleCollectionsClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armnetwork.AdminRuleCollectionsClientListResponse]{
				More: func(_ armnetwork.AdminRuleCollectionsClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armnetwork.AdminRuleCollectionsClientListResponse) (armnetwork.AdminRuleCollectionsClientListResponse, error) {
					return armnetwork.AdminRuleCollectionsClientListResponse{
						AdminRuleCollectionListResult: armnetwork.AdminRuleCollectionListResult{
							Value: []*armnetwork.AdminRuleCollection{{ID: to.Ptr(testAdminRuleCollectionNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestAdminRuleCollection(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "collection-1",
			Properties: adminRuleCollectionDesired("conformance", defaultGroups),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testAdminRuleCollectionNativeID, got.ProgressResult.NativeID)
		require.Equal(t, "config-1", sawConfig)
		require.Len(t, sent.Properties.AppliesToGroups, 1)
		require.Equal(t, testAdminRuleCollectionGroupID, *sent.Properties.AppliesToGroups[0].NetworkGroupID)
		require.Equal(t, "conformance", *sent.Properties.Description)
	})

	// ARM rejects a collection bound to nothing, so the empty case is caught
	// before the call.
	t.Run("Create_requires_applies_to_groups", func(t *testing.T) {
		_, err := prov.Create(context.Background(), &resource.CreateRequest{
			Properties: adminRuleCollectionDesired("conformance", nil),
		})
		require.ErrorContains(t, err, "appliesToGroups is required")
	})

	t.Run("Create_requires_a_group_id_on_every_entry", func(t *testing.T) {
		_, err := prov.Create(context.Background(), &resource.CreateRequest{
			Properties: adminRuleCollectionDesired("conformance", []any{map[string]any{}}),
		})
		require.ErrorContains(t, err, "appliesToGroups.networkGroupId is required")
	})

	t.Run("Create_requires_configuration", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "collection-1", "resourceGroupName": "rg-1", "networkManagerName": "nm-1",
			"appliesToGroups": defaultGroups,
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "securityAdminConfigurationName is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testAdminRuleCollectionNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "collection-1", props["name"])
		// All three parents come from the native ID, not the response body.
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "nm-1", props["networkManagerName"])
		require.Equal(t, "config-1", props["securityAdminConfigurationName"])
		require.Equal(t, []any{map[string]any{"networkGroupId": testAdminRuleCollectionGroupID}},
			props["appliesToGroups"])
		require.Equal(t, "conformance", props["description"])
		require.NotContains(t, got.Properties, "provisioningState")
	})

	t.Run("Update", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testAdminRuleCollectionNativeID,
			DesiredProperties: adminRuleCollectionDesired("redescribed", defaultGroups),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, "redescribed", *sent.Properties.Description)
	})

	t.Run("Delete_sends_force", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testAdminRuleCollectionNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
		require.NotNil(t, sawForce)
		require.True(t, *sawForce)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _, _, _ string, _ *armnetwork.AdminRuleCollectionsClientBeginDeleteOptions) (*runtime.Poller[armnetwork.AdminRuleCollectionsClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testAdminRuleCollectionNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_configuration", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{
				"resourceGroupName": "rg-1", "networkManagerName": "nm-1",
				"securityAdminConfigurationName": "config-1",
			},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testAdminRuleCollectionNativeID}, got.NativeIDs)
	})

	t.Run("List_without_parents_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure_with_message", func(t *testing.T) {
		fake.createOrUpdateFn = func(_ context.Context, _, _, _, _ string, _ armnetwork.AdminRuleCollection, _ *armnetwork.AdminRuleCollectionsClientCreateOrUpdateOptions) (armnetwork.AdminRuleCollectionsClientCreateOrUpdateResponse, error) {
			return armnetwork.AdminRuleCollectionsClientCreateOrUpdateResponse{}, &azcore.ResponseError{StatusCode: 409}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "collection-1", Properties: adminRuleCollectionDesired("conformance", defaultGroups),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.NotEmpty(t, got.ProgressResult.StatusMessage)
	})
}

func TestNetworkManagerAdminRuleCollection_ReadNotFound(t *testing.T) {
	fake := &fakeAdminRuleCollectionsAPI{
		getFn: func(_ context.Context, _, _, _, _ string, _ *armnetwork.AdminRuleCollectionsClientGetOptions) (armnetwork.AdminRuleCollectionsClientGetResponse, error) {
			return armnetwork.AdminRuleCollectionsClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestAdminRuleCollection(fake).Read(context.Background(),
		&resource.ReadRequest{NativeID: testAdminRuleCollectionNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeAdminRuleCollectionsAPI struct {
	createOrUpdateFn func(ctx context.Context, rgName, managerName, configName, name string, params armnetwork.AdminRuleCollection, options *armnetwork.AdminRuleCollectionsClientCreateOrUpdateOptions) (armnetwork.AdminRuleCollectionsClientCreateOrUpdateResponse, error)
	getFn            func(ctx context.Context, rgName, managerName, configName, name string, options *armnetwork.AdminRuleCollectionsClientGetOptions) (armnetwork.AdminRuleCollectionsClientGetResponse, error)
	beginDeleteFn    func(ctx context.Context, rgName, managerName, configName, name string, options *armnetwork.AdminRuleCollectionsClientBeginDeleteOptions) (*runtime.Poller[armnetwork.AdminRuleCollectionsClientDeleteResponse], error)
	newListPagerFn   func(rgName, managerName, configName string, options *armnetwork.AdminRuleCollectionsClientListOptions) *runtime.Pager[armnetwork.AdminRuleCollectionsClientListResponse]
}

func (f *fakeAdminRuleCollectionsAPI) CreateOrUpdate(ctx context.Context, rgName, managerName, configName, name string, params armnetwork.AdminRuleCollection, options *armnetwork.AdminRuleCollectionsClientCreateOrUpdateOptions) (armnetwork.AdminRuleCollectionsClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, managerName, configName, name, params, options)
}

func (f *fakeAdminRuleCollectionsAPI) Get(ctx context.Context, rgName, managerName, configName, name string, options *armnetwork.AdminRuleCollectionsClientGetOptions) (armnetwork.AdminRuleCollectionsClientGetResponse, error) {
	return f.getFn(ctx, rgName, managerName, configName, name, options)
}

func (f *fakeAdminRuleCollectionsAPI) BeginDelete(ctx context.Context, rgName, managerName, configName, name string, options *armnetwork.AdminRuleCollectionsClientBeginDeleteOptions) (*runtime.Poller[armnetwork.AdminRuleCollectionsClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, managerName, configName, name, options)
}

func (f *fakeAdminRuleCollectionsAPI) NewListPager(rgName, managerName, configName string, options *armnetwork.AdminRuleCollectionsClientListOptions) *runtime.Pager[armnetwork.AdminRuleCollectionsClientListResponse] {
	return f.newListPagerFn(rgName, managerName, configName, options)
}
