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

const testSecurityAdminConfigNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/networkManagers/nm-1/securityAdminConfigurations/config-1"

func newTestSecurityAdminConfiguration(api networkManagerSecurityAdminConfigurationsAPI) *NetworkManagerSecurityAdminConfiguration {
	return &NetworkManagerSecurityAdminConfiguration{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

func securityAdminConfigDesired(description string, services []any) []byte {
	props := map[string]any{
		"name":               "config-1",
		"resourceGroupName":  "rg-1",
		"networkManagerName": "nm-1",
		"description":        description,
	}
	if services != nil {
		props["applyOnNetworkIntentPolicyBasedServices"] = services
	}
	out, _ := json.Marshal(props)
	return out
}

func TestNetworkManagerSecurityAdminConfiguration_CRUD(t *testing.T) {
	configResult := armnetwork.SecurityAdminConfiguration{
		ID:   to.Ptr(testSecurityAdminConfigNativeID),
		Name: to.Ptr("config-1"),
		Properties: &armnetwork.SecurityAdminConfigurationPropertiesFormat{
			ApplyOnNetworkIntentPolicyBasedServices: []*armnetwork.NetworkIntentPolicyBasedService{
				to.Ptr(armnetwork.NetworkIntentPolicyBasedServiceNone),
			},
			Description:       to.Ptr("conformance"),
			ProvisioningState: to.Ptr(armnetwork.ProvisioningStateSucceeded),
			ResourceGUID:      to.Ptr("00000000-0000-0000-0000-000000000000"),
		},
	}

	var sent armnetwork.SecurityAdminConfiguration
	var sawForce *bool
	deleteCalls := 0
	fake := &fakeSecurityAdminConfigurationsAPI{
		createOrUpdateFn: func(_ context.Context, rgName, managerName, name string, params armnetwork.SecurityAdminConfiguration, _ *armnetwork.SecurityAdminConfigurationsClientCreateOrUpdateOptions) (armnetwork.SecurityAdminConfigurationsClientCreateOrUpdateResponse, error) {
			require.Equal(t, "rg-1", rgName)
			require.Equal(t, "nm-1", managerName)
			require.Equal(t, "config-1", name)
			sent = params
			return armnetwork.SecurityAdminConfigurationsClientCreateOrUpdateResponse{SecurityAdminConfiguration: configResult}, nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ *armnetwork.SecurityAdminConfigurationsClientGetOptions) (armnetwork.SecurityAdminConfigurationsClientGetResponse, error) {
			return armnetwork.SecurityAdminConfigurationsClientGetResponse{SecurityAdminConfiguration: configResult}, nil
		},
		beginDeleteFn: func(_ context.Context, _, _, _ string, options *armnetwork.SecurityAdminConfigurationsClientBeginDeleteOptions) (*runtime.Poller[armnetwork.SecurityAdminConfigurationsClientDeleteResponse], error) {
			deleteCalls++
			if options != nil {
				sawForce = options.Force
			}
			return newDonePoller(armnetwork.SecurityAdminConfigurationsClientDeleteResponse{}), nil
		},
		newListPagerFn: func(_, _ string, _ *armnetwork.SecurityAdminConfigurationsClientListOptions) *runtime.Pager[armnetwork.SecurityAdminConfigurationsClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armnetwork.SecurityAdminConfigurationsClientListResponse]{
				More: func(_ armnetwork.SecurityAdminConfigurationsClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armnetwork.SecurityAdminConfigurationsClientListResponse) (armnetwork.SecurityAdminConfigurationsClientListResponse, error) {
					return armnetwork.SecurityAdminConfigurationsClientListResponse{
						SecurityAdminConfigurationListResult: armnetwork.SecurityAdminConfigurationListResult{
							Value: []*armnetwork.SecurityAdminConfiguration{{ID: to.Ptr(testSecurityAdminConfigNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestSecurityAdminConfiguration(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "config-1",
			Properties: securityAdminConfigDesired("conformance", []any{"None"}),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testSecurityAdminConfigNativeID, got.ProgressResult.NativeID)
		require.Len(t, sent.Properties.ApplyOnNetworkIntentPolicyBasedServices, 1)
		require.Equal(t, armnetwork.NetworkIntentPolicyBasedServiceNone,
			*sent.Properties.ApplyOnNetworkIntentPolicyBasedServices[0])
		require.Equal(t, "conformance", *sent.Properties.Description)
	})

	// An omitted list is left out of the request body entirely so ARM applies its
	// own default rather than being told to apply the rules to nothing.
	t.Run("Create_without_intent_services_sends_none", func(t *testing.T) {
		_, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "config-1",
			Properties: securityAdminConfigDesired("conformance", nil),
		})
		require.NoError(t, err)
		require.Nil(t, sent.Properties.ApplyOnNetworkIntentPolicyBasedServices)
	})

	t.Run("Create_requires_manager", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "config-1", "resourceGroupName": "rg-1"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "networkManagerName is required")
	})

	t.Run("Create_requires_resource_group", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "config-1", "networkManagerName": "nm-1"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "resourceGroupName is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testSecurityAdminConfigNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "config-1", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "nm-1", props["networkManagerName"])
		require.Equal(t, []any{"None"}, props["applyOnNetworkIntentPolicyBasedServices"])
		require.Equal(t, "conformance", props["description"])
		require.NotContains(t, got.Properties, "provisioningState")
	})

	t.Run("Update", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testSecurityAdminConfigNativeID,
			DesiredProperties: securityAdminConfigDesired("redescribed", []any{"None"}),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, "redescribed", *sent.Properties.Description)
	})

	// force=true is the only way past ARM's refusal to remove a configuration
	// that has been deployed. Commits are not modelled, so without it such a
	// configuration would be undeletable through this plugin.
	t.Run("Delete_sends_force", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testSecurityAdminConfigNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
		require.NotNil(t, sawForce)
		require.True(t, *sawForce)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _, _ string, _ *armnetwork.SecurityAdminConfigurationsClientBeginDeleteOptions) (*runtime.Poller[armnetwork.SecurityAdminConfigurationsClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testSecurityAdminConfigNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_manager", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "networkManagerName": "nm-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testSecurityAdminConfigNativeID}, got.NativeIDs)
	})

	t.Run("List_without_parents_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure_with_message", func(t *testing.T) {
		fake.createOrUpdateFn = func(_ context.Context, _, _, _ string, _ armnetwork.SecurityAdminConfiguration, _ *armnetwork.SecurityAdminConfigurationsClientCreateOrUpdateOptions) (armnetwork.SecurityAdminConfigurationsClientCreateOrUpdateResponse, error) {
			return armnetwork.SecurityAdminConfigurationsClientCreateOrUpdateResponse{}, &azcore.ResponseError{StatusCode: 409}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "config-1", Properties: securityAdminConfigDesired("conformance", []any{"None"}),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.NotEmpty(t, got.ProgressResult.StatusMessage)
	})
}

func TestNetworkManagerSecurityAdminConfiguration_ReadNotFound(t *testing.T) {
	fake := &fakeSecurityAdminConfigurationsAPI{
		getFn: func(_ context.Context, _, _, _ string, _ *armnetwork.SecurityAdminConfigurationsClientGetOptions) (armnetwork.SecurityAdminConfigurationsClientGetResponse, error) {
			return armnetwork.SecurityAdminConfigurationsClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestSecurityAdminConfiguration(fake).Read(context.Background(),
		&resource.ReadRequest{NativeID: testSecurityAdminConfigNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeSecurityAdminConfigurationsAPI struct {
	createOrUpdateFn func(ctx context.Context, rgName, managerName, name string, params armnetwork.SecurityAdminConfiguration, options *armnetwork.SecurityAdminConfigurationsClientCreateOrUpdateOptions) (armnetwork.SecurityAdminConfigurationsClientCreateOrUpdateResponse, error)
	getFn            func(ctx context.Context, rgName, managerName, name string, options *armnetwork.SecurityAdminConfigurationsClientGetOptions) (armnetwork.SecurityAdminConfigurationsClientGetResponse, error)
	beginDeleteFn    func(ctx context.Context, rgName, managerName, name string, options *armnetwork.SecurityAdminConfigurationsClientBeginDeleteOptions) (*runtime.Poller[armnetwork.SecurityAdminConfigurationsClientDeleteResponse], error)
	newListPagerFn   func(rgName, managerName string, options *armnetwork.SecurityAdminConfigurationsClientListOptions) *runtime.Pager[armnetwork.SecurityAdminConfigurationsClientListResponse]
}

func (f *fakeSecurityAdminConfigurationsAPI) CreateOrUpdate(ctx context.Context, rgName, managerName, name string, params armnetwork.SecurityAdminConfiguration, options *armnetwork.SecurityAdminConfigurationsClientCreateOrUpdateOptions) (armnetwork.SecurityAdminConfigurationsClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, managerName, name, params, options)
}

func (f *fakeSecurityAdminConfigurationsAPI) Get(ctx context.Context, rgName, managerName, name string, options *armnetwork.SecurityAdminConfigurationsClientGetOptions) (armnetwork.SecurityAdminConfigurationsClientGetResponse, error) {
	return f.getFn(ctx, rgName, managerName, name, options)
}

func (f *fakeSecurityAdminConfigurationsAPI) BeginDelete(ctx context.Context, rgName, managerName, name string, options *armnetwork.SecurityAdminConfigurationsClientBeginDeleteOptions) (*runtime.Poller[armnetwork.SecurityAdminConfigurationsClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, managerName, name, options)
}

func (f *fakeSecurityAdminConfigurationsAPI) NewListPager(rgName, managerName string, options *armnetwork.SecurityAdminConfigurationsClientListOptions) *runtime.Pager[armnetwork.SecurityAdminConfigurationsClientListResponse] {
	return f.newListPagerFn(rgName, managerName, options)
}
