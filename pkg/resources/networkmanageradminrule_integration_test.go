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
	testAdminRuleNativeID        = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/networkManagers/nm-1/securityAdminConfigurations/config-1/ruleCollections/collection-1/rules/rule-1"
	testDefaultAdminRuleNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/networkManagers/nm-1/securityAdminConfigurations/config-1/ruleCollections/collection-1/rules/rule-default"
)

func newTestAdminRule(api networkManagerAdminRulesAPI) *NetworkManagerAdminRule {
	return &NetworkManagerAdminRule{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

func adminRuleDesired(overrides map[string]any) []byte {
	props := map[string]any{
		"name":                           "rule-1",
		"resourceGroupName":              "rg-1",
		"networkManagerName":             "nm-1",
		"securityAdminConfigurationName": "config-1",
		"ruleCollectionName":             "collection-1",
		"access":                         "Deny",
		"direction":                      "Inbound",
		"priority":                       100,
		"protocol":                       "Tcp",
		"sources": []any{map[string]any{
			"addressPrefix": "Internet", "addressPrefixType": "ServiceTag",
		}},
		"destinations": []any{map[string]any{
			"addressPrefix": "10.20.0.0/16", "addressPrefixType": "IPPrefix",
		}},
		"destinationPortRanges": []any{"3389"},
		"description":           "deny rdp",
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

func TestNetworkManagerAdminRule_CRUD(t *testing.T) {
	ruleResult := &armnetwork.AdminRule{
		ID:   to.Ptr(testAdminRuleNativeID),
		Name: to.Ptr("rule-1"),
		Kind: to.Ptr(armnetwork.AdminRuleKindCustom),
		Properties: &armnetwork.AdminPropertiesFormat{
			Access:    to.Ptr(armnetwork.SecurityConfigurationRuleAccessDeny),
			Direction: to.Ptr(armnetwork.SecurityConfigurationRuleDirectionInbound),
			Priority:  to.Ptr(int32(100)),
			Protocol:  to.Ptr(armnetwork.SecurityConfigurationRuleProtocolTCP),
			Sources: []*armnetwork.AddressPrefixItem{{
				AddressPrefix:     to.Ptr("Internet"),
				AddressPrefixType: to.Ptr(armnetwork.AddressPrefixTypeServiceTag),
			}},
			Destinations: []*armnetwork.AddressPrefixItem{{
				AddressPrefix:     to.Ptr("10.20.0.0/16"),
				AddressPrefixType: to.Ptr(armnetwork.AddressPrefixTypeIPPrefix),
			}},
			DestinationPortRanges: []*string{to.Ptr("3389")},
			Description:           to.Ptr("deny rdp"),
			ProvisioningState:     to.Ptr(armnetwork.ProvisioningStateSucceeded),
			ResourceGUID:          to.Ptr("00000000-0000-0000-0000-000000000000"),
		},
	}
	defaultRule := &armnetwork.DefaultAdminRule{
		ID:   to.Ptr(testDefaultAdminRuleNativeID),
		Name: to.Ptr("rule-default"),
		Kind: to.Ptr(armnetwork.AdminRuleKindDefault),
	}

	var sent armnetwork.BaseAdminRuleClassification
	var sawCollection string
	var sawForce *bool
	deleteCalls := 0
	fake := &fakeAdminRulesAPI{
		createOrUpdateFn: func(_ context.Context, rgName, managerName, configName, collectionName, name string, rule armnetwork.BaseAdminRuleClassification, _ *armnetwork.AdminRulesClientCreateOrUpdateOptions) (armnetwork.AdminRulesClientCreateOrUpdateResponse, error) {
			require.Equal(t, "rg-1", rgName)
			require.Equal(t, "nm-1", managerName)
			require.Equal(t, "config-1", configName)
			require.Equal(t, "rule-1", name)
			sawCollection = collectionName
			sent = rule
			return armnetwork.AdminRulesClientCreateOrUpdateResponse{BaseAdminRuleClassification: ruleResult}, nil
		},
		getFn: func(_ context.Context, _, _, _, _, _ string, _ *armnetwork.AdminRulesClientGetOptions) (armnetwork.AdminRulesClientGetResponse, error) {
			return armnetwork.AdminRulesClientGetResponse{BaseAdminRuleClassification: ruleResult}, nil
		},
		beginDeleteFn: func(_ context.Context, _, _, _, _, _ string, options *armnetwork.AdminRulesClientBeginDeleteOptions) (*runtime.Poller[armnetwork.AdminRulesClientDeleteResponse], error) {
			deleteCalls++
			if options != nil {
				sawForce = options.Force
			}
			return newDonePoller(armnetwork.AdminRulesClientDeleteResponse{}), nil
		},
		newListPagerFn: func(_, _, _, _ string, _ *armnetwork.AdminRulesClientListOptions) *runtime.Pager[armnetwork.AdminRulesClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armnetwork.AdminRulesClientListResponse]{
				More: func(_ armnetwork.AdminRulesClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armnetwork.AdminRulesClientListResponse) (armnetwork.AdminRulesClientListResponse, error) {
					return armnetwork.AdminRulesClientListResponse{
						AdminRuleListResult: armnetwork.AdminRuleListResult{
							// A collection normally carries both kinds; only the
							// Custom one is ours to manage.
							Value: []armnetwork.BaseAdminRuleClassification{ruleResult, defaultRule},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestAdminRule(fake)

	t.Run("Create_sends_kind_custom", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "rule-1",
			Properties: adminRuleDesired(nil),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testAdminRuleNativeID, got.ProgressResult.NativeID)
		require.Equal(t, "collection-1", sawCollection)

		custom, ok := sent.(*armnetwork.AdminRule)
		require.True(t, ok, "the rule must be sent as the Custom variant")
		// The kind discriminator sits at the resource level, not inside
		// properties.
		require.Equal(t, armnetwork.AdminRuleKindCustom, *custom.Kind)
		require.Equal(t, armnetwork.SecurityConfigurationRuleAccessDeny, *custom.Properties.Access)
		require.Equal(t, armnetwork.SecurityConfigurationRuleDirectionInbound, *custom.Properties.Direction)
		require.EqualValues(t, 100, *custom.Properties.Priority)
		require.Equal(t, armnetwork.SecurityConfigurationRuleProtocolTCP, *custom.Properties.Protocol)
		require.Len(t, custom.Properties.Sources, 1)
		require.Equal(t, "Internet", *custom.Properties.Sources[0].AddressPrefix)
		require.Equal(t, armnetwork.AddressPrefixTypeServiceTag, *custom.Properties.Sources[0].AddressPrefixType)
		require.Equal(t, []*string{to.Ptr("3389")}, custom.Properties.DestinationPortRanges)
		require.Nil(t, custom.Properties.SourcePortRanges)
	})

	t.Run("Create_requires_access", func(t *testing.T) {
		_, err := prov.Create(context.Background(), &resource.CreateRequest{
			Properties: adminRuleDesired(map[string]any{"access": nil}),
		})
		require.ErrorContains(t, err, "access is required")
	})

	t.Run("Create_requires_direction", func(t *testing.T) {
		_, err := prov.Create(context.Background(), &resource.CreateRequest{
			Properties: adminRuleDesired(map[string]any{"direction": nil}),
		})
		require.ErrorContains(t, err, "direction is required")
	})

	// Priority 0 is not a legal ARM value, but an absent priority and a zero one
	// must still be told apart: the field is a pointer for exactly that reason.
	t.Run("Create_requires_priority", func(t *testing.T) {
		_, err := prov.Create(context.Background(), &resource.CreateRequest{
			Properties: adminRuleDesired(map[string]any{"priority": nil}),
		})
		require.ErrorContains(t, err, "priority is required")
	})

	t.Run("Create_requires_protocol", func(t *testing.T) {
		_, err := prov.Create(context.Background(), &resource.CreateRequest{
			Properties: adminRuleDesired(map[string]any{"protocol": nil}),
		})
		require.ErrorContains(t, err, "protocol is required")
	})

	t.Run("Create_requires_collection", func(t *testing.T) {
		_, err := prov.Create(context.Background(), &resource.CreateRequest{
			Properties: adminRuleDesired(map[string]any{"ruleCollectionName": nil}),
		})
		require.ErrorContains(t, err, "ruleCollectionName is required")
	})

	t.Run("Create_requires_an_address_prefix_type", func(t *testing.T) {
		_, err := prov.Create(context.Background(), &resource.CreateRequest{
			Properties: adminRuleDesired(map[string]any{
				"sources": []any{map[string]any{"addressPrefix": "Internet"}},
			}),
		})
		require.ErrorContains(t, err, "sources.addressPrefixType is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testAdminRuleNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "rule-1", props["name"])
		// All four parents come from the native ID, not the response body.
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "nm-1", props["networkManagerName"])
		require.Equal(t, "config-1", props["securityAdminConfigurationName"])
		require.Equal(t, "collection-1", props["ruleCollectionName"])
		require.Equal(t, "Deny", props["access"])
		require.Equal(t, "Inbound", props["direction"])
		require.EqualValues(t, 100, props["priority"])
		require.Equal(t, "Tcp", props["protocol"])
		require.Equal(t, []any{map[string]any{
			"addressPrefix": "Internet", "addressPrefixType": "ServiceTag",
		}}, props["sources"])
		require.Equal(t, []any{"3389"}, props["destinationPortRanges"])
		require.NotContains(t, got.Properties, "provisioningState")
	})

	// A Default rule is service-authored and entirely read-only. Presenting one
	// as managed state would read as unfixable drift forever, so it is refused.
	t.Run("Read_refuses_a_default_rule", func(t *testing.T) {
		fake.getFn = func(_ context.Context, _, _, _, _, _ string, _ *armnetwork.AdminRulesClientGetOptions) (armnetwork.AdminRulesClientGetResponse, error) {
			return armnetwork.AdminRulesClientGetResponse{BaseAdminRuleClassification: defaultRule}, nil
		}
		_, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testDefaultAdminRuleNativeID})
		require.ErrorContains(t, err, "Default rule")

		fake.getFn = func(_ context.Context, _, _, _, _, _ string, _ *armnetwork.AdminRulesClientGetOptions) (armnetwork.AdminRulesClientGetResponse, error) {
			return armnetwork.AdminRulesClientGetResponse{BaseAdminRuleClassification: ruleResult}, nil
		}
	})

	t.Run("Update", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID: testAdminRuleNativeID,
			DesiredProperties: adminRuleDesired(map[string]any{
				"priority":              200,
				"destinationPortRanges": []any{"22", "3389"},
				"description":           "deny rdp and ssh",
			}),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)

		custom, ok := sent.(*armnetwork.AdminRule)
		require.True(t, ok)
		require.EqualValues(t, 200, *custom.Properties.Priority)
		require.Equal(t, []*string{to.Ptr("22"), to.Ptr("3389")}, custom.Properties.DestinationPortRanges)
		require.Equal(t, "deny rdp and ssh", *custom.Properties.Description)
	})

	t.Run("Delete_sends_force", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testAdminRuleNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
		require.NotNil(t, sawForce)
		require.True(t, *sawForce)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _, _, _, _ string, _ *armnetwork.AdminRulesClientBeginDeleteOptions) (*runtime.Poller[armnetwork.AdminRulesClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testAdminRuleNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	// Discovery must not offer a service-owned Default rule for import.
	t.Run("List_filters_out_default_rules", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{
				"resourceGroupName": "rg-1", "networkManagerName": "nm-1",
				"securityAdminConfigurationName": "config-1", "ruleCollectionName": "collection-1",
			},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testAdminRuleNativeID}, got.NativeIDs)
	})

	t.Run("List_without_parents_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure_with_message", func(t *testing.T) {
		fake.createOrUpdateFn = func(_ context.Context, _, _, _, _, _ string, _ armnetwork.BaseAdminRuleClassification, _ *armnetwork.AdminRulesClientCreateOrUpdateOptions) (armnetwork.AdminRulesClientCreateOrUpdateResponse, error) {
			return armnetwork.AdminRulesClientCreateOrUpdateResponse{}, &azcore.ResponseError{StatusCode: 409}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "rule-1", Properties: adminRuleDesired(nil),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.NotEmpty(t, got.ProgressResult.StatusMessage)
	})
}

func TestNetworkManagerAdminRule_ReadNotFound(t *testing.T) {
	fake := &fakeAdminRulesAPI{
		getFn: func(_ context.Context, _, _, _, _, _ string, _ *armnetwork.AdminRulesClientGetOptions) (armnetwork.AdminRulesClientGetResponse, error) {
			return armnetwork.AdminRulesClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestAdminRule(fake).Read(context.Background(),
		&resource.ReadRequest{NativeID: testAdminRuleNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeAdminRulesAPI struct {
	createOrUpdateFn func(ctx context.Context, rgName, managerName, configName, collectionName, name string, rule armnetwork.BaseAdminRuleClassification, options *armnetwork.AdminRulesClientCreateOrUpdateOptions) (armnetwork.AdminRulesClientCreateOrUpdateResponse, error)
	getFn            func(ctx context.Context, rgName, managerName, configName, collectionName, name string, options *armnetwork.AdminRulesClientGetOptions) (armnetwork.AdminRulesClientGetResponse, error)
	beginDeleteFn    func(ctx context.Context, rgName, managerName, configName, collectionName, name string, options *armnetwork.AdminRulesClientBeginDeleteOptions) (*runtime.Poller[armnetwork.AdminRulesClientDeleteResponse], error)
	newListPagerFn   func(rgName, managerName, configName, collectionName string, options *armnetwork.AdminRulesClientListOptions) *runtime.Pager[armnetwork.AdminRulesClientListResponse]
}

func (f *fakeAdminRulesAPI) CreateOrUpdate(ctx context.Context, rgName, managerName, configName, collectionName, name string, rule armnetwork.BaseAdminRuleClassification, options *armnetwork.AdminRulesClientCreateOrUpdateOptions) (armnetwork.AdminRulesClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, managerName, configName, collectionName, name, rule, options)
}

func (f *fakeAdminRulesAPI) Get(ctx context.Context, rgName, managerName, configName, collectionName, name string, options *armnetwork.AdminRulesClientGetOptions) (armnetwork.AdminRulesClientGetResponse, error) {
	return f.getFn(ctx, rgName, managerName, configName, collectionName, name, options)
}

func (f *fakeAdminRulesAPI) BeginDelete(ctx context.Context, rgName, managerName, configName, collectionName, name string, options *armnetwork.AdminRulesClientBeginDeleteOptions) (*runtime.Poller[armnetwork.AdminRulesClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, managerName, configName, collectionName, name, options)
}

func (f *fakeAdminRulesAPI) NewListPager(rgName, managerName, configName, collectionName string, options *armnetwork.AdminRulesClientListOptions) *runtime.Pager[armnetwork.AdminRulesClientListResponse] {
	return f.newListPagerFn(rgName, managerName, configName, collectionName, options)
}
