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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/netapp/armnetapp/v7"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const (
	testNetAppAccountNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.NetApp/netAppAccounts/acct-1"
)

func newTestNetAppAccount(api netAppAccountsAPI) *NetAppAccount {
	return &NetAppAccount{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func netAppAccountDesired(tagValue string) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":              "acct-1",
		"location":          "eastus",
		"resourceGroupName": "rg-1",
		"nfsV4IdDomain":     "contoso.com",
		"Tags":              []any{map[string]any{"Key": "env", "Value": tagValue}},
	})
	return out
}

func TestNetAppAccount_CRUD(t *testing.T) {
	acctResult := armnetapp.Account{
		ID:       to.Ptr(testNetAppAccountNativeID),
		Name:     to.Ptr("acct-1"),
		Location: to.Ptr("East US"),
		Properties: &armnetapp.AccountProperties{
			NfsV4IDDomain:     to.Ptr("contoso.com"),
			ProvisioningState: to.Ptr("Succeeded"),
			// ARM echoes the AD list back with the join account name in it.
			ActiveDirectories: []*armnetapp.ActiveDirectory{{
				Username: to.Ptr("domain-admin"),
				Domain:   to.Ptr("contoso.com"),
			}},
		},
		Tags: map[string]*string{"env": to.Ptr("test")},
	}

	var sentCreate armnetapp.Account
	var sentPatch armnetapp.AccountPatch
	deleteCalls := 0
	fake := &fakeNetAppAccountsAPI{
		beginCreateOrUpdateFn: func(_ context.Context, _, name string, params armnetapp.Account, _ *armnetapp.AccountsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetapp.AccountsClientCreateOrUpdateResponse], error) {
			require.Equal(t, "acct-1", name)
			sentCreate = params
			return newDonePoller(armnetapp.AccountsClientCreateOrUpdateResponse{Account: acctResult}), nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armnetapp.AccountsClientGetOptions) (armnetapp.AccountsClientGetResponse, error) {
			return armnetapp.AccountsClientGetResponse{Account: acctResult}, nil
		},
		beginUpdateFn: func(_ context.Context, _, _ string, params armnetapp.AccountPatch, _ *armnetapp.AccountsClientBeginUpdateOptions) (*runtime.Poller[armnetapp.AccountsClientUpdateResponse], error) {
			sentPatch = params
			return newDonePoller(armnetapp.AccountsClientUpdateResponse{Account: acctResult}), nil
		},
		beginDeleteFn: func(_ context.Context, _, _ string, _ *armnetapp.AccountsClientBeginDeleteOptions) (*runtime.Poller[armnetapp.AccountsClientDeleteResponse], error) {
			deleteCalls++
			return newDonePoller(armnetapp.AccountsClientDeleteResponse{}), nil
		},
		newListBySubscriptionPagerFn: func(_ *armnetapp.AccountsClientListBySubscriptionOptions) *runtime.Pager[armnetapp.AccountsClientListBySubscriptionResponse] {
			return runtime.NewPager(runtime.PagingHandler[armnetapp.AccountsClientListBySubscriptionResponse]{
				More: func(_ armnetapp.AccountsClientListBySubscriptionResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armnetapp.AccountsClientListBySubscriptionResponse) (armnetapp.AccountsClientListBySubscriptionResponse, error) {
					return armnetapp.AccountsClientListBySubscriptionResponse{
						AccountList: armnetapp.AccountList{
							Value: []*armnetapp.Account{
								{ID: to.Ptr(testNetAppAccountNativeID)},
								{ID: to.Ptr("/subscriptions/sub-1/resourceGroups/rg-2/providers/Microsoft.NetApp/netAppAccounts/acct-2")},
							},
						},
					}, nil
				},
			})
		},
		newListPagerFn: func(_ string, _ *armnetapp.AccountsClientListOptions) *runtime.Pager[armnetapp.AccountsClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armnetapp.AccountsClientListResponse]{
				More: func(_ armnetapp.AccountsClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armnetapp.AccountsClientListResponse) (armnetapp.AccountsClientListResponse, error) {
					return armnetapp.AccountsClientListResponse{
						AccountList: armnetapp.AccountList{
							Value: []*armnetapp.Account{{ID: to.Ptr(testNetAppAccountNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestNetAppAccount(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "acct-1",
			Properties: netAppAccountDesired("test"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testNetAppAccountNativeID, got.ProgressResult.NativeID)
		require.Equal(t, "contoso.com", *sentCreate.Properties.NfsV4IDDomain)
		// Active Directory connections are never sent: an empty list would tear down
		// an out-of-band domain join.
		require.Nil(t, sentCreate.Properties.ActiveDirectories)
		require.Equal(t, "test", *sentCreate.Tags["env"])
	})

	t.Run("Create_requires_location", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "acct-1", "resourceGroupName": "rg-1",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "location is required")
	})

	t.Run("Create_requires_resource_group", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "acct-1", "location": "eastus"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "resourceGroupName is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testNetAppAccountNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "acct-1", props["name"])
		// ARM returns "East US"; read must normalise or desired state drifts.
		require.Equal(t, "eastus", props["location"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "contoso.com", props["nfsV4IdDomain"])
	})

	// provisioningState and resourceGuid are service bookkeeping, not desired
	// state: surfacing them would only ever read back as noise.
	// activeDirectories carries a domain-join username and password; it must never
	// reach state, along with the service bookkeeping beside it.
	t.Run("Read_drops_service_bookkeeping", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testNetAppAccountNativeID})
		require.NoError(t, err)
		require.NotContains(t, got.Properties, "provisioningState")
		require.NotContains(t, got.Properties, "activeDirectories")
		require.NotContains(t, got.Properties, "domain-admin")
		require.NotContains(t, got.Properties, "resourceGuid")
		require.NotContains(t, got.Properties, "resourceGUID")
	})

	// armnetapp.AccountPatch carries tags and nothing else, so a tag change is the
	// only in-place update this resource has.
	t.Run("Update_sends_tags_and_properties", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testNetAppAccountNativeID,
			DesiredProperties: netAppAccountDesired("updated"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, "updated", *sentPatch.Tags["env"])
		require.Equal(t, "contoso.com", *sentPatch.Properties.NfsV4IDDomain)
		// Never send the AD list on an update either.
		require.Nil(t, sentPatch.Properties.ActiveDirectories)
	})

	t.Run("Delete", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testNetAppAccountNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _ string, _ *armnetapp.AccountsClientBeginDeleteOptions) (*runtime.Poller[armnetapp.AccountsClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testNetAppAccountNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_resource_group", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testNetAppAccountNativeID}, got.NativeIDs)
	})

	t.Run("List_without_group_is_subscription_wide", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 2)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, _ armnetapp.Account, _ *armnetapp.AccountsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetapp.AccountsClientCreateOrUpdateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 409}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "acct-1", Properties: netAppAccountDesired("test"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

func TestNetAppAccount_ReadNotFound(t *testing.T) {
	fake := &fakeNetAppAccountsAPI{
		getFn: func(_ context.Context, _, _ string, _ *armnetapp.AccountsClientGetOptions) (armnetapp.AccountsClientGetResponse, error) {
			return armnetapp.AccountsClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestNetAppAccount(fake).Read(context.Background(), &resource.ReadRequest{NativeID: testNetAppAccountNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeNetAppAccountsAPI struct {
	beginCreateOrUpdateFn        func(ctx context.Context, rgName, name string, params armnetapp.Account, options *armnetapp.AccountsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetapp.AccountsClientCreateOrUpdateResponse], error)
	getFn                        func(ctx context.Context, rgName, name string, options *armnetapp.AccountsClientGetOptions) (armnetapp.AccountsClientGetResponse, error)
	beginUpdateFn                func(ctx context.Context, rgName, name string, params armnetapp.AccountPatch, options *armnetapp.AccountsClientBeginUpdateOptions) (*runtime.Poller[armnetapp.AccountsClientUpdateResponse], error)
	beginDeleteFn                func(ctx context.Context, rgName, name string, options *armnetapp.AccountsClientBeginDeleteOptions) (*runtime.Poller[armnetapp.AccountsClientDeleteResponse], error)
	newListBySubscriptionPagerFn func(options *armnetapp.AccountsClientListBySubscriptionOptions) *runtime.Pager[armnetapp.AccountsClientListBySubscriptionResponse]
	newListPagerFn               func(rgName string, options *armnetapp.AccountsClientListOptions) *runtime.Pager[armnetapp.AccountsClientListResponse]
}

func (f *fakeNetAppAccountsAPI) BeginCreateOrUpdate(ctx context.Context, rgName, name string, params armnetapp.Account, options *armnetapp.AccountsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetapp.AccountsClientCreateOrUpdateResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, rgName, name, params, options)
}

func (f *fakeNetAppAccountsAPI) Get(ctx context.Context, rgName, name string, options *armnetapp.AccountsClientGetOptions) (armnetapp.AccountsClientGetResponse, error) {
	return f.getFn(ctx, rgName, name, options)
}

func (f *fakeNetAppAccountsAPI) BeginUpdate(ctx context.Context, rgName, name string, params armnetapp.AccountPatch, options *armnetapp.AccountsClientBeginUpdateOptions) (*runtime.Poller[armnetapp.AccountsClientUpdateResponse], error) {
	return f.beginUpdateFn(ctx, rgName, name, params, options)
}

func (f *fakeNetAppAccountsAPI) BeginDelete(ctx context.Context, rgName, name string, options *armnetapp.AccountsClientBeginDeleteOptions) (*runtime.Poller[armnetapp.AccountsClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, name, options)
}

func (f *fakeNetAppAccountsAPI) NewListBySubscriptionPager(options *armnetapp.AccountsClientListBySubscriptionOptions) *runtime.Pager[armnetapp.AccountsClientListBySubscriptionResponse] {
	return f.newListBySubscriptionPagerFn(options)
}

func (f *fakeNetAppAccountsAPI) NewListPager(rgName string, options *armnetapp.AccountsClientListOptions) *runtime.Pager[armnetapp.AccountsClientListResponse] {
	return f.newListPagerFn(rgName, options)
}
