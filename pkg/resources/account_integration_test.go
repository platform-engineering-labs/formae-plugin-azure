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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/cognitiveservices/armcognitiveservices"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testCognitiveAccountNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.CognitiveServices/accounts/myaccount"

func TestCognitiveAccount_CRUD(t *testing.T) {
	accessEnabled := armcognitiveservices.PublicNetworkAccessEnabled

	fake := &fakeCognitiveAccountsAPI{
		beginCreateFn: func(_ context.Context, _, _ string, _ armcognitiveservices.Account, _ *armcognitiveservices.AccountsClientBeginCreateOptions) (*runtime.Poller[armcognitiveservices.AccountsClientCreateResponse], error) {
			return newDonePoller(armcognitiveservices.AccountsClientCreateResponse{
				Account: armcognitiveservices.Account{
					ID:       to.Ptr(testCognitiveAccountNativeID),
					Name:     to.Ptr("myaccount"),
					Location: to.Ptr("eastus"),
					Kind:     to.Ptr("OpenAI"),
					SKU:      &armcognitiveservices.SKU{Name: to.Ptr("S0")},
					Properties: &armcognitiveservices.AccountProperties{
						Endpoint: to.Ptr("https://myaccount.openai.azure.com/"),
					},
				},
			}), nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armcognitiveservices.AccountsClientGetOptions) (armcognitiveservices.AccountsClientGetResponse, error) {
			return armcognitiveservices.AccountsClientGetResponse{
				Account: armcognitiveservices.Account{
					ID:       to.Ptr(testCognitiveAccountNativeID),
					Name:     to.Ptr("myaccount"),
					Location: to.Ptr("eastus"),
					Kind:     to.Ptr("OpenAI"),
					SKU:      &armcognitiveservices.SKU{Name: to.Ptr("S0")},
					Properties: &armcognitiveservices.AccountProperties{
						CustomSubDomainName: to.Ptr("myaccount"),
						PublicNetworkAccess: &accessEnabled,
						Endpoint:            to.Ptr("https://myaccount.openai.azure.com/"),
					},
				},
			}, nil
		},
		beginUpdateFn: func(_ context.Context, _, _ string, _ armcognitiveservices.Account, _ *armcognitiveservices.AccountsClientBeginUpdateOptions) (*runtime.Poller[armcognitiveservices.AccountsClientUpdateResponse], error) {
			return newDonePoller(armcognitiveservices.AccountsClientUpdateResponse{
				Account: armcognitiveservices.Account{
					ID:       to.Ptr(testCognitiveAccountNativeID),
					Name:     to.Ptr("myaccount"),
					Location: to.Ptr("eastus"),
					Kind:     to.Ptr("OpenAI"),
					SKU:      &armcognitiveservices.SKU{Name: to.Ptr("S0")},
					Tags:     map[string]*string{"Environment": to.Ptr("updated")},
				},
			}), nil
		},
		beginDeleteFn: func(_ context.Context, _, _ string, _ *armcognitiveservices.AccountsClientBeginDeleteOptions) (*runtime.Poller[armcognitiveservices.AccountsClientDeleteResponse], error) {
			return newDonePoller(armcognitiveservices.AccountsClientDeleteResponse{}), nil
		},
		newListByResourceGroupPagerFn: func(_ string, _ *armcognitiveservices.AccountsClientListByResourceGroupOptions) *runtime.Pager[armcognitiveservices.AccountsClientListByResourceGroupResponse] {
			return runtime.NewPager(runtime.PagingHandler[armcognitiveservices.AccountsClientListByResourceGroupResponse]{
				More: func(_ armcognitiveservices.AccountsClientListByResourceGroupResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armcognitiveservices.AccountsClientListByResourceGroupResponse) (armcognitiveservices.AccountsClientListByResourceGroupResponse, error) {
					return armcognitiveservices.AccountsClientListByResourceGroupResponse{
						AccountListResult: armcognitiveservices.AccountListResult{
							Value: []*armcognitiveservices.Account{
								{ID: to.Ptr(testCognitiveAccountNativeID)},
								{ID: to.Ptr("/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.CognitiveServices/accounts/other")},
							},
						},
					}, nil
				},
			})
		},
		newListPagerFn: func(_ *armcognitiveservices.AccountsClientListOptions) *runtime.Pager[armcognitiveservices.AccountsClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armcognitiveservices.AccountsClientListResponse]{
				More: func(_ armcognitiveservices.AccountsClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armcognitiveservices.AccountsClientListResponse) (armcognitiveservices.AccountsClientListResponse, error) {
					return armcognitiveservices.AccountsClientListResponse{
						AccountListResult: armcognitiveservices.AccountListResult{
							Value: []*armcognitiveservices.Account{{ID: to.Ptr(testCognitiveAccountNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestCognitiveAccount(fake)

	t.Run("Create", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName": "rg-1", "name": "myaccount",
			"location": "eastus", "kind": "OpenAI",
			"sku": map[string]any{"name": "S0"},
		})
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "myaccount", Properties: props})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testCognitiveAccountNativeID, got.ProgressResult.NativeID)
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testCognitiveAccountNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "myaccount", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "eastus", props["location"])
		require.Equal(t, "OpenAI", props["kind"])
	})

	t.Run("Update_keeps_native_id", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"sku":  map[string]any{"name": "S0"},
			"Tags": []map[string]string{{"Key": "Environment", "Value": "updated"}},
		})
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testCognitiveAccountNativeID,
			DesiredProperties: props,
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testCognitiveAccountNativeID, got.ProgressResult.NativeID)
	})

	t.Run("Delete", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testCognitiveAccountNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _ string, _ *armcognitiveservices.AccountsClientBeginDeleteOptions) (*runtime.Poller[armcognitiveservices.AccountsClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testCognitiveAccountNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 2)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.beginCreateFn = func(_ context.Context, _, _ string, _ armcognitiveservices.Account, _ *armcognitiveservices.AccountsClientBeginCreateOptions) (*runtime.Poller[armcognitiveservices.AccountsClientCreateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 409}
		}
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName": "rg-1", "name": "myaccount",
			"location": "eastus", "kind": "OpenAI",
			"sku": map[string]any{"name": "S0"},
		})
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

// --- Test helpers ---

func newTestCognitiveAccount(api cognitiveAccountsAPI) *CognitiveAccount {
	return &CognitiveAccount{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

type fakeCognitiveAccountsAPI struct {
	beginCreateFn                 func(ctx context.Context, resourceGroupName string, accountName string, account armcognitiveservices.Account, options *armcognitiveservices.AccountsClientBeginCreateOptions) (*runtime.Poller[armcognitiveservices.AccountsClientCreateResponse], error)
	getFn                         func(ctx context.Context, resourceGroupName string, accountName string, options *armcognitiveservices.AccountsClientGetOptions) (armcognitiveservices.AccountsClientGetResponse, error)
	beginUpdateFn                 func(ctx context.Context, resourceGroupName string, accountName string, account armcognitiveservices.Account, options *armcognitiveservices.AccountsClientBeginUpdateOptions) (*runtime.Poller[armcognitiveservices.AccountsClientUpdateResponse], error)
	beginDeleteFn                 func(ctx context.Context, resourceGroupName string, accountName string, options *armcognitiveservices.AccountsClientBeginDeleteOptions) (*runtime.Poller[armcognitiveservices.AccountsClientDeleteResponse], error)
	newListByResourceGroupPagerFn func(resourceGroupName string, options *armcognitiveservices.AccountsClientListByResourceGroupOptions) *runtime.Pager[armcognitiveservices.AccountsClientListByResourceGroupResponse]
	newListPagerFn                func(options *armcognitiveservices.AccountsClientListOptions) *runtime.Pager[armcognitiveservices.AccountsClientListResponse]
}

func (f *fakeCognitiveAccountsAPI) BeginCreate(ctx context.Context, resourceGroupName string, accountName string, account armcognitiveservices.Account, options *armcognitiveservices.AccountsClientBeginCreateOptions) (*runtime.Poller[armcognitiveservices.AccountsClientCreateResponse], error) {
	return f.beginCreateFn(ctx, resourceGroupName, accountName, account, options)
}

func (f *fakeCognitiveAccountsAPI) Get(ctx context.Context, resourceGroupName string, accountName string, options *armcognitiveservices.AccountsClientGetOptions) (armcognitiveservices.AccountsClientGetResponse, error) {
	return f.getFn(ctx, resourceGroupName, accountName, options)
}

func (f *fakeCognitiveAccountsAPI) BeginUpdate(ctx context.Context, resourceGroupName string, accountName string, account armcognitiveservices.Account, options *armcognitiveservices.AccountsClientBeginUpdateOptions) (*runtime.Poller[armcognitiveservices.AccountsClientUpdateResponse], error) {
	return f.beginUpdateFn(ctx, resourceGroupName, accountName, account, options)
}

func (f *fakeCognitiveAccountsAPI) BeginDelete(ctx context.Context, resourceGroupName string, accountName string, options *armcognitiveservices.AccountsClientBeginDeleteOptions) (*runtime.Poller[armcognitiveservices.AccountsClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, resourceGroupName, accountName, options)
}

func (f *fakeCognitiveAccountsAPI) NewListByResourceGroupPager(resourceGroupName string, options *armcognitiveservices.AccountsClientListByResourceGroupOptions) *runtime.Pager[armcognitiveservices.AccountsClientListByResourceGroupResponse] {
	return f.newListByResourceGroupPagerFn(resourceGroupName, options)
}

func (f *fakeCognitiveAccountsAPI) NewListPager(options *armcognitiveservices.AccountsClientListOptions) *runtime.Pager[armcognitiveservices.AccountsClientListResponse] {
	return f.newListPagerFn(options)
}
