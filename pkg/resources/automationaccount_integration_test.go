// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/automation/armautomation"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testAutomationAccountNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Automation/automationAccounts/aa-1"

func newTestAutomationAccount(api automationAccountAPI) *AutomationAccount {
	return &AutomationAccount{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func automationAccountDesired(tagValue string) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":              "aa-1",
		"location":          "eastus",
		"resourceGroupName": "rg-1",
		"skuName":           "Free",
		"Tags":              []map[string]string{{"Key": "env", "Value": tagValue}},
	})
	return out
}

func TestAutomationAccount_CRUD(t *testing.T) {
	// The response deliberately carries the service-managed fields the read path
	// must drop, and the spaced-out region form ARM answers with.
	acctResult := armautomation.Account{
		ID:       to.Ptr(testAutomationAccountNativeID),
		Name:     to.Ptr("aa-1"),
		Location: to.Ptr("East US"),
		Properties: &armautomation.AccountProperties{
			SKU:              &armautomation.SKU{Name: to.Ptr(armautomation.SKUNameEnumFree)},
			State:            to.Ptr(armautomation.AutomationAccountStateOk),
			LastModifiedBy:   to.Ptr("someone@example.com"),
			CreationTime:     to.Ptr(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)),
			LastModifiedTime: to.Ptr(time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)),
		},
		Tags: map[string]*string{"env": to.Ptr("conformance")},
	}

	var sentCreate armautomation.AccountCreateOrUpdateParameters
	var sentUpdate armautomation.AccountUpdateParameters
	deleteCalls := 0
	fake := &fakeAutomationAccountAPI{
		createOrUpdateFn: func(_ context.Context, rgName, name string, params armautomation.AccountCreateOrUpdateParameters, _ *armautomation.AccountClientCreateOrUpdateOptions) (armautomation.AccountClientCreateOrUpdateResponse, error) {
			require.Equal(t, "rg-1", rgName)
			require.Equal(t, "aa-1", name)
			sentCreate = params
			return armautomation.AccountClientCreateOrUpdateResponse{Account: acctResult}, nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armautomation.AccountClientGetOptions) (armautomation.AccountClientGetResponse, error) {
			return armautomation.AccountClientGetResponse{Account: acctResult}, nil
		},
		updateFn: func(_ context.Context, _, _ string, params armautomation.AccountUpdateParameters, _ *armautomation.AccountClientUpdateOptions) (armautomation.AccountClientUpdateResponse, error) {
			sentUpdate = params
			return armautomation.AccountClientUpdateResponse{Account: acctResult}, nil
		},
		deleteFn: func(_ context.Context, _, _ string, _ *armautomation.AccountClientDeleteOptions) (armautomation.AccountClientDeleteResponse, error) {
			deleteCalls++
			return armautomation.AccountClientDeleteResponse{}, nil
		},
		newListPagerFn: func(_ *armautomation.AccountClientListOptions) *runtime.Pager[armautomation.AccountClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armautomation.AccountClientListResponse]{
				More: func(armautomation.AccountClientListResponse) bool { return false },
				Fetcher: func(context.Context, *armautomation.AccountClientListResponse) (armautomation.AccountClientListResponse, error) {
					return armautomation.AccountClientListResponse{
						AccountListResult: armautomation.AccountListResult{
							Value: []*armautomation.Account{{ID: to.Ptr(testAutomationAccountNativeID)}},
						},
					}, nil
				},
			})
		},
		newListByResourceGroupPagerFn: func(rgName string, _ *armautomation.AccountClientListByResourceGroupOptions) *runtime.Pager[armautomation.AccountClientListByResourceGroupResponse] {
			require.Equal(t, "rg-1", rgName)
			return runtime.NewPager(runtime.PagingHandler[armautomation.AccountClientListByResourceGroupResponse]{
				More: func(armautomation.AccountClientListByResourceGroupResponse) bool { return false },
				Fetcher: func(context.Context, *armautomation.AccountClientListByResourceGroupResponse) (armautomation.AccountClientListByResourceGroupResponse, error) {
					return armautomation.AccountClientListByResourceGroupResponse{
						AccountListResult: armautomation.AccountListResult{
							Value: []*armautomation.Account{{ID: to.Ptr(testAutomationAccountNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestAutomationAccount(fake)

	t.Run("Create_is_synchronous", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "aa-1",
			Properties: automationAccountDesired("conformance"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testAutomationAccountNativeID, got.ProgressResult.NativeID)
		// There is no LRO anywhere in armautomation, so no resume token is minted.
		require.Empty(t, got.ProgressResult.RequestID)

		require.Equal(t, "eastus", *sentCreate.Location)
		require.Equal(t, armautomation.SKUNameEnumFree, *sentCreate.Properties.SKU.Name)
		require.Equal(t, "conformance", *sentCreate.Tags["env"])
	})

	t.Run("Create_requires_resource_group", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "aa-1", "location": "eastus", "skuName": "Free"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "resourceGroupName is required")
	})

	t.Run("Create_requires_location", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "aa-1", "resourceGroupName": "rg-1", "skuName": "Free"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "location is required")
	})

	// skuName is required rather than provider-defaulted precisely so the read
	// always has something to compare against, so an omitted one must be refused
	// at the handler rather than silently letting ARM pick.
	t.Run("Create_requires_sku", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "aa-1", "resourceGroupName": "rg-1", "location": "eastus"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "skuName is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testAutomationAccountNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "aa-1", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "Free", props["skuName"])
		// ARM answers "East US"; desired state carries the compact form.
		require.Equal(t, "eastus", props["location"])
		require.Equal(t, []any{map[string]any{"Key": "env", "Value": "conformance"}}, props["Tags"])
	})

	// state moves on its own and the timestamps advance on every write: all of
	// them would read back as drift.
	t.Run("Read_drops_service_state", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testAutomationAccountNativeID})
		require.NoError(t, err)
		for _, key := range []string{"state", "creationTime", "lastModifiedTime", "lastModifiedBy"} {
			require.NotContains(t, got.Properties, key)
		}
	})

	// The PATCH must not restate the location: ARM accepts it but a region is
	// createOnly, and sending it would let a schema mistake read as an accepted
	// move.
	t.Run("Update_patches_sku_and_tags_only", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testAutomationAccountNativeID,
			DesiredProperties: automationAccountDesired("conformance-updated"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Nil(t, sentUpdate.Location)
		require.Equal(t, armautomation.SKUNameEnumFree, *sentUpdate.Properties.SKU.Name)
		require.Equal(t, "conformance-updated", *sentUpdate.Tags["env"])
	})

	t.Run("Delete_is_synchronous", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testAutomationAccountNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Empty(t, got.ProgressResult.RequestID)
		require.Equal(t, before+1, deleteCalls)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(context.Context, string, string, *armautomation.AccountClientDeleteOptions) (armautomation.AccountClientDeleteResponse, error) {
			return armautomation.AccountClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testAutomationAccountNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_resource_group", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testAutomationAccountNativeID}, got.NativeIDs)
	})

	t.Run("List_falls_back_to_subscription_wide", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Equal(t, []string{testAutomationAccountNativeID}, got.NativeIDs)
	})

	// A dropped provider error is the failure this plugin has 51 existing
	// instances of, so assert the cause survives onto StatusMessage.
	t.Run("Azure_error_maps_to_failure_with_cause", func(t *testing.T) {
		fake.createOrUpdateFn = func(context.Context, string, string, armautomation.AccountCreateOrUpdateParameters, *armautomation.AccountClientCreateOrUpdateOptions) (armautomation.AccountClientCreateOrUpdateResponse, error) {
			return armautomation.AccountClientCreateOrUpdateResponse{}, &azcore.ResponseError{StatusCode: 409, ErrorCode: "Conflict"}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "aa-1", Properties: automationAccountDesired("conformance"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.Contains(t, got.ProgressResult.StatusMessage, "Conflict")
	})
}

func TestAutomationAccount_ReadNotFound(t *testing.T) {
	fake := &fakeAutomationAccountAPI{
		getFn: func(context.Context, string, string, *armautomation.AccountClientGetOptions) (armautomation.AccountClientGetResponse, error) {
			return armautomation.AccountClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestAutomationAccount(fake).Read(context.Background(),
		&resource.ReadRequest{NativeID: testAutomationAccountNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeAutomationAccountAPI struct {
	createOrUpdateFn              func(ctx context.Context, rgName, name string, params armautomation.AccountCreateOrUpdateParameters, options *armautomation.AccountClientCreateOrUpdateOptions) (armautomation.AccountClientCreateOrUpdateResponse, error)
	getFn                         func(ctx context.Context, rgName, name string, options *armautomation.AccountClientGetOptions) (armautomation.AccountClientGetResponse, error)
	updateFn                      func(ctx context.Context, rgName, name string, params armautomation.AccountUpdateParameters, options *armautomation.AccountClientUpdateOptions) (armautomation.AccountClientUpdateResponse, error)
	deleteFn                      func(ctx context.Context, rgName, name string, options *armautomation.AccountClientDeleteOptions) (armautomation.AccountClientDeleteResponse, error)
	newListPagerFn                func(options *armautomation.AccountClientListOptions) *runtime.Pager[armautomation.AccountClientListResponse]
	newListByResourceGroupPagerFn func(rgName string, options *armautomation.AccountClientListByResourceGroupOptions) *runtime.Pager[armautomation.AccountClientListByResourceGroupResponse]
}

func (f *fakeAutomationAccountAPI) CreateOrUpdate(ctx context.Context, rgName, name string, params armautomation.AccountCreateOrUpdateParameters, options *armautomation.AccountClientCreateOrUpdateOptions) (armautomation.AccountClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, name, params, options)
}

func (f *fakeAutomationAccountAPI) Get(ctx context.Context, rgName, name string, options *armautomation.AccountClientGetOptions) (armautomation.AccountClientGetResponse, error) {
	return f.getFn(ctx, rgName, name, options)
}

func (f *fakeAutomationAccountAPI) Update(ctx context.Context, rgName, name string, params armautomation.AccountUpdateParameters, options *armautomation.AccountClientUpdateOptions) (armautomation.AccountClientUpdateResponse, error) {
	return f.updateFn(ctx, rgName, name, params, options)
}

func (f *fakeAutomationAccountAPI) Delete(ctx context.Context, rgName, name string, options *armautomation.AccountClientDeleteOptions) (armautomation.AccountClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, name, options)
}

func (f *fakeAutomationAccountAPI) NewListPager(options *armautomation.AccountClientListOptions) *runtime.Pager[armautomation.AccountClientListResponse] {
	return f.newListPagerFn(options)
}

func (f *fakeAutomationAccountAPI) NewListByResourceGroupPager(rgName string, options *armautomation.AccountClientListByResourceGroupOptions) *runtime.Pager[armautomation.AccountClientListByResourceGroupResponse] {
	return f.newListByResourceGroupPagerFn(rgName, options)
}
