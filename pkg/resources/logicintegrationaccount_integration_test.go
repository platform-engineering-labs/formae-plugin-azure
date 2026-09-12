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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/logic/armlogic"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testLogicIntegrationAccountNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Logic/integrationAccounts/ia-1"

func newTestLogicIntegrationAccount(api logicIntegrationAccountsAPI) *LogicIntegrationAccount {
	return &LogicIntegrationAccount{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func logicIntegrationAccountDesired(skuName string) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":              "ia-1",
		"location":          "eastus",
		"resourceGroupName": "rg-1",
		"skuName":           skuName,
		"Tags":              []map[string]string{{"Key": "purpose", "Value": "conformance"}},
	})
	return out
}

func TestLogicIntegrationAccount_CRUD(t *testing.T) {
	accountResult := armlogic.IntegrationAccount{
		ID:       to.Ptr(testLogicIntegrationAccountNativeID),
		Name:     to.Ptr("ia-1"),
		Location: to.Ptr("East US"),
		SKU:      &armlogic.IntegrationAccountSKU{Name: to.Ptr(armlogic.IntegrationAccountSKUNameFree)},
		Tags:     map[string]*string{"purpose": to.Ptr("conformance")},
		Properties: &armlogic.IntegrationAccountProperties{
			State: to.Ptr(armlogic.WorkflowStateEnabled),
		},
	}

	var sentCreate armlogic.IntegrationAccount
	createCalls := 0
	deleteCalls := 0
	fake := &fakeLogicIntegrationAccountsAPI{
		createOrUpdateFn: func(_ context.Context, rgName, name string, params armlogic.IntegrationAccount, _ *armlogic.IntegrationAccountsClientCreateOrUpdateOptions) (armlogic.IntegrationAccountsClientCreateOrUpdateResponse, error) {
			require.Equal(t, "rg-1", rgName)
			require.Equal(t, "ia-1", name)
			sentCreate = params
			createCalls++
			return armlogic.IntegrationAccountsClientCreateOrUpdateResponse{IntegrationAccount: accountResult}, nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armlogic.IntegrationAccountsClientGetOptions) (armlogic.IntegrationAccountsClientGetResponse, error) {
			return armlogic.IntegrationAccountsClientGetResponse{IntegrationAccount: accountResult}, nil
		},
		deleteFn: func(_ context.Context, _, _ string, _ *armlogic.IntegrationAccountsClientDeleteOptions) (armlogic.IntegrationAccountsClientDeleteResponse, error) {
			deleteCalls++
			return armlogic.IntegrationAccountsClientDeleteResponse{}, nil
		},
		newListByResourceGroupPagerFn: func(_ string, _ *armlogic.IntegrationAccountsClientListByResourceGroupOptions) *runtime.Pager[armlogic.IntegrationAccountsClientListByResourceGroupResponse] {
			return runtime.NewPager(runtime.PagingHandler[armlogic.IntegrationAccountsClientListByResourceGroupResponse]{
				More: func(_ armlogic.IntegrationAccountsClientListByResourceGroupResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armlogic.IntegrationAccountsClientListByResourceGroupResponse) (armlogic.IntegrationAccountsClientListByResourceGroupResponse, error) {
					return armlogic.IntegrationAccountsClientListByResourceGroupResponse{
						IntegrationAccountListResult: armlogic.IntegrationAccountListResult{
							Value: []*armlogic.IntegrationAccount{{ID: to.Ptr(testLogicIntegrationAccountNativeID)}},
						},
					}, nil
				},
			})
		},
		newListBySubscriptionPagerFn: func(_ *armlogic.IntegrationAccountsClientListBySubscriptionOptions) *runtime.Pager[armlogic.IntegrationAccountsClientListBySubscriptionResponse] {
			return runtime.NewPager(runtime.PagingHandler[armlogic.IntegrationAccountsClientListBySubscriptionResponse]{
				More: func(_ armlogic.IntegrationAccountsClientListBySubscriptionResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armlogic.IntegrationAccountsClientListBySubscriptionResponse) (armlogic.IntegrationAccountsClientListBySubscriptionResponse, error) {
					return armlogic.IntegrationAccountsClientListBySubscriptionResponse{
						IntegrationAccountListResult: armlogic.IntegrationAccountListResult{
							Value: []*armlogic.IntegrationAccount{{ID: to.Ptr(testLogicIntegrationAccountNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestLogicIntegrationAccount(fake)

	// Create is synchronous: IntegrationAccountsClient has no BeginX at all, so
	// no resume token is ever produced.
	t.Run("Create_is_synchronous", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "ia-1",
			Properties: logicIntegrationAccountDesired("Free"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testLogicIntegrationAccountNativeID, got.ProgressResult.NativeID)
		require.Empty(t, got.ProgressResult.RequestID)

		require.Equal(t, "eastus", *sentCreate.Location)
		require.Equal(t, armlogic.IntegrationAccountSKUNameFree, *sentCreate.SKU.Name)
		require.Equal(t, "conformance", *sentCreate.Tags["purpose"])
		// ARM rejects an integration account PUT whose body carries no properties
		// member at all, so an empty one is always sent.
		require.NotNil(t, sentCreate.Properties)
	})

	t.Run("Create_requires_resource_group", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "ia-1", "location": "eastus", "skuName": "Free"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "resourceGroupName is required")
	})

	t.Run("Create_requires_location", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "ia-1", "resourceGroupName": "rg-1", "skuName": "Free"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "location is required")
	})

	// skuName is required rather than provider-defaulted: ARM's own default is
	// NotSpecified, which produces an account no workflow can use, and the two
	// paid tiers bill per hour.
	t.Run("Create_requires_sku", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "ia-1", "location": "eastus", "resourceGroupName": "rg-1"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "skuName is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testLogicIntegrationAccountNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "ia-1", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		// ARM answers "East US"; desired state carries the compact form.
		require.Equal(t, "eastus", props["location"])
		require.Equal(t, "Free", props["skuName"])
		require.NotNil(t, props["Tags"])
	})

	// properties.state is service state rather than desired state, and
	// integration service environments are retired; neither is modelled.
	t.Run("Read_drops_service_state", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testLogicIntegrationAccountNativeID})
		require.NoError(t, err)
		for _, key := range []string{"state", "integrationServiceEnvironment"} {
			require.NotContains(t, got.Properties, key)
		}
	})

	t.Run("Read_rejects_a_child_id", func(t *testing.T) {
		_, err := prov.Read(context.Background(), &resource.ReadRequest{
			NativeID: testLogicIntegrationAccountNativeID + "/schemas/s-1",
		})
		require.Error(t, err)
	})

	// Update reissues CreateOrUpdate: the SDK's Update is a whole-document PATCH
	// taking the same IntegrationAccount body, so the two are equivalent.
	t.Run("Update_reissues_create_or_update", func(t *testing.T) {
		before := createCalls
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testLogicIntegrationAccountNativeID,
			DesiredProperties: logicIntegrationAccountDesired("Free"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Empty(t, got.ProgressResult.RequestID)
		require.Equal(t, before+1, createCalls)
	})

	t.Run("Delete_is_synchronous", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testLogicIntegrationAccountNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _ string, _ *armlogic.IntegrationAccountsClientDeleteOptions) (armlogic.IntegrationAccountsClientDeleteResponse, error) {
			return armlogic.IntegrationAccountsClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testLogicIntegrationAccountNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_resource_group", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testLogicIntegrationAccountNativeID}, got.NativeIDs)
	})

	t.Run("List_falls_back_to_subscription", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Equal(t, []string{testLogicIntegrationAccountNativeID}, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure_with_a_cause", func(t *testing.T) {
		fake.createOrUpdateFn = func(_ context.Context, _, _ string, _ armlogic.IntegrationAccount, _ *armlogic.IntegrationAccountsClientCreateOrUpdateOptions) (armlogic.IntegrationAccountsClientCreateOrUpdateResponse, error) {
			return armlogic.IntegrationAccountsClientCreateOrUpdateResponse{}, &azcore.ResponseError{StatusCode: 409}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "ia-1", Properties: logicIntegrationAccountDesired("Free"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.NotEmpty(t, got.ProgressResult.StatusMessage)
	})
}

func TestLogicIntegrationAccount_ReadNotFound(t *testing.T) {
	fake := &fakeLogicIntegrationAccountsAPI{
		getFn: func(_ context.Context, _, _ string, _ *armlogic.IntegrationAccountsClientGetOptions) (armlogic.IntegrationAccountsClientGetResponse, error) {
			return armlogic.IntegrationAccountsClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestLogicIntegrationAccount(fake).Read(context.Background(),
		&resource.ReadRequest{NativeID: testLogicIntegrationAccountNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeLogicIntegrationAccountsAPI struct {
	createOrUpdateFn              func(ctx context.Context, rgName, name string, params armlogic.IntegrationAccount, options *armlogic.IntegrationAccountsClientCreateOrUpdateOptions) (armlogic.IntegrationAccountsClientCreateOrUpdateResponse, error)
	getFn                         func(ctx context.Context, rgName, name string, options *armlogic.IntegrationAccountsClientGetOptions) (armlogic.IntegrationAccountsClientGetResponse, error)
	deleteFn                      func(ctx context.Context, rgName, name string, options *armlogic.IntegrationAccountsClientDeleteOptions) (armlogic.IntegrationAccountsClientDeleteResponse, error)
	newListByResourceGroupPagerFn func(rgName string, options *armlogic.IntegrationAccountsClientListByResourceGroupOptions) *runtime.Pager[armlogic.IntegrationAccountsClientListByResourceGroupResponse]
	newListBySubscriptionPagerFn  func(options *armlogic.IntegrationAccountsClientListBySubscriptionOptions) *runtime.Pager[armlogic.IntegrationAccountsClientListBySubscriptionResponse]
}

func (f *fakeLogicIntegrationAccountsAPI) CreateOrUpdate(ctx context.Context, rgName, name string, params armlogic.IntegrationAccount, options *armlogic.IntegrationAccountsClientCreateOrUpdateOptions) (armlogic.IntegrationAccountsClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, name, params, options)
}

func (f *fakeLogicIntegrationAccountsAPI) Get(ctx context.Context, rgName, name string, options *armlogic.IntegrationAccountsClientGetOptions) (armlogic.IntegrationAccountsClientGetResponse, error) {
	return f.getFn(ctx, rgName, name, options)
}

func (f *fakeLogicIntegrationAccountsAPI) Delete(ctx context.Context, rgName, name string, options *armlogic.IntegrationAccountsClientDeleteOptions) (armlogic.IntegrationAccountsClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, name, options)
}

func (f *fakeLogicIntegrationAccountsAPI) NewListByResourceGroupPager(rgName string, options *armlogic.IntegrationAccountsClientListByResourceGroupOptions) *runtime.Pager[armlogic.IntegrationAccountsClientListByResourceGroupResponse] {
	return f.newListByResourceGroupPagerFn(rgName, options)
}

func (f *fakeLogicIntegrationAccountsAPI) NewListBySubscriptionPager(options *armlogic.IntegrationAccountsClientListBySubscriptionOptions) *runtime.Pager[armlogic.IntegrationAccountsClientListBySubscriptionResponse] {
	return f.newListBySubscriptionPagerFn(options)
}
