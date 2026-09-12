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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/apimanagement/armapimanagement"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testApimProductNativeID = testApimServiceNativeID + "/products/starter"

func newTestApiManagementProduct(api apiManagementProductsAPI) *ApiManagementProduct {
	return &ApiManagementProduct{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func apimProductDesired(displayName string) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":                 "starter",
		"resourceGroupName":    "rg-1",
		"serviceName":          "apim1",
		"displayName":          displayName,
		"description":          "Starter product",
		"subscriptionRequired": false,
		"state":                "published",
	})
	return out
}

func TestApiManagementProduct_CRUD(t *testing.T) {
	productResult := armapimanagement.ProductContract{
		ID:   to.Ptr(testApimProductNativeID),
		Name: to.Ptr("starter"),
		Properties: &armapimanagement.ProductContractProperties{
			DisplayName:          to.Ptr("Starter"),
			Description:          to.Ptr("Starter product"),
			SubscriptionRequired: to.Ptr(false),
			State:                to.Ptr(armapimanagement.ProductStatePublished),
		},
	}

	var sentCreate armapimanagement.ProductContract
	var sentUpdate armapimanagement.ProductUpdateParameters
	var sawIfMatch string
	var sawDeleteOptions *armapimanagement.ProductClientDeleteOptions
	deleteCalls := 0
	fake := &fakeApiManagementProductsAPI{
		createOrUpdateFn: func(_ context.Context, _, serviceName, productID string, params armapimanagement.ProductContract, _ *armapimanagement.ProductClientCreateOrUpdateOptions) (armapimanagement.ProductClientCreateOrUpdateResponse, error) {
			require.Equal(t, "apim1", serviceName)
			require.Equal(t, "starter", productID)
			sentCreate = params
			return armapimanagement.ProductClientCreateOrUpdateResponse{ProductContract: productResult}, nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ *armapimanagement.ProductClientGetOptions) (armapimanagement.ProductClientGetResponse, error) {
			return armapimanagement.ProductClientGetResponse{ProductContract: productResult}, nil
		},
		updateFn: func(_ context.Context, _, _, _, ifMatch string, params armapimanagement.ProductUpdateParameters, _ *armapimanagement.ProductClientUpdateOptions) (armapimanagement.ProductClientUpdateResponse, error) {
			sawIfMatch = ifMatch
			sentUpdate = params
			return armapimanagement.ProductClientUpdateResponse{ProductContract: productResult}, nil
		},
		deleteFn: func(_ context.Context, _, _, _, ifMatch string, options *armapimanagement.ProductClientDeleteOptions) (armapimanagement.ProductClientDeleteResponse, error) {
			sawIfMatch = ifMatch
			sawDeleteOptions = options
			deleteCalls++
			return armapimanagement.ProductClientDeleteResponse{}, nil
		},
		newListByServicePagerFn: func(_, _ string, _ *armapimanagement.ProductClientListByServiceOptions) *runtime.Pager[armapimanagement.ProductClientListByServiceResponse] {
			return runtime.NewPager(runtime.PagingHandler[armapimanagement.ProductClientListByServiceResponse]{
				More: func(_ armapimanagement.ProductClientListByServiceResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armapimanagement.ProductClientListByServiceResponse) (armapimanagement.ProductClientListByServiceResponse, error) {
					return armapimanagement.ProductClientListByServiceResponse{
						ProductCollection: armapimanagement.ProductCollection{
							Value: []*armapimanagement.ProductContract{{ID: to.Ptr(testApimProductNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestApiManagementProduct(fake)

	t.Run("Create_is_synchronous", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "starter",
			Properties: apimProductDesired("Starter"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testApimProductNativeID, got.ProgressResult.NativeID)
		require.Empty(t, got.ProgressResult.RequestID)
		require.Equal(t, "Starter", *sentCreate.Properties.DisplayName)
		require.False(t, *sentCreate.Properties.SubscriptionRequired)
		require.Equal(t, armapimanagement.ProductStatePublished, *sentCreate.Properties.State)
		// An open product must not carry either subscription-only field: ARM
		// rejects the request when subscriptionRequired is false and one is set.
		require.Nil(t, sentCreate.Properties.ApprovalRequired)
		require.Nil(t, sentCreate.Properties.SubscriptionsLimit)
	})

	t.Run("Create_omits_state_when_unset_so_ARM_defaults_it", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "starter", "resourceGroupName": "rg-1", "serviceName": "apim1",
			"displayName": "Starter",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.Nil(t, sentCreate.Properties.State)
		require.Nil(t, sentCreate.Properties.SubscriptionRequired)
	})

	t.Run("Create_requires_display_name", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "starter", "resourceGroupName": "rg-1", "serviceName": "apim1",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "displayName is required")
	})

	t.Run("Create_requires_service_name", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "starter", "resourceGroupName": "rg-1"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "serviceName is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testApimProductNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "starter", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "apim1", props["serviceName"])
		require.Equal(t, "Starter", props["displayName"])
		require.Equal(t, "published", props["state"])
		require.Equal(t, false, props["subscriptionRequired"])
	})

	t.Run("Update_uses_patch_with_wildcard_if_match", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testApimProductNativeID,
			DesiredProperties: apimProductDesired("Starter v2"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, "*", sawIfMatch)
		require.Equal(t, "Starter v2", *sentUpdate.Properties.DisplayName)
	})

	t.Run("Delete_asks_ARM_to_drop_subscriptions_too", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testApimProductNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
		require.Equal(t, "*", sawIfMatch)
		require.NotNil(t, sawDeleteOptions)
		require.True(t, *sawDeleteOptions.DeleteSubscriptions)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _, _, _ string, _ *armapimanagement.ProductClientDeleteOptions) (armapimanagement.ProductClientDeleteResponse, error) {
			return armapimanagement.ProductClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testApimProductNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_service", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "serviceName": "apim1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testApimProductNativeID}, got.NativeIDs)
	})

	t.Run("List_without_parents_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure_with_a_reason", func(t *testing.T) {
		fake.createOrUpdateFn = func(_ context.Context, _, _, _ string, _ armapimanagement.ProductContract, _ *armapimanagement.ProductClientCreateOrUpdateOptions) (armapimanagement.ProductClientCreateOrUpdateResponse, error) {
			return armapimanagement.ProductClientCreateOrUpdateResponse{}, &azcore.ResponseError{StatusCode: 400}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "starter", Properties: apimProductDesired("Starter"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.NotEmpty(t, got.ProgressResult.StatusMessage)
	})
}

func TestApiManagementProduct_ReadNotFound(t *testing.T) {
	fake := &fakeApiManagementProductsAPI{
		getFn: func(_ context.Context, _, _, _ string, _ *armapimanagement.ProductClientGetOptions) (armapimanagement.ProductClientGetResponse, error) {
			return armapimanagement.ProductClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestApiManagementProduct(fake).Read(context.Background(),
		&resource.ReadRequest{NativeID: testApimProductNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

func TestApiManagementProduct_RejectsForeignNativeID(t *testing.T) {
	_, err := newTestApiManagementProduct(&fakeApiManagementProductsAPI{}).Read(context.Background(),
		&resource.ReadRequest{NativeID: testApimServiceNativeID + "/apis/api1"})
	require.ErrorContains(t, err, "is not a service/products")
}

// --- Test helpers ---

type fakeApiManagementProductsAPI struct {
	createOrUpdateFn        func(ctx context.Context, rgName, serviceName, productID string, params armapimanagement.ProductContract, options *armapimanagement.ProductClientCreateOrUpdateOptions) (armapimanagement.ProductClientCreateOrUpdateResponse, error)
	getFn                   func(ctx context.Context, rgName, serviceName, productID string, options *armapimanagement.ProductClientGetOptions) (armapimanagement.ProductClientGetResponse, error)
	updateFn                func(ctx context.Context, rgName, serviceName, productID, ifMatch string, params armapimanagement.ProductUpdateParameters, options *armapimanagement.ProductClientUpdateOptions) (armapimanagement.ProductClientUpdateResponse, error)
	deleteFn                func(ctx context.Context, rgName, serviceName, productID, ifMatch string, options *armapimanagement.ProductClientDeleteOptions) (armapimanagement.ProductClientDeleteResponse, error)
	newListByServicePagerFn func(rgName, serviceName string, options *armapimanagement.ProductClientListByServiceOptions) *runtime.Pager[armapimanagement.ProductClientListByServiceResponse]
}

func (f *fakeApiManagementProductsAPI) CreateOrUpdate(ctx context.Context, rgName, serviceName, productID string, params armapimanagement.ProductContract, options *armapimanagement.ProductClientCreateOrUpdateOptions) (armapimanagement.ProductClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, serviceName, productID, params, options)
}

func (f *fakeApiManagementProductsAPI) Get(ctx context.Context, rgName, serviceName, productID string, options *armapimanagement.ProductClientGetOptions) (armapimanagement.ProductClientGetResponse, error) {
	return f.getFn(ctx, rgName, serviceName, productID, options)
}

func (f *fakeApiManagementProductsAPI) Update(ctx context.Context, rgName, serviceName, productID, ifMatch string, params armapimanagement.ProductUpdateParameters, options *armapimanagement.ProductClientUpdateOptions) (armapimanagement.ProductClientUpdateResponse, error) {
	return f.updateFn(ctx, rgName, serviceName, productID, ifMatch, params, options)
}

func (f *fakeApiManagementProductsAPI) Delete(ctx context.Context, rgName, serviceName, productID, ifMatch string, options *armapimanagement.ProductClientDeleteOptions) (armapimanagement.ProductClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, serviceName, productID, ifMatch, options)
}

func (f *fakeApiManagementProductsAPI) NewListByServicePager(rgName, serviceName string, options *armapimanagement.ProductClientListByServiceOptions) *runtime.Pager[armapimanagement.ProductClientListByServiceResponse] {
	return f.newListByServicePagerFn(rgName, serviceName, options)
}
