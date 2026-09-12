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

const testApimProductApiNativeID = testApimProductNativeID + "/apis/api1"

func newTestApiManagementProductApi(api apiManagementProductAPIsAPI) *ApiManagementProductApi {
	return &ApiManagementProductApi{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func apimProductApiDesired() []byte {
	out, _ := json.Marshal(map[string]any{
		"resourceGroupName": "rg-1",
		"serviceName":       "apim1",
		"productName":       "starter",
		"apiName":           "api1",
	})
	return out
}

func TestApiManagementProductApi_CRUD(t *testing.T) {
	var sawNames []string
	exists := true
	deleteCalls := 0
	fake := &fakeApiManagementProductAPIsAPI{
		createOrUpdateFn: func(_ context.Context, rgName, serviceName, productID, apiID string, _ *armapimanagement.ProductAPIClientCreateOrUpdateOptions) (armapimanagement.ProductAPIClientCreateOrUpdateResponse, error) {
			sawNames = []string{rgName, serviceName, productID, apiID}
			// ARM answers with the API's own contract, whose ID is NOT the link's.
			return armapimanagement.ProductAPIClientCreateOrUpdateResponse{
				APIContract: armapimanagement.APIContract{ID: to.Ptr(testApimServiceNativeID + "/apis/api1")},
			}, nil
		},
		checkEntityExistsFn: func(_ context.Context, _, _, _, _ string, _ *armapimanagement.ProductAPIClientCheckEntityExistsOptions) (armapimanagement.ProductAPIClientCheckEntityExistsResponse, error) {
			return armapimanagement.ProductAPIClientCheckEntityExistsResponse{Success: exists}, nil
		},
		deleteFn: func(_ context.Context, _, _, _, _ string, _ *armapimanagement.ProductAPIClientDeleteOptions) (armapimanagement.ProductAPIClientDeleteResponse, error) {
			deleteCalls++
			return armapimanagement.ProductAPIClientDeleteResponse{}, nil
		},
		newListByProductPagerFn: func(_, _, _ string, _ *armapimanagement.ProductAPIClientListByProductOptions) *runtime.Pager[armapimanagement.ProductAPIClientListByProductResponse] {
			return runtime.NewPager(runtime.PagingHandler[armapimanagement.ProductAPIClientListByProductResponse]{
				More: func(_ armapimanagement.ProductAPIClientListByProductResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armapimanagement.ProductAPIClientListByProductResponse) (armapimanagement.ProductAPIClientListByProductResponse, error) {
					return armapimanagement.ProductAPIClientListByProductResponse{
						APICollection: armapimanagement.APICollection{
							Value: []*armapimanagement.APIContract{{
								ID:   to.Ptr(testApimServiceNativeID + "/apis/api1"),
								Name: to.Ptr("api1"),
							}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestApiManagementProductApi(fake)

	t.Run("Create_composes_the_link_id_rather_than_reading_it_back", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "starter-api1",
			Properties: apimProductApiDesired(),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testApimProductApiNativeID, got.ProgressResult.NativeID)
		require.Empty(t, got.ProgressResult.RequestID)
		require.Equal(t, []string{"rg-1", "apim1", "starter", "api1"}, sawNames)
	})

	t.Run("Create_requires_both_ends", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName": "rg-1", "serviceName": "apim1", "productName": "starter",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "apiName is required")

		props, _ = json.Marshal(map[string]any{
			"resourceGroupName": "rg-1", "serviceName": "apim1", "apiName": "api1",
		})
		_, err = prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "productName is required")
	})

	t.Run("Read_reports_both_ends", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testApimProductApiNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "apim1", props["serviceName"])
		require.Equal(t, "starter", props["productName"])
		require.Equal(t, "api1", props["apiName"])
		require.Equal(t, testApimProductApiNativeID, props["id"])
	})

	t.Run("Read_of_an_unlinked_api_is_NotFound", func(t *testing.T) {
		exists = false
		defer func() { exists = true }()
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testApimProductApiNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
	})

	t.Run("Update_re_puts_the_link", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testApimProductApiNativeID,
			DesiredProperties: apimProductApiDesired(),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testApimProductApiNativeID, got.ProgressResult.NativeID)
	})

	t.Run("Delete_unlinks", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testApimProductApiNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _, _, _ string, _ *armapimanagement.ProductAPIClientDeleteOptions) (armapimanagement.ProductAPIClientDeleteResponse, error) {
			return armapimanagement.ProductAPIClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testApimProductApiNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_composes_link_ids_from_the_api_names", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{
				"resourceGroupName": "rg-1", "serviceName": "apim1", "productName": "starter",
			},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testApimProductApiNativeID}, got.NativeIDs)
	})

	t.Run("List_without_parents_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure_with_a_reason", func(t *testing.T) {
		fake.createOrUpdateFn = func(_ context.Context, _, _, _, _ string, _ *armapimanagement.ProductAPIClientCreateOrUpdateOptions) (armapimanagement.ProductAPIClientCreateOrUpdateResponse, error) {
			return armapimanagement.ProductAPIClientCreateOrUpdateResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: apimProductApiDesired()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.NotEmpty(t, got.ProgressResult.StatusMessage)
	})
}

func TestApiManagementProductApi_ReadError(t *testing.T) {
	fake := &fakeApiManagementProductAPIsAPI{
		checkEntityExistsFn: func(_ context.Context, _, _, _, _ string, _ *armapimanagement.ProductAPIClientCheckEntityExistsOptions) (armapimanagement.ProductAPIClientCheckEntityExistsResponse, error) {
			return armapimanagement.ProductAPIClientCheckEntityExistsResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestApiManagementProductApi(fake).Read(context.Background(),
		&resource.ReadRequest{NativeID: testApimProductApiNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeApiManagementProductAPIsAPI struct {
	createOrUpdateFn        func(ctx context.Context, rgName, serviceName, productID, apiID string, options *armapimanagement.ProductAPIClientCreateOrUpdateOptions) (armapimanagement.ProductAPIClientCreateOrUpdateResponse, error)
	checkEntityExistsFn     func(ctx context.Context, rgName, serviceName, productID, apiID string, options *armapimanagement.ProductAPIClientCheckEntityExistsOptions) (armapimanagement.ProductAPIClientCheckEntityExistsResponse, error)
	deleteFn                func(ctx context.Context, rgName, serviceName, productID, apiID string, options *armapimanagement.ProductAPIClientDeleteOptions) (armapimanagement.ProductAPIClientDeleteResponse, error)
	newListByProductPagerFn func(rgName, serviceName, productID string, options *armapimanagement.ProductAPIClientListByProductOptions) *runtime.Pager[armapimanagement.ProductAPIClientListByProductResponse]
}

func (f *fakeApiManagementProductAPIsAPI) CreateOrUpdate(ctx context.Context, rgName, serviceName, productID, apiID string, options *armapimanagement.ProductAPIClientCreateOrUpdateOptions) (armapimanagement.ProductAPIClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, serviceName, productID, apiID, options)
}

func (f *fakeApiManagementProductAPIsAPI) CheckEntityExists(ctx context.Context, rgName, serviceName, productID, apiID string, options *armapimanagement.ProductAPIClientCheckEntityExistsOptions) (armapimanagement.ProductAPIClientCheckEntityExistsResponse, error) {
	return f.checkEntityExistsFn(ctx, rgName, serviceName, productID, apiID, options)
}

func (f *fakeApiManagementProductAPIsAPI) Delete(ctx context.Context, rgName, serviceName, productID, apiID string, options *armapimanagement.ProductAPIClientDeleteOptions) (armapimanagement.ProductAPIClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, serviceName, productID, apiID, options)
}

func (f *fakeApiManagementProductAPIsAPI) NewListByProductPager(rgName, serviceName, productID string, options *armapimanagement.ProductAPIClientListByProductOptions) *runtime.Pager[armapimanagement.ProductAPIClientListByProductResponse] {
	return f.newListByProductPagerFn(rgName, serviceName, productID, options)
}
