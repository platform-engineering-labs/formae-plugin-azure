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

const testApimProductGroupNativeID = testApimProductNativeID + "/groups/developers"

func newTestApiManagementProductGroup(api apiManagementProductGroupsAPI) *ApiManagementProductGroup {
	return &ApiManagementProductGroup{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func apimProductGroupDesired() []byte {
	out, _ := json.Marshal(map[string]any{
		"resourceGroupName": "rg-1",
		"serviceName":       "apim1",
		"productName":       "starter",
		"groupName":         "developers",
	})
	return out
}

func TestApiManagementProductGroup_CRUD(t *testing.T) {
	var sawNames []string
	exists := true
	deleteCalls := 0
	fake := &fakeApiManagementProductGroupsAPI{
		createOrUpdateFn: func(_ context.Context, rgName, serviceName, productID, groupID string, _ *armapimanagement.ProductGroupClientCreateOrUpdateOptions) (armapimanagement.ProductGroupClientCreateOrUpdateResponse, error) {
			sawNames = []string{rgName, serviceName, productID, groupID}
			// ARM answers with the group's own contract, whose ID is NOT the link's.
			return armapimanagement.ProductGroupClientCreateOrUpdateResponse{
				GroupContract: armapimanagement.GroupContract{ID: to.Ptr(testApimServiceNativeID + "/groups/developers")},
			}, nil
		},
		checkEntityExistsFn: func(_ context.Context, _, _, _, _ string, _ *armapimanagement.ProductGroupClientCheckEntityExistsOptions) (armapimanagement.ProductGroupClientCheckEntityExistsResponse, error) {
			return armapimanagement.ProductGroupClientCheckEntityExistsResponse{Success: exists}, nil
		},
		deleteFn: func(_ context.Context, _, _, _, _ string, _ *armapimanagement.ProductGroupClientDeleteOptions) (armapimanagement.ProductGroupClientDeleteResponse, error) {
			deleteCalls++
			return armapimanagement.ProductGroupClientDeleteResponse{}, nil
		},
		newListByProductPagerFn: func(_, _, _ string, _ *armapimanagement.ProductGroupClientListByProductOptions) *runtime.Pager[armapimanagement.ProductGroupClientListByProductResponse] {
			return runtime.NewPager(runtime.PagingHandler[armapimanagement.ProductGroupClientListByProductResponse]{
				More: func(_ armapimanagement.ProductGroupClientListByProductResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armapimanagement.ProductGroupClientListByProductResponse) (armapimanagement.ProductGroupClientListByProductResponse, error) {
					return armapimanagement.ProductGroupClientListByProductResponse{
						GroupCollection: armapimanagement.GroupCollection{
							Value: []*armapimanagement.GroupContract{{
								ID:   to.Ptr(testApimServiceNativeID + "/groups/developers"),
								Name: to.Ptr("developers"),
							}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestApiManagementProductGroup(fake)

	t.Run("Create_composes_the_link_id_rather_than_reading_it_back", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "starter-developers",
			Properties: apimProductGroupDesired(),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testApimProductGroupNativeID, got.ProgressResult.NativeID)
		require.Empty(t, got.ProgressResult.RequestID)
		require.Equal(t, []string{"rg-1", "apim1", "starter", "developers"}, sawNames)
	})

	t.Run("Create_requires_both_ends", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName": "rg-1", "serviceName": "apim1", "productName": "starter",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "groupName is required")

		props, _ = json.Marshal(map[string]any{
			"resourceGroupName": "rg-1", "serviceName": "apim1", "apiName": "developers",
		})
		_, err = prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "productName is required")
	})

	t.Run("Read_reports_both_ends", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testApimProductGroupNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "apim1", props["serviceName"])
		require.Equal(t, "starter", props["productName"])
		require.Equal(t, "developers", props["groupName"])
		require.Equal(t, testApimProductGroupNativeID, props["id"])
	})

	t.Run("Read_of_an_unlinked_group_is_NotFound", func(t *testing.T) {
		exists = false
		defer func() { exists = true }()
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testApimProductGroupNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
	})

	t.Run("Update_re_puts_the_link", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testApimProductGroupNativeID,
			DesiredProperties: apimProductGroupDesired(),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testApimProductGroupNativeID, got.ProgressResult.NativeID)
	})

	t.Run("Delete_unlinks", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testApimProductGroupNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _, _, _ string, _ *armapimanagement.ProductGroupClientDeleteOptions) (armapimanagement.ProductGroupClientDeleteResponse, error) {
			return armapimanagement.ProductGroupClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testApimProductGroupNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_composes_link_ids_from_the_group_names", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{
				"resourceGroupName": "rg-1", "serviceName": "apim1", "productName": "starter",
			},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testApimProductGroupNativeID}, got.NativeIDs)
	})

	t.Run("List_without_parents_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure_with_a_reason", func(t *testing.T) {
		fake.createOrUpdateFn = func(_ context.Context, _, _, _, _ string, _ *armapimanagement.ProductGroupClientCreateOrUpdateOptions) (armapimanagement.ProductGroupClientCreateOrUpdateResponse, error) {
			return armapimanagement.ProductGroupClientCreateOrUpdateResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: apimProductGroupDesired()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.NotEmpty(t, got.ProgressResult.StatusMessage)
	})
}

func TestApiManagementProductGroup_ReadError(t *testing.T) {
	fake := &fakeApiManagementProductGroupsAPI{
		checkEntityExistsFn: func(_ context.Context, _, _, _, _ string, _ *armapimanagement.ProductGroupClientCheckEntityExistsOptions) (armapimanagement.ProductGroupClientCheckEntityExistsResponse, error) {
			return armapimanagement.ProductGroupClientCheckEntityExistsResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestApiManagementProductGroup(fake).Read(context.Background(),
		&resource.ReadRequest{NativeID: testApimProductGroupNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeApiManagementProductGroupsAPI struct {
	createOrUpdateFn        func(ctx context.Context, rgName, serviceName, productID, groupID string, options *armapimanagement.ProductGroupClientCreateOrUpdateOptions) (armapimanagement.ProductGroupClientCreateOrUpdateResponse, error)
	checkEntityExistsFn     func(ctx context.Context, rgName, serviceName, productID, groupID string, options *armapimanagement.ProductGroupClientCheckEntityExistsOptions) (armapimanagement.ProductGroupClientCheckEntityExistsResponse, error)
	deleteFn                func(ctx context.Context, rgName, serviceName, productID, groupID string, options *armapimanagement.ProductGroupClientDeleteOptions) (armapimanagement.ProductGroupClientDeleteResponse, error)
	newListByProductPagerFn func(rgName, serviceName, productID string, options *armapimanagement.ProductGroupClientListByProductOptions) *runtime.Pager[armapimanagement.ProductGroupClientListByProductResponse]
}

func (f *fakeApiManagementProductGroupsAPI) CreateOrUpdate(ctx context.Context, rgName, serviceName, productID, groupID string, options *armapimanagement.ProductGroupClientCreateOrUpdateOptions) (armapimanagement.ProductGroupClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, serviceName, productID, groupID, options)
}

func (f *fakeApiManagementProductGroupsAPI) CheckEntityExists(ctx context.Context, rgName, serviceName, productID, groupID string, options *armapimanagement.ProductGroupClientCheckEntityExistsOptions) (armapimanagement.ProductGroupClientCheckEntityExistsResponse, error) {
	return f.checkEntityExistsFn(ctx, rgName, serviceName, productID, groupID, options)
}

func (f *fakeApiManagementProductGroupsAPI) Delete(ctx context.Context, rgName, serviceName, productID, groupID string, options *armapimanagement.ProductGroupClientDeleteOptions) (armapimanagement.ProductGroupClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, serviceName, productID, groupID, options)
}

func (f *fakeApiManagementProductGroupsAPI) NewListByProductPager(rgName, serviceName, productID string, options *armapimanagement.ProductGroupClientListByProductOptions) *runtime.Pager[armapimanagement.ProductGroupClientListByProductResponse] {
	return f.newListByProductPagerFn(rgName, serviceName, productID, options)
}
