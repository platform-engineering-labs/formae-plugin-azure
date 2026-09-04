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

const testApimApiTagDescriptionNativeID = testApimApiNativeID + "/tagDescriptions/orders-tag"

func newTestApiManagementApiTagDescription(api apiManagementAPITagDescriptionsAPI) *ApiManagementApiTagDescription {
	return &ApiManagementApiTagDescription{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func apimApiTagDescriptionDesired(description string) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":                    "orders-tag",
		"resourceGroupName":       "rg-1",
		"serviceName":             "apim1",
		"apiName":                 "api1",
		"description":             description,
		"externalDocsDescription": "Ordering guide",
		"externalDocsUrl":         "https://docs.example.com/orders",
	})
	return out
}

func TestApiManagementApiTagDescription_CRUD(t *testing.T) {
	descResult := armapimanagement.TagDescriptionContract{
		ID:   to.Ptr(testApimApiTagDescriptionNativeID),
		Name: to.Ptr("orders-tag"),
		Properties: &armapimanagement.TagDescriptionContractProperties{
			Description:             to.Ptr("Everything order-related"),
			ExternalDocsDescription: to.Ptr("Ordering guide"),
			ExternalDocsURL:         to.Ptr("https://docs.example.com/orders"),
			DisplayName:             to.Ptr("Orders"),
			TagID:                   to.Ptr(testApimServiceNativeID + "/tags/orders-tag"),
		},
	}

	var sentBody armapimanagement.TagDescriptionCreateParameters
	var sawAPI, sawTag, sawIfMatch string
	createCalls := 0
	deleteCalls := 0
	fake := &fakeApiManagementAPITagDescriptionsAPI{
		createOrUpdateFn: func(_ context.Context, _, _, apiID, tagDescriptionID string, params armapimanagement.TagDescriptionCreateParameters, _ *armapimanagement.APITagDescriptionClientCreateOrUpdateOptions) (armapimanagement.APITagDescriptionClientCreateOrUpdateResponse, error) {
			sawAPI, sawTag = apiID, tagDescriptionID
			sentBody = params
			createCalls++
			return armapimanagement.APITagDescriptionClientCreateOrUpdateResponse{TagDescriptionContract: descResult}, nil
		},
		getFn: func(_ context.Context, _, _, _, _ string, _ *armapimanagement.APITagDescriptionClientGetOptions) (armapimanagement.APITagDescriptionClientGetResponse, error) {
			return armapimanagement.APITagDescriptionClientGetResponse{TagDescriptionContract: descResult}, nil
		},
		deleteFn: func(_ context.Context, _, _, _, _, ifMatch string, _ *armapimanagement.APITagDescriptionClientDeleteOptions) (armapimanagement.APITagDescriptionClientDeleteResponse, error) {
			sawIfMatch = ifMatch
			deleteCalls++
			return armapimanagement.APITagDescriptionClientDeleteResponse{}, nil
		},
		newListByServicePagerFn: func(_, _, _ string, _ *armapimanagement.APITagDescriptionClientListByServiceOptions) *runtime.Pager[armapimanagement.APITagDescriptionClientListByServiceResponse] {
			return runtime.NewPager(runtime.PagingHandler[armapimanagement.APITagDescriptionClientListByServiceResponse]{
				More: func(_ armapimanagement.APITagDescriptionClientListByServiceResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armapimanagement.APITagDescriptionClientListByServiceResponse) (armapimanagement.APITagDescriptionClientListByServiceResponse, error) {
					return armapimanagement.APITagDescriptionClientListByServiceResponse{
						TagDescriptionCollection: armapimanagement.TagDescriptionCollection{
							Value: []*armapimanagement.TagDescriptionContract{{ID: to.Ptr(testApimApiTagDescriptionNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestApiManagementApiTagDescription(fake)

	t.Run("Create_is_synchronous", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "orders-tag",
			Properties: apimApiTagDescriptionDesired("Everything order-related"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testApimApiTagDescriptionNativeID, got.ProgressResult.NativeID)
		require.Empty(t, got.ProgressResult.RequestID)

		require.Equal(t, "api1", sawAPI)
		// The resource name IS the tag identifier: ARM addresses a description
		// by the tag it describes.
		require.Equal(t, "orders-tag", sawTag)
		require.Equal(t, "Everything order-related", *sentBody.Properties.Description)
		require.Equal(t, "https://docs.example.com/orders", *sentBody.Properties.ExternalDocsURL)
	})

	t.Run("Create_requires_api", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "orders-tag", "resourceGroupName": "rg-1", "serviceName": "apim1",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "apiName is required")
	})

	t.Run("Create_requires_service", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "orders-tag", "resourceGroupName": "rg-1"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "serviceName is required")
	})

	// A missing tag is what ARM answers when the tag this description points at
	// does not exist, which is the normal case until an
	// AZURE::ApiManagement::Tag type exists.
	t.Run("Missing_tag_maps_to_failure_with_a_reason", func(t *testing.T) {
		fake.createOrUpdateFn = func(_ context.Context, _, _, _, _ string, _ armapimanagement.TagDescriptionCreateParameters, _ *armapimanagement.APITagDescriptionClientCreateOrUpdateOptions) (armapimanagement.APITagDescriptionClientCreateOrUpdateResponse, error) {
			return armapimanagement.APITagDescriptionClientCreateOrUpdateResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "orders-tag", Properties: apimApiTagDescriptionDesired("Everything order-related"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.Equal(t, resource.OperationErrorCodeNotFound, got.ProgressResult.ErrorCode)
		require.NotEmpty(t, got.ProgressResult.StatusMessage)

		fake.createOrUpdateFn = func(_ context.Context, _, _, apiID, tagDescriptionID string, params armapimanagement.TagDescriptionCreateParameters, _ *armapimanagement.APITagDescriptionClientCreateOrUpdateOptions) (armapimanagement.APITagDescriptionClientCreateOrUpdateResponse, error) {
			sawAPI, sawTag = apiID, tagDescriptionID
			sentBody = params
			createCalls++
			return armapimanagement.APITagDescriptionClientCreateOrUpdateResponse{TagDescriptionContract: descResult}, nil
		}
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testApimApiTagDescriptionNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "orders-tag", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "apim1", props["serviceName"])
		require.Equal(t, "api1", props["apiName"])
		require.Equal(t, "Everything order-related", props["description"])
		// Both are derived by ARM from the tag being described.
		require.Equal(t, "Orders", props["displayName"])
		require.Equal(t, testApimServiceNativeID+"/tags/orders-tag", props["tagId"])
	})

	t.Run("Update_reissues_create_or_update", func(t *testing.T) {
		before := createCalls
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testApimApiTagDescriptionNativeID,
			DesiredProperties: apimApiTagDescriptionDesired("Order endpoints"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		// There is no PATCH verb for a tag description.
		require.Equal(t, before+1, createCalls)
		require.Equal(t, "Order endpoints", *sentBody.Properties.Description)
	})

	t.Run("Delete_is_synchronous", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testApimApiTagDescriptionNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
		require.Equal(t, "*", sawIfMatch)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _, _, _, _ string, _ *armapimanagement.APITagDescriptionClientDeleteOptions) (armapimanagement.APITagDescriptionClientDeleteResponse, error) {
			return armapimanagement.APITagDescriptionClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testApimApiTagDescriptionNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_api", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{
				"resourceGroupName": "rg-1", "serviceName": "apim1", "apiName": "api1",
			},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testApimApiTagDescriptionNativeID}, got.NativeIDs)
	})

	t.Run("List_without_the_api_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "serviceName": "apim1"},
		})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})
}

func TestApiManagementApiTagDescription_ReadNotFound(t *testing.T) {
	fake := &fakeApiManagementAPITagDescriptionsAPI{
		getFn: func(_ context.Context, _, _, _, _ string, _ *armapimanagement.APITagDescriptionClientGetOptions) (armapimanagement.APITagDescriptionClientGetResponse, error) {
			return armapimanagement.APITagDescriptionClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestApiManagementApiTagDescription(fake).Read(context.Background(),
		&resource.ReadRequest{NativeID: testApimApiTagDescriptionNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeApiManagementAPITagDescriptionsAPI struct {
	createOrUpdateFn        func(ctx context.Context, rgName, serviceName, apiID, tagDescriptionID string, params armapimanagement.TagDescriptionCreateParameters, options *armapimanagement.APITagDescriptionClientCreateOrUpdateOptions) (armapimanagement.APITagDescriptionClientCreateOrUpdateResponse, error)
	getFn                   func(ctx context.Context, rgName, serviceName, apiID, tagDescriptionID string, options *armapimanagement.APITagDescriptionClientGetOptions) (armapimanagement.APITagDescriptionClientGetResponse, error)
	deleteFn                func(ctx context.Context, rgName, serviceName, apiID, tagDescriptionID, ifMatch string, options *armapimanagement.APITagDescriptionClientDeleteOptions) (armapimanagement.APITagDescriptionClientDeleteResponse, error)
	newListByServicePagerFn func(rgName, serviceName, apiID string, options *armapimanagement.APITagDescriptionClientListByServiceOptions) *runtime.Pager[armapimanagement.APITagDescriptionClientListByServiceResponse]
}

func (f *fakeApiManagementAPITagDescriptionsAPI) CreateOrUpdate(ctx context.Context, rgName, serviceName, apiID, tagDescriptionID string, params armapimanagement.TagDescriptionCreateParameters, options *armapimanagement.APITagDescriptionClientCreateOrUpdateOptions) (armapimanagement.APITagDescriptionClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, serviceName, apiID, tagDescriptionID, params, options)
}

func (f *fakeApiManagementAPITagDescriptionsAPI) Get(ctx context.Context, rgName, serviceName, apiID, tagDescriptionID string, options *armapimanagement.APITagDescriptionClientGetOptions) (armapimanagement.APITagDescriptionClientGetResponse, error) {
	return f.getFn(ctx, rgName, serviceName, apiID, tagDescriptionID, options)
}

func (f *fakeApiManagementAPITagDescriptionsAPI) Delete(ctx context.Context, rgName, serviceName, apiID, tagDescriptionID, ifMatch string, options *armapimanagement.APITagDescriptionClientDeleteOptions) (armapimanagement.APITagDescriptionClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, serviceName, apiID, tagDescriptionID, ifMatch, options)
}

func (f *fakeApiManagementAPITagDescriptionsAPI) NewListByServicePager(rgName, serviceName, apiID string, options *armapimanagement.APITagDescriptionClientListByServiceOptions) *runtime.Pager[armapimanagement.APITagDescriptionClientListByServiceResponse] {
	return f.newListByServicePagerFn(rgName, serviceName, apiID, options)
}
