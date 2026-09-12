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

const testApimApiOperationNativeID = testApimApiNativeID + "/operations/get-status"

func newTestApiManagementApiOperation(api apiManagementAPIOperationsAPI) *ApiManagementApiOperation {
	return &ApiManagementApiOperation{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func apimApiOperationDesired(displayName string) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":              "get-status",
		"resourceGroupName": "rg-1",
		"serviceName":       "apim1",
		"apiName":           "api1",
		"displayName":       displayName,
		"method":            "GET",
		"urlTemplate":       "/status",
	})
	return out
}

func TestApiManagementApiOperation_CRUD(t *testing.T) {
	opResult := armapimanagement.OperationContract{
		ID:   to.Ptr(testApimApiOperationNativeID),
		Name: to.Ptr("get-status"),
		Properties: &armapimanagement.OperationContractProperties{
			DisplayName: to.Ptr("Get status"),
			Method:      to.Ptr("GET"),
			URLTemplate: to.Ptr("/status"),
			Description: to.Ptr("Health probe"),
			Policies:    to.Ptr("<policies><inbound /></policies>"),
			Responses: []*armapimanagement.ResponseContract{
				{StatusCode: to.Ptr(int32(200))},
			},
			TemplateParameters: []*armapimanagement.ParameterContract{},
		},
	}

	var sentCreate armapimanagement.OperationContract
	var sentUpdate armapimanagement.OperationUpdateContract
	var sawAPI, sawIfMatch string
	createCalls := 0
	deleteCalls := 0
	fake := &fakeApiManagementAPIOperationsAPI{
		createOrUpdateFn: func(_ context.Context, _, _, apiID, operationID string, params armapimanagement.OperationContract, _ *armapimanagement.APIOperationClientCreateOrUpdateOptions) (armapimanagement.APIOperationClientCreateOrUpdateResponse, error) {
			require.Equal(t, "get-status", operationID)
			sawAPI = apiID
			sentCreate = params
			createCalls++
			return armapimanagement.APIOperationClientCreateOrUpdateResponse{OperationContract: opResult}, nil
		},
		getFn: func(_ context.Context, _, _, _, _ string, _ *armapimanagement.APIOperationClientGetOptions) (armapimanagement.APIOperationClientGetResponse, error) {
			return armapimanagement.APIOperationClientGetResponse{OperationContract: opResult}, nil
		},
		updateFn: func(_ context.Context, _, _, _, _, ifMatch string, params armapimanagement.OperationUpdateContract, _ *armapimanagement.APIOperationClientUpdateOptions) (armapimanagement.APIOperationClientUpdateResponse, error) {
			sawIfMatch = ifMatch
			sentUpdate = params
			return armapimanagement.APIOperationClientUpdateResponse{OperationContract: opResult}, nil
		},
		deleteFn: func(_ context.Context, _, _, _, _, ifMatch string, _ *armapimanagement.APIOperationClientDeleteOptions) (armapimanagement.APIOperationClientDeleteResponse, error) {
			sawIfMatch = ifMatch
			deleteCalls++
			return armapimanagement.APIOperationClientDeleteResponse{}, nil
		},
		newListByAPIPagerFn: func(_, _, _ string, _ *armapimanagement.APIOperationClientListByAPIOptions) *runtime.Pager[armapimanagement.APIOperationClientListByAPIResponse] {
			return runtime.NewPager(runtime.PagingHandler[armapimanagement.APIOperationClientListByAPIResponse]{
				More: func(_ armapimanagement.APIOperationClientListByAPIResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armapimanagement.APIOperationClientListByAPIResponse) (armapimanagement.APIOperationClientListByAPIResponse, error) {
					return armapimanagement.APIOperationClientListByAPIResponse{
						OperationCollection: armapimanagement.OperationCollection{
							Value: []*armapimanagement.OperationContract{{ID: to.Ptr(testApimApiOperationNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestApiManagementApiOperation(fake)

	t.Run("Create_is_synchronous", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "get-status",
			Properties: apimApiOperationDesired("Get status"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testApimApiOperationNativeID, got.ProgressResult.NativeID)
		require.Empty(t, got.ProgressResult.RequestID)

		require.Equal(t, "api1", sawAPI)
		require.Equal(t, "GET", *sentCreate.Properties.Method)
		require.Equal(t, "/status", *sentCreate.Properties.URLTemplate)
		// The request and response contracts are not modelled, so nothing is
		// sent for them: ARM would otherwise materialize defaults inside each
		// nested object.
		require.Nil(t, sentCreate.Properties.Request)
		require.Nil(t, sentCreate.Properties.Responses)
		require.Nil(t, sentCreate.Properties.TemplateParameters)
		// The operation's policy is its own resource; sending it from here
		// would let the two fight over one document.
		require.Nil(t, sentCreate.Properties.Policies)
	})

	t.Run("Create_requires_method", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "get-status", "resourceGroupName": "rg-1", "serviceName": "apim1",
			"apiName": "api1", "displayName": "Get status",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "method is required")
	})

	t.Run("Create_requires_url_template", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "get-status", "resourceGroupName": "rg-1", "serviceName": "apim1",
			"apiName": "api1", "displayName": "Get status", "method": "GET",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "urlTemplate is required")
	})

	t.Run("Create_requires_api", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "get-status", "resourceGroupName": "rg-1", "serviceName": "apim1",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "apiName is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testApimApiOperationNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "get-status", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		// All three parents come from the native ID, not the response body.
		require.Equal(t, "apim1", props["serviceName"])
		require.Equal(t, "api1", props["apiName"])
		require.Equal(t, "GET", props["method"])
		require.Equal(t, "/status", props["urlTemplate"])
		require.Equal(t, "Health probe", props["description"])
	})

	// ARM echoes the operation's policy and materializes empty request,
	// response and template-parameter blocks; none is modelled, so none may be
	// reported.
	t.Run("Read_drops_unmodelled_blocks", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testApimApiOperationNativeID})
		require.NoError(t, err)
		for _, key := range []string{"policies", "request", "responses", "templateParameters"} {
			require.NotContains(t, got.Properties, key)
		}
	})

	t.Run("Update_uses_patch_with_wildcard_if_match", func(t *testing.T) {
		before := createCalls
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testApimApiOperationNativeID,
			DesiredProperties: apimApiOperationDesired("Get status v2"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Empty(t, got.ProgressResult.RequestID)
		require.Equal(t, "*", sawIfMatch)
		require.Equal(t, "Get status v2", *sentUpdate.Properties.DisplayName)
		// An update must not go through the create verb.
		require.Equal(t, before, createCalls)
	})

	t.Run("Delete_is_synchronous", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testApimApiOperationNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
		require.Equal(t, "*", sawIfMatch)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _, _, _, _ string, _ *armapimanagement.APIOperationClientDeleteOptions) (armapimanagement.APIOperationClientDeleteResponse, error) {
			return armapimanagement.APIOperationClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testApimApiOperationNativeID})
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
		require.Equal(t, []string{testApimApiOperationNativeID}, got.NativeIDs)
	})

	t.Run("List_without_parents_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "serviceName": "apim1"},
		})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure_with_a_reason", func(t *testing.T) {
		fake.createOrUpdateFn = func(_ context.Context, _, _, _, _ string, _ armapimanagement.OperationContract, _ *armapimanagement.APIOperationClientCreateOrUpdateOptions) (armapimanagement.APIOperationClientCreateOrUpdateResponse, error) {
			return armapimanagement.APIOperationClientCreateOrUpdateResponse{}, &azcore.ResponseError{StatusCode: 409}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "get-status", Properties: apimApiOperationDesired("Get status"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.NotEmpty(t, got.ProgressResult.StatusMessage)
	})
}

func TestApiManagementApiOperation_ReadNotFound(t *testing.T) {
	fake := &fakeApiManagementAPIOperationsAPI{
		getFn: func(_ context.Context, _, _, _, _ string, _ *armapimanagement.APIOperationClientGetOptions) (armapimanagement.APIOperationClientGetResponse, error) {
			return armapimanagement.APIOperationClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestApiManagementApiOperation(fake).Read(context.Background(),
		&resource.ReadRequest{NativeID: testApimApiOperationNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeApiManagementAPIOperationsAPI struct {
	createOrUpdateFn    func(ctx context.Context, rgName, serviceName, apiID, operationID string, params armapimanagement.OperationContract, options *armapimanagement.APIOperationClientCreateOrUpdateOptions) (armapimanagement.APIOperationClientCreateOrUpdateResponse, error)
	getFn               func(ctx context.Context, rgName, serviceName, apiID, operationID string, options *armapimanagement.APIOperationClientGetOptions) (armapimanagement.APIOperationClientGetResponse, error)
	updateFn            func(ctx context.Context, rgName, serviceName, apiID, operationID, ifMatch string, params armapimanagement.OperationUpdateContract, options *armapimanagement.APIOperationClientUpdateOptions) (armapimanagement.APIOperationClientUpdateResponse, error)
	deleteFn            func(ctx context.Context, rgName, serviceName, apiID, operationID, ifMatch string, options *armapimanagement.APIOperationClientDeleteOptions) (armapimanagement.APIOperationClientDeleteResponse, error)
	newListByAPIPagerFn func(rgName, serviceName, apiID string, options *armapimanagement.APIOperationClientListByAPIOptions) *runtime.Pager[armapimanagement.APIOperationClientListByAPIResponse]
}

func (f *fakeApiManagementAPIOperationsAPI) CreateOrUpdate(ctx context.Context, rgName, serviceName, apiID, operationID string, params armapimanagement.OperationContract, options *armapimanagement.APIOperationClientCreateOrUpdateOptions) (armapimanagement.APIOperationClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, serviceName, apiID, operationID, params, options)
}

func (f *fakeApiManagementAPIOperationsAPI) Get(ctx context.Context, rgName, serviceName, apiID, operationID string, options *armapimanagement.APIOperationClientGetOptions) (armapimanagement.APIOperationClientGetResponse, error) {
	return f.getFn(ctx, rgName, serviceName, apiID, operationID, options)
}

func (f *fakeApiManagementAPIOperationsAPI) Update(ctx context.Context, rgName, serviceName, apiID, operationID, ifMatch string, params armapimanagement.OperationUpdateContract, options *armapimanagement.APIOperationClientUpdateOptions) (armapimanagement.APIOperationClientUpdateResponse, error) {
	return f.updateFn(ctx, rgName, serviceName, apiID, operationID, ifMatch, params, options)
}

func (f *fakeApiManagementAPIOperationsAPI) Delete(ctx context.Context, rgName, serviceName, apiID, operationID, ifMatch string, options *armapimanagement.APIOperationClientDeleteOptions) (armapimanagement.APIOperationClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, serviceName, apiID, operationID, ifMatch, options)
}

func (f *fakeApiManagementAPIOperationsAPI) NewListByAPIPager(rgName, serviceName, apiID string, options *armapimanagement.APIOperationClientListByAPIOptions) *runtime.Pager[armapimanagement.APIOperationClientListByAPIResponse] {
	return f.newListByAPIPagerFn(rgName, serviceName, apiID, options)
}
