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

const testApimApiNativeID = testApimServiceNativeID + "/apis/api1"

func newTestApiManagementApi(api apiManagementAPIsAPI) *ApiManagementApi {
	return &ApiManagementApi{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func apimApiDesired(displayName string) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":              "api1",
		"resourceGroupName": "rg-1",
		"serviceName":       "apim1",
		"displayName":       displayName,
		"path":              "orders",
		"protocols":         []string{"https"},
		"serviceUrl":        "https://backend.example.com",
	})
	return out
}

func TestApiManagementApi_CRUD(t *testing.T) {
	apiResult := armapimanagement.APIContract{
		ID:   to.Ptr(testApimApiNativeID),
		Name: to.Ptr("api1"),
		Properties: &armapimanagement.APIContractProperties{
			DisplayName:          to.Ptr("Orders"),
			Path:                 to.Ptr("orders"),
			Protocols:            []*armapimanagement.Protocol{to.Ptr(armapimanagement.ProtocolHTTPS)},
			ServiceURL:           to.Ptr("https://backend.example.com"),
			APIRevision:          to.Ptr("1"),
			IsCurrent:            to.Ptr(true),
			SubscriptionRequired: to.Ptr(true),
			SubscriptionKeyParameterNames: &armapimanagement.SubscriptionKeyParameterNamesContract{
				Header: to.Ptr("Ocp-Apim-Subscription-Key"),
				Query:  to.Ptr("subscription-key"),
			},
			APIVersionSet: &armapimanagement.APIVersionSetContractDetails{
				ID:   to.Ptr(testApimServiceNativeID + "/apiVersionSets/vs1"),
				Name: to.Ptr("Orders versions"),
			},
			SourceAPIID: to.Ptr("ignored"),
		},
	}

	var sentCreate armapimanagement.APICreateOrUpdateParameter
	var sentUpdate armapimanagement.APIUpdateContract
	var sawIfMatch string
	deleteCalls := 0
	fake := &fakeApiManagementAPIsAPI{
		beginCreateOrUpdateFn: func(_ context.Context, _, serviceName, apiID string, params armapimanagement.APICreateOrUpdateParameter, _ *armapimanagement.APIClientBeginCreateOrUpdateOptions) (*runtime.Poller[armapimanagement.APIClientCreateOrUpdateResponse], error) {
			require.Equal(t, "apim1", serviceName)
			require.Equal(t, "api1", apiID)
			sentCreate = params
			return newDonePoller(armapimanagement.APIClientCreateOrUpdateResponse{APIContract: apiResult}), nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ *armapimanagement.APIClientGetOptions) (armapimanagement.APIClientGetResponse, error) {
			return armapimanagement.APIClientGetResponse{APIContract: apiResult}, nil
		},
		updateFn: func(_ context.Context, _, _, _, ifMatch string, params armapimanagement.APIUpdateContract, _ *armapimanagement.APIClientUpdateOptions) (armapimanagement.APIClientUpdateResponse, error) {
			sawIfMatch = ifMatch
			sentUpdate = params
			return armapimanagement.APIClientUpdateResponse{APIContract: apiResult}, nil
		},
		deleteFn: func(_ context.Context, _, _, _, ifMatch string, _ *armapimanagement.APIClientDeleteOptions) (armapimanagement.APIClientDeleteResponse, error) {
			sawIfMatch = ifMatch
			deleteCalls++
			return armapimanagement.APIClientDeleteResponse{}, nil
		},
		newListByServicePagerFn: func(_, _ string, _ *armapimanagement.APIClientListByServiceOptions) *runtime.Pager[armapimanagement.APIClientListByServiceResponse] {
			return runtime.NewPager(runtime.PagingHandler[armapimanagement.APIClientListByServiceResponse]{
				More: func(_ armapimanagement.APIClientListByServiceResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armapimanagement.APIClientListByServiceResponse) (armapimanagement.APIClientListByServiceResponse, error) {
					return armapimanagement.APIClientListByServiceResponse{
						APICollection: armapimanagement.APICollection{
							Value: []*armapimanagement.APIContract{{ID: to.Ptr(testApimApiNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestApiManagementApi(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "api1",
			Properties: apimApiDesired("Orders"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testApimApiNativeID, got.ProgressResult.NativeID)

		require.Equal(t, "orders", *sentCreate.Properties.Path)
		require.Equal(t, armapimanagement.ProtocolHTTPS, *sentCreate.Properties.Protocols[0])
		// This resource models the explicit form only: an import would make ARM
		// synthesize operations that then look like unmanaged children.
		require.Nil(t, sentCreate.Properties.Value)
		require.Nil(t, sentCreate.Properties.Format)
		// The pair is omitted wholesale when neither name is declared, so ARM
		// applies its own defaults rather than being sent empty strings.
		require.Nil(t, sentCreate.Properties.SubscriptionKeyParameterNames)
	})

	t.Run("Create_sends_one_subscription_key_name", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "api1", "resourceGroupName": "rg-1", "serviceName": "apim1",
			"displayName": "Orders", "path": "orders", "protocols": []string{"https"},
			"subscriptionKeyHeaderName": "X-Key",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.Equal(t, "X-Key", *sentCreate.Properties.SubscriptionKeyParameterNames.Header)
		require.Nil(t, sentCreate.Properties.SubscriptionKeyParameterNames.Query)
	})

	t.Run("Create_requires_path", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "api1", "resourceGroupName": "rg-1", "serviceName": "apim1", "displayName": "Orders",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "path is required")
	})

	t.Run("Create_requires_protocols", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "api1", "resourceGroupName": "rg-1", "serviceName": "apim1",
			"displayName": "Orders", "path": "orders",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "protocols is required")
	})

	t.Run("Create_requires_service", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "api1", "resourceGroupName": "rg-1"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "serviceName is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testApimApiNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "api1", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		// Both parents come from the native ID, not the response body.
		require.Equal(t, "apim1", props["serviceName"])
		require.Equal(t, "orders", props["path"])
		require.Equal(t, []any{"https"}, props["protocols"])
		require.Equal(t, "1", props["apiRevision"])
		require.Equal(t, "Ocp-Apim-Subscription-Key", props["subscriptionKeyHeaderName"])
	})

	// apiVersionSet is ARM's expanded copy of a property already reported as
	// apiVersionSetId, and sourceApiId is not modelled: reporting either would
	// be drift against a schema that has no such field.
	t.Run("Read_drops_the_expanded_version_set", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testApimApiNativeID})
		require.NoError(t, err)
		require.NotContains(t, got.Properties, "apiVersionSet\"")
		require.NotContains(t, got.Properties, "sourceApiId")
	})

	// The PATCH takes ifMatch positionally rather than as an option, and formae
	// has no optimistic-concurrency model for these, so the wildcard is sent.
	t.Run("Update_sends_wildcard_if_match", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testApimApiNativeID,
			DesiredProperties: apimApiDesired("Orders v2"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Empty(t, got.ProgressResult.RequestID)
		require.Equal(t, "*", sawIfMatch)
		require.Equal(t, "Orders v2", *sentUpdate.Properties.DisplayName)
	})

	t.Run("Delete_is_synchronous", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testApimApiNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Empty(t, got.ProgressResult.RequestID)
		require.Equal(t, before+1, deleteCalls)
		require.Equal(t, "*", sawIfMatch)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _, _, _ string, _ *armapimanagement.APIClientDeleteOptions) (armapimanagement.APIClientDeleteResponse, error) {
			return armapimanagement.APIClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testApimApiNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_service", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "serviceName": "apim1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testApimApiNativeID}, got.NativeIDs)
	})

	// ARM has no subscription-wide listing here: without both parents there is
	// nothing to page, so List must return empty rather than error.
	t.Run("List_without_parents_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure_with_a_reason", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _, _ string, _ armapimanagement.APICreateOrUpdateParameter, _ *armapimanagement.APIClientBeginCreateOrUpdateOptions) (*runtime.Poller[armapimanagement.APIClientCreateOrUpdateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 400}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "api1", Properties: apimApiDesired("Orders"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.NotEmpty(t, got.ProgressResult.StatusMessage)
	})
}

func TestApiManagementApi_ReadNotFound(t *testing.T) {
	fake := &fakeApiManagementAPIsAPI{
		getFn: func(_ context.Context, _, _, _ string, _ *armapimanagement.APIClientGetOptions) (armapimanagement.APIClientGetResponse, error) {
			return armapimanagement.APIClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestApiManagementApi(fake).Read(context.Background(), &resource.ReadRequest{NativeID: testApimApiNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeApiManagementAPIsAPI struct {
	beginCreateOrUpdateFn   func(ctx context.Context, rgName, serviceName, apiID string, params armapimanagement.APICreateOrUpdateParameter, options *armapimanagement.APIClientBeginCreateOrUpdateOptions) (*runtime.Poller[armapimanagement.APIClientCreateOrUpdateResponse], error)
	getFn                   func(ctx context.Context, rgName, serviceName, apiID string, options *armapimanagement.APIClientGetOptions) (armapimanagement.APIClientGetResponse, error)
	updateFn                func(ctx context.Context, rgName, serviceName, apiID, ifMatch string, params armapimanagement.APIUpdateContract, options *armapimanagement.APIClientUpdateOptions) (armapimanagement.APIClientUpdateResponse, error)
	deleteFn                func(ctx context.Context, rgName, serviceName, apiID, ifMatch string, options *armapimanagement.APIClientDeleteOptions) (armapimanagement.APIClientDeleteResponse, error)
	newListByServicePagerFn func(rgName, serviceName string, options *armapimanagement.APIClientListByServiceOptions) *runtime.Pager[armapimanagement.APIClientListByServiceResponse]
}

func (f *fakeApiManagementAPIsAPI) BeginCreateOrUpdate(ctx context.Context, rgName, serviceName, apiID string, params armapimanagement.APICreateOrUpdateParameter, options *armapimanagement.APIClientBeginCreateOrUpdateOptions) (*runtime.Poller[armapimanagement.APIClientCreateOrUpdateResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, rgName, serviceName, apiID, params, options)
}

func (f *fakeApiManagementAPIsAPI) Get(ctx context.Context, rgName, serviceName, apiID string, options *armapimanagement.APIClientGetOptions) (armapimanagement.APIClientGetResponse, error) {
	return f.getFn(ctx, rgName, serviceName, apiID, options)
}

func (f *fakeApiManagementAPIsAPI) Update(ctx context.Context, rgName, serviceName, apiID, ifMatch string, params armapimanagement.APIUpdateContract, options *armapimanagement.APIClientUpdateOptions) (armapimanagement.APIClientUpdateResponse, error) {
	return f.updateFn(ctx, rgName, serviceName, apiID, ifMatch, params, options)
}

func (f *fakeApiManagementAPIsAPI) Delete(ctx context.Context, rgName, serviceName, apiID, ifMatch string, options *armapimanagement.APIClientDeleteOptions) (armapimanagement.APIClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, serviceName, apiID, ifMatch, options)
}

func (f *fakeApiManagementAPIsAPI) NewListByServicePager(rgName, serviceName string, options *armapimanagement.APIClientListByServiceOptions) *runtime.Pager[armapimanagement.APIClientListByServiceResponse] {
	return f.newListByServicePagerFn(rgName, serviceName, options)
}
