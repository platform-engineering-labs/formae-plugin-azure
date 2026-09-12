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

const testApimBackendNativeID = testApimServiceNativeID + "/backends/echo"

func newTestApiManagementBackend(api apiManagementBackendsAPI) *ApiManagementBackend {
	return &ApiManagementBackend{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func apimBackendDesired(title string) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":              "echo",
		"resourceGroupName": "rg-1",
		"serviceName":       "apim1",
		"url":               "https://echo.platform.engineering",
		"protocol":          "http",
		"title":             title,
		"description":       "Conformance backend",
		"tls": map[string]any{
			"validateCertificateChain": false,
			"validateCertificateName":  false,
		},
	})
	return out
}

func TestApiManagementBackend_CRUD(t *testing.T) {
	backendResult := armapimanagement.BackendContract{
		ID:   to.Ptr(testApimBackendNativeID),
		Name: to.Ptr("echo"),
		Properties: &armapimanagement.BackendContractProperties{
			URL:         to.Ptr("https://echo.platform.engineering"),
			Protocol:    to.Ptr(armapimanagement.BackendProtocolHTTP),
			Title:       to.Ptr("Echo"),
			Description: to.Ptr("Conformance backend"),
			TLS: &armapimanagement.BackendTLSProperties{
				ValidateCertificateChain: to.Ptr(false),
				ValidateCertificateName:  to.Ptr(false),
			},
			Credentials: &armapimanagement.BackendCredentialsContract{
				Authorization: &armapimanagement.BackendAuthorizationHeaderCredentials{
					Scheme: to.Ptr("Basic"),
					// ARM answers with a masked placeholder, never the value.
					Parameter: to.Ptr("****"),
				},
			},
		},
	}

	var sentCreate armapimanagement.BackendContract
	var sentUpdate armapimanagement.BackendUpdateParameters
	var sawIfMatch string
	deleteCalls := 0
	fake := &fakeApiManagementBackendsAPI{
		createOrUpdateFn: func(_ context.Context, _, serviceName, backendID string, params armapimanagement.BackendContract, _ *armapimanagement.BackendClientCreateOrUpdateOptions) (armapimanagement.BackendClientCreateOrUpdateResponse, error) {
			require.Equal(t, "apim1", serviceName)
			require.NotEmpty(t, backendID)
			sentCreate = params
			return armapimanagement.BackendClientCreateOrUpdateResponse{BackendContract: backendResult}, nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ *armapimanagement.BackendClientGetOptions) (armapimanagement.BackendClientGetResponse, error) {
			return armapimanagement.BackendClientGetResponse{BackendContract: backendResult}, nil
		},
		updateFn: func(_ context.Context, _, _, _, ifMatch string, params armapimanagement.BackendUpdateParameters, _ *armapimanagement.BackendClientUpdateOptions) (armapimanagement.BackendClientUpdateResponse, error) {
			sawIfMatch = ifMatch
			sentUpdate = params
			return armapimanagement.BackendClientUpdateResponse{BackendContract: backendResult}, nil
		},
		deleteFn: func(_ context.Context, _, _, _, ifMatch string, _ *armapimanagement.BackendClientDeleteOptions) (armapimanagement.BackendClientDeleteResponse, error) {
			sawIfMatch = ifMatch
			deleteCalls++
			return armapimanagement.BackendClientDeleteResponse{}, nil
		},
		newListByServicePagerFn: func(_, _ string, _ *armapimanagement.BackendClientListByServiceOptions) *runtime.Pager[armapimanagement.BackendClientListByServiceResponse] {
			return runtime.NewPager(runtime.PagingHandler[armapimanagement.BackendClientListByServiceResponse]{
				More: func(_ armapimanagement.BackendClientListByServiceResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armapimanagement.BackendClientListByServiceResponse) (armapimanagement.BackendClientListByServiceResponse, error) {
					return armapimanagement.BackendClientListByServiceResponse{
						BackendCollection: armapimanagement.BackendCollection{
							Value: []*armapimanagement.BackendContract{{ID: to.Ptr(testApimBackendNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestApiManagementBackend(fake)

	t.Run("Create_is_synchronous", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "echo",
			Properties: apimBackendDesired("Echo"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testApimBackendNativeID, got.ProgressResult.NativeID)
		require.Empty(t, got.ProgressResult.RequestID)
		require.Equal(t, "https://echo.platform.engineering", *sentCreate.Properties.URL)
		require.Equal(t, armapimanagement.BackendProtocolHTTP, *sentCreate.Properties.Protocol)
		require.False(t, *sentCreate.Properties.TLS.ValidateCertificateChain)
		require.Nil(t, sentCreate.Properties.Credentials)
	})

	t.Run("Create_sends_an_authorization_header_only_when_both_halves_are_set", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "echo", "resourceGroupName": "rg-1", "serviceName": "apim1",
			"url": "https://echo.platform.engineering", "protocol": "http",
			"credentials": map[string]any{"authorizationScheme": "Basic"},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.NotNil(t, sentCreate.Properties.Credentials)
		require.Nil(t, sentCreate.Properties.Credentials.Authorization)

		props, _ = json.Marshal(map[string]any{
			"name": "echo", "resourceGroupName": "rg-1", "serviceName": "apim1",
			"url": "https://echo.platform.engineering", "protocol": "http",
			"credentials": map[string]any{
				"authorizationScheme":    "Basic",
				"authorizationParameter": "dXNlcjpwYXNz",
				"certificateIds":         []string{testApimServiceNativeID + "/certificates/client"},
			},
		})
		_, err = prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.Equal(t, "Basic", *sentCreate.Properties.Credentials.Authorization.Scheme)
		require.Equal(t, "dXNlcjpwYXNz", *sentCreate.Properties.Credentials.Authorization.Parameter)
		require.Len(t, sentCreate.Properties.Credentials.CertificateIDs, 1)
	})

	t.Run("Create_requires_url_and_protocol", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "echo", "resourceGroupName": "rg-1", "serviceName": "apim1",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "url is required")

		props, _ = json.Marshal(map[string]any{
			"name": "echo", "resourceGroupName": "rg-1", "serviceName": "apim1",
			"url": "https://echo.platform.engineering",
		})
		_, err = prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "protocol is required")
	})

	t.Run("Read_never_reports_the_masked_authorization_parameter", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testApimBackendNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "echo", props["name"])
		require.Equal(t, "http", props["protocol"])
		require.Equal(t, map[string]any{
			"validateCertificateChain": false,
			"validateCertificateName":  false,
		}, props["tls"])
		creds, ok := props["credentials"].(map[string]any)
		require.True(t, ok)
		require.Equal(t, "Basic", creds["authorizationScheme"])
		require.NotContains(t, creds, "authorizationParameter")
	})

	t.Run("Update_uses_patch_with_wildcard_if_match", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testApimBackendNativeID,
			DesiredProperties: apimBackendDesired("Echo v2"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, "*", sawIfMatch)
		require.Equal(t, "Echo v2", *sentUpdate.Properties.Title)
	})

	t.Run("Delete_is_synchronous", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testApimBackendNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
		require.Equal(t, "*", sawIfMatch)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _, _, _ string, _ *armapimanagement.BackendClientDeleteOptions) (armapimanagement.BackendClientDeleteResponse, error) {
			return armapimanagement.BackendClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testApimBackendNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_service", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "serviceName": "apim1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testApimBackendNativeID}, got.NativeIDs)
	})

	t.Run("List_without_parents_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure_with_a_reason", func(t *testing.T) {
		fake.createOrUpdateFn = func(_ context.Context, _, _, _ string, _ armapimanagement.BackendContract, _ *armapimanagement.BackendClientCreateOrUpdateOptions) (armapimanagement.BackendClientCreateOrUpdateResponse, error) {
			return armapimanagement.BackendClientCreateOrUpdateResponse{}, &azcore.ResponseError{StatusCode: 400}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "echo", Properties: apimBackendDesired("Echo"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.NotEmpty(t, got.ProgressResult.StatusMessage)
	})
}

func TestApiManagementBackend_ReadNotFound(t *testing.T) {
	fake := &fakeApiManagementBackendsAPI{
		getFn: func(_ context.Context, _, _, _ string, _ *armapimanagement.BackendClientGetOptions) (armapimanagement.BackendClientGetResponse, error) {
			return armapimanagement.BackendClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestApiManagementBackend(fake).Read(context.Background(),
		&resource.ReadRequest{NativeID: testApimBackendNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeApiManagementBackendsAPI struct {
	createOrUpdateFn        func(ctx context.Context, rgName, serviceName, backendID string, params armapimanagement.BackendContract, options *armapimanagement.BackendClientCreateOrUpdateOptions) (armapimanagement.BackendClientCreateOrUpdateResponse, error)
	getFn                   func(ctx context.Context, rgName, serviceName, backendID string, options *armapimanagement.BackendClientGetOptions) (armapimanagement.BackendClientGetResponse, error)
	updateFn                func(ctx context.Context, rgName, serviceName, backendID, ifMatch string, params armapimanagement.BackendUpdateParameters, options *armapimanagement.BackendClientUpdateOptions) (armapimanagement.BackendClientUpdateResponse, error)
	deleteFn                func(ctx context.Context, rgName, serviceName, backendID, ifMatch string, options *armapimanagement.BackendClientDeleteOptions) (armapimanagement.BackendClientDeleteResponse, error)
	newListByServicePagerFn func(rgName, serviceName string, options *armapimanagement.BackendClientListByServiceOptions) *runtime.Pager[armapimanagement.BackendClientListByServiceResponse]
}

func (f *fakeApiManagementBackendsAPI) CreateOrUpdate(ctx context.Context, rgName, serviceName, backendID string, params armapimanagement.BackendContract, options *armapimanagement.BackendClientCreateOrUpdateOptions) (armapimanagement.BackendClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, serviceName, backendID, params, options)
}

func (f *fakeApiManagementBackendsAPI) Get(ctx context.Context, rgName, serviceName, backendID string, options *armapimanagement.BackendClientGetOptions) (armapimanagement.BackendClientGetResponse, error) {
	return f.getFn(ctx, rgName, serviceName, backendID, options)
}

func (f *fakeApiManagementBackendsAPI) Update(ctx context.Context, rgName, serviceName, backendID, ifMatch string, params armapimanagement.BackendUpdateParameters, options *armapimanagement.BackendClientUpdateOptions) (armapimanagement.BackendClientUpdateResponse, error) {
	return f.updateFn(ctx, rgName, serviceName, backendID, ifMatch, params, options)
}

func (f *fakeApiManagementBackendsAPI) Delete(ctx context.Context, rgName, serviceName, backendID, ifMatch string, options *armapimanagement.BackendClientDeleteOptions) (armapimanagement.BackendClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, serviceName, backendID, ifMatch, options)
}

func (f *fakeApiManagementBackendsAPI) NewListByServicePager(rgName, serviceName string, options *armapimanagement.BackendClientListByServiceOptions) *runtime.Pager[armapimanagement.BackendClientListByServiceResponse] {
	return f.newListByServicePagerFn(rgName, serviceName, options)
}
