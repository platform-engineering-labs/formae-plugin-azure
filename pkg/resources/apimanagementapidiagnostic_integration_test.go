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

const testApimApiDiagnosticNativeID = testApimApiNativeID + "/diagnostics/applicationinsights"

func newTestApiManagementApiDiagnostic(api apiManagementAPIDiagnosticsAPI) *ApiManagementApiDiagnostic {
	return &ApiManagementApiDiagnostic{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

// Same shared body as the service-wide diagnostic, plus the one name that makes
// it per-API — which is exactly the relationship the two resources have.
func apimApiDiagnosticDesired(verbosity string) []byte {
	body := apimDiagnosticBodyDesired(verbosity)
	body["apiName"] = "api1"
	out, _ := json.Marshal(body)
	return out
}

func TestApiManagementApiDiagnostic_CRUD(t *testing.T) {
	diagResult := armapimanagement.DiagnosticContract{
		ID:   to.Ptr(testApimApiDiagnosticNativeID),
		Name: to.Ptr("applicationinsights"),
		Properties: &armapimanagement.DiagnosticContractProperties{
			LoggerID:  to.Ptr(testApimLoggerNativeID),
			Verbosity: to.Ptr(armapimanagement.VerbosityInformation),
			Backend: &armapimanagement.PipelineDiagnosticSettings{
				Response: &armapimanagement.HTTPMessageDiagnostic{
					Body: &armapimanagement.BodyDiagnosticSettings{Bytes: to.Ptr(int32(1024))},
				},
			},
		},
	}

	var sawAPI string
	var sentCreate armapimanagement.DiagnosticContract
	var sentUpdate armapimanagement.DiagnosticContract
	var sawIfMatch string
	deleteCalls := 0
	fake := &fakeApiManagementAPIDiagnosticsAPI{
		createOrUpdateFn: func(_ context.Context, _, serviceName, apiID, diagnosticID string, params armapimanagement.DiagnosticContract, _ *armapimanagement.APIDiagnosticClientCreateOrUpdateOptions) (armapimanagement.APIDiagnosticClientCreateOrUpdateResponse, error) {
			require.Equal(t, "apim1", serviceName)
			require.Equal(t, "applicationinsights", diagnosticID)
			sawAPI = apiID
			sentCreate = params
			return armapimanagement.APIDiagnosticClientCreateOrUpdateResponse{DiagnosticContract: diagResult}, nil
		},
		getFn: func(_ context.Context, _, _, _, _ string, _ *armapimanagement.APIDiagnosticClientGetOptions) (armapimanagement.APIDiagnosticClientGetResponse, error) {
			return armapimanagement.APIDiagnosticClientGetResponse{DiagnosticContract: diagResult}, nil
		},
		updateFn: func(_ context.Context, _, _, _, _, ifMatch string, params armapimanagement.DiagnosticContract, _ *armapimanagement.APIDiagnosticClientUpdateOptions) (armapimanagement.APIDiagnosticClientUpdateResponse, error) {
			sawIfMatch = ifMatch
			sentUpdate = params
			return armapimanagement.APIDiagnosticClientUpdateResponse{DiagnosticContract: diagResult}, nil
		},
		deleteFn: func(_ context.Context, _, _, _, _, ifMatch string, _ *armapimanagement.APIDiagnosticClientDeleteOptions) (armapimanagement.APIDiagnosticClientDeleteResponse, error) {
			sawIfMatch = ifMatch
			deleteCalls++
			return armapimanagement.APIDiagnosticClientDeleteResponse{}, nil
		},
		newListByServicePagerFn: func(_, _, _ string, _ *armapimanagement.APIDiagnosticClientListByServiceOptions) *runtime.Pager[armapimanagement.APIDiagnosticClientListByServiceResponse] {
			return runtime.NewPager(runtime.PagingHandler[armapimanagement.APIDiagnosticClientListByServiceResponse]{
				More: func(_ armapimanagement.APIDiagnosticClientListByServiceResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armapimanagement.APIDiagnosticClientListByServiceResponse) (armapimanagement.APIDiagnosticClientListByServiceResponse, error) {
					return armapimanagement.APIDiagnosticClientListByServiceResponse{
						DiagnosticCollection: armapimanagement.DiagnosticCollection{
							Value: []*armapimanagement.DiagnosticContract{{ID: to.Ptr(testApimApiDiagnosticNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestApiManagementApiDiagnostic(fake)

	t.Run("Create_carries_the_api_in_the_path_not_the_body", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "applicationinsights",
			Properties: apimApiDiagnosticDesired("information"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testApimApiDiagnosticNativeID, got.ProgressResult.NativeID)
		require.Empty(t, got.ProgressResult.RequestID)
		require.Equal(t, "api1", sawAPI)
		// The body is the shared one, byte for byte the same shape the
		// service-wide diagnostic sends.
		require.Equal(t, testApimLoggerNativeID, *sentCreate.Properties.LoggerID)
		require.Equal(t, int32(512), *sentCreate.Properties.Frontend.Request.Body.Bytes)
	})

	t.Run("Create_requires_the_api_and_the_logger", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "applicationinsights", "resourceGroupName": "rg-1", "serviceName": "apim1",
			"loggerId": testApimLoggerNativeID,
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "apiName is required")

		props, _ = json.Marshal(map[string]any{
			"name": "applicationinsights", "resourceGroupName": "rg-1", "serviceName": "apim1",
			"apiName": "api1",
		})
		_, err = prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "loggerId is required")
	})

	t.Run("Read_recovers_the_api_from_the_native_ID", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testApimApiDiagnosticNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "applicationinsights", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "apim1", props["serviceName"])
		require.Equal(t, "api1", props["apiName"])

		backend := props["backend"].(map[string]any)
		response := backend["response"].(map[string]any)
		require.Equal(t, 1024.0, response["bodyBytes"])
		// ARM returned no frontend block, so none is reported.
		require.NotContains(t, props, "frontend")
	})

	t.Run("Update_uses_the_same_contract_as_create_with_wildcard_if_match", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testApimApiDiagnosticNativeID,
			DesiredProperties: apimApiDiagnosticDesired("verbose"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, "*", sawIfMatch)
		require.Equal(t, armapimanagement.VerbosityVerbose, *sentUpdate.Properties.Verbosity)
	})

	t.Run("Delete_is_synchronous", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testApimApiDiagnosticNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
		require.Equal(t, "*", sawIfMatch)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _, _, _, _ string, _ *armapimanagement.APIDiagnosticClientDeleteOptions) (armapimanagement.APIDiagnosticClientDeleteResponse, error) {
			return armapimanagement.APIDiagnosticClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testApimApiDiagnosticNativeID})
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
		require.Equal(t, []string{testApimApiDiagnosticNativeID}, got.NativeIDs)
	})

	t.Run("List_without_the_api_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "serviceName": "apim1"},
		})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure_with_a_reason", func(t *testing.T) {
		fake.createOrUpdateFn = func(_ context.Context, _, _, _, _ string, _ armapimanagement.DiagnosticContract, _ *armapimanagement.APIDiagnosticClientCreateOrUpdateOptions) (armapimanagement.APIDiagnosticClientCreateOrUpdateResponse, error) {
			return armapimanagement.APIDiagnosticClientCreateOrUpdateResponse{}, &azcore.ResponseError{StatusCode: 400}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "applicationinsights", Properties: apimApiDiagnosticDesired("information"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.NotEmpty(t, got.ProgressResult.StatusMessage)
	})
}

func TestApiManagementApiDiagnostic_ReadNotFound(t *testing.T) {
	fake := &fakeApiManagementAPIDiagnosticsAPI{
		getFn: func(_ context.Context, _, _, _, _ string, _ *armapimanagement.APIDiagnosticClientGetOptions) (armapimanagement.APIDiagnosticClientGetResponse, error) {
			return armapimanagement.APIDiagnosticClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestApiManagementApiDiagnostic(fake).Read(context.Background(),
		&resource.ReadRequest{NativeID: testApimApiDiagnosticNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// A service-wide diagnostic ID must not parse as a per-API one: the two live at
// different depths and sending one to the other's client would 404 in a way
// that looks like a missing resource rather than a bad ID.
func TestApiManagementApiDiagnostic_RejectsTheServiceWideID(t *testing.T) {
	_, err := newTestApiManagementApiDiagnostic(&fakeApiManagementAPIDiagnosticsAPI{}).Read(
		context.Background(), &resource.ReadRequest{NativeID: testApimDiagnosticNativeID})
	require.ErrorContains(t, err, "is not a service/apis/diagnostics")
}

// --- Test helpers ---

type fakeApiManagementAPIDiagnosticsAPI struct {
	createOrUpdateFn        func(ctx context.Context, rgName, serviceName, apiID, diagnosticID string, params armapimanagement.DiagnosticContract, options *armapimanagement.APIDiagnosticClientCreateOrUpdateOptions) (armapimanagement.APIDiagnosticClientCreateOrUpdateResponse, error)
	getFn                   func(ctx context.Context, rgName, serviceName, apiID, diagnosticID string, options *armapimanagement.APIDiagnosticClientGetOptions) (armapimanagement.APIDiagnosticClientGetResponse, error)
	updateFn                func(ctx context.Context, rgName, serviceName, apiID, diagnosticID, ifMatch string, params armapimanagement.DiagnosticContract, options *armapimanagement.APIDiagnosticClientUpdateOptions) (armapimanagement.APIDiagnosticClientUpdateResponse, error)
	deleteFn                func(ctx context.Context, rgName, serviceName, apiID, diagnosticID, ifMatch string, options *armapimanagement.APIDiagnosticClientDeleteOptions) (armapimanagement.APIDiagnosticClientDeleteResponse, error)
	newListByServicePagerFn func(rgName, serviceName, apiID string, options *armapimanagement.APIDiagnosticClientListByServiceOptions) *runtime.Pager[armapimanagement.APIDiagnosticClientListByServiceResponse]
}

func (f *fakeApiManagementAPIDiagnosticsAPI) CreateOrUpdate(ctx context.Context, rgName, serviceName, apiID, diagnosticID string, params armapimanagement.DiagnosticContract, options *armapimanagement.APIDiagnosticClientCreateOrUpdateOptions) (armapimanagement.APIDiagnosticClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, serviceName, apiID, diagnosticID, params, options)
}

func (f *fakeApiManagementAPIDiagnosticsAPI) Get(ctx context.Context, rgName, serviceName, apiID, diagnosticID string, options *armapimanagement.APIDiagnosticClientGetOptions) (armapimanagement.APIDiagnosticClientGetResponse, error) {
	return f.getFn(ctx, rgName, serviceName, apiID, diagnosticID, options)
}

func (f *fakeApiManagementAPIDiagnosticsAPI) Update(ctx context.Context, rgName, serviceName, apiID, diagnosticID, ifMatch string, params armapimanagement.DiagnosticContract, options *armapimanagement.APIDiagnosticClientUpdateOptions) (armapimanagement.APIDiagnosticClientUpdateResponse, error) {
	return f.updateFn(ctx, rgName, serviceName, apiID, diagnosticID, ifMatch, params, options)
}

func (f *fakeApiManagementAPIDiagnosticsAPI) Delete(ctx context.Context, rgName, serviceName, apiID, diagnosticID, ifMatch string, options *armapimanagement.APIDiagnosticClientDeleteOptions) (armapimanagement.APIDiagnosticClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, serviceName, apiID, diagnosticID, ifMatch, options)
}

func (f *fakeApiManagementAPIDiagnosticsAPI) NewListByServicePager(rgName, serviceName, apiID string, options *armapimanagement.APIDiagnosticClientListByServiceOptions) *runtime.Pager[armapimanagement.APIDiagnosticClientListByServiceResponse] {
	return f.newListByServicePagerFn(rgName, serviceName, apiID, options)
}
