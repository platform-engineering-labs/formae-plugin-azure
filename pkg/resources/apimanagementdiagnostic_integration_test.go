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

const testApimDiagnosticNativeID = testApimServiceNativeID + "/diagnostics/applicationinsights"

func newTestApiManagementDiagnostic(api apiManagementDiagnosticsAPI) *ApiManagementDiagnostic {
	return &ApiManagementDiagnostic{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

// apimDiagnosticBodyDesired is the shared half of both diagnostics' desired
// state, so the two tests exercise the same body through the same helper.
func apimDiagnosticBodyDesired(verbosity string) map[string]any {
	return map[string]any{
		"resourceGroupName":       "rg-1",
		"serviceName":             "apim1",
		"name":                    "applicationinsights",
		"loggerId":                testApimLoggerNativeID,
		"alwaysLog":               "allErrors",
		"httpCorrelationProtocol": "W3C",
		"logClientIp":             true,
		"operationNameFormat":     "Name",
		"verbosity":               verbosity,
		"sampling": map[string]any{
			"samplingType": "fixed",
			"percentage":   100,
		},
		"frontend": map[string]any{
			"request": map[string]any{
				"headers":   []string{"x-formae-conformance"},
				"bodyBytes": 512,
			},
		},
	}
}

func apimDiagnosticDesired(verbosity string) []byte {
	out, _ := json.Marshal(apimDiagnosticBodyDesired(verbosity))
	return out
}

func TestApiManagementDiagnostic_CRUD(t *testing.T) {
	diagResult := armapimanagement.DiagnosticContract{
		ID:   to.Ptr(testApimDiagnosticNativeID),
		Name: to.Ptr("applicationinsights"),
		Properties: &armapimanagement.DiagnosticContractProperties{
			LoggerID:                to.Ptr(testApimLoggerNativeID),
			AlwaysLog:               to.Ptr(armapimanagement.AlwaysLogAllErrors),
			HTTPCorrelationProtocol: to.Ptr(armapimanagement.HTTPCorrelationProtocolW3C),
			LogClientIP:             to.Ptr(true),
			OperationNameFormat:     to.Ptr(armapimanagement.OperationNameFormatName),
			Verbosity:               to.Ptr(armapimanagement.VerbosityInformation),
			Sampling: &armapimanagement.SamplingSettings{
				SamplingType: to.Ptr(armapimanagement.SamplingTypeFixed),
				Percentage:   to.Ptr(100.0),
			},
			Frontend: &armapimanagement.PipelineDiagnosticSettings{
				Request: &armapimanagement.HTTPMessageDiagnostic{
					Headers: []*string{to.Ptr("x-formae-conformance")},
					Body:    &armapimanagement.BodyDiagnosticSettings{Bytes: to.Ptr(int32(512))},
					// Service-populated, and deliberately not modelled: it would
					// read back as drift on every sync.
					DataMasking: &armapimanagement.DataMasking{
						Headers: []*armapimanagement.DataMaskingEntity{{
							Mode:  to.Ptr(armapimanagement.DataMaskingModeHide),
							Value: to.Ptr("Ocp-Apim-Subscription-Key"),
						}},
					},
				},
			},
		},
	}

	var sentCreate armapimanagement.DiagnosticContract
	var sentUpdate armapimanagement.DiagnosticContract
	var sawIfMatch string
	deleteCalls := 0
	fake := &fakeApiManagementDiagnosticsAPI{
		createOrUpdateFn: func(_ context.Context, _, serviceName, diagnosticID string, params armapimanagement.DiagnosticContract, _ *armapimanagement.DiagnosticClientCreateOrUpdateOptions) (armapimanagement.DiagnosticClientCreateOrUpdateResponse, error) {
			require.Equal(t, "apim1", serviceName)
			require.Equal(t, "applicationinsights", diagnosticID)
			sentCreate = params
			return armapimanagement.DiagnosticClientCreateOrUpdateResponse{DiagnosticContract: diagResult}, nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ *armapimanagement.DiagnosticClientGetOptions) (armapimanagement.DiagnosticClientGetResponse, error) {
			return armapimanagement.DiagnosticClientGetResponse{DiagnosticContract: diagResult}, nil
		},
		updateFn: func(_ context.Context, _, _, _, ifMatch string, params armapimanagement.DiagnosticContract, _ *armapimanagement.DiagnosticClientUpdateOptions) (armapimanagement.DiagnosticClientUpdateResponse, error) {
			sawIfMatch = ifMatch
			sentUpdate = params
			return armapimanagement.DiagnosticClientUpdateResponse{DiagnosticContract: diagResult}, nil
		},
		deleteFn: func(_ context.Context, _, _, _, ifMatch string, _ *armapimanagement.DiagnosticClientDeleteOptions) (armapimanagement.DiagnosticClientDeleteResponse, error) {
			sawIfMatch = ifMatch
			deleteCalls++
			return armapimanagement.DiagnosticClientDeleteResponse{}, nil
		},
		newListByServicePagerFn: func(_, _ string, _ *armapimanagement.DiagnosticClientListByServiceOptions) *runtime.Pager[armapimanagement.DiagnosticClientListByServiceResponse] {
			return runtime.NewPager(runtime.PagingHandler[armapimanagement.DiagnosticClientListByServiceResponse]{
				More: func(_ armapimanagement.DiagnosticClientListByServiceResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armapimanagement.DiagnosticClientListByServiceResponse) (armapimanagement.DiagnosticClientListByServiceResponse, error) {
					return armapimanagement.DiagnosticClientListByServiceResponse{
						DiagnosticCollection: armapimanagement.DiagnosticCollection{
							Value: []*armapimanagement.DiagnosticContract{{ID: to.Ptr(testApimDiagnosticNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestApiManagementDiagnostic(fake)

	t.Run("Create_sends_the_whole_nested_body", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "applicationinsights",
			Properties: apimDiagnosticDesired("information"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testApimDiagnosticNativeID, got.ProgressResult.NativeID)
		require.Empty(t, got.ProgressResult.RequestID)

		p := sentCreate.Properties
		require.Equal(t, testApimLoggerNativeID, *p.LoggerID)
		require.Equal(t, armapimanagement.AlwaysLogAllErrors, *p.AlwaysLog)
		require.Equal(t, armapimanagement.HTTPCorrelationProtocolW3C, *p.HTTPCorrelationProtocol)
		require.Equal(t, armapimanagement.VerbosityInformation, *p.Verbosity)
		require.Equal(t, armapimanagement.SamplingTypeFixed, *p.Sampling.SamplingType)
		require.InDelta(t, 100.0, *p.Sampling.Percentage, 0.001)
		// bodyBytes is flattened in the schema and expanded back into ARM's
		// one-field body block on the way out.
		require.Equal(t, int32(512), *p.Frontend.Request.Body.Bytes)
		require.Equal(t, []*string{to.Ptr("x-formae-conformance")}, p.Frontend.Request.Headers)
		// Never sent: the service owns it.
		require.Nil(t, p.Frontend.Request.DataMasking)
		require.Nil(t, p.Backend)
	})

	t.Run("Create_leaves_every_unset_enum_nil_so_ARM_defaults_it", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "applicationinsights", "resourceGroupName": "rg-1", "serviceName": "apim1",
			"loggerId": testApimLoggerNativeID,
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		p := sentCreate.Properties
		require.Nil(t, p.AlwaysLog)
		require.Nil(t, p.HTTPCorrelationProtocol)
		require.Nil(t, p.OperationNameFormat)
		require.Nil(t, p.Verbosity)
		require.Nil(t, p.Sampling)
		require.Nil(t, p.Frontend)
	})

	t.Run("Create_requires_a_logger", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "applicationinsights", "resourceGroupName": "rg-1", "serviceName": "apim1",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "loggerId is required")
	})

	t.Run("Read_drops_the_service_populated_data_masking", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testApimDiagnosticNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "applicationinsights", props["name"])
		require.Equal(t, testApimLoggerNativeID, props["loggerId"])
		require.Equal(t, "W3C", props["httpCorrelationProtocol"])
		require.Equal(t, map[string]any{"samplingType": "fixed", "percentage": 100.0}, props["sampling"])

		frontend := props["frontend"].(map[string]any)
		request := frontend["request"].(map[string]any)
		require.Equal(t, []any{"x-formae-conformance"}, request["headers"])
		require.Equal(t, 512.0, request["bodyBytes"])
		require.NotContains(t, request, "dataMasking")
		// ARM returned no backend block, so none is reported.
		require.NotContains(t, props, "backend")
	})

	t.Run("Update_uses_the_same_contract_as_create_with_wildcard_if_match", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testApimDiagnosticNativeID,
			DesiredProperties: apimDiagnosticDesired("verbose"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, "*", sawIfMatch)
		require.Equal(t, armapimanagement.VerbosityVerbose, *sentUpdate.Properties.Verbosity)
	})

	t.Run("Delete_is_synchronous", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testApimDiagnosticNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
		require.Equal(t, "*", sawIfMatch)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _, _, _ string, _ *armapimanagement.DiagnosticClientDeleteOptions) (armapimanagement.DiagnosticClientDeleteResponse, error) {
			return armapimanagement.DiagnosticClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testApimDiagnosticNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_service", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "serviceName": "apim1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testApimDiagnosticNativeID}, got.NativeIDs)
	})

	t.Run("List_without_parents_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure_with_a_reason", func(t *testing.T) {
		fake.createOrUpdateFn = func(_ context.Context, _, _, _ string, _ armapimanagement.DiagnosticContract, _ *armapimanagement.DiagnosticClientCreateOrUpdateOptions) (armapimanagement.DiagnosticClientCreateOrUpdateResponse, error) {
			return armapimanagement.DiagnosticClientCreateOrUpdateResponse{}, &azcore.ResponseError{StatusCode: 400}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "applicationinsights", Properties: apimDiagnosticDesired("information"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.NotEmpty(t, got.ProgressResult.StatusMessage)
	})
}

func TestApiManagementDiagnostic_ReadNotFound(t *testing.T) {
	fake := &fakeApiManagementDiagnosticsAPI{
		getFn: func(_ context.Context, _, _, _ string, _ *armapimanagement.DiagnosticClientGetOptions) (armapimanagement.DiagnosticClientGetResponse, error) {
			return armapimanagement.DiagnosticClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestApiManagementDiagnostic(fake).Read(context.Background(),
		&resource.ReadRequest{NativeID: testApimDiagnosticNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// ARM is inconsistent about the casing it echoes for these enums, and a false
// drift on "w3c" vs "W3C" is indistinguishable from a real one.
func TestApimDiagnosticReadPropsCanonicalizesEnums(t *testing.T) {
	props := map[string]any{}
	apimDiagnosticReadProps(props, &armapimanagement.DiagnosticContractProperties{
		HTTPCorrelationProtocol: to.Ptr(armapimanagement.HTTPCorrelationProtocol("w3c")),
		OperationNameFormat:     to.Ptr(armapimanagement.OperationNameFormat("url")),
		Verbosity:               to.Ptr(armapimanagement.Verbosity("Information")),
	})
	require.Equal(t, "W3C", props["httpCorrelationProtocol"])
	require.Equal(t, "Url", props["operationNameFormat"])
	require.Equal(t, "information", props["verbosity"])
}

// --- Test helpers ---

type fakeApiManagementDiagnosticsAPI struct {
	createOrUpdateFn        func(ctx context.Context, rgName, serviceName, diagnosticID string, params armapimanagement.DiagnosticContract, options *armapimanagement.DiagnosticClientCreateOrUpdateOptions) (armapimanagement.DiagnosticClientCreateOrUpdateResponse, error)
	getFn                   func(ctx context.Context, rgName, serviceName, diagnosticID string, options *armapimanagement.DiagnosticClientGetOptions) (armapimanagement.DiagnosticClientGetResponse, error)
	updateFn                func(ctx context.Context, rgName, serviceName, diagnosticID, ifMatch string, params armapimanagement.DiagnosticContract, options *armapimanagement.DiagnosticClientUpdateOptions) (armapimanagement.DiagnosticClientUpdateResponse, error)
	deleteFn                func(ctx context.Context, rgName, serviceName, diagnosticID, ifMatch string, options *armapimanagement.DiagnosticClientDeleteOptions) (armapimanagement.DiagnosticClientDeleteResponse, error)
	newListByServicePagerFn func(rgName, serviceName string, options *armapimanagement.DiagnosticClientListByServiceOptions) *runtime.Pager[armapimanagement.DiagnosticClientListByServiceResponse]
}

func (f *fakeApiManagementDiagnosticsAPI) CreateOrUpdate(ctx context.Context, rgName, serviceName, diagnosticID string, params armapimanagement.DiagnosticContract, options *armapimanagement.DiagnosticClientCreateOrUpdateOptions) (armapimanagement.DiagnosticClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, serviceName, diagnosticID, params, options)
}

func (f *fakeApiManagementDiagnosticsAPI) Get(ctx context.Context, rgName, serviceName, diagnosticID string, options *armapimanagement.DiagnosticClientGetOptions) (armapimanagement.DiagnosticClientGetResponse, error) {
	return f.getFn(ctx, rgName, serviceName, diagnosticID, options)
}

func (f *fakeApiManagementDiagnosticsAPI) Update(ctx context.Context, rgName, serviceName, diagnosticID, ifMatch string, params armapimanagement.DiagnosticContract, options *armapimanagement.DiagnosticClientUpdateOptions) (armapimanagement.DiagnosticClientUpdateResponse, error) {
	return f.updateFn(ctx, rgName, serviceName, diagnosticID, ifMatch, params, options)
}

func (f *fakeApiManagementDiagnosticsAPI) Delete(ctx context.Context, rgName, serviceName, diagnosticID, ifMatch string, options *armapimanagement.DiagnosticClientDeleteOptions) (armapimanagement.DiagnosticClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, serviceName, diagnosticID, ifMatch, options)
}

func (f *fakeApiManagementDiagnosticsAPI) NewListByServicePager(rgName, serviceName string, options *armapimanagement.DiagnosticClientListByServiceOptions) *runtime.Pager[armapimanagement.DiagnosticClientListByServiceResponse] {
	return f.newListByServicePagerFn(rgName, serviceName, options)
}
