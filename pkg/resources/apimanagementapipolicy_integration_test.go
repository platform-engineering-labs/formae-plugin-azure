// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/apimanagement/armapimanagement"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testApimApiPolicyNativeID = testApimApiNativeID + "/policies/policy"

func newTestApiManagementApiPolicy(api apiManagementAPIPoliciesAPI) *ApiManagementApiPolicy {
	return &ApiManagementApiPolicy{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func apimApiPolicyDesired(value string) []byte {
	out, _ := json.Marshal(map[string]any{
		"resourceGroupName": "rg-1",
		"serviceName":       "apim1",
		"apiName":           "api1",
		"value":             value,
		"format":            "xml",
	})
	return out
}

func TestApiManagementApiPolicy_CRUD(t *testing.T) {
	policyResult := armapimanagement.PolicyContract{
		ID:   to.Ptr(testApimApiPolicyNativeID),
		Name: to.Ptr("policy"),
		Properties: &armapimanagement.PolicyContractProperties{
			Value:  to.Ptr(testApimPolicyReserialized),
			Format: to.Ptr(armapimanagement.PolicyContentFormatXML),
		},
	}

	var sentBody armapimanagement.PolicyContract
	var sawAPI string
	var sawPolicyID armapimanagement.PolicyIDName
	var sawIfMatch string
	createCalls := 0
	deleteCalls := 0
	fake := &fakeApiManagementAPIPoliciesAPI{
		createOrUpdateFn: func(_ context.Context, _, _, apiID string, policyID armapimanagement.PolicyIDName, params armapimanagement.PolicyContract, _ *armapimanagement.APIPolicyClientCreateOrUpdateOptions) (armapimanagement.APIPolicyClientCreateOrUpdateResponse, error) {
			sawAPI = apiID
			sawPolicyID = policyID
			sentBody = params
			createCalls++
			return armapimanagement.APIPolicyClientCreateOrUpdateResponse{PolicyContract: policyResult}, nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ armapimanagement.PolicyIDName, _ *armapimanagement.APIPolicyClientGetOptions) (armapimanagement.APIPolicyClientGetResponse, error) {
			return armapimanagement.APIPolicyClientGetResponse{PolicyContract: policyResult}, nil
		},
		deleteFn: func(_ context.Context, _, _, _ string, _ armapimanagement.PolicyIDName, ifMatch string, _ *armapimanagement.APIPolicyClientDeleteOptions) (armapimanagement.APIPolicyClientDeleteResponse, error) {
			sawIfMatch = ifMatch
			deleteCalls++
			return armapimanagement.APIPolicyClientDeleteResponse{}, nil
		},
		listByAPIFn: func(_ context.Context, _, _, _ string, _ *armapimanagement.APIPolicyClientListByAPIOptions) (armapimanagement.APIPolicyClientListByAPIResponse, error) {
			return armapimanagement.APIPolicyClientListByAPIResponse{
				PolicyCollection: armapimanagement.PolicyCollection{
					Value: []*armapimanagement.PolicyContract{{ID: to.Ptr(testApimApiPolicyNativeID)}},
				},
			}, nil
		},
	}
	prov := newTestApiManagementApiPolicy(fake)

	t.Run("Create_is_synchronous", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Properties: apimApiPolicyDesired(testApimPolicyDeclared),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testApimApiPolicyNativeID, got.ProgressResult.NativeID)
		require.Empty(t, got.ProgressResult.RequestID)

		require.Equal(t, "api1", sawAPI)
		require.Equal(t, armapimanagement.PolicyIDNamePolicy, sawPolicyID)
		require.Equal(t, testApimPolicyDeclared, *sentBody.Properties.Value)

		// The read-back is the caller's own document, not ARM's rendering.
		var props map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &props))
		require.Equal(t, testApimPolicyDeclared, props["value"])
		require.Equal(t, "api1", props["apiName"])
	})

	t.Run("Create_requires_api", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName": "rg-1", "serviceName": "apim1", "value": "<policies />",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "apiName is required")
	})

	t.Run("Create_requires_value", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName": "rg-1", "serviceName": "apim1", "apiName": "api1",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "value is required")
	})

	t.Run("Read_echoes_the_declared_document", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{
			NativeID:        testApimApiPolicyNativeID,
			PriorProperties: apimApiPolicyDesired(testApimPolicyDeclared),
		})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		// All three scope values come from the native ID.
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "apim1", props["serviceName"])
		require.Equal(t, "api1", props["apiName"])
		require.Equal(t, testApimPolicyDeclared, props["value"])
	})

	t.Run("Read_reports_a_genuine_change", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{
			NativeID:        testApimApiPolicyNativeID,
			PriorProperties: apimApiPolicyDesired(`<policies><inbound><base /></inbound></policies>`),
		})
		require.NoError(t, err)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, testApimPolicyReserialized, props["value"])
	})

	t.Run("Update_reissues_create_or_update", func(t *testing.T) {
		before := createCalls
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testApimApiPolicyNativeID,
			DesiredProperties: apimApiPolicyDesired(`<policies><inbound><base /></inbound></policies>`),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, createCalls)

		var props map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &props))
		require.Equal(t, `<policies><inbound><base /></inbound></policies>`, props["value"])
	})

	t.Run("Delete_is_synchronous", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testApimApiPolicyNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
		require.Equal(t, "*", sawIfMatch)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _, _ string, _ armapimanagement.PolicyIDName, _ string, _ *armapimanagement.APIPolicyClientDeleteOptions) (armapimanagement.APIPolicyClientDeleteResponse, error) {
			return armapimanagement.APIPolicyClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testApimApiPolicyNativeID})
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
		require.Equal(t, []string{testApimApiPolicyNativeID}, got.NativeIDs)
	})

	t.Run("List_without_parents_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "serviceName": "apim1"},
		})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure_with_a_reason", func(t *testing.T) {
		fake.createOrUpdateFn = func(_ context.Context, _, _, _ string, _ armapimanagement.PolicyIDName, _ armapimanagement.PolicyContract, _ *armapimanagement.APIPolicyClientCreateOrUpdateOptions) (armapimanagement.APIPolicyClientCreateOrUpdateResponse, error) {
			return armapimanagement.APIPolicyClientCreateOrUpdateResponse{}, &azcore.ResponseError{StatusCode: 400}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Properties: apimApiPolicyDesired(testApimPolicyDeclared),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.NotEmpty(t, got.ProgressResult.StatusMessage)
	})
}

func TestApiManagementApiPolicy_ReadNotFound(t *testing.T) {
	fake := &fakeApiManagementAPIPoliciesAPI{
		getFn: func(_ context.Context, _, _, _ string, _ armapimanagement.PolicyIDName, _ *armapimanagement.APIPolicyClientGetOptions) (armapimanagement.APIPolicyClientGetResponse, error) {
			return armapimanagement.APIPolicyClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestApiManagementApiPolicy(fake).Read(context.Background(),
		&resource.ReadRequest{NativeID: testApimApiPolicyNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeApiManagementAPIPoliciesAPI struct {
	createOrUpdateFn func(ctx context.Context, rgName, serviceName, apiID string, policyID armapimanagement.PolicyIDName, params armapimanagement.PolicyContract, options *armapimanagement.APIPolicyClientCreateOrUpdateOptions) (armapimanagement.APIPolicyClientCreateOrUpdateResponse, error)
	getFn            func(ctx context.Context, rgName, serviceName, apiID string, policyID armapimanagement.PolicyIDName, options *armapimanagement.APIPolicyClientGetOptions) (armapimanagement.APIPolicyClientGetResponse, error)
	deleteFn         func(ctx context.Context, rgName, serviceName, apiID string, policyID armapimanagement.PolicyIDName, ifMatch string, options *armapimanagement.APIPolicyClientDeleteOptions) (armapimanagement.APIPolicyClientDeleteResponse, error)
	listByAPIFn      func(ctx context.Context, rgName, serviceName, apiID string, options *armapimanagement.APIPolicyClientListByAPIOptions) (armapimanagement.APIPolicyClientListByAPIResponse, error)
}

func (f *fakeApiManagementAPIPoliciesAPI) CreateOrUpdate(ctx context.Context, rgName, serviceName, apiID string, policyID armapimanagement.PolicyIDName, params armapimanagement.PolicyContract, options *armapimanagement.APIPolicyClientCreateOrUpdateOptions) (armapimanagement.APIPolicyClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, serviceName, apiID, policyID, params, options)
}

func (f *fakeApiManagementAPIPoliciesAPI) Get(ctx context.Context, rgName, serviceName, apiID string, policyID armapimanagement.PolicyIDName, options *armapimanagement.APIPolicyClientGetOptions) (armapimanagement.APIPolicyClientGetResponse, error) {
	return f.getFn(ctx, rgName, serviceName, apiID, policyID, options)
}

func (f *fakeApiManagementAPIPoliciesAPI) Delete(ctx context.Context, rgName, serviceName, apiID string, policyID armapimanagement.PolicyIDName, ifMatch string, options *armapimanagement.APIPolicyClientDeleteOptions) (armapimanagement.APIPolicyClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, serviceName, apiID, policyID, ifMatch, options)
}

func (f *fakeApiManagementAPIPoliciesAPI) ListByAPI(ctx context.Context, rgName, serviceName, apiID string, options *armapimanagement.APIPolicyClientListByAPIOptions) (armapimanagement.APIPolicyClientListByAPIResponse, error) {
	return f.listByAPIFn(ctx, rgName, serviceName, apiID, options)
}
