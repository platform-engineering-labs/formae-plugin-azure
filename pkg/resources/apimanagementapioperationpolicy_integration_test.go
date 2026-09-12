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

const testApimApiOperationPolicyNativeID = testApimApiOperationNativeID + "/policies/policy"

func newTestApiManagementApiOperationPolicy(api apiManagementAPIOperationPoliciesAPI) *ApiManagementApiOperationPolicy {
	return &ApiManagementApiOperationPolicy{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func apimApiOperationPolicyDesired(value string) []byte {
	out, _ := json.Marshal(map[string]any{
		"resourceGroupName": "rg-1",
		"serviceName":       "apim1",
		"apiName":           "api1",
		"operationName":     "get-status",
		"value":             value,
		"format":            "xml",
	})
	return out
}

func TestApiManagementApiOperationPolicy_CRUD(t *testing.T) {
	policyResult := armapimanagement.PolicyContract{
		ID:   to.Ptr(testApimApiOperationPolicyNativeID),
		Name: to.Ptr("policy"),
		Properties: &armapimanagement.PolicyContractProperties{
			Value:  to.Ptr(testApimPolicyReserialized),
			Format: to.Ptr(armapimanagement.PolicyContentFormatXML),
		},
	}

	var sentBody armapimanagement.PolicyContract
	var sawAPI, sawOperation, sawIfMatch string
	createCalls := 0
	deleteCalls := 0
	fake := &fakeApiManagementAPIOperationPoliciesAPI{
		createOrUpdateFn: func(_ context.Context, _, _, apiID, operationID string, _ armapimanagement.PolicyIDName, params armapimanagement.PolicyContract, _ *armapimanagement.APIOperationPolicyClientCreateOrUpdateOptions) (armapimanagement.APIOperationPolicyClientCreateOrUpdateResponse, error) {
			sawAPI, sawOperation = apiID, operationID
			sentBody = params
			createCalls++
			return armapimanagement.APIOperationPolicyClientCreateOrUpdateResponse{PolicyContract: policyResult}, nil
		},
		getFn: func(_ context.Context, _, _, _, _ string, _ armapimanagement.PolicyIDName, _ *armapimanagement.APIOperationPolicyClientGetOptions) (armapimanagement.APIOperationPolicyClientGetResponse, error) {
			return armapimanagement.APIOperationPolicyClientGetResponse{PolicyContract: policyResult}, nil
		},
		deleteFn: func(_ context.Context, _, _, _, _ string, _ armapimanagement.PolicyIDName, ifMatch string, _ *armapimanagement.APIOperationPolicyClientDeleteOptions) (armapimanagement.APIOperationPolicyClientDeleteResponse, error) {
			sawIfMatch = ifMatch
			deleteCalls++
			return armapimanagement.APIOperationPolicyClientDeleteResponse{}, nil
		},
		listByOperationFn: func(_ context.Context, _, _, _, _ string, _ *armapimanagement.APIOperationPolicyClientListByOperationOptions) (armapimanagement.APIOperationPolicyClientListByOperationResponse, error) {
			return armapimanagement.APIOperationPolicyClientListByOperationResponse{
				PolicyCollection: armapimanagement.PolicyCollection{
					Value: []*armapimanagement.PolicyContract{{ID: to.Ptr(testApimApiOperationPolicyNativeID)}},
				},
			}, nil
		},
	}
	prov := newTestApiManagementApiOperationPolicy(fake)

	t.Run("Create_is_synchronous", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Properties: apimApiOperationPolicyDesired(testApimPolicyDeclared),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testApimApiOperationPolicyNativeID, got.ProgressResult.NativeID)
		require.Empty(t, got.ProgressResult.RequestID)

		require.Equal(t, "api1", sawAPI)
		require.Equal(t, "get-status", sawOperation)
		require.Equal(t, testApimPolicyDeclared, *sentBody.Properties.Value)

		var props map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &props))
		require.Equal(t, testApimPolicyDeclared, props["value"])
		require.Equal(t, "get-status", props["operationName"])
	})

	t.Run("Create_requires_operation", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName": "rg-1", "serviceName": "apim1", "apiName": "api1", "value": "<policies />",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "operationName is required")
	})

	t.Run("Create_requires_value", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName": "rg-1", "serviceName": "apim1",
			"apiName": "api1", "operationName": "get-status",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "value is required")
	})

	t.Run("Read_echoes_the_declared_document", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{
			NativeID:        testApimApiOperationPolicyNativeID,
			PriorProperties: apimApiOperationPolicyDesired(testApimPolicyDeclared),
		})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		// All four scope values come from the native ID.
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "apim1", props["serviceName"])
		require.Equal(t, "api1", props["apiName"])
		require.Equal(t, "get-status", props["operationName"])
		require.Equal(t, testApimPolicyDeclared, props["value"])
	})

	t.Run("Read_reports_a_genuine_change", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{
			NativeID:        testApimApiOperationPolicyNativeID,
			PriorProperties: apimApiOperationPolicyDesired(`<policies><inbound><base /></inbound></policies>`),
		})
		require.NoError(t, err)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, testApimPolicyReserialized, props["value"])
	})

	t.Run("Update_reissues_create_or_update", func(t *testing.T) {
		before := createCalls
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testApimApiOperationPolicyNativeID,
			DesiredProperties: apimApiOperationPolicyDesired(`<policies><inbound><base /></inbound></policies>`),
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
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testApimApiOperationPolicyNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
		require.Equal(t, "*", sawIfMatch)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _, _, _ string, _ armapimanagement.PolicyIDName, _ string, _ *armapimanagement.APIOperationPolicyClientDeleteOptions) (armapimanagement.APIOperationPolicyClientDeleteResponse, error) {
			return armapimanagement.APIOperationPolicyClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testApimApiOperationPolicyNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_operation", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{
				"resourceGroupName": "rg-1", "serviceName": "apim1",
				"apiName": "api1", "operationName": "get-status",
			},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testApimApiOperationPolicyNativeID}, got.NativeIDs)
	})

	t.Run("List_without_the_operation_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{
				"resourceGroupName": "rg-1", "serviceName": "apim1", "apiName": "api1",
			},
		})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure_with_a_reason", func(t *testing.T) {
		fake.createOrUpdateFn = func(_ context.Context, _, _, _, _ string, _ armapimanagement.PolicyIDName, _ armapimanagement.PolicyContract, _ *armapimanagement.APIOperationPolicyClientCreateOrUpdateOptions) (armapimanagement.APIOperationPolicyClientCreateOrUpdateResponse, error) {
			return armapimanagement.APIOperationPolicyClientCreateOrUpdateResponse{}, &azcore.ResponseError{StatusCode: 400}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Properties: apimApiOperationPolicyDesired(testApimPolicyDeclared),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.NotEmpty(t, got.ProgressResult.StatusMessage)
	})
}

func TestApiManagementApiOperationPolicy_ReadNotFound(t *testing.T) {
	fake := &fakeApiManagementAPIOperationPoliciesAPI{
		getFn: func(_ context.Context, _, _, _, _ string, _ armapimanagement.PolicyIDName, _ *armapimanagement.APIOperationPolicyClientGetOptions) (armapimanagement.APIOperationPolicyClientGetResponse, error) {
			return armapimanagement.APIOperationPolicyClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestApiManagementApiOperationPolicy(fake).Read(context.Background(),
		&resource.ReadRequest{NativeID: testApimApiOperationPolicyNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeApiManagementAPIOperationPoliciesAPI struct {
	createOrUpdateFn  func(ctx context.Context, rgName, serviceName, apiID, operationID string, policyID armapimanagement.PolicyIDName, params armapimanagement.PolicyContract, options *armapimanagement.APIOperationPolicyClientCreateOrUpdateOptions) (armapimanagement.APIOperationPolicyClientCreateOrUpdateResponse, error)
	getFn             func(ctx context.Context, rgName, serviceName, apiID, operationID string, policyID armapimanagement.PolicyIDName, options *armapimanagement.APIOperationPolicyClientGetOptions) (armapimanagement.APIOperationPolicyClientGetResponse, error)
	deleteFn          func(ctx context.Context, rgName, serviceName, apiID, operationID string, policyID armapimanagement.PolicyIDName, ifMatch string, options *armapimanagement.APIOperationPolicyClientDeleteOptions) (armapimanagement.APIOperationPolicyClientDeleteResponse, error)
	listByOperationFn func(ctx context.Context, rgName, serviceName, apiID, operationID string, options *armapimanagement.APIOperationPolicyClientListByOperationOptions) (armapimanagement.APIOperationPolicyClientListByOperationResponse, error)
}

func (f *fakeApiManagementAPIOperationPoliciesAPI) CreateOrUpdate(ctx context.Context, rgName, serviceName, apiID, operationID string, policyID armapimanagement.PolicyIDName, params armapimanagement.PolicyContract, options *armapimanagement.APIOperationPolicyClientCreateOrUpdateOptions) (armapimanagement.APIOperationPolicyClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, serviceName, apiID, operationID, policyID, params, options)
}

func (f *fakeApiManagementAPIOperationPoliciesAPI) Get(ctx context.Context, rgName, serviceName, apiID, operationID string, policyID armapimanagement.PolicyIDName, options *armapimanagement.APIOperationPolicyClientGetOptions) (armapimanagement.APIOperationPolicyClientGetResponse, error) {
	return f.getFn(ctx, rgName, serviceName, apiID, operationID, policyID, options)
}

func (f *fakeApiManagementAPIOperationPoliciesAPI) Delete(ctx context.Context, rgName, serviceName, apiID, operationID string, policyID armapimanagement.PolicyIDName, ifMatch string, options *armapimanagement.APIOperationPolicyClientDeleteOptions) (armapimanagement.APIOperationPolicyClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, serviceName, apiID, operationID, policyID, ifMatch, options)
}

func (f *fakeApiManagementAPIOperationPoliciesAPI) ListByOperation(ctx context.Context, rgName, serviceName, apiID, operationID string, options *armapimanagement.APIOperationPolicyClientListByOperationOptions) (armapimanagement.APIOperationPolicyClientListByOperationResponse, error) {
	return f.listByOperationFn(ctx, rgName, serviceName, apiID, operationID, options)
}
