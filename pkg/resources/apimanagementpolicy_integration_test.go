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

const testApimPolicyNativeID = testApimServiceNativeID + "/policies/policy"

func newTestApiManagementPolicy(api apiManagementPoliciesAPI) *ApiManagementPolicy {
	return &ApiManagementPolicy{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func apimPolicyDesired(value string) []byte {
	out, _ := json.Marshal(map[string]any{
		"resourceGroupName": "rg-1",
		"serviceName":       "apim1",
		"value":             value,
		"format":            "xml",
	})
	return out
}

func TestApiManagementPolicy_CRUD(t *testing.T) {
	// ARM answers with its own re-serialization of whatever was submitted.
	policyResult := armapimanagement.PolicyContract{
		ID:   to.Ptr(testApimPolicyNativeID),
		Name: to.Ptr("policy"),
		Properties: &armapimanagement.PolicyContractProperties{
			Value:  to.Ptr(testApimPolicyReserialized),
			Format: to.Ptr(armapimanagement.PolicyContentFormatXML),
		},
	}

	var sentBody armapimanagement.PolicyContract
	var sawPolicyID armapimanagement.PolicyIDName
	var sawIfMatch string
	createCalls := 0
	deleteCalls := 0
	fake := &fakeApiManagementPoliciesAPI{
		createOrUpdateFn: func(_ context.Context, _, serviceName string, policyID armapimanagement.PolicyIDName, params armapimanagement.PolicyContract, _ *armapimanagement.PolicyClientCreateOrUpdateOptions) (armapimanagement.PolicyClientCreateOrUpdateResponse, error) {
			require.Equal(t, "apim1", serviceName)
			sawPolicyID = policyID
			sentBody = params
			createCalls++
			return armapimanagement.PolicyClientCreateOrUpdateResponse{PolicyContract: policyResult}, nil
		},
		getFn: func(_ context.Context, _, _ string, _ armapimanagement.PolicyIDName, _ *armapimanagement.PolicyClientGetOptions) (armapimanagement.PolicyClientGetResponse, error) {
			return armapimanagement.PolicyClientGetResponse{PolicyContract: policyResult}, nil
		},
		deleteFn: func(_ context.Context, _, _ string, _ armapimanagement.PolicyIDName, ifMatch string, _ *armapimanagement.PolicyClientDeleteOptions) (armapimanagement.PolicyClientDeleteResponse, error) {
			sawIfMatch = ifMatch
			deleteCalls++
			return armapimanagement.PolicyClientDeleteResponse{}, nil
		},
		listByServiceFn: func(_ context.Context, _, _ string, _ *armapimanagement.PolicyClientListByServiceOptions) (armapimanagement.PolicyClientListByServiceResponse, error) {
			return armapimanagement.PolicyClientListByServiceResponse{
				PolicyCollection: armapimanagement.PolicyCollection{
					Value: []*armapimanagement.PolicyContract{{ID: to.Ptr(testApimPolicyNativeID)}},
				},
			}, nil
		},
	}
	prov := newTestApiManagementPolicy(fake)

	t.Run("Create_is_synchronous", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Properties: apimPolicyDesired(testApimPolicyDeclared),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testApimPolicyNativeID, got.ProgressResult.NativeID)
		require.Empty(t, got.ProgressResult.RequestID)

		// A policy is a singleton child whose ARM name is always "policy".
		require.Equal(t, armapimanagement.PolicyIDNamePolicy, sawPolicyID)
		require.Equal(t, testApimPolicyDeclared, *sentBody.Properties.Value)
	})

	// The read-back after a create must be the caller's own document, not
	// ARM's re-serialization of it, or the very next sync reports drift.
	t.Run("Create_reports_the_declared_document", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Properties: apimPolicyDesired(testApimPolicyDeclared),
		})
		require.NoError(t, err)

		var props map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &props))
		require.Equal(t, testApimPolicyDeclared, props["value"])
		require.Equal(t, "xml", props["format"])
		require.Equal(t, testApimPolicyNativeID, props["id"])
	})

	t.Run("Create_requires_value", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"resourceGroupName": "rg-1", "serviceName": "apim1"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "value is required")
	})

	t.Run("Create_requires_service", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"resourceGroupName": "rg-1", "value": "<policies />"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "serviceName is required")
	})

	// The whole point of the shared body helper: ARM's rendering differs
	// textually from what was declared, and reporting it would show drift on
	// every sync.
	t.Run("Read_echoes_the_declared_document", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{
			NativeID:        testApimPolicyNativeID,
			PriorProperties: apimPolicyDesired(testApimPolicyDeclared),
		})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "apim1", props["serviceName"])
		require.Equal(t, testApimPolicyDeclared, props["value"])
	})

	// An out-of-band edit in the portal is real drift and must be reported.
	t.Run("Read_reports_a_genuine_change", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{
			NativeID:        testApimPolicyNativeID,
			PriorProperties: apimPolicyDesired(`<policies><inbound><base /></inbound></policies>`),
		})
		require.NoError(t, err)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, testApimPolicyReserialized, props["value"])
	})

	// Discovery has no prior state, so ARM's document is all there is.
	t.Run("Read_without_prior_state_reports_arm", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testApimPolicyNativeID})
		require.NoError(t, err)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, testApimPolicyReserialized, props["value"])
	})

	t.Run("Update_reissues_create_or_update", func(t *testing.T) {
		before := createCalls
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testApimPolicyNativeID,
			DesiredProperties: apimPolicyDesired(`<policies><inbound><base /></inbound></policies>`),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Empty(t, got.ProgressResult.RequestID)
		// There is no PATCH verb for a policy.
		require.Equal(t, before+1, createCalls)

		var props map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &props))
		require.Equal(t, `<policies><inbound><base /></inbound></policies>`, props["value"])
		// The scope comes from the native ID even though the desired document
		// also carries it.
		require.Equal(t, "apim1", props["serviceName"])
	})

	t.Run("Update_requires_value", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"resourceGroupName": "rg-1", "serviceName": "apim1"})
		_, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID: testApimPolicyNativeID, DesiredProperties: props,
		})
		require.ErrorContains(t, err, "value is required")
	})

	t.Run("Delete_is_synchronous", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testApimPolicyNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
		require.Equal(t, "*", sawIfMatch)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _ string, _ armapimanagement.PolicyIDName, _ string, _ *armapimanagement.PolicyClientDeleteOptions) (armapimanagement.PolicyClientDeleteResponse, error) {
			return armapimanagement.PolicyClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testApimPolicyNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	// ARM answers with a collection rather than a pager: there is at most one
	// service policy.
	t.Run("List_by_service", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "serviceName": "apim1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testApimPolicyNativeID}, got.NativeIDs)
	})

	t.Run("List_without_parents_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure_with_a_reason", func(t *testing.T) {
		fake.createOrUpdateFn = func(_ context.Context, _, _ string, _ armapimanagement.PolicyIDName, _ armapimanagement.PolicyContract, _ *armapimanagement.PolicyClientCreateOrUpdateOptions) (armapimanagement.PolicyClientCreateOrUpdateResponse, error) {
			return armapimanagement.PolicyClientCreateOrUpdateResponse{}, &azcore.ResponseError{StatusCode: 400}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Properties: apimPolicyDesired(testApimPolicyDeclared),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.Equal(t, resource.OperationErrorCodeInvalidRequest, got.ProgressResult.ErrorCode)
		require.NotEmpty(t, got.ProgressResult.StatusMessage)
	})
}

func TestApiManagementPolicy_ReadNotFound(t *testing.T) {
	fake := &fakeApiManagementPoliciesAPI{
		getFn: func(_ context.Context, _, _ string, _ armapimanagement.PolicyIDName, _ *armapimanagement.PolicyClientGetOptions) (armapimanagement.PolicyClientGetResponse, error) {
			return armapimanagement.PolicyClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestApiManagementPolicy(fake).Read(context.Background(),
		&resource.ReadRequest{NativeID: testApimPolicyNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// The four policy scopes differ only in the length of their type chain, so
// each parser has to reject the others' IDs.
func TestApiManagementPolicy_ScopesDoNotOverlap(t *testing.T) {
	apiPolicyID := testApimApiNativeID + "/policies/policy"
	operationPolicyID := testApimApiOperationNativeID + "/policies/policy"

	_, _, err := apiManagementPolicyIDParts(apiPolicyID)
	require.Error(t, err)
	_, _, _, err = apiManagementApiPolicyIDParts(testApimPolicyNativeID)
	require.Error(t, err)
	_, _, _, err = apiManagementApiPolicyIDParts(operationPolicyID)
	require.Error(t, err)
	_, _, _, _, err = apiManagementApiOperationPolicyIDParts(apiPolicyID)
	require.Error(t, err)

	rg, svc, err := apiManagementPolicyIDParts(testApimPolicyNativeID)
	require.NoError(t, err)
	require.Equal(t, "rg-1", rg)
	require.Equal(t, "apim1", svc)
}

// --- Test helpers ---

type fakeApiManagementPoliciesAPI struct {
	createOrUpdateFn func(ctx context.Context, rgName, serviceName string, policyID armapimanagement.PolicyIDName, params armapimanagement.PolicyContract, options *armapimanagement.PolicyClientCreateOrUpdateOptions) (armapimanagement.PolicyClientCreateOrUpdateResponse, error)
	getFn            func(ctx context.Context, rgName, serviceName string, policyID armapimanagement.PolicyIDName, options *armapimanagement.PolicyClientGetOptions) (armapimanagement.PolicyClientGetResponse, error)
	deleteFn         func(ctx context.Context, rgName, serviceName string, policyID armapimanagement.PolicyIDName, ifMatch string, options *armapimanagement.PolicyClientDeleteOptions) (armapimanagement.PolicyClientDeleteResponse, error)
	listByServiceFn  func(ctx context.Context, rgName, serviceName string, options *armapimanagement.PolicyClientListByServiceOptions) (armapimanagement.PolicyClientListByServiceResponse, error)
}

func (f *fakeApiManagementPoliciesAPI) CreateOrUpdate(ctx context.Context, rgName, serviceName string, policyID armapimanagement.PolicyIDName, params armapimanagement.PolicyContract, options *armapimanagement.PolicyClientCreateOrUpdateOptions) (armapimanagement.PolicyClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, serviceName, policyID, params, options)
}

func (f *fakeApiManagementPoliciesAPI) Get(ctx context.Context, rgName, serviceName string, policyID armapimanagement.PolicyIDName, options *armapimanagement.PolicyClientGetOptions) (armapimanagement.PolicyClientGetResponse, error) {
	return f.getFn(ctx, rgName, serviceName, policyID, options)
}

func (f *fakeApiManagementPoliciesAPI) Delete(ctx context.Context, rgName, serviceName string, policyID armapimanagement.PolicyIDName, ifMatch string, options *armapimanagement.PolicyClientDeleteOptions) (armapimanagement.PolicyClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, serviceName, policyID, ifMatch, options)
}

func (f *fakeApiManagementPoliciesAPI) ListByService(ctx context.Context, rgName, serviceName string, options *armapimanagement.PolicyClientListByServiceOptions) (armapimanagement.PolicyClientListByServiceResponse, error) {
	return f.listByServiceFn(ctx, rgName, serviceName, options)
}
