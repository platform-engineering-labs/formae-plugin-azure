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

const testApimProductPolicyNativeID = testApimProductNativeID + "/policies/policy"

func newTestApiManagementProductPolicy(api apiManagementProductPoliciesAPI) *ApiManagementProductPolicy {
	return &ApiManagementProductPolicy{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func apimProductPolicyDesired(value string) []byte {
	out, _ := json.Marshal(map[string]any{
		"resourceGroupName": "rg-1",
		"serviceName":       "apim1",
		"productName":       "starter",
		"value":             value,
		"format":            "xml",
	})
	return out
}

func TestApiManagementProductPolicy_CRUD(t *testing.T) {
	policyResult := armapimanagement.PolicyContract{
		ID:   to.Ptr(testApimProductPolicyNativeID),
		Name: to.Ptr("policy"),
		Properties: &armapimanagement.PolicyContractProperties{
			Value:  to.Ptr(testApimPolicyReserialized),
			Format: to.Ptr(armapimanagement.PolicyContentFormatXML),
		},
	}

	var sentBody armapimanagement.PolicyContract
	var sawProduct string
	var sawPolicyID armapimanagement.PolicyIDName
	var sawIfMatch string
	createCalls := 0
	deleteCalls := 0
	fake := &fakeApiManagementProductPoliciesAPI{
		createOrUpdateFn: func(_ context.Context, _, _, productID string, policyID armapimanagement.PolicyIDName, params armapimanagement.PolicyContract, _ *armapimanagement.ProductPolicyClientCreateOrUpdateOptions) (armapimanagement.ProductPolicyClientCreateOrUpdateResponse, error) {
			sawProduct = productID
			sawPolicyID = policyID
			sentBody = params
			createCalls++
			return armapimanagement.ProductPolicyClientCreateOrUpdateResponse{PolicyContract: policyResult}, nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ armapimanagement.PolicyIDName, _ *armapimanagement.ProductPolicyClientGetOptions) (armapimanagement.ProductPolicyClientGetResponse, error) {
			return armapimanagement.ProductPolicyClientGetResponse{PolicyContract: policyResult}, nil
		},
		deleteFn: func(_ context.Context, _, _, _ string, _ armapimanagement.PolicyIDName, ifMatch string, _ *armapimanagement.ProductPolicyClientDeleteOptions) (armapimanagement.ProductPolicyClientDeleteResponse, error) {
			sawIfMatch = ifMatch
			deleteCalls++
			return armapimanagement.ProductPolicyClientDeleteResponse{}, nil
		},
		listByProductFn: func(_ context.Context, _, _, _ string, _ *armapimanagement.ProductPolicyClientListByProductOptions) (armapimanagement.ProductPolicyClientListByProductResponse, error) {
			return armapimanagement.ProductPolicyClientListByProductResponse{
				PolicyCollection: armapimanagement.PolicyCollection{
					Value: []*armapimanagement.PolicyContract{{ID: to.Ptr(testApimProductPolicyNativeID)}},
				},
			}, nil
		},
	}
	prov := newTestApiManagementProductPolicy(fake)

	t.Run("Create_is_synchronous", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Properties: apimProductPolicyDesired(testApimPolicyDeclared),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testApimProductPolicyNativeID, got.ProgressResult.NativeID)
		require.Empty(t, got.ProgressResult.RequestID)

		require.Equal(t, "starter", sawProduct)
		require.Equal(t, armapimanagement.PolicyIDNamePolicy, sawPolicyID)
		require.Equal(t, testApimPolicyDeclared, *sentBody.Properties.Value)

		// The read-back is the caller's own document, not ARM's rendering.
		var props map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &props))
		require.Equal(t, testApimPolicyDeclared, props["value"])
		require.Equal(t, "starter", props["productName"])
	})

	t.Run("Create_requires_product", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName": "rg-1", "serviceName": "apim1", "value": "<policies />",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "productName is required")
	})

	t.Run("Create_requires_value", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName": "rg-1", "serviceName": "apim1", "productName": "starter",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "value is required")
	})

	t.Run("Read_echoes_the_declared_document", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{
			NativeID:        testApimProductPolicyNativeID,
			PriorProperties: apimProductPolicyDesired(testApimPolicyDeclared),
		})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		// All three scope values come from the native ID.
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "apim1", props["serviceName"])
		require.Equal(t, "starter", props["productName"])
		require.Equal(t, testApimPolicyDeclared, props["value"])
	})

	t.Run("Read_reports_a_genuine_change", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{
			NativeID:        testApimProductPolicyNativeID,
			PriorProperties: apimProductPolicyDesired(`<policies><inbound><base /></inbound></policies>`),
		})
		require.NoError(t, err)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, testApimPolicyReserialized, props["value"])
	})

	t.Run("Update_reissues_create_or_update", func(t *testing.T) {
		before := createCalls
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testApimProductPolicyNativeID,
			DesiredProperties: apimProductPolicyDesired(`<policies><inbound><base /></inbound></policies>`),
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
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testApimProductPolicyNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
		require.Equal(t, "*", sawIfMatch)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _, _ string, _ armapimanagement.PolicyIDName, _ string, _ *armapimanagement.ProductPolicyClientDeleteOptions) (armapimanagement.ProductPolicyClientDeleteResponse, error) {
			return armapimanagement.ProductPolicyClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testApimProductPolicyNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_product", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{
				"resourceGroupName": "rg-1", "serviceName": "apim1", "productName": "starter",
			},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testApimProductPolicyNativeID}, got.NativeIDs)
	})

	t.Run("List_without_parents_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "serviceName": "apim1"},
		})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure_with_a_reason", func(t *testing.T) {
		fake.createOrUpdateFn = func(_ context.Context, _, _, _ string, _ armapimanagement.PolicyIDName, _ armapimanagement.PolicyContract, _ *armapimanagement.ProductPolicyClientCreateOrUpdateOptions) (armapimanagement.ProductPolicyClientCreateOrUpdateResponse, error) {
			return armapimanagement.ProductPolicyClientCreateOrUpdateResponse{}, &azcore.ResponseError{StatusCode: 400}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Properties: apimProductPolicyDesired(testApimPolicyDeclared),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.NotEmpty(t, got.ProgressResult.StatusMessage)
	})
}

func TestApiManagementProductPolicy_ReadNotFound(t *testing.T) {
	fake := &fakeApiManagementProductPoliciesAPI{
		getFn: func(_ context.Context, _, _, _ string, _ armapimanagement.PolicyIDName, _ *armapimanagement.ProductPolicyClientGetOptions) (armapimanagement.ProductPolicyClientGetResponse, error) {
			return armapimanagement.ProductPolicyClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestApiManagementProductPolicy(fake).Read(context.Background(),
		&resource.ReadRequest{NativeID: testApimProductPolicyNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeApiManagementProductPoliciesAPI struct {
	createOrUpdateFn func(ctx context.Context, rgName, serviceName, productID string, policyID armapimanagement.PolicyIDName, params armapimanagement.PolicyContract, options *armapimanagement.ProductPolicyClientCreateOrUpdateOptions) (armapimanagement.ProductPolicyClientCreateOrUpdateResponse, error)
	getFn            func(ctx context.Context, rgName, serviceName, productID string, policyID armapimanagement.PolicyIDName, options *armapimanagement.ProductPolicyClientGetOptions) (armapimanagement.ProductPolicyClientGetResponse, error)
	deleteFn         func(ctx context.Context, rgName, serviceName, productID string, policyID armapimanagement.PolicyIDName, ifMatch string, options *armapimanagement.ProductPolicyClientDeleteOptions) (armapimanagement.ProductPolicyClientDeleteResponse, error)
	listByProductFn  func(ctx context.Context, rgName, serviceName, productID string, options *armapimanagement.ProductPolicyClientListByProductOptions) (armapimanagement.ProductPolicyClientListByProductResponse, error)
}

func (f *fakeApiManagementProductPoliciesAPI) CreateOrUpdate(ctx context.Context, rgName, serviceName, productID string, policyID armapimanagement.PolicyIDName, params armapimanagement.PolicyContract, options *armapimanagement.ProductPolicyClientCreateOrUpdateOptions) (armapimanagement.ProductPolicyClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, serviceName, productID, policyID, params, options)
}

func (f *fakeApiManagementProductPoliciesAPI) Get(ctx context.Context, rgName, serviceName, productID string, policyID armapimanagement.PolicyIDName, options *armapimanagement.ProductPolicyClientGetOptions) (armapimanagement.ProductPolicyClientGetResponse, error) {
	return f.getFn(ctx, rgName, serviceName, productID, policyID, options)
}

func (f *fakeApiManagementProductPoliciesAPI) Delete(ctx context.Context, rgName, serviceName, productID string, policyID armapimanagement.PolicyIDName, ifMatch string, options *armapimanagement.ProductPolicyClientDeleteOptions) (armapimanagement.ProductPolicyClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, serviceName, productID, policyID, ifMatch, options)
}

func (f *fakeApiManagementProductPoliciesAPI) ListByProduct(ctx context.Context, rgName, serviceName, productID string, options *armapimanagement.ProductPolicyClientListByProductOptions) (armapimanagement.ProductPolicyClientListByProductResponse, error) {
	return f.listByProductFn(ctx, rgName, serviceName, productID, options)
}
