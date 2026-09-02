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

const testApimApiSchemaNativeID = testApimApiNativeID + "/schemas/orders"

// As a fixture would declare it: indented, keys in author order.
const testApimApiSchemaDeclared = `{
  "schemas": {
    "Status": {
      "type": "object",
      "properties": {
        "ok": { "type": "boolean" }
      }
    }
  }
}`

func newTestApiManagementApiSchema(api apiManagementAPISchemasAPI) *ApiManagementApiSchema {
	return &ApiManagementApiSchema{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func apimApiSchemaDesired(value string) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":              "orders",
		"resourceGroupName": "rg-1",
		"serviceName":       "apim1",
		"apiName":           "api1",
		"contentType":       apimSchemaContentTypeOpenAPIComponents,
		"value":             value,
	})
	return out
}

func TestApiManagementApiSchema_CRUD(t *testing.T) {
	// ARM parses the document and hands back its own serialization: keys
	// reordered, whitespace gone.
	reserialized := map[string]any{
		"schemas": map[string]any{
			"Status": map[string]any{
				"properties": map[string]any{"ok": map[string]any{"type": "boolean"}},
				"type":       "object",
			},
		},
	}
	schemaResult := armapimanagement.SchemaContract{
		ID:   to.Ptr(testApimApiSchemaNativeID),
		Name: to.Ptr("orders"),
		Properties: &armapimanagement.SchemaContractProperties{
			ContentType: to.Ptr(apimSchemaContentTypeOpenAPIComponents),
			Document:    &armapimanagement.SchemaDocumentProperties{Components: reserialized},
		},
	}

	var sentBody armapimanagement.SchemaContract
	var sawIfMatch string
	createCalls := 0
	deleteCalls := 0
	fake := &fakeApiManagementAPISchemasAPI{
		beginCreateOrUpdateFn: func(_ context.Context, _, _, apiID, schemaID string, params armapimanagement.SchemaContract, _ *armapimanagement.APISchemaClientBeginCreateOrUpdateOptions) (*runtime.Poller[armapimanagement.APISchemaClientCreateOrUpdateResponse], error) {
			require.Equal(t, "api1", apiID)
			require.Equal(t, "orders", schemaID)
			sentBody = params
			createCalls++
			return newDonePoller(armapimanagement.APISchemaClientCreateOrUpdateResponse{SchemaContract: schemaResult}), nil
		},
		getFn: func(_ context.Context, _, _, _, _ string, _ *armapimanagement.APISchemaClientGetOptions) (armapimanagement.APISchemaClientGetResponse, error) {
			return armapimanagement.APISchemaClientGetResponse{SchemaContract: schemaResult}, nil
		},
		deleteFn: func(_ context.Context, _, _, _, _, ifMatch string, _ *armapimanagement.APISchemaClientDeleteOptions) (armapimanagement.APISchemaClientDeleteResponse, error) {
			sawIfMatch = ifMatch
			deleteCalls++
			return armapimanagement.APISchemaClientDeleteResponse{}, nil
		},
		newListByAPIPagerFn: func(_, _, _ string, _ *armapimanagement.APISchemaClientListByAPIOptions) *runtime.Pager[armapimanagement.APISchemaClientListByAPIResponse] {
			return runtime.NewPager(runtime.PagingHandler[armapimanagement.APISchemaClientListByAPIResponse]{
				More: func(_ armapimanagement.APISchemaClientListByAPIResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armapimanagement.APISchemaClientListByAPIResponse) (armapimanagement.APISchemaClientListByAPIResponse, error) {
					return armapimanagement.APISchemaClientListByAPIResponse{
						SchemaCollection: armapimanagement.SchemaCollection{
							Value: []*armapimanagement.SchemaContract{{ID: to.Ptr(testApimApiSchemaNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestApiManagementApiSchema(fake)

	// An OpenAPI components document travels as a structured object in
	// document.components, not as text in document.value.
	t.Run("Create_sends_json_as_a_structured_components_document", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "orders",
			Properties: apimApiSchemaDesired(testApimApiSchemaDeclared),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testApimApiSchemaNativeID, got.ProgressResult.NativeID)

		require.NotNil(t, sentBody.Properties.Document.Components)
		require.Nil(t, sentBody.Properties.Document.Value)
		require.Nil(t, sentBody.Properties.Document.Definitions)
		require.True(t, apimJSONEquivalent(apimAnyToJSON(sentBody.Properties.Document.Components),
			testApimApiSchemaDeclared))
	})

	t.Run("Create_sends_swagger_definitions_in_their_own_field", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "orders", "resourceGroupName": "rg-1", "serviceName": "apim1", "apiName": "api1",
			"contentType": apimSchemaContentTypeSwaggerDefs, "value": `{"Status":{"type":"object"}}`,
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.NotNil(t, sentBody.Properties.Document.Definitions)
		require.Nil(t, sentBody.Properties.Document.Components)
	})

	// An XSD is not JSON, so it travels as plain text.
	t.Run("Create_sends_xsd_as_text", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "orders", "resourceGroupName": "rg-1", "serviceName": "apim1", "apiName": "api1",
			"contentType": "application/vnd.ms-azure-apim.xsd+xml", "value": "<xsd:schema />",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.Equal(t, "<xsd:schema />", *sentBody.Properties.Document.Value)
		require.Nil(t, sentBody.Properties.Document.Components)
	})

	t.Run("Create_rejects_malformed_json", func(t *testing.T) {
		_, err := prov.Create(context.Background(), &resource.CreateRequest{
			Properties: apimApiSchemaDesired(`{"schemas":`),
		})
		require.ErrorContains(t, err, "value is not valid JSON")
	})

	t.Run("Create_requires_content_type", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "orders", "resourceGroupName": "rg-1", "serviceName": "apim1", "apiName": "api1",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "contentType is required")
	})

	t.Run("Create_requires_value", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "orders", "resourceGroupName": "rg-1", "serviceName": "apim1", "apiName": "api1",
			"contentType": apimSchemaContentTypeOpenAPIComponents,
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "value is required")
	})

	// Same problem as the policies: ARM's serialization differs textually, so
	// the caller's own document has to be reported when the two carry the same
	// data.
	t.Run("Read_echoes_the_declared_document", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{
			NativeID:        testApimApiSchemaNativeID,
			PriorProperties: apimApiSchemaDesired(testApimApiSchemaDeclared),
		})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "orders", props["name"])
		require.Equal(t, "api1", props["apiName"])
		require.Equal(t, apimSchemaContentTypeOpenAPIComponents, props["contentType"])
		require.Equal(t, testApimApiSchemaDeclared, props["value"])
	})

	t.Run("Read_reports_a_genuine_change", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{
			NativeID:        testApimApiSchemaNativeID,
			PriorProperties: apimApiSchemaDesired(`{"schemas":{}}`),
		})
		require.NoError(t, err)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.NotEqual(t, `{"schemas":{}}`, props["value"])
		require.True(t, apimJSONEquivalent(props["value"].(string), testApimApiSchemaDeclared))
	})

	t.Run("Read_without_prior_state_reports_arm", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testApimApiSchemaNativeID})
		require.NoError(t, err)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.True(t, apimJSONEquivalent(props["value"].(string), testApimApiSchemaDeclared))
	})

	t.Run("Update_reissues_create_or_update", func(t *testing.T) {
		before := createCalls
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testApimApiSchemaNativeID,
			DesiredProperties: apimApiSchemaDesired(testApimApiSchemaDeclared),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		// There is no PATCH verb for a schema.
		require.Equal(t, before+1, createCalls)

		var props map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &props))
		require.Equal(t, testApimApiSchemaDeclared, props["value"])
	})

	t.Run("Update_in_progress_yields_an_update_resume_token", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _, _, _ string, _ armapimanagement.SchemaContract, _ *armapimanagement.APISchemaClientBeginCreateOrUpdateOptions) (*runtime.Poller[armapimanagement.APISchemaClientCreateOrUpdateResponse], error) {
			return newInProgressPoller[armapimanagement.APISchemaClientCreateOrUpdateResponse](), nil
		}
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testApimApiSchemaNativeID,
			DesiredProperties: apimApiSchemaDesired(testApimApiSchemaDeclared),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusInProgress, got.ProgressResult.OperationStatus)

		var reqID lroRequestID
		require.NoError(t, json.Unmarshal([]byte(got.ProgressResult.RequestID), &reqID))
		// Create and update share one poller type, so the operation kind has to
		// be recorded or Status reports the wrong operation.
		require.Equal(t, lroOpUpdate, reqID.OperationType)
	})

	t.Run("Delete_is_synchronous", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testApimApiSchemaNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Empty(t, got.ProgressResult.RequestID)
		require.Equal(t, before+1, deleteCalls)
		require.Equal(t, "*", sawIfMatch)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _, _, _, _ string, _ *armapimanagement.APISchemaClientDeleteOptions) (armapimanagement.APISchemaClientDeleteResponse, error) {
			return armapimanagement.APISchemaClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testApimApiSchemaNativeID})
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
		require.Equal(t, []string{testApimApiSchemaNativeID}, got.NativeIDs)
	})

	t.Run("List_without_the_api_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "serviceName": "apim1"},
		})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure_with_a_reason", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _, _, _ string, _ armapimanagement.SchemaContract, _ *armapimanagement.APISchemaClientBeginCreateOrUpdateOptions) (*runtime.Poller[armapimanagement.APISchemaClientCreateOrUpdateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 400}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "orders", Properties: apimApiSchemaDesired(testApimApiSchemaDeclared),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.NotEmpty(t, got.ProgressResult.StatusMessage)
	})
}

func TestApiManagementApiSchema_ReadNotFound(t *testing.T) {
	fake := &fakeApiManagementAPISchemasAPI{
		getFn: func(_ context.Context, _, _, _, _ string, _ *armapimanagement.APISchemaClientGetOptions) (armapimanagement.APISchemaClientGetResponse, error) {
			return armapimanagement.APISchemaClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestApiManagementApiSchema(fake).Read(context.Background(),
		&resource.ReadRequest{NativeID: testApimApiSchemaNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// Both schema resources have a leaf type of "schemas"; only the length of the
// chain tells a per-API schema from a service-wide one.
func TestApiManagementApiSchema_RejectsGlobalSchemaID(t *testing.T) {
	globalID := testApimServiceNativeID + "/schemas/orders"
	_, _, _, _, err := apiManagementApiSchemaIDParts(globalID)
	require.Error(t, err)
	_, _, _, err = apiManagementGlobalSchemaIDParts(testApimApiSchemaNativeID)
	require.Error(t, err)
}

// --- Test helpers ---

type fakeApiManagementAPISchemasAPI struct {
	beginCreateOrUpdateFn func(ctx context.Context, rgName, serviceName, apiID, schemaID string, params armapimanagement.SchemaContract, options *armapimanagement.APISchemaClientBeginCreateOrUpdateOptions) (*runtime.Poller[armapimanagement.APISchemaClientCreateOrUpdateResponse], error)
	getFn                 func(ctx context.Context, rgName, serviceName, apiID, schemaID string, options *armapimanagement.APISchemaClientGetOptions) (armapimanagement.APISchemaClientGetResponse, error)
	deleteFn              func(ctx context.Context, rgName, serviceName, apiID, schemaID, ifMatch string, options *armapimanagement.APISchemaClientDeleteOptions) (armapimanagement.APISchemaClientDeleteResponse, error)
	newListByAPIPagerFn   func(rgName, serviceName, apiID string, options *armapimanagement.APISchemaClientListByAPIOptions) *runtime.Pager[armapimanagement.APISchemaClientListByAPIResponse]
}

func (f *fakeApiManagementAPISchemasAPI) BeginCreateOrUpdate(ctx context.Context, rgName, serviceName, apiID, schemaID string, params armapimanagement.SchemaContract, options *armapimanagement.APISchemaClientBeginCreateOrUpdateOptions) (*runtime.Poller[armapimanagement.APISchemaClientCreateOrUpdateResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, rgName, serviceName, apiID, schemaID, params, options)
}

func (f *fakeApiManagementAPISchemasAPI) Get(ctx context.Context, rgName, serviceName, apiID, schemaID string, options *armapimanagement.APISchemaClientGetOptions) (armapimanagement.APISchemaClientGetResponse, error) {
	return f.getFn(ctx, rgName, serviceName, apiID, schemaID, options)
}

func (f *fakeApiManagementAPISchemasAPI) Delete(ctx context.Context, rgName, serviceName, apiID, schemaID, ifMatch string, options *armapimanagement.APISchemaClientDeleteOptions) (armapimanagement.APISchemaClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, serviceName, apiID, schemaID, ifMatch, options)
}

func (f *fakeApiManagementAPISchemasAPI) NewListByAPIPager(rgName, serviceName, apiID string, options *armapimanagement.APISchemaClientListByAPIOptions) *runtime.Pager[armapimanagement.APISchemaClientListByAPIResponse] {
	return f.newListByAPIPagerFn(rgName, serviceName, apiID, options)
}
