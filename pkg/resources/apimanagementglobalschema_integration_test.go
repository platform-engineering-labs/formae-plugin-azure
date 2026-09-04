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

const testApimGlobalSchemaNativeID = testApimServiceNativeID + "/schemas/shared"

// As a fixture would declare it: indented, self-closing tag spaced.
const testApimGlobalSchemaDeclaredXSD = `<xsd:schema xmlns:xsd="http://www.w3.org/2001/XMLSchema">
  <xsd:element name="OrderId" type="xsd:string" />
</xsd:schema>`

// As ARM hands it back: CRLF, different indentation, attribute order changed.
const testApimGlobalSchemaReserializedXSD = "<xsd:schema xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\">\r\n\t" +
	"<xsd:element type=\"xsd:string\" name=\"OrderId\"/>\r\n</xsd:schema>"

func newTestApiManagementGlobalSchema(api apiManagementGlobalSchemasAPI) *ApiManagementGlobalSchema {
	return &ApiManagementGlobalSchema{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func apimGlobalSchemaDesired(schemaType, value string) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":              "shared",
		"resourceGroupName": "rg-1",
		"serviceName":       "apim1",
		"schemaType":        schemaType,
		"value":             value,
		"description":       "Shared order types",
	})
	return out
}

func TestApiManagementGlobalSchema_CRUD(t *testing.T) {
	schemaResult := armapimanagement.GlobalSchemaContract{
		ID:   to.Ptr(testApimGlobalSchemaNativeID),
		Name: to.Ptr("shared"),
		Properties: &armapimanagement.GlobalSchemaContractProperties{
			SchemaType:  to.Ptr(armapimanagement.SchemaTypeXML),
			Description: to.Ptr("Shared order types"),
			Value:       testApimGlobalSchemaReserializedXSD,
		},
	}

	var sentBody armapimanagement.GlobalSchemaContract
	var sawIfMatch string
	createCalls := 0
	deleteCalls := 0
	fake := &fakeApiManagementGlobalSchemasAPI{
		beginCreateOrUpdateFn: func(_ context.Context, _, serviceName, schemaID string, params armapimanagement.GlobalSchemaContract, _ *armapimanagement.GlobalSchemaClientBeginCreateOrUpdateOptions) (*runtime.Poller[armapimanagement.GlobalSchemaClientCreateOrUpdateResponse], error) {
			require.Equal(t, "apim1", serviceName)
			require.Equal(t, "shared", schemaID)
			sentBody = params
			createCalls++
			return newDonePoller(armapimanagement.GlobalSchemaClientCreateOrUpdateResponse{GlobalSchemaContract: schemaResult}), nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ *armapimanagement.GlobalSchemaClientGetOptions) (armapimanagement.GlobalSchemaClientGetResponse, error) {
			return armapimanagement.GlobalSchemaClientGetResponse{GlobalSchemaContract: schemaResult}, nil
		},
		deleteFn: func(_ context.Context, _, _, _, ifMatch string, _ *armapimanagement.GlobalSchemaClientDeleteOptions) (armapimanagement.GlobalSchemaClientDeleteResponse, error) {
			sawIfMatch = ifMatch
			deleteCalls++
			return armapimanagement.GlobalSchemaClientDeleteResponse{}, nil
		},
		newListByServicePagerFn: func(_, _ string, _ *armapimanagement.GlobalSchemaClientListByServiceOptions) *runtime.Pager[armapimanagement.GlobalSchemaClientListByServiceResponse] {
			return runtime.NewPager(runtime.PagingHandler[armapimanagement.GlobalSchemaClientListByServiceResponse]{
				More: func(_ armapimanagement.GlobalSchemaClientListByServiceResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armapimanagement.GlobalSchemaClientListByServiceResponse) (armapimanagement.GlobalSchemaClientListByServiceResponse, error) {
					return armapimanagement.GlobalSchemaClientListByServiceResponse{
						GlobalSchemaCollection: armapimanagement.GlobalSchemaCollection{
							Value: []*armapimanagement.GlobalSchemaContract{{ID: to.Ptr(testApimGlobalSchemaNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestApiManagementGlobalSchema(fake)

	// An XSD travels as text in `value`; the structured `document` field is for
	// the json flavour only.
	t.Run("Create_sends_xml_as_text", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "shared",
			Properties: apimGlobalSchemaDesired("xml", testApimGlobalSchemaDeclaredXSD),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testApimGlobalSchemaNativeID, got.ProgressResult.NativeID)

		require.Equal(t, armapimanagement.SchemaTypeXML, *sentBody.Properties.SchemaType)
		require.Equal(t, testApimGlobalSchemaDeclaredXSD, sentBody.Properties.Value)
		require.Nil(t, sentBody.Properties.Document)
	})

	t.Run("Create_sends_json_as_a_structured_document", func(t *testing.T) {
		_, err := prov.Create(context.Background(), &resource.CreateRequest{
			Properties: apimGlobalSchemaDesired("json", `{"type":"object"}`),
		})
		require.NoError(t, err)
		require.NotNil(t, sentBody.Properties.Document)
		require.Nil(t, sentBody.Properties.Value)
	})

	t.Run("Create_rejects_malformed_json", func(t *testing.T) {
		_, err := prov.Create(context.Background(), &resource.CreateRequest{
			Properties: apimGlobalSchemaDesired("json", `{`),
		})
		require.ErrorContains(t, err, "value is not valid JSON")
	})

	t.Run("Create_requires_schema_type", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "shared", "resourceGroupName": "rg-1", "serviceName": "apim1", "value": "<xsd:schema />",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "schemaType is required")
	})

	t.Run("Create_requires_value", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "shared", "resourceGroupName": "rg-1", "serviceName": "apim1", "schemaType": "xml",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "value is required")
	})

	// ARM re-serializes the XSD the same way it does a policy document, so the
	// caller's own text has to be reported when the two are equivalent.
	t.Run("Read_echoes_the_declared_document", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{
			NativeID:        testApimGlobalSchemaNativeID,
			PriorProperties: apimGlobalSchemaDesired("xml", testApimGlobalSchemaDeclaredXSD),
		})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "shared", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "apim1", props["serviceName"])
		require.Equal(t, "xml", props["schemaType"])
		require.Equal(t, testApimGlobalSchemaDeclaredXSD, props["value"])
		require.Equal(t, "Shared order types", props["description"])
	})

	t.Run("Read_reports_a_genuine_change", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{
			NativeID:        testApimGlobalSchemaNativeID,
			PriorProperties: apimGlobalSchemaDesired("xml", `<xsd:schema />`),
		})
		require.NoError(t, err)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, testApimGlobalSchemaReserializedXSD, props["value"])
	})

	t.Run("Read_without_prior_state_reports_arm", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testApimGlobalSchemaNativeID})
		require.NoError(t, err)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, testApimGlobalSchemaReserializedXSD, props["value"])
	})

	t.Run("Update_reissues_create_or_update", func(t *testing.T) {
		before := createCalls
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testApimGlobalSchemaNativeID,
			DesiredProperties: apimGlobalSchemaDesired("xml", testApimGlobalSchemaDeclaredXSD),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		// There is no PATCH verb for a global schema.
		require.Equal(t, before+1, createCalls)

		var props map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &props))
		require.Equal(t, testApimGlobalSchemaDeclaredXSD, props["value"])
	})

	t.Run("Create_in_progress_yields_a_create_resume_token", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _, _ string, _ armapimanagement.GlobalSchemaContract, _ *armapimanagement.GlobalSchemaClientBeginCreateOrUpdateOptions) (*runtime.Poller[armapimanagement.GlobalSchemaClientCreateOrUpdateResponse], error) {
			return newInProgressPoller[armapimanagement.GlobalSchemaClientCreateOrUpdateResponse](), nil
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "shared",
			Properties: apimGlobalSchemaDesired("xml", testApimGlobalSchemaDeclaredXSD),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusInProgress, got.ProgressResult.OperationStatus)
		require.Equal(t, testApimGlobalSchemaNativeID, got.ProgressResult.NativeID)

		var reqID lroRequestID
		require.NoError(t, json.Unmarshal([]byte(got.ProgressResult.RequestID), &reqID))
		require.Equal(t, lroOpCreate, reqID.OperationType)
	})

	t.Run("Delete_is_synchronous", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testApimGlobalSchemaNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Empty(t, got.ProgressResult.RequestID)
		require.Equal(t, before+1, deleteCalls)
		require.Equal(t, "*", sawIfMatch)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _, _, _ string, _ *armapimanagement.GlobalSchemaClientDeleteOptions) (armapimanagement.GlobalSchemaClientDeleteResponse, error) {
			return armapimanagement.GlobalSchemaClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testApimGlobalSchemaNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_service", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "serviceName": "apim1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testApimGlobalSchemaNativeID}, got.NativeIDs)
	})

	t.Run("List_without_parents_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure_with_a_reason", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _, _ string, _ armapimanagement.GlobalSchemaContract, _ *armapimanagement.GlobalSchemaClientBeginCreateOrUpdateOptions) (*runtime.Poller[armapimanagement.GlobalSchemaClientCreateOrUpdateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 400}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "shared", Properties: apimGlobalSchemaDesired("xml", testApimGlobalSchemaDeclaredXSD),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.NotEmpty(t, got.ProgressResult.StatusMessage)
	})
}

func TestApiManagementGlobalSchema_ReadNotFound(t *testing.T) {
	fake := &fakeApiManagementGlobalSchemasAPI{
		getFn: func(_ context.Context, _, _, _ string, _ *armapimanagement.GlobalSchemaClientGetOptions) (armapimanagement.GlobalSchemaClientGetResponse, error) {
			return armapimanagement.GlobalSchemaClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestApiManagementGlobalSchema(fake).Read(context.Background(),
		&resource.ReadRequest{NativeID: testApimGlobalSchemaNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeApiManagementGlobalSchemasAPI struct {
	beginCreateOrUpdateFn   func(ctx context.Context, rgName, serviceName, schemaID string, params armapimanagement.GlobalSchemaContract, options *armapimanagement.GlobalSchemaClientBeginCreateOrUpdateOptions) (*runtime.Poller[armapimanagement.GlobalSchemaClientCreateOrUpdateResponse], error)
	getFn                   func(ctx context.Context, rgName, serviceName, schemaID string, options *armapimanagement.GlobalSchemaClientGetOptions) (armapimanagement.GlobalSchemaClientGetResponse, error)
	deleteFn                func(ctx context.Context, rgName, serviceName, schemaID, ifMatch string, options *armapimanagement.GlobalSchemaClientDeleteOptions) (armapimanagement.GlobalSchemaClientDeleteResponse, error)
	newListByServicePagerFn func(rgName, serviceName string, options *armapimanagement.GlobalSchemaClientListByServiceOptions) *runtime.Pager[armapimanagement.GlobalSchemaClientListByServiceResponse]
}

func (f *fakeApiManagementGlobalSchemasAPI) BeginCreateOrUpdate(ctx context.Context, rgName, serviceName, schemaID string, params armapimanagement.GlobalSchemaContract, options *armapimanagement.GlobalSchemaClientBeginCreateOrUpdateOptions) (*runtime.Poller[armapimanagement.GlobalSchemaClientCreateOrUpdateResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, rgName, serviceName, schemaID, params, options)
}

func (f *fakeApiManagementGlobalSchemasAPI) Get(ctx context.Context, rgName, serviceName, schemaID string, options *armapimanagement.GlobalSchemaClientGetOptions) (armapimanagement.GlobalSchemaClientGetResponse, error) {
	return f.getFn(ctx, rgName, serviceName, schemaID, options)
}

func (f *fakeApiManagementGlobalSchemasAPI) Delete(ctx context.Context, rgName, serviceName, schemaID, ifMatch string, options *armapimanagement.GlobalSchemaClientDeleteOptions) (armapimanagement.GlobalSchemaClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, serviceName, schemaID, ifMatch, options)
}

func (f *fakeApiManagementGlobalSchemasAPI) NewListByServicePager(rgName, serviceName string, options *armapimanagement.GlobalSchemaClientListByServiceOptions) *runtime.Pager[armapimanagement.GlobalSchemaClientListByServiceResponse] {
	return f.newListByServicePagerFn(rgName, serviceName, options)
}
