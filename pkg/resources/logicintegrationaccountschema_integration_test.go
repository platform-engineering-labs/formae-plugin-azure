// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/logic/armlogic"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testLogicIntegrationAccountSchemaNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Logic/integrationAccounts/ia-1/schemas/sch-1"

func newTestLogicIntegrationAccountSchema(api logicIntegrationAccountSchemasAPI) *LogicIntegrationAccountSchema {
	return &LogicIntegrationAccountSchema{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

const testLogicSchemaContent = `<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema"><xs:element name="Order" type="xs:string" /></xs:schema>`

func logicSchemaDesired(fileName string) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":                   "sch-1",
		"resourceGroupName":      "rg-1",
		"integrationAccountName": "ia-1",
		"schemaType":             "Xml",
		"content":                testLogicSchemaContent,
		"fileName":               fileName,
	})
	return out
}

func TestLogicIntegrationAccountSchema_CRUD(t *testing.T) {
	// ARM's answer replaces content with a contentLink SAS URL and fills in the
	// documentName and targetNamespace it derived from the XSD's root element.
	result := armlogic.IntegrationAccountSchema{
		ID:   to.Ptr(testLogicIntegrationAccountSchemaNativeID),
		Name: to.Ptr("sch-1"),
		Properties: &armlogic.IntegrationAccountSchemaProperties{
			SchemaType:      to.Ptr(armlogic.SchemaTypeXML),
			FileName:        to.Ptr("order.xsd"),
			DocumentName:    to.Ptr("Order"),
			TargetNamespace: to.Ptr("http://formae.test/order"),
			ContentType:     to.Ptr("application/xml"),
			ContentLink: &armlogic.ContentLink{
				URI:            to.Ptr("https://prod.blob.core.windows.net/schemas/sch-1?sig=REDACTED"),
				ContentVersion: to.Ptr("\"0x8D45CE54B058881\""),
			},
			CreatedTime: to.Ptr(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)),
			ChangedTime: to.Ptr(time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)),
		},
	}

	var sentCreate armlogic.IntegrationAccountSchema
	createCalls := 0
	deleteCalls := 0
	fake := &fakeLogicIntegrationAccountSchemasAPI{
		createOrUpdateFn: func(_ context.Context, rgName, accountName, name string, params armlogic.IntegrationAccountSchema, _ *armlogic.IntegrationAccountSchemasClientCreateOrUpdateOptions) (armlogic.IntegrationAccountSchemasClientCreateOrUpdateResponse, error) {
			require.Equal(t, "rg-1", rgName)
			require.Equal(t, "ia-1", accountName)
			require.Equal(t, "sch-1", name)
			sentCreate = params
			createCalls++
			return armlogic.IntegrationAccountSchemasClientCreateOrUpdateResponse{IntegrationAccountSchema: result}, nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ *armlogic.IntegrationAccountSchemasClientGetOptions) (armlogic.IntegrationAccountSchemasClientGetResponse, error) {
			return armlogic.IntegrationAccountSchemasClientGetResponse{IntegrationAccountSchema: result}, nil
		},
		deleteFn: func(_ context.Context, _, _, _ string, _ *armlogic.IntegrationAccountSchemasClientDeleteOptions) (armlogic.IntegrationAccountSchemasClientDeleteResponse, error) {
			deleteCalls++
			return armlogic.IntegrationAccountSchemasClientDeleteResponse{}, nil
		},
		newListPagerFn: func(_, _ string, _ *armlogic.IntegrationAccountSchemasClientListOptions) *runtime.Pager[armlogic.IntegrationAccountSchemasClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armlogic.IntegrationAccountSchemasClientListResponse]{
				More: func(_ armlogic.IntegrationAccountSchemasClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armlogic.IntegrationAccountSchemasClientListResponse) (armlogic.IntegrationAccountSchemasClientListResponse, error) {
					return armlogic.IntegrationAccountSchemasClientListResponse{
						IntegrationAccountSchemaListResult: armlogic.IntegrationAccountSchemaListResult{
							Value: []*armlogic.IntegrationAccountSchema{{ID: to.Ptr(testLogicIntegrationAccountSchemaNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestLogicIntegrationAccountSchema(fake)

	// Create is synchronous: IntegrationAccountSchemasClient has no BeginX at all, so no
	// resume token is ever produced.
	t.Run("Create_is_synchronous", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "sch-1",
			Properties: logicSchemaDesired("order.xsd"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testLogicIntegrationAccountSchemaNativeID, got.ProgressResult.NativeID)
		require.Empty(t, got.ProgressResult.RequestID)

		require.Equal(t, armlogic.SchemaTypeXML, *sentCreate.Properties.SchemaType)
		require.Equal(t, testLogicSchemaContent, *sentCreate.Properties.Content)
		require.Equal(t, "order.xsd", *sentCreate.Properties.FileName)
	})

	t.Run("Create_requires_resource_group", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "sch-1", "integrationAccountName": "ia-1"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "resourceGroupName is required")
	})

	t.Run("Create_requires_integration_account", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "sch-1", "resourceGroupName": "rg-1"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "integrationAccountName is required")
	})

	t.Run("Create_requires_schema_type", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "sch-1", "resourceGroupName": "rg-1", "integrationAccountName": "ia-1",
			"content": testLogicSchemaContent,
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "schemaType is required")
	})

	t.Run("Create_requires_content", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "sch-1", "resourceGroupName": "rg-1", "integrationAccountName": "ia-1",
			"schemaType": "Xml",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "content is required")
	})

	// An omitted fileName must be left out of the body rather than sent as an
	// empty string.
	t.Run("Create_without_file_name_sends_none", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "sch-1", "resourceGroupName": "rg-1", "integrationAccountName": "ia-1",
			"schemaType": "Xml", "content": testLogicSchemaContent,
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.Nil(t, sentCreate.Properties.FileName)
	})


	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testLogicIntegrationAccountSchemaNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "sch-1", props["name"])
		// Both parents come from the native ID, not the response body: ARM echoes
		// neither on a child.
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "ia-1", props["integrationAccountName"])
		require.Equal(t, "Xml", props["schemaType"])
		require.Equal(t, "order.xsd", props["fileName"])
	})

	t.Run("Read_drops_write_only_content_and_derived_fields", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testLogicIntegrationAccountSchemaNativeID})
		require.NoError(t, err)
		for _, key := range []string{"content", "contentLink", "sig=REDACTED", "documentName", "targetNamespace", "contentType", "createdTime", "changedTime"} {
			require.NotContains(t, got.Properties, key)
		}
	})

	// armExactIDParts, not armIDParts: an ID naming a different child kind of the
	// same account must be rejected here rather than 404ing against the wrong
	// client.
	t.Run("Read_rejects_another_child_kind", func(t *testing.T) {
		_, err := prov.Read(context.Background(), &resource.ReadRequest{
			NativeID: "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Logic/integrationAccounts/ia-1/sessions/s-1",
		})
		require.Error(t, err)
	})

	// Update reissues CreateOrUpdate: this API has no PATCH verb for schemas.
	t.Run("Update_reissues_create_or_update", func(t *testing.T) {
		before := createCalls
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testLogicIntegrationAccountSchemaNativeID,
			DesiredProperties: logicSchemaDesired("order-v2.xsd"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Empty(t, got.ProgressResult.RequestID)
		require.Equal(t, before+1, createCalls)
		require.Equal(t, "order-v2.xsd", *sentCreate.Properties.FileName)
	})

	t.Run("Delete_is_synchronous", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testLogicIntegrationAccountSchemaNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Empty(t, got.ProgressResult.RequestID)
		require.Equal(t, before+1, deleteCalls)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _, _ string, _ *armlogic.IntegrationAccountSchemasClientDeleteOptions) (armlogic.IntegrationAccountSchemasClientDeleteResponse, error) {
			return armlogic.IntegrationAccountSchemasClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testLogicIntegrationAccountSchemaNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_account", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "integrationAccountName": "ia-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testLogicIntegrationAccountSchemaNativeID}, got.NativeIDs)
	})

	// ARM has no subscription-wide listing here: without both parents there is
	// nothing to page, so List must return empty rather than error. Both keys ARE
	// supplied by the hint's listParam, so no subscriptionWideList entry is
	// needed.
	t.Run("List_without_parents_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure_with_a_cause", func(t *testing.T) {
		fake.createOrUpdateFn = func(_ context.Context, _, _, _ string, _ armlogic.IntegrationAccountSchema, _ *armlogic.IntegrationAccountSchemasClientCreateOrUpdateOptions) (armlogic.IntegrationAccountSchemasClientCreateOrUpdateResponse, error) {
			return armlogic.IntegrationAccountSchemasClientCreateOrUpdateResponse{}, &azcore.ResponseError{StatusCode: 409}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "sch-1", Properties: logicSchemaDesired("order.xsd"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.NotEmpty(t, got.ProgressResult.StatusMessage)
	})
}

func TestLogicIntegrationAccountSchema_ReadNotFound(t *testing.T) {
	fake := &fakeLogicIntegrationAccountSchemasAPI{
		getFn: func(_ context.Context, _, _, _ string, _ *armlogic.IntegrationAccountSchemasClientGetOptions) (armlogic.IntegrationAccountSchemasClientGetResponse, error) {
			return armlogic.IntegrationAccountSchemasClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestLogicIntegrationAccountSchema(fake).Read(context.Background(),
		&resource.ReadRequest{NativeID: testLogicIntegrationAccountSchemaNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeLogicIntegrationAccountSchemasAPI struct {
	createOrUpdateFn func(ctx context.Context, rgName, accountName, name string, params armlogic.IntegrationAccountSchema, options *armlogic.IntegrationAccountSchemasClientCreateOrUpdateOptions) (armlogic.IntegrationAccountSchemasClientCreateOrUpdateResponse, error)
	getFn            func(ctx context.Context, rgName, accountName, name string, options *armlogic.IntegrationAccountSchemasClientGetOptions) (armlogic.IntegrationAccountSchemasClientGetResponse, error)
	deleteFn         func(ctx context.Context, rgName, accountName, name string, options *armlogic.IntegrationAccountSchemasClientDeleteOptions) (armlogic.IntegrationAccountSchemasClientDeleteResponse, error)
	newListPagerFn   func(rgName, accountName string, options *armlogic.IntegrationAccountSchemasClientListOptions) *runtime.Pager[armlogic.IntegrationAccountSchemasClientListResponse]
}

func (f *fakeLogicIntegrationAccountSchemasAPI) CreateOrUpdate(ctx context.Context, rgName, accountName, name string, params armlogic.IntegrationAccountSchema, options *armlogic.IntegrationAccountSchemasClientCreateOrUpdateOptions) (armlogic.IntegrationAccountSchemasClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, accountName, name, params, options)
}

func (f *fakeLogicIntegrationAccountSchemasAPI) Get(ctx context.Context, rgName, accountName, name string, options *armlogic.IntegrationAccountSchemasClientGetOptions) (armlogic.IntegrationAccountSchemasClientGetResponse, error) {
	return f.getFn(ctx, rgName, accountName, name, options)
}

func (f *fakeLogicIntegrationAccountSchemasAPI) Delete(ctx context.Context, rgName, accountName, name string, options *armlogic.IntegrationAccountSchemasClientDeleteOptions) (armlogic.IntegrationAccountSchemasClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, accountName, name, options)
}

func (f *fakeLogicIntegrationAccountSchemasAPI) NewListPager(rgName, accountName string, options *armlogic.IntegrationAccountSchemasClientListOptions) *runtime.Pager[armlogic.IntegrationAccountSchemasClientListResponse] {
	return f.newListPagerFn(rgName, accountName, options)
}
