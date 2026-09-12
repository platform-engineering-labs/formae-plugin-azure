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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/datafactory/armdatafactory"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

// All five AZURE::DataFactory::LinkedService* types run through the one
// DataFactoryLinkedService provisioner, so the shared CRUD is exercised once
// against the Key Vault connector — the cheapest of the five — and each of the
// other four gets its own build/read round trip.

const testLinkedServiceNativeID = testDataFactoryNativeID + "/linkedservices/ls-1"

func newTestLinkedService(api dataFactoryLinkedServicesAPI, kind *linkedServiceKind) *DataFactoryLinkedService {
	return &DataFactoryLinkedService{
		api:    api,
		kind:   kind,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func linkedServiceDesired(overrides map[string]any) []byte {
	props := map[string]any{
		"name":              "ls-1",
		"resourceGroupName": "rg-1",
		"factoryName":       "adf-1",
	}
	for k, v := range overrides {
		if v == nil {
			delete(props, k)
			continue
		}
		props[k] = v
	}
	out, _ := json.Marshal(props)
	return out
}

// linkedServiceRoundTrip builds a payload through a kind and hands the result
// straight back to that kind's reader, which is what an ARM echo of an
// unchanged linked service amounts to.
func linkedServiceRoundTrip(t *testing.T, kind *linkedServiceKind, payload []byte) (armdatafactory.LinkedServiceClassification, map[string]any) {
	t.Helper()
	var common dataFactoryLinkedServiceCommon
	require.NoError(t, common.parse(payload, "ls-1"))
	built, err := kind.build(&common, payload)
	require.NoError(t, err)

	prov := newTestLinkedService(nil, kind)
	props := prov.buildPropertiesFromResult(&armdatafactory.LinkedServiceResource{
		ID:         to.Ptr(testLinkedServiceNativeID),
		Name:       to.Ptr("ls-1"),
		Etag:       to.Ptr("W/\"datetime\""),
		Properties: built,
	}, "rg-1", "adf-1")
	return built, props
}

func TestDataFactoryLinkedService_SharedCRUD(t *testing.T) {
	keyVaultResult := armdatafactory.LinkedServiceResource{
		ID:   to.Ptr(testLinkedServiceNativeID),
		Name: to.Ptr("ls-1"),
		Properties: &armdatafactory.AzureKeyVaultLinkedService{
			Type:        to.Ptr("AzureKeyVault"),
			Description: to.Ptr("secrets for the copy pipeline"),
			Annotations: []any{"conformance"},
			ConnectVia: &armdatafactory.IntegrationRuntimeReference{
				Type:          to.Ptr(armdatafactory.IntegrationRuntimeReferenceTypeIntegrationRuntimeReference),
				ReferenceName: to.Ptr("azir-1"),
			},
			TypeProperties: &armdatafactory.AzureKeyVaultLinkedServiceTypeProperties{
				BaseURL: "https://kv-1.vault.azure.net/",
			},
		},
	}

	var sent armdatafactory.LinkedServiceResource
	var sawRG, sawFactory, sawName string
	createCalls := 0
	deleteCalls := 0
	fake := &fakeLinkedServicesAPI{
		createOrUpdateFn: func(_ context.Context, rgName, factoryName, name string, params armdatafactory.LinkedServiceResource, _ *armdatafactory.LinkedServicesClientCreateOrUpdateOptions) (armdatafactory.LinkedServicesClientCreateOrUpdateResponse, error) {
			sawRG, sawFactory, sawName, sent = rgName, factoryName, name, params
			createCalls++
			return armdatafactory.LinkedServicesClientCreateOrUpdateResponse{LinkedServiceResource: keyVaultResult}, nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ *armdatafactory.LinkedServicesClientGetOptions) (armdatafactory.LinkedServicesClientGetResponse, error) {
			return armdatafactory.LinkedServicesClientGetResponse{LinkedServiceResource: keyVaultResult}, nil
		},
		deleteFn: func(_ context.Context, _, _, _ string, _ *armdatafactory.LinkedServicesClientDeleteOptions) (armdatafactory.LinkedServicesClientDeleteResponse, error) {
			deleteCalls++
			return armdatafactory.LinkedServicesClientDeleteResponse{}, nil
		},
		newListByFactoryPagerFn: func(_, _ string, _ *armdatafactory.LinkedServicesClientListByFactoryOptions) *runtime.Pager[armdatafactory.LinkedServicesClientListByFactoryResponse] {
			return runtime.NewPager(runtime.PagingHandler[armdatafactory.LinkedServicesClientListByFactoryResponse]{
				More: func(_ armdatafactory.LinkedServicesClientListByFactoryResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armdatafactory.LinkedServicesClientListByFactoryResponse) (armdatafactory.LinkedServicesClientListByFactoryResponse, error) {
					return armdatafactory.LinkedServicesClientListByFactoryResponse{
						LinkedServiceListResponse: armdatafactory.LinkedServiceListResponse{
							Value: []*armdatafactory.LinkedServiceResource{
								{
									ID: to.Ptr(testLinkedServiceNativeID),
									Properties: &armdatafactory.AzureKeyVaultLinkedService{
										Type: to.Ptr("AzureKeyVault"),
									},
								},
								{
									// A different connector in the same factory:
									// it must not be claimed by this type.
									ID: to.Ptr(testDataFactoryNativeID + "/linkedservices/blob-1"),
									Properties: &armdatafactory.AzureBlobStorageLinkedService{
										Type: to.Ptr("AzureBlobStorage"),
									},
								},
								// No ID and no properties: skipped, not a panic.
								{},
							},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestLinkedService(fake, &dataFactoryLinkedServiceKeyVaultKind)

	keyVaultProps := map[string]any{
		"baseUrl":                          "https://kv-1.vault.azure.net/",
		"description":                      "secrets for the copy pipeline",
		"connectViaIntegrationRuntimeName": "azir-1",
		"annotations":                      []string{"conformance"},
	}

	// LinkedServicesClient has no BeginX: a create reports success directly and
	// never hands back a resume token.
	t.Run("Create_is_synchronous", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "ls-1",
			Properties: linkedServiceDesired(keyVaultProps),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testLinkedServiceNativeID, got.ProgressResult.NativeID)
		require.Empty(t, got.ProgressResult.RequestID)

		require.Equal(t, "rg-1", sawRG)
		require.Equal(t, "adf-1", sawFactory)
		require.Equal(t, "ls-1", sawName)

		ls, ok := sent.Properties.(*armdatafactory.AzureKeyVaultLinkedService)
		require.True(t, ok)
		require.Equal(t, "https://kv-1.vault.azure.net/", ls.TypeProperties.BaseURL)
		require.Equal(t, "secrets for the copy pipeline", *ls.Description)
		require.Equal(t, "azir-1", *ls.ConnectVia.ReferenceName)
		require.Equal(t, []any{"conformance"}, ls.Annotations)
	})

	// An undeclared integration runtime must leave connectVia out of the body so
	// the service routes through the factory's default AutoResolve runtime.
	t.Run("Create_without_connect_via_sends_none", func(t *testing.T) {
		_, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "ls-1",
			Properties: linkedServiceDesired(map[string]any{"baseUrl": "https://kv-1.vault.azure.net/"}),
		})
		require.NoError(t, err)
		ls, ok := sent.Properties.(*armdatafactory.AzureKeyVaultLinkedService)
		require.True(t, ok)
		require.Nil(t, ls.ConnectVia)
		require.Nil(t, ls.Annotations)
		require.Nil(t, ls.Description)
	})

	t.Run("Create_requires_factory", func(t *testing.T) {
		_, err := prov.Create(context.Background(), &resource.CreateRequest{
			Properties: linkedServiceDesired(map[string]any{"factoryName": nil, "baseUrl": "https://kv-1.vault.azure.net/"}),
		})
		require.ErrorContains(t, err, "factoryName is required")
	})

	t.Run("Create_requires_resource_group", func(t *testing.T) {
		_, err := prov.Create(context.Background(), &resource.CreateRequest{
			Properties: linkedServiceDesired(map[string]any{"resourceGroupName": nil, "baseUrl": "https://kv-1.vault.azure.net/"}),
		})
		require.ErrorContains(t, err, "resourceGroupName is required")
	})

	t.Run("Create_falls_back_to_label_for_name", func(t *testing.T) {
		_, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "ls-1",
			Properties: linkedServiceDesired(map[string]any{
				"name": nil, "baseUrl": "https://kv-1.vault.azure.net/",
			}),
		})
		require.NoError(t, err)
		require.Equal(t, "ls-1", sawName)
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testLinkedServiceNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
		require.Equal(t, ResourceTypeDataFactoryLinkedServiceKeyVault, got.ResourceType)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "ls-1", props["name"])
		// Both parents come from the native ID, not the response body.
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "adf-1", props["factoryName"])
		require.Equal(t, "https://kv-1.vault.azure.net/", props["baseUrl"])
		require.Equal(t, "secrets for the copy pipeline", props["description"])
		require.Equal(t, "azir-1", props["connectViaIntegrationRuntimeName"])
		require.Equal(t, []any{"conformance"}, props["annotations"])
	})

	t.Run("Update_reissues_create_or_update", func(t *testing.T) {
		before := createCalls
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID: testLinkedServiceNativeID,
			DesiredProperties: linkedServiceDesired(map[string]any{
				"baseUrl":     "https://kv-2.vault.azure.net/",
				"description": "moved to the shared vault",
			}),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Empty(t, got.ProgressResult.RequestID)
		require.Equal(t, before+1, createCalls)
		ls, ok := sent.Properties.(*armdatafactory.AzureKeyVaultLinkedService)
		require.True(t, ok)
		require.Equal(t, "https://kv-2.vault.azure.net/", ls.TypeProperties.BaseURL)
	})

	t.Run("Delete_is_synchronous", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testLinkedServiceNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _, _ string, _ *armdatafactory.LinkedServicesClientDeleteOptions) (armdatafactory.LinkedServicesClientDeleteResponse, error) {
			return armdatafactory.LinkedServicesClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testLinkedServiceNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	// A linked service still referenced by a dataset cannot be deleted; that
	// arrives as a 400 and must surface with the provider's own reason.
	t.Run("Delete_in_use_maps_to_failure_with_reason", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _, _ string, _ *armdatafactory.LinkedServicesClientDeleteOptions) (armdatafactory.LinkedServicesClientDeleteResponse, error) {
			return armdatafactory.LinkedServicesClientDeleteResponse{},
				&azcore.ResponseError{StatusCode: 400, ErrorCode: "LinkedServiceIsInUse"}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testLinkedServiceNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.Equal(t, resource.OperationErrorCodeInvalidRequest, got.ProgressResult.ErrorCode)
		require.Contains(t, got.ProgressResult.StatusMessage, "LinkedServiceIsInUse")
	})

	// One factory pager returns every connector, so the results must be filtered
	// by discriminator: reading a blob linked service through the Key Vault
	// provisioner would surface the wrong shape.
	t.Run("List_keeps_only_this_connector", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "factoryName": "adf-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testLinkedServiceNativeID}, got.NativeIDs)
	})

	// ARM has no subscription-wide listing here: without both parents there is
	// nothing to page, so List must return empty rather than error.
	t.Run("List_without_parents_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)

		got, err = prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"factoryName": "adf-1"},
		})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure_with_reason", func(t *testing.T) {
		fake.createOrUpdateFn = func(_ context.Context, _, _, _ string, _ armdatafactory.LinkedServiceResource, _ *armdatafactory.LinkedServicesClientCreateOrUpdateOptions) (armdatafactory.LinkedServicesClientCreateOrUpdateResponse, error) {
			return armdatafactory.LinkedServicesClientCreateOrUpdateResponse{},
				&azcore.ResponseError{StatusCode: 404, ErrorCode: "FactoryNotFound"}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "ls-1", Properties: linkedServiceDesired(keyVaultProps),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.Equal(t, resource.OperationErrorCodeNotFound, got.ProgressResult.ErrorCode)
		require.Contains(t, got.ProgressResult.StatusMessage, "FactoryNotFound")
	})
}

func TestDataFactoryLinkedServiceKeyVault(t *testing.T) {
	kind := &dataFactoryLinkedServiceKeyVaultKind
	require.Equal(t, "AzureKeyVault", kind.armType)

	t.Run("requires_base_url", func(t *testing.T) {
		var common dataFactoryLinkedServiceCommon
		payload := linkedServiceDesired(nil)
		require.NoError(t, common.parse(payload, "ls-1"))
		_, err := kind.build(&common, payload)
		require.ErrorContains(t, err, "baseUrl is required")
	})

	t.Run("round_trip", func(t *testing.T) {
		_, props := linkedServiceRoundTrip(t, kind,
			linkedServiceDesired(map[string]any{"baseUrl": "https://kv-1.vault.azure.net/"}))
		require.Equal(t, "https://kv-1.vault.azure.net/", props["baseUrl"])
	})

	// Data Factory types most connector fields as "string, or Expression with
	// resultType string". Only the literal form is expressible in the schema, so
	// an expression object must be reported as absent rather than rendered in
	// Go's map formatting, which no PKL union could match.
	t.Run("an_expression_object_is_not_reported", func(t *testing.T) {
		props := map[string]any{}
		kind.readTypeProperties(&armdatafactory.AzureKeyVaultLinkedService{
			TypeProperties: &armdatafactory.AzureKeyVaultLinkedServiceTypeProperties{
				BaseURL: map[string]any{"type": "Expression", "value": "@pipeline().parameters.vault"},
			},
		}, props)
		require.NotContains(t, props, "baseUrl")
	})
}

func TestDataFactoryLinkedServiceBlobStorage(t *testing.T) {
	kind := &dataFactoryLinkedServiceBlobStorageKind
	require.Equal(t, "AzureBlobStorage", kind.armType)

	build := func(t *testing.T, overrides map[string]any) (armdatafactory.LinkedServiceClassification, error) {
		t.Helper()
		var common dataFactoryLinkedServiceCommon
		payload := linkedServiceDesired(overrides)
		require.NoError(t, common.parse(payload, "ls-1"))
		return kind.build(&common, payload)
	}

	// The two authentication shapes are mutually exclusive in ARM, and that check
	// belongs here so the mistake fails before any ARM call rather than as an
	// opaque 400.
	t.Run("rejects_both_endpoint_and_connection_string", func(t *testing.T) {
		_, err := build(t, map[string]any{
			"serviceEndpoint":  "https://sa1.blob.core.windows.net",
			"connectionString": "DefaultEndpointsProtocol=https;AccountName=sa1;",
		})
		require.ErrorContains(t, err, "mutually exclusive")
	})

	t.Run("rejects_neither", func(t *testing.T) {
		_, err := build(t, nil)
		require.ErrorContains(t, err, "one of serviceEndpoint or connectionString is required")
	})

	// The managed-identity shape: nothing secret is stored anywhere, and the
	// endpoint really does round trip.
	t.Run("service_endpoint_round_trip", func(t *testing.T) {
		_, props := linkedServiceRoundTrip(t, kind, linkedServiceDesired(map[string]any{
			"serviceEndpoint": "https://sa1.blob.core.windows.net",
			"accountKind":     "StorageV2",
		}))
		require.Equal(t, "https://sa1.blob.core.windows.net", props["serviceEndpoint"])
		require.Equal(t, "StorageV2", props["accountKind"])
	})

	// A connection string is always wrapped in SecureString so the service stores
	// it encrypted, and it is never read back: ARM returns only a mask.
	t.Run("connection_string_is_secured_and_never_read_back", func(t *testing.T) {
		built, props := linkedServiceRoundTrip(t, kind, linkedServiceDesired(map[string]any{
			"connectionString": "DefaultEndpointsProtocol=https;AccountName=sa1;AccountKey=k;",
		}))
		ls, ok := built.(*armdatafactory.AzureBlobStorageLinkedService)
		require.True(t, ok)
		secret, ok := ls.TypeProperties.ConnectionString.(*armdatafactory.SecureString)
		require.True(t, ok)
		require.Equal(t, "SecureString", *secret.Type)
		require.NotContains(t, props, "connectionString")
	})

	t.Run("accountKind_casing_is_canonicalized", func(t *testing.T) {
		props := map[string]any{}
		kind.readTypeProperties(&armdatafactory.AzureBlobStorageLinkedService{
			TypeProperties: &armdatafactory.AzureBlobStorageLinkedServiceTypeProperties{
				AccountKind: to.Ptr("storagev2"),
			},
		}, props)
		require.Equal(t, "StorageV2", props["accountKind"])
	})
}

func TestDataFactoryLinkedServiceSqlDatabase(t *testing.T) {
	kind := &dataFactoryLinkedServiceSQLDatabaseKind
	require.Equal(t, "AzureSqlDatabase", kind.armType)

	t.Run("requires_connection_string", func(t *testing.T) {
		var common dataFactoryLinkedServiceCommon
		payload := linkedServiceDesired(nil)
		require.NoError(t, common.parse(payload, "ls-1"))
		_, err := kind.build(&common, payload)
		require.ErrorContains(t, err, "connectionString is required")
	})

	t.Run("connection_string_is_secured_and_never_read_back", func(t *testing.T) {
		built, props := linkedServiceRoundTrip(t, kind, linkedServiceDesired(map[string]any{
			"connectionString":   "Data Source=tcp:srv.database.windows.net,1433;Initial Catalog=db;",
			"servicePrincipalId": "33333333-3333-3333-3333-333333333333",
			"tenant":             "22222222-2222-2222-2222-222222222222",
		}))
		ls, ok := built.(*armdatafactory.AzureSQLDatabaseLinkedService)
		require.True(t, ok)
		secret, ok := ls.TypeProperties.ConnectionString.(*armdatafactory.SecureString)
		require.True(t, ok)
		require.Equal(t, "SecureString", *secret.Type)

		require.NotContains(t, props, "connectionString")
		require.Equal(t, "33333333-3333-3333-3333-333333333333", props["servicePrincipalId"])
		require.Equal(t, "22222222-2222-2222-2222-222222222222", props["tenant"])
	})
}

func TestDataFactoryLinkedServiceWeb(t *testing.T) {
	kind := &dataFactoryLinkedServiceWebKind
	require.Equal(t, "Web", kind.armType)

	build := func(t *testing.T, overrides map[string]any) (armdatafactory.LinkedServiceClassification, error) {
		t.Helper()
		var common dataFactoryLinkedServiceCommon
		payload := linkedServiceDesired(overrides)
		require.NoError(t, common.parse(payload, "ls-1"))
		return kind.build(&common, payload)
	}

	t.Run("requires_url", func(t *testing.T) {
		_, err := build(t, map[string]any{"authenticationType": "Anonymous"})
		require.ErrorContains(t, err, "url is required")
	})

	t.Run("requires_authentication_type", func(t *testing.T) {
		_, err := build(t, map[string]any{"url": "https://api.example.com"})
		require.ErrorContains(t, err, "authenticationType is required")
	})

	// ClientCertificate needs a base64 PFX and its password, neither of which ARM
	// ever returns, so it is refused rather than created-but-unverifiable.
	t.Run("rejects_client_certificate", func(t *testing.T) {
		_, err := build(t, map[string]any{
			"url": "https://api.example.com", "authenticationType": "ClientCertificate",
		})
		require.ErrorContains(t, err, "Anonymous or Basic")
	})

	t.Run("basic_requires_username_and_password", func(t *testing.T) {
		_, err := build(t, map[string]any{
			"url": "https://api.example.com", "authenticationType": "Basic",
		})
		require.ErrorContains(t, err, "username is required")

		_, err = build(t, map[string]any{
			"url": "https://api.example.com", "authenticationType": "Basic", "username": "svc",
		})
		require.ErrorContains(t, err, "password is required")
	})

	t.Run("anonymous_round_trip", func(t *testing.T) {
		built, props := linkedServiceRoundTrip(t, kind, linkedServiceDesired(map[string]any{
			"url": "https://api.example.com/v1/rows", "authenticationType": "Anonymous",
		}))
		_, ok := built.(*armdatafactory.WebLinkedService).TypeProperties.(*armdatafactory.WebAnonymousAuthentication)
		require.True(t, ok)
		require.Equal(t, "https://api.example.com/v1/rows", props["url"])
		require.Equal(t, "Anonymous", props["authenticationType"])
		require.NotContains(t, props, "username")
	})

	t.Run("basic_round_trip_never_reads_the_password_back", func(t *testing.T) {
		built, props := linkedServiceRoundTrip(t, kind, linkedServiceDesired(map[string]any{
			"url": "https://api.example.com/v1/rows", "authenticationType": "Basic",
			"username": "svc", "password": "s3cret",
		}))
		basic, ok := built.(*armdatafactory.WebLinkedService).TypeProperties.(*armdatafactory.WebBasicAuthentication)
		require.True(t, ok)
		secret, ok := basic.Password.(*armdatafactory.SecureString)
		require.True(t, ok)
		require.Equal(t, "SecureString", *secret.Type)

		require.Equal(t, "Basic", props["authenticationType"])
		require.Equal(t, "svc", props["username"])
		require.NotContains(t, props, "password")
	})
}

func TestDataFactoryLinkedServiceTableStorage(t *testing.T) {
	kind := &dataFactoryLinkedServiceTableStorageKind
	require.Equal(t, "AzureTableStorage", kind.armType)

	t.Run("requires_connection_string", func(t *testing.T) {
		var common dataFactoryLinkedServiceCommon
		payload := linkedServiceDesired(nil)
		require.NoError(t, common.parse(payload, "ls-1"))
		_, err := kind.build(&common, payload)
		require.ErrorContains(t, err, "connectionString is required")
	})

	// There is no managed-identity endpoint form for table storage, so the
	// connection string is the only configuration — and it is write-only.
	t.Run("connection_string_is_secured_and_never_read_back", func(t *testing.T) {
		built, props := linkedServiceRoundTrip(t, kind, linkedServiceDesired(map[string]any{
			"connectionString": "DefaultEndpointsProtocol=https;AccountName=sa1;EndpointSuffix=core.windows.net",
			"description":      "conformance table store",
		}))
		ls, ok := built.(*armdatafactory.AzureTableStorageLinkedService)
		require.True(t, ok)
		secret, ok := ls.TypeProperties.ConnectionString.(*armdatafactory.SecureString)
		require.True(t, ok)
		require.Equal(t, "SecureString", *secret.Type)

		require.NotContains(t, props, "connectionString")
		require.Equal(t, "conformance table store", props["description"])
	})
}

// Every one of the five must be reachable by its own AZURE:: type name, and each
// must claim a distinct ARM discriminator — two kinds sharing one would make
// List hand the same IDs to two provisioners.
func TestDataFactoryLinkedServiceKindsAreDistinct(t *testing.T) {
	kinds := []*linkedServiceKind{
		&dataFactoryLinkedServiceKeyVaultKind,
		&dataFactoryLinkedServiceBlobStorageKind,
		&dataFactoryLinkedServiceSQLDatabaseKind,
		&dataFactoryLinkedServiceWebKind,
		&dataFactoryLinkedServiceTableStorageKind,
	}
	seenType := map[string]bool{}
	seenARM := map[string]bool{}
	for _, kind := range kinds {
		require.NotEmpty(t, kind.resourceType)
		require.NotEmpty(t, kind.armType)
		require.False(t, seenType[kind.resourceType], "duplicate resource type %s", kind.resourceType)
		require.False(t, seenARM[kind.armType], "duplicate ARM discriminator %s", kind.armType)
		seenType[kind.resourceType] = true
		seenARM[kind.armType] = true
	}
	require.Len(t, seenType, 5)
}

func TestDataFactoryLinkedService_ReadNotFound(t *testing.T) {
	fake := &fakeLinkedServicesAPI{
		getFn: func(_ context.Context, _, _, _ string, _ *armdatafactory.LinkedServicesClientGetOptions) (armdatafactory.LinkedServicesClientGetResponse, error) {
			return armdatafactory.LinkedServicesClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestLinkedService(fake, &dataFactoryLinkedServiceKeyVaultKind).
		Read(context.Background(), &resource.ReadRequest{NativeID: testLinkedServiceNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// Reading a connector of another kind must degrade to the shared fields rather
// than panicking on the type assertion.
func TestDataFactoryLinkedService_ReadOfWrongKindIsSafe(t *testing.T) {
	fake := &fakeLinkedServicesAPI{
		getFn: func(_ context.Context, _, _, _ string, _ *armdatafactory.LinkedServicesClientGetOptions) (armdatafactory.LinkedServicesClientGetResponse, error) {
			return armdatafactory.LinkedServicesClientGetResponse{
				LinkedServiceResource: armdatafactory.LinkedServiceResource{
					ID:   to.Ptr(testLinkedServiceNativeID),
					Name: to.Ptr("ls-1"),
					Properties: &armdatafactory.AzureBlobStorageLinkedService{
						Type: to.Ptr("AzureBlobStorage"),
					},
				},
			}, nil
		},
	}
	got, err := newTestLinkedService(fake, &dataFactoryLinkedServiceKeyVaultKind).
		Read(context.Background(), &resource.ReadRequest{NativeID: testLinkedServiceNativeID})
	require.NoError(t, err)
	require.NotContains(t, got.Properties, "baseUrl")
}

func TestDataFactoryLinkedService_StatusIsAlwaysDone(t *testing.T) {
	got, err := newTestLinkedService(&fakeLinkedServicesAPI{}, &dataFactoryLinkedServiceKeyVaultKind).
		Status(context.Background(), &resource.StatusRequest{RequestID: "anything"})
	require.NoError(t, err)
	require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
}

// --- Test helpers ---

type fakeLinkedServicesAPI struct {
	createOrUpdateFn        func(ctx context.Context, rgName, factoryName, name string, params armdatafactory.LinkedServiceResource, options *armdatafactory.LinkedServicesClientCreateOrUpdateOptions) (armdatafactory.LinkedServicesClientCreateOrUpdateResponse, error)
	getFn                   func(ctx context.Context, rgName, factoryName, name string, options *armdatafactory.LinkedServicesClientGetOptions) (armdatafactory.LinkedServicesClientGetResponse, error)
	deleteFn                func(ctx context.Context, rgName, factoryName, name string, options *armdatafactory.LinkedServicesClientDeleteOptions) (armdatafactory.LinkedServicesClientDeleteResponse, error)
	newListByFactoryPagerFn func(rgName, factoryName string, options *armdatafactory.LinkedServicesClientListByFactoryOptions) *runtime.Pager[armdatafactory.LinkedServicesClientListByFactoryResponse]
}

func (f *fakeLinkedServicesAPI) CreateOrUpdate(ctx context.Context, rgName, factoryName, name string, params armdatafactory.LinkedServiceResource, options *armdatafactory.LinkedServicesClientCreateOrUpdateOptions) (armdatafactory.LinkedServicesClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, factoryName, name, params, options)
}

func (f *fakeLinkedServicesAPI) Get(ctx context.Context, rgName, factoryName, name string, options *armdatafactory.LinkedServicesClientGetOptions) (armdatafactory.LinkedServicesClientGetResponse, error) {
	return f.getFn(ctx, rgName, factoryName, name, options)
}

func (f *fakeLinkedServicesAPI) Delete(ctx context.Context, rgName, factoryName, name string, options *armdatafactory.LinkedServicesClientDeleteOptions) (armdatafactory.LinkedServicesClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, factoryName, name, options)
}

func (f *fakeLinkedServicesAPI) NewListByFactoryPager(rgName, factoryName string, options *armdatafactory.LinkedServicesClientListByFactoryOptions) *runtime.Pager[armdatafactory.LinkedServicesClientListByFactoryResponse] {
	return f.newListByFactoryPagerFn(rgName, factoryName, options)
}
