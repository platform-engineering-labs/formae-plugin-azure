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

const testApimNamedValueNativeID = testApimServiceNativeID + "/namedValues/backend-url"

func newTestApiManagementNamedValue(api apiManagementNamedValuesAPI) *ApiManagementNamedValue {
	return &ApiManagementNamedValue{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func apimNamedValueDesired(value string) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":              "backend-url",
		"resourceGroupName": "rg-1",
		"serviceName":       "apim1",
		"displayName":       "backend-url",
		"value":             value,
		"secret":            false,
		"tags":              []string{"conformance"},
	})
	return out
}

func TestApiManagementNamedValue_CRUD(t *testing.T) {
	// Note what ARM does NOT return: the value. Reporting it back is what would
	// show drift on every sync, which is why the schema makes it write-only.
	nvResult := armapimanagement.NamedValueContract{
		ID:   to.Ptr(testApimNamedValueNativeID),
		Name: to.Ptr("backend-url"),
		Properties: &armapimanagement.NamedValueContractProperties{
			DisplayName: to.Ptr("backend-url"),
			Secret:      to.Ptr(false),
			Tags:        []*string{to.Ptr("conformance")},
		},
	}

	var sentCreate armapimanagement.NamedValueCreateContract
	var sawCreateName string
	var sentUpdate armapimanagement.NamedValueUpdateParameters
	var sawIfMatch string
	deleteCalls := 0
	fake := &fakeApiManagementNamedValuesAPI{
		beginCreateOrUpdateFn: func(_ context.Context, _, serviceName, namedValueID string, params armapimanagement.NamedValueCreateContract, _ *armapimanagement.NamedValueClientBeginCreateOrUpdateOptions) (*runtime.Poller[armapimanagement.NamedValueClientCreateOrUpdateResponse], error) {
			require.Equal(t, "apim1", serviceName)
			sawCreateName = namedValueID
			sentCreate = params
			return newDonePoller(armapimanagement.NamedValueClientCreateOrUpdateResponse{
				NamedValueContract: nvResult,
			}), nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ *armapimanagement.NamedValueClientGetOptions) (armapimanagement.NamedValueClientGetResponse, error) {
			return armapimanagement.NamedValueClientGetResponse{NamedValueContract: nvResult}, nil
		},
		beginUpdateFn: func(_ context.Context, _, _, _, ifMatch string, params armapimanagement.NamedValueUpdateParameters, _ *armapimanagement.NamedValueClientBeginUpdateOptions) (*runtime.Poller[armapimanagement.NamedValueClientUpdateResponse], error) {
			sawIfMatch = ifMatch
			sentUpdate = params
			return newDonePoller(armapimanagement.NamedValueClientUpdateResponse{
				NamedValueContract: nvResult,
			}), nil
		},
		deleteFn: func(_ context.Context, _, _, _, ifMatch string, _ *armapimanagement.NamedValueClientDeleteOptions) (armapimanagement.NamedValueClientDeleteResponse, error) {
			sawIfMatch = ifMatch
			deleteCalls++
			return armapimanagement.NamedValueClientDeleteResponse{}, nil
		},
		newListByServicePagerFn: func(_, _ string, _ *armapimanagement.NamedValueClientListByServiceOptions) *runtime.Pager[armapimanagement.NamedValueClientListByServiceResponse] {
			return runtime.NewPager(runtime.PagingHandler[armapimanagement.NamedValueClientListByServiceResponse]{
				More: func(_ armapimanagement.NamedValueClientListByServiceResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armapimanagement.NamedValueClientListByServiceResponse) (armapimanagement.NamedValueClientListByServiceResponse, error) {
					return armapimanagement.NamedValueClientListByServiceResponse{
						NamedValueCollection: armapimanagement.NamedValueCollection{
							Value: []*armapimanagement.NamedValueContract{{ID: to.Ptr(testApimNamedValueNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestApiManagementNamedValue(fake)

	t.Run("Create_completes_when_the_poller_is_already_done", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "backend-url",
			Properties: apimNamedValueDesired("https://echo.platform.engineering"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testApimNamedValueNativeID, got.ProgressResult.NativeID)
		require.Empty(t, got.ProgressResult.RequestID)
		require.Equal(t, "backend-url", sawCreateName)
		require.Equal(t, "https://echo.platform.engineering", *sentCreate.Properties.Value)
		require.Equal(t, []*string{to.Ptr("conformance")}, sentCreate.Properties.Tags)
		// An inline value carries no Key Vault block.
		require.Nil(t, sentCreate.Properties.KeyVault)

		var props map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &props))
		require.NotContains(t, props, "value")
		require.Equal(t, []any{"conformance"}, props["tags"])
	})

	t.Run("Create_sends_a_key_vault_block_instead_of_a_value", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "vault-secret", "resourceGroupName": "rg-1", "serviceName": "apim1",
			"displayName": "vault-secret", "secret": true,
			"keyVaultSecretIdentifier": "https://vault.vault.azure.net/secrets/backend-key",
			"keyVaultIdentityClientId": "11111111-2222-3333-4444-555555555555",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.Nil(t, sentCreate.Properties.Value)
		require.Equal(t, "https://vault.vault.azure.net/secrets/backend-key",
			*sentCreate.Properties.KeyVault.SecretIdentifier)
		require.Equal(t, "11111111-2222-3333-4444-555555555555",
			*sentCreate.Properties.KeyVault.IdentityClientID)
	})

	t.Run("Create_rejects_neither_or_both_value_sources", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "nv", "resourceGroupName": "rg-1", "serviceName": "apim1", "displayName": "nv",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "either value or keyVaultSecretIdentifier is required")

		props, _ = json.Marshal(map[string]any{
			"name": "nv", "resourceGroupName": "rg-1", "serviceName": "apim1", "displayName": "nv",
			"value": "x", "keyVaultSecretIdentifier": "https://vault.vault.azure.net/secrets/s",
		})
		_, err = prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "mutually exclusive")
	})

	t.Run("Create_requires_display_name", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "nv", "resourceGroupName": "rg-1", "serviceName": "apim1", "value": "x",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "displayName is required")
	})

	t.Run("Create_pins_the_native_ID_while_the_LRO_runs", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _, _ string, _ armapimanagement.NamedValueCreateContract, _ *armapimanagement.NamedValueClientBeginCreateOrUpdateOptions) (*runtime.Poller[armapimanagement.NamedValueClientCreateOrUpdateResponse], error) {
			return newPendingPoller[armapimanagement.NamedValueClientCreateOrUpdateResponse](), nil
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "backend-url",
			Properties: apimNamedValueDesired("https://echo.platform.engineering"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusInProgress, got.ProgressResult.OperationStatus)
		require.Equal(t, testApimNamedValueNativeID, got.ProgressResult.NativeID)
		require.NotEmpty(t, got.ProgressResult.RequestID)

		reqID, err := decodeLROStatus(got.ProgressResult.RequestID)
		require.NoError(t, err)
		require.Equal(t, lroOpCreate, reqID.OperationType)
		require.Equal(t, testApimNamedValueNativeID, reqID.NativeID)
	})

	t.Run("Read_never_reports_the_value", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testApimNamedValueNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "backend-url", props["name"])
		require.Equal(t, "backend-url", props["displayName"])
		require.Equal(t, false, props["secret"])
		require.NotContains(t, props, "value")
	})

	t.Run("Update_uses_the_LRO_patch_with_wildcard_if_match", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testApimNamedValueNativeID,
			DesiredProperties: apimNamedValueDesired("https://echo2.platform.engineering"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, "*", sawIfMatch)
		require.Equal(t, "https://echo2.platform.engineering", *sentUpdate.Properties.Value)
	})

	t.Run("Delete_is_synchronous", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testApimNamedValueNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
		require.Equal(t, "*", sawIfMatch)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _, _, _ string, _ *armapimanagement.NamedValueClientDeleteOptions) (armapimanagement.NamedValueClientDeleteResponse, error) {
			return armapimanagement.NamedValueClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testApimNamedValueNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_service", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "serviceName": "apim1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testApimNamedValueNativeID}, got.NativeIDs)
	})

	t.Run("List_without_parents_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure_with_a_reason", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _, _ string, _ armapimanagement.NamedValueCreateContract, _ *armapimanagement.NamedValueClientBeginCreateOrUpdateOptions) (*runtime.Poller[armapimanagement.NamedValueClientCreateOrUpdateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 400}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "backend-url",
			Properties: apimNamedValueDesired("https://echo.platform.engineering"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.NotEmpty(t, got.ProgressResult.StatusMessage)
	})
}

func TestApiManagementNamedValue_ReadNotFound(t *testing.T) {
	fake := &fakeApiManagementNamedValuesAPI{
		getFn: func(_ context.Context, _, _, _ string, _ *armapimanagement.NamedValueClientGetOptions) (armapimanagement.NamedValueClientGetResponse, error) {
			return armapimanagement.NamedValueClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestApiManagementNamedValue(fake).Read(context.Background(),
		&resource.ReadRequest{NativeID: testApimNamedValueNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

func TestApiManagementNamedValue_StatusRejectsAnUnknownOperation(t *testing.T) {
	reqID, err := encodeLROStart("nonsense", "token", testApimNamedValueNativeID)
	require.NoError(t, err)
	got, err := newTestApiManagementNamedValue(&fakeApiManagementNamedValuesAPI{}).Status(
		context.Background(), &resource.StatusRequest{RequestID: reqID})
	require.Error(t, err)
	require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
}

// --- Test helpers ---

type fakeApiManagementNamedValuesAPI struct {
	beginCreateOrUpdateFn   func(ctx context.Context, rgName, serviceName, namedValueID string, params armapimanagement.NamedValueCreateContract, options *armapimanagement.NamedValueClientBeginCreateOrUpdateOptions) (*runtime.Poller[armapimanagement.NamedValueClientCreateOrUpdateResponse], error)
	getFn                   func(ctx context.Context, rgName, serviceName, namedValueID string, options *armapimanagement.NamedValueClientGetOptions) (armapimanagement.NamedValueClientGetResponse, error)
	beginUpdateFn           func(ctx context.Context, rgName, serviceName, namedValueID, ifMatch string, params armapimanagement.NamedValueUpdateParameters, options *armapimanagement.NamedValueClientBeginUpdateOptions) (*runtime.Poller[armapimanagement.NamedValueClientUpdateResponse], error)
	deleteFn                func(ctx context.Context, rgName, serviceName, namedValueID, ifMatch string, options *armapimanagement.NamedValueClientDeleteOptions) (armapimanagement.NamedValueClientDeleteResponse, error)
	newListByServicePagerFn func(rgName, serviceName string, options *armapimanagement.NamedValueClientListByServiceOptions) *runtime.Pager[armapimanagement.NamedValueClientListByServiceResponse]
}

func (f *fakeApiManagementNamedValuesAPI) BeginCreateOrUpdate(ctx context.Context, rgName, serviceName, namedValueID string, params armapimanagement.NamedValueCreateContract, options *armapimanagement.NamedValueClientBeginCreateOrUpdateOptions) (*runtime.Poller[armapimanagement.NamedValueClientCreateOrUpdateResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, rgName, serviceName, namedValueID, params, options)
}

func (f *fakeApiManagementNamedValuesAPI) Get(ctx context.Context, rgName, serviceName, namedValueID string, options *armapimanagement.NamedValueClientGetOptions) (armapimanagement.NamedValueClientGetResponse, error) {
	return f.getFn(ctx, rgName, serviceName, namedValueID, options)
}

func (f *fakeApiManagementNamedValuesAPI) BeginUpdate(ctx context.Context, rgName, serviceName, namedValueID, ifMatch string, params armapimanagement.NamedValueUpdateParameters, options *armapimanagement.NamedValueClientBeginUpdateOptions) (*runtime.Poller[armapimanagement.NamedValueClientUpdateResponse], error) {
	return f.beginUpdateFn(ctx, rgName, serviceName, namedValueID, ifMatch, params, options)
}

func (f *fakeApiManagementNamedValuesAPI) Delete(ctx context.Context, rgName, serviceName, namedValueID, ifMatch string, options *armapimanagement.NamedValueClientDeleteOptions) (armapimanagement.NamedValueClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, serviceName, namedValueID, ifMatch, options)
}

func (f *fakeApiManagementNamedValuesAPI) NewListByServicePager(rgName, serviceName string, options *armapimanagement.NamedValueClientListByServiceOptions) *runtime.Pager[armapimanagement.NamedValueClientListByServiceResponse] {
	return f.newListByServicePagerFn(rgName, serviceName, options)
}
