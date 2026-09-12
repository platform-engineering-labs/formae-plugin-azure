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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/apimanagement/armapimanagement"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testApimCertificateNativeID = testApimServiceNativeID + "/certificates/client-cert"

func newTestApiManagementCertificate(api apiManagementCertificatesAPI) *ApiManagementCertificate {
	return &ApiManagementCertificate{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func apimCertificateDesired(data string) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":              "client-cert",
		"resourceGroupName": "rg-1",
		"serviceName":       "apim1",
		"data":              data,
		"password":          "FormaeConformance1!",
	})
	return out
}

func TestApiManagementCertificate_CRUD(t *testing.T) {
	// ARM answers with what it read out of the blob, never with the blob.
	certResult := armapimanagement.CertificateContract{
		ID:   to.Ptr(testApimCertificateNativeID),
		Name: to.Ptr("client-cert"),
		Properties: &armapimanagement.CertificateContractProperties{
			Subject:        to.Ptr("CN=conformance.formae.invalid, O=Platform Engineering Labs"),
			Thumbprint:     to.Ptr("23F9147E614CDED1036B189E24FD052555A9A1C8"),
			ExpirationDate: to.Ptr(time.Date(2056, 8, 25, 17, 1, 30, 0, time.UTC)),
		},
	}

	var sentCreate armapimanagement.CertificateCreateOrUpdateParameters
	var sawIfMatch string
	createCalls := 0
	deleteCalls := 0
	fake := &fakeApiManagementCertificatesAPI{
		createOrUpdateFn: func(_ context.Context, _, serviceName, certificateID string, params armapimanagement.CertificateCreateOrUpdateParameters, _ *armapimanagement.CertificateClientCreateOrUpdateOptions) (armapimanagement.CertificateClientCreateOrUpdateResponse, error) {
			require.Equal(t, "apim1", serviceName)
			require.NotEmpty(t, certificateID)
			sentCreate = params
			createCalls++
			return armapimanagement.CertificateClientCreateOrUpdateResponse{CertificateContract: certResult}, nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ *armapimanagement.CertificateClientGetOptions) (armapimanagement.CertificateClientGetResponse, error) {
			return armapimanagement.CertificateClientGetResponse{CertificateContract: certResult}, nil
		},
		deleteFn: func(_ context.Context, _, _, _, ifMatch string, _ *armapimanagement.CertificateClientDeleteOptions) (armapimanagement.CertificateClientDeleteResponse, error) {
			sawIfMatch = ifMatch
			deleteCalls++
			return armapimanagement.CertificateClientDeleteResponse{}, nil
		},
		newListByServicePagerFn: func(_, _ string, _ *armapimanagement.CertificateClientListByServiceOptions) *runtime.Pager[armapimanagement.CertificateClientListByServiceResponse] {
			return runtime.NewPager(runtime.PagingHandler[armapimanagement.CertificateClientListByServiceResponse]{
				More: func(_ armapimanagement.CertificateClientListByServiceResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armapimanagement.CertificateClientListByServiceResponse) (armapimanagement.CertificateClientListByServiceResponse, error) {
					return armapimanagement.CertificateClientListByServiceResponse{
						CertificateCollection: armapimanagement.CertificateCollection{
							Value: []*armapimanagement.CertificateContract{{ID: to.Ptr(testApimCertificateNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestApiManagementCertificate(fake)

	t.Run("Create_sends_the_blob_and_its_password", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "client-cert",
			Properties: apimCertificateDesired("MIIKfQIBAzCCCjcGCS"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testApimCertificateNativeID, got.ProgressResult.NativeID)
		require.Empty(t, got.ProgressResult.RequestID)
		require.Equal(t, "MIIKfQIBAzCCCjcGCS", *sentCreate.Properties.Data)
		require.Equal(t, "FormaeConformance1!", *sentCreate.Properties.Password)
		require.Nil(t, sentCreate.Properties.KeyVault)

		// Neither half of the blob is echoed back: ARM does not return them.
		var props map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &props))
		require.NotContains(t, props, "data")
		require.NotContains(t, props, "password")
	})

	t.Run("Create_sends_a_key_vault_block_instead_of_a_blob", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "vault-cert", "resourceGroupName": "rg-1", "serviceName": "apim1",
			"keyVaultSecretIdentifier": "https://vault.vault.azure.net/secrets/client-cert",
			"keyVaultIdentityClientId": "11111111-2222-3333-4444-555555555555",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.Nil(t, sentCreate.Properties.Data)
		require.Equal(t, "https://vault.vault.azure.net/secrets/client-cert",
			*sentCreate.Properties.KeyVault.SecretIdentifier)
		require.Equal(t, "11111111-2222-3333-4444-555555555555",
			*sentCreate.Properties.KeyVault.IdentityClientID)
	})

	t.Run("Create_rejects_neither_or_both_certificate_sources", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "c", "resourceGroupName": "rg-1", "serviceName": "apim1",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "either data or keyVaultSecretIdentifier is required")

		props, _ = json.Marshal(map[string]any{
			"name": "c", "resourceGroupName": "rg-1", "serviceName": "apim1",
			"data": "MIIK", "keyVaultSecretIdentifier": "https://vault.vault.azure.net/secrets/c",
		})
		_, err = prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "mutually exclusive")
	})

	t.Run("Read_reports_what_ARM_read_out_of_the_certificate", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testApimCertificateNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "client-cert", props["name"])
		require.Equal(t, "CN=conformance.formae.invalid, O=Platform Engineering Labs", props["subject"])
		require.Equal(t, "23F9147E614CDED1036B189E24FD052555A9A1C8", props["thumbprint"])
		require.Equal(t, "2056-08-25T17:01:30Z", props["expirationDate"])
		require.NotContains(t, props, "data")
		require.NotContains(t, props, "password")
	})

	t.Run("Update_re_puts_because_there_is_no_patch_verb", func(t *testing.T) {
		before := createCalls
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testApimCertificateNativeID,
			DesiredProperties: apimCertificateDesired("MIIKfQIBAzCCCjcGCS-rotated"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, createCalls)
		require.Equal(t, "MIIKfQIBAzCCCjcGCS-rotated", *sentCreate.Properties.Data)
	})

	t.Run("Delete_is_synchronous", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testApimCertificateNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
		require.Equal(t, "*", sawIfMatch)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _, _, _ string, _ *armapimanagement.CertificateClientDeleteOptions) (armapimanagement.CertificateClientDeleteResponse, error) {
			return armapimanagement.CertificateClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testApimCertificateNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_service", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "serviceName": "apim1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testApimCertificateNativeID}, got.NativeIDs)
	})

	t.Run("List_without_parents_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})

	// ARM parses the PKCS#12 blob on the way in, so a malformed or expired
	// certificate fails here rather than at first use. The reason has to reach
	// StatusMessage or the failure is unexplainable.
	t.Run("Azure_error_maps_to_failure_with_a_reason", func(t *testing.T) {
		fake.createOrUpdateFn = func(_ context.Context, _, _, _ string, _ armapimanagement.CertificateCreateOrUpdateParameters, _ *armapimanagement.CertificateClientCreateOrUpdateOptions) (armapimanagement.CertificateClientCreateOrUpdateResponse, error) {
			return armapimanagement.CertificateClientCreateOrUpdateResponse{}, &azcore.ResponseError{StatusCode: 400}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "client-cert", Properties: apimCertificateDesired("not-a-pfx"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.NotEmpty(t, got.ProgressResult.StatusMessage)
	})
}

func TestApiManagementCertificate_ReadNotFound(t *testing.T) {
	fake := &fakeApiManagementCertificatesAPI{
		getFn: func(_ context.Context, _, _, _ string, _ *armapimanagement.CertificateClientGetOptions) (armapimanagement.CertificateClientGetResponse, error) {
			return armapimanagement.CertificateClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestApiManagementCertificate(fake).Read(context.Background(),
		&resource.ReadRequest{NativeID: testApimCertificateNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeApiManagementCertificatesAPI struct {
	createOrUpdateFn        func(ctx context.Context, rgName, serviceName, certificateID string, params armapimanagement.CertificateCreateOrUpdateParameters, options *armapimanagement.CertificateClientCreateOrUpdateOptions) (armapimanagement.CertificateClientCreateOrUpdateResponse, error)
	getFn                   func(ctx context.Context, rgName, serviceName, certificateID string, options *armapimanagement.CertificateClientGetOptions) (armapimanagement.CertificateClientGetResponse, error)
	deleteFn                func(ctx context.Context, rgName, serviceName, certificateID, ifMatch string, options *armapimanagement.CertificateClientDeleteOptions) (armapimanagement.CertificateClientDeleteResponse, error)
	newListByServicePagerFn func(rgName, serviceName string, options *armapimanagement.CertificateClientListByServiceOptions) *runtime.Pager[armapimanagement.CertificateClientListByServiceResponse]
}

func (f *fakeApiManagementCertificatesAPI) CreateOrUpdate(ctx context.Context, rgName, serviceName, certificateID string, params armapimanagement.CertificateCreateOrUpdateParameters, options *armapimanagement.CertificateClientCreateOrUpdateOptions) (armapimanagement.CertificateClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, serviceName, certificateID, params, options)
}

func (f *fakeApiManagementCertificatesAPI) Get(ctx context.Context, rgName, serviceName, certificateID string, options *armapimanagement.CertificateClientGetOptions) (armapimanagement.CertificateClientGetResponse, error) {
	return f.getFn(ctx, rgName, serviceName, certificateID, options)
}

func (f *fakeApiManagementCertificatesAPI) Delete(ctx context.Context, rgName, serviceName, certificateID, ifMatch string, options *armapimanagement.CertificateClientDeleteOptions) (armapimanagement.CertificateClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, serviceName, certificateID, ifMatch, options)
}

func (f *fakeApiManagementCertificatesAPI) NewListByServicePager(rgName, serviceName string, options *armapimanagement.CertificateClientListByServiceOptions) *runtime.Pager[armapimanagement.CertificateClientListByServiceResponse] {
	return f.newListByServicePagerFn(rgName, serviceName, options)
}
