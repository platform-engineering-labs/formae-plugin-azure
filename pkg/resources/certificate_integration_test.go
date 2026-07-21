// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build integration

package resources

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const (
	testCertVaultURI = "https://my-vault.vault.azure.net/"
	testCertName     = "formae-test-cert"
	testCertNativeID = "https://my-vault.vault.azure.net/certificates/formae-test-cert"
	testCertSecretID = "https://my-vault.vault.azure.net/secrets/formae-test-cert/v1"
	testCertKID      = "https://my-vault.vault.azure.net/keys/formae-test-cert/v1"
)

func newTestKeyVaultCertificate(api certificatesAPI) *KeyVaultCertificate {
	return &KeyVaultCertificate{
		config: &config.Config{SubscriptionId: "sub-1"},
		newAPI: func(string) (certificatesAPI, error) { return api, nil },
	}
}

func certID(version string) *azcertificates.ID {
	id := azcertificates.ID(testCertNativeID + "/" + version)
	return &id
}

func certSID() *azcertificates.ID {
	id := azcertificates.ID(testCertSecretID)
	return &id
}

func certKID() *azcertificates.ID {
	id := azcertificates.ID(testCertKID)
	return &id
}

// fullCertificate is the metadata-bearing bundle returned by Get/Update/Import.
func fullCertificate(tags map[string]*string) azcertificates.Certificate {
	return azcertificates.Certificate{
		ID:             certID("v1"),
		SID:            certSID(),
		KID:            certKID(),
		X509Thumbprint: []byte{0x01, 0x02, 0x03, 0x04},
		Attributes:     &azcertificates.CertificateAttributes{Enabled: to.Ptr(true)},
		Tags:           tags,
	}
}

func TestKeyVaultCertificate_CRUD(t *testing.T) {
	fake := &fakeCertificatesAPI{
		createCertificateFn: func(_ context.Context, _ string, _ azcertificates.CreateCertificateParameters, _ *azcertificates.CreateCertificateOptions) (azcertificates.CreateCertificateResponse, error) {
			return azcertificates.CreateCertificateResponse{CertificateOperation: azcertificates.CertificateOperation{
				ID:     certID(""),
				Status: to.Ptr("inProgress"),
			}}, nil
		},
		getCertificateFn: func(_ context.Context, _, _ string, _ *azcertificates.GetCertificateOptions) (azcertificates.GetCertificateResponse, error) {
			return azcertificates.GetCertificateResponse{Certificate: fullCertificate(nil)}, nil
		},
		updateCertificateFn: func(_ context.Context, _, _ string, params azcertificates.UpdateCertificateParameters, _ *azcertificates.UpdateCertificateOptions) (azcertificates.UpdateCertificateResponse, error) {
			return azcertificates.UpdateCertificateResponse{Certificate: fullCertificate(params.Tags)}, nil
		},
		deleteCertificateFn: func(_ context.Context, _ string, _ *azcertificates.DeleteCertificateOptions) (azcertificates.DeleteCertificateResponse, error) {
			return azcertificates.DeleteCertificateResponse{}, nil
		},
		listFn: func(_ *azcertificates.ListCertificatePropertiesOptions) *runtime.Pager[azcertificates.ListCertificatePropertiesResponse] {
			otherID := azcertificates.ID(testCertVaultURI + "certificates/other-cert/abc123")
			return runtime.NewPager(runtime.PagingHandler[azcertificates.ListCertificatePropertiesResponse]{
				More: func(_ azcertificates.ListCertificatePropertiesResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *azcertificates.ListCertificatePropertiesResponse) (azcertificates.ListCertificatePropertiesResponse, error) {
					return azcertificates.ListCertificatePropertiesResponse{CertificatePropertiesListResult: azcertificates.CertificatePropertiesListResult{
						Value: []*azcertificates.CertificateProperties{
							{ID: certID("v1")},
							{ID: &otherID},
						},
					}}, nil
				},
			})
		},
	}
	prov := newTestKeyVaultCertificate(fake)

	t.Run("Create", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name":     testCertName,
			"vaultUri": testCertVaultURI,
			"policy": map[string]any{
				"issuerName":     "Self",
				"subject":        "CN=formae-test",
				"keyType":        "RSA",
				"validityMonths": 12,
			},
		})
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Label: testCertName, Properties: props})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testCertNativeID, got.ProgressResult.NativeID)

		// Neither the write-only PFX data nor its password may echo back.
		var serialized map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &serialized))
		require.NotContains(t, serialized, "data")
		require.NotContains(t, serialized, "password")
		require.Equal(t, testCertName, serialized["name"])
	})

	t.Run("Create_requires_vaultUri", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": testCertName, "policy": map[string]any{"issuerName": "Self", "subject": "CN=x"}})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.Error(t, err)
	})

	t.Run("Create_requires_data_or_policy", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": testCertName, "vaultUri": testCertVaultURI})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.Error(t, err)
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testCertNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var serialized map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &serialized))
		require.Equal(t, testCertName, serialized["name"])
		require.Equal(t, "01020304", serialized["thumbprint"])
		require.Equal(t, testCertSecretID, serialized["secretId"])
		require.Equal(t, testCertKID, serialized["kid"])
		require.Equal(t, true, serialized["enabled"])
		// Write-only fields must never surface on read.
		require.NotContains(t, serialized, "data")
		require.NotContains(t, serialized, "password")
	})

	t.Run("Update_keeps_native_id", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"tags": []map[string]string{{"Key": "Environment", "Value": "updated"}},
		})
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{NativeID: testCertNativeID, DesiredProperties: props})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testCertNativeID, got.ProgressResult.NativeID)
	})

	t.Run("Delete", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testCertNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteCertificateFn = func(_ context.Context, _ string, _ *azcertificates.DeleteCertificateOptions) (azcertificates.DeleteCertificateResponse, error) {
			return azcertificates.DeleteCertificateResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testCertNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Status_is_synchronous_success", func(t *testing.T) {
		got, err := prov.Status(context.Background(), &resource.StatusRequest{RequestID: "req-1"})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, "req-1", got.ProgressResult.RequestID)
	})

	t.Run("List", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"vaultUri": testCertVaultURI},
		})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 2)
		require.Equal(t, testCertNativeID, got.NativeIDs[0])
	})

	t.Run("List_without_vault_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.createCertificateFn = func(_ context.Context, _ string, _ azcertificates.CreateCertificateParameters, _ *azcertificates.CreateCertificateOptions) (azcertificates.CreateCertificateResponse, error) {
			return azcertificates.CreateCertificateResponse{}, &azcore.ResponseError{StatusCode: 403}
		}
		props, _ := json.Marshal(map[string]any{
			"vaultUri": testCertVaultURI,
			"policy":   map[string]any{"issuerName": "Self", "subject": "CN=x"},
		})
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Label: testCertName, Properties: props})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

func TestKeyVaultCertificate_ImportRoundTrip(t *testing.T) {
	var importedBase64, importedPassword string
	fake := &fakeCertificatesAPI{
		importCertificateFn: func(_ context.Context, _ string, params azcertificates.ImportCertificateParameters, _ *azcertificates.ImportCertificateOptions) (azcertificates.ImportCertificateResponse, error) {
			if params.Base64EncodedCertificate != nil {
				importedBase64 = *params.Base64EncodedCertificate
			}
			if params.Password != nil {
				importedPassword = *params.Password
			}
			return azcertificates.ImportCertificateResponse{Certificate: fullCertificate(params.Tags)}, nil
		},
	}
	prov := newTestKeyVaultCertificate(fake)

	// The write-only import path: base64 PFX plus its password. Core unwraps
	// top-level opaque values to plain strings before reaching the plugin.
	props, _ := json.Marshal(map[string]any{
		"name":     testCertName,
		"vaultUri": testCertVaultURI,
		"data":     "BASE64-PFX-BYTES",
		"password": "pfx-password",
	})
	got, err := prov.Create(context.Background(), &resource.CreateRequest{Label: testCertName, Properties: props})
	require.NoError(t, err)
	require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	require.Equal(t, testCertNativeID, got.ProgressResult.NativeID)

	// The plugin must forward the write-only values to Azure verbatim.
	require.Equal(t, "BASE64-PFX-BYTES", importedBase64)
	require.Equal(t, "pfx-password", importedPassword)

	// But the serialized state must carry neither of them back.
	var serialized map[string]any
	require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &serialized))
	require.NotContains(t, serialized, "data")
	require.NotContains(t, serialized, "password")
	require.Equal(t, testCertName, serialized["name"])
	require.Equal(t, testCertNativeID, serialized["id"])
}

// --- Test helpers ---

type fakeCertificatesAPI struct {
	importCertificateFn func(ctx context.Context, name string, parameters azcertificates.ImportCertificateParameters, options *azcertificates.ImportCertificateOptions) (azcertificates.ImportCertificateResponse, error)
	createCertificateFn func(ctx context.Context, name string, parameters azcertificates.CreateCertificateParameters, options *azcertificates.CreateCertificateOptions) (azcertificates.CreateCertificateResponse, error)
	getCertificateFn    func(ctx context.Context, name string, version string, options *azcertificates.GetCertificateOptions) (azcertificates.GetCertificateResponse, error)
	updateCertificateFn func(ctx context.Context, name string, version string, parameters azcertificates.UpdateCertificateParameters, options *azcertificates.UpdateCertificateOptions) (azcertificates.UpdateCertificateResponse, error)
	deleteCertificateFn func(ctx context.Context, name string, options *azcertificates.DeleteCertificateOptions) (azcertificates.DeleteCertificateResponse, error)
	listFn              func(options *azcertificates.ListCertificatePropertiesOptions) *runtime.Pager[azcertificates.ListCertificatePropertiesResponse]
}

func (f *fakeCertificatesAPI) ImportCertificate(ctx context.Context, name string, parameters azcertificates.ImportCertificateParameters, options *azcertificates.ImportCertificateOptions) (azcertificates.ImportCertificateResponse, error) {
	return f.importCertificateFn(ctx, name, parameters, options)
}

func (f *fakeCertificatesAPI) CreateCertificate(ctx context.Context, name string, parameters azcertificates.CreateCertificateParameters, options *azcertificates.CreateCertificateOptions) (azcertificates.CreateCertificateResponse, error) {
	return f.createCertificateFn(ctx, name, parameters, options)
}

func (f *fakeCertificatesAPI) GetCertificate(ctx context.Context, name string, version string, options *azcertificates.GetCertificateOptions) (azcertificates.GetCertificateResponse, error) {
	return f.getCertificateFn(ctx, name, version, options)
}

func (f *fakeCertificatesAPI) UpdateCertificate(ctx context.Context, name string, version string, parameters azcertificates.UpdateCertificateParameters, options *azcertificates.UpdateCertificateOptions) (azcertificates.UpdateCertificateResponse, error) {
	return f.updateCertificateFn(ctx, name, version, parameters, options)
}

func (f *fakeCertificatesAPI) DeleteCertificate(ctx context.Context, name string, options *azcertificates.DeleteCertificateOptions) (azcertificates.DeleteCertificateResponse, error) {
	return f.deleteCertificateFn(ctx, name, options)
}

func (f *fakeCertificatesAPI) NewListCertificatePropertiesPager(options *azcertificates.ListCertificatePropertiesOptions) *runtime.Pager[azcertificates.ListCertificatePropertiesResponse] {
	return f.listFn(options)
}
