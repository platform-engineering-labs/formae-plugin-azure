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
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const (
	testSecretVaultURI = "https://my-vault.vault.azure.net/"
	testSecretName     = "pg-admin-password"
	testSecretNativeID = "https://my-vault.vault.azure.net/secrets/pg-admin-password"
)

func newTestKeyVaultSecret(api secretsAPI) *KeyVaultSecret {
	return &KeyVaultSecret{
		config: &config.Config{SubscriptionId: "sub-1"},
		newAPI: func(string) (secretsAPI, error) { return api, nil },
	}
}

func secretID(version string) *azsecrets.ID {
	id := azsecrets.ID(testSecretNativeID + "/" + version)
	return &id
}

func TestKeyVaultSecret_CRUD(t *testing.T) {
	fake := &fakeSecretsAPI{
		setSecretFn: func(_ context.Context, _ string, params azsecrets.SetSecretParameters, _ *azsecrets.SetSecretOptions) (azsecrets.SetSecretResponse, error) {
			return azsecrets.SetSecretResponse{Secret: azsecrets.Secret{
				ID:          secretID("v1"),
				ContentType: params.ContentType,
				Tags:        params.Tags,
			}}, nil
		},
		getSecretFn: func(_ context.Context, _, _ string, _ *azsecrets.GetSecretOptions) (azsecrets.GetSecretResponse, error) {
			return azsecrets.GetSecretResponse{Secret: azsecrets.Secret{
				ID:          secretID("v1"),
				Value:       to.Ptr("super-secret"),
				ContentType: to.Ptr("text/plain"),
			}}, nil
		},
		updateSecretPropertiesFn: func(_ context.Context, _, _ string, params azsecrets.UpdateSecretPropertiesParameters, _ *azsecrets.UpdateSecretPropertiesOptions) (azsecrets.UpdateSecretPropertiesResponse, error) {
			return azsecrets.UpdateSecretPropertiesResponse{Secret: azsecrets.Secret{
				ID:          secretID("v1"),
				ContentType: params.ContentType,
				Tags:        params.Tags,
			}}, nil
		},
		deleteSecretFn: func(_ context.Context, _ string, _ *azsecrets.DeleteSecretOptions) (azsecrets.DeleteSecretResponse, error) {
			return azsecrets.DeleteSecretResponse{}, nil
		},
		listFn: func(_ *azsecrets.ListSecretPropertiesOptions) *runtime.Pager[azsecrets.ListSecretPropertiesResponse] {
			otherID := azsecrets.ID(testSecretVaultURI + "secrets/other-secret/abc123")
			return runtime.NewPager(runtime.PagingHandler[azsecrets.ListSecretPropertiesResponse]{
				More: func(_ azsecrets.ListSecretPropertiesResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *azsecrets.ListSecretPropertiesResponse) (azsecrets.ListSecretPropertiesResponse, error) {
					return azsecrets.ListSecretPropertiesResponse{SecretPropertiesListResult: azsecrets.SecretPropertiesListResult{
						Value: []*azsecrets.SecretProperties{
							{ID: secretID("v1")},
							{ID: &otherID},
						},
					}}, nil
				},
			})
		},
	}
	prov := newTestKeyVaultSecret(fake)

	t.Run("Create", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name":        testSecretName,
			"vaultUri":    testSecretVaultURI,
			"value":       "super-secret",
			"contentType": "text/plain",
		})
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Label: testSecretName, Properties: props})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testSecretNativeID, got.ProgressResult.NativeID)

		// value must NOT be echoed back: it is write-only.
		var serialized map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &serialized))
		require.NotContains(t, serialized, "value")
		require.Equal(t, testSecretName, serialized["name"])
	})

	t.Run("Create_requires_vaultUri", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": testSecretName, "value": "x"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.Error(t, err)
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testSecretNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var serialized map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &serialized))
		require.Equal(t, testSecretName, serialized["name"])
		require.Equal(t, "text/plain", serialized["contentType"])
		require.NotContains(t, serialized, "value")
	})

	t.Run("Update_keeps_native_id", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"contentType": "application/json"})
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{NativeID: testSecretNativeID, DesiredProperties: props})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testSecretNativeID, got.ProgressResult.NativeID)
	})

	t.Run("Delete", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testSecretNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteSecretFn = func(_ context.Context, _ string, _ *azsecrets.DeleteSecretOptions) (azsecrets.DeleteSecretResponse, error) {
			return azsecrets.DeleteSecretResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testSecretNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"vaultUri": testSecretVaultURI},
		})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 2)
		require.Equal(t, testSecretNativeID, got.NativeIDs[0])
	})

	t.Run("List_without_vault_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.setSecretFn = func(_ context.Context, _ string, _ azsecrets.SetSecretParameters, _ *azsecrets.SetSecretOptions) (azsecrets.SetSecretResponse, error) {
			return azsecrets.SetSecretResponse{}, &azcore.ResponseError{StatusCode: 403}
		}
		props, _ := json.Marshal(map[string]any{"vaultUri": testSecretVaultURI, "value": "x"})
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Label: testSecretName, Properties: props})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

func TestKeyVaultSecret_UpdateRotation(t *testing.T) {
	t.Run("value patch op rotates via SetSecret", func(t *testing.T) {
		var setVal string
		setCalled, updateCalled := false, false
		fake := &fakeSecretsAPI{
			setSecretFn: func(_ context.Context, _ string, params azsecrets.SetSecretParameters, _ *azsecrets.SetSecretOptions) (azsecrets.SetSecretResponse, error) {
				setCalled = true
				if params.Value != nil {
					setVal = *params.Value
				}
				return azsecrets.SetSecretResponse{Secret: azsecrets.Secret{ID: secretID("v2")}}, nil
			},
			updateSecretPropertiesFn: func(_ context.Context, _, _ string, _ azsecrets.UpdateSecretPropertiesParameters, _ *azsecrets.UpdateSecretPropertiesOptions) (azsecrets.UpdateSecretPropertiesResponse, error) {
				updateCalled = true
				return azsecrets.UpdateSecretPropertiesResponse{Secret: azsecrets.Secret{ID: secretID("v1")}}, nil
			},
		}
		prov := newTestKeyVaultSecret(fake)

		patch := `[{"op":"add","path":"/value","value":"rotated-secret"}]`
		props, _ := json.Marshal(map[string]any{"value": "rotated-secret", "contentType": "text/plain"})
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testSecretNativeID,
			DesiredProperties: props,
			PatchDocument:     &patch,
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.True(t, setCalled, "SetSecret should rotate the value")
		require.False(t, updateCalled, "UpdateSecretProperties should not run when the value changed")
		require.Equal(t, "rotated-secret", setVal)
	})

	t.Run("no value patch op updates metadata only", func(t *testing.T) {
		setCalled, updateCalled := false, false
		fake := &fakeSecretsAPI{
			setSecretFn: func(_ context.Context, _ string, _ azsecrets.SetSecretParameters, _ *azsecrets.SetSecretOptions) (azsecrets.SetSecretResponse, error) {
				setCalled = true
				return azsecrets.SetSecretResponse{Secret: azsecrets.Secret{ID: secretID("v1")}}, nil
			},
			updateSecretPropertiesFn: func(_ context.Context, _, _ string, params azsecrets.UpdateSecretPropertiesParameters, _ *azsecrets.UpdateSecretPropertiesOptions) (azsecrets.UpdateSecretPropertiesResponse, error) {
				updateCalled = true
				return azsecrets.UpdateSecretPropertiesResponse{Secret: azsecrets.Secret{ID: secretID("v1"), ContentType: params.ContentType}}, nil
			},
		}
		prov := newTestKeyVaultSecret(fake)

		// A setOnce-frozen or unchanged value carries no /value op even though the
		// desired props still contain a value; SetSecret must not fire.
		patch := `[{"op":"replace","path":"/contentType","value":"application/json"}]`
		props, _ := json.Marshal(map[string]any{"value": "unchanged-frozen", "contentType": "application/json"})
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testSecretNativeID,
			DesiredProperties: props,
			PatchDocument:     &patch,
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.False(t, setCalled, "SetSecret must not run without a value patch op")
		require.True(t, updateCalled, "metadata-only update should use UpdateSecretProperties")
	})
}

// --- Test helpers ---

type fakeSecretsAPI struct {
	setSecretFn              func(ctx context.Context, name string, parameters azsecrets.SetSecretParameters, options *azsecrets.SetSecretOptions) (azsecrets.SetSecretResponse, error)
	getSecretFn              func(ctx context.Context, name string, version string, options *azsecrets.GetSecretOptions) (azsecrets.GetSecretResponse, error)
	updateSecretPropertiesFn func(ctx context.Context, name string, version string, parameters azsecrets.UpdateSecretPropertiesParameters, options *azsecrets.UpdateSecretPropertiesOptions) (azsecrets.UpdateSecretPropertiesResponse, error)
	deleteSecretFn           func(ctx context.Context, name string, options *azsecrets.DeleteSecretOptions) (azsecrets.DeleteSecretResponse, error)
	listFn                   func(options *azsecrets.ListSecretPropertiesOptions) *runtime.Pager[azsecrets.ListSecretPropertiesResponse]
}

func (f *fakeSecretsAPI) SetSecret(ctx context.Context, name string, parameters azsecrets.SetSecretParameters, options *azsecrets.SetSecretOptions) (azsecrets.SetSecretResponse, error) {
	return f.setSecretFn(ctx, name, parameters, options)
}

func (f *fakeSecretsAPI) GetSecret(ctx context.Context, name string, version string, options *azsecrets.GetSecretOptions) (azsecrets.GetSecretResponse, error) {
	return f.getSecretFn(ctx, name, version, options)
}

func (f *fakeSecretsAPI) UpdateSecretProperties(ctx context.Context, name string, version string, parameters azsecrets.UpdateSecretPropertiesParameters, options *azsecrets.UpdateSecretPropertiesOptions) (azsecrets.UpdateSecretPropertiesResponse, error) {
	return f.updateSecretPropertiesFn(ctx, name, version, parameters, options)
}

func (f *fakeSecretsAPI) DeleteSecret(ctx context.Context, name string, options *azsecrets.DeleteSecretOptions) (azsecrets.DeleteSecretResponse, error) {
	return f.deleteSecretFn(ctx, name, options)
}

func (f *fakeSecretsAPI) NewListSecretPropertiesPager(options *azsecrets.ListSecretPropertiesOptions) *runtime.Pager[azsecrets.ListSecretPropertiesResponse] {
	return f.listFn(options)
}
