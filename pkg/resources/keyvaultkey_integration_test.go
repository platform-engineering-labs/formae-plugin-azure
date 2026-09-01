// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const (
	testKeyVaultURI = "https://my-vault.vault.azure.net/"
	testKeyName     = "signing-key"
	testKeyNativeID = "https://my-vault.vault.azure.net/keys/signing-key"
)

func newTestKeyVaultKey(api keysAPI) *KeyVaultKey {
	return &KeyVaultKey{
		config: &config.Config{SubscriptionId: "sub-1"},
		newAPI: func(string) (keysAPI, error) { return api, nil },
	}
}

func keyID(version string) *azkeys.ID {
	id := azkeys.ID(testKeyNativeID + "/" + version)
	return &id
}

// rsaModulus returns a modulus of the byte length an RSA key of bits would have,
// which is what Read derives keySize from.
func rsaModulus(bits int) []byte {
	return bytes.Repeat([]byte{0xAB}, bits/8)
}

func rsaKeyBundle(version string, ops []*azkeys.KeyOperation, tags map[string]*string) azkeys.KeyBundle {
	return azkeys.KeyBundle{
		Key: &azkeys.JSONWebKey{
			KID:    keyID(version),
			Kty:    to.Ptr(azkeys.KeyTypeRSA),
			N:      rsaModulus(2048),
			E:      []byte{1, 0, 1},
			KeyOps: ops,
		},
		Attributes: &azkeys.KeyAttributes{Enabled: to.Ptr(true)},
		Tags:       tags,
	}
}

func TestKeyVaultKey_CRUD(t *testing.T) {
	defaultOps := []*azkeys.KeyOperation{to.Ptr(azkeys.KeyOperationSign), to.Ptr(azkeys.KeyOperationVerify)}

	fake := &fakeKeysAPI{
		createKeyFn: func(_ context.Context, _ string, params azkeys.CreateKeyParameters, _ *azkeys.CreateKeyOptions) (azkeys.CreateKeyResponse, error) {
			// Azure never echoes KeySize back; the response only carries the JWK.
			return azkeys.CreateKeyResponse{KeyBundle: rsaKeyBundle("v1", params.KeyOps, params.Tags)}, nil
		},
		getKeyFn: func(_ context.Context, _, _ string, _ *azkeys.GetKeyOptions) (azkeys.GetKeyResponse, error) {
			return azkeys.GetKeyResponse{KeyBundle: rsaKeyBundle("v1", defaultOps, nil)}, nil
		},
		updateKeyFn: func(_ context.Context, _, _ string, params azkeys.UpdateKeyParameters, _ *azkeys.UpdateKeyOptions) (azkeys.UpdateKeyResponse, error) {
			kb := rsaKeyBundle("v1", params.KeyOps, params.Tags)
			if params.KeyAttributes != nil {
				kb.Attributes = params.KeyAttributes
			}
			return azkeys.UpdateKeyResponse{KeyBundle: kb}, nil
		},
		deleteKeyFn: func(_ context.Context, _ string, _ *azkeys.DeleteKeyOptions) (azkeys.DeleteKeyResponse, error) {
			return azkeys.DeleteKeyResponse{}, nil
		},
		purgeDeletedKeyFn: func(_ context.Context, _ string, _ *azkeys.PurgeDeletedKeyOptions) (azkeys.PurgeDeletedKeyResponse, error) {
			return azkeys.PurgeDeletedKeyResponse{}, nil
		},
		listFn: func(_ *azkeys.ListKeyPropertiesOptions) *runtime.Pager[azkeys.ListKeyPropertiesResponse] {
			otherID := azkeys.ID(testKeyVaultURI + "keys/other-key/abc123")
			return runtime.NewPager(runtime.PagingHandler[azkeys.ListKeyPropertiesResponse]{
				More: func(_ azkeys.ListKeyPropertiesResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *azkeys.ListKeyPropertiesResponse) (azkeys.ListKeyPropertiesResponse, error) {
					return azkeys.ListKeyPropertiesResponse{KeyPropertiesListResult: azkeys.KeyPropertiesListResult{
						Value: []*azkeys.KeyProperties{
							{KID: keyID("v1")},
							{KID: &otherID},
						},
					}}, nil
				},
			})
		},
	}
	prov := newTestKeyVaultKey(fake)

	mkProps := func() json.RawMessage {
		props, _ := json.Marshal(map[string]any{
			"name":     testKeyName,
			"vaultUri": testKeyVaultURI,
			"keyType":  "RSA",
			"keySize":  2048,
			"keyOps":   []string{"sign", "verify"},
			"enabled":  true,
		})
		return props
	}

	t.Run("Create", func(t *testing.T) {
		var seen azkeys.CreateKeyParameters
		fake.createKeyFn = func(_ context.Context, _ string, params azkeys.CreateKeyParameters, _ *azkeys.CreateKeyOptions) (azkeys.CreateKeyResponse, error) {
			seen = params
			return azkeys.CreateKeyResponse{KeyBundle: rsaKeyBundle("v1", params.KeyOps, params.Tags)}, nil
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Label: testKeyName, Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testKeyNativeID, got.ProgressResult.NativeID)

		require.Equal(t, azkeys.KeyTypeRSA, *seen.Kty)
		require.Equal(t, int32(2048), *seen.KeySize)
		require.Len(t, seen.KeyOps, 2)
		require.True(t, *seen.KeyAttributes.Enabled)

		var serialized map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &serialized))
		require.Equal(t, testKeyName, serialized["name"])
		require.Equal(t, "RSA", serialized["keyType"])
		require.Equal(t, "v1", serialized["keyVersion"])
		// keySize is absent from the create response and must be derived.
		require.Equal(t, float64(2048), serialized["keySize"])
	})

	t.Run("Create_requires_vaultUri", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": testKeyName, "keyType": "RSA"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.Error(t, err)
	})

	t.Run("Create_requires_keyType", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": testKeyName, "vaultUri": testKeyVaultURI})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.Error(t, err)
	})

	t.Run("Read_derives_keySize_from_modulus", func(t *testing.T) {
		fake.getKeyFn = func(_ context.Context, _, _ string, _ *azkeys.GetKeyOptions) (azkeys.GetKeyResponse, error) {
			kb := rsaKeyBundle("v1", defaultOps, nil)
			kb.Key.N = rsaModulus(4096)
			return azkeys.GetKeyResponse{KeyBundle: kb}, nil
		}
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testKeyNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
		require.Equal(t, ResourceTypeKeyVaultKey, got.ResourceType)

		var serialized map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &serialized))
		require.Equal(t, float64(4096), serialized["keySize"])
		require.Equal(t, testKeyVaultURI, serialized["vaultUri"])
		require.Equal(t, []any{"sign", "verify"}, serialized["keyOps"])
		require.Equal(t, true, serialized["enabled"])

		fake.getKeyFn = func(_ context.Context, _, _ string, _ *azkeys.GetKeyOptions) (azkeys.GetKeyResponse, error) {
			return azkeys.GetKeyResponse{KeyBundle: rsaKeyBundle("v1", defaultOps, nil)}, nil
		}
	})

	t.Run("Read_omits_keySize_for_ec_key", func(t *testing.T) {
		fake.getKeyFn = func(_ context.Context, _, _ string, _ *azkeys.GetKeyOptions) (azkeys.GetKeyResponse, error) {
			return azkeys.GetKeyResponse{KeyBundle: azkeys.KeyBundle{
				Key: &azkeys.JSONWebKey{
					KID: keyID("v1"),
					Kty: to.Ptr(azkeys.KeyTypeEC),
					Crv: to.Ptr(azkeys.CurveNameP256),
					X:   []byte{1, 2, 3},
					Y:   []byte{4, 5, 6},
				},
			}}, nil
		}
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testKeyNativeID})
		require.NoError(t, err)

		var serialized map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &serialized))
		require.NotContains(t, serialized, "keySize")
		require.Equal(t, "P-256", serialized["curveName"])

		fake.getKeyFn = func(_ context.Context, _, _ string, _ *azkeys.GetKeyOptions) (azkeys.GetKeyResponse, error) {
			return azkeys.GetKeyResponse{KeyBundle: rsaKeyBundle("v1", defaultOps, nil)}, nil
		}
	})

	t.Run("Read_not_found", func(t *testing.T) {
		fake.getKeyFn = func(_ context.Context, _, _ string, _ *azkeys.GetKeyOptions) (azkeys.GetKeyResponse, error) {
			return azkeys.GetKeyResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testKeyNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)

		fake.getKeyFn = func(_ context.Context, _, _ string, _ *azkeys.GetKeyOptions) (azkeys.GetKeyResponse, error) {
			return azkeys.GetKeyResponse{KeyBundle: rsaKeyBundle("v1", defaultOps, nil)}, nil
		}
	})

	t.Run("Update_keeps_native_id", func(t *testing.T) {
		var seen azkeys.UpdateKeyParameters
		fake.updateKeyFn = func(_ context.Context, _, version string, params azkeys.UpdateKeyParameters, _ *azkeys.UpdateKeyOptions) (azkeys.UpdateKeyResponse, error) {
			require.Empty(t, version, "an empty version patches the current key version")
			seen = params
			kb := rsaKeyBundle("v1", params.KeyOps, params.Tags)
			kb.Attributes = params.KeyAttributes
			return azkeys.UpdateKeyResponse{KeyBundle: kb}, nil
		}
		desired, _ := json.Marshal(map[string]any{
			"name":     testKeyName,
			"vaultUri": testKeyVaultURI,
			"keyType":  "RSA",
			"keyOps":   []string{"sign"},
			"enabled":  false,
			"Tags":     []map[string]string{{"Key": "Environment", "Value": "updated"}},
		})
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{NativeID: testKeyNativeID, DesiredProperties: desired})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testKeyNativeID, got.ProgressResult.NativeID)
		require.Len(t, seen.KeyOps, 1)
		require.False(t, *seen.KeyAttributes.Enabled)
		require.Equal(t, "updated", *seen.Tags["Environment"])

		var serialized map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &serialized))
		require.Equal(t, false, serialized["enabled"])
	})

	t.Run("Delete_purges_so_the_name_is_reusable", func(t *testing.T) {
		purged := false
		fake.purgeDeletedKeyFn = func(_ context.Context, name string, _ *azkeys.PurgeDeletedKeyOptions) (azkeys.PurgeDeletedKeyResponse, error) {
			purged = true
			require.Equal(t, testKeyName, name)
			return azkeys.PurgeDeletedKeyResponse{}, nil
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testKeyNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.True(t, purged, "a soft-deleted key holds its name until it is purged")
	})

	t.Run("Delete_survives_a_purge_that_is_refused", func(t *testing.T) {
		// Purge protection makes purge impossible; the delete itself still succeeded.
		fake.purgeDeletedKeyFn = func(_ context.Context, _ string, _ *azkeys.PurgeDeletedKeyOptions) (azkeys.PurgeDeletedKeyResponse, error) {
			return azkeys.PurgeDeletedKeyResponse{}, &azcore.ResponseError{StatusCode: 403}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testKeyNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteKeyFn = func(_ context.Context, _ string, _ *azkeys.DeleteKeyOptions) (azkeys.DeleteKeyResponse, error) {
			return azkeys.DeleteKeyResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testKeyNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Delete_error_reports_the_provider_message", func(t *testing.T) {
		fake.deleteKeyFn = func(_ context.Context, _ string, _ *azkeys.DeleteKeyOptions) (azkeys.DeleteKeyResponse, error) {
			return azkeys.DeleteKeyResponse{}, &azcore.ResponseError{StatusCode: 403, ErrorCode: "ForbiddenByRbac"}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testKeyNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.Contains(t, got.ProgressResult.StatusMessage, "ForbiddenByRbac")

		fake.deleteKeyFn = func(_ context.Context, _ string, _ *azkeys.DeleteKeyOptions) (azkeys.DeleteKeyResponse, error) {
			return azkeys.DeleteKeyResponse{}, nil
		}
	})

	t.Run("List", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"vaultUri": testKeyVaultURI},
		})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 2)
		require.Equal(t, testKeyNativeID, got.NativeIDs[0])
	})

	t.Run("List_without_vault_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure_with_a_message", func(t *testing.T) {
		fake.createKeyFn = func(_ context.Context, _ string, _ azkeys.CreateKeyParameters, _ *azkeys.CreateKeyOptions) (azkeys.CreateKeyResponse, error) {
			return azkeys.CreateKeyResponse{}, &azcore.ResponseError{StatusCode: 403, ErrorCode: "ForbiddenByRbac"}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Label: testKeyName, Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.Contains(t, got.ProgressResult.StatusMessage, "ForbiddenByRbac")
	})
}

func TestKeyVaultKey_Attributes(t *testing.T) {
	t.Run("no attributes declared sends no attribute block", func(t *testing.T) {
		var seen azkeys.CreateKeyParameters
		fake := &fakeKeysAPI{
			createKeyFn: func(_ context.Context, _ string, params azkeys.CreateKeyParameters, _ *azkeys.CreateKeyOptions) (azkeys.CreateKeyResponse, error) {
				seen = params
				return azkeys.CreateKeyResponse{KeyBundle: rsaKeyBundle("v1", nil, nil)}, nil
			},
		}
		props, _ := json.Marshal(map[string]any{"name": testKeyName, "vaultUri": testKeyVaultURI, "keyType": "RSA"})
		_, err := newTestKeyVaultKey(fake).Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.Nil(t, seen.KeyAttributes)
	})

	t.Run("expiresOn and notBefore round-trip as RFC 3339 UTC", func(t *testing.T) {
		var seen azkeys.CreateKeyParameters
		fake := &fakeKeysAPI{
			createKeyFn: func(_ context.Context, _ string, params azkeys.CreateKeyParameters, _ *azkeys.CreateKeyOptions) (azkeys.CreateKeyResponse, error) {
				seen = params
				kb := rsaKeyBundle("v1", nil, nil)
				kb.Attributes = params.KeyAttributes
				return azkeys.CreateKeyResponse{KeyBundle: kb}, nil
			},
		}
		props, _ := json.Marshal(map[string]any{
			"name": testKeyName, "vaultUri": testKeyVaultURI, "keyType": "RSA",
			"expiresOn": "2030-01-01T00:00:00Z", "notBefore": "2026-01-01T00:00:00Z",
		})
		got, err := newTestKeyVaultKey(fake).Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.NotNil(t, seen.KeyAttributes.Expires)

		var serialized map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &serialized))
		require.Equal(t, "2030-01-01T00:00:00Z", serialized["expiresOn"])
		require.Equal(t, "2026-01-01T00:00:00Z", serialized["notBefore"])
	})

	t.Run("an unparseable time is rejected before any request", func(t *testing.T) {
		fake := &fakeKeysAPI{
			createKeyFn: func(_ context.Context, _ string, _ azkeys.CreateKeyParameters, _ *azkeys.CreateKeyOptions) (azkeys.CreateKeyResponse, error) {
				t.Fatal("CreateKey must not be called with an invalid expiresOn")
				return azkeys.CreateKeyResponse{}, nil
			},
		}
		props, _ := json.Marshal(map[string]any{
			"name": testKeyName, "vaultUri": testKeyVaultURI, "keyType": "RSA", "expiresOn": "not-a-time",
		})
		_, err := newTestKeyVaultKey(fake).Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.Error(t, err)
	})
}

func TestParseKeyID(t *testing.T) {
	vaultURL, name, err := parseKeyID(testKeyNativeID)
	require.NoError(t, err)
	require.Equal(t, "https://my-vault.vault.azure.net", vaultURL)
	require.Equal(t, testKeyName, name)

	// A secret id must not parse as a key id.
	_, _, err = parseKeyID("https://my-vault.vault.azure.net/secrets/signing-key")
	require.Error(t, err)

	_, _, err = parseKeyID("not-a-url")
	require.Error(t, err)
}

// --- Test helpers ---

type fakeKeysAPI struct {
	createKeyFn       func(ctx context.Context, name string, parameters azkeys.CreateKeyParameters, options *azkeys.CreateKeyOptions) (azkeys.CreateKeyResponse, error)
	getKeyFn          func(ctx context.Context, name string, version string, options *azkeys.GetKeyOptions) (azkeys.GetKeyResponse, error)
	updateKeyFn       func(ctx context.Context, name string, version string, parameters azkeys.UpdateKeyParameters, options *azkeys.UpdateKeyOptions) (azkeys.UpdateKeyResponse, error)
	deleteKeyFn       func(ctx context.Context, name string, options *azkeys.DeleteKeyOptions) (azkeys.DeleteKeyResponse, error)
	purgeDeletedKeyFn func(ctx context.Context, name string, options *azkeys.PurgeDeletedKeyOptions) (azkeys.PurgeDeletedKeyResponse, error)
	listFn            func(options *azkeys.ListKeyPropertiesOptions) *runtime.Pager[azkeys.ListKeyPropertiesResponse]
}

func (f *fakeKeysAPI) CreateKey(ctx context.Context, name string, parameters azkeys.CreateKeyParameters, options *azkeys.CreateKeyOptions) (azkeys.CreateKeyResponse, error) {
	return f.createKeyFn(ctx, name, parameters, options)
}

func (f *fakeKeysAPI) GetKey(ctx context.Context, name string, version string, options *azkeys.GetKeyOptions) (azkeys.GetKeyResponse, error) {
	return f.getKeyFn(ctx, name, version, options)
}

func (f *fakeKeysAPI) UpdateKey(ctx context.Context, name string, version string, parameters azkeys.UpdateKeyParameters, options *azkeys.UpdateKeyOptions) (azkeys.UpdateKeyResponse, error) {
	return f.updateKeyFn(ctx, name, version, parameters, options)
}

func (f *fakeKeysAPI) DeleteKey(ctx context.Context, name string, options *azkeys.DeleteKeyOptions) (azkeys.DeleteKeyResponse, error) {
	return f.deleteKeyFn(ctx, name, options)
}

func (f *fakeKeysAPI) PurgeDeletedKey(ctx context.Context, name string, options *azkeys.PurgeDeletedKeyOptions) (azkeys.PurgeDeletedKeyResponse, error) {
	if f.purgeDeletedKeyFn == nil {
		return azkeys.PurgeDeletedKeyResponse{}, nil
	}
	return f.purgeDeletedKeyFn(ctx, name, options)
}

func (f *fakeKeysAPI) NewListKeyPropertiesPager(options *azkeys.ListKeyPropertiesOptions) *runtime.Pager[azkeys.ListKeyPropertiesResponse] {
	return f.listFn(options)
}
