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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/cdn/armcdn/v2"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testCdnSecretNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Cdn/profiles/afd-1/secrets/sec-1"
const testCdnSecretKVCertID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.KeyVault/vaults/kv-1/secrets/cert-1"

func fullCdnSecretProps() map[string]any {
	return map[string]any{
		"resourceGroupName": "rg-1",
		"profileName":       "afd-1",
		"name":              "sec-1",
		"secretSource":      testCdnSecretKVCertID,
		"useLatestVersion":  true,
	}
}

func createCdnSecretProps() json.RawMessage {
	props, _ := json.Marshal(fullCdnSecretProps())
	return props
}

// TestCdnSecret_MarshallerRoundTrip verifies the polymorphic
// CustomerCertificateParameters (Key Vault certificate reference) survives
// build -> serialize with no drift.
func TestCdnSecret_MarshallerRoundTrip(t *testing.T) {
	var props map[string]any
	require.NoError(t, json.Unmarshal(createCdnSecretProps(), &props))

	params := buildCdnSecretParams(props)
	params.ID = to.Ptr(testCdnSecretNativeID)
	params.Name = to.Ptr("sec-1")

	raw, err := serializeCdnSecretProperties(params, "rg-1", "afd-1", "sec-1")
	require.NoError(t, err)

	var got map[string]any
	require.NoError(t, json.Unmarshal(raw, &got))

	require.Equal(t, "sec-1", got["name"])
	require.Equal(t, "CustomerCertificate", got["type"])
	require.Equal(t, testCdnSecretKVCertID, got["secretSource"], "KV cert reference must round-trip as-is")
	require.Equal(t, true, got["useLatestVersion"])
}

func TestCdnSecret_CRUD(t *testing.T) {
	var builtProps map[string]any
	require.NoError(t, json.Unmarshal(createCdnSecretProps(), &builtProps))
	built := buildCdnSecretParams(builtProps)
	built.ID = to.Ptr(testCdnSecretNativeID)
	built.Name = to.Ptr("sec-1")

	doneResult := armcdn.SecretsClientCreateResponse{Secret: built}

	fake := &fakeCdnSecretsAPI{
		beginCreateFn: func(_ context.Context, _, _, _ string, _ armcdn.Secret, _ *armcdn.SecretsClientBeginCreateOptions) (*runtime.Poller[armcdn.SecretsClientCreateResponse], error) {
			return newDonePoller(doneResult), nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ *armcdn.SecretsClientGetOptions) (armcdn.SecretsClientGetResponse, error) {
			return armcdn.SecretsClientGetResponse{Secret: built}, nil
		},
		beginDeleteFn: func(_ context.Context, _, _, _ string, _ *armcdn.SecretsClientBeginDeleteOptions) (*runtime.Poller[armcdn.SecretsClientDeleteResponse], error) {
			return newInProgressPoller[armcdn.SecretsClientDeleteResponse](), nil
		},
		newListByProfilePagerFn: func(_, _ string, _ *armcdn.SecretsClientListByProfileOptions) *runtime.Pager[armcdn.SecretsClientListByProfileResponse] {
			return runtime.NewPager(runtime.PagingHandler[armcdn.SecretsClientListByProfileResponse]{
				More: func(_ armcdn.SecretsClientListByProfileResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armcdn.SecretsClientListByProfileResponse) (armcdn.SecretsClientListByProfileResponse, error) {
					return armcdn.SecretsClientListByProfileResponse{
						SecretListResult: armcdn.SecretListResult{Value: []*armcdn.Secret{{ID: to.Ptr(testCdnSecretNativeID)}}},
					}, nil
				},
			})
		},
	}
	prov := newTestCdnSecret(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: createCdnSecretProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testCdnSecretNativeID, got.ProgressResult.NativeID)
		var props map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &props))
		require.Equal(t, testCdnSecretKVCertID, props["secretSource"])
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testCdnSecretNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "afd-1", props["profileName"])
	})

	t.Run("Update", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{NativeID: testCdnSecretNativeID, DesiredProperties: createCdnSecretProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Delete", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testCdnSecretNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusInProgress, got.ProgressResult.OperationStatus)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _, _ string, _ *armcdn.SecretsClientBeginDeleteOptions) (*runtime.Poller[armcdn.SecretsClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testCdnSecretNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "profileName": "afd-1"}})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 1)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.beginCreateFn = func(_ context.Context, _, _, _ string, _ armcdn.Secret, _ *armcdn.SecretsClientBeginCreateOptions) (*runtime.Poller[armcdn.SecretsClientCreateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 403}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: createCdnSecretProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

// --- Test helpers ---

func newTestCdnSecret(api cdnSecretsAPI) *CdnSecret {
	return &CdnSecret{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

type fakeCdnSecretsAPI struct {
	beginCreateFn           func(ctx context.Context, rgName, profileName, secretName string, secret armcdn.Secret, opts *armcdn.SecretsClientBeginCreateOptions) (*runtime.Poller[armcdn.SecretsClientCreateResponse], error)
	getFn                   func(ctx context.Context, rgName, profileName, secretName string, opts *armcdn.SecretsClientGetOptions) (armcdn.SecretsClientGetResponse, error)
	beginDeleteFn           func(ctx context.Context, rgName, profileName, secretName string, opts *armcdn.SecretsClientBeginDeleteOptions) (*runtime.Poller[armcdn.SecretsClientDeleteResponse], error)
	newListByProfilePagerFn func(rgName, profileName string, opts *armcdn.SecretsClientListByProfileOptions) *runtime.Pager[armcdn.SecretsClientListByProfileResponse]
}

func (f *fakeCdnSecretsAPI) BeginCreate(ctx context.Context, rgName, profileName, secretName string, secret armcdn.Secret, opts *armcdn.SecretsClientBeginCreateOptions) (*runtime.Poller[armcdn.SecretsClientCreateResponse], error) {
	return f.beginCreateFn(ctx, rgName, profileName, secretName, secret, opts)
}

func (f *fakeCdnSecretsAPI) Get(ctx context.Context, rgName, profileName, secretName string, opts *armcdn.SecretsClientGetOptions) (armcdn.SecretsClientGetResponse, error) {
	return f.getFn(ctx, rgName, profileName, secretName, opts)
}

func (f *fakeCdnSecretsAPI) BeginDelete(ctx context.Context, rgName, profileName, secretName string, opts *armcdn.SecretsClientBeginDeleteOptions) (*runtime.Poller[armcdn.SecretsClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, profileName, secretName, opts)
}

func (f *fakeCdnSecretsAPI) NewListByProfilePager(rgName, profileName string, opts *armcdn.SecretsClientListByProfileOptions) *runtime.Pager[armcdn.SecretsClientListByProfileResponse] {
	return f.newListByProfilePagerFn(rgName, profileName, opts)
}
