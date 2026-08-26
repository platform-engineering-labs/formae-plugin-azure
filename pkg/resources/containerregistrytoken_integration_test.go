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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerregistry/armcontainerregistry"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const (
	testRegistryTokenNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.ContainerRegistry/registries/acr1/tokens/tk1"
	testTokenScopeMapID       = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.ContainerRegistry/registries/acr1/scopeMaps/sm1"
)

type fakeRegistryTokensAPI struct {
	beginCreateFn func(ctx context.Context, rgName, registryName, name string, params armcontainerregistry.Token, options *armcontainerregistry.TokensClientBeginCreateOptions) (*runtime.Poller[armcontainerregistry.TokensClientCreateResponse], error)
	getFn         func(ctx context.Context, rgName, registryName, name string, options *armcontainerregistry.TokensClientGetOptions) (armcontainerregistry.TokensClientGetResponse, error)
	beginUpdateFn func(ctx context.Context, rgName, registryName, name string, params armcontainerregistry.TokenUpdateParameters, options *armcontainerregistry.TokensClientBeginUpdateOptions) (*runtime.Poller[armcontainerregistry.TokensClientUpdateResponse], error)
	beginDeleteFn func(ctx context.Context, rgName, registryName, name string, options *armcontainerregistry.TokensClientBeginDeleteOptions) (*runtime.Poller[armcontainerregistry.TokensClientDeleteResponse], error)
	listPagerFn   func(rgName, registryName string, options *armcontainerregistry.TokensClientListOptions) *runtime.Pager[armcontainerregistry.TokensClientListResponse]
}

func (f *fakeRegistryTokensAPI) BeginCreate(ctx context.Context, rgName, registryName, name string, params armcontainerregistry.Token, options *armcontainerregistry.TokensClientBeginCreateOptions) (*runtime.Poller[armcontainerregistry.TokensClientCreateResponse], error) {
	return f.beginCreateFn(ctx, rgName, registryName, name, params, options)
}

func (f *fakeRegistryTokensAPI) Get(ctx context.Context, rgName, registryName, name string, options *armcontainerregistry.TokensClientGetOptions) (armcontainerregistry.TokensClientGetResponse, error) {
	return f.getFn(ctx, rgName, registryName, name, options)
}

func (f *fakeRegistryTokensAPI) BeginUpdate(ctx context.Context, rgName, registryName, name string, params armcontainerregistry.TokenUpdateParameters, options *armcontainerregistry.TokensClientBeginUpdateOptions) (*runtime.Poller[armcontainerregistry.TokensClientUpdateResponse], error) {
	return f.beginUpdateFn(ctx, rgName, registryName, name, params, options)
}

func (f *fakeRegistryTokensAPI) BeginDelete(ctx context.Context, rgName, registryName, name string, options *armcontainerregistry.TokensClientBeginDeleteOptions) (*runtime.Poller[armcontainerregistry.TokensClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, registryName, name, options)
}

func (f *fakeRegistryTokensAPI) NewListPager(rgName, registryName string, options *armcontainerregistry.TokensClientListOptions) *runtime.Pager[armcontainerregistry.TokensClientListResponse] {
	return f.listPagerFn(rgName, registryName, options)
}

func newTestRegistryToken(api containerRegistryTokensAPI) *ContainerRegistryToken {
	return &ContainerRegistryToken{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func registryTokenDesired(status string) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":              "tk1",
		"resourceGroupName": "rg-1",
		"registryName":      "acr1",
		"scopeMapId":        testTokenScopeMapID,
		"status":            status,
	})
	return out
}

func TestContainerRegistryToken_CRUD(t *testing.T) {
	created := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	tokenResult := armcontainerregistry.Token{
		ID:   to.Ptr(testRegistryTokenNativeID),
		Name: to.Ptr("tk1"),
		Properties: &armcontainerregistry.TokenProperties{
			ScopeMapID: to.Ptr(testTokenScopeMapID),
			Status:     to.Ptr(armcontainerregistry.TokenStatusEnabled),
			// A password issued out of band by generateCredentials. Its value is a
			// secret and must never reach formae state.
			Credentials: &armcontainerregistry.TokenCredentialsProperties{
				Passwords: []*armcontainerregistry.TokenPassword{{
					Name:         to.Ptr(armcontainerregistry.TokenPasswordNamePassword1),
					Value:        to.Ptr("s3cr3t-token-password"),
					CreationTime: to.Ptr(created),
				}},
				Certificates: []*armcontainerregistry.TokenCertificate{{
					Name:       to.Ptr(armcontainerregistry.TokenCertificateNameCertificate1),
					Thumbprint: to.Ptr("AA:BB:CC"),
				}},
			},
			CreationDate:      to.Ptr(created),
			ProvisioningState: to.Ptr(armcontainerregistry.ProvisioningStateSucceeded),
		},
	}

	var sentCreate armcontainerregistry.Token
	var sentUpdate armcontainerregistry.TokenUpdateParameters
	createCalls := 0
	updateCalls := 0
	deleteCalls := 0
	fake := &fakeRegistryTokensAPI{
		beginCreateFn: func(_ context.Context, rgName, registryName, name string, params armcontainerregistry.Token, _ *armcontainerregistry.TokensClientBeginCreateOptions) (*runtime.Poller[armcontainerregistry.TokensClientCreateResponse], error) {
			require.Equal(t, "rg-1", rgName)
			require.Equal(t, "acr1", registryName)
			require.Equal(t, "tk1", name)
			sentCreate = params
			createCalls++
			return newDonePoller(armcontainerregistry.TokensClientCreateResponse{Token: tokenResult}), nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ *armcontainerregistry.TokensClientGetOptions) (armcontainerregistry.TokensClientGetResponse, error) {
			return armcontainerregistry.TokensClientGetResponse{Token: tokenResult}, nil
		},
		beginUpdateFn: func(_ context.Context, _, _, _ string, params armcontainerregistry.TokenUpdateParameters, _ *armcontainerregistry.TokensClientBeginUpdateOptions) (*runtime.Poller[armcontainerregistry.TokensClientUpdateResponse], error) {
			sentUpdate = params
			updateCalls++
			return newDonePoller(armcontainerregistry.TokensClientUpdateResponse{Token: tokenResult}), nil
		},
		beginDeleteFn: func(_ context.Context, _, _, _ string, _ *armcontainerregistry.TokensClientBeginDeleteOptions) (*runtime.Poller[armcontainerregistry.TokensClientDeleteResponse], error) {
			deleteCalls++
			return newDonePoller(armcontainerregistry.TokensClientDeleteResponse{}), nil
		},
		listPagerFn: func(_, _ string, _ *armcontainerregistry.TokensClientListOptions) *runtime.Pager[armcontainerregistry.TokensClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armcontainerregistry.TokensClientListResponse]{
				More: func(_ armcontainerregistry.TokensClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armcontainerregistry.TokensClientListResponse) (armcontainerregistry.TokensClientListResponse, error) {
					return armcontainerregistry.TokensClientListResponse{
						TokenListResult: armcontainerregistry.TokenListResult{
							Value: []*armcontainerregistry.Token{
								{ID: to.Ptr(testRegistryTokenNativeID)},
								// A nil entry must not panic the walk.
								nil,
							},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestRegistryToken(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "tk1", Properties: registryTokenDesired("enabled"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testRegistryTokenNativeID, got.ProgressResult.NativeID)

		require.Equal(t, testTokenScopeMapID, *sentCreate.Properties.ScopeMapID)
		require.Equal(t, armcontainerregistry.TokenStatusEnabled, *sentCreate.Properties.Status)
		// Passwords are issued by generateCredentials, never by this resource.
		require.Nil(t, sentCreate.Properties.Credentials)
	})

	t.Run("Create_requires_scope_map", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "tk1", "resourceGroupName": "rg-1", "registryName": "acr1",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "scopeMapId is required")
	})

	t.Run("Create_requires_registry", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "tk1", "resourceGroupName": "rg-1"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "registryName is required")
	})

	t.Run("Create_omits_unset_status", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "tk1", "resourceGroupName": "rg-1", "registryName": "acr1",
			"scopeMapId": testTokenScopeMapID,
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.Nil(t, sentCreate.Properties.Status)
	})

	// The native ID reported while the LRO is still running must match the path ARM
	// actually assigns, or the resource is orphaned once it completes.
	t.Run("PendingCreateReportsRealNativeID", func(t *testing.T) {
		fake.beginCreateFn = func(_ context.Context, _, _, _ string, _ armcontainerregistry.Token, _ *armcontainerregistry.TokensClientBeginCreateOptions) (*runtime.Poller[armcontainerregistry.TokensClientCreateResponse], error) {
			return newPendingPoller[armcontainerregistry.TokensClientCreateResponse](), nil
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "tk1", Properties: registryTokenDesired("enabled"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusInProgress, got.ProgressResult.OperationStatus)
		require.Equal(t, testRegistryTokenNativeID, got.ProgressResult.NativeID)
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testRegistryTokenNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "tk1", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "acr1", props["registryName"])
		require.Equal(t, testTokenScopeMapID, props["scopeMapId"])
		require.Equal(t, "enabled", props["status"])
	})

	// The whole point of leaving credentials unmodelled: a password issued out of
	// band must not land in state, and must not read as drift either.
	t.Run("credentials_never_serialized", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testRegistryTokenNativeID})
		require.NoError(t, err)
		require.NotContains(t, got.Properties, "s3cr3t-token-password")
		for _, key := range []string{
			"credentials", "passwords", "certificates", "AA:BB:CC",
			"creationDate", "provisioningState",
		} {
			require.NotContains(t, got.Properties, key)
		}
	})

	// This API has a real update verb, and its patch body carries no credentials —
	// so revoking access with a status flip leaves an existing password alone.
	t.Run("Update_patches_status_without_touching_credentials", func(t *testing.T) {
		beforeUpdate := updateCalls
		beforeCreate := createCalls
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testRegistryTokenNativeID,
			DesiredProperties: registryTokenDesired("disabled"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, beforeUpdate+1, updateCalls)
		// No re-PUT: the create verb must not be touched.
		require.Equal(t, beforeCreate, createCalls)
		require.Equal(t, armcontainerregistry.TokenStatusDisabled, *sentUpdate.Properties.Status)
		require.Nil(t, sentUpdate.Properties.Credentials)
	})

	// The update token belongs to a poller with the Update response type. Resuming it
	// as a Create response would kill the plugin operator mid-apply.
	t.Run("PendingUpdateResumesAsUpdate", func(t *testing.T) {
		fake.beginUpdateFn = func(_ context.Context, _, _, _ string, _ armcontainerregistry.TokenUpdateParameters, _ *armcontainerregistry.TokensClientBeginUpdateOptions) (*runtime.Poller[armcontainerregistry.TokensClientUpdateResponse], error) {
			return newPendingPoller[armcontainerregistry.TokensClientUpdateResponse](), nil
		}
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testRegistryTokenNativeID,
			DesiredProperties: registryTokenDesired("disabled"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusInProgress, got.ProgressResult.OperationStatus)

		reqID, err := decodeLROStatus(got.ProgressResult.RequestID)
		require.NoError(t, err)
		require.Equal(t, lroOpUpdate, reqID.OperationType)
		require.Equal(t, testRegistryTokenNativeID, reqID.NativeID)
	})

	t.Run("Delete", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testRegistryTokenNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _, _ string, _ *armcontainerregistry.TokensClientBeginDeleteOptions) (*runtime.Poller[armcontainerregistry.TokensClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testRegistryTokenNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "registryName": "acr1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testRegistryTokenNativeID}, got.NativeIDs)
	})

	t.Run("List_without_registry_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})

	t.Run("Read_NotFound", func(t *testing.T) {
		fake.getFn = func(_ context.Context, _, _, _ string, _ *armcontainerregistry.TokensClientGetOptions) (armcontainerregistry.TokensClientGetResponse, error) {
			return armcontainerregistry.TokensClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testRegistryTokenNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
	})
}
