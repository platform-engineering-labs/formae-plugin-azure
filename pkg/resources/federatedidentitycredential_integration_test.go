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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/msi/armmsi"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testFICNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.ManagedIdentity/userAssignedIdentities/uai-1/federatedIdentityCredentials/fic-1"

func TestFederatedIdentityCredential_CRUD(t *testing.T) {
	upstream := armmsi.FederatedIdentityCredential{
		ID:   to.Ptr(testFICNativeID),
		Name: to.Ptr("fic-1"),
		Properties: &armmsi.FederatedIdentityCredentialProperties{
			Issuer:    to.Ptr("https://oidc.example/issuer"),
			Subject:   to.Ptr("system:serviceaccount:ns:sa"),
			Audiences: []*string{to.Ptr("api://AzureADTokenExchange")},
		},
	}
	fake := &fakeFederatedIdentityCredentialsAPI{
		createOrUpdateFn: func(_ context.Context, _, _, _ string, _ armmsi.FederatedIdentityCredential, _ *armmsi.FederatedIdentityCredentialsClientCreateOrUpdateOptions) (armmsi.FederatedIdentityCredentialsClientCreateOrUpdateResponse, error) {
			return armmsi.FederatedIdentityCredentialsClientCreateOrUpdateResponse{FederatedIdentityCredential: upstream}, nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ *armmsi.FederatedIdentityCredentialsClientGetOptions) (armmsi.FederatedIdentityCredentialsClientGetResponse, error) {
			return armmsi.FederatedIdentityCredentialsClientGetResponse{FederatedIdentityCredential: upstream}, nil
		},
		deleteFn: func(_ context.Context, _, _, _ string, _ *armmsi.FederatedIdentityCredentialsClientDeleteOptions) (armmsi.FederatedIdentityCredentialsClientDeleteResponse, error) {
			return armmsi.FederatedIdentityCredentialsClientDeleteResponse{}, nil
		},
		newListPagerFn: func(_, _ string, _ *armmsi.FederatedIdentityCredentialsClientListOptions) *runtime.Pager[armmsi.FederatedIdentityCredentialsClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armmsi.FederatedIdentityCredentialsClientListResponse]{
				More: func(_ armmsi.FederatedIdentityCredentialsClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armmsi.FederatedIdentityCredentialsClientListResponse) (armmsi.FederatedIdentityCredentialsClientListResponse, error) {
					return armmsi.FederatedIdentityCredentialsClientListResponse{
						FederatedIdentityCredentialsListResult: armmsi.FederatedIdentityCredentialsListResult{
							Value: []*armmsi.FederatedIdentityCredential{{ID: to.Ptr(testFICNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestFederatedIdentityCredential(fake)

	mkProps := func() json.RawMessage {
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName":        "rg-1",
			"userAssignedIdentityName": "uai-1",
			"name":                     "fic-1",
			"issuer":                   "https://oidc.example/issuer",
			"subject":                  "system:serviceaccount:ns:sa",
			"audiences":                []string{"api://AzureADTokenExchange"},
		})
		return props
	}

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testFICNativeID, got.ProgressResult.NativeID)

		var serialized map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &serialized))
		require.Equal(t, "https://oidc.example/issuer", serialized["issuer"])
		require.Equal(t, "system:serviceaccount:ns:sa", serialized["subject"])
		require.Equal(t, testFICNativeID, serialized["id"])
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testFICNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _, _ string, _ *armmsi.FederatedIdentityCredentialsClientDeleteOptions) (armmsi.FederatedIdentityCredentialsClientDeleteResponse, error) {
			return armmsi.FederatedIdentityCredentialsClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testFICNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{
				"resourceGroupName":        "rg-1",
				"userAssignedIdentityName": "uai-1",
			},
		})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 1)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.createOrUpdateFn = func(_ context.Context, _, _, _ string, _ armmsi.FederatedIdentityCredential, _ *armmsi.FederatedIdentityCredentialsClientCreateOrUpdateOptions) (armmsi.FederatedIdentityCredentialsClientCreateOrUpdateResponse, error) {
			return armmsi.FederatedIdentityCredentialsClientCreateOrUpdateResponse{}, &azcore.ResponseError{StatusCode: 403}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

// --- Test helpers ---

func newTestFederatedIdentityCredential(api federatedIdentityCredentialsAPI) *FederatedIdentityCredential {
	return &FederatedIdentityCredential{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

type fakeFederatedIdentityCredentialsAPI struct {
	createOrUpdateFn func(ctx context.Context, rgName, uaiName, ficName string, params armmsi.FederatedIdentityCredential, opts *armmsi.FederatedIdentityCredentialsClientCreateOrUpdateOptions) (armmsi.FederatedIdentityCredentialsClientCreateOrUpdateResponse, error)
	getFn            func(ctx context.Context, rgName, uaiName, ficName string, opts *armmsi.FederatedIdentityCredentialsClientGetOptions) (armmsi.FederatedIdentityCredentialsClientGetResponse, error)
	deleteFn         func(ctx context.Context, rgName, uaiName, ficName string, opts *armmsi.FederatedIdentityCredentialsClientDeleteOptions) (armmsi.FederatedIdentityCredentialsClientDeleteResponse, error)
	newListPagerFn   func(rgName, uaiName string, opts *armmsi.FederatedIdentityCredentialsClientListOptions) *runtime.Pager[armmsi.FederatedIdentityCredentialsClientListResponse]
}

func (f *fakeFederatedIdentityCredentialsAPI) CreateOrUpdate(ctx context.Context, rgName, uaiName, ficName string, params armmsi.FederatedIdentityCredential, opts *armmsi.FederatedIdentityCredentialsClientCreateOrUpdateOptions) (armmsi.FederatedIdentityCredentialsClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, uaiName, ficName, params, opts)
}

func (f *fakeFederatedIdentityCredentialsAPI) Get(ctx context.Context, rgName, uaiName, ficName string, opts *armmsi.FederatedIdentityCredentialsClientGetOptions) (armmsi.FederatedIdentityCredentialsClientGetResponse, error) {
	return f.getFn(ctx, rgName, uaiName, ficName, opts)
}

func (f *fakeFederatedIdentityCredentialsAPI) Delete(ctx context.Context, rgName, uaiName, ficName string, opts *armmsi.FederatedIdentityCredentialsClientDeleteOptions) (armmsi.FederatedIdentityCredentialsClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, uaiName, ficName, opts)
}

func (f *fakeFederatedIdentityCredentialsAPI) NewListPager(rgName, uaiName string, opts *armmsi.FederatedIdentityCredentialsClientListOptions) *runtime.Pager[armmsi.FederatedIdentityCredentialsClientListResponse] {
	return f.newListPagerFn(rgName, uaiName, opts)
}
