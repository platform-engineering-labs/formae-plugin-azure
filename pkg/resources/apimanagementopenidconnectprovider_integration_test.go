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

const testApimOidcProviderNativeID = testApimServiceNativeID + "/openidConnectProviders/oidc1"

func newTestApiManagementOpenIdConnectProvider(api apiManagementOpenIDConnectProvidersAPI) *ApiManagementOpenIdConnectProvider {
	return &ApiManagementOpenIdConnectProvider{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func apimOidcProviderDesired(displayName string) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":              "oidc1",
		"resourceGroupName": "rg-1",
		"serviceName":       "apim1",
		"displayName":       displayName,
		"metadataEndpoint":  "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration",
		"clientId":          "client-1",
		"description":       "Entra ID",
	})
	return out
}

func TestApiManagementOpenIdConnectProvider_CRUD(t *testing.T) {
	providerResult := armapimanagement.OpenidConnectProviderContract{
		ID:   to.Ptr(testApimOidcProviderNativeID),
		Name: to.Ptr("oidc1"),
		Properties: &armapimanagement.OpenidConnectProviderContractProperties{
			DisplayName:      to.Ptr("Entra ID"),
			MetadataEndpoint: to.Ptr("https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration"),
			ClientID:         to.Ptr("client-1"),
			Description:      to.Ptr("Entra ID"),
			// ARM never returns the secret from a Get; this stands in for a
			// hypothetical leak, and the read must drop it either way.
			ClientSecret: to.Ptr("should-never-be-serialized"),
		},
	}

	var sentCreate armapimanagement.OpenidConnectProviderContract
	var sentUpdate armapimanagement.OpenidConnectProviderUpdateContract
	var sawIfMatch string
	createCalls := 0
	deleteCalls := 0
	fake := &fakeApiManagementOpenIDConnectProvidersAPI{
		createOrUpdateFn: func(_ context.Context, _, serviceName, opid string, params armapimanagement.OpenidConnectProviderContract, _ *armapimanagement.OpenIDConnectProviderClientCreateOrUpdateOptions) (armapimanagement.OpenIDConnectProviderClientCreateOrUpdateResponse, error) {
			require.Equal(t, "apim1", serviceName)
			require.Equal(t, "oidc1", opid)
			sentCreate = params
			createCalls++
			return armapimanagement.OpenIDConnectProviderClientCreateOrUpdateResponse{OpenidConnectProviderContract: providerResult}, nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ *armapimanagement.OpenIDConnectProviderClientGetOptions) (armapimanagement.OpenIDConnectProviderClientGetResponse, error) {
			return armapimanagement.OpenIDConnectProviderClientGetResponse{OpenidConnectProviderContract: providerResult}, nil
		},
		updateFn: func(_ context.Context, _, _, _, ifMatch string, params armapimanagement.OpenidConnectProviderUpdateContract, _ *armapimanagement.OpenIDConnectProviderClientUpdateOptions) (armapimanagement.OpenIDConnectProviderClientUpdateResponse, error) {
			sawIfMatch = ifMatch
			sentUpdate = params
			return armapimanagement.OpenIDConnectProviderClientUpdateResponse{}, nil
		},
		deleteFn: func(_ context.Context, _, _, _, ifMatch string, _ *armapimanagement.OpenIDConnectProviderClientDeleteOptions) (armapimanagement.OpenIDConnectProviderClientDeleteResponse, error) {
			sawIfMatch = ifMatch
			deleteCalls++
			return armapimanagement.OpenIDConnectProviderClientDeleteResponse{}, nil
		},
		newListByServicePagerFn: func(_, _ string, _ *armapimanagement.OpenIDConnectProviderClientListByServiceOptions) *runtime.Pager[armapimanagement.OpenIDConnectProviderClientListByServiceResponse] {
			return runtime.NewPager(runtime.PagingHandler[armapimanagement.OpenIDConnectProviderClientListByServiceResponse]{
				More: func(_ armapimanagement.OpenIDConnectProviderClientListByServiceResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armapimanagement.OpenIDConnectProviderClientListByServiceResponse) (armapimanagement.OpenIDConnectProviderClientListByServiceResponse, error) {
					return armapimanagement.OpenIDConnectProviderClientListByServiceResponse{
						OpenIDConnectProviderCollection: armapimanagement.OpenIDConnectProviderCollection{
							Value: []*armapimanagement.OpenidConnectProviderContract{{ID: to.Ptr(testApimOidcProviderNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestApiManagementOpenIdConnectProvider(fake)

	t.Run("Create_is_synchronous", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "oidc1",
			Properties: apimOidcProviderDesired("Entra ID"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testApimOidcProviderNativeID, got.ProgressResult.NativeID)
		require.Empty(t, got.ProgressResult.RequestID)

		require.Equal(t, "client-1", *sentCreate.Properties.ClientID)
		require.Contains(t, *sentCreate.Properties.MetadataEndpoint, ".well-known/openid-configuration")
		// No secret was declared, so none may be invented.
		require.Nil(t, sentCreate.Properties.ClientSecret)
	})

	t.Run("Create_sends_the_secret_when_declared", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "oidc1", "resourceGroupName": "rg-1", "serviceName": "apim1",
			"displayName": "Entra ID", "metadataEndpoint": "https://idp/.well-known/openid-configuration",
			"clientId": "client-1", "clientSecret": "s3cr3t",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.Equal(t, "s3cr3t", *sentCreate.Properties.ClientSecret)
	})

	t.Run("Create_requires_metadata_endpoint", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "oidc1", "resourceGroupName": "rg-1", "serviceName": "apim1", "displayName": "Entra ID",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "metadataEndpoint is required")
	})

	t.Run("Create_requires_client_id", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "oidc1", "resourceGroupName": "rg-1", "serviceName": "apim1",
			"displayName": "Entra ID", "metadataEndpoint": "https://idp/.well-known/openid-configuration",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "clientId is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testApimOidcProviderNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "oidc1", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "apim1", props["serviceName"])
		require.Equal(t, "client-1", props["clientId"])
		require.Equal(t, "Entra ID", props["displayName"])
	})

	// Putting the client secret in resource state would persist a live
	// credential.
	t.Run("Read_never_serializes_the_secret", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testApimOidcProviderNativeID})
		require.NoError(t, err)
		require.NotContains(t, got.Properties, "clientSecret")
		require.NotContains(t, got.Properties, "should-never-be-serialized")
	})

	// The PATCH answers 204 with no body, so the handler has to re-read to
	// report the current state.
	t.Run("Update_rereads_after_the_empty_patch", func(t *testing.T) {
		before := createCalls
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testApimOidcProviderNativeID,
			DesiredProperties: apimOidcProviderDesired("Entra ID v2"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, "*", sawIfMatch)
		require.Equal(t, "Entra ID v2", *sentUpdate.Properties.DisplayName)
		require.Equal(t, before, createCalls)

		var props map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &props))
		require.Equal(t, "oidc1", props["name"])
	})

	t.Run("Delete_is_synchronous", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testApimOidcProviderNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
		require.Equal(t, "*", sawIfMatch)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _, _, _ string, _ *armapimanagement.OpenIDConnectProviderClientDeleteOptions) (armapimanagement.OpenIDConnectProviderClientDeleteResponse, error) {
			return armapimanagement.OpenIDConnectProviderClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testApimOidcProviderNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_service", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "serviceName": "apim1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testApimOidcProviderNativeID}, got.NativeIDs)
	})

	t.Run("List_without_parents_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure_with_a_reason", func(t *testing.T) {
		fake.createOrUpdateFn = func(_ context.Context, _, _, _ string, _ armapimanagement.OpenidConnectProviderContract, _ *armapimanagement.OpenIDConnectProviderClientCreateOrUpdateOptions) (armapimanagement.OpenIDConnectProviderClientCreateOrUpdateResponse, error) {
			return armapimanagement.OpenIDConnectProviderClientCreateOrUpdateResponse{}, &azcore.ResponseError{StatusCode: 400}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "oidc1", Properties: apimOidcProviderDesired("Entra ID"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.NotEmpty(t, got.ProgressResult.StatusMessage)
	})
}

func TestApiManagementOpenIdConnectProvider_ReadNotFound(t *testing.T) {
	fake := &fakeApiManagementOpenIDConnectProvidersAPI{
		getFn: func(_ context.Context, _, _, _ string, _ *armapimanagement.OpenIDConnectProviderClientGetOptions) (armapimanagement.OpenIDConnectProviderClientGetResponse, error) {
			return armapimanagement.OpenIDConnectProviderClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestApiManagementOpenIdConnectProvider(fake).Read(context.Background(),
		&resource.ReadRequest{NativeID: testApimOidcProviderNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeApiManagementOpenIDConnectProvidersAPI struct {
	createOrUpdateFn        func(ctx context.Context, rgName, serviceName, opid string, params armapimanagement.OpenidConnectProviderContract, options *armapimanagement.OpenIDConnectProviderClientCreateOrUpdateOptions) (armapimanagement.OpenIDConnectProviderClientCreateOrUpdateResponse, error)
	getFn                   func(ctx context.Context, rgName, serviceName, opid string, options *armapimanagement.OpenIDConnectProviderClientGetOptions) (armapimanagement.OpenIDConnectProviderClientGetResponse, error)
	updateFn                func(ctx context.Context, rgName, serviceName, opid, ifMatch string, params armapimanagement.OpenidConnectProviderUpdateContract, options *armapimanagement.OpenIDConnectProviderClientUpdateOptions) (armapimanagement.OpenIDConnectProviderClientUpdateResponse, error)
	deleteFn                func(ctx context.Context, rgName, serviceName, opid, ifMatch string, options *armapimanagement.OpenIDConnectProviderClientDeleteOptions) (armapimanagement.OpenIDConnectProviderClientDeleteResponse, error)
	newListByServicePagerFn func(rgName, serviceName string, options *armapimanagement.OpenIDConnectProviderClientListByServiceOptions) *runtime.Pager[armapimanagement.OpenIDConnectProviderClientListByServiceResponse]
}

func (f *fakeApiManagementOpenIDConnectProvidersAPI) CreateOrUpdate(ctx context.Context, rgName, serviceName, opid string, params armapimanagement.OpenidConnectProviderContract, options *armapimanagement.OpenIDConnectProviderClientCreateOrUpdateOptions) (armapimanagement.OpenIDConnectProviderClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, serviceName, opid, params, options)
}

func (f *fakeApiManagementOpenIDConnectProvidersAPI) Get(ctx context.Context, rgName, serviceName, opid string, options *armapimanagement.OpenIDConnectProviderClientGetOptions) (armapimanagement.OpenIDConnectProviderClientGetResponse, error) {
	return f.getFn(ctx, rgName, serviceName, opid, options)
}

func (f *fakeApiManagementOpenIDConnectProvidersAPI) Update(ctx context.Context, rgName, serviceName, opid, ifMatch string, params armapimanagement.OpenidConnectProviderUpdateContract, options *armapimanagement.OpenIDConnectProviderClientUpdateOptions) (armapimanagement.OpenIDConnectProviderClientUpdateResponse, error) {
	return f.updateFn(ctx, rgName, serviceName, opid, ifMatch, params, options)
}

func (f *fakeApiManagementOpenIDConnectProvidersAPI) Delete(ctx context.Context, rgName, serviceName, opid, ifMatch string, options *armapimanagement.OpenIDConnectProviderClientDeleteOptions) (armapimanagement.OpenIDConnectProviderClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, serviceName, opid, ifMatch, options)
}

func (f *fakeApiManagementOpenIDConnectProvidersAPI) NewListByServicePager(rgName, serviceName string, options *armapimanagement.OpenIDConnectProviderClientListByServiceOptions) *runtime.Pager[armapimanagement.OpenIDConnectProviderClientListByServiceResponse] {
	return f.newListByServicePagerFn(rgName, serviceName, options)
}
