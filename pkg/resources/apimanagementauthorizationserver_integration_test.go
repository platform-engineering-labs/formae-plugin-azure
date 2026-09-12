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

const testApimAuthServerNativeID = testApimServiceNativeID + "/authorizationServers/auth1"

func newTestApiManagementAuthorizationServer(api apiManagementAuthorizationServersAPI) *ApiManagementAuthorizationServer {
	return &ApiManagementAuthorizationServer{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func apimAuthServerDesired(displayName string) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":                       "auth1",
		"resourceGroupName":          "rg-1",
		"serviceName":                "apim1",
		"displayName":                displayName,
		"authorizationEndpoint":      "https://login.example.com/authorize",
		"clientRegistrationEndpoint": "https://login.example.com/register",
		"clientId":                   "client-1",
		"grantTypes":                 []string{"implicit"},
	})
	return out
}

func TestApiManagementAuthorizationServer_CRUD(t *testing.T) {
	serverResult := armapimanagement.AuthorizationServerContract{
		ID:   to.Ptr(testApimAuthServerNativeID),
		Name: to.Ptr("auth1"),
		Properties: &armapimanagement.AuthorizationServerContractProperties{
			DisplayName:                to.Ptr("Example IdP"),
			AuthorizationEndpoint:      to.Ptr("https://login.example.com/authorize"),
			ClientRegistrationEndpoint: to.Ptr("https://login.example.com/register"),
			ClientID:                   to.Ptr("client-1"),
			GrantTypes:                 []*armapimanagement.GrantType{to.Ptr(armapimanagement.GrantTypeImplicit)},
			AuthorizationMethods:       []*armapimanagement.AuthorizationMethod{to.Ptr(armapimanagement.AuthorizationMethodGET)},
			BearerTokenSendingMethods:  []*armapimanagement.BearerTokenSendingMethod{to.Ptr(armapimanagement.BearerTokenSendingMethodAuthorizationHeader)},
			ClientAuthenticationMethod: []*armapimanagement.ClientAuthenticationMethod{to.Ptr(armapimanagement.ClientAuthenticationMethodBasic)},
			SupportState:               to.Ptr(false),
			// ARM never returns the secret from a Get; this stands in for a
			// hypothetical leak, and the read must drop it either way.
			ClientSecret:          to.Ptr("should-never-be-serialized"),
			ResourceOwnerUsername: to.Ptr("owner"),
		},
	}

	var sentCreate armapimanagement.AuthorizationServerContract
	var sentUpdate armapimanagement.AuthorizationServerUpdateContract
	var sawIfMatch string
	createCalls := 0
	deleteCalls := 0
	fake := &fakeApiManagementAuthorizationServersAPI{
		createOrUpdateFn: func(_ context.Context, _, serviceName, authsid string, params armapimanagement.AuthorizationServerContract, _ *armapimanagement.AuthorizationServerClientCreateOrUpdateOptions) (armapimanagement.AuthorizationServerClientCreateOrUpdateResponse, error) {
			require.Equal(t, "apim1", serviceName)
			require.Equal(t, "auth1", authsid)
			sentCreate = params
			createCalls++
			return armapimanagement.AuthorizationServerClientCreateOrUpdateResponse{AuthorizationServerContract: serverResult}, nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ *armapimanagement.AuthorizationServerClientGetOptions) (armapimanagement.AuthorizationServerClientGetResponse, error) {
			return armapimanagement.AuthorizationServerClientGetResponse{AuthorizationServerContract: serverResult}, nil
		},
		updateFn: func(_ context.Context, _, _, _, ifMatch string, params armapimanagement.AuthorizationServerUpdateContract, _ *armapimanagement.AuthorizationServerClientUpdateOptions) (armapimanagement.AuthorizationServerClientUpdateResponse, error) {
			sawIfMatch = ifMatch
			sentUpdate = params
			return armapimanagement.AuthorizationServerClientUpdateResponse{}, nil
		},
		deleteFn: func(_ context.Context, _, _, _, ifMatch string, _ *armapimanagement.AuthorizationServerClientDeleteOptions) (armapimanagement.AuthorizationServerClientDeleteResponse, error) {
			sawIfMatch = ifMatch
			deleteCalls++
			return armapimanagement.AuthorizationServerClientDeleteResponse{}, nil
		},
		newListByServicePagerFn: func(_, _ string, _ *armapimanagement.AuthorizationServerClientListByServiceOptions) *runtime.Pager[armapimanagement.AuthorizationServerClientListByServiceResponse] {
			return runtime.NewPager(runtime.PagingHandler[armapimanagement.AuthorizationServerClientListByServiceResponse]{
				More: func(_ armapimanagement.AuthorizationServerClientListByServiceResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armapimanagement.AuthorizationServerClientListByServiceResponse) (armapimanagement.AuthorizationServerClientListByServiceResponse, error) {
					return armapimanagement.AuthorizationServerClientListByServiceResponse{
						AuthorizationServerCollection: armapimanagement.AuthorizationServerCollection{
							Value: []*armapimanagement.AuthorizationServerContract{{ID: to.Ptr(testApimAuthServerNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestApiManagementAuthorizationServer(fake)

	t.Run("Create_is_synchronous", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "auth1",
			Properties: apimAuthServerDesired("Example IdP"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testApimAuthServerNativeID, got.ProgressResult.NativeID)
		require.Empty(t, got.ProgressResult.RequestID)

		require.Equal(t, armapimanagement.GrantTypeImplicit, *sentCreate.Properties.GrantTypes[0])
		// The implicit flow needs no token endpoint and no secret, so neither
		// may be invented.
		require.Nil(t, sentCreate.Properties.TokenEndpoint)
		require.Nil(t, sentCreate.Properties.ClientSecret)
		// The three method lists are omitted so ARM applies its own defaults.
		require.Nil(t, sentCreate.Properties.AuthorizationMethods)
		require.Nil(t, sentCreate.Properties.BearerTokenSendingMethods)
		require.Nil(t, sentCreate.Properties.ClientAuthenticationMethod)
	})

	t.Run("Create_sends_the_secret_and_token_endpoint_when_declared", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "auth1", "resourceGroupName": "rg-1", "serviceName": "apim1",
			"displayName": "Example IdP", "authorizationEndpoint": "https://login.example.com/authorize",
			"clientRegistrationEndpoint": "https://login.example.com/register",
			"clientId":                   "client-1", "grantTypes": []string{"authorizationCode"},
			"tokenEndpoint": "https://login.example.com/token", "clientSecret": "s3cr3t",
			"authorizationMethods": []string{"GET", "POST"},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.Equal(t, "https://login.example.com/token", *sentCreate.Properties.TokenEndpoint)
		require.Equal(t, "s3cr3t", *sentCreate.Properties.ClientSecret)
		require.Len(t, sentCreate.Properties.AuthorizationMethods, 2)
	})

	t.Run("Create_requires_grant_types", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "auth1", "resourceGroupName": "rg-1", "serviceName": "apim1",
			"displayName": "Example IdP", "authorizationEndpoint": "https://a",
			"clientRegistrationEndpoint": "https://b", "clientId": "client-1",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "grantTypes is required")
	})

	t.Run("Create_requires_client_registration_endpoint", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "auth1", "resourceGroupName": "rg-1", "serviceName": "apim1",
			"displayName": "Example IdP", "authorizationEndpoint": "https://a",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "clientRegistrationEndpoint is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testApimAuthServerNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "auth1", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "apim1", props["serviceName"])
		require.Equal(t, "client-1", props["clientId"])
		require.Equal(t, []any{"implicit"}, props["grantTypes"])
		require.Equal(t, []any{"GET"}, props["authorizationMethods"])
		require.Equal(t, []any{"authorizationHeader"}, props["bearerTokenSendingMethods"])
		require.Equal(t, false, props["supportState"])
	})

	// Putting the client secret or the resource-owner credentials in resource
	// state would persist live credentials.
	t.Run("Read_never_serializes_credentials", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testApimAuthServerNativeID})
		require.NoError(t, err)
		require.NotContains(t, got.Properties, "clientSecret")
		require.NotContains(t, got.Properties, "should-never-be-serialized")
		require.NotContains(t, got.Properties, "resourceOwnerUsername")
	})

	// The PATCH answers 204 with no body, so the handler has to re-read to
	// report the current state.
	t.Run("Update_rereads_after_the_empty_patch", func(t *testing.T) {
		before := createCalls
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testApimAuthServerNativeID,
			DesiredProperties: apimAuthServerDesired("Example IdP v2"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, "*", sawIfMatch)
		require.Equal(t, "Example IdP v2", *sentUpdate.Properties.DisplayName)
		require.Equal(t, before, createCalls)

		var props map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &props))
		require.Equal(t, "auth1", props["name"])
	})

	t.Run("Delete_is_synchronous", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testApimAuthServerNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
		require.Equal(t, "*", sawIfMatch)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _, _, _ string, _ *armapimanagement.AuthorizationServerClientDeleteOptions) (armapimanagement.AuthorizationServerClientDeleteResponse, error) {
			return armapimanagement.AuthorizationServerClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testApimAuthServerNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_service", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "serviceName": "apim1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testApimAuthServerNativeID}, got.NativeIDs)
	})

	t.Run("List_without_parents_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure_with_a_reason", func(t *testing.T) {
		fake.createOrUpdateFn = func(_ context.Context, _, _, _ string, _ armapimanagement.AuthorizationServerContract, _ *armapimanagement.AuthorizationServerClientCreateOrUpdateOptions) (armapimanagement.AuthorizationServerClientCreateOrUpdateResponse, error) {
			return armapimanagement.AuthorizationServerClientCreateOrUpdateResponse{}, &azcore.ResponseError{StatusCode: 400}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "auth1", Properties: apimAuthServerDesired("Example IdP"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.NotEmpty(t, got.ProgressResult.StatusMessage)
	})
}

func TestApiManagementAuthorizationServer_ReadNotFound(t *testing.T) {
	fake := &fakeApiManagementAuthorizationServersAPI{
		getFn: func(_ context.Context, _, _, _ string, _ *armapimanagement.AuthorizationServerClientGetOptions) (armapimanagement.AuthorizationServerClientGetResponse, error) {
			return armapimanagement.AuthorizationServerClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestApiManagementAuthorizationServer(fake).Read(context.Background(),
		&resource.ReadRequest{NativeID: testApimAuthServerNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeApiManagementAuthorizationServersAPI struct {
	createOrUpdateFn        func(ctx context.Context, rgName, serviceName, authsid string, params armapimanagement.AuthorizationServerContract, options *armapimanagement.AuthorizationServerClientCreateOrUpdateOptions) (armapimanagement.AuthorizationServerClientCreateOrUpdateResponse, error)
	getFn                   func(ctx context.Context, rgName, serviceName, authsid string, options *armapimanagement.AuthorizationServerClientGetOptions) (armapimanagement.AuthorizationServerClientGetResponse, error)
	updateFn                func(ctx context.Context, rgName, serviceName, authsid, ifMatch string, params armapimanagement.AuthorizationServerUpdateContract, options *armapimanagement.AuthorizationServerClientUpdateOptions) (armapimanagement.AuthorizationServerClientUpdateResponse, error)
	deleteFn                func(ctx context.Context, rgName, serviceName, authsid, ifMatch string, options *armapimanagement.AuthorizationServerClientDeleteOptions) (armapimanagement.AuthorizationServerClientDeleteResponse, error)
	newListByServicePagerFn func(rgName, serviceName string, options *armapimanagement.AuthorizationServerClientListByServiceOptions) *runtime.Pager[armapimanagement.AuthorizationServerClientListByServiceResponse]
}

func (f *fakeApiManagementAuthorizationServersAPI) CreateOrUpdate(ctx context.Context, rgName, serviceName, authsid string, params armapimanagement.AuthorizationServerContract, options *armapimanagement.AuthorizationServerClientCreateOrUpdateOptions) (armapimanagement.AuthorizationServerClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, serviceName, authsid, params, options)
}

func (f *fakeApiManagementAuthorizationServersAPI) Get(ctx context.Context, rgName, serviceName, authsid string, options *armapimanagement.AuthorizationServerClientGetOptions) (armapimanagement.AuthorizationServerClientGetResponse, error) {
	return f.getFn(ctx, rgName, serviceName, authsid, options)
}

func (f *fakeApiManagementAuthorizationServersAPI) Update(ctx context.Context, rgName, serviceName, authsid, ifMatch string, params armapimanagement.AuthorizationServerUpdateContract, options *armapimanagement.AuthorizationServerClientUpdateOptions) (armapimanagement.AuthorizationServerClientUpdateResponse, error) {
	return f.updateFn(ctx, rgName, serviceName, authsid, ifMatch, params, options)
}

func (f *fakeApiManagementAuthorizationServersAPI) Delete(ctx context.Context, rgName, serviceName, authsid, ifMatch string, options *armapimanagement.AuthorizationServerClientDeleteOptions) (armapimanagement.AuthorizationServerClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, serviceName, authsid, ifMatch, options)
}

func (f *fakeApiManagementAuthorizationServersAPI) NewListByServicePager(rgName, serviceName string, options *armapimanagement.AuthorizationServerClientListByServiceOptions) *runtime.Pager[armapimanagement.AuthorizationServerClientListByServiceResponse] {
	return f.newListByServicePagerFn(rgName, serviceName, options)
}
