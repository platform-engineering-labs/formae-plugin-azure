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

const testApimUserNativeID = testApimServiceNativeID + "/users/conformance-user"

func newTestApiManagementUser(api apiManagementUsersAPI) *ApiManagementUser {
	return &ApiManagementUser{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func apimUserDesired(firstName string) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":              "conformance-user",
		"resourceGroupName": "rg-1",
		"serviceName":       "apim1",
		"email":             "conformance.user@platform.engineering",
		"firstName":         firstName,
		"lastName":          "User",
		"note":              "Created by the conformance suite",
		"state":             "active",
	})
	return out
}

func TestApiManagementUser_CRUD(t *testing.T) {
	userResult := armapimanagement.UserContract{
		ID:   to.Ptr(testApimUserNativeID),
		Name: to.Ptr("conformance-user"),
		Properties: &armapimanagement.UserContractProperties{
			Email:            to.Ptr("conformance.user@platform.engineering"),
			FirstName:        to.Ptr("Conformance"),
			LastName:         to.Ptr("User"),
			Note:             to.Ptr("Created by the conformance suite"),
			State:            to.Ptr(armapimanagement.UserStateActive),
			RegistrationDate: to.Ptr(time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)),
			Groups: []*armapimanagement.GroupContractProperties{{
				DisplayName: to.Ptr("Developers"),
			}},
		},
	}

	var sentCreate armapimanagement.UserCreateParameters
	var sentUpdate armapimanagement.UserUpdateParameters
	var sawIfMatch string
	var sawDeleteOptions *armapimanagement.UserClientDeleteOptions
	deleteCalls := 0
	fake := &fakeApiManagementUsersAPI{
		createOrUpdateFn: func(_ context.Context, _, serviceName, userID string, params armapimanagement.UserCreateParameters, _ *armapimanagement.UserClientCreateOrUpdateOptions) (armapimanagement.UserClientCreateOrUpdateResponse, error) {
			require.Equal(t, "apim1", serviceName)
			require.Equal(t, "conformance-user", userID)
			sentCreate = params
			return armapimanagement.UserClientCreateOrUpdateResponse{UserContract: userResult}, nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ *armapimanagement.UserClientGetOptions) (armapimanagement.UserClientGetResponse, error) {
			return armapimanagement.UserClientGetResponse{UserContract: userResult}, nil
		},
		updateFn: func(_ context.Context, _, _, _, ifMatch string, params armapimanagement.UserUpdateParameters, _ *armapimanagement.UserClientUpdateOptions) (armapimanagement.UserClientUpdateResponse, error) {
			sawIfMatch = ifMatch
			sentUpdate = params
			return armapimanagement.UserClientUpdateResponse{UserContract: userResult}, nil
		},
		deleteFn: func(_ context.Context, _, _, _, ifMatch string, options *armapimanagement.UserClientDeleteOptions) (armapimanagement.UserClientDeleteResponse, error) {
			sawIfMatch = ifMatch
			sawDeleteOptions = options
			deleteCalls++
			return armapimanagement.UserClientDeleteResponse{}, nil
		},
		newListByServicePagerFn: func(_, _ string, _ *armapimanagement.UserClientListByServiceOptions) *runtime.Pager[armapimanagement.UserClientListByServiceResponse] {
			return runtime.NewPager(runtime.PagingHandler[armapimanagement.UserClientListByServiceResponse]{
				More: func(_ armapimanagement.UserClientListByServiceResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armapimanagement.UserClientListByServiceResponse) (armapimanagement.UserClientListByServiceResponse, error) {
					return armapimanagement.UserClientListByServiceResponse{
						UserCollection: armapimanagement.UserCollection{
							Value: []*armapimanagement.UserContract{{ID: to.Ptr(testApimUserNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestApiManagementUser(fake)

	t.Run("Create_is_synchronous_and_sends_no_email", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "conformance-user",
			Properties: apimUserDesired("Conformance"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testApimUserNativeID, got.ProgressResult.NativeID)
		require.Empty(t, got.ProgressResult.RequestID)
		require.Equal(t, "conformance.user@platform.engineering", *sentCreate.Properties.Email)
		require.Equal(t, "Conformance", *sentCreate.Properties.FirstName)
		require.Equal(t, armapimanagement.UserStateActive, *sentCreate.Properties.State)
		// Confirmation left nil means ARM sends nothing at all.
		require.Nil(t, sentCreate.Properties.Confirmation)
		// No password declared, so ARM generates one.
		require.Nil(t, sentCreate.Properties.Password)
	})

	t.Run("Create_forwards_password_and_confirmation_when_declared", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "conformance-user", "resourceGroupName": "rg-1", "serviceName": "apim1",
			"email": "a@b.invalid", "firstName": "A", "lastName": "B",
			"password": "Sup3rSecret!", "confirmation": "signup",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.Equal(t, "Sup3rSecret!", *sentCreate.Properties.Password)
		require.Equal(t, armapimanagement.ConfirmationSignup, *sentCreate.Properties.Confirmation)
	})

	t.Run("Create_requires_the_three_ARM_required_fields", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "u", "resourceGroupName": "rg-1", "serviceName": "apim1",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "email is required")

		props, _ = json.Marshal(map[string]any{
			"name": "u", "resourceGroupName": "rg-1", "serviceName": "apim1", "email": "a@b.invalid",
		})
		_, err = prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "firstName is required")

		props, _ = json.Marshal(map[string]any{
			"name": "u", "resourceGroupName": "rg-1", "serviceName": "apim1",
			"email": "a@b.invalid", "firstName": "A",
		})
		_, err = prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "lastName is required")
	})

	t.Run("Read_drops_registration_date_and_groups", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testApimUserNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "conformance-user", props["name"])
		require.Equal(t, "conformance.user@platform.engineering", props["email"])
		require.Equal(t, "active", props["state"])
		// Neither is in the schema: registrationDate changes on every recreate,
		// and groups mirrors the GroupUser links.
		require.NotContains(t, props, "registrationDate")
		require.NotContains(t, props, "groups")
		// Never echoed: ARM does not return it.
		require.NotContains(t, props, "password")
	})

	t.Run("Update_uses_patch_with_wildcard_if_match_and_no_confirmation", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testApimUserNativeID,
			DesiredProperties: apimUserDesired("Conformance2"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, "*", sawIfMatch)
		require.Equal(t, "Conformance2", *sentUpdate.Properties.FirstName)
	})

	t.Run("Delete_drops_subscriptions_and_notifies_nobody", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testApimUserNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
		require.Equal(t, "*", sawIfMatch)
		require.NotNil(t, sawDeleteOptions)
		require.True(t, *sawDeleteOptions.DeleteSubscriptions)
		require.False(t, *sawDeleteOptions.Notify)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _, _, _ string, _ *armapimanagement.UserClientDeleteOptions) (armapimanagement.UserClientDeleteResponse, error) {
			return armapimanagement.UserClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testApimUserNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_service", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "serviceName": "apim1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testApimUserNativeID}, got.NativeIDs)
	})

	t.Run("List_without_parents_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure_with_a_reason", func(t *testing.T) {
		fake.createOrUpdateFn = func(_ context.Context, _, _, _ string, _ armapimanagement.UserCreateParameters, _ *armapimanagement.UserClientCreateOrUpdateOptions) (armapimanagement.UserClientCreateOrUpdateResponse, error) {
			return armapimanagement.UserClientCreateOrUpdateResponse{}, &azcore.ResponseError{StatusCode: 400}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "conformance-user", Properties: apimUserDesired("Conformance"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.NotEmpty(t, got.ProgressResult.StatusMessage)
	})
}

func TestApiManagementUser_ReadNotFound(t *testing.T) {
	fake := &fakeApiManagementUsersAPI{
		getFn: func(_ context.Context, _, _, _ string, _ *armapimanagement.UserClientGetOptions) (armapimanagement.UserClientGetResponse, error) {
			return armapimanagement.UserClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestApiManagementUser(fake).Read(context.Background(),
		&resource.ReadRequest{NativeID: testApimUserNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeApiManagementUsersAPI struct {
	createOrUpdateFn        func(ctx context.Context, rgName, serviceName, userID string, params armapimanagement.UserCreateParameters, options *armapimanagement.UserClientCreateOrUpdateOptions) (armapimanagement.UserClientCreateOrUpdateResponse, error)
	getFn                   func(ctx context.Context, rgName, serviceName, userID string, options *armapimanagement.UserClientGetOptions) (armapimanagement.UserClientGetResponse, error)
	updateFn                func(ctx context.Context, rgName, serviceName, userID, ifMatch string, params armapimanagement.UserUpdateParameters, options *armapimanagement.UserClientUpdateOptions) (armapimanagement.UserClientUpdateResponse, error)
	deleteFn                func(ctx context.Context, rgName, serviceName, userID, ifMatch string, options *armapimanagement.UserClientDeleteOptions) (armapimanagement.UserClientDeleteResponse, error)
	newListByServicePagerFn func(rgName, serviceName string, options *armapimanagement.UserClientListByServiceOptions) *runtime.Pager[armapimanagement.UserClientListByServiceResponse]
}

func (f *fakeApiManagementUsersAPI) CreateOrUpdate(ctx context.Context, rgName, serviceName, userID string, params armapimanagement.UserCreateParameters, options *armapimanagement.UserClientCreateOrUpdateOptions) (armapimanagement.UserClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, serviceName, userID, params, options)
}

func (f *fakeApiManagementUsersAPI) Get(ctx context.Context, rgName, serviceName, userID string, options *armapimanagement.UserClientGetOptions) (armapimanagement.UserClientGetResponse, error) {
	return f.getFn(ctx, rgName, serviceName, userID, options)
}

func (f *fakeApiManagementUsersAPI) Update(ctx context.Context, rgName, serviceName, userID, ifMatch string, params armapimanagement.UserUpdateParameters, options *armapimanagement.UserClientUpdateOptions) (armapimanagement.UserClientUpdateResponse, error) {
	return f.updateFn(ctx, rgName, serviceName, userID, ifMatch, params, options)
}

func (f *fakeApiManagementUsersAPI) Delete(ctx context.Context, rgName, serviceName, userID, ifMatch string, options *armapimanagement.UserClientDeleteOptions) (armapimanagement.UserClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, serviceName, userID, ifMatch, options)
}

func (f *fakeApiManagementUsersAPI) NewListByServicePager(rgName, serviceName string, options *armapimanagement.UserClientListByServiceOptions) *runtime.Pager[armapimanagement.UserClientListByServiceResponse] {
	return f.newListByServicePagerFn(rgName, serviceName, options)
}
