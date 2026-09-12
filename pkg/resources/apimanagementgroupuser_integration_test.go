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

const testApimGroupUserNativeID = testApimGroupNativeID + "/users/conformance-user"

func newTestApiManagementGroupUser(api apiManagementGroupUsersAPI) *ApiManagementGroupUser {
	return &ApiManagementGroupUser{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func apimGroupUserDesired() []byte {
	out, _ := json.Marshal(map[string]any{
		"resourceGroupName": "rg-1",
		"serviceName":       "apim1",
		"groupName":         "partners",
		"userName":          "conformance-user",
	})
	return out
}

func TestApiManagementGroupUser_CRUD(t *testing.T) {
	var sawNames []string
	exists := true
	deleteCalls := 0
	fake := &fakeApiManagementGroupUsersAPI{
		createFn: func(_ context.Context, rgName, serviceName, groupID, userID string, _ *armapimanagement.GroupUserClientCreateOptions) (armapimanagement.GroupUserClientCreateResponse, error) {
			sawNames = []string{rgName, serviceName, groupID, userID}
			// ARM answers with the user's own contract, whose ID is NOT the link's.
			return armapimanagement.GroupUserClientCreateResponse{
				UserContract: armapimanagement.UserContract{ID: to.Ptr(testApimServiceNativeID + "/users/conformance-user")},
			}, nil
		},
		checkEntityExistsFn: func(_ context.Context, _, _, _, _ string, _ *armapimanagement.GroupUserClientCheckEntityExistsOptions) (armapimanagement.GroupUserClientCheckEntityExistsResponse, error) {
			return armapimanagement.GroupUserClientCheckEntityExistsResponse{Success: exists}, nil
		},
		deleteFn: func(_ context.Context, _, _, _, _ string, _ *armapimanagement.GroupUserClientDeleteOptions) (armapimanagement.GroupUserClientDeleteResponse, error) {
			deleteCalls++
			return armapimanagement.GroupUserClientDeleteResponse{}, nil
		},
		newListPagerFn: func(_, _, _ string, _ *armapimanagement.GroupUserClientListOptions) *runtime.Pager[armapimanagement.GroupUserClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armapimanagement.GroupUserClientListResponse]{
				More: func(_ armapimanagement.GroupUserClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armapimanagement.GroupUserClientListResponse) (armapimanagement.GroupUserClientListResponse, error) {
					return armapimanagement.GroupUserClientListResponse{
						UserCollection: armapimanagement.UserCollection{
							Value: []*armapimanagement.UserContract{{
								ID:   to.Ptr(testApimServiceNativeID + "/users/conformance-user"),
								Name: to.Ptr("conformance-user"),
							}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestApiManagementGroupUser(fake)

	t.Run("Create_composes_the_link_id_rather_than_reading_it_back", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "partners-conformance-user",
			Properties: apimGroupUserDesired(),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testApimGroupUserNativeID, got.ProgressResult.NativeID)
		require.Empty(t, got.ProgressResult.RequestID)
		require.Equal(t, []string{"rg-1", "apim1", "partners", "conformance-user"}, sawNames)
	})

	t.Run("Create_requires_both_ends", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName": "rg-1", "serviceName": "apim1", "groupName": "partners",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "userName is required")

		props, _ = json.Marshal(map[string]any{
			"resourceGroupName": "rg-1", "serviceName": "apim1", "userName": "conformance-user",
		})
		_, err = prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "groupName is required")
	})

	t.Run("Read_reports_both_ends", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testApimGroupUserNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "apim1", props["serviceName"])
		require.Equal(t, "partners", props["groupName"])
		require.Equal(t, "conformance-user", props["userName"])
		require.Equal(t, testApimGroupUserNativeID, props["id"])
	})

	t.Run("Read_of_an_unlinked_user_is_NotFound", func(t *testing.T) {
		exists = false
		defer func() { exists = true }()
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testApimGroupUserNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
	})

	t.Run("Update_re_puts_the_link", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testApimGroupUserNativeID,
			DesiredProperties: apimGroupUserDesired(),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testApimGroupUserNativeID, got.ProgressResult.NativeID)
	})

	t.Run("Delete_unlinks", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testApimGroupUserNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _, _, _ string, _ *armapimanagement.GroupUserClientDeleteOptions) (armapimanagement.GroupUserClientDeleteResponse, error) {
			return armapimanagement.GroupUserClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testApimGroupUserNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_composes_link_ids_from_the_user_names", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{
				"resourceGroupName": "rg-1", "serviceName": "apim1", "groupName": "partners",
			},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testApimGroupUserNativeID}, got.NativeIDs)
	})

	t.Run("List_without_parents_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure_with_a_reason", func(t *testing.T) {
		fake.createFn = func(_ context.Context, _, _, _, _ string, _ *armapimanagement.GroupUserClientCreateOptions) (armapimanagement.GroupUserClientCreateResponse, error) {
			return armapimanagement.GroupUserClientCreateResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: apimGroupUserDesired()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.NotEmpty(t, got.ProgressResult.StatusMessage)
	})
}

func TestApiManagementGroupUser_ReadError(t *testing.T) {
	fake := &fakeApiManagementGroupUsersAPI{
		checkEntityExistsFn: func(_ context.Context, _, _, _, _ string, _ *armapimanagement.GroupUserClientCheckEntityExistsOptions) (armapimanagement.GroupUserClientCheckEntityExistsResponse, error) {
			return armapimanagement.GroupUserClientCheckEntityExistsResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestApiManagementGroupUser(fake).Read(context.Background(),
		&resource.ReadRequest{NativeID: testApimGroupUserNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeApiManagementGroupUsersAPI struct {
	createFn            func(ctx context.Context, rgName, serviceName, groupID, userID string, options *armapimanagement.GroupUserClientCreateOptions) (armapimanagement.GroupUserClientCreateResponse, error)
	checkEntityExistsFn func(ctx context.Context, rgName, serviceName, groupID, userID string, options *armapimanagement.GroupUserClientCheckEntityExistsOptions) (armapimanagement.GroupUserClientCheckEntityExistsResponse, error)
	deleteFn            func(ctx context.Context, rgName, serviceName, groupID, userID string, options *armapimanagement.GroupUserClientDeleteOptions) (armapimanagement.GroupUserClientDeleteResponse, error)
	newListPagerFn      func(rgName, serviceName, groupID string, options *armapimanagement.GroupUserClientListOptions) *runtime.Pager[armapimanagement.GroupUserClientListResponse]
}

func (f *fakeApiManagementGroupUsersAPI) Create(ctx context.Context, rgName, serviceName, groupID, userID string, options *armapimanagement.GroupUserClientCreateOptions) (armapimanagement.GroupUserClientCreateResponse, error) {
	return f.createFn(ctx, rgName, serviceName, groupID, userID, options)
}

func (f *fakeApiManagementGroupUsersAPI) CheckEntityExists(ctx context.Context, rgName, serviceName, groupID, userID string, options *armapimanagement.GroupUserClientCheckEntityExistsOptions) (armapimanagement.GroupUserClientCheckEntityExistsResponse, error) {
	return f.checkEntityExistsFn(ctx, rgName, serviceName, groupID, userID, options)
}

func (f *fakeApiManagementGroupUsersAPI) Delete(ctx context.Context, rgName, serviceName, groupID, userID string, options *armapimanagement.GroupUserClientDeleteOptions) (armapimanagement.GroupUserClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, serviceName, groupID, userID, options)
}

func (f *fakeApiManagementGroupUsersAPI) NewListPager(rgName, serviceName, groupID string, options *armapimanagement.GroupUserClientListOptions) *runtime.Pager[armapimanagement.GroupUserClientListResponse] {
	return f.newListPagerFn(rgName, serviceName, groupID, options)
}
