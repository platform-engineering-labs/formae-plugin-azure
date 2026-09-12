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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testStorageLocalUserNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Storage/storageAccounts/acct1/localUsers/sftpuser"

func localUserDesired(homeDir string) json.RawMessage {
	props, _ := json.Marshal(map[string]any{
		"resourceGroupName":     "rg-1",
		"storageAccountName":    "acct1",
		"name":                  "sftpuser",
		"homeDirectory":         homeDir,
		"hasSharedKey":          false,
		"hasSshPassword":        true,
		"allowAclAuthorization": true,
		"permissionScopes": []map[string]any{
			{"permissions": "rwl", "resourceName": "uploads", "service": "blob"},
		},
		"sshAuthorizedKeys": []map[string]any{
			{"key": "ssh-rsa AAAAB3NzaC1yc2E=", "description": "conformance"},
		},
	})
	return props
}

// echoLocalUser answers the way ARM does: the request properties come back, with
// the server-assigned sid and userId added.
func echoLocalUser(sent armstorage.LocalUser) armstorage.LocalUser {
	sent.ID = to.Ptr(testStorageLocalUserNativeID)
	sent.Name = to.Ptr("sftpuser")
	if sent.Properties != nil {
		sent.Properties.Sid = to.Ptr("S-1-2-0-1")
		sent.Properties.UserID = to.Ptr[int32](1000)
	}
	return sent
}

func TestStorageLocalUser_CRUD(t *testing.T) {
	var lastSent armstorage.LocalUser
	fake := &fakeStorageLocalUsersAPI{
		createOrUpdateFn: func(_ context.Context, _, _, _ string, props armstorage.LocalUser, _ *armstorage.LocalUsersClientCreateOrUpdateOptions) (armstorage.LocalUsersClientCreateOrUpdateResponse, error) {
			lastSent = props
			return armstorage.LocalUsersClientCreateOrUpdateResponse{LocalUser: echoLocalUser(props)}, nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ *armstorage.LocalUsersClientGetOptions) (armstorage.LocalUsersClientGetResponse, error) {
			return armstorage.LocalUsersClientGetResponse{LocalUser: echoLocalUser(lastSent)}, nil
		},
		deleteFn: func(_ context.Context, _, _, _ string, _ *armstorage.LocalUsersClientDeleteOptions) (armstorage.LocalUsersClientDeleteResponse, error) {
			return armstorage.LocalUsersClientDeleteResponse{}, nil
		},
		newListPagerFn: func(_, _ string, _ *armstorage.LocalUsersClientListOptions) *runtime.Pager[armstorage.LocalUsersClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armstorage.LocalUsersClientListResponse]{
				More: func(_ armstorage.LocalUsersClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armstorage.LocalUsersClientListResponse) (armstorage.LocalUsersClientListResponse, error) {
					return armstorage.LocalUsersClientListResponse{
						LocalUsers: armstorage.LocalUsers{
							Value: []*armstorage.LocalUser{{ID: to.Ptr(testStorageLocalUserNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestStorageLocalUser(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: localUserDesired("uploads/incoming")})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testStorageLocalUserNativeID, got.ProgressResult.NativeID)

		// hasSSHKey is derived, never taken from the caller.
		require.True(t, *lastSent.Properties.HasSSHKey)
		require.True(t, *lastSent.Properties.HasSSHPassword)
		require.False(t, *lastSent.Properties.HasSharedKey)
		require.True(t, *lastSent.Properties.AllowACLAuthorization)
		require.Len(t, lastSent.Properties.PermissionScopes, 1)
		require.Equal(t, "rwl", *lastSent.Properties.PermissionScopes[0].Permissions)
		require.Equal(t, "blob", *lastSent.Properties.PermissionScopes[0].Service)
		require.Equal(t, "ssh-rsa AAAAB3NzaC1yc2E=", *lastSent.Properties.SSHAuthorizedKeys[0].Key)

		var serialized map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &serialized))
		require.Equal(t, "sftpuser", serialized["name"])
		require.Equal(t, "acct1", serialized["storageAccountName"])
		require.Equal(t, "rg-1", serialized["resourceGroupName"])
		require.Equal(t, "uploads/incoming", serialized["homeDirectory"])
		require.Equal(t, true, serialized["hasSshPassword"])
		require.Equal(t, false, serialized["hasSharedKey"])
		require.Equal(t, true, serialized["allowAclAuthorization"])
		require.Equal(t, "S-1-2-0-1", serialized["sid"])
		require.EqualValues(t, 1000, serialized["userId"])
		// hasSSHKey is not a schema field, so it must never be reported back.
		require.NotContains(t, serialized, "hasSshKey")
		// An unset isNfsV3Enabled must stay absent rather than read back as false.
		require.NotContains(t, serialized, "isNfsV3Enabled")
	})

	t.Run("Create_requires_storageAccountName", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"resourceGroupName": "rg-1", "name": "sftpuser"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "storageAccountName is required")
	})

	t.Run("Create_falls_back_to_the_label_for_the_name", func(t *testing.T) {
		var seenUser string
		fake.createOrUpdateFn = func(_ context.Context, _, _, username string, props armstorage.LocalUser, _ *armstorage.LocalUsersClientCreateOrUpdateOptions) (armstorage.LocalUsersClientCreateOrUpdateResponse, error) {
			seenUser = username
			lastSent = props
			return armstorage.LocalUsersClientCreateOrUpdateResponse{LocalUser: echoLocalUser(props)}, nil
		}
		props, _ := json.Marshal(map[string]any{"resourceGroupName": "rg-1", "storageAccountName": "acct1"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props, Label: "labelled"})
		require.NoError(t, err)
		require.Equal(t, "labelled", seenUser)
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testStorageLocalUserNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
		require.Equal(t, ResourceTypeStorageLocalUser, got.ResourceType)
	})

	t.Run("Update_derives_names_from_the_native_id", func(t *testing.T) {
		var seenRG, seenAcct, seenUser string
		fake.createOrUpdateFn = func(_ context.Context, rg, acct, username string, props armstorage.LocalUser, _ *armstorage.LocalUsersClientCreateOrUpdateOptions) (armstorage.LocalUsersClientCreateOrUpdateResponse, error) {
			seenRG, seenAcct, seenUser, lastSent = rg, acct, username, props
			return armstorage.LocalUsersClientCreateOrUpdateResponse{LocalUser: echoLocalUser(props)}, nil
		}
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testStorageLocalUserNativeID,
			DesiredProperties: localUserDesired("uploads/archive"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, "rg-1", seenRG)
		require.Equal(t, "acct1", seenAcct)
		require.Equal(t, "sftpuser", seenUser)
		require.Equal(t, "uploads/archive", *lastSent.Properties.HomeDirectory)
	})

	t.Run("Delete", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testStorageLocalUserNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _, _ string, _ *armstorage.LocalUsersClientDeleteOptions) (armstorage.LocalUsersClientDeleteResponse, error) {
			return armstorage.LocalUsersClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testStorageLocalUserNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Status_rereads", func(t *testing.T) {
		got, err := prov.Status(context.Background(), &resource.StatusRequest{
			RequestID: "req-1",
			NativeID:  testStorageLocalUserNativeID,
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testStorageLocalUserNativeID, got.ProgressResult.NativeID)
	})

	t.Run("List_by_account", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "storageAccountName": "acct1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testStorageLocalUserNativeID}, got.NativeIDs)
	})

	t.Run("List_without_parent_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})
}

func TestStorageLocalUser_Failures(t *testing.T) {
	fake := &fakeStorageLocalUsersAPI{
		createOrUpdateFn: func(_ context.Context, _, _, _ string, _ armstorage.LocalUser, _ *armstorage.LocalUsersClientCreateOrUpdateOptions) (armstorage.LocalUsersClientCreateOrUpdateResponse, error) {
			return armstorage.LocalUsersClientCreateOrUpdateResponse{}, &azcore.ResponseError{StatusCode: 403, ErrorCode: "AuthorizationFailed"}
		},
		getFn: func(_ context.Context, _, _, _ string, _ *armstorage.LocalUsersClientGetOptions) (armstorage.LocalUsersClientGetResponse, error) {
			return armstorage.LocalUsersClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	prov := newTestStorageLocalUser(fake)

	t.Run("Create_failure_reports_the_provider_error", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: localUserDesired("home")})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.Equal(t, resource.OperationErrorCodeAccessDenied, got.ProgressResult.ErrorCode)
		require.Contains(t, got.ProgressResult.StatusMessage, "AuthorizationFailed")
	})

	t.Run("Read_maps_404", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testStorageLocalUserNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
	})
}

func TestStorageLocalUserIDParts(t *testing.T) {
	rg, acct, user, err := storageLocalUserIDParts(testStorageLocalUserNativeID)
	require.NoError(t, err)
	require.Equal(t, "rg-1", rg)
	require.Equal(t, "acct1", acct)
	require.Equal(t, "sftpuser", user)

	_, _, _, err = storageLocalUserIDParts("/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Storage/storageAccounts/acct1")
	require.Error(t, err)
}

// --- Test helpers ---

func newTestStorageLocalUser(api storageLocalUsersAPI) *StorageLocalUser {
	return &StorageLocalUser{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

type fakeStorageLocalUsersAPI struct {
	createOrUpdateFn func(ctx context.Context, rgName, accountName, username string, properties armstorage.LocalUser, opts *armstorage.LocalUsersClientCreateOrUpdateOptions) (armstorage.LocalUsersClientCreateOrUpdateResponse, error)
	getFn            func(ctx context.Context, rgName, accountName, username string, opts *armstorage.LocalUsersClientGetOptions) (armstorage.LocalUsersClientGetResponse, error)
	deleteFn         func(ctx context.Context, rgName, accountName, username string, opts *armstorage.LocalUsersClientDeleteOptions) (armstorage.LocalUsersClientDeleteResponse, error)
	newListPagerFn   func(rgName, accountName string, opts *armstorage.LocalUsersClientListOptions) *runtime.Pager[armstorage.LocalUsersClientListResponse]
}

func (f *fakeStorageLocalUsersAPI) CreateOrUpdate(ctx context.Context, rgName, accountName, username string, properties armstorage.LocalUser, opts *armstorage.LocalUsersClientCreateOrUpdateOptions) (armstorage.LocalUsersClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, accountName, username, properties, opts)
}

func (f *fakeStorageLocalUsersAPI) Get(ctx context.Context, rgName, accountName, username string, opts *armstorage.LocalUsersClientGetOptions) (armstorage.LocalUsersClientGetResponse, error) {
	return f.getFn(ctx, rgName, accountName, username, opts)
}

func (f *fakeStorageLocalUsersAPI) Delete(ctx context.Context, rgName, accountName, username string, opts *armstorage.LocalUsersClientDeleteOptions) (armstorage.LocalUsersClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, accountName, username, opts)
}

func (f *fakeStorageLocalUsersAPI) NewListPager(rgName, accountName string, opts *armstorage.LocalUsersClientListOptions) *runtime.Pager[armstorage.LocalUsersClientListResponse] {
	return f.newListPagerFn(rgName, accountName, opts)
}
