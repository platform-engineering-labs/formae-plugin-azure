// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeStorageLocalUser = "AZURE::Storage::LocalUser"

// storageLocalUsersAPI is the subset of *armstorage.LocalUsersClient used here.
// Every operation is synchronous — there is no BeginX verb on this client.
//
// ListKeys and RegeneratePassword are deliberately absent: the shared key and the
// SSH password they return are write-once secrets that Get never echoes, so this
// resource never carries them and never needs to fetch them.
type storageLocalUsersAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName, accountName, username string, properties armstorage.LocalUser, options *armstorage.LocalUsersClientCreateOrUpdateOptions) (armstorage.LocalUsersClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName, accountName, username string, options *armstorage.LocalUsersClientGetOptions) (armstorage.LocalUsersClientGetResponse, error)
	Delete(ctx context.Context, resourceGroupName, accountName, username string, options *armstorage.LocalUsersClientDeleteOptions) (armstorage.LocalUsersClientDeleteResponse, error)
	NewListPager(resourceGroupName, accountName string, options *armstorage.LocalUsersClientListOptions) *runtime.Pager[armstorage.LocalUsersClientListResponse]
}

func init() {
	registry.Register(ResourceTypeStorageLocalUser, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &StorageLocalUser{api: c.StorageLocalUsersClient, config: cfg}
	})
}

// StorageLocalUser provisions a local user of a storage account
// (`Microsoft.Storage/storageAccounts/<account>/localUsers/<username>`). The
// parent account must have a hierarchical namespace, and SFTP enabled for SFTP
// users.
type StorageLocalUser struct {
	api    storageLocalUsersAPI
	config *config.Config
}

// storageLocalUserProps mirrors schema/pkl/storage/storagelocaluser.pkl.
type storageLocalUserProps struct {
	Name               string                            `json:"name"`
	ResourceGroupName  string                            `json:"resourceGroupName"`
	StorageAccountName string                            `json:"storageAccountName"`
	PermissionScopes   []storageLocalUserPermissionScope `json:"permissionScopes"`
	SSHAuthorizedKeys  []storageLocalUserSSHKey          `json:"sshAuthorizedKeys"`
	HomeDirectory      string                            `json:"homeDirectory"`
	HasSharedKey       *bool                             `json:"hasSharedKey"`
	HasSSHPassword     *bool                             `json:"hasSshPassword"`
	AllowACLAuth       *bool                             `json:"allowAclAuthorization"`
	IsNfsV3Enabled     *bool                             `json:"isNfsV3Enabled"`
	GroupID            *int32                            `json:"groupId"`
	ExtendedGroups     []int32                           `json:"extendedGroups"`
}

type storageLocalUserPermissionScope struct {
	Permissions  string `json:"permissions"`
	ResourceName string `json:"resourceName"`
	Service      string `json:"service"`
}

type storageLocalUserSSHKey struct {
	Key         string `json:"key"`
	Description string `json:"description,omitempty"`
}

func storageLocalUserIDParts(resourceID string) (rgName, accountName, username string, err error) {
	rgName, names, err := armIDParts(resourceID, "storageaccounts", "localusers")
	if err != nil {
		return "", "", "", err
	}
	return rgName, names["storageaccounts"], names["localusers"], nil
}

// localUserFromProps builds the ARM body.
//
// hasSSHKey is not a schema field: ARM treats it as "an SSH key exists", which is
// entirely determined by sshAuthorizedKeys, so sending it derived keeps the two
// from ever disagreeing.
func localUserFromProps(props storageLocalUserProps) armstorage.LocalUser {
	p := &armstorage.LocalUserProperties{
		HasSharedKey:          to.Ptr(props.HasSharedKey != nil && *props.HasSharedKey),
		HasSSHPassword:        to.Ptr(props.HasSSHPassword != nil && *props.HasSSHPassword),
		HasSSHKey:             to.Ptr(len(props.SSHAuthorizedKeys) > 0),
		AllowACLAuthorization: to.Ptr(props.AllowACLAuth == nil || *props.AllowACLAuth),
	}
	if props.HomeDirectory != "" {
		p.HomeDirectory = to.Ptr(props.HomeDirectory)
	}
	if props.IsNfsV3Enabled != nil {
		p.IsNFSv3Enabled = to.Ptr(*props.IsNfsV3Enabled)
	}
	if props.GroupID != nil {
		p.GroupID = to.Ptr(*props.GroupID)
	}
	for _, g := range props.ExtendedGroups {
		p.ExtendedGroups = append(p.ExtendedGroups, to.Ptr(g))
	}
	for _, scope := range props.PermissionScopes {
		p.PermissionScopes = append(p.PermissionScopes, &armstorage.PermissionScope{
			Permissions:  to.Ptr(scope.Permissions),
			ResourceName: to.Ptr(scope.ResourceName),
			Service:      to.Ptr(scope.Service),
		})
	}
	for _, key := range props.SSHAuthorizedKeys {
		k := &armstorage.SSHPublicKey{Key: to.Ptr(key.Key)}
		if key.Description != "" {
			k.Description = to.Ptr(key.Description)
		}
		p.SSHAuthorizedKeys = append(p.SSHAuthorizedKeys, k)
	}
	return armstorage.LocalUser{Properties: p}
}

func serializeStorageLocalUserProperties(result armstorage.LocalUser, rgName, accountName, username string) (json.RawMessage, error) {
	props := map[string]any{
		"resourceGroupName":  rgName,
		"storageAccountName": accountName,
		"name":               username,
	}
	if result.Name != nil && *result.Name != "" {
		props["name"] = *result.Name
	}
	if result.ID != nil {
		props["id"] = *result.ID
	}

	// The three booleans below carry a schema default, so they are always part of
	// the desired document and must always be part of the read-back one. ARM omits
	// them when they are false, which would otherwise read as drift.
	props["hasSharedKey"] = false
	props["hasSshPassword"] = false
	props["allowAclAuthorization"] = true

	p := result.Properties
	if p == nil {
		return json.Marshal(props)
	}

	if p.HasSharedKey != nil {
		props["hasSharedKey"] = *p.HasSharedKey
	}
	if p.HasSSHPassword != nil {
		props["hasSshPassword"] = *p.HasSSHPassword
	}
	if p.AllowACLAuthorization != nil {
		props["allowAclAuthorization"] = *p.AllowACLAuthorization
	}
	// isNfsV3Enabled has no schema default: ARM omits it on non-NFSv3 users, so
	// surfacing a false would be a property the caller never declared.
	if p.IsNFSv3Enabled != nil && *p.IsNFSv3Enabled {
		props["isNfsV3Enabled"] = true
	}
	if p.HomeDirectory != nil && *p.HomeDirectory != "" {
		props["homeDirectory"] = *p.HomeDirectory
	}
	if p.GroupID != nil {
		props["groupId"] = *p.GroupID
	}
	if len(p.ExtendedGroups) > 0 {
		groups := make([]int32, 0, len(p.ExtendedGroups))
		for _, g := range p.ExtendedGroups {
			if g != nil {
				groups = append(groups, *g)
			}
		}
		if len(groups) > 0 {
			props["extendedGroups"] = groups
		}
	}
	if len(p.PermissionScopes) > 0 {
		scopes := make([]map[string]any, 0, len(p.PermissionScopes))
		for _, s := range p.PermissionScopes {
			if s == nil {
				continue
			}
			scope := map[string]any{}
			if s.Permissions != nil {
				scope["permissions"] = *s.Permissions
			}
			if s.ResourceName != nil {
				scope["resourceName"] = *s.ResourceName
			}
			if s.Service != nil {
				scope["service"] = *s.Service
			}
			scopes = append(scopes, scope)
		}
		if len(scopes) > 0 {
			props["permissionScopes"] = scopes
		}
	}
	if len(p.SSHAuthorizedKeys) > 0 {
		keys := make([]map[string]any, 0, len(p.SSHAuthorizedKeys))
		for _, k := range p.SSHAuthorizedKeys {
			if k == nil || k.Key == nil {
				continue
			}
			entry := map[string]any{"key": *k.Key}
			if k.Description != nil && *k.Description != "" {
				entry["description"] = *k.Description
			}
			keys = append(keys, entry)
		}
		if len(keys) > 0 {
			props["sshAuthorizedKeys"] = keys
		}
	}
	// Server-assigned identifiers, exposed as outputs only.
	if p.Sid != nil {
		props["sid"] = *p.Sid
	}
	if p.UserID != nil {
		props["userId"] = *p.UserID
	}

	return json.Marshal(props)
}

// upsert parses the payload and issues the single CreateOrUpdate that backs both
// Create and Update. username is empty only when the payload itself is unusable.
func (u *StorageLocalUser) upsert(ctx context.Context, payload json.RawMessage, label, nativeID string) (armstorage.LocalUser, string, string, string, error) {
	var props storageLocalUserProps
	if err := json.Unmarshal(payload, &props); err != nil {
		return armstorage.LocalUser{}, "", "", "", fmt.Errorf("failed to parse resource properties: %w", err)
	}

	rgName, accountName, username := props.ResourceGroupName, props.StorageAccountName, props.Name
	if nativeID != "" {
		var err error
		rgName, accountName, username, err = storageLocalUserIDParts(nativeID)
		if err != nil {
			return armstorage.LocalUser{}, "", "", "", err
		}
	}
	if rgName == "" {
		return armstorage.LocalUser{}, "", "", "", fmt.Errorf("resourceGroupName is required")
	}
	if accountName == "" {
		return armstorage.LocalUser{}, "", "", "", fmt.Errorf("storageAccountName is required")
	}
	if username == "" {
		username = label
	}
	if username == "" {
		return armstorage.LocalUser{}, "", "", "", fmt.Errorf("name is required")
	}

	result, err := u.api.CreateOrUpdate(ctx, rgName, accountName, username, localUserFromProps(props), nil)
	if err != nil {
		return armstorage.LocalUser{}, rgName, accountName, username, err
	}
	return result.LocalUser, rgName, accountName, username, nil
}

func (u *StorageLocalUser) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	user, rgName, accountName, username, err := u.upsert(ctx, request.Properties, request.Label, "")
	if err != nil {
		if username == "" {
			return nil, err
		}
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
				StatusMessage:   err.Error(),
			},
		}, nil
	}

	propsJSON, err := serializeStorageLocalUserProperties(user, rgName, accountName, username)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize LocalUser properties: %w", err)
	}

	nativeID := ""
	if user.ID != nil {
		nativeID = *user.ID
	}
	return &resource.CreateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:          resource.OperationCreate,
			OperationStatus:    resource.OperationStatusSuccess,
			NativeID:           nativeID,
			ResourceProperties: propsJSON,
		},
	}, nil
}

func (u *StorageLocalUser) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, accountName, username, err := storageLocalUserIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := u.api.Get(ctx, rgName, accountName, username, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := serializeStorageLocalUserProperties(result.LocalUser, rgName, accountName, username)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize LocalUser properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeStorageLocalUser,
		Properties:   string(propsJSON),
	}, nil
}

func (u *StorageLocalUser) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	user, rgName, accountName, username, err := u.upsert(ctx, request.DesiredProperties, request.Label, request.NativeID)
	if err != nil {
		if username == "" {
			return nil, err
		}
		return &resource.UpdateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationUpdate,
				OperationStatus: resource.OperationStatusFailure,
				NativeID:        request.NativeID,
				ErrorCode:       operationErrorCode(err),
				StatusMessage:   err.Error(),
			},
		}, nil
	}

	propsJSON, err := serializeStorageLocalUserProperties(user, rgName, accountName, username)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize LocalUser properties after update: %w", err)
	}

	nativeID := request.NativeID
	if user.ID != nil {
		nativeID = *user.ID
	}
	return &resource.UpdateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:          resource.OperationUpdate,
			OperationStatus:    resource.OperationStatusSuccess,
			NativeID:           nativeID,
			ResourceProperties: propsJSON,
		},
	}, nil
}

func (u *StorageLocalUser) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, accountName, username, err := storageLocalUserIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	// Synchronous delete; a missing user means the goal is already met.
	if _, err := u.api.Delete(ctx, rgName, accountName, username, nil); err != nil {
		if isDeleteSuccessError(err) {
			return &resource.DeleteResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationDelete,
					OperationStatus: resource.OperationStatusSuccess,
					NativeID:        request.NativeID,
				},
			}, nil
		}
		return &resource.DeleteResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationDelete,
				OperationStatus: resource.OperationStatusFailure,
				NativeID:        request.NativeID,
				ErrorCode:       operationErrorCode(err),
				StatusMessage:   err.Error(),
			},
		}, nil
	}

	return &resource.DeleteResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationDelete,
			OperationStatus: resource.OperationStatusSuccess,
			NativeID:        request.NativeID,
		},
	}, nil
}

// Status re-reads the user: local-user writes are synchronous, so a Status call
// only ever confirms what Create/Update already reported.
func (u *StorageLocalUser) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	rgName, accountName, username, err := storageLocalUserIDParts(request.NativeID)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
				StatusMessage:   err.Error(),
			},
		}, err
	}

	result, err := u.api.Get(ctx, rgName, accountName, username, nil)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       operationErrorCode(err),
				StatusMessage:   err.Error(),
			},
		}, fmt.Errorf("failed to get LocalUser status: %w", err)
	}

	propsJSON, err := serializeStorageLocalUserProperties(result.LocalUser, rgName, accountName, username)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize LocalUser properties: %w", err)
	}
	nativeID := request.NativeID
	if result.ID != nil {
		nativeID = *result.ID
	}
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus:    resource.OperationStatusSuccess,
			RequestID:          request.RequestID,
			NativeID:           nativeID,
			ResourceProperties: propsJSON,
		},
	}, nil
}

func (u *StorageLocalUser) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	accountName := request.AdditionalProperties["storageAccountName"]
	if rgName == "" || accountName == "" {
		return &resource.ListResult{}, nil
	}

	var nativeIDs []string
	pager := u.api.NewListPager(rgName, accountName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list LocalUsers in storage account %s: %w", accountName, err)
		}
		for _, item := range page.Value {
			if item != nil && item.ID != nil {
				nativeIDs = append(nativeIDs, *item.ID)
			}
		}
	}

	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
