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

const ResourceTypeFileShare = "AZURE::Storage::FileShare"

// deleteIncludeSnapshots deletes the share together with its snapshots. It is also
// the service-side default, but it is passed explicitly so a change of that default
// cannot turn Delete into a failure on shares that have snapshots.
const deleteIncludeSnapshots = "snapshots"

// fileSharesAPI is the subset of *armstorage.FileSharesClient used here. File share
// operations are synchronous (no LRO/poller).
type fileSharesAPI interface {
	Create(ctx context.Context, resourceGroupName, accountName, shareName string, fileShare armstorage.FileShare, options *armstorage.FileSharesClientCreateOptions) (armstorage.FileSharesClientCreateResponse, error)
	Get(ctx context.Context, resourceGroupName, accountName, shareName string, options *armstorage.FileSharesClientGetOptions) (armstorage.FileSharesClientGetResponse, error)
	Update(ctx context.Context, resourceGroupName, accountName, shareName string, fileShare armstorage.FileShare, options *armstorage.FileSharesClientUpdateOptions) (armstorage.FileSharesClientUpdateResponse, error)
	Delete(ctx context.Context, resourceGroupName, accountName, shareName string, options *armstorage.FileSharesClientDeleteOptions) (armstorage.FileSharesClientDeleteResponse, error)
	NewListPager(resourceGroupName, accountName string, options *armstorage.FileSharesClientListOptions) *runtime.Pager[armstorage.FileSharesClientListResponse]
}

func init() {
	registry.Register(ResourceTypeFileShare, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &FileShare{api: c.FileSharesClient, config: cfg}
	})
}

// FileShare is the provisioner for Azure file shares
// (`Microsoft.Storage/storageAccounts/<acct>/fileServices/default/shares/<name>`).
// It is a child of AZURE::Storage::StorageAccount. All operations are synchronous.
//
// ponytail: stored access policies (signedIdentifiers) and the Files Provisioned v2
// knobs (provisionedIops / provisionedBandwidthMibps / paid bursting) are not
// modelled — v2 needs a FileStorage account type to exercise, so they are deferred
// rather than shipped unverified.
type FileShare struct {
	api    fileSharesAPI
	config *config.Config
}

func fileShareIDParts(resourceID string) (rgName, accountName, shareName string, err error) {
	rgName, names, err := armIDParts(resourceID, "storageaccounts", "shares")
	if err != nil {
		return "", "", "", err
	}
	return rgName, names["storageaccounts"], names["shares"], nil
}

func serializeFileShareProperties(result armstorage.FileShare, rgName, accountName, shareName string) (json.RawMessage, error) {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	props["storageAccountName"] = accountName
	if result.Name != nil {
		props["name"] = *result.Name
	} else {
		props["name"] = shareName
	}
	if result.ID != nil {
		props["id"] = *result.ID
	}

	if p := result.FileShareProperties; p != nil {
		if p.ShareQuota != nil {
			props["shareQuota"] = int(*p.ShareQuota)
		}
		if p.AccessTier != nil {
			props["accessTier"] = string(*p.AccessTier)
		}
		if p.EnabledProtocols != nil {
			props["enabledProtocols"] = string(*p.EnabledProtocols)
		}
		if p.RootSquash != nil {
			props["rootSquash"] = string(*p.RootSquash)
		}
		if len(p.Metadata) > 0 {
			props["metadata"] = azureTagsToFormaeTags(p.Metadata)
		}
	}

	return json.Marshal(props)
}

func fileShareParamsFromProperties(props map[string]any) armstorage.FileShare {
	share := armstorage.FileShare{FileShareProperties: &armstorage.FileShareProperties{}}

	if v, ok := props["shareQuota"].(float64); ok {
		share.FileShareProperties.ShareQuota = to.Ptr(int32(v))
	}
	if v, ok := props["accessTier"].(string); ok && v != "" {
		share.FileShareProperties.AccessTier = to.Ptr(armstorage.ShareAccessTier(v))
	}
	if v, ok := props["enabledProtocols"].(string); ok && v != "" {
		share.FileShareProperties.EnabledProtocols = to.Ptr(armstorage.EnabledProtocols(v))
	}
	if v, ok := props["rootSquash"].(string); ok && v != "" {
		share.FileShareProperties.RootSquash = to.Ptr(armstorage.RootSquashType(v))
	}
	if md := metadataFromProperties(props); md != nil {
		share.FileShareProperties.Metadata = md
	}

	return share
}

func (s *FileShare) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props map[string]any
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	rgName, _ := props["resourceGroupName"].(string)
	if rgName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	accountName, _ := props["storageAccountName"].(string)
	if accountName == "" {
		return nil, fmt.Errorf("storageAccountName is required")
	}
	shareName, _ := props["name"].(string)
	if shareName == "" {
		shareName = request.Label
	}
	if shareName == "" {
		return nil, fmt.Errorf("name is required")
	}

	result, err := s.api.Create(ctx, rgName, accountName, shareName, fileShareParamsFromProperties(props), nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	propsJSON, err := serializeFileShareProperties(result.FileShare, rgName, accountName, shareName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize FileShare properties: %w", err)
	}

	nativeID := ""
	if result.ID != nil {
		nativeID = *result.ID
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

func (s *FileShare) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, accountName, shareName, err := fileShareIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := s.api.Get(ctx, rgName, accountName, shareName, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := serializeFileShareProperties(result.FileShare, rgName, accountName, shareName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize FileShare properties: %w", err)
	}

	return &resource.ReadResult{
		ResourceType: ResourceTypeFileShare,
		Properties:   string(propsJSON),
	}, nil
}

func (s *FileShare) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, accountName, shareName, err := fileShareIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props map[string]any
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse desired properties: %w", err)
	}

	params := fileShareParamsFromProperties(props)
	// enabledProtocols can only be set at create time; ARM rejects it in a PATCH.
	params.FileShareProperties.EnabledProtocols = nil

	result, err := s.api.Update(ctx, rgName, accountName, shareName, params, nil)
	if err != nil {
		return &resource.UpdateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationUpdate,
				OperationStatus: resource.OperationStatusFailure,
				NativeID:        request.NativeID,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	propsJSON, err := serializeFileShareProperties(result.FileShare, rgName, accountName, shareName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize FileShare properties: %w", err)
	}

	nativeID := request.NativeID
	if result.ID != nil {
		nativeID = *result.ID
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

func (s *FileShare) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, accountName, shareName, err := fileShareIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	// Synchronous delete. NotFound means the goal is already achieved.
	opts := &armstorage.FileSharesClientDeleteOptions{Include: to.Ptr(deleteIncludeSnapshots)}
	if _, err := s.api.Delete(ctx, rgName, accountName, shareName, opts); err != nil {
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

// Status is a no-op success passthrough: file share operations are synchronous, so
// Create/Update/Delete never return InProgress. It exists only to satisfy the
// Provisioner interface.
func (s *FileShare) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

func (s *FileShare) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	accountName := request.AdditionalProperties["storageAccountName"]

	var nativeIDs []string
	pager := s.api.NewListPager(rgName, accountName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list file shares in storage account %s: %w", accountName, err)
		}
		for _, share := range page.Value {
			if share.ID != nil {
				nativeIDs = append(nativeIDs, *share.ID)
			}
		}
	}

	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
