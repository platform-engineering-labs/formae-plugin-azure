// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeStorageBlobContainerImmutabilityPolicy = "AZURE::Storage::BlobContainerImmutabilityPolicy"

// blobContainerImmutabilityPolicyAPI is the immutability-policy verb subset of
// *armstorage.BlobContainersClient. There is no CRUD resource here and no list
// operation: the policy is a singleton named `default` under the container, and
// every modification carries the current ETag as If-Match.
//
// LockImmutabilityPolicy and ExtendImmutabilityPolicy are deliberately left out:
// a locked policy can never be deleted or shortened, which would strand the
// container and its resource group forever.
type blobContainerImmutabilityPolicyAPI interface {
	CreateOrUpdateImmutabilityPolicy(ctx context.Context, resourceGroupName, accountName, containerName string, options *armstorage.BlobContainersClientCreateOrUpdateImmutabilityPolicyOptions) (armstorage.BlobContainersClientCreateOrUpdateImmutabilityPolicyResponse, error)
	GetImmutabilityPolicy(ctx context.Context, resourceGroupName, accountName, containerName string, options *armstorage.BlobContainersClientGetImmutabilityPolicyOptions) (armstorage.BlobContainersClientGetImmutabilityPolicyResponse, error)
	DeleteImmutabilityPolicy(ctx context.Context, resourceGroupName, accountName, containerName, ifMatch string, options *armstorage.BlobContainersClientDeleteImmutabilityPolicyOptions) (armstorage.BlobContainersClientDeleteImmutabilityPolicyResponse, error)
}

func init() {
	registry.Register(ResourceTypeStorageBlobContainerImmutabilityPolicy, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &StorageBlobContainerImmutabilityPolicy{api: c.BlobContainersClient, config: cfg}
	})
}

// StorageBlobContainerImmutabilityPolicy provisions the time-based retention
// policy of a blob container
// (`.../containers/<container>/immutabilityPolicies/default`).
type StorageBlobContainerImmutabilityPolicy struct {
	api    blobContainerImmutabilityPolicyAPI
	config *config.Config
}

// storageBlobContainerImmutabilityPolicyProps mirrors
// schema/pkl/storage/storageblobcontainerimmutabilitypolicy.pkl.
type storageBlobContainerImmutabilityPolicyProps struct {
	ResourceGroupName             string `json:"resourceGroupName"`
	StorageAccountName            string `json:"storageAccountName"`
	ContainerName                 string `json:"containerName"`
	ImmutabilityPeriodInDays      *int32 `json:"immutabilityPeriodSinceCreationInDays"`
	AllowProtectedAppendWrites    *bool  `json:"allowProtectedAppendWrites"`
	AllowProtectedAppendWritesAll *bool  `json:"allowProtectedAppendWritesAll"`
}

func storageBlobContainerImmutabilityPolicyIDParts(resourceID string) (rgName, accountName, containerName string, err error) {
	rgName, names, err := armIDParts(resourceID, "storageaccounts", "containers")
	if err != nil {
		return "", "", "", err
	}
	return rgName, names["storageaccounts"], names["containers"], nil
}

func immutabilityPolicyFromProps(props storageBlobContainerImmutabilityPolicyProps) *armstorage.ImmutabilityPolicy {
	p := &armstorage.ImmutabilityPolicyProperty{
		// allowProtectedAppendWrites carries a schema default, so it is always sent.
		AllowProtectedAppendWrites: to.Ptr(props.AllowProtectedAppendWrites != nil && *props.AllowProtectedAppendWrites),
	}
	if props.ImmutabilityPeriodInDays != nil {
		p.ImmutabilityPeriodSinceCreationInDays = to.Ptr(*props.ImmutabilityPeriodInDays)
	}
	// The two flags are mutually exclusive when true, so the All variant is only
	// sent when the caller asked for it.
	if props.AllowProtectedAppendWritesAll != nil {
		p.AllowProtectedAppendWritesAll = to.Ptr(*props.AllowProtectedAppendWritesAll)
		if *props.AllowProtectedAppendWritesAll {
			p.AllowProtectedAppendWrites = nil
		}
	}
	return &armstorage.ImmutabilityPolicy{Properties: p}
}

func serializeStorageBlobContainerImmutabilityPolicyProperties(policy armstorage.ImmutabilityPolicy, rgName, accountName, containerName string) (json.RawMessage, error) {
	props := map[string]any{
		"resourceGroupName":          rgName,
		"storageAccountName":         accountName,
		"containerName":              containerName,
		"allowProtectedAppendWrites": false,
	}
	if policy.ID != nil {
		props["id"] = *policy.ID
	}

	if p := policy.Properties; p != nil {
		if p.ImmutabilityPeriodSinceCreationInDays != nil {
			props["immutabilityPeriodSinceCreationInDays"] = *p.ImmutabilityPeriodSinceCreationInDays
		}
		if p.AllowProtectedAppendWrites != nil {
			props["allowProtectedAppendWrites"] = *p.AllowProtectedAppendWrites
		}
		// No schema default: a false echoed for a flag the caller never set would
		// read as drift.
		if p.AllowProtectedAppendWritesAll != nil && *p.AllowProtectedAppendWritesAll {
			props["allowProtectedAppendWritesAll"] = true
		}
		if p.State != nil {
			props["state"] = string(*p.State)
		}
	}

	return json.Marshal(props)
}

// currentETag fetches the ETag ARM demands as If-Match on every modification of
// an existing policy.
func (i *StorageBlobContainerImmutabilityPolicy) currentETag(ctx context.Context, rgName, accountName, containerName string) (string, error) {
	result, err := i.api.GetImmutabilityPolicy(ctx, rgName, accountName, containerName, nil)
	if err != nil {
		return "", err
	}
	if result.Etag != nil {
		return *result.Etag, nil
	}
	if result.ETag != nil {
		return *result.ETag, nil
	}
	return "", fmt.Errorf("ARM returned no ETag for the immutability policy on container %s", containerName)
}

func (i *StorageBlobContainerImmutabilityPolicy) parseProps(payload json.RawMessage, nativeID string) (storageBlobContainerImmutabilityPolicyProps, error) {
	var props storageBlobContainerImmutabilityPolicyProps
	if err := json.Unmarshal(payload, &props); err != nil {
		return props, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if nativeID != "" {
		rgName, accountName, containerName, err := storageBlobContainerImmutabilityPolicyIDParts(nativeID)
		if err != nil {
			return props, err
		}
		props.ResourceGroupName, props.StorageAccountName, props.ContainerName = rgName, accountName, containerName
	}
	if props.ResourceGroupName == "" {
		return props, fmt.Errorf("resourceGroupName is required")
	}
	if props.StorageAccountName == "" {
		return props, fmt.Errorf("storageAccountName is required")
	}
	if props.ContainerName == "" {
		return props, fmt.Errorf("containerName is required")
	}
	if props.ImmutabilityPeriodInDays == nil {
		return props, fmt.Errorf("immutabilityPeriodSinceCreationInDays is required")
	}
	return props, nil
}

func (i *StorageBlobContainerImmutabilityPolicy) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	props, err := i.parseProps(request.Properties, "")
	if err != nil {
		return nil, err
	}

	// A create needs no If-Match: there is nothing to conflict with.
	result, err := i.api.CreateOrUpdateImmutabilityPolicy(ctx, props.ResourceGroupName, props.StorageAccountName, props.ContainerName,
		&armstorage.BlobContainersClientCreateOrUpdateImmutabilityPolicyOptions{Parameters: immutabilityPolicyFromProps(props)})
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
				StatusMessage:   err.Error(),
			},
		}, nil
	}

	propsJSON, err := serializeStorageBlobContainerImmutabilityPolicyProperties(result.ImmutabilityPolicy, props.ResourceGroupName, props.StorageAccountName, props.ContainerName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize ImmutabilityPolicy properties: %w", err)
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

func (i *StorageBlobContainerImmutabilityPolicy) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, accountName, containerName, err := storageBlobContainerImmutabilityPolicyIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := i.api.GetImmutabilityPolicy(ctx, rgName, accountName, containerName, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := serializeStorageBlobContainerImmutabilityPolicyProperties(result.ImmutabilityPolicy, rgName, accountName, containerName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize ImmutabilityPolicy properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeStorageBlobContainerImmutabilityPolicy,
		Properties:   string(propsJSON),
	}, nil
}

// Update re-issues createOrUpdate with the current ETag as If-Match. ARM rejects
// a modification without it, so the ETag is read immediately beforehand rather
// than carried in the resource.
func (i *StorageBlobContainerImmutabilityPolicy) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	props, err := i.parseProps(request.DesiredProperties, request.NativeID)
	if err != nil {
		return nil, err
	}

	etag, err := i.currentETag(ctx, props.ResourceGroupName, props.StorageAccountName, props.ContainerName)
	if err != nil {
		return &resource.UpdateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationUpdate,
				OperationStatus: resource.OperationStatusFailure,
				NativeID:        request.NativeID,
				ErrorCode:       operationErrorCode(err),
				StatusMessage:   fmt.Sprintf("failed to read the ETag needed to modify the immutability policy: %v", err),
			},
		}, nil
	}

	result, err := i.api.CreateOrUpdateImmutabilityPolicy(ctx, props.ResourceGroupName, props.StorageAccountName, props.ContainerName,
		&armstorage.BlobContainersClientCreateOrUpdateImmutabilityPolicyOptions{
			IfMatch:    to.Ptr(etag),
			Parameters: immutabilityPolicyFromProps(props),
		})
	if err != nil {
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

	propsJSON, err := serializeStorageBlobContainerImmutabilityPolicyProperties(result.ImmutabilityPolicy, props.ResourceGroupName, props.StorageAccountName, props.ContainerName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize ImmutabilityPolicy properties after update: %w", err)
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

// Delete needs the ETag too. A LOCKED policy cannot be deleted at all — ARM
// answers 409 — and there is nothing this provisioner can do about it, so the
// provider error is reported verbatim rather than swallowed.
func (i *StorageBlobContainerImmutabilityPolicy) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, accountName, containerName, err := storageBlobContainerImmutabilityPolicyIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	etag, err := i.currentETag(ctx, rgName, accountName, containerName)
	if err != nil {
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
				StatusMessage:   fmt.Sprintf("failed to read the ETag needed to delete the immutability policy: %v", err),
			},
		}, nil
	}

	if _, err := i.api.DeleteImmutabilityPolicy(ctx, rgName, accountName, containerName, etag, nil); err != nil {
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

// Immutability-policy writes are synchronous, so Status just re-reads.
func (i *StorageBlobContainerImmutabilityPolicy) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	rgName, accountName, containerName, err := storageBlobContainerImmutabilityPolicyIDParts(request.NativeID)
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

	result, err := i.api.GetImmutabilityPolicy(ctx, rgName, accountName, containerName, nil)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       operationErrorCode(err),
				StatusMessage:   err.Error(),
			},
		}, fmt.Errorf("failed to get ImmutabilityPolicy status: %w", err)
	}

	propsJSON, err := serializeStorageBlobContainerImmutabilityPolicyProperties(result.ImmutabilityPolicy, rgName, accountName, containerName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize ImmutabilityPolicy properties: %w", err)
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

// List probes the container's one policy. ARM has no list verb here, and a
// container without a policy must list as empty rather than error, or discovery
// of every container without retention fails.
func (i *StorageBlobContainerImmutabilityPolicy) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	accountName := request.AdditionalProperties["storageAccountName"]
	containerName := request.AdditionalProperties["containerName"]
	if rgName == "" || accountName == "" || containerName == "" {
		return &resource.ListResult{}, nil
	}

	result, err := i.api.GetImmutabilityPolicy(ctx, rgName, accountName, containerName, nil)
	if err != nil {
		if operationErrorCode(err) == resource.OperationErrorCodeNotFound {
			return &resource.ListResult{}, nil
		}
		return nil, fmt.Errorf("failed to list ImmutabilityPolicies on container %s: %w", containerName, err)
	}
	// ARM answers 200 with an empty body for a container that never had a policy.
	if result.ID == nil || result.Properties == nil || result.Properties.ImmutabilityPeriodSinceCreationInDays == nil {
		return &resource.ListResult{}, nil
	}
	return &resource.ListResult{NativeIDs: []string{*result.ID}}, nil
}
