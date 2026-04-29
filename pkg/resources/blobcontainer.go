// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeBlobContainer = "Azure::Storage::BlobContainer"

type blobContainersAPI interface {
	Create(ctx context.Context, resourceGroupName, accountName, containerName string, blobContainer armstorage.BlobContainer, options *armstorage.BlobContainersClientCreateOptions) (armstorage.BlobContainersClientCreateResponse, error)
	Get(ctx context.Context, resourceGroupName, accountName, containerName string, options *armstorage.BlobContainersClientGetOptions) (armstorage.BlobContainersClientGetResponse, error)
	Update(ctx context.Context, resourceGroupName, accountName, containerName string, blobContainer armstorage.BlobContainer, options *armstorage.BlobContainersClientUpdateOptions) (armstorage.BlobContainersClientUpdateResponse, error)
	Delete(ctx context.Context, resourceGroupName, accountName, containerName string, options *armstorage.BlobContainersClientDeleteOptions) (armstorage.BlobContainersClientDeleteResponse, error)
	NewListPager(resourceGroupName, accountName string, options *armstorage.BlobContainersClientListOptions) *runtime.Pager[armstorage.BlobContainersClientListResponse]
}

func init() {
	registry.Register(ResourceTypeBlobContainer, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &BlobContainer{api: c.BlobContainersClient, config: cfg}
	})
}

// BlobContainer is the provisioner for blob containers under a storage account
// (`Microsoft.Storage/storageAccounts/blobServices/default/containers/<name>`).
type BlobContainer struct {
	api    blobContainersAPI
	config *config.Config
}

func serializeBlobContainerProperties(result armstorage.BlobContainer, rgName, accountName, containerName string) (json.RawMessage, error) {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	props["storageAccountName"] = accountName
	if result.Name != nil {
		props["name"] = *result.Name
	} else {
		props["name"] = containerName
	}

	if result.ContainerProperties != nil {
		if result.ContainerProperties.PublicAccess != nil {
			props["publicAccess"] = string(*result.ContainerProperties.PublicAccess)
		} else {
			props["publicAccess"] = string(armstorage.PublicAccessNone)
		}
		if result.ContainerProperties.DefaultEncryptionScope != nil {
			props["defaultEncryptionScope"] = *result.ContainerProperties.DefaultEncryptionScope
		}
		if result.ContainerProperties.DenyEncryptionScopeOverride != nil {
			props["denyEncryptionScopeOverride"] = *result.ContainerProperties.DenyEncryptionScopeOverride
		}
		if len(result.ContainerProperties.Metadata) > 0 {
			tags := make([]map[string]string, 0, len(result.ContainerProperties.Metadata))
			for k, v := range result.ContainerProperties.Metadata {
				val := ""
				if v != nil {
					val = *v
				}
				tags = append(tags, map[string]string{"Key": k, "Value": val})
			}
			props["metadata"] = tags
		}
	} else {
		props["publicAccess"] = string(armstorage.PublicAccessNone)
	}

	if result.ID != nil {
		props["id"] = *result.ID
	}

	return json.Marshal(props)
}

func blobContainerParamsFromProperties(props map[string]any) armstorage.BlobContainer {
	cp := &armstorage.ContainerProperties{}

	if v, ok := props["publicAccess"].(string); ok && v != "" {
		pa := armstorage.PublicAccess(v)
		cp.PublicAccess = &pa
	}
	// Encryption-scope fields are coupled: ARM rejects sending denyEncryptionScopeOverride
	// without also sending defaultEncryptionScope ("Container encryption policy missing header").
	if v, ok := props["defaultEncryptionScope"].(string); ok && v != "" {
		cp.DefaultEncryptionScope = &v
		if d, ok := props["denyEncryptionScopeOverride"].(bool); ok {
			cp.DenyEncryptionScopeOverride = &d
		}
	}
	if rawMD, ok := props["metadata"].([]any); ok && len(rawMD) > 0 {
		md := make(map[string]*string, len(rawMD))
		for _, raw := range rawMD {
			entry, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			k, _ := entry["Key"].(string)
			v, _ := entry["Value"].(string)
			if k == "" {
				continue
			}
			val := v
			md[k] = &val
		}
		cp.Metadata = md
	}

	return armstorage.BlobContainer{ContainerProperties: cp}
}

func (b *BlobContainer) parseNativeID(nativeID string) (rgName, accountName, containerName string, err error) {
	parts := splitResourceID(nativeID)
	rgName = parts["resourcegroups"]
	accountName = parts["storageaccounts"]
	containerName = parts["containers"]
	if rgName == "" || accountName == "" || containerName == "" {
		return "", "", "", fmt.Errorf("invalid NativeID: %s", nativeID)
	}
	return rgName, accountName, containerName, nil
}

func (b *BlobContainer) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
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
	containerName, _ := props["name"].(string)
	if containerName == "" {
		containerName = request.Label
	}
	if containerName == "" {
		return nil, fmt.Errorf("name is required")
	}

	params := blobContainerParamsFromProperties(props)

	result, err := b.api.Create(ctx, rgName, accountName, containerName, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       mapAzureErrorToOperationErrorCode(err),
			},
		}, nil
	}

	propsJSON, err := serializeBlobContainerProperties(result.BlobContainer, rgName, accountName, containerName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize BlobContainer properties: %w", err)
	}

	return &resource.CreateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:          resource.OperationCreate,
			OperationStatus:    resource.OperationStatusSuccess,
			NativeID:           *result.ID,
			ResourceProperties: propsJSON,
		},
	}, nil
}

func (b *BlobContainer) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, accountName, containerName, err := b.parseNativeID(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := b.api.Get(ctx, rgName, accountName, containerName, nil)
	if err != nil {
		return &resource.ReadResult{
			ErrorCode: mapAzureErrorToOperationErrorCode(err),
		}, nil
	}

	propsJSON, err := serializeBlobContainerProperties(result.BlobContainer, rgName, accountName, containerName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize BlobContainer properties: %w", err)
	}

	return &resource.ReadResult{
		ResourceType: ResourceTypeBlobContainer,
		Properties:   string(propsJSON),
	}, nil
}

func (b *BlobContainer) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, accountName, containerName, err := b.parseNativeID(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props map[string]any
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse desired properties: %w", err)
	}

	params := blobContainerParamsFromProperties(props)

	result, err := b.api.Update(ctx, rgName, accountName, containerName, params, nil)
	if err != nil {
		return &resource.UpdateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationUpdate,
				OperationStatus: resource.OperationStatusFailure,
				NativeID:        request.NativeID,
				ErrorCode:       mapAzureErrorToOperationErrorCode(err),
			},
		}, nil
	}

	propsJSON, err := serializeBlobContainerProperties(result.BlobContainer, rgName, accountName, containerName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize BlobContainer properties after update: %w", err)
	}

	return &resource.UpdateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:          resource.OperationUpdate,
			OperationStatus:    resource.OperationStatusSuccess,
			NativeID:           *result.ID,
			ResourceProperties: propsJSON,
		},
	}, nil
}

func (b *BlobContainer) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, accountName, containerName, err := b.parseNativeID(request.NativeID)
	if err != nil {
		return nil, err
	}

	if _, err := b.api.Delete(ctx, rgName, accountName, containerName, nil); err != nil {
		if mapAzureErrorToOperationErrorCode(err) == resource.OperationErrorCodeNotFound {
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
				ErrorCode:       mapAzureErrorToOperationErrorCode(err),
			},
		}, fmt.Errorf("failed to delete BlobContainer: %w", err)
	}

	return &resource.DeleteResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationDelete,
			OperationStatus: resource.OperationStatusSuccess,
			NativeID:        request.NativeID,
		},
	}, nil
}

func (b *BlobContainer) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	rgName, accountName, containerName, err := b.parseNativeID(request.NativeID)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
			},
		}, err
	}

	result, err := b.api.Get(ctx, rgName, accountName, containerName, nil)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       mapAzureErrorToOperationErrorCode(err),
			},
		}, fmt.Errorf("failed to get BlobContainer status: %w", err)
	}

	propsJSON, err := serializeBlobContainerProperties(result.BlobContainer, rgName, accountName, containerName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize BlobContainer properties: %w", err)
	}

	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus:    resource.OperationStatusSuccess,
			RequestID:          request.RequestID,
			NativeID:           *result.ID,
			ResourceProperties: propsJSON,
		},
	}, nil
}

func (b *BlobContainer) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	accountName := request.AdditionalProperties["storageAccountName"]
	if rgName == "" || accountName == "" {
		return &resource.ListResult{}, nil
	}

	var nativeIDs []string
	pager := b.api.NewListPager(rgName, accountName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list BlobContainers: %w", err)
		}
		for _, item := range page.Value {
			if item.ID != nil {
				nativeIDs = append(nativeIDs, *item.ID)
			}
		}
	}

	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
