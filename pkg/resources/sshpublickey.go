// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v5"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeSSHPublicKey = "AZURE::Compute::SshPublicKey"

// sshPublicKeysAPI is the subset of *armcompute.SSHPublicKeysClient used here.
// All operations are synchronous (no LRO/poller). Note the create verb is
// `Create`, not `CreateOrUpdate` — it fails on an existing name rather than
// upserting, so Update goes through the separate PATCH.
type sshPublicKeysAPI interface {
	Create(ctx context.Context, resourceGroupName string, sshPublicKeyName string, parameters armcompute.SSHPublicKeyResource, options *armcompute.SSHPublicKeysClientCreateOptions) (armcompute.SSHPublicKeysClientCreateResponse, error)
	Get(ctx context.Context, resourceGroupName string, sshPublicKeyName string, options *armcompute.SSHPublicKeysClientGetOptions) (armcompute.SSHPublicKeysClientGetResponse, error)
	Update(ctx context.Context, resourceGroupName string, sshPublicKeyName string, parameters armcompute.SSHPublicKeyUpdateResource, options *armcompute.SSHPublicKeysClientUpdateOptions) (armcompute.SSHPublicKeysClientUpdateResponse, error)
	Delete(ctx context.Context, resourceGroupName string, sshPublicKeyName string, options *armcompute.SSHPublicKeysClientDeleteOptions) (armcompute.SSHPublicKeysClientDeleteResponse, error)
	NewListByResourceGroupPager(resourceGroupName string, options *armcompute.SSHPublicKeysClientListByResourceGroupOptions) *runtime.Pager[armcompute.SSHPublicKeysClientListByResourceGroupResponse]
	NewListBySubscriptionPager(options *armcompute.SSHPublicKeysClientListBySubscriptionOptions) *runtime.Pager[armcompute.SSHPublicKeysClientListBySubscriptionResponse]
}

func init() {
	registry.Register(ResourceTypeSSHPublicKey, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &SSHPublicKey{api: c.SSHPublicKeysClient, config: cfg}
	})
}

// SSHPublicKey is the provisioner for Azure SSH public keys
// (`Microsoft.Compute/sshPublicKeys/<name>`). All operations are synchronous.
type SSHPublicKey struct {
	api    sshPublicKeysAPI
	config *config.Config
}

func serializeSSHPublicKeyProperties(result armcompute.SSHPublicKeyResource, rgName, name string) (json.RawMessage, error) {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	if result.Name != nil {
		props["name"] = *result.Name
	} else {
		props["name"] = name
	}
	if result.Location != nil {
		props["location"] = *result.Location
	}
	if result.ID != nil {
		props["id"] = *result.ID
	}
	if result.Properties != nil && result.Properties.PublicKey != nil {
		props["publicKey"] = *result.Properties.PublicKey
	}
	if tags := azureTagsToFormaeTags(result.Tags); tags != nil {
		props["Tags"] = tags
	}

	return json.Marshal(props)
}

func sshPublicKeyIDParts(resourceID string) (rgName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "sshpublickeys")
	if err != nil {
		return "", "", err
	}
	return rgName, names["sshpublickeys"], nil
}

func (s *SSHPublicKey) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props map[string]any
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	rgName, _ := props["resourceGroupName"].(string)
	if rgName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	name, _ := props["name"].(string)
	if name == "" {
		name = request.Label
	}
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}
	location, _ := props["location"].(string)
	if location == "" {
		return nil, fmt.Errorf("location is required")
	}

	params := armcompute.SSHPublicKeyResource{
		Location:   stringPtr(location),
		Properties: &armcompute.SSHPublicKeyResourceProperties{},
	}
	if key, ok := props["publicKey"].(string); ok && key != "" {
		params.Properties.PublicKey = stringPtr(key)
	}
	if azureTags := formaeTagsToAzureTags(request.Properties); azureTags != nil {
		params.Tags = azureTags
	}

	// Synchronous: Create returns the final state immediately.
	result, err := s.api.Create(ctx, rgName, name, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	propsJSON, err := serializeSSHPublicKeyProperties(result.SSHPublicKeyResource, rgName, name)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize SshPublicKey properties: %w", err)
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

func (s *SSHPublicKey) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, name, err := sshPublicKeyIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := s.api.Get(ctx, rgName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := serializeSSHPublicKeyProperties(result.SSHPublicKeyResource, rgName, name)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize SshPublicKey properties: %w", err)
	}

	return &resource.ReadResult{
		ResourceType: ResourceTypeSSHPublicKey,
		Properties:   string(propsJSON),
	}, nil
}

func (s *SSHPublicKey) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, name, err := sshPublicKeyIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props map[string]any
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse desired properties: %w", err)
	}

	update := armcompute.SSHPublicKeyUpdateResource{
		Properties: &armcompute.SSHPublicKeyResourceProperties{},
	}
	if key, ok := props["publicKey"].(string); ok && key != "" {
		update.Properties.PublicKey = stringPtr(key)
	}
	if azureTags := formaeTagsToAzureTags(request.DesiredProperties); azureTags != nil {
		update.Tags = azureTags
	}

	result, err := s.api.Update(ctx, rgName, name, update, nil)
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

	propsJSON, err := serializeSSHPublicKeyProperties(result.SSHPublicKeyResource, rgName, name)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize SshPublicKey properties: %w", err)
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

func (s *SSHPublicKey) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, name, err := sshPublicKeyIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	// Synchronous delete. NotFound means the goal is already achieved.
	if _, err := s.api.Delete(ctx, rgName, name, nil); err != nil {
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

// Status is a no-op success passthrough: SSH public key operations are
// synchronous, so Create/Update/Delete never return InProgress. It exists only
// to satisfy the Provisioner interface.
func (s *SSHPublicKey) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

func (s *SSHPublicKey) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]

	var nativeIDs []string
	if rgName != "" {
		pager := s.api.NewListByResourceGroupPager(rgName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list SSH public keys in resource group %s: %w", rgName, err)
			}
			for _, key := range page.Value {
				if key.ID != nil {
					nativeIDs = append(nativeIDs, *key.ID)
				}
			}
		}
		return &resource.ListResult{NativeIDs: nativeIDs}, nil
	}

	pager := s.api.NewListBySubscriptionPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list SSH public keys: %w", err)
		}
		for _, key := range page.Value {
			if key.ID != nil {
				nativeIDs = append(nativeIDs, *key.ID)
			}
		}
	}

	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
