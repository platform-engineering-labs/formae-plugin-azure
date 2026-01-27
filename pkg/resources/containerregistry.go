// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerregistry/armcontainerregistry"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeContainerRegistry = "Azure::ContainerRegistry::Registry"

func init() {
	registry.Register(ResourceTypeContainerRegistry, func(client *client.Client, cfg *config.Config) prov.Provisioner {
		return &ContainerRegistry{client, cfg}
	})
}

// ContainerRegistry is the provisioner for Azure Container Registries.
type ContainerRegistry struct {
	Client *client.Client
	Config *config.Config
}

// serializeContainerRegistryProperties converts an Azure Registry to Formae property format
func serializeContainerRegistryProperties(result armcontainerregistry.Registry, rgName, registryName string) (json.RawMessage, error) {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	if result.Name != nil {
		props["name"] = *result.Name
	} else {
		props["name"] = registryName
	}

	if result.Location != nil {
		props["location"] = *result.Location
	}

	// SKU
	if result.SKU != nil && result.SKU.Name != nil {
		sku := make(map[string]any)
		sku["name"] = string(*result.SKU.Name)
		props["sku"] = sku
	}

	// Properties
	if result.Properties != nil {
		if result.Properties.AdminUserEnabled != nil {
			props["adminUserEnabled"] = *result.Properties.AdminUserEnabled
		}
		if result.Properties.LoginServer != nil {
			props["loginServer"] = *result.Properties.LoginServer
		}
		if result.Properties.PublicNetworkAccess != nil {
			props["publicNetworkAccess"] = string(*result.Properties.PublicNetworkAccess)
		}
		if result.Properties.ZoneRedundancy != nil {
			props["zoneRedundancy"] = string(*result.Properties.ZoneRedundancy)
		}
	}

	// Add tags
	if tags := azureTagsToFormaeTags(result.Tags); tags != nil {
		props["Tags"] = tags
	}

	// Include id for resolvable references
	if result.ID != nil {
		props["id"] = *result.ID
	}

	return json.Marshal(props)
}

func (cr *ContainerRegistry) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props map[string]any
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	rgName, ok := props["resourceGroupName"].(string)
	if !ok || rgName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}

	location, ok := props["location"].(string)
	if !ok || location == "" {
		return nil, fmt.Errorf("location is required")
	}

	registryName, ok := props["name"].(string)
	if !ok || registryName == "" {
		registryName = request.Label
	}

	// Parse SKU
	var sku *armcontainerregistry.SKU
	if skuRaw, ok := props["sku"].(map[string]any); ok {
		sku = &armcontainerregistry.SKU{}
		if name, ok := skuRaw["name"].(string); ok {
			skuName := armcontainerregistry.SKUName(name)
			sku.Name = &skuName
		}
	}
	if sku == nil || sku.Name == nil {
		return nil, fmt.Errorf("sku.name is required")
	}

	params := armcontainerregistry.Registry{
		Location:   stringPtr(location),
		SKU:        sku,
		Properties: &armcontainerregistry.RegistryProperties{},
	}

	// Parse adminUserEnabled
	if adminEnabled, ok := props["adminUserEnabled"].(bool); ok {
		params.Properties.AdminUserEnabled = &adminEnabled
	}

	// Parse publicNetworkAccess
	if publicAccess, ok := props["publicNetworkAccess"].(string); ok {
		access := armcontainerregistry.PublicNetworkAccess(publicAccess)
		params.Properties.PublicNetworkAccess = &access
	}

	// Parse zoneRedundancy
	if zoneRedundancy, ok := props["zoneRedundancy"].(string); ok {
		zr := armcontainerregistry.ZoneRedundancy(zoneRedundancy)
		params.Properties.ZoneRedundancy = &zr
	}

	if azureTags := formaeTagsToAzureTags(request.Properties); azureTags != nil {
		params.Tags = azureTags
	}

	// Container Registry creation is async (LRO)
	poller, err := cr.Client.RegistriesClient.BeginCreate(ctx, rgName, registryName, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       mapAzureErrorToOperationErrorCode(err),
			},
		}, fmt.Errorf("failed to start Container Registry creation: %w", err)
	}

	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.ContainerRegistry/registries/%s",
		cr.Config.SubscriptionId, rgName, registryName)

	if poller.Done() {
		result, err := poller.Result(ctx)
		if err != nil {
			return &resource.CreateResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationCreate,
					OperationStatus: resource.OperationStatusFailure,
					ErrorCode:       mapAzureErrorToOperationErrorCode(err),
				},
			}, fmt.Errorf("failed to get Container Registry create result: %w", err)
		}

		propsJSON, err := serializeContainerRegistryProperties(result.Registry, rgName, registryName)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize Container Registry properties: %w", err)
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

	resumeToken, err := poller.ResumeToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get resume token: %w", err)
	}

	reqID := lroRequestID{
		OperationType: "create",
		ResumeToken:   resumeToken,
		NativeID:      expectedNativeID,
	}
	reqIDJSON, err := json.Marshal(reqID)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request ID: %w", err)
	}

	return &resource.CreateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationCreate,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       string(reqIDJSON),
			NativeID:        expectedNativeID,
		},
	}, nil
}

func (cr *ContainerRegistry) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	parts := splitResourceID(request.NativeID)

	rgName, ok := parts["resourcegroups"]
	if !ok || rgName == "" {
		return nil, fmt.Errorf("invalid NativeID: could not extract resource group name from %s", request.NativeID)
	}

	registryName, ok := parts["registries"]
	if !ok || registryName == "" {
		return nil, fmt.Errorf("invalid NativeID: could not extract registry name from %s", request.NativeID)
	}

	result, err := cr.Client.RegistriesClient.Get(ctx, rgName, registryName, nil)
	if err != nil {
		return &resource.ReadResult{
			ErrorCode: mapAzureErrorToOperationErrorCode(err),
		}, fmt.Errorf("failed to read Container Registry: %w", err)
	}

	propsJSON, err := serializeContainerRegistryProperties(result.Registry, rgName, registryName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize Container Registry properties: %w", err)
	}

	return &resource.ReadResult{
		Properties: string(propsJSON),
	}, nil
}

func (cr *ContainerRegistry) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	parts := splitResourceID(request.NativeID)

	rgName, ok := parts["resourcegroups"]
	if !ok || rgName == "" {
		return nil, fmt.Errorf("invalid NativeID: could not extract resource group name from %s", request.NativeID)
	}

	registryName, ok := parts["registries"]
	if !ok || registryName == "" {
		return nil, fmt.Errorf("invalid NativeID: could not extract registry name from %s", request.NativeID)
	}

	var props map[string]any
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	params := armcontainerregistry.RegistryUpdateParameters{
		Properties: &armcontainerregistry.RegistryPropertiesUpdateParameters{},
	}

	// Parse adminUserEnabled (updatable)
	if adminEnabled, ok := props["adminUserEnabled"].(bool); ok {
		params.Properties.AdminUserEnabled = &adminEnabled
	}

	// Parse publicNetworkAccess (updatable)
	if publicAccess, ok := props["publicNetworkAccess"].(string); ok {
		access := armcontainerregistry.PublicNetworkAccess(publicAccess)
		params.Properties.PublicNetworkAccess = &access
	}

	// Parse SKU (updatable)
	if skuRaw, ok := props["sku"].(map[string]any); ok {
		if name, ok := skuRaw["name"].(string); ok {
			skuName := armcontainerregistry.SKUName(name)
			params.SKU = &armcontainerregistry.SKU{Name: &skuName}
		}
	}

	if azureTags := formaeTagsToAzureTags(request.DesiredProperties); azureTags != nil {
		params.Tags = azureTags
	}

	// Container Registry update is async (LRO)
	poller, err := cr.Client.RegistriesClient.BeginUpdate(ctx, rgName, registryName, params, nil)
	if err != nil {
		return &resource.UpdateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationUpdate,
				OperationStatus: resource.OperationStatusFailure,
				NativeID:        request.NativeID,
				ErrorCode:       mapAzureErrorToOperationErrorCode(err),
			},
		}, fmt.Errorf("failed to start Container Registry update: %w", err)
	}

	if poller.Done() {
		result, err := poller.Result(ctx)
		if err != nil {
			return &resource.UpdateResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationUpdate,
					OperationStatus: resource.OperationStatusFailure,
					NativeID:        request.NativeID,
					ErrorCode:       mapAzureErrorToOperationErrorCode(err),
				},
			}, fmt.Errorf("failed to get Container Registry update result: %w", err)
		}

		propsJSON, err := serializeContainerRegistryProperties(result.Registry, rgName, registryName)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize Container Registry properties: %w", err)
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

	resumeToken, err := poller.ResumeToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get resume token: %w", err)
	}

	reqID := lroRequestID{
		OperationType: "update",
		ResumeToken:   resumeToken,
		NativeID:      request.NativeID,
	}
	reqIDJSON, err := json.Marshal(reqID)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request ID: %w", err)
	}

	return &resource.UpdateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationUpdate,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       string(reqIDJSON),
			NativeID:        request.NativeID,
		},
	}, nil
}

func (cr *ContainerRegistry) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	parts := splitResourceID(request.NativeID)

	rgName, ok := parts["resourcegroups"]
	if !ok || rgName == "" {
		return nil, fmt.Errorf("invalid NativeID: could not extract resource group name from %s", request.NativeID)
	}

	registryName, ok := parts["registries"]
	if !ok || registryName == "" {
		return nil, fmt.Errorf("invalid NativeID: could not extract registry name from %s", request.NativeID)
	}

	// Container Registry deletion is async (LRO)
	poller, err := cr.Client.RegistriesClient.BeginDelete(ctx, rgName, registryName, nil)
	if err != nil {
		// If the resource is already gone (NotFound), treat as success
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
		}, fmt.Errorf("failed to start Container Registry deletion: %w", err)
	}

	if poller.Done() {
		_, err := poller.Result(ctx)
		if err != nil {
			return &resource.DeleteResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationDelete,
					OperationStatus: resource.OperationStatusFailure,
					NativeID:        request.NativeID,
					ErrorCode:       mapAzureErrorToOperationErrorCode(err),
				},
			}, fmt.Errorf("failed to get Container Registry delete result: %w", err)
		}

		return &resource.DeleteResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationDelete,
				OperationStatus: resource.OperationStatusSuccess,
				NativeID:        request.NativeID,
			},
		}, nil
	}

	resumeToken, err := poller.ResumeToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get resume token: %w", err)
	}

	reqID := lroRequestID{
		OperationType: "delete",
		ResumeToken:   resumeToken,
		NativeID:      request.NativeID,
	}
	reqIDJSON, err := json.Marshal(reqID)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request ID: %w", err)
	}

	return &resource.DeleteResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationDelete,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       string(reqIDJSON),
			NativeID:        request.NativeID,
		},
	}, nil
}

func (cr *ContainerRegistry) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	var reqID lroRequestID
	if err := json.Unmarshal([]byte(request.RequestID), &reqID); err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
			},
		}, fmt.Errorf("failed to parse request ID: %w", err)
	}

	switch reqID.OperationType {
	case "create":
		return cr.statusCreate(ctx, request, reqID)
	case "update":
		return cr.statusUpdate(ctx, request, reqID)
	case "delete":
		return cr.statusDelete(ctx, request, reqID)
	default:
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
			},
		}, fmt.Errorf("unexpected operation type: %s", reqID.OperationType)
	}
}

func (cr *ContainerRegistry) statusCreate(ctx context.Context, request *resource.StatusRequest, reqID lroRequestID) (*resource.StatusResult, error) {
	poller, err := cr.Client.ResumeCreateContainerRegistryPoller(reqID.ResumeToken)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
			},
		}, fmt.Errorf("failed to resume poller: %w", err)
	}

	if poller.Done() {
		result, err := poller.Result(ctx)
		if err != nil {
			return &resource.StatusResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationCreate,
					OperationStatus: resource.OperationStatusFailure,
					RequestID:       request.RequestID,
					ErrorCode:       mapAzureErrorToOperationErrorCode(err),
				},
			}, nil
		}

		parts := splitResourceID(*result.ID)
		rgName := parts["resourcegroups"]
		registryName := parts["registries"]

		propsJSON, err := serializeContainerRegistryProperties(result.Registry, rgName, registryName)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize Container Registry properties: %w", err)
		}

		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				Operation:          resource.OperationCreate,
				OperationStatus:    resource.OperationStatusSuccess,
				RequestID:          request.RequestID,
				NativeID:           *result.ID,
				ResourceProperties: propsJSON,
			},
		}, nil
	}

	_, err = poller.Poll(ctx)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       mapAzureErrorToOperationErrorCode(err),
			},
		}, nil
	}

	if poller.Done() {
		result, err := poller.Result(ctx)
		if err != nil {
			return &resource.StatusResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationCreate,
					OperationStatus: resource.OperationStatusFailure,
					RequestID:       request.RequestID,
					ErrorCode:       mapAzureErrorToOperationErrorCode(err),
				},
			}, nil
		}

		parts := splitResourceID(*result.ID)
		rgName := parts["resourcegroups"]
		registryName := parts["registries"]

		propsJSON, err := serializeContainerRegistryProperties(result.Registry, rgName, registryName)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize Container Registry properties: %w", err)
		}

		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				Operation:          resource.OperationCreate,
				OperationStatus:    resource.OperationStatusSuccess,
				RequestID:          request.RequestID,
				NativeID:           *result.ID,
				ResourceProperties: propsJSON,
			},
		}, nil
	}

	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationCreate,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       request.RequestID,
		},
	}, nil
}

func (cr *ContainerRegistry) statusUpdate(ctx context.Context, request *resource.StatusRequest, reqID lroRequestID) (*resource.StatusResult, error) {
	poller, err := cr.Client.ResumeUpdateContainerRegistryPoller(reqID.ResumeToken)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationUpdate,
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
			},
		}, fmt.Errorf("failed to resume poller: %w", err)
	}

	if poller.Done() {
		result, err := poller.Result(ctx)
		if err != nil {
			return &resource.StatusResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationUpdate,
					OperationStatus: resource.OperationStatusFailure,
					RequestID:       request.RequestID,
					NativeID:        reqID.NativeID,
					ErrorCode:       mapAzureErrorToOperationErrorCode(err),
				},
			}, nil
		}

		parts := splitResourceID(*result.ID)
		rgName := parts["resourcegroups"]
		registryName := parts["registries"]

		propsJSON, err := serializeContainerRegistryProperties(result.Registry, rgName, registryName)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize Container Registry properties: %w", err)
		}

		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				Operation:          resource.OperationUpdate,
				OperationStatus:    resource.OperationStatusSuccess,
				RequestID:          request.RequestID,
				NativeID:           *result.ID,
				ResourceProperties: propsJSON,
			},
		}, nil
	}

	_, err = poller.Poll(ctx)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationUpdate,
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				NativeID:        reqID.NativeID,
				ErrorCode:       mapAzureErrorToOperationErrorCode(err),
			},
		}, nil
	}

	if poller.Done() {
		result, err := poller.Result(ctx)
		if err != nil {
			return &resource.StatusResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationUpdate,
					OperationStatus: resource.OperationStatusFailure,
					RequestID:       request.RequestID,
					NativeID:        reqID.NativeID,
					ErrorCode:       mapAzureErrorToOperationErrorCode(err),
				},
			}, nil
		}

		parts := splitResourceID(*result.ID)
		rgName := parts["resourcegroups"]
		registryName := parts["registries"]

		propsJSON, err := serializeContainerRegistryProperties(result.Registry, rgName, registryName)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize Container Registry properties: %w", err)
		}

		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				Operation:          resource.OperationUpdate,
				OperationStatus:    resource.OperationStatusSuccess,
				RequestID:          request.RequestID,
				NativeID:           *result.ID,
				ResourceProperties: propsJSON,
			},
		}, nil
	}

	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationUpdate,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       request.RequestID,
			NativeID:        reqID.NativeID,
		},
	}, nil
}

func (cr *ContainerRegistry) statusDelete(ctx context.Context, request *resource.StatusRequest, reqID lroRequestID) (*resource.StatusResult, error) {
	poller, err := cr.Client.ResumeDeleteContainerRegistryPoller(reqID.ResumeToken)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationDelete,
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
			},
		}, fmt.Errorf("failed to resume poller: %w", err)
	}

	if poller.Done() {
		_, err := poller.Result(ctx)
		if err != nil {
			// NotFound means resource is already deleted - success
			if isDeleteSuccessError(err) {
				return &resource.StatusResult{
					ProgressResult: &resource.ProgressResult{
						Operation:       resource.OperationDelete,
						OperationStatus: resource.OperationStatusSuccess,
						RequestID:       request.RequestID,
						NativeID:        reqID.NativeID,
					},
				}, nil
			}
			return &resource.StatusResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationDelete,
					OperationStatus: resource.OperationStatusFailure,
					RequestID:       request.RequestID,
					NativeID:        reqID.NativeID,
					ErrorCode:       mapAzureErrorToOperationErrorCode(err),
				},
			}, nil
		}

		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationDelete,
				OperationStatus: resource.OperationStatusSuccess,
				RequestID:       request.RequestID,
				NativeID:        reqID.NativeID,
			},
		}, nil
	}

	_, err = poller.Poll(ctx)
	if err != nil {
		// NotFound means resource is already deleted - success
		if isDeleteSuccessError(err) {
			return &resource.StatusResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationDelete,
					OperationStatus: resource.OperationStatusSuccess,
					RequestID:       request.RequestID,
					NativeID:        reqID.NativeID,
				},
			}, nil
		}
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationDelete,
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				NativeID:        reqID.NativeID,
				ErrorCode:       mapAzureErrorToOperationErrorCode(err),
			},
		}, nil
	}

	if poller.Done() {
		_, err := poller.Result(ctx)
		if err != nil {
			// NotFound means resource is already deleted - success
			if isDeleteSuccessError(err) {
				return &resource.StatusResult{
					ProgressResult: &resource.ProgressResult{
						Operation:       resource.OperationDelete,
						OperationStatus: resource.OperationStatusSuccess,
						RequestID:       request.RequestID,
						NativeID:        reqID.NativeID,
					},
				}, nil
			}
			return &resource.StatusResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationDelete,
					OperationStatus: resource.OperationStatusFailure,
					RequestID:       request.RequestID,
					NativeID:        reqID.NativeID,
					ErrorCode:       mapAzureErrorToOperationErrorCode(err),
				},
			}, nil
		}

		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationDelete,
				OperationStatus: resource.OperationStatusSuccess,
				RequestID:       request.RequestID,
				NativeID:        reqID.NativeID,
			},
		}, nil
	}

	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationDelete,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       request.RequestID,
			NativeID:        reqID.NativeID,
		},
	}, nil
}

func (cr *ContainerRegistry) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	// Get resourceGroupName from AdditionalProperties
	rgName, ok := request.AdditionalProperties["resourceGroupName"]
	if !ok || rgName == "" {
		return nil, fmt.Errorf("resourceGroupName is required in AdditionalProperties for listing Container Registries")
	}

	pager := cr.Client.RegistriesClient.NewListByResourceGroupPager(rgName, nil)

	var nativeIDs []string

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list Container Registries: %w", err)
		}

		for _, registry := range page.Value {
			if registry.ID == nil {
				continue
			}
			nativeIDs = append(nativeIDs, *registry.ID)
		}
	}

	return &resource.ListResult{
		NativeIDs: nativeIDs,
	}, nil
}
