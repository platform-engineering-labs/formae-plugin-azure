// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerregistry/armcontainerregistry"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeContainerRegistry = "AZURE::ContainerRegistry::Registry"

type containerRegistryAPI interface {
	BeginCreate(ctx context.Context, resourceGroupName string, registryName string, registry armcontainerregistry.Registry, options *armcontainerregistry.RegistriesClientBeginCreateOptions) (*runtime.Poller[armcontainerregistry.RegistriesClientCreateResponse], error)
	Get(ctx context.Context, resourceGroupName string, registryName string, options *armcontainerregistry.RegistriesClientGetOptions) (armcontainerregistry.RegistriesClientGetResponse, error)
	BeginUpdate(ctx context.Context, resourceGroupName string, registryName string, registryUpdateParameters armcontainerregistry.RegistryUpdateParameters, options *armcontainerregistry.RegistriesClientBeginUpdateOptions) (*runtime.Poller[armcontainerregistry.RegistriesClientUpdateResponse], error)
	BeginDelete(ctx context.Context, resourceGroupName string, registryName string, options *armcontainerregistry.RegistriesClientBeginDeleteOptions) (*runtime.Poller[armcontainerregistry.RegistriesClientDeleteResponse], error)
	NewListPager(options *armcontainerregistry.RegistriesClientListOptions) *runtime.Pager[armcontainerregistry.RegistriesClientListResponse]
	NewListByResourceGroupPager(resourceGroupName string, options *armcontainerregistry.RegistriesClientListByResourceGroupOptions) *runtime.Pager[armcontainerregistry.RegistriesClientListByResourceGroupResponse]
}

func init() {
	registry.Register(ResourceTypeContainerRegistry, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &ContainerRegistry{
			api:      c.RegistriesClient,
			config:   cfg,
			pipeline: c.Pipeline(),
		}
	})
}

// ContainerRegistry is the provisioner for Azure Container Registries.
type ContainerRegistry struct {
	api      containerRegistryAPI
	config   *config.Config
	pipeline runtime.Pipeline
}

func containerRegistryIDParts(resourceID string) (rgName, registryName string, err error) {
	rgName, names, err := armIDParts(resourceID, "registries")
	if err != nil {
		return "", "", err
	}
	return rgName, names["registries"], nil
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
	poller, err := cr.api.BeginCreate(ctx, rgName, registryName, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.ContainerRegistry/registries/%s",
		cr.config.SubscriptionId, rgName, registryName)

	if poller.Done() {
		result, err := poller.Result(ctx)
		if err != nil {
			return &resource.CreateResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationCreate,
					OperationStatus: resource.OperationStatusFailure,
					ErrorCode:       operationErrorCode(err),
				},
			}, nil
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

	reqIDJSON, err := encodeLROStart(lroOpCreate, resumeToken, expectedNativeID)
	if err != nil {
		return nil, err
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
	rgName, registryName, err := containerRegistryIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := cr.api.Get(ctx, rgName, registryName, nil)
	if err != nil {
		return &resource.ReadResult{
			ErrorCode: operationErrorCode(err),
		}, nil
	}

	propsJSON, err := serializeContainerRegistryProperties(result.Registry, rgName, registryName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize Container Registry properties: %w", err)
	}

	return &resource.ReadResult{
		ResourceType: ResourceTypeContainerRegistry,
		Properties:   string(propsJSON),
	}, nil
}

func (cr *ContainerRegistry) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, registryName, err := containerRegistryIDParts(request.NativeID)
	if err != nil {
		return nil, err
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
	poller, err := cr.api.BeginUpdate(ctx, rgName, registryName, params, nil)
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

	if poller.Done() {
		result, err := poller.Result(ctx)
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

	reqIDJSON, err := encodeLROStart(lroOpUpdate, resumeToken, request.NativeID)
	if err != nil {
		return nil, err
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
	rgName, registryName, err := containerRegistryIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	// Container Registry deletion is async (LRO)
	poller, err := cr.api.BeginDelete(ctx, rgName, registryName, nil)
	if err != nil {
		// If the resource is already gone (NotFound), treat as success
		if operationErrorCode(err) == resource.OperationErrorCodeNotFound {
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
					ErrorCode:       operationErrorCode(err),
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

	reqIDJSON, err := encodeLROStart(lroOpDelete, resumeToken, request.NativeID)
	if err != nil {
		return nil, err
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
	reqID, err := decodeLROStatus(request.RequestID)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
			},
		}, err
	}

	switch reqID.OperationType {
	case lroOpCreate:
		return cr.statusCreate(ctx, request, &reqID)
	case lroOpUpdate:
		return cr.statusUpdate(ctx, request, &reqID)
	case lroOpDelete:
		return cr.statusDelete(ctx, request, &reqID)
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

func (cr *ContainerRegistry) statusCreate(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	return statusLRO(ctx, request, reqID, resource.OperationCreate,
		func(token string) (*runtime.Poller[armcontainerregistry.RegistriesClientCreateResponse], error) {
			return resumePoller[armcontainerregistry.RegistriesClientCreateResponse](cr.pipeline, token)
		},
		func(_ context.Context, result armcontainerregistry.RegistriesClientCreateResponse, _ resource.Operation) (string, json.RawMessage, error) {
			rgName, registryName, err := containerRegistryIDParts(*result.ID)
			if err != nil {
				return "", nil, err
			}
			propsJSON, err := serializeContainerRegistryProperties(result.Registry, rgName, registryName)
			if err != nil {
				return "", nil, fmt.Errorf("failed to serialize Container Registry properties: %w", err)
			}
			return *result.ID, propsJSON, nil
		})
}

func (cr *ContainerRegistry) statusUpdate(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	return statusLRO(ctx, request, reqID, resource.OperationUpdate,
		func(token string) (*runtime.Poller[armcontainerregistry.RegistriesClientUpdateResponse], error) {
			return resumePoller[armcontainerregistry.RegistriesClientUpdateResponse](cr.pipeline, token)
		},
		func(_ context.Context, result armcontainerregistry.RegistriesClientUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
			rgName, registryName, err := containerRegistryIDParts(*result.ID)
			if err != nil {
				return "", nil, err
			}
			propsJSON, err := serializeContainerRegistryProperties(result.Registry, rgName, registryName)
			if err != nil {
				return "", nil, fmt.Errorf("failed to serialize Container Registry properties: %w", err)
			}
			return *result.ID, propsJSON, nil
		})
}

func (cr *ContainerRegistry) statusDelete(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	return statusDeleteLRO(ctx, request, reqID,
		func(token string) (*runtime.Poller[armcontainerregistry.RegistriesClientDeleteResponse], error) {
			return resumePoller[armcontainerregistry.RegistriesClientDeleteResponse](cr.pipeline, token)
		}, nil)
}

func (cr *ContainerRegistry) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]

	var nativeIDs []string

	if rgName != "" {
		pager := cr.api.NewListByResourceGroupPager(rgName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list Container Registries: %w", err)
			}
			for _, registry := range page.Value {
				if registry.ID != nil {
					nativeIDs = append(nativeIDs, *registry.ID)
				}
			}
		}
	} else {
		pager := cr.api.NewListPager(nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list Container Registries: %w", err)
			}
			for _, registry := range page.Value {
				if registry.ID != nil {
					nativeIDs = append(nativeIDs, *registry.ID)
				}
			}
		}
	}

	return &resource.ListResult{
		NativeIDs: nativeIDs,
	}, nil
}
