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

const ResourceTypeVirtualMachineExtension = "AZURE::Compute::VirtualMachineExtension"

type virtualMachineExtensionsAPI interface {
	BeginCreateOrUpdate(ctx context.Context, resourceGroupName string, vmName string, vmExtensionName string, extensionParameters armcompute.VirtualMachineExtension, options *armcompute.VirtualMachineExtensionsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armcompute.VirtualMachineExtensionsClientCreateOrUpdateResponse], error)
	Get(ctx context.Context, resourceGroupName string, vmName string, vmExtensionName string, options *armcompute.VirtualMachineExtensionsClientGetOptions) (armcompute.VirtualMachineExtensionsClientGetResponse, error)
	BeginUpdate(ctx context.Context, resourceGroupName string, vmName string, vmExtensionName string, extensionParameters armcompute.VirtualMachineExtensionUpdate, options *armcompute.VirtualMachineExtensionsClientBeginUpdateOptions) (*runtime.Poller[armcompute.VirtualMachineExtensionsClientUpdateResponse], error)
	BeginDelete(ctx context.Context, resourceGroupName string, vmName string, vmExtensionName string, options *armcompute.VirtualMachineExtensionsClientBeginDeleteOptions) (*runtime.Poller[armcompute.VirtualMachineExtensionsClientDeleteResponse], error)
	List(ctx context.Context, resourceGroupName string, vmName string, options *armcompute.VirtualMachineExtensionsClientListOptions) (armcompute.VirtualMachineExtensionsClientListResponse, error)
}

func init() {
	registry.Register(ResourceTypeVirtualMachineExtension, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &VirtualMachineExtension{
			api:      c.VirtualMachineExtensionsClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// VirtualMachineExtension is the provisioner for Azure Virtual Machine Extensions.
type VirtualMachineExtension struct {
	api      virtualMachineExtensionsAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

func virtualMachineExtensionIDParts(resourceID string) (rgName, vmName, extName string, err error) {
	rgName, names, err := armIDParts(resourceID, "virtualmachines", "extensions")
	if err != nil {
		return "", "", "", err
	}
	return rgName, names["virtualmachines"], names["extensions"], nil
}

// serializeVirtualMachineExtensionProperties converts an Azure extension to Formae
// property format. protectedSettings is writeOnly and never echoed back.
func serializeVirtualMachineExtensionProperties(result armcompute.VirtualMachineExtension, rgName, vmName string) (json.RawMessage, error) {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	props["virtualMachineName"] = vmName

	if result.Name != nil {
		props["name"] = *result.Name
	}
	if result.Location != nil {
		props["location"] = *result.Location
	}

	if result.Properties != nil {
		if result.Properties.Publisher != nil {
			props["publisher"] = *result.Properties.Publisher
		}
		if result.Properties.Type != nil {
			props["type"] = *result.Properties.Type
		}
		if result.Properties.TypeHandlerVersion != nil {
			props["typeHandlerVersion"] = *result.Properties.TypeHandlerVersion
		}
		if result.Properties.AutoUpgradeMinorVersion != nil {
			props["autoUpgradeMinorVersion"] = *result.Properties.AutoUpgradeMinorVersion
		}
		if result.Properties.Settings != nil {
			props["settings"] = result.Properties.Settings
		}
	}

	if tags := azureTagsToFormaeTags(result.Tags); tags != nil {
		props["Tags"] = tags
	}

	if result.ID != nil {
		props["id"] = *result.ID
	}

	return json.Marshal(props)
}

func (v *VirtualMachineExtension) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props map[string]any
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	rgName, ok := props["resourceGroupName"].(string)
	if !ok || rgName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}

	vmName, ok := props["virtualMachineName"].(string)
	if !ok || vmName == "" {
		return nil, fmt.Errorf("virtualMachineName is required")
	}

	extName, ok := props["name"].(string)
	if !ok || extName == "" {
		extName = request.Label
	}

	location, ok := props["location"].(string)
	if !ok || location == "" {
		return nil, fmt.Errorf("location is required")
	}

	publisher, ok := props["publisher"].(string)
	if !ok || publisher == "" {
		return nil, fmt.Errorf("publisher is required")
	}

	extType, ok := props["type"].(string)
	if !ok || extType == "" {
		return nil, fmt.Errorf("type is required")
	}

	params := armcompute.VirtualMachineExtension{
		Location: stringPtr(location),
		Properties: &armcompute.VirtualMachineExtensionProperties{
			Publisher: stringPtr(publisher),
			Type:      stringPtr(extType),
		},
	}

	if typeHandlerVersion, ok := props["typeHandlerVersion"].(string); ok {
		params.Properties.TypeHandlerVersion = stringPtr(typeHandlerVersion)
	}
	if autoUpgrade, ok := props["autoUpgradeMinorVersion"].(bool); ok {
		params.Properties.AutoUpgradeMinorVersion = &autoUpgrade
	}
	if settings, ok := props["settings"]; ok && settings != nil {
		params.Properties.Settings = settings
	}
	if protected, ok := props["protectedSettings"]; ok && protected != nil {
		params.Properties.ProtectedSettings = protected
	}

	if azureTags := formaeTagsToAzureTags(request.Properties); azureTags != nil {
		params.Tags = azureTags
	}

	poller, err := v.api.BeginCreateOrUpdate(ctx, rgName, vmName, extName, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Compute/virtualMachines/%s/extensions/%s",
		v.config.SubscriptionId, rgName, vmName, extName)

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

		propsJSON, err := serializeVirtualMachineExtensionProperties(result.VirtualMachineExtension, rgName, vmName)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize VM extension properties: %w", err)
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
			RequestID:       reqIDJSON,
			NativeID:        expectedNativeID,
		},
	}, nil
}

func (v *VirtualMachineExtension) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, vmName, extName, err := virtualMachineExtensionIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := v.api.Get(ctx, rgName, vmName, extName, nil)
	if err != nil {
		return &resource.ReadResult{
			ErrorCode: operationErrorCode(err),
		}, nil
	}

	propsJSON, err := serializeVirtualMachineExtensionProperties(result.VirtualMachineExtension, rgName, vmName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize VM extension properties: %w", err)
	}

	return &resource.ReadResult{
		ResourceType: ResourceTypeVirtualMachineExtension,
		Properties:   string(propsJSON),
	}, nil
}

func (v *VirtualMachineExtension) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, vmName, extName, err := virtualMachineExtensionIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props map[string]any
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	params := armcompute.VirtualMachineExtensionUpdate{
		Properties: &armcompute.VirtualMachineExtensionUpdateProperties{},
	}

	if publisher, ok := props["publisher"].(string); ok {
		params.Properties.Publisher = stringPtr(publisher)
	}
	if extType, ok := props["type"].(string); ok {
		params.Properties.Type = stringPtr(extType)
	}
	if typeHandlerVersion, ok := props["typeHandlerVersion"].(string); ok {
		params.Properties.TypeHandlerVersion = stringPtr(typeHandlerVersion)
	}
	if autoUpgrade, ok := props["autoUpgradeMinorVersion"].(bool); ok {
		params.Properties.AutoUpgradeMinorVersion = &autoUpgrade
	}
	if settings, ok := props["settings"]; ok && settings != nil {
		params.Properties.Settings = settings
	}
	if protected, ok := props["protectedSettings"]; ok && protected != nil {
		params.Properties.ProtectedSettings = protected
	}

	if azureTags := formaeTagsToAzureTags(request.DesiredProperties); azureTags != nil {
		params.Tags = azureTags
	}

	poller, err := v.api.BeginUpdate(ctx, rgName, vmName, extName, params, nil)
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

		propsJSON, err := serializeVirtualMachineExtensionProperties(result.VirtualMachineExtension, rgName, vmName)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize VM extension properties: %w", err)
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
			RequestID:       reqIDJSON,
			NativeID:        request.NativeID,
		},
	}, nil
}

func (v *VirtualMachineExtension) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, vmName, extName, err := virtualMachineExtensionIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, err := v.api.BeginDelete(ctx, rgName, vmName, extName, nil)
	if err != nil {
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
		}, fmt.Errorf("failed to start VM extension deletion: %w", err)
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
			RequestID:       reqIDJSON,
			NativeID:        request.NativeID,
		},
	}, nil
}

func (v *VirtualMachineExtension) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
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
		return v.statusCreate(ctx, request, &reqID)
	case lroOpUpdate:
		return v.statusUpdate(ctx, request, &reqID)
	case lroOpDelete:
		return v.statusDelete(ctx, request, &reqID)
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

func (v *VirtualMachineExtension) statusCreate(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	return statusLRO(ctx, request, reqID, resource.OperationCreate,
		func(token string) (*runtime.Poller[armcompute.VirtualMachineExtensionsClientCreateOrUpdateResponse], error) {
			return resumePoller[armcompute.VirtualMachineExtensionsClientCreateOrUpdateResponse](v.pipeline, token)
		},
		func(_ context.Context, result armcompute.VirtualMachineExtensionsClientCreateOrUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
			rgName, vmName, _, err := virtualMachineExtensionIDParts(*result.ID)
			if err != nil {
				return "", nil, err
			}
			propsJSON, err := serializeVirtualMachineExtensionProperties(result.VirtualMachineExtension, rgName, vmName)
			if err != nil {
				return "", nil, fmt.Errorf("failed to serialize VM extension properties: %w", err)
			}
			return *result.ID, propsJSON, nil
		})
}

func (v *VirtualMachineExtension) statusUpdate(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	return statusLRO(ctx, request, reqID, resource.OperationUpdate,
		func(token string) (*runtime.Poller[armcompute.VirtualMachineExtensionsClientUpdateResponse], error) {
			return resumePoller[armcompute.VirtualMachineExtensionsClientUpdateResponse](v.pipeline, token)
		},
		func(_ context.Context, result armcompute.VirtualMachineExtensionsClientUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
			rgName, vmName, _, err := virtualMachineExtensionIDParts(*result.ID)
			if err != nil {
				return "", nil, err
			}
			propsJSON, err := serializeVirtualMachineExtensionProperties(result.VirtualMachineExtension, rgName, vmName)
			if err != nil {
				return "", nil, fmt.Errorf("failed to serialize VM extension properties: %w", err)
			}
			return *result.ID, propsJSON, nil
		})
}

func (v *VirtualMachineExtension) statusDelete(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	return statusDeleteLRO(ctx, request, reqID,
		func(token string) (*runtime.Poller[armcompute.VirtualMachineExtensionsClientDeleteResponse], error) {
			return resumePoller[armcompute.VirtualMachineExtensionsClientDeleteResponse](v.pipeline, token)
		}, nil)
}

func (v *VirtualMachineExtension) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName, ok := request.AdditionalProperties["resourceGroupName"]
	if !ok || rgName == "" {
		return nil, fmt.Errorf("resourceGroupName is required in AdditionalProperties for listing VM extensions")
	}

	vmName, ok := request.AdditionalProperties["virtualMachineName"]
	if !ok || vmName == "" {
		return nil, fmt.Errorf("virtualMachineName is required in AdditionalProperties for listing VM extensions")
	}

	result, err := v.api.List(ctx, rgName, vmName, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to list VM extensions: %w", err)
	}

	var nativeIDs []string
	for _, ext := range result.Value {
		if ext.ID != nil {
			nativeIDs = append(nativeIDs, *ext.ID)
		}
	}

	return &resource.ListResult{
		NativeIDs: nativeIDs,
	}, nil
}
