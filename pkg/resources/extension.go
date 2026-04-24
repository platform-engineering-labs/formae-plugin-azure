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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/kubernetesconfiguration/armkubernetesconfiguration"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

type extensionsAPI interface {
	BeginCreate(ctx context.Context, resourceGroupName string, clusterRp string, clusterResourceName string, clusterName string, extensionName string, extension armkubernetesconfiguration.Extension, options *armkubernetesconfiguration.ExtensionsClientBeginCreateOptions) (*runtime.Poller[armkubernetesconfiguration.ExtensionsClientCreateResponse], error)
	Get(ctx context.Context, resourceGroupName string, clusterRp string, clusterResourceName string, clusterName string, extensionName string, options *armkubernetesconfiguration.ExtensionsClientGetOptions) (armkubernetesconfiguration.ExtensionsClientGetResponse, error)
	BeginUpdate(ctx context.Context, resourceGroupName string, clusterRp string, clusterResourceName string, clusterName string, extensionName string, patchExtension armkubernetesconfiguration.PatchExtension, options *armkubernetesconfiguration.ExtensionsClientBeginUpdateOptions) (*runtime.Poller[armkubernetesconfiguration.ExtensionsClientUpdateResponse], error)
	BeginDelete(ctx context.Context, resourceGroupName string, clusterRp string, clusterResourceName string, clusterName string, extensionName string, options *armkubernetesconfiguration.ExtensionsClientBeginDeleteOptions) (*runtime.Poller[armkubernetesconfiguration.ExtensionsClientDeleteResponse], error)
	NewListPager(resourceGroupName string, clusterRp string, clusterResourceName string, clusterName string, options *armkubernetesconfiguration.ExtensionsClientListOptions) *runtime.Pager[armkubernetesconfiguration.ExtensionsClientListResponse]
	ResumeCreatePoller(token string) (*runtime.Poller[armkubernetesconfiguration.ExtensionsClientCreateResponse], error)
	ResumeUpdatePoller(token string) (*runtime.Poller[armkubernetesconfiguration.ExtensionsClientUpdateResponse], error)
	ResumeDeletePoller(token string) (*runtime.Poller[armkubernetesconfiguration.ExtensionsClientDeleteResponse], error)
}

// extensionsClientWrapper composes the SDK client with resume-poller helpers.
type extensionsClientWrapper struct {
	*armkubernetesconfiguration.ExtensionsClient
	pipeline runtime.Pipeline
}

func (w *extensionsClientWrapper) ResumeCreatePoller(token string) (*runtime.Poller[armkubernetesconfiguration.ExtensionsClientCreateResponse], error) {
	return runtime.NewPollerFromResumeToken[armkubernetesconfiguration.ExtensionsClientCreateResponse](token, w.pipeline, nil)
}

func (w *extensionsClientWrapper) ResumeUpdatePoller(token string) (*runtime.Poller[armkubernetesconfiguration.ExtensionsClientUpdateResponse], error) {
	return runtime.NewPollerFromResumeToken[armkubernetesconfiguration.ExtensionsClientUpdateResponse](token, w.pipeline, nil)
}

func (w *extensionsClientWrapper) ResumeDeletePoller(token string) (*runtime.Poller[armkubernetesconfiguration.ExtensionsClientDeleteResponse], error) {
	return runtime.NewPollerFromResumeToken[armkubernetesconfiguration.ExtensionsClientDeleteResponse](token, w.pipeline, nil)
}

const (
	ResourceTypeExtension = "Azure::KubernetesConfiguration::Extension"

	// AKS cluster resource provider and type for the Extensions API
	aksClusterRP           = "Microsoft.ContainerService"
	aksClusterResourceName = "managedClusters"
)

func init() {
	registry.Register(ResourceTypeExtension, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &Extension{
			api: &extensionsClientWrapper{
				ExtensionsClient: c.ExtensionsClient,
				pipeline:         c.Pipeline(),
			},
			config: cfg,
		}
	})
}

type Extension struct {
	api    extensionsAPI
	config *config.Config
}

func serializeExtensionProperties(result armkubernetesconfiguration.Extension, rgName, clusterName string) (json.RawMessage, error) {
	props := make(map[string]interface{})

	if result.ID != nil {
		props["id"] = *result.ID
	}
	if result.Name != nil {
		props["name"] = *result.Name
	}
	props["resourceGroupName"] = rgName
	props["clusterName"] = clusterName

	if result.Properties != nil {
		if result.Properties.ExtensionType != nil {
			props["extensionType"] = *result.Properties.ExtensionType
		}
		if result.Properties.AutoUpgradeMinorVersion != nil {
			props["autoUpgradeMinorVersion"] = *result.Properties.AutoUpgradeMinorVersion
		}
		if result.Properties.ReleaseTrain != nil {
			props["releaseTrain"] = *result.Properties.ReleaseTrain
		}
		if result.Properties.Version != nil {
			props["version"] = *result.Properties.Version
		}
		if len(result.Properties.ConfigurationSettings) > 0 {
			settings := make(map[string]string, len(result.Properties.ConfigurationSettings))
			for k, v := range result.Properties.ConfigurationSettings {
				if v != nil {
					settings[k] = *v
				}
			}
			props["configurationSettings"] = settings
		}
		// ConfigurationProtectedSettings are write-only; Azure never returns them
	}

	return json.Marshal(props)
}

func parseStringMap(raw interface{}) map[string]*string {
	m, ok := raw.(map[string]interface{})
	if !ok {
		return nil
	}
	result := make(map[string]*string, len(m))
	for k, v := range m {
		if s, ok := v.(string); ok {
			result[k] = to.Ptr(s)
		}
	}
	return result
}

func (e *Extension) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props map[string]interface{}
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	rgName, ok := props["resourceGroupName"].(string)
	if !ok || rgName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}

	clusterName, ok := props["clusterName"].(string)
	if !ok || clusterName == "" {
		return nil, fmt.Errorf("clusterName is required")
	}

	extensionName, ok := props["name"].(string)
	if !ok || extensionName == "" {
		extensionName = request.Label
	}

	params := armkubernetesconfiguration.Extension{
		Properties: &armkubernetesconfiguration.ExtensionProperties{},
	}

	if extType, ok := props["extensionType"].(string); ok {
		params.Properties.ExtensionType = to.Ptr(extType)
	}
	if autoUpgrade, ok := props["autoUpgradeMinorVersion"].(bool); ok {
		params.Properties.AutoUpgradeMinorVersion = to.Ptr(autoUpgrade)
	}
	if releaseTrain, ok := props["releaseTrain"].(string); ok {
		params.Properties.ReleaseTrain = to.Ptr(releaseTrain)
	}
	if version, ok := props["version"].(string); ok {
		params.Properties.Version = to.Ptr(version)
	}
	if settings := parseStringMap(props["configurationSettings"]); settings != nil {
		params.Properties.ConfigurationSettings = settings
	}
	if protectedSettings := parseStringMap(props["configurationProtectedSettings"]); protectedSettings != nil {
		params.Properties.ConfigurationProtectedSettings = protectedSettings
	}

	poller, err := e.api.BeginCreate(ctx, rgName, aksClusterRP, aksClusterResourceName, clusterName, extensionName, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       mapAzureErrorToOperationErrorCode(err),
			},
		}, nil
	}

	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.ContainerService/managedClusters/%s/providers/Microsoft.KubernetesConfiguration/extensions/%s",
		e.config.SubscriptionId, rgName, clusterName, extensionName)

	if poller.Done() {
		result, err := poller.Result(ctx)
		if err != nil {
			return &resource.CreateResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationCreate,
					OperationStatus: resource.OperationStatusFailure,
					ErrorCode:       mapAzureErrorToOperationErrorCode(err),
				},
			}, nil
		}

		propsJSON, err := serializeExtensionProperties(result.Extension, rgName, clusterName)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize extension properties: %w", err)
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

func (e *Extension) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, clusterName, extensionName, err := parseExtensionNativeID(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := e.api.Get(ctx, rgName, aksClusterRP, aksClusterResourceName, clusterName, extensionName, nil)
	if err != nil {
		return &resource.ReadResult{
			ErrorCode: mapAzureErrorToOperationErrorCode(err),
		}, nil
	}

	propsJSON, err := serializeExtensionProperties(result.Extension, rgName, clusterName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize extension properties: %w", err)
	}

	return &resource.ReadResult{
		Properties: string(propsJSON),
	}, nil
}

func (e *Extension) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, clusterName, extensionName, err := parseExtensionNativeID(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props map[string]interface{}
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	patch := armkubernetesconfiguration.PatchExtension{
		Properties: &armkubernetesconfiguration.PatchExtensionProperties{},
	}

	if autoUpgrade, ok := props["autoUpgradeMinorVersion"].(bool); ok {
		patch.Properties.AutoUpgradeMinorVersion = to.Ptr(autoUpgrade)
	}
	if releaseTrain, ok := props["releaseTrain"].(string); ok {
		patch.Properties.ReleaseTrain = to.Ptr(releaseTrain)
	}
	if version, ok := props["version"].(string); ok {
		patch.Properties.Version = to.Ptr(version)
	}
	if settings := parseStringMap(props["configurationSettings"]); settings != nil {
		patch.Properties.ConfigurationSettings = settings
	}
	if protectedSettings := parseStringMap(props["configurationProtectedSettings"]); protectedSettings != nil {
		patch.Properties.ConfigurationProtectedSettings = protectedSettings
	}

	poller, err := e.api.BeginUpdate(ctx, rgName, aksClusterRP, aksClusterResourceName, clusterName, extensionName, patch, nil)
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
			}, nil
		}

		propsJSON, err := serializeExtensionProperties(result.Extension, rgName, clusterName)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize extension properties: %w", err)
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

func (e *Extension) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, clusterName, extensionName, err := parseExtensionNativeID(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, err := e.api.BeginDelete(ctx, rgName, aksClusterRP, aksClusterResourceName, clusterName, extensionName, nil)
	if err != nil {
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
		}, fmt.Errorf("failed to start extension deletion: %w", err)
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

func (e *Extension) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
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
		return e.statusCreate(ctx, request, &reqID)
	case "update":
		return e.statusUpdate(ctx, request, &reqID)
	case "delete":
		return e.statusDelete(ctx, request, &reqID)
	default:
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
			},
		}, fmt.Errorf("unknown operation type: %s", reqID.OperationType)
	}
}

func (e *Extension) statusCreate(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	poller, err := e.api.ResumeCreatePoller(reqID.ResumeToken)
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
		return e.handleCreateComplete(ctx, request, poller)
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
		return e.handleCreateComplete(ctx, request, poller)
	}

	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationCreate,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       request.RequestID,
			NativeID:        reqID.NativeID,
		},
	}, nil
}

func (e *Extension) handleCreateComplete(ctx context.Context, request *resource.StatusRequest, poller *runtime.Poller[armkubernetesconfiguration.ExtensionsClientCreateResponse]) (*resource.StatusResult, error) {
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
	clusterName := parts["managedclusters"]

	propsJSON, err := serializeExtensionProperties(result.Extension, rgName, clusterName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize extension properties: %w", err)
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

func (e *Extension) statusUpdate(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	poller, err := e.api.ResumeUpdatePoller(reqID.ResumeToken)
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
					ErrorCode:       mapAzureErrorToOperationErrorCode(err),
				},
			}, nil
		}
		parts := splitResourceID(*result.ID)
		rgName := parts["resourcegroups"]
		clusterName := parts["managedclusters"]
		propsJSON, err := serializeExtensionProperties(result.Extension, rgName, clusterName)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize extension properties: %w", err)
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
					ErrorCode:       mapAzureErrorToOperationErrorCode(err),
				},
			}, nil
		}
		parts := splitResourceID(*result.ID)
		rgName := parts["resourcegroups"]
		clusterName := parts["managedclusters"]
		propsJSON, err := serializeExtensionProperties(result.Extension, rgName, clusterName)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize extension properties: %w", err)
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

func (e *Extension) statusDelete(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	poller, err := e.api.ResumeDeletePoller(reqID.ResumeToken)
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
		if err != nil && !isDeleteSuccessError(err) {
			return &resource.StatusResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationDelete,
					OperationStatus: resource.OperationStatusFailure,
					RequestID:       request.RequestID,
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
				ErrorCode:       mapAzureErrorToOperationErrorCode(err),
			},
		}, nil
	}

	if poller.Done() {
		_, err := poller.Result(ctx)
		if err != nil && !isDeleteSuccessError(err) {
			return &resource.StatusResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationDelete,
					OperationStatus: resource.OperationStatusFailure,
					RequestID:       request.RequestID,
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

func (e *Extension) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	resourceGroupName, ok := request.AdditionalProperties["resourceGroupName"]
	if !ok || resourceGroupName == "" {
		return nil, fmt.Errorf("resourceGroupName is required in AdditionalProperties for listing Extensions")
	}

	clusterName, ok := request.AdditionalProperties["clusterName"]
	if !ok || clusterName == "" {
		return nil, fmt.Errorf("clusterName is required in AdditionalProperties for listing Extensions")
	}

	pager := e.api.NewListPager(resourceGroupName, aksClusterRP, aksClusterResourceName, clusterName, nil)

	var nativeIDs []string

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list extensions: %w", err)
		}

		for _, ext := range page.Value {
			if ext.ID == nil {
				continue
			}
			nativeIDs = append(nativeIDs, *ext.ID)
		}
	}

	return &resource.ListResult{
		NativeIDs: nativeIDs,
	}, nil
}

// parseExtensionNativeID extracts resourceGroupName, clusterName, and extensionName from a native ID.
func parseExtensionNativeID(nativeID string) (rgName, clusterName, extensionName string, err error) {
	parts := splitResourceID(nativeID)

	rgName, ok := parts["resourcegroups"]
	if !ok || rgName == "" {
		return "", "", "", fmt.Errorf("invalid NativeID: could not extract resource group name from %s", nativeID)
	}

	clusterName, ok = parts["managedclusters"]
	if !ok || clusterName == "" {
		return "", "", "", fmt.Errorf("invalid NativeID: could not extract cluster name from %s", nativeID)
	}

	extensionName, ok = parts["extensions"]
	if !ok || extensionName == "" {
		return "", "", "", fmt.Errorf("invalid NativeID: could not extract extension name from %s", nativeID)
	}

	return rgName, clusterName, extensionName, nil
}
