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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerservice/armcontainerservice/v4"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeTrustedAccessRoleBinding = "Azure::ContainerService::TrustedAccessRoleBinding"

func init() {
	registry.Register(ResourceTypeTrustedAccessRoleBinding, func(client *client.Client, cfg *config.Config) prov.Provisioner {
		return &TrustedAccessRoleBinding{client, cfg}
	})
}

type TrustedAccessRoleBinding struct {
	Client *client.Client
	Config *config.Config
}

func serializeTrustedAccessRoleBindingProperties(result armcontainerservice.TrustedAccessRoleBinding, rgName, clusterName string) (json.RawMessage, error) {
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
		if result.Properties.SourceResourceID != nil {
			props["sourceResourceId"] = *result.Properties.SourceResourceID
		}
		if result.Properties.Roles != nil {
			roles := make([]string, 0, len(result.Properties.Roles))
			for _, r := range result.Properties.Roles {
				if r != nil {
					roles = append(roles, *r)
				}
			}
			props["roles"] = roles
		}
	}

	return json.Marshal(props)
}

func (t *TrustedAccessRoleBinding) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
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

	bindingName, ok := props["name"].(string)
	if !ok || bindingName == "" {
		bindingName = request.Label
	}

	sourceResourceID, ok := props["sourceResourceId"].(string)
	if !ok || sourceResourceID == "" {
		return nil, fmt.Errorf("sourceResourceId is required")
	}

	var roles []*string
	if rolesRaw, ok := props["roles"].([]interface{}); ok {
		for _, r := range rolesRaw {
			if s, ok := r.(string); ok {
				roles = append(roles, to.Ptr(s))
			}
		}
	}

	params := armcontainerservice.TrustedAccessRoleBinding{
		Properties: &armcontainerservice.TrustedAccessRoleBindingProperties{
			SourceResourceID: to.Ptr(sourceResourceID),
			Roles:            roles,
		},
	}

	poller, err := t.Client.TrustedAccessRoleBindingsClient.BeginCreateOrUpdate(ctx, rgName, clusterName, bindingName, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       mapAzureErrorToOperationErrorCode(err),
			},
		}, nil
	}

	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.ContainerService/managedClusters/%s/trustedAccessRoleBindings/%s",
		t.Config.SubscriptionId, rgName, clusterName, bindingName)

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

		propsJSON, err := serializeTrustedAccessRoleBindingProperties(result.TrustedAccessRoleBinding, rgName, clusterName)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize trusted access role binding properties: %w", err)
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

func (t *TrustedAccessRoleBinding) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, clusterName, bindingName, err := parseTrustedAccessRoleBindingNativeID(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := t.Client.TrustedAccessRoleBindingsClient.Get(ctx, rgName, clusterName, bindingName, nil)
	if err != nil {
		return &resource.ReadResult{
			ErrorCode: mapAzureErrorToOperationErrorCode(err),
		}, nil
	}

	propsJSON, err := serializeTrustedAccessRoleBindingProperties(result.TrustedAccessRoleBinding, rgName, clusterName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize trusted access role binding properties: %w", err)
	}

	return &resource.ReadResult{
		Properties: string(propsJSON),
	}, nil
}

func (t *TrustedAccessRoleBinding) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, clusterName, bindingName, err := parseTrustedAccessRoleBindingNativeID(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props map[string]interface{}
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	sourceResourceID, ok := props["sourceResourceId"].(string)
	if !ok || sourceResourceID == "" {
		return nil, fmt.Errorf("sourceResourceId is required")
	}

	var roles []*string
	if rolesRaw, ok := props["roles"].([]interface{}); ok {
		for _, r := range rolesRaw {
			if s, ok := r.(string); ok {
				roles = append(roles, to.Ptr(s))
			}
		}
	}

	params := armcontainerservice.TrustedAccessRoleBinding{
		Properties: &armcontainerservice.TrustedAccessRoleBindingProperties{
			SourceResourceID: to.Ptr(sourceResourceID),
			Roles:            roles,
		},
	}

	poller, err := t.Client.TrustedAccessRoleBindingsClient.BeginCreateOrUpdate(ctx, rgName, clusterName, bindingName, params, nil)
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

		propsJSON, err := serializeTrustedAccessRoleBindingProperties(result.TrustedAccessRoleBinding, rgName, clusterName)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize trusted access role binding properties: %w", err)
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

func (t *TrustedAccessRoleBinding) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, clusterName, bindingName, err := parseTrustedAccessRoleBindingNativeID(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, err := t.Client.TrustedAccessRoleBindingsClient.BeginDelete(ctx, rgName, clusterName, bindingName, nil)
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
		}, fmt.Errorf("failed to start trusted access role binding deletion: %w", err)
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

func (t *TrustedAccessRoleBinding) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
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
	case "create", "update":
		return t.statusCreateOrUpdate(ctx, request, &reqID)
	case "delete":
		return t.statusDelete(ctx, request, &reqID)
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

func (t *TrustedAccessRoleBinding) statusCreateOrUpdate(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	operation := resource.OperationCreate
	if reqID.OperationType == "update" {
		operation = resource.OperationUpdate
	}

	poller, err := t.Client.ResumeCreateTrustedAccessRoleBindingPoller(reqID.ResumeToken)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       operation,
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
			},
		}, fmt.Errorf("failed to resume poller: %w", err)
	}

	if poller.Done() {
		return t.handleCreateOrUpdateComplete(ctx, request, poller, operation)
	}

	_, err = poller.Poll(ctx)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       operation,
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       mapAzureErrorToOperationErrorCode(err),
			},
		}, nil
	}

	if poller.Done() {
		return t.handleCreateOrUpdateComplete(ctx, request, poller, operation)
	}

	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       operation,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       request.RequestID,
			NativeID:        reqID.NativeID,
		},
	}, nil
}

func (t *TrustedAccessRoleBinding) handleCreateOrUpdateComplete(ctx context.Context, request *resource.StatusRequest, poller *runtime.Poller[armcontainerservice.TrustedAccessRoleBindingsClientCreateOrUpdateResponse], operation resource.Operation) (*resource.StatusResult, error) {
	result, err := poller.Result(ctx)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       operation,
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       mapAzureErrorToOperationErrorCode(err),
			},
		}, nil
	}

	parts := splitResourceID(*result.ID)
	rgName := parts["resourcegroups"]
	clusterName := parts["managedclusters"]

	propsJSON, err := serializeTrustedAccessRoleBindingProperties(result.TrustedAccessRoleBinding, rgName, clusterName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize trusted access role binding properties: %w", err)
	}

	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			Operation:          operation,
			OperationStatus:    resource.OperationStatusSuccess,
			RequestID:          request.RequestID,
			NativeID:           *result.ID,
			ResourceProperties: propsJSON,
		},
	}, nil
}

func (t *TrustedAccessRoleBinding) statusDelete(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	poller, err := t.Client.ResumeDeleteTrustedAccessRoleBindingPoller(reqID.ResumeToken)
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

func (t *TrustedAccessRoleBinding) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	resourceGroupName, ok := request.AdditionalProperties["resourceGroupName"]
	if !ok || resourceGroupName == "" {
		return nil, fmt.Errorf("resourceGroupName is required in AdditionalProperties for listing TrustedAccessRoleBindings")
	}

	clusterName, ok := request.AdditionalProperties["clusterName"]
	if !ok || clusterName == "" {
		return nil, fmt.Errorf("clusterName is required in AdditionalProperties for listing TrustedAccessRoleBindings")
	}

	pager := t.Client.TrustedAccessRoleBindingsClient.NewListPager(resourceGroupName, clusterName, nil)

	var nativeIDs []string

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list trusted access role bindings: %w", err)
		}

		for _, binding := range page.Value {
			if binding.ID == nil {
				continue
			}
			nativeIDs = append(nativeIDs, *binding.ID)
		}
	}

	return &resource.ListResult{
		NativeIDs: nativeIDs,
	}, nil
}

func parseTrustedAccessRoleBindingNativeID(nativeID string) (rgName, clusterName, bindingName string, err error) {
	parts := splitResourceID(nativeID)

	rgName, ok := parts["resourcegroups"]
	if !ok || rgName == "" {
		return "", "", "", fmt.Errorf("invalid NativeID: could not extract resource group name from %s", nativeID)
	}

	clusterName, ok = parts["managedclusters"]
	if !ok || clusterName == "" {
		return "", "", "", fmt.Errorf("invalid NativeID: could not extract cluster name from %s", nativeID)
	}

	bindingName, ok = parts["trustedaccessrolebindings"]
	if !ok || bindingName == "" {
		return "", "", "", fmt.Errorf("invalid NativeID: could not extract trusted access role binding name from %s", nativeID)
	}

	return rgName, clusterName, bindingName, nil
}
