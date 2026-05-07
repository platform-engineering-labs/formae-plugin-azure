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

type trustedAccessRoleBindingsAPI interface {
	BeginCreateOrUpdate(ctx context.Context, resourceGroupName string, resourceName string, trustedAccessRoleBindingName string, trustedAccessRoleBinding armcontainerservice.TrustedAccessRoleBinding, options *armcontainerservice.TrustedAccessRoleBindingsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armcontainerservice.TrustedAccessRoleBindingsClientCreateOrUpdateResponse], error)
	Get(ctx context.Context, resourceGroupName string, resourceName string, trustedAccessRoleBindingName string, options *armcontainerservice.TrustedAccessRoleBindingsClientGetOptions) (armcontainerservice.TrustedAccessRoleBindingsClientGetResponse, error)
	BeginDelete(ctx context.Context, resourceGroupName string, resourceName string, trustedAccessRoleBindingName string, options *armcontainerservice.TrustedAccessRoleBindingsClientBeginDeleteOptions) (*runtime.Poller[armcontainerservice.TrustedAccessRoleBindingsClientDeleteResponse], error)
	NewListPager(resourceGroupName string, resourceName string, options *armcontainerservice.TrustedAccessRoleBindingsClientListOptions) *runtime.Pager[armcontainerservice.TrustedAccessRoleBindingsClientListResponse]
}

func init() {
	registry.Register(ResourceTypeTrustedAccessRoleBinding, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &TrustedAccessRoleBinding{
			api:      c.TrustedAccessRoleBindingsClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

type TrustedAccessRoleBinding struct {
	api      trustedAccessRoleBindingsAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

func serializeTrustedAccessRoleBindingProperties(result armcontainerservice.TrustedAccessRoleBinding, rgName, clusterName string) (json.RawMessage, error) {
	props := make(map[string]any)

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
	var props map[string]any
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
	if rolesRaw, ok := props["roles"].([]any); ok {
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

	poller, err := t.api.BeginCreateOrUpdate(ctx, rgName, clusterName, bindingName, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.ContainerService/managedClusters/%s/trustedAccessRoleBindings/%s",
		t.config.SubscriptionId, rgName, clusterName, bindingName)

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

func (t *TrustedAccessRoleBinding) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, clusterName, bindingName, err := parseTrustedAccessRoleBindingNativeID(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := t.api.Get(ctx, rgName, clusterName, bindingName, nil)
	if err != nil {
		return &resource.ReadResult{
			ErrorCode: operationErrorCode(err),
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

	var props map[string]any
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	sourceResourceID, ok := props["sourceResourceId"].(string)
	if !ok || sourceResourceID == "" {
		return nil, fmt.Errorf("sourceResourceId is required")
	}

	var roles []*string
	if rolesRaw, ok := props["roles"].([]any); ok {
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

	poller, err := t.api.BeginCreateOrUpdate(ctx, rgName, clusterName, bindingName, params, nil)
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

func (t *TrustedAccessRoleBinding) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, clusterName, bindingName, err := parseTrustedAccessRoleBindingNativeID(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, err := t.api.BeginDelete(ctx, rgName, clusterName, bindingName, nil)
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
		}, fmt.Errorf("failed to start trusted access role binding deletion: %w", err)
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

func (t *TrustedAccessRoleBinding) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
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
	case lroOpCreate, lroOpUpdate:
		return t.statusCreateOrUpdate(ctx, request, &reqID)
	case lroOpDelete:
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
	if reqID.OperationType == lroOpUpdate {
		operation = resource.OperationUpdate
	}
	return statusLRO(ctx, request, reqID, operation,
		func(token string) (*runtime.Poller[armcontainerservice.TrustedAccessRoleBindingsClientCreateOrUpdateResponse], error) {
			return resumePoller[armcontainerservice.TrustedAccessRoleBindingsClientCreateOrUpdateResponse](t.pipeline, token)
		},
		func(_ context.Context, result armcontainerservice.TrustedAccessRoleBindingsClientCreateOrUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
			rgName, clusterName, _, err := parseTrustedAccessRoleBindingNativeID(*result.ID)
			if err != nil {
				return "", nil, err
			}
			propsJSON, err := serializeTrustedAccessRoleBindingProperties(result.TrustedAccessRoleBinding, rgName, clusterName)
			if err != nil {
				return "", nil, fmt.Errorf("failed to serialize trusted access role binding properties: %w", err)
			}
			return *result.ID, propsJSON, nil
		})
}

func (t *TrustedAccessRoleBinding) statusDelete(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	return statusDeleteLRO(ctx, request, reqID,
		func(token string) (*runtime.Poller[armcontainerservice.TrustedAccessRoleBindingsClientDeleteResponse], error) {
			return resumePoller[armcontainerservice.TrustedAccessRoleBindingsClientDeleteResponse](t.pipeline, token)
		}, nil)
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

	pager := t.api.NewListPager(resourceGroupName, clusterName, nil)

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
	rgName, names, err := armIDParts(nativeID, "managedclusters", "trustedaccessrolebindings")
	if err != nil {
		return "", "", "", err
	}
	return rgName, names["managedclusters"], names["trustedaccessrolebindings"], nil
}
