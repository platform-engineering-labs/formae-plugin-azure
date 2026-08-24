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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/monitor/armmonitor"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeMonitorPrivateLinkScopedResource = "AZURE::Insights::PrivateLinkScopedResource"

// monitorPrivateLinkScopedResourcesAPI is the armmonitor surface used here. Both
// writes are LROs, and there is no separate update verb — CreateOrUpdate is it,
// though every field this schema models is createOnly anyway.
type monitorPrivateLinkScopedResourcesAPI interface {
	BeginCreateOrUpdate(ctx context.Context, resourceGroupName, scopeName, name string, parameters armmonitor.ScopedResource, options *armmonitor.PrivateLinkScopedResourcesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armmonitor.PrivateLinkScopedResourcesClientCreateOrUpdateResponse], error)
	Get(ctx context.Context, resourceGroupName, scopeName, name string, options *armmonitor.PrivateLinkScopedResourcesClientGetOptions) (armmonitor.PrivateLinkScopedResourcesClientGetResponse, error)
	BeginDelete(ctx context.Context, resourceGroupName, scopeName, name string, options *armmonitor.PrivateLinkScopedResourcesClientBeginDeleteOptions) (*runtime.Poller[armmonitor.PrivateLinkScopedResourcesClientDeleteResponse], error)
	NewListByPrivateLinkScopePager(resourceGroupName, scopeName string, options *armmonitor.PrivateLinkScopedResourcesClientListByPrivateLinkScopeOptions) *runtime.Pager[armmonitor.PrivateLinkScopedResourcesClientListByPrivateLinkScopeResponse]
}

func init() {
	registry.Register(ResourceTypeMonitorPrivateLinkScopedResource, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &MonitorPrivateLinkScopedResource{
			api:      c.MonitorPrivateLinkScopedResourcesClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// MonitorPrivateLinkScopedResource is the provisioner for scope memberships
// (Microsoft.Insights/privateLinkScopes/scopedResources). It is a child of
// AZURE::Insights::PrivateLinkScope.
type MonitorPrivateLinkScopedResource struct {
	api      monitorPrivateLinkScopedResourcesAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

// monitorPrivateLinkScopedResourceProps mirrors
// schema/pkl/insights/privatelinkscopedresource.pkl.
type monitorPrivateLinkScopedResourceProps struct {
	Name              string `json:"name"`
	ResourceGroupName string `json:"resourceGroupName"`
	ScopeName         string `json:"scopeName"`
	LinkedResourceID  string `json:"linkedResourceId"`
}

func monitorPrivateLinkScopedResourceIDParts(resourceID string) (rgName, scopeName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "privatelinkscopes", "scopedresources")
	if err != nil {
		return "", "", "", err
	}
	return rgName, names["privatelinkscopes"], names["scopedresources"], nil
}

func (m *MonitorPrivateLinkScopedResource) buildPropertiesFromResult(scoped *armmonitor.ScopedResource, rgName, scopeName string) map[string]any {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	props["scopeName"] = scopeName

	if scoped.ID != nil {
		props["id"] = *scoped.ID
	}
	if scoped.Name != nil {
		props["name"] = *scoped.Name
	}

	if p := scoped.Properties; p != nil {
		if p.LinkedResourceID != nil {
			props["linkedResourceId"] = *p.LinkedResourceID
		}
		// kind and subscriptionLocation are derived by the service from the linked
		// resource, and provisioningState is service state. None can be set, so none
		// is read back.
	}

	return props
}

func (m *MonitorPrivateLinkScopedResource) parseProps(payload json.RawMessage, label string) (monitorPrivateLinkScopedResourceProps, string, error) {
	var props monitorPrivateLinkScopedResourceProps
	if err := json.Unmarshal(payload, &props); err != nil {
		return props, "", fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return props, "", fmt.Errorf("resourceGroupName is required")
	}
	if props.ScopeName == "" {
		return props, "", fmt.Errorf("scopeName is required")
	}
	if props.LinkedResourceID == "" {
		return props, "", fmt.Errorf("linkedResourceId is required")
	}
	name := props.Name
	if name == "" {
		name = label
	}
	if name == "" {
		return props, "", fmt.Errorf("name is required")
	}
	return props, name, nil
}

func (m *MonitorPrivateLinkScopedResource) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	props, name, err := m.parseProps(request.Properties, request.Label)
	if err != nil {
		return nil, err
	}

	params := armmonitor.ScopedResource{
		Properties: &armmonitor.ScopedResourceProperties{
			LinkedResourceID: to.Ptr(props.LinkedResourceID),
		},
	}

	poller, err := m.api.BeginCreateOrUpdate(ctx, props.ResourceGroupName, props.ScopeName, name, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Insights/privateLinkScopes/%s/scopedResources/%s",
		m.config.SubscriptionId, props.ResourceGroupName, props.ScopeName, name)

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
		nativeID, propsJSON, err := m.completeFromScopedResource(&result.ScopedResource)
		if err != nil {
			return nil, err
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

func (m *MonitorPrivateLinkScopedResource) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, scopeName, name, err := monitorPrivateLinkScopedResourceIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := m.api.Get(ctx, rgName, scopeName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(m.buildPropertiesFromResult(&result.ScopedResource, rgName, scopeName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeMonitorPrivateLinkScopedResource,
		Properties:   string(propsJSON),
	}, nil
}

// Update reissues CreateOrUpdate, but ARM accepts almost nothing through it: the
// linked resource ID cannot be changed in place —
//
//	BadRequest: Cannot change the linked resource id of the resource from '<old>' to
//	'<new>'
//
// — and it is the only field this schema carries. Every field is therefore createOnly
// and core replaces the resource instead of calling this. The path is kept so a
// future mutable field (or a stored in-flight update token) still has a home.
func (m *MonitorPrivateLinkScopedResource) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, scopeName, name, err := monitorPrivateLinkScopedResourceIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	props, _, err := m.parseProps(request.DesiredProperties, name)
	if err != nil {
		return nil, err
	}

	params := armmonitor.ScopedResource{
		Properties: &armmonitor.ScopedResourceProperties{
			LinkedResourceID: to.Ptr(props.LinkedResourceID),
		},
	}

	poller, err := m.api.BeginCreateOrUpdate(ctx, rgName, scopeName, name, params, nil)
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
		propsJSON, err := json.Marshal(m.buildPropertiesFromResult(&result.ScopedResource, rgName, scopeName))
		if err != nil {
			return nil, fmt.Errorf("failed to marshal response properties: %w", err)
		}
		return &resource.UpdateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:          resource.OperationUpdate,
				OperationStatus:    resource.OperationStatusSuccess,
				NativeID:           request.NativeID,
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

func (m *MonitorPrivateLinkScopedResource) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, scopeName, name, err := monitorPrivateLinkScopedResourceIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, err := m.api.BeginDelete(ctx, rgName, scopeName, name, nil)
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
			},
		}, nil
	}

	if poller.Done() {
		if _, err := poller.Result(ctx); err != nil && !isDeleteSuccessError(err) {
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

func (m *MonitorPrivateLinkScopedResource) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	reqID, err := decodeLROStatus(request.RequestID)
	if err != nil {
		return nil, err
	}

	switch reqID.OperationType {
	case lroOpCreate, lroOpUpdate:
		// Both resume as CreateOrUpdate responses: there is no separate update verb,
		// so the poller that issued either token has the same response type.
		operation := resource.OperationCreate
		if reqID.OperationType == lroOpUpdate {
			operation = resource.OperationUpdate
		}
		return statusLRO(ctx, request, &reqID, operation,
			func(token string) (*runtime.Poller[armmonitor.PrivateLinkScopedResourcesClientCreateOrUpdateResponse], error) {
				return resumePoller[armmonitor.PrivateLinkScopedResourcesClientCreateOrUpdateResponse](m.pipeline, token)
			},
			func(_ context.Context, result armmonitor.PrivateLinkScopedResourcesClientCreateOrUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				return m.completeFromScopedResource(&result.ScopedResource)
			})
	case lroOpDelete:
		return statusDeleteLRO(ctx, request, &reqID,
			func(token string) (*runtime.Poller[armmonitor.PrivateLinkScopedResourcesClientDeleteResponse], error) {
				return resumePoller[armmonitor.PrivateLinkScopedResourcesClientDeleteResponse](m.pipeline, token)
			}, nil)
	default:
		return nil, fmt.Errorf("unknown operation type: %s", reqID.OperationType)
	}
}

func (m *MonitorPrivateLinkScopedResource) completeFromScopedResource(scoped *armmonitor.ScopedResource) (string, json.RawMessage, error) {
	nativeID := ""
	rgName := ""
	scopeName := ""
	if scoped.ID != nil {
		nativeID = *scoped.ID
		if rg, scope, _, err := monitorPrivateLinkScopedResourceIDParts(*scoped.ID); err == nil {
			rgName = rg
			scopeName = scope
		}
	}
	propsJSON, err := json.Marshal(m.buildPropertiesFromResult(scoped, rgName, scopeName))
	if err != nil {
		return "", nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return nativeID, propsJSON, nil
}

// List requires both the resource group and the scope: a membership only exists
// inside one.
func (m *MonitorPrivateLinkScopedResource) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	scopeName := request.AdditionalProperties["scopeName"]
	if rgName == "" || scopeName == "" {
		return &resource.ListResult{}, nil
	}

	var nativeIDs []string
	pager := m.api.NewListByPrivateLinkScopePager(rgName, scopeName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list scoped resources: %w", err)
		}
		for _, scoped := range page.Value {
			if scoped != nil && scoped.ID != nil {
				nativeIDs = append(nativeIDs, *scoped.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
