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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/dashboard/armdashboard"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeGrafana = "AZURE::Dashboard::Grafana"

type grafanaAPI interface {
	BeginCreate(ctx context.Context, resourceGroupName string, workspaceName string, requestBodyParameters armdashboard.ManagedGrafana, options *armdashboard.GrafanaClientBeginCreateOptions) (*runtime.Poller[armdashboard.GrafanaClientCreateResponse], error)
	Get(ctx context.Context, resourceGroupName string, workspaceName string, options *armdashboard.GrafanaClientGetOptions) (armdashboard.GrafanaClientGetResponse, error)
	Update(ctx context.Context, resourceGroupName string, workspaceName string, requestBodyParameters armdashboard.ManagedGrafanaUpdateParameters, options *armdashboard.GrafanaClientUpdateOptions) (armdashboard.GrafanaClientUpdateResponse, error)
	BeginDelete(ctx context.Context, resourceGroupName string, workspaceName string, options *armdashboard.GrafanaClientBeginDeleteOptions) (*runtime.Poller[armdashboard.GrafanaClientDeleteResponse], error)
	NewListByResourceGroupPager(resourceGroupName string, options *armdashboard.GrafanaClientListByResourceGroupOptions) *runtime.Pager[armdashboard.GrafanaClientListByResourceGroupResponse]
	NewListPager(options *armdashboard.GrafanaClientListOptions) *runtime.Pager[armdashboard.GrafanaClientListResponse]
}

func init() {
	registry.Register(ResourceTypeGrafana, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &Grafana{
			api:      c.GrafanaClient,
			config:   cfg,
			pipeline: c.Pipeline(),
		}
	})
}

// Grafana is the provisioner for Azure Managed Grafana workspaces.
type Grafana struct {
	api      grafanaAPI
	config   *config.Config
	pipeline runtime.Pipeline
}

func grafanaIDParts(resourceID string) (rgName, workspaceName string, err error) {
	rgName, names, err := armIDParts(resourceID, "grafana")
	if err != nil {
		return "", "", err
	}
	return rgName, names["grafana"], nil
}

func serializeGrafanaProperties(result armdashboard.ManagedGrafana, rgName, workspaceName string) (json.RawMessage, error) {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	if result.Name != nil {
		props["name"] = *result.Name
	} else {
		props["name"] = workspaceName
	}

	if result.Location != nil {
		props["location"] = *result.Location
	}

	if result.SKU != nil && result.SKU.Name != nil {
		props["sku"] = map[string]any{"name": *result.SKU.Name}
	}

	if result.Identity != nil && result.Identity.Type != nil {
		props["identity"] = map[string]any{"type": string(*result.Identity.Type)}
	}

	if result.Properties != nil {
		if result.Properties.APIKey != nil {
			props["apiKey"] = string(*result.Properties.APIKey)
		}
		if result.Properties.PublicNetworkAccess != nil {
			props["publicNetworkAccess"] = string(*result.Properties.PublicNetworkAccess)
		}
		if result.Properties.Endpoint != nil {
			props["endpoint"] = *result.Properties.Endpoint
		}
		if result.Properties.GrafanaVersion != nil {
			props["grafanaVersion"] = *result.Properties.GrafanaVersion
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

func grafanaParamsFromProps(props map[string]any) armdashboard.ManagedGrafana {
	params := armdashboard.ManagedGrafana{
		Properties: &armdashboard.ManagedGrafanaProperties{},
	}

	if location, ok := props["location"].(string); ok {
		params.Location = stringPtr(location)
	}

	if skuRaw, ok := props["sku"].(map[string]any); ok {
		if name, ok := skuRaw["name"].(string); ok {
			params.SKU = &armdashboard.ResourceSKU{Name: stringPtr(name)}
		}
	}

	if identityRaw, ok := props["identity"].(map[string]any); ok {
		if idType, ok := identityRaw["type"].(string); ok {
			params.Identity = &armdashboard.ManagedServiceIdentity{
				Type: to.Ptr(armdashboard.ManagedServiceIdentityType(idType)),
			}
		}
	}

	if apiKey, ok := props["apiKey"].(string); ok {
		params.Properties.APIKey = to.Ptr(armdashboard.APIKey(apiKey))
	}

	if publicAccess, ok := props["publicNetworkAccess"].(string); ok {
		params.Properties.PublicNetworkAccess = to.Ptr(armdashboard.PublicNetworkAccess(publicAccess))
	}

	return params
}

func (g *Grafana) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
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

	workspaceName, ok := props["name"].(string)
	if !ok || workspaceName == "" {
		workspaceName = request.Label
	}

	params := grafanaParamsFromProps(props)
	if azureTags := formaeTagsToAzureTags(request.Properties); azureTags != nil {
		params.Tags = azureTags
	}

	poller, err := g.api.BeginCreate(ctx, rgName, workspaceName, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Dashboard/grafana/%s",
		g.config.SubscriptionId, rgName, workspaceName)

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

		propsJSON, err := serializeGrafanaProperties(result.ManagedGrafana, rgName, workspaceName)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize Grafana properties: %w", err)
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

func (g *Grafana) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, workspaceName, err := grafanaIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := g.api.Get(ctx, rgName, workspaceName, nil)
	if err != nil {
		return &resource.ReadResult{
			ErrorCode: operationErrorCode(err),
		}, nil
	}

	propsJSON, err := serializeGrafanaProperties(result.ManagedGrafana, rgName, workspaceName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize Grafana properties: %w", err)
	}

	return &resource.ReadResult{
		ResourceType: ResourceTypeGrafana,
		Properties:   string(propsJSON),
	}, nil
}

func (g *Grafana) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, workspaceName, err := grafanaIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props map[string]any
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	params := armdashboard.ManagedGrafanaUpdateParameters{
		Properties: &armdashboard.ManagedGrafanaPropertiesUpdateParameters{},
	}

	if skuRaw, ok := props["sku"].(map[string]any); ok {
		if name, ok := skuRaw["name"].(string); ok {
			params.SKU = &armdashboard.ResourceSKU{Name: stringPtr(name)}
		}
	}

	if identityRaw, ok := props["identity"].(map[string]any); ok {
		if idType, ok := identityRaw["type"].(string); ok {
			params.Identity = &armdashboard.ManagedServiceIdentity{
				Type: to.Ptr(armdashboard.ManagedServiceIdentityType(idType)),
			}
		}
	}

	if apiKey, ok := props["apiKey"].(string); ok {
		params.Properties.APIKey = to.Ptr(armdashboard.APIKey(apiKey))
	}

	if publicAccess, ok := props["publicNetworkAccess"].(string); ok {
		params.Properties.PublicNetworkAccess = to.Ptr(armdashboard.PublicNetworkAccess(publicAccess))
	}

	if azureTags := formaeTagsToAzureTags(request.DesiredProperties); azureTags != nil {
		params.Tags = azureTags
	}

	// Grafana update is synchronous in the SDK (PATCH).
	result, err := g.api.Update(ctx, rgName, workspaceName, params, nil)
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

	propsJSON, err := serializeGrafanaProperties(result.ManagedGrafana, rgName, workspaceName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize Grafana properties: %w", err)
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

func (g *Grafana) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, workspaceName, err := grafanaIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, err := g.api.BeginDelete(ctx, rgName, workspaceName, nil)
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
		}, fmt.Errorf("failed to start Grafana deletion: %w", err)
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
			}, fmt.Errorf("failed to get Grafana delete result: %w", err)
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

func (g *Grafana) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
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
		return g.statusCreate(ctx, request, &reqID)
	case lroOpDelete:
		return g.statusDelete(ctx, request, &reqID)
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

func (g *Grafana) statusCreate(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	return statusLRO(ctx, request, reqID, resource.OperationCreate,
		func(token string) (*runtime.Poller[armdashboard.GrafanaClientCreateResponse], error) {
			return resumePoller[armdashboard.GrafanaClientCreateResponse](g.pipeline, token)
		},
		func(_ context.Context, result armdashboard.GrafanaClientCreateResponse, _ resource.Operation) (string, json.RawMessage, error) {
			rgName, workspaceName, err := grafanaIDParts(*result.ID)
			if err != nil {
				return "", nil, err
			}
			propsJSON, err := serializeGrafanaProperties(result.ManagedGrafana, rgName, workspaceName)
			if err != nil {
				return "", nil, fmt.Errorf("failed to serialize Grafana properties: %w", err)
			}
			return *result.ID, propsJSON, nil
		})
}

func (g *Grafana) statusDelete(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	return statusDeleteLRO(ctx, request, reqID,
		func(token string) (*runtime.Poller[armdashboard.GrafanaClientDeleteResponse], error) {
			return resumePoller[armdashboard.GrafanaClientDeleteResponse](g.pipeline, token)
		}, nil)
}

func (g *Grafana) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]

	var nativeIDs []string

	if rgName != "" {
		pager := g.api.NewListByResourceGroupPager(rgName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list Grafana workspaces: %w", err)
			}
			for _, workspace := range page.Value {
				if workspace.ID != nil {
					nativeIDs = append(nativeIDs, *workspace.ID)
				}
			}
		}
	} else {
		pager := g.api.NewListPager(nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list Grafana workspaces: %w", err)
			}
			for _, workspace := range page.Value {
				if workspace.ID != nil {
					nativeIDs = append(nativeIDs, *workspace.ID)
				}
			}
		}
	}

	return &resource.ListResult{
		NativeIDs: nativeIDs,
	}, nil
}
