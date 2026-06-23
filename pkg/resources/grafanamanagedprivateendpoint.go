// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/dashboard/armdashboard"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeGrafanaManagedPrivateEndpoint = "AZURE::Dashboard::GrafanaManagedPrivateEndpoint"

type grafanaManagedPrivateEndpointsAPI interface {
	BeginCreate(ctx context.Context, resourceGroupName string, workspaceName string, managedPrivateEndpointName string, requestBodyParameters armdashboard.ManagedPrivateEndpointModel, options *armdashboard.ManagedPrivateEndpointsClientBeginCreateOptions) (*runtime.Poller[armdashboard.ManagedPrivateEndpointsClientCreateResponse], error)
	Get(ctx context.Context, resourceGroupName string, workspaceName string, managedPrivateEndpointName string, options *armdashboard.ManagedPrivateEndpointsClientGetOptions) (armdashboard.ManagedPrivateEndpointsClientGetResponse, error)
	BeginUpdate(ctx context.Context, resourceGroupName string, workspaceName string, managedPrivateEndpointName string, requestBodyParameters armdashboard.ManagedPrivateEndpointUpdateParameters, options *armdashboard.ManagedPrivateEndpointsClientBeginUpdateOptions) (*runtime.Poller[armdashboard.ManagedPrivateEndpointsClientUpdateResponse], error)
	BeginDelete(ctx context.Context, resourceGroupName string, workspaceName string, managedPrivateEndpointName string, options *armdashboard.ManagedPrivateEndpointsClientBeginDeleteOptions) (*runtime.Poller[armdashboard.ManagedPrivateEndpointsClientDeleteResponse], error)
	NewListPager(resourceGroupName string, workspaceName string, options *armdashboard.ManagedPrivateEndpointsClientListOptions) *runtime.Pager[armdashboard.ManagedPrivateEndpointsClientListResponse]
}

func init() {
	registry.Register(ResourceTypeGrafanaManagedPrivateEndpoint, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &GrafanaManagedPrivateEndpoint{
			api:      c.GrafanaManagedPrivateEndpointsClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// GrafanaManagedPrivateEndpoint is the provisioner for Azure Grafana managed private endpoints.
type GrafanaManagedPrivateEndpoint struct {
	api      grafanaManagedPrivateEndpointsAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

func grafanaManagedPrivateEndpointIDParts(resourceID string) (rgName, workspaceName, mpeName string, err error) {
	rgName, names, err := armIDParts(resourceID, "grafana", "managedprivateendpoints")
	if err != nil {
		return "", "", "", err
	}
	return rgName, names["grafana"], names["managedprivateendpoints"], nil
}

func serializeGrafanaManagedPrivateEndpointProperties(result armdashboard.ManagedPrivateEndpointModel, rgName, workspaceName, mpeName string) (json.RawMessage, error) {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	props["workspaceName"] = workspaceName
	if result.Name != nil {
		props["name"] = *result.Name
	} else {
		props["name"] = mpeName
	}

	if result.Location != nil {
		props["location"] = *result.Location
	}

	if result.Properties != nil {
		if result.Properties.PrivateLinkResourceID != nil {
			props["privateLinkResourceId"] = *result.Properties.PrivateLinkResourceID
		}
		if result.Properties.PrivateLinkResourceRegion != nil {
			props["privateLinkResourceRegion"] = *result.Properties.PrivateLinkResourceRegion
		}
		if result.Properties.RequestMessage != nil {
			props["requestMessage"] = *result.Properties.RequestMessage
		}
		if len(result.Properties.GroupIDs) > 0 {
			groupIDs := make([]string, 0, len(result.Properties.GroupIDs))
			for _, g := range result.Properties.GroupIDs {
				if g != nil {
					groupIDs = append(groupIDs, *g)
				}
			}
			props["groupIds"] = groupIDs
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

func (g *GrafanaManagedPrivateEndpoint) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props map[string]any
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	rgName, ok := props["resourceGroupName"].(string)
	if !ok || rgName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}

	workspaceName, ok := props["workspaceName"].(string)
	if !ok || workspaceName == "" {
		return nil, fmt.Errorf("workspaceName is required")
	}

	mpeName, ok := props["name"].(string)
	if !ok || mpeName == "" {
		mpeName = request.Label
	}

	location, ok := props["location"].(string)
	if !ok || location == "" {
		return nil, fmt.Errorf("location is required")
	}

	privateLinkResourceID, ok := props["privateLinkResourceId"].(string)
	if !ok || privateLinkResourceID == "" {
		return nil, fmt.Errorf("privateLinkResourceId is required")
	}

	params := armdashboard.ManagedPrivateEndpointModel{
		Location: stringPtr(location),
		Properties: &armdashboard.ManagedPrivateEndpointModelProperties{
			PrivateLinkResourceID: stringPtr(privateLinkResourceID),
		},
	}

	if region, ok := props["privateLinkResourceRegion"].(string); ok && region != "" {
		params.Properties.PrivateLinkResourceRegion = stringPtr(region)
	}
	if msg, ok := props["requestMessage"].(string); ok && msg != "" {
		params.Properties.RequestMessage = stringPtr(msg)
	}
	if raw, ok := props["groupIds"].([]any); ok {
		groupIDs := make([]*string, 0, len(raw))
		for _, v := range raw {
			if s, ok := v.(string); ok {
				groupIDs = append(groupIDs, stringPtr(s))
			}
		}
		if len(groupIDs) > 0 {
			params.Properties.GroupIDs = groupIDs
		}
	}

	if azureTags := formaeTagsToAzureTags(request.Properties); azureTags != nil {
		params.Tags = azureTags
	}

	poller, err := g.api.BeginCreate(ctx, rgName, workspaceName, mpeName, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Dashboard/grafana/%s/managedPrivateEndpoints/%s",
		g.config.SubscriptionId, rgName, workspaceName, mpeName)

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

		propsJSON, err := serializeGrafanaManagedPrivateEndpointProperties(result.ManagedPrivateEndpointModel, rgName, workspaceName, mpeName)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize Grafana managed private endpoint properties: %w", err)
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

func (g *GrafanaManagedPrivateEndpoint) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, workspaceName, mpeName, err := grafanaManagedPrivateEndpointIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := g.api.Get(ctx, rgName, workspaceName, mpeName, nil)
	if err != nil {
		return &resource.ReadResult{
			ErrorCode: operationErrorCode(err),
		}, nil
	}

	propsJSON, err := serializeGrafanaManagedPrivateEndpointProperties(result.ManagedPrivateEndpointModel, rgName, workspaceName, mpeName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize Grafana managed private endpoint properties: %w", err)
	}

	return &resource.ReadResult{
		ResourceType: ResourceTypeGrafanaManagedPrivateEndpoint,
		Properties:   string(propsJSON),
	}, nil
}

func (g *GrafanaManagedPrivateEndpoint) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, workspaceName, mpeName, err := grafanaManagedPrivateEndpointIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	params := armdashboard.ManagedPrivateEndpointUpdateParameters{}
	if azureTags := formaeTagsToAzureTags(request.DesiredProperties); azureTags != nil {
		params.Tags = azureTags
	}

	poller, err := g.api.BeginUpdate(ctx, rgName, workspaceName, mpeName, params, nil)
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

		propsJSON, err := serializeGrafanaManagedPrivateEndpointProperties(result.ManagedPrivateEndpointModel, rgName, workspaceName, mpeName)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize Grafana managed private endpoint properties: %w", err)
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

func (g *GrafanaManagedPrivateEndpoint) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, workspaceName, mpeName, err := grafanaManagedPrivateEndpointIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, err := g.api.BeginDelete(ctx, rgName, workspaceName, mpeName, nil)
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
		}, fmt.Errorf("failed to start Grafana managed private endpoint deletion: %w", err)
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

func (g *GrafanaManagedPrivateEndpoint) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
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
	case lroOpUpdate:
		return g.statusUpdate(ctx, request, &reqID)
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

func (g *GrafanaManagedPrivateEndpoint) statusCreate(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	return statusLRO(ctx, request, reqID, resource.OperationCreate,
		func(token string) (*runtime.Poller[armdashboard.ManagedPrivateEndpointsClientCreateResponse], error) {
			return resumePoller[armdashboard.ManagedPrivateEndpointsClientCreateResponse](g.pipeline, token)
		},
		func(_ context.Context, result armdashboard.ManagedPrivateEndpointsClientCreateResponse, _ resource.Operation) (string, json.RawMessage, error) {
			rgName, workspaceName, mpeName, err := grafanaManagedPrivateEndpointIDParts(*result.ID)
			if err != nil {
				return "", nil, err
			}
			propsJSON, err := serializeGrafanaManagedPrivateEndpointProperties(result.ManagedPrivateEndpointModel, rgName, workspaceName, mpeName)
			if err != nil {
				return "", nil, fmt.Errorf("failed to serialize Grafana managed private endpoint properties: %w", err)
			}
			return *result.ID, propsJSON, nil
		})
}

func (g *GrafanaManagedPrivateEndpoint) statusUpdate(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	return statusLRO(ctx, request, reqID, resource.OperationUpdate,
		func(token string) (*runtime.Poller[armdashboard.ManagedPrivateEndpointsClientUpdateResponse], error) {
			return resumePoller[armdashboard.ManagedPrivateEndpointsClientUpdateResponse](g.pipeline, token)
		},
		func(_ context.Context, result armdashboard.ManagedPrivateEndpointsClientUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
			rgName, workspaceName, mpeName, err := grafanaManagedPrivateEndpointIDParts(*result.ID)
			if err != nil {
				return "", nil, err
			}
			propsJSON, err := serializeGrafanaManagedPrivateEndpointProperties(result.ManagedPrivateEndpointModel, rgName, workspaceName, mpeName)
			if err != nil {
				return "", nil, fmt.Errorf("failed to serialize Grafana managed private endpoint properties: %w", err)
			}
			return *result.ID, propsJSON, nil
		})
}

func (g *GrafanaManagedPrivateEndpoint) statusDelete(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	return statusDeleteLRO(ctx, request, reqID,
		func(token string) (*runtime.Poller[armdashboard.ManagedPrivateEndpointsClientDeleteResponse], error) {
			return resumePoller[armdashboard.ManagedPrivateEndpointsClientDeleteResponse](g.pipeline, token)
		}, nil)
}

func (g *GrafanaManagedPrivateEndpoint) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	workspaceName := request.AdditionalProperties["workspaceName"]

	if rgName == "" || workspaceName == "" {
		return &resource.ListResult{}, nil
	}

	var nativeIDs []string
	pager := g.api.NewListPager(rgName, workspaceName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list Grafana managed private endpoints: %w", err)
		}
		for _, mpe := range page.Value {
			if mpe.ID != nil {
				nativeIDs = append(nativeIDs, *mpe.ID)
			}
		}
	}

	return &resource.ListResult{
		NativeIDs: nativeIDs,
	}, nil
}
