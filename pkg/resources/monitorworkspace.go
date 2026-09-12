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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/monitor/armmonitorworkspaces"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeMonitorWorkspace = "AZURE::Monitor::MonitorWorkspace"

// monitorWorkspacesAPI is the armmonitorworkspaces surface used here. The create is
// synchronous while the delete is an LRO — the same split Azure Monitor private link
// scopes have, so Status only ever handles a delete token.
type monitorWorkspacesAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName, azureMonitorWorkspaceName string, resource armmonitorworkspaces.AzureMonitorWorkspaceResource, options *armmonitorworkspaces.AzureMonitorWorkspacesClientCreateOrUpdateOptions) (armmonitorworkspaces.AzureMonitorWorkspacesClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName, azureMonitorWorkspaceName string, options *armmonitorworkspaces.AzureMonitorWorkspacesClientGetOptions) (armmonitorworkspaces.AzureMonitorWorkspacesClientGetResponse, error)
	BeginDelete(ctx context.Context, resourceGroupName, azureMonitorWorkspaceName string, options *armmonitorworkspaces.AzureMonitorWorkspacesClientBeginDeleteOptions) (*runtime.Poller[armmonitorworkspaces.AzureMonitorWorkspacesClientDeleteResponse], error)
	NewListByResourceGroupPager(resourceGroupName string, options *armmonitorworkspaces.AzureMonitorWorkspacesClientListByResourceGroupOptions) *runtime.Pager[armmonitorworkspaces.AzureMonitorWorkspacesClientListByResourceGroupResponse]
	NewListBySubscriptionPager(options *armmonitorworkspaces.AzureMonitorWorkspacesClientListBySubscriptionOptions) *runtime.Pager[armmonitorworkspaces.AzureMonitorWorkspacesClientListBySubscriptionResponse]
}

func init() {
	registry.Register(ResourceTypeMonitorWorkspace, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &MonitorWorkspace{
			api:      c.MonitorWorkspacesClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// MonitorWorkspace is the provisioner for Azure Monitor workspaces
// (Microsoft.Monitor/accounts) — the Prometheus metrics store Prometheus rule groups
// and managed Grafana read from.
//
// Despite the "Monitor" name this type does NOT live in armmonitor: it has its own
// SDK module, armmonitorworkspaces, and its own ARM namespace Microsoft.Monitor.
type MonitorWorkspace struct {
	api      monitorWorkspacesAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

// monitorWorkspaceProps mirrors schema/pkl/monitor/monitorworkspace.pkl.
type monitorWorkspaceProps struct {
	Name                string `json:"name"`
	ResourceGroupName   string `json:"resourceGroupName"`
	Location            string `json:"location"`
	PublicNetworkAccess string `json:"publicNetworkAccess"`
}

func monitorWorkspaceIDParts(resourceID string) (rgName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "accounts")
	if err != nil {
		return "", "", err
	}
	return rgName, names["accounts"], nil
}

func (m *MonitorWorkspace) buildPropertiesFromResult(workspace *armmonitorworkspaces.AzureMonitorWorkspaceResource, rgName string) map[string]any {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName

	if workspace.ID != nil {
		props["id"] = *workspace.ID
	}
	if workspace.Name != nil {
		props["name"] = *workspace.Name
	}
	if workspace.Location != nil {
		props["location"] = normalizeAzureLocation(*workspace.Location)
	}
	if tags := azureTagsToFormaeTags(workspace.Tags); len(tags) > 0 {
		props["Tags"] = tags
	}

	p := workspace.Properties
	if p == nil {
		return props
	}

	if p.PublicNetworkAccess != nil {
		props["publicNetworkAccess"] = canonicalizeEnum(string(*p.PublicNetworkAccess), "Enabled", "Disabled")
	}
	// The service assigns these; other resources address the workspace through them.
	if p.AccountID != nil {
		props["accountId"] = *p.AccountID
	}
	if p.Metrics != nil && p.Metrics.PrometheusQueryEndpoint != nil {
		props["prometheusQueryEndpoint"] = *p.Metrics.PrometheusQueryEndpoint
	}
	if s := p.DefaultIngestionSettings; s != nil {
		if s.DataCollectionEndpointResourceID != nil {
			props["defaultDataCollectionEndpointId"] = *s.DataCollectionEndpointResourceID
		}
		if s.DataCollectionRuleResourceID != nil {
			props["defaultDataCollectionRuleId"] = *s.DataCollectionRuleResourceID
		}
		if s.IngestionEndpoints != nil && s.IngestionEndpoints.Metrics != nil {
			props["metricsIngestionEndpoint"] = *s.IngestionEndpoints.Metrics
		}
	}
	// provisioningState and privateEndpointConnections are service state;
	// metrics.internalId is documented as system-only; identity and etag never belong
	// in desired state.

	return props
}

// monitorWorkspaceParams builds the request body shared by create and update.
func monitorWorkspaceParams(props monitorWorkspaceProps, payload json.RawMessage) armmonitorworkspaces.AzureMonitorWorkspaceResource {
	params := armmonitorworkspaces.AzureMonitorWorkspaceResource{
		Location:   to.Ptr(props.Location),
		Properties: &armmonitorworkspaces.AzureMonitorWorkspace{},
	}
	if props.PublicNetworkAccess != "" {
		params.Properties.PublicNetworkAccess = to.Ptr(armmonitorworkspaces.PublicNetworkAccess(props.PublicNetworkAccess))
	}
	if tags := formaeTagsToAzureTags(payload); len(tags) > 0 {
		params.Tags = tags
	}
	return params
}

func (m *MonitorWorkspace) parseProps(payload json.RawMessage, label string) (monitorWorkspaceProps, string, error) {
	var props monitorWorkspaceProps
	if err := json.Unmarshal(payload, &props); err != nil {
		return props, "", fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return props, "", fmt.Errorf("resourceGroupName is required")
	}
	if props.Location == "" {
		return props, "", fmt.Errorf("location is required")
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

func (m *MonitorWorkspace) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	props, name, err := m.parseProps(request.Properties, request.Label)
	if err != nil {
		return nil, err
	}

	result, err := m.api.CreateOrUpdate(ctx, props.ResourceGroupName, name,
		monitorWorkspaceParams(props, request.Properties), nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
				StatusMessage:   err.Error(),
			},
		}, nil
	}

	nativeID := ""
	if result.ID != nil {
		nativeID = *result.ID
	}
	propsJSON, err := json.Marshal(m.buildPropertiesFromResult(&result.AzureMonitorWorkspaceResource, props.ResourceGroupName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
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

func (m *MonitorWorkspace) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, name, err := monitorWorkspaceIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := m.api.Get(ctx, rgName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(m.buildPropertiesFromResult(&result.AzureMonitorWorkspaceResource, rgName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeMonitorWorkspace,
		Properties:   string(propsJSON),
	}, nil
}

// Update reissues CreateOrUpdate. The PATCH verb takes
// AzureMonitorWorkspaceResourceUpdate, whose properties block is the same shape, so
// a PUT is both simpler and consistent with the rest of the plugin. Location rides
// along because a PUT without it is rejected.
func (m *MonitorWorkspace) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, name, err := monitorWorkspaceIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	props, _, err := m.parseProps(request.DesiredProperties, name)
	if err != nil {
		return nil, err
	}

	result, err := m.api.CreateOrUpdate(ctx, rgName, name,
		monitorWorkspaceParams(props, request.DesiredProperties), nil)
	if err != nil {
		return &resource.UpdateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationUpdate,
				OperationStatus: resource.OperationStatusFailure,
				NativeID:        request.NativeID,
				ErrorCode:       operationErrorCode(err),
				StatusMessage:   err.Error(),
			},
		}, nil
	}

	propsJSON, err := json.Marshal(m.buildPropertiesFromResult(&result.AzureMonitorWorkspaceResource, rgName))
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

func (m *MonitorWorkspace) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, name, err := monitorWorkspaceIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, err := m.api.BeginDelete(ctx, rgName, name, nil)
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
				StatusMessage:   err.Error(),
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
					StatusMessage:   err.Error(),
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

// Status only ever sees a delete token: create and update are synchronous here, so
// they never report as in progress.
func (m *MonitorWorkspace) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	reqID, err := decodeLROStatus(request.RequestID)
	if err != nil {
		return nil, err
	}

	switch reqID.OperationType {
	case lroOpDelete:
		return statusDeleteLRO(ctx, request, &reqID,
			func(token string) (*runtime.Poller[armmonitorworkspaces.AzureMonitorWorkspacesClientDeleteResponse], error) {
				return resumePoller[armmonitorworkspaces.AzureMonitorWorkspacesClientDeleteResponse](m.pipeline, token)
			}, nil)
	case lroOpCreate, lroOpUpdate:
		// Reachable only if a stored request ID predates this handler; the writes
		// themselves never hand one out.
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusSuccess,
				RequestID:       request.RequestID,
				NativeID:        reqID.NativeID,
			},
		}, nil
	default:
		return nil, fmt.Errorf("unknown operation type: %s", reqID.OperationType)
	}
}

// List narrows to a resource group when one is given, and otherwise walks the whole
// subscription.
func (m *MonitorWorkspace) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]

	var nativeIDs []string
	if rgName != "" {
		pager := m.api.NewListByResourceGroupPager(rgName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list monitor workspaces: %w", err)
			}
			for _, workspace := range page.Value {
				if workspace != nil && workspace.ID != nil {
					nativeIDs = append(nativeIDs, *workspace.ID)
				}
			}
		}
		return &resource.ListResult{NativeIDs: nativeIDs}, nil
	}

	pager := m.api.NewListBySubscriptionPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list monitor workspaces: %w", err)
		}
		for _, workspace := range page.Value {
			if workspace != nil && workspace.ID != nil {
				nativeIDs = append(nativeIDs, *workspace.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
