// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/operationalinsights/armoperationalinsights"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeLogAnalyticsWorkspace = "AZURE::OperationalInsights::Workspace"

// logAnalyticsWorkspacesAPI is the armoperationalinsights surface used here.
// Create and Delete are LROs; Update is synchronous (a plain PATCH).
type logAnalyticsWorkspacesAPI interface {
	BeginCreateOrUpdate(ctx context.Context, resourceGroupName string, workspaceName string, parameters armoperationalinsights.Workspace, options *armoperationalinsights.WorkspacesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armoperationalinsights.WorkspacesClientCreateOrUpdateResponse], error)
	Get(ctx context.Context, resourceGroupName string, workspaceName string, options *armoperationalinsights.WorkspacesClientGetOptions) (armoperationalinsights.WorkspacesClientGetResponse, error)
	Update(ctx context.Context, resourceGroupName string, workspaceName string, parameters armoperationalinsights.WorkspacePatch, options *armoperationalinsights.WorkspacesClientUpdateOptions) (armoperationalinsights.WorkspacesClientUpdateResponse, error)
	BeginDelete(ctx context.Context, resourceGroupName string, workspaceName string, options *armoperationalinsights.WorkspacesClientBeginDeleteOptions) (*runtime.Poller[armoperationalinsights.WorkspacesClientDeleteResponse], error)
	NewListPager(options *armoperationalinsights.WorkspacesClientListOptions) *runtime.Pager[armoperationalinsights.WorkspacesClientListResponse]
	NewListByResourceGroupPager(resourceGroupName string, options *armoperationalinsights.WorkspacesClientListByResourceGroupOptions) *runtime.Pager[armoperationalinsights.WorkspacesClientListByResourceGroupResponse]
}

func init() {
	registry.Register(ResourceTypeLogAnalyticsWorkspace, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &LogAnalyticsWorkspace{
			api:      c.LogAnalyticsWorkspacesClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// LogAnalyticsWorkspace is the provisioner for Log Analytics workspaces
// (Microsoft.OperationalInsights/workspaces).
//
// The workspace shared keys are deliberately never serialized: ARM returns them
// only from a separate SharedKeys call, so putting them in resource state would
// persist live credentials.
type LogAnalyticsWorkspace struct {
	api      logAnalyticsWorkspacesAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

func logAnalyticsWorkspaceIDParts(resourceID string) (rgName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "workspaces")
	if err != nil {
		return "", "", err
	}
	return rgName, names["workspaces"], nil
}

func (w *LogAnalyticsWorkspace) buildPropertiesFromResult(ws *armoperationalinsights.Workspace, rgName string) map[string]any {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName

	if ws.ID != nil {
		props["id"] = *ws.ID
	}
	if ws.Name != nil {
		props["name"] = *ws.Name
	}
	if ws.Location != nil {
		props["location"] = strings.ToLower(strings.ReplaceAll(*ws.Location, " ", ""))
	}

	if ws.Properties != nil {
		if sku := ws.Properties.SKU; sku != nil && sku.Name != nil {
			s := map[string]any{"name": string(*sku.Name)}
			if sku.CapacityReservationLevel != nil {
				s["capacityReservationLevel"] = int32(*sku.CapacityReservationLevel)
			}
			props["sku"] = s
		}
		if ws.Properties.RetentionInDays != nil {
			props["retentionInDays"] = *ws.Properties.RetentionInDays
		}
		if capping := ws.Properties.WorkspaceCapping; capping != nil && capping.DailyQuotaGb != nil {
			props["dailyQuotaGb"] = *capping.DailyQuotaGb
		}
		if ws.Properties.PublicNetworkAccessForIngestion != nil {
			props["publicNetworkAccessForIngestion"] = string(*ws.Properties.PublicNetworkAccessForIngestion)
		}
		if ws.Properties.PublicNetworkAccessForQuery != nil {
			props["publicNetworkAccessForQuery"] = string(*ws.Properties.PublicNetworkAccessForQuery)
		}
		if ws.Properties.CustomerID != nil {
			props["customerId"] = *ws.Properties.CustomerID
		}
	}

	if tags := azureTagsToFormaeTags(ws.Tags); tags != nil {
		props["Tags"] = tags
	}

	return props
}

// buildWorkspaceProperties maps the schema onto ARM workspace properties. Shared
// by the create body and the update patch, which take the same properties type.
func buildWorkspaceProperties(props map[string]any) *armoperationalinsights.WorkspaceProperties {
	wsProps := &armoperationalinsights.WorkspaceProperties{}

	if raw, ok := props["sku"].(map[string]any); ok {
		if name, ok := raw["name"].(string); ok && name != "" {
			sku := &armoperationalinsights.WorkspaceSKU{
				Name: to.Ptr(armoperationalinsights.WorkspaceSKUNameEnum(name)),
			}
			if level, ok := capacity(raw["capacityReservationLevel"]); ok {
				sku.CapacityReservationLevel = to.Ptr(armoperationalinsights.CapacityReservationLevel(level))
			}
			wsProps.SKU = sku
		}
	}
	if v, ok := capacity(props["retentionInDays"]); ok {
		wsProps.RetentionInDays = to.Ptr(v)
	}
	if v, ok := props["dailyQuotaGb"].(float64); ok {
		wsProps.WorkspaceCapping = &armoperationalinsights.WorkspaceCapping{DailyQuotaGb: to.Ptr(v)}
	}
	if v, ok := props["publicNetworkAccessForIngestion"].(string); ok && v != "" {
		wsProps.PublicNetworkAccessForIngestion = to.Ptr(armoperationalinsights.PublicNetworkAccessType(v))
	}
	if v, ok := props["publicNetworkAccessForQuery"].(string); ok && v != "" {
		wsProps.PublicNetworkAccessForQuery = to.Ptr(armoperationalinsights.PublicNetworkAccessType(v))
	}

	return wsProps
}

func (w *LogAnalyticsWorkspace) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
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
	wsName, ok := props["name"].(string)
	if !ok || wsName == "" {
		wsName = request.Label
	}
	if wsName == "" {
		return nil, fmt.Errorf("name is required")
	}

	params := armoperationalinsights.Workspace{
		Location:   to.Ptr(location),
		Properties: buildWorkspaceProperties(props),
	}
	if azureTags := formaeTagsToAzureTags(request.Properties); azureTags != nil {
		params.Tags = azureTags
	}

	poller, err := w.api.BeginCreateOrUpdate(ctx, rgName, wsName, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.OperationalInsights/workspaces/%s",
		w.config.SubscriptionId, rgName, wsName)

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
		propsJSON, err := json.Marshal(w.buildPropertiesFromResult(&result.Workspace, rgName))
		if err != nil {
			return nil, fmt.Errorf("failed to marshal response properties: %w", err)
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

func (w *LogAnalyticsWorkspace) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, wsName, err := logAnalyticsWorkspaceIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := w.api.Get(ctx, rgName, wsName, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(w.buildPropertiesFromResult(&result.Workspace, rgName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeLogAnalyticsWorkspace,
		Properties:   string(propsJSON),
	}, nil
}

// Update is a synchronous PATCH — unlike Create/Delete there is no poller here,
// so Status is never reached for an update.
func (w *LogAnalyticsWorkspace) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, wsName, err := logAnalyticsWorkspaceIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props map[string]any
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	params := armoperationalinsights.WorkspacePatch{Properties: buildWorkspaceProperties(props)}
	if azureTags := formaeTagsToAzureTags(request.DesiredProperties); azureTags != nil {
		params.Tags = azureTags
	}

	result, err := w.api.Update(ctx, rgName, wsName, params, nil)
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

	propsJSON, err := json.Marshal(w.buildPropertiesFromResult(&result.Workspace, rgName))
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

// Delete soft-deletes: the workspace name stays reserved and its data recoverable
// for 14 days. The SDK's Force option would make that irreversible, so it is
// deliberately not set — a destroy must not destroy recoverability the user may
// still need. Names in conformance fixtures carry the run ID, so soft-deleted
// workspaces never collide with a later run.
func (w *LogAnalyticsWorkspace) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, wsName, err := logAnalyticsWorkspaceIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, err := w.api.BeginDelete(ctx, rgName, wsName, nil)
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

func (w *LogAnalyticsWorkspace) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	reqID, err := decodeLROStatus(request.RequestID)
	if err != nil {
		return nil, err
	}

	switch reqID.OperationType {
	case lroOpCreate:
		return statusLRO(ctx, request, &reqID, resource.OperationCreate,
			func(token string) (*runtime.Poller[armoperationalinsights.WorkspacesClientCreateOrUpdateResponse], error) {
				return resumePoller[armoperationalinsights.WorkspacesClientCreateOrUpdateResponse](w.pipeline, token)
			},
			func(_ context.Context, result armoperationalinsights.WorkspacesClientCreateOrUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				return w.completeFromWorkspace(&result.Workspace)
			})
	case lroOpDelete:
		return statusDeleteLRO(ctx, request, &reqID,
			func(token string) (*runtime.Poller[armoperationalinsights.WorkspacesClientDeleteResponse], error) {
				return resumePoller[armoperationalinsights.WorkspacesClientDeleteResponse](w.pipeline, token)
			}, nil)
	default:
		return nil, fmt.Errorf("unknown operation type: %s", reqID.OperationType)
	}
}

func (w *LogAnalyticsWorkspace) completeFromWorkspace(ws *armoperationalinsights.Workspace) (string, json.RawMessage, error) {
	nativeID := ""
	rgName := ""
	if ws.ID != nil {
		nativeID = *ws.ID
		if rg, _, err := logAnalyticsWorkspaceIDParts(*ws.ID); err == nil {
			rgName = rg
		}
	}
	propsJSON, err := json.Marshal(w.buildPropertiesFromResult(ws, rgName))
	if err != nil {
		return "", nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return nativeID, propsJSON, nil
}

func (w *LogAnalyticsWorkspace) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]

	var nativeIDs []string

	if rgName != "" {
		pager := w.api.NewListByResourceGroupPager(rgName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list log analytics workspaces: %w", err)
			}
			for _, ws := range page.Value {
				if ws.ID != nil {
					nativeIDs = append(nativeIDs, *ws.ID)
				}
			}
		}
		return &resource.ListResult{NativeIDs: nativeIDs}, nil
	}

	pager := w.api.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list log analytics workspaces: %w", err)
		}
		for _, ws := range page.Value {
			if ws.ID != nil {
				nativeIDs = append(nativeIDs, *ws.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
