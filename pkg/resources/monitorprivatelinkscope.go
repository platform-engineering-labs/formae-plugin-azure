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

const ResourceTypeMonitorPrivateLinkScope = "AZURE::Insights::PrivateLinkScope"

// monitorPrivateLinkScopesAPI is the armmonitor surface used here. The create is
// synchronous while the delete is an LRO — an unusual split, so Status only ever
// handles a delete token.
type monitorPrivateLinkScopesAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName, scopeName string, azureMonitorPrivateLinkScopePayload armmonitor.AzureMonitorPrivateLinkScope, options *armmonitor.PrivateLinkScopesClientCreateOrUpdateOptions) (armmonitor.PrivateLinkScopesClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName, scopeName string, options *armmonitor.PrivateLinkScopesClientGetOptions) (armmonitor.PrivateLinkScopesClientGetResponse, error)
	BeginDelete(ctx context.Context, resourceGroupName, scopeName string, options *armmonitor.PrivateLinkScopesClientBeginDeleteOptions) (*runtime.Poller[armmonitor.PrivateLinkScopesClientDeleteResponse], error)
	NewListPager(options *armmonitor.PrivateLinkScopesClientListOptions) *runtime.Pager[armmonitor.PrivateLinkScopesClientListResponse]
	NewListByResourceGroupPager(resourceGroupName string, options *armmonitor.PrivateLinkScopesClientListByResourceGroupOptions) *runtime.Pager[armmonitor.PrivateLinkScopesClientListByResourceGroupResponse]
}

func init() {
	registry.Register(ResourceTypeMonitorPrivateLinkScope, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &MonitorPrivateLinkScope{
			api:      c.MonitorPrivateLinkScopesClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// MonitorPrivateLinkScope is the provisioner for Azure Monitor Private Link Scopes
// (Microsoft.Insights/privateLinkScopes).
type MonitorPrivateLinkScope struct {
	api      monitorPrivateLinkScopesAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

// monitorPrivateLinkScopeProps mirrors
// schema/pkl/insights/privatelinkscope.pkl. ARM's accessModeSettings block is
// flattened into the two modes it carries.
type monitorPrivateLinkScopeProps struct {
	Name                string `json:"name"`
	ResourceGroupName   string `json:"resourceGroupName"`
	Location            string `json:"location"`
	IngestionAccessMode string `json:"ingestionAccessMode"`
	QueryAccessMode     string `json:"queryAccessMode"`
}

func monitorPrivateLinkScopeIDParts(resourceID string) (rgName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "privatelinkscopes")
	if err != nil {
		return "", "", err
	}
	return rgName, names["privatelinkscopes"], nil
}

func (m *MonitorPrivateLinkScope) buildPropertiesFromResult(scope *armmonitor.AzureMonitorPrivateLinkScope, rgName string) map[string]any {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName

	if scope.ID != nil {
		props["id"] = *scope.ID
	}
	if scope.Name != nil {
		props["name"] = *scope.Name
	}
	if scope.Location != nil {
		// The location is the literal "global" for this type, so it is passed through
		// rather than normalised as a region name would be.
		props["location"] = *scope.Location
	}
	if tags := azureTagsToFormaeTags(scope.Tags); len(tags) > 0 {
		props["Tags"] = tags
	}

	if p := scope.Properties; p != nil {
		if settings := p.AccessModeSettings; settings != nil {
			if settings.IngestionAccessMode != nil {
				props["ingestionAccessMode"] = canonicalizeEnum(string(*settings.IngestionAccessMode), "Open", "PrivateOnly")
			}
			if settings.QueryAccessMode != nil {
				props["queryAccessMode"] = canonicalizeEnum(string(*settings.QueryAccessMode), "Open", "PrivateOnly")
			}
			// exclusions carve out per-connection overrides, keyed by a private
			// endpoint connection name. They are not modelled, and reading them back
			// would drift against a scope that never declared them.
		}
		// privateEndpointConnections are ARM's back-references to endpoints that
		// attached themselves; provisioningState and systemData are service state.
	}

	return props
}

// monitorPrivateLinkScopeParams builds the request body shared by create and update.
func monitorPrivateLinkScopeParams(props monitorPrivateLinkScopeProps, payload json.RawMessage) armmonitor.AzureMonitorPrivateLinkScope {
	params := armmonitor.AzureMonitorPrivateLinkScope{
		Location: to.Ptr(props.Location),
		Properties: &armmonitor.AzureMonitorPrivateLinkScopeProperties{
			AccessModeSettings: &armmonitor.AccessModeSettings{
				IngestionAccessMode: to.Ptr(armmonitor.AccessMode(props.IngestionAccessMode)),
				QueryAccessMode:     to.Ptr(armmonitor.AccessMode(props.QueryAccessMode)),
			},
		},
	}
	if tags := formaeTagsToAzureTags(payload); len(tags) > 0 {
		params.Tags = tags
	}
	return params
}

func (m *MonitorPrivateLinkScope) parseProps(payload json.RawMessage, label string) (monitorPrivateLinkScopeProps, string, error) {
	var props monitorPrivateLinkScopeProps
	if err := json.Unmarshal(payload, &props); err != nil {
		return props, "", fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return props, "", fmt.Errorf("resourceGroupName is required")
	}
	if props.Location == "" {
		return props, "", fmt.Errorf("location is required")
	}
	if props.IngestionAccessMode == "" {
		return props, "", fmt.Errorf("ingestionAccessMode is required")
	}
	if props.QueryAccessMode == "" {
		return props, "", fmt.Errorf("queryAccessMode is required")
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

func (m *MonitorPrivateLinkScope) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	props, name, err := m.parseProps(request.Properties, request.Label)
	if err != nil {
		return nil, err
	}

	result, err := m.api.CreateOrUpdate(ctx, props.ResourceGroupName, name,
		monitorPrivateLinkScopeParams(props, request.Properties), nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	nativeID := ""
	if result.ID != nil {
		nativeID = *result.ID
	}
	propsJSON, err := json.Marshal(m.buildPropertiesFromResult(&result.AzureMonitorPrivateLinkScope, props.ResourceGroupName))
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

func (m *MonitorPrivateLinkScope) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, name, err := monitorPrivateLinkScopeIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := m.api.Get(ctx, rgName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(m.buildPropertiesFromResult(&result.AzureMonitorPrivateLinkScope, rgName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeMonitorPrivateLinkScope,
		Properties:   string(propsJSON),
	}, nil
}

// Update reissues CreateOrUpdate. UpdateTags exists but reaches only the tags, and
// it cannot change either access mode. Location rides along because a PUT without it
// is rejected.
func (m *MonitorPrivateLinkScope) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, name, err := monitorPrivateLinkScopeIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	props, _, err := m.parseProps(request.DesiredProperties, name)
	if err != nil {
		return nil, err
	}

	result, err := m.api.CreateOrUpdate(ctx, rgName, name,
		monitorPrivateLinkScopeParams(props, request.DesiredProperties), nil)
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

	propsJSON, err := json.Marshal(m.buildPropertiesFromResult(&result.AzureMonitorPrivateLinkScope, rgName))
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

func (m *MonitorPrivateLinkScope) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, name, err := monitorPrivateLinkScopeIDParts(request.NativeID)
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

// Status only ever sees a delete token: create and update are synchronous here, so
// they never report as in progress.
func (m *MonitorPrivateLinkScope) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	reqID, err := decodeLROStatus(request.RequestID)
	if err != nil {
		return nil, err
	}

	switch reqID.OperationType {
	case lroOpDelete:
		return statusDeleteLRO(ctx, request, &reqID,
			func(token string) (*runtime.Poller[armmonitor.PrivateLinkScopesClientDeleteResponse], error) {
				return resumePoller[armmonitor.PrivateLinkScopesClientDeleteResponse](m.pipeline, token)
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
func (m *MonitorPrivateLinkScope) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]

	var nativeIDs []string
	if rgName != "" {
		pager := m.api.NewListByResourceGroupPager(rgName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list private link scopes: %w", err)
			}
			for _, scope := range page.Value {
				if scope != nil && scope.ID != nil {
					nativeIDs = append(nativeIDs, *scope.ID)
				}
			}
		}
		return &resource.ListResult{NativeIDs: nativeIDs}, nil
	}

	pager := m.api.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list private link scopes: %w", err)
		}
		for _, scope := range page.Value {
			if scope != nil && scope.ID != nil {
				nativeIDs = append(nativeIDs, *scope.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
