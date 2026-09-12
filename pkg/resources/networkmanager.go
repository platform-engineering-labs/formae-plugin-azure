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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v4"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeNetworkManager = "AZURE::Network::NetworkManager"

// networkManagersAPI is the armnetwork.ManagersClient surface used here.
//
// CreateOrUpdate and Get are synchronous; only Delete is an LRO. Patch is
// deliberately absent: armnetwork.PatchObject carries tags and nothing else, so a
// manager whose description or scopes changed would silently never reconcile.
// Update reissues CreateOrUpdate instead.
type networkManagersAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName string, networkManagerName string, parameters armnetwork.Manager, options *armnetwork.ManagersClientCreateOrUpdateOptions) (armnetwork.ManagersClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName string, networkManagerName string, options *armnetwork.ManagersClientGetOptions) (armnetwork.ManagersClientGetResponse, error)
	BeginDelete(ctx context.Context, resourceGroupName string, networkManagerName string, options *armnetwork.ManagersClientBeginDeleteOptions) (*runtime.Poller[armnetwork.ManagersClientDeleteResponse], error)
	NewListPager(resourceGroupName string, options *armnetwork.ManagersClientListOptions) *runtime.Pager[armnetwork.ManagersClientListResponse]
	NewListBySubscriptionPager(options *armnetwork.ManagersClientListBySubscriptionOptions) *runtime.Pager[armnetwork.ManagersClientListBySubscriptionResponse]
}

func init() {
	registry.Register(ResourceTypeNetworkManager, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &NetworkManager{
			api:      c.NetworkManagersClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// NetworkManager is the provisioner for Azure Virtual Network Manager instances
// (Microsoft.Network/networkManagers).
//
// The manager is the parent of network groups, connectivity configurations and
// security admin configurations. It changes nothing on its own: a configuration
// only takes effect once it is committed to a region, and commits
// (networkManagerCommits) are deliberately not modelled by this plugin because a
// committed configuration cannot be deleted.
type NetworkManager struct {
	api      networkManagersAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

// networkManagerScopesProps mirrors the NetworkManagerScopes class in
// schema/pkl/network/networkmanager.pkl.
//
// Management groups are absent by design: writing a management-group scope needs a
// role assignment above subscription level, which this provider cannot assume.
type networkManagerScopesProps struct {
	Subscriptions []string `json:"subscriptions"`
}

// networkManagerProps mirrors schema/pkl/network/networkmanager.pkl.
type networkManagerProps struct {
	Name                        string                     `json:"name"`
	Location                    string                     `json:"location"`
	ResourceGroupName           string                     `json:"resourceGroupName"`
	NetworkManagerScopeAccesses []string                   `json:"networkManagerScopeAccesses"`
	NetworkManagerScopes        *networkManagerScopesProps `json:"networkManagerScopes"`
	Description                 *string                    `json:"description"`
}

func networkManagerIDParts(resourceID string) (rgName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "networkmanagers")
	if err != nil {
		return "", "", err
	}
	return rgName, names["networkmanagers"], nil
}

// buildNetworkManagerParams validates the declared properties and builds the ARM
// body. Both scope accesses and at least one subscription scope are required: ARM
// rejects a manager with an empty scope, and the "X is required" failures it
// returns arrive without an obvious cause, so they are caught here instead.
func buildNetworkManagerParams(props *networkManagerProps, properties json.RawMessage) (armnetwork.Manager, error) {
	if len(props.NetworkManagerScopeAccesses) == 0 {
		return armnetwork.Manager{}, fmt.Errorf("networkManagerScopeAccesses is required")
	}
	if props.NetworkManagerScopes == nil || len(props.NetworkManagerScopes.Subscriptions) == 0 {
		return armnetwork.Manager{}, fmt.Errorf("networkManagerScopes.subscriptions is required")
	}

	accesses := make([]*armnetwork.ConfigurationType, 0, len(props.NetworkManagerScopeAccesses))
	for _, access := range props.NetworkManagerScopeAccesses {
		accesses = append(accesses, to.Ptr(armnetwork.ConfigurationType(access)))
	}

	managerProps := &armnetwork.ManagerProperties{
		NetworkManagerScopeAccesses: accesses,
		NetworkManagerScopes: &armnetwork.ManagerPropertiesNetworkManagerScopes{
			Subscriptions: stringPointers(props.NetworkManagerScopes.Subscriptions),
		},
	}
	if props.Description != nil && *props.Description != "" {
		managerProps.Description = to.Ptr(*props.Description)
	}

	params := armnetwork.Manager{
		Location:   to.Ptr(props.Location),
		Properties: managerProps,
	}
	if azureTags := formaeTagsToAzureTags(properties); azureTags != nil {
		params.Tags = azureTags
	}
	return params, nil
}

func (n *NetworkManager) buildPropertiesFromResult(manager *armnetwork.Manager, rgName string) map[string]any {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName

	if manager.ID != nil {
		props["id"] = *manager.ID
	}
	if manager.Name != nil {
		props["name"] = *manager.Name
	}
	if manager.Location != nil {
		props["location"] = normalizeAzureLocation(*manager.Location)
	}

	if p := manager.Properties; p != nil {
		if len(p.NetworkManagerScopeAccesses) > 0 {
			accesses := make([]string, 0, len(p.NetworkManagerScopeAccesses))
			for _, access := range p.NetworkManagerScopeAccesses {
				if access != nil {
					accesses = append(accesses, canonicalizeEnum(string(*access), "Connectivity", "SecurityAdmin"))
				}
			}
			props["networkManagerScopeAccesses"] = accesses
		}
		// Only the subscription scopes are reported. crossTenantScopes is
		// read-only and managementGroups is not modelled, so a manager scoped to
		// a management group elsewhere reads back with its subscription scopes
		// alone rather than with a block this schema cannot express.
		if s := p.NetworkManagerScopes; s != nil && len(s.Subscriptions) > 0 {
			props["networkManagerScopes"] = map[string]any{
				"subscriptions": stringsFromPointers(s.Subscriptions),
			}
		}
		if p.Description != nil && *p.Description != "" {
			props["description"] = *p.Description
		}
		// provisioningState and resourceGuid are dropped: neither is desired
		// state and both move without anyone declaring them.
	}

	if tags := azureTagsToFormaeTags(manager.Tags); tags != nil {
		props["Tags"] = tags
	}

	return props
}

func (n *NetworkManager) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props networkManagerProps
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	if props.Location == "" {
		return nil, fmt.Errorf("location is required")
	}
	name := props.Name
	if name == "" {
		name = request.Label
	}
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}

	params, err := buildNetworkManagerParams(&props, request.Properties)
	if err != nil {
		return nil, err
	}

	result, err := n.api.CreateOrUpdate(ctx, props.ResourceGroupName, name, params, nil)
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
	propsJSON, err := json.Marshal(n.buildPropertiesFromResult(&result.Manager, props.ResourceGroupName))
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

func (n *NetworkManager) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, name, err := networkManagerIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := n.api.Get(ctx, rgName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(n.buildPropertiesFromResult(&result.Manager, rgName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeNetworkManager,
		Properties:   string(propsJSON),
	}, nil
}

func (n *NetworkManager) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, name, err := networkManagerIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props networkManagerProps
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.Location == "" {
		return nil, fmt.Errorf("location is required")
	}

	params, err := buildNetworkManagerParams(&props, request.DesiredProperties)
	if err != nil {
		return nil, err
	}

	result, err := n.api.CreateOrUpdate(ctx, rgName, name, params, nil)
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

	propsJSON, err := json.Marshal(n.buildPropertiesFromResult(&result.Manager, rgName))
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

// Delete removes the manager. Force is set: without it ARM refuses to delete a
// manager that still owns a deployed (committed) configuration, and the caller has
// no other way to get past that. This plugin never commits a configuration, so in
// practice force only covers a manager someone committed by hand.
func (n *NetworkManager) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, name, err := networkManagerIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, err := n.api.BeginDelete(ctx, rgName, name, &armnetwork.ManagersClientBeginDeleteOptions{
		Force: to.Ptr(true),
	})
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

// Status only ever sees a delete: create and update are synchronous, so no other
// operation hands out a RequestID.
func (n *NetworkManager) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	reqID, err := decodeLROStatus(request.RequestID)
	if err != nil {
		return nil, err
	}

	switch reqID.OperationType {
	case lroOpDelete:
		return statusDeleteLRO(ctx, request, &reqID,
			func(token string) (*runtime.Poller[armnetwork.ManagersClientDeleteResponse], error) {
				return resumePoller[armnetwork.ManagersClientDeleteResponse](n.pipeline, token)
			}, nil)
	default:
		return nil, fmt.Errorf("unknown operation type: %s", reqID.OperationType)
	}
}

// List enumerates managers in one resource group, falling back to the whole
// subscription when discovery has no resource group to scope by.
func (n *NetworkManager) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]

	var nativeIDs []string
	collect := func(values []*armnetwork.Manager) {
		for _, manager := range values {
			if manager != nil && manager.ID != nil {
				nativeIDs = append(nativeIDs, *manager.ID)
			}
		}
	}

	if rgName != "" {
		pager := n.api.NewListPager(rgName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list network managers: %w", err)
			}
			collect(page.Value)
		}
		return &resource.ListResult{NativeIDs: nativeIDs}, nil
	}

	pager := n.api.NewListBySubscriptionPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list network managers: %w", err)
		}
		collect(page.Value)
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
