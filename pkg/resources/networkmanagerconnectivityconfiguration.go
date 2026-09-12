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

const ResourceTypeNetworkManagerConnectivityConfiguration = "AZURE::Network::NetworkManagerConnectivityConfiguration"

// networkManagerConnectivityConfigurationsAPI is the
// armnetwork.ConnectivityConfigurationsClient surface used here. CreateOrUpdate
// doubles as the update verb and is synchronous; only Delete is an LRO.
type networkManagerConnectivityConfigurationsAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName string, networkManagerName string, configurationName string, connectivityConfiguration armnetwork.ConnectivityConfiguration, options *armnetwork.ConnectivityConfigurationsClientCreateOrUpdateOptions) (armnetwork.ConnectivityConfigurationsClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName string, networkManagerName string, configurationName string, options *armnetwork.ConnectivityConfigurationsClientGetOptions) (armnetwork.ConnectivityConfigurationsClientGetResponse, error)
	BeginDelete(ctx context.Context, resourceGroupName string, networkManagerName string, configurationName string, options *armnetwork.ConnectivityConfigurationsClientBeginDeleteOptions) (*runtime.Poller[armnetwork.ConnectivityConfigurationsClientDeleteResponse], error)
	NewListPager(resourceGroupName string, networkManagerName string, options *armnetwork.ConnectivityConfigurationsClientListOptions) *runtime.Pager[armnetwork.ConnectivityConfigurationsClientListResponse]
}

func init() {
	registry.Register(ResourceTypeNetworkManagerConnectivityConfiguration, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &NetworkManagerConnectivityConfiguration{
			api:      c.NetworkManagerConnectivityConfigurationsClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// NetworkManagerConnectivityConfiguration is the provisioner for connectivity
// configurations (Microsoft.Network/networkManagers/connectivityConfigurations).
//
// The configuration declares a topology — Mesh or HubAndSpoke — over the members
// of one or more network groups. It is INERT until it is committed to a region,
// and commits (networkManagerCommits) are deliberately not modelled: a committed
// configuration cannot be deleted, so leaving it uncommitted is what keeps it
// tearable-down.
type NetworkManagerConnectivityConfiguration struct {
	api      networkManagerConnectivityConfigurationsAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

// connectivityGroupItemProps mirrors the ConnectivityGroupItem class in
// schema/pkl/network/networkmanagerconnectivityconfiguration.pkl.
type connectivityGroupItemProps struct {
	NetworkGroupID    string  `json:"networkGroupId"`
	GroupConnectivity string  `json:"groupConnectivity"`
	IsGlobal          *string `json:"isGlobal"`
	UseHubGateway     *string `json:"useHubGateway"`
}

// connectivityHubProps mirrors the ConnectivityHub class in the same module.
type connectivityHubProps struct {
	ResourceID   string `json:"resourceId"`
	ResourceType string `json:"resourceType"`
}

// networkManagerConnectivityConfigurationProps mirrors
// schema/pkl/network/networkmanagerconnectivityconfiguration.pkl.
type networkManagerConnectivityConfigurationProps struct {
	Name                  string                       `json:"name"`
	ResourceGroupName     string                       `json:"resourceGroupName"`
	NetworkManagerName    string                       `json:"networkManagerName"`
	ConnectivityTopology  string                       `json:"connectivityTopology"`
	AppliesToGroups       []connectivityGroupItemProps `json:"appliesToGroups"`
	Hubs                  []connectivityHubProps       `json:"hubs"`
	IsGlobal              *string                      `json:"isGlobal"`
	DeleteExistingPeering *string                      `json:"deleteExistingPeering"`
	Description           *string                      `json:"description"`
}

func networkManagerConnectivityConfigurationIDParts(resourceID string) (rgName, managerName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "networkmanagers", "connectivityconfigurations")
	if err != nil {
		return "", "", "", err
	}
	return rgName, names["networkmanagers"], names["connectivityconfigurations"], nil
}

// buildConnectivityConfigurationParams validates the declared properties and
// builds the ARM body.
//
// The topology/hub pairing is checked here rather than left to ARM: a Mesh
// configuration that names a hub, and a HubAndSpoke one that names none, both fail
// with a generic BadRequest that says nothing about which side is wrong.
func buildConnectivityConfigurationParams(props *networkManagerConnectivityConfigurationProps) (armnetwork.ConnectivityConfiguration, error) {
	if props.ConnectivityTopology == "" {
		return armnetwork.ConnectivityConfiguration{}, fmt.Errorf("connectivityTopology is required")
	}
	if len(props.AppliesToGroups) == 0 {
		return armnetwork.ConnectivityConfiguration{}, fmt.Errorf("appliesToGroups is required")
	}
	switch props.ConnectivityTopology {
	case string(armnetwork.ConnectivityTopologyHubAndSpoke):
		if len(props.Hubs) == 0 {
			return armnetwork.ConnectivityConfiguration{}, fmt.Errorf("hubs is required for the HubAndSpoke topology")
		}
	case string(armnetwork.ConnectivityTopologyMesh):
		if len(props.Hubs) > 0 {
			return armnetwork.ConnectivityConfiguration{}, fmt.Errorf("hubs must be empty for the Mesh topology")
		}
	}

	groups := make([]*armnetwork.ConnectivityGroupItem, 0, len(props.AppliesToGroups))
	for i := range props.AppliesToGroups {
		item := &props.AppliesToGroups[i]
		if item.NetworkGroupID == "" {
			return armnetwork.ConnectivityConfiguration{}, fmt.Errorf("appliesToGroups.networkGroupId is required")
		}
		if item.GroupConnectivity == "" {
			return armnetwork.ConnectivityConfiguration{}, fmt.Errorf("appliesToGroups.groupConnectivity is required")
		}
		group := &armnetwork.ConnectivityGroupItem{
			NetworkGroupID:    to.Ptr(item.NetworkGroupID),
			GroupConnectivity: to.Ptr(armnetwork.GroupConnectivity(item.GroupConnectivity)),
		}
		// An unset flag is left out of the request entirely so ARM applies its
		// own default rather than receiving an empty string.
		if item.IsGlobal != nil && *item.IsGlobal != "" {
			group.IsGlobal = to.Ptr(armnetwork.IsGlobal(*item.IsGlobal))
		}
		if item.UseHubGateway != nil && *item.UseHubGateway != "" {
			group.UseHubGateway = to.Ptr(armnetwork.UseHubGateway(*item.UseHubGateway))
		}
		groups = append(groups, group)
	}

	configProps := &armnetwork.ConnectivityConfigurationProperties{
		ConnectivityTopology: to.Ptr(armnetwork.ConnectivityTopology(props.ConnectivityTopology)),
		AppliesToGroups:      groups,
	}

	if len(props.Hubs) > 0 {
		hubs := make([]*armnetwork.Hub, 0, len(props.Hubs))
		for i := range props.Hubs {
			hub := &props.Hubs[i]
			if hub.ResourceID == "" {
				return armnetwork.ConnectivityConfiguration{}, fmt.Errorf("hubs.resourceId is required")
			}
			if hub.ResourceType == "" {
				return armnetwork.ConnectivityConfiguration{}, fmt.Errorf("hubs.resourceType is required")
			}
			hubs = append(hubs, &armnetwork.Hub{
				ResourceID:   to.Ptr(hub.ResourceID),
				ResourceType: to.Ptr(hub.ResourceType),
			})
		}
		configProps.Hubs = hubs
	}

	if props.IsGlobal != nil && *props.IsGlobal != "" {
		configProps.IsGlobal = to.Ptr(armnetwork.IsGlobal(*props.IsGlobal))
	}
	if props.DeleteExistingPeering != nil && *props.DeleteExistingPeering != "" {
		configProps.DeleteExistingPeering = to.Ptr(armnetwork.DeleteExistingPeering(*props.DeleteExistingPeering))
	}
	if props.Description != nil && *props.Description != "" {
		configProps.Description = to.Ptr(*props.Description)
	}

	return armnetwork.ConnectivityConfiguration{Properties: configProps}, nil
}

func (c *NetworkManagerConnectivityConfiguration) buildPropertiesFromResult(config *armnetwork.ConnectivityConfiguration, rgName, managerName string) map[string]any {
	props := make(map[string]any)

	// Both parents come from the native ID: ARM echoes neither on the body.
	props["resourceGroupName"] = rgName
	props["networkManagerName"] = managerName

	if config.ID != nil {
		props["id"] = *config.ID
	}
	if config.Name != nil {
		props["name"] = *config.Name
	}

	p := config.Properties
	if p == nil {
		return props
	}

	if p.ConnectivityTopology != nil {
		props["connectivityTopology"] = canonicalizeEnum(string(*p.ConnectivityTopology), "Mesh", "HubAndSpoke")
	}
	if len(p.AppliesToGroups) > 0 {
		groups := make([]map[string]any, 0, len(p.AppliesToGroups))
		for _, item := range p.AppliesToGroups {
			if item == nil {
				continue
			}
			group := make(map[string]any)
			if item.NetworkGroupID != nil {
				group["networkGroupId"] = *item.NetworkGroupID
			}
			if item.GroupConnectivity != nil {
				group["groupConnectivity"] = canonicalizeEnum(string(*item.GroupConnectivity), "DirectlyConnected", "None")
			}
			if item.IsGlobal != nil {
				group["isGlobal"] = canonicalizeEnum(string(*item.IsGlobal), "True", "False")
			}
			if item.UseHubGateway != nil {
				group["useHubGateway"] = canonicalizeEnum(string(*item.UseHubGateway), "True", "False")
			}
			groups = append(groups, group)
		}
		props["appliesToGroups"] = groups
	}
	if len(p.Hubs) > 0 {
		hubs := make([]map[string]any, 0, len(p.Hubs))
		for _, hub := range p.Hubs {
			if hub == nil {
				continue
			}
			entry := make(map[string]any)
			if hub.ResourceID != nil {
				entry["resourceId"] = *hub.ResourceID
			}
			if hub.ResourceType != nil {
				entry["resourceType"] = *hub.ResourceType
			}
			hubs = append(hubs, entry)
		}
		props["hubs"] = hubs
	}
	if p.IsGlobal != nil {
		props["isGlobal"] = canonicalizeEnum(string(*p.IsGlobal), "True", "False")
	}
	if p.DeleteExistingPeering != nil {
		props["deleteExistingPeering"] = canonicalizeEnum(string(*p.DeleteExistingPeering), "True", "False")
	}
	if p.Description != nil && *p.Description != "" {
		props["description"] = *p.Description
	}
	// provisioningState and resourceGuid are dropped: neither is desired state.

	return props
}

func (c *NetworkManagerConnectivityConfiguration) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props networkManagerConnectivityConfigurationProps
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	if props.NetworkManagerName == "" {
		return nil, fmt.Errorf("networkManagerName is required")
	}
	name := props.Name
	if name == "" {
		name = request.Label
	}
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}

	params, err := buildConnectivityConfigurationParams(&props)
	if err != nil {
		return nil, err
	}

	result, err := c.api.CreateOrUpdate(ctx, props.ResourceGroupName, props.NetworkManagerName, name, params, nil)
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
	propsJSON, err := json.Marshal(c.buildPropertiesFromResult(&result.ConnectivityConfiguration,
		props.ResourceGroupName, props.NetworkManagerName))
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

func (c *NetworkManagerConnectivityConfiguration) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, managerName, name, err := networkManagerConnectivityConfigurationIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := c.api.Get(ctx, rgName, managerName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(c.buildPropertiesFromResult(&result.ConnectivityConfiguration, rgName, managerName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeNetworkManagerConnectivityConfiguration,
		Properties:   string(propsJSON),
	}, nil
}

func (c *NetworkManagerConnectivityConfiguration) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, managerName, name, err := networkManagerConnectivityConfigurationIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props networkManagerConnectivityConfigurationProps
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	params, err := buildConnectivityConfigurationParams(&props)
	if err != nil {
		return nil, err
	}

	result, err := c.api.CreateOrUpdate(ctx, rgName, managerName, name, params, nil)
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

	propsJSON, err := json.Marshal(c.buildPropertiesFromResult(&result.ConnectivityConfiguration, rgName, managerName))
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

// Delete removes the configuration. Force is set because ARM refuses to delete a
// configuration that has been deployed (committed) to a region; this plugin never
// commits one, so force only matters for a configuration someone committed by
// hand. When force does apply, the service runs a cleanup deployment first.
func (c *NetworkManagerConnectivityConfiguration) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, managerName, name, err := networkManagerConnectivityConfigurationIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, err := c.api.BeginDelete(ctx, rgName, managerName, name,
		&armnetwork.ConnectivityConfigurationsClientBeginDeleteOptions{Force: to.Ptr(true)})
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

// Status only ever sees a delete: create and update are synchronous.
func (c *NetworkManagerConnectivityConfiguration) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	reqID, err := decodeLROStatus(request.RequestID)
	if err != nil {
		return nil, err
	}

	switch reqID.OperationType {
	case lroOpDelete:
		return statusDeleteLRO(ctx, request, &reqID,
			func(token string) (*runtime.Poller[armnetwork.ConnectivityConfigurationsClientDeleteResponse], error) {
				return resumePoller[armnetwork.ConnectivityConfigurationsClientDeleteResponse](c.pipeline, token)
			}, nil)
	default:
		return nil, fmt.Errorf("unknown operation type: %s", reqID.OperationType)
	}
}

// List enumerates the connectivity configurations of one manager. There is no
// subscription-wide pager, so without both parents there is nothing to enumerate.
func (c *NetworkManagerConnectivityConfiguration) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	managerName := request.AdditionalProperties["networkManagerName"]
	if rgName == "" || managerName == "" {
		return &resource.ListResult{}, nil
	}

	var nativeIDs []string
	pager := c.api.NewListPager(rgName, managerName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list connectivity configurations: %w", err)
		}
		for _, config := range page.Value {
			if config != nil && config.ID != nil {
				nativeIDs = append(nativeIDs, *config.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
