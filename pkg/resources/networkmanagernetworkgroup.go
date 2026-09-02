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

const ResourceTypeNetworkManagerNetworkGroup = "AZURE::Network::NetworkManagerNetworkGroup"

// networkManagerGroupsAPI is the armnetwork.GroupsClient surface used here.
// CreateOrUpdate doubles as the update verb and is synchronous; only Delete is an
// LRO.
type networkManagerGroupsAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName string, networkManagerName string, networkGroupName string, parameters armnetwork.Group, options *armnetwork.GroupsClientCreateOrUpdateOptions) (armnetwork.GroupsClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName string, networkManagerName string, networkGroupName string, options *armnetwork.GroupsClientGetOptions) (armnetwork.GroupsClientGetResponse, error)
	BeginDelete(ctx context.Context, resourceGroupName string, networkManagerName string, networkGroupName string, options *armnetwork.GroupsClientBeginDeleteOptions) (*runtime.Poller[armnetwork.GroupsClientDeleteResponse], error)
	NewListPager(resourceGroupName string, networkManagerName string, options *armnetwork.GroupsClientListOptions) *runtime.Pager[armnetwork.GroupsClientListResponse]
}

func init() {
	registry.Register(ResourceTypeNetworkManagerNetworkGroup, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &NetworkManagerNetworkGroup{
			api:      c.NetworkManagerGroupsClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// NetworkManagerNetworkGroup is the provisioner for network groups inside a
// virtual network manager (Microsoft.Network/networkManagers/networkGroups).
//
// A group is the membership set a configuration is applied to. It carries nothing
// but a description; membership comes from NetworkManagerStaticMember children, or
// from an Azure Policy definition for the dynamic case.
type NetworkManagerNetworkGroup struct {
	api      networkManagerGroupsAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

// networkManagerNetworkGroupProps mirrors
// schema/pkl/network/networkmanagernetworkgroup.pkl.
type networkManagerNetworkGroupProps struct {
	Name               string  `json:"name"`
	ResourceGroupName  string  `json:"resourceGroupName"`
	NetworkManagerName string  `json:"networkManagerName"`
	Description        *string `json:"description"`
}

func networkManagerNetworkGroupIDParts(resourceID string) (rgName, managerName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "networkmanagers", "networkgroups")
	if err != nil {
		return "", "", "", err
	}
	return rgName, names["networkmanagers"], names["networkgroups"], nil
}

func buildNetworkManagerNetworkGroupParams(props *networkManagerNetworkGroupProps) armnetwork.Group {
	groupProps := &armnetwork.GroupProperties{}
	if props.Description != nil && *props.Description != "" {
		groupProps.Description = to.Ptr(*props.Description)
	}
	return armnetwork.Group{Properties: groupProps}
}

func (g *NetworkManagerNetworkGroup) buildPropertiesFromResult(group *armnetwork.Group, rgName, managerName string) map[string]any {
	props := make(map[string]any)

	// Both parents come from the native ID rather than the response body: ARM
	// echoes neither on the group itself.
	props["resourceGroupName"] = rgName
	props["networkManagerName"] = managerName

	if group.ID != nil {
		props["id"] = *group.ID
	}
	if group.Name != nil {
		props["name"] = *group.Name
	}
	if p := group.Properties; p != nil {
		if p.Description != nil && *p.Description != "" {
			props["description"] = *p.Description
		}
	}

	return props
}

func (g *NetworkManagerNetworkGroup) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props networkManagerNetworkGroupProps
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

	result, err := g.api.CreateOrUpdate(ctx, props.ResourceGroupName, props.NetworkManagerName, name,
		buildNetworkManagerNetworkGroupParams(&props), nil)
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
	propsJSON, err := json.Marshal(g.buildPropertiesFromResult(&result.Group, props.ResourceGroupName, props.NetworkManagerName))
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

func (g *NetworkManagerNetworkGroup) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, managerName, name, err := networkManagerNetworkGroupIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := g.api.Get(ctx, rgName, managerName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(g.buildPropertiesFromResult(&result.Group, rgName, managerName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeNetworkManagerNetworkGroup,
		Properties:   string(propsJSON),
	}, nil
}

func (g *NetworkManagerNetworkGroup) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, managerName, name, err := networkManagerNetworkGroupIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props networkManagerNetworkGroupProps
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	result, err := g.api.CreateOrUpdate(ctx, rgName, managerName, name,
		buildNetworkManagerNetworkGroupParams(&props), nil)
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

	propsJSON, err := json.Marshal(g.buildPropertiesFromResult(&result.Group, rgName, managerName))
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

// Delete removes the group and, with it, its static members. Force is set because
// ARM refuses to delete a group that is referenced by a deployed (committed)
// configuration; this plugin never commits one, so force only matters for a
// configuration someone committed by hand.
func (g *NetworkManagerNetworkGroup) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, managerName, name, err := networkManagerNetworkGroupIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, err := g.api.BeginDelete(ctx, rgName, managerName, name, &armnetwork.GroupsClientBeginDeleteOptions{
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

// Status only ever sees a delete: create and update are synchronous.
func (g *NetworkManagerNetworkGroup) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	reqID, err := decodeLROStatus(request.RequestID)
	if err != nil {
		return nil, err
	}

	switch reqID.OperationType {
	case lroOpDelete:
		return statusDeleteLRO(ctx, request, &reqID,
			func(token string) (*runtime.Poller[armnetwork.GroupsClientDeleteResponse], error) {
				return resumePoller[armnetwork.GroupsClientDeleteResponse](g.pipeline, token)
			}, nil)
	default:
		return nil, fmt.Errorf("unknown operation type: %s", reqID.OperationType)
	}
}

// List enumerates the groups of one manager. There is no subscription-wide pager
// for network groups, so without both parents there is nothing to enumerate.
func (g *NetworkManagerNetworkGroup) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	managerName := request.AdditionalProperties["networkManagerName"]
	if rgName == "" || managerName == "" {
		return &resource.ListResult{}, nil
	}

	var nativeIDs []string
	pager := g.api.NewListPager(rgName, managerName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list network groups: %w", err)
		}
		for _, group := range page.Value {
			if group != nil && group.ID != nil {
				nativeIDs = append(nativeIDs, *group.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
