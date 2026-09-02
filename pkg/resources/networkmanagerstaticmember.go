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

const ResourceTypeNetworkManagerStaticMember = "AZURE::Network::NetworkManagerStaticMember"

// networkManagerStaticMembersAPI is the armnetwork.StaticMembersClient surface used
// here. Every verb is synchronous — there is no BeginX on StaticMembersClient — so
// no poller is ever created and Status has no real work to do.
type networkManagerStaticMembersAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName string, networkManagerName string, networkGroupName string, staticMemberName string, parameters armnetwork.StaticMember, options *armnetwork.StaticMembersClientCreateOrUpdateOptions) (armnetwork.StaticMembersClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName string, networkManagerName string, networkGroupName string, staticMemberName string, options *armnetwork.StaticMembersClientGetOptions) (armnetwork.StaticMembersClientGetResponse, error)
	Delete(ctx context.Context, resourceGroupName string, networkManagerName string, networkGroupName string, staticMemberName string, options *armnetwork.StaticMembersClientDeleteOptions) (armnetwork.StaticMembersClientDeleteResponse, error)
	NewListPager(resourceGroupName string, networkManagerName string, networkGroupName string, options *armnetwork.StaticMembersClientListOptions) *runtime.Pager[armnetwork.StaticMembersClientListResponse]
}

func init() {
	registry.Register(ResourceTypeNetworkManagerStaticMember, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &NetworkManagerStaticMember{
			api:    c.NetworkManagerStaticMembersClient,
			config: cfg,
		}
	})
}

// NetworkManagerStaticMember is the provisioner for static members of a network
// group (Microsoft.Network/networkManagers/networkGroups/staticMembers).
//
// A static member is nothing but a pointer at one virtual network, so every field
// is create-only: aiming it somewhere else is a replace.
type NetworkManagerStaticMember struct {
	api    networkManagerStaticMembersAPI
	config *config.Config
}

// networkManagerStaticMemberProps mirrors
// schema/pkl/network/networkmanagerstaticmember.pkl.
type networkManagerStaticMemberProps struct {
	Name               string `json:"name"`
	ResourceGroupName  string `json:"resourceGroupName"`
	NetworkManagerName string `json:"networkManagerName"`
	NetworkGroupName   string `json:"networkGroupName"`
	ResourceID         string `json:"resourceId"`
}

func networkManagerStaticMemberIDParts(resourceID string) (rgName, managerName, groupName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "networkmanagers", "networkgroups", "staticmembers")
	if err != nil {
		return "", "", "", "", err
	}
	return rgName, names["networkmanagers"], names["networkgroups"], names["staticmembers"], nil
}

func (m *NetworkManagerStaticMember) buildPropertiesFromResult(member *armnetwork.StaticMember, rgName, managerName, groupName string) map[string]any {
	props := make(map[string]any)

	// All three parents come from the native ID: ARM echoes none of them on the
	// member body.
	props["resourceGroupName"] = rgName
	props["networkManagerName"] = managerName
	props["networkGroupName"] = groupName

	if member.ID != nil {
		props["id"] = *member.ID
	}
	if member.Name != nil {
		props["name"] = *member.Name
	}
	if p := member.Properties; p != nil {
		if p.ResourceID != nil {
			props["resourceId"] = *p.ResourceID
		}
		// region and provisioningState are dropped: the service derives the
		// region from the target virtual network and neither value is desired
		// state.
	}

	return props
}

func (m *NetworkManagerStaticMember) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props networkManagerStaticMemberProps
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	if props.NetworkManagerName == "" {
		return nil, fmt.Errorf("networkManagerName is required")
	}
	if props.NetworkGroupName == "" {
		return nil, fmt.Errorf("networkGroupName is required")
	}
	if props.ResourceID == "" {
		return nil, fmt.Errorf("resourceId is required")
	}
	name := props.Name
	if name == "" {
		name = request.Label
	}
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}

	params := armnetwork.StaticMember{
		Properties: &armnetwork.StaticMemberProperties{
			ResourceID: to.Ptr(props.ResourceID),
		},
	}

	result, err := m.api.CreateOrUpdate(ctx, props.ResourceGroupName, props.NetworkManagerName,
		props.NetworkGroupName, name, params, nil)
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
	propsJSON, err := json.Marshal(m.buildPropertiesFromResult(&result.StaticMember,
		props.ResourceGroupName, props.NetworkManagerName, props.NetworkGroupName))
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

func (m *NetworkManagerStaticMember) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, managerName, groupName, name, err := networkManagerStaticMemberIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := m.api.Get(ctx, rgName, managerName, groupName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(m.buildPropertiesFromResult(&result.StaticMember, rgName, managerName, groupName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeNetworkManagerStaticMember,
		Properties:   string(propsJSON),
	}, nil
}

// Update reissues CreateOrUpdate. Every field of a static member is create-only, so
// core replaces rather than updates one in practice; this exists so a forced
// update converges instead of erroring.
func (m *NetworkManagerStaticMember) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, managerName, groupName, name, err := networkManagerStaticMemberIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props networkManagerStaticMemberProps
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceID == "" {
		return nil, fmt.Errorf("resourceId is required")
	}

	params := armnetwork.StaticMember{
		Properties: &armnetwork.StaticMemberProperties{
			ResourceID: to.Ptr(props.ResourceID),
		},
	}

	result, err := m.api.CreateOrUpdate(ctx, rgName, managerName, groupName, name, params, nil)
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

	propsJSON, err := json.Marshal(m.buildPropertiesFromResult(&result.StaticMember, rgName, managerName, groupName))
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

func (m *NetworkManagerStaticMember) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, managerName, groupName, name, err := networkManagerStaticMemberIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	if _, err := m.api.Delete(ctx, rgName, managerName, groupName, name, nil); err != nil && !isDeleteSuccessError(err) {
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

// Status echoes success: every StaticMembersClient verb is synchronous, so nothing
// can still be running by the time this is asked.
func (m *NetworkManagerStaticMember) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

// List enumerates the static members of one network group. There is no
// subscription-wide pager, so without all three parents there is nothing to
// enumerate.
func (m *NetworkManagerStaticMember) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	managerName := request.AdditionalProperties["networkManagerName"]
	groupName := request.AdditionalProperties["networkGroupName"]
	if rgName == "" || managerName == "" || groupName == "" {
		return &resource.ListResult{}, nil
	}

	var nativeIDs []string
	pager := m.api.NewListPager(rgName, managerName, groupName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list network group static members: %w", err)
		}
		for _, member := range page.Value {
			if member != nil && member.ID != nil {
				nativeIDs = append(nativeIDs, *member.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
