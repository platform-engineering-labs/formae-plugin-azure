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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v4"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeNetworkManagerSubscriptionConnection = "AZURE::Network::NetworkManagerSubscriptionConnection"

// networkManagerSubscriptionConnectionsAPI is the
// armnetwork.SubscriptionNetworkManagerConnectionsClient surface used here. Every
// verb is synchronous, and CreateOrUpdate doubles as the update verb.
//
// The client is bound to a subscription and templates it into the URL as a single
// {subscriptionId} segment, url.PathEscape'd on its own — it does NOT build a
// scope string and escape the whole thing into one segment, which is what makes
// armlocks' *ByScope verbs unusable. The generated URLs here are correct.
type networkManagerSubscriptionConnectionsAPI interface {
	CreateOrUpdate(ctx context.Context, networkManagerConnectionName string, parameters armnetwork.ManagerConnection, options *armnetwork.SubscriptionNetworkManagerConnectionsClientCreateOrUpdateOptions) (armnetwork.SubscriptionNetworkManagerConnectionsClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, networkManagerConnectionName string, options *armnetwork.SubscriptionNetworkManagerConnectionsClientGetOptions) (armnetwork.SubscriptionNetworkManagerConnectionsClientGetResponse, error)
	Delete(ctx context.Context, networkManagerConnectionName string, options *armnetwork.SubscriptionNetworkManagerConnectionsClientDeleteOptions) (armnetwork.SubscriptionNetworkManagerConnectionsClientDeleteResponse, error)
	NewListPager(options *armnetwork.SubscriptionNetworkManagerConnectionsClientListOptions) *runtime.Pager[armnetwork.SubscriptionNetworkManagerConnectionsClientListResponse]
}

func init() {
	registry.Register(ResourceTypeNetworkManagerSubscriptionConnection, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &NetworkManagerSubscriptionConnection{
			api:    c.NetworkManagerSubscriptionConnectionsClient,
			config: cfg,
		}
	})
}

// NetworkManagerSubscriptionConnection is the provisioner for a subscription's
// side of a cross-tenant network manager connection
// (Microsoft.Network/networkManagerConnections at subscription scope).
//
// The management-group counterpart is deliberately not implemented: writing it
// needs a role assignment above subscription level.
type NetworkManagerSubscriptionConnection struct {
	api    networkManagerSubscriptionConnectionsAPI
	config *config.Config
}

// networkManagerSubscriptionConnectionProps mirrors
// schema/pkl/network/networkmanagersubscriptionconnection.pkl.
type networkManagerSubscriptionConnectionProps struct {
	Name             string  `json:"name"`
	NetworkManagerID string  `json:"networkManagerId"`
	Description      *string `json:"description"`
}

const networkManagerConnectionSegment = "/providers/microsoft.network/networkmanagerconnections/"

// networkManagerSubscriptionConnectionIDParts recovers the connection name.
//
// The resource lives at subscription scope, so the ID has no resource group and
// armIDParts (which insists on one) does not apply. The client is already bound to
// a subscription, so only the name is needed.
func networkManagerSubscriptionConnectionIDParts(resourceID string) (name string, err error) {
	idx := strings.Index(strings.ToLower(resourceID), networkManagerConnectionSegment)
	if idx < 0 {
		return "", fmt.Errorf("not a network manager connection resource ID: %s", resourceID)
	}
	name = resourceID[idx+len(networkManagerConnectionSegment):]
	if name == "" || strings.Contains(name, "/") {
		return "", fmt.Errorf("not a network manager connection resource ID: %s", resourceID)
	}
	return name, nil
}

func buildNetworkManagerSubscriptionConnectionParams(props *networkManagerSubscriptionConnectionProps) armnetwork.ManagerConnection {
	connProps := &armnetwork.ManagerConnectionProperties{
		NetworkManagerID: to.Ptr(props.NetworkManagerID),
	}
	if props.Description != nil && *props.Description != "" {
		connProps.Description = to.Ptr(*props.Description)
	}
	return armnetwork.ManagerConnection{Properties: connProps}
}

func (c *NetworkManagerSubscriptionConnection) buildPropertiesFromResult(conn *armnetwork.ManagerConnection) map[string]any {
	props := make(map[string]any)

	if conn.ID != nil {
		props["id"] = *conn.ID
	}
	if conn.Name != nil {
		props["name"] = *conn.Name
	}
	if p := conn.Properties; p != nil {
		if p.NetworkManagerID != nil {
			props["networkManagerId"] = *p.NetworkManagerID
		}
		if p.Description != nil && *p.Description != "" {
			props["description"] = *p.Description
		}
		// connectionState is dropped: it is the service's verdict on the pairing
		// (Connected, Pending, Conflict, Revoked, Rejected), not desired state.
	}

	return props
}

func (c *NetworkManagerSubscriptionConnection) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props networkManagerSubscriptionConnectionProps
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.NetworkManagerID == "" {
		return nil, fmt.Errorf("networkManagerId is required")
	}
	name := props.Name
	if name == "" {
		name = request.Label
	}
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}

	result, err := c.api.CreateOrUpdate(ctx, name, buildNetworkManagerSubscriptionConnectionParams(&props), nil)
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
	if nativeID == "" {
		nativeID = fmt.Sprintf("/subscriptions/%s/providers/Microsoft.Network/networkManagerConnections/%s",
			c.config.SubscriptionId, name)
	}
	propsJSON, err := json.Marshal(c.buildPropertiesFromResult(&result.ManagerConnection))
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

func (c *NetworkManagerSubscriptionConnection) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	name, err := networkManagerSubscriptionConnectionIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := c.api.Get(ctx, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(c.buildPropertiesFromResult(&result.ManagerConnection))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeNetworkManagerSubscriptionConnection,
		Properties:   string(propsJSON),
	}, nil
}

func (c *NetworkManagerSubscriptionConnection) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	name, err := networkManagerSubscriptionConnectionIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props networkManagerSubscriptionConnectionProps
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.NetworkManagerID == "" {
		return nil, fmt.Errorf("networkManagerId is required")
	}

	result, err := c.api.CreateOrUpdate(ctx, name, buildNetworkManagerSubscriptionConnectionParams(&props), nil)
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

	propsJSON, err := json.Marshal(c.buildPropertiesFromResult(&result.ManagerConnection))
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

func (c *NetworkManagerSubscriptionConnection) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	name, err := networkManagerSubscriptionConnectionIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	if _, err := c.api.Delete(ctx, name, nil); err != nil && !isDeleteSuccessError(err) {
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

// Status echoes success: every verb on this client is synchronous.
func (c *NetworkManagerSubscriptionConnection) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

// List enumerates the connections created by this subscription. The scope is the
// client's own subscription, so there is no AdditionalProperties key to read and
// the resource needs no listParam.
func (c *NetworkManagerSubscriptionConnection) List(ctx context.Context, _ *resource.ListRequest) (*resource.ListResult, error) {
	var nativeIDs []string
	pager := c.api.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list network manager connections: %w", err)
		}
		for _, conn := range page.Value {
			if conn != nil && conn.ID != nil {
				nativeIDs = append(nativeIDs, *conn.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
