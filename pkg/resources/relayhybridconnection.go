// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/relay/armrelay"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeRelayHybridConnection = "AZURE::Relay::HybridConnection"

// relayHybridConnectionsAPI is the armrelay surface used here. Unlike the
// namespace these calls are all synchronous — no pollers, so Status never does
// real work — and there is no PATCH verb: an update is another CreateOrUpdate.
type relayHybridConnectionsAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName string, namespaceName string, forwardingRuleName string, parameters armrelay.HybridConnection, options *armrelay.HybridConnectionsClientCreateOrUpdateOptions) (armrelay.HybridConnectionsClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName string, namespaceName string, forwardingRuleName string, options *armrelay.HybridConnectionsClientGetOptions) (armrelay.HybridConnectionsClientGetResponse, error)
	Delete(ctx context.Context, resourceGroupName string, namespaceName string, forwardingRuleName string, options *armrelay.HybridConnectionsClientDeleteOptions) (armrelay.HybridConnectionsClientDeleteResponse, error)
	NewListByNamespacePager(resourceGroupName string, namespaceName string, options *armrelay.HybridConnectionsClientListByNamespaceOptions) *runtime.Pager[armrelay.HybridConnectionsClientListByNamespaceResponse]
}

func init() {
	registry.Register(ResourceTypeRelayHybridConnection, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &RelayHybridConnection{
			api:    c.RelayHybridConnectionsClient,
			config: cfg,
		}
	})
}

// DNSForwardingRule is the provisioner for rules inside a DNS forwarding ruleset
// (Microsoft.Network/dnsForwardingRulesets/forwardingRules).
type RelayHybridConnection struct {
	api    relayHybridConnectionsAPI
	config *config.Config
}

// relayHybridConnectionProps mirrors schema/pkl/network/dnsforwardingrule.pkl.
type relayHybridConnectionProps struct {
	Name                        string  `json:"name"`
	ResourceGroupName           string  `json:"resourceGroupName"`
	NamespaceName               string  `json:"namespaceName"`
	RequiresClientAuthorization *bool   `json:"requiresClientAuthorization"`
	UserMetadata                *string `json:"userMetadata"`
}

func relayHybridConnectionIDParts(resourceID string) (rgName, namespaceName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "namespaces", "hybridconnections")
	if err != nil {
		return "", "", "", err
	}
	return rgName, names["namespaces"], names["hybridconnections"], nil
}

func (h *RelayHybridConnection) buildPropertiesFromResult(hc *armrelay.HybridConnection, rgName, namespaceName string) map[string]any {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	props["namespaceName"] = namespaceName

	if hc.ID != nil {
		props["id"] = *hc.ID
	}
	if hc.Name != nil {
		props["name"] = *hc.Name
	}

	if p := hc.Properties; p != nil {
		if p.RequiresClientAuthorization != nil {
			props["requiresClientAuthorization"] = *p.RequiresClientAuthorization
		}
		if p.UserMetadata != nil {
			props["userMetadata"] = *p.UserMetadata
		}
		// createdAt, updatedAt and listenerCount are deliberately dropped: the
		// timestamps move on their own and the listener count changes whenever a
		// listener connects, so all three would read back as drift.
	}

	return props
}

func (h *RelayHybridConnection) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props relayHybridConnectionProps
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	if props.NamespaceName == "" {
		return nil, fmt.Errorf("namespaceName is required")
	}

	name := props.Name
	if name == "" {
		name = request.Label
	}
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}

	hcProps := &armrelay.HybridConnectionProperties{
		RequiresClientAuthorization: props.RequiresClientAuthorization,
		UserMetadata:                props.UserMetadata,
	}

	result, err := h.api.CreateOrUpdate(ctx, props.ResourceGroupName, props.NamespaceName, name,
		armrelay.HybridConnection{Properties: hcProps}, nil)
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
	propsJSON, err := json.Marshal(h.buildPropertiesFromResult(&result.HybridConnection,
		props.ResourceGroupName, props.NamespaceName))
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

func (h *RelayHybridConnection) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, namespaceName, name, err := relayHybridConnectionIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := h.api.Get(ctx, rgName, namespaceName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(h.buildPropertiesFromResult(&result.HybridConnection, rgName, namespaceName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeRelayHybridConnection,
		Properties:   string(propsJSON),
	}, nil
}

// Update re-PUTs through CreateOrUpdate: this API has no PATCH verb for hybrid
// connections. requiresClientAuthorization is createOnly all the same — ARM
// rejects flipping it on an existing hc — so only userMetadata really
// changes here.
func (h *RelayHybridConnection) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, namespaceName, name, err := relayHybridConnectionIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props relayHybridConnectionProps
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	result, err := h.api.CreateOrUpdate(ctx, rgName, namespaceName, name,
		armrelay.HybridConnection{Properties: &armrelay.HybridConnectionProperties{
			RequiresClientAuthorization: props.RequiresClientAuthorization,
			UserMetadata:                props.UserMetadata,
		}}, nil)
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

	propsJSON, err := json.Marshal(h.buildPropertiesFromResult(&result.HybridConnection, rgName, namespaceName))
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

func (h *RelayHybridConnection) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, namespaceName, name, err := relayHybridConnectionIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	if _, err := h.api.Delete(ctx, rgName, namespaceName, name, nil); err != nil && !isDeleteSuccessError(err) {
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

// Status is never reached with real work to do: every operation on a forwarding
// hc is synchronous, so it echoes success.
func (h *RelayHybridConnection) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

// List requires both the resource group and the ruleset name: ARM has no
// subscription-wide listing for forwarding rules.
func (h *RelayHybridConnection) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	namespaceName := request.AdditionalProperties["namespaceName"]
	if rgName == "" || namespaceName == "" {
		return &resource.ListResult{}, nil
	}

	var nativeIDs []string
	pager := h.api.NewListByNamespacePager(rgName, namespaceName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list relay hybrid connections: %w", err)
		}
		for _, hc := range page.Value {
			if hc.ID != nil {
				nativeIDs = append(nativeIDs, *hc.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
