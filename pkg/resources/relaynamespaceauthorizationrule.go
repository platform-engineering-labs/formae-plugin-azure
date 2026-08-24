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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/relay/armrelay"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeRelayNamespaceAuthorizationRule = "AZURE::Relay::NamespaceAuthorizationRule"

// relayNamespaceAuthRulesAPI is the armrelay surface used here. Authorization
// rules hang off the namespaces client rather than having one of their own, and
// every call is synchronous — there is no PATCH verb, so an update is another
// CreateOrUpdate.
type relayNamespaceAuthRulesAPI interface {
	CreateOrUpdateAuthorizationRule(ctx context.Context, resourceGroupName string, namespaceName string, authorizationRuleName string, parameters armrelay.AuthorizationRule, options *armrelay.NamespacesClientCreateOrUpdateAuthorizationRuleOptions) (armrelay.NamespacesClientCreateOrUpdateAuthorizationRuleResponse, error)
	GetAuthorizationRule(ctx context.Context, resourceGroupName string, namespaceName string, authorizationRuleName string, options *armrelay.NamespacesClientGetAuthorizationRuleOptions) (armrelay.NamespacesClientGetAuthorizationRuleResponse, error)
	DeleteAuthorizationRule(ctx context.Context, resourceGroupName string, namespaceName string, authorizationRuleName string, options *armrelay.NamespacesClientDeleteAuthorizationRuleOptions) (armrelay.NamespacesClientDeleteAuthorizationRuleResponse, error)
	NewListAuthorizationRulesPager(resourceGroupName string, namespaceName string, options *armrelay.NamespacesClientListAuthorizationRulesOptions) *runtime.Pager[armrelay.NamespacesClientListAuthorizationRulesResponse]
}

func init() {
	registry.Register(ResourceTypeRelayNamespaceAuthorizationRule, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &RelayNamespaceAuthorizationRule{
			api:    c.RelayNamespacesClient,
			config: cfg,
		}
	})
}

// RelayNamespaceAuthorizationRule is the provisioner for namespace-wide SAS rules
// on an Azure Relay namespace
// (Microsoft.Relay/namespaces/authorizationRules).
//
// The rule's keys are never serialized: ARM returns them only from a separate
// ListKeys call, so putting them in resource state would persist live credentials.
type RelayNamespaceAuthorizationRule struct {
	api    relayNamespaceAuthRulesAPI
	config *config.Config
}

// relayNamespaceAuthRuleProps mirrors
// schema/pkl/relay/namespaceauthorizationrule.pkl.
type relayNamespaceAuthRuleProps struct {
	Name              string   `json:"name"`
	ResourceGroupName string   `json:"resourceGroupName"`
	NamespaceName     string   `json:"namespaceName"`
	Rights            []string `json:"rights"`
}

func relayNamespaceAuthRuleIDParts(resourceID string) (rgName, namespaceName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "namespaces", "authorizationrules")
	if err != nil {
		return "", "", "", err
	}
	return rgName, names["namespaces"], names["authorizationrules"], nil
}

// relayAccessRights converts the schema's rights into the ARM shape. Shared with
// the hybrid-connection-scoped rule, which takes the same rights. Order is
// echoed as sent: ARM treats the rights as a set, and sorting them here would
// only make a desired list written in another order look like drift.
func relayAccessRights(rights []string) []*armrelay.AccessRights {
	if len(rights) == 0 {
		return nil
	}
	out := make([]*armrelay.AccessRights, 0, len(rights))
	for _, right := range rights {
		if right == "" {
			continue
		}
		out = append(out, to.Ptr(armrelay.AccessRights(right)))
	}
	return out
}

func (a *RelayNamespaceAuthorizationRule) buildPropertiesFromResult(rule *armrelay.AuthorizationRule, rgName, namespaceName string) map[string]any {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	props["namespaceName"] = namespaceName

	if rule.ID != nil {
		props["id"] = *rule.ID
	}
	if rule.Name != nil {
		props["name"] = *rule.Name
	}

	if p := rule.Properties; p != nil && len(p.Rights) > 0 {
		rights := make([]string, 0, len(p.Rights))
		for _, right := range p.Rights {
			if right == nil {
				continue
			}
			rights = append(rights, canonicalizeEnum(string(*right), "Listen", "Send", "Manage"))
		}
		props["rights"] = rights
	}

	return props
}

func (a *RelayNamespaceAuthorizationRule) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props relayNamespaceAuthRuleProps
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	if props.NamespaceName == "" {
		return nil, fmt.Errorf("namespaceName is required")
	}
	if len(props.Rights) == 0 {
		return nil, fmt.Errorf("rights is required")
	}
	name := props.Name
	if name == "" {
		name = request.Label
	}
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}

	result, err := a.api.CreateOrUpdateAuthorizationRule(ctx, props.ResourceGroupName, props.NamespaceName, name,
		armrelay.AuthorizationRule{
			Properties: &armrelay.AuthorizationRuleProperties{Rights: relayAccessRights(props.Rights)},
		}, nil)
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
	propsJSON, err := json.Marshal(a.buildPropertiesFromResult(&result.AuthorizationRule,
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

func (a *RelayNamespaceAuthorizationRule) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, namespaceName, name, err := relayNamespaceAuthRuleIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := a.api.GetAuthorizationRule(ctx, rgName, namespaceName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(a.buildPropertiesFromResult(&result.AuthorizationRule, rgName, namespaceName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeRelayNamespaceAuthorizationRule,
		Properties:   string(propsJSON),
	}, nil
}

// Update re-PUTs through CreateOrUpdateAuthorizationRule: this API has no PATCH
// verb. rights is the only mutable property, so it is the only thing an update can
// carry.
func (a *RelayNamespaceAuthorizationRule) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, namespaceName, name, err := relayNamespaceAuthRuleIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props relayNamespaceAuthRuleProps
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	result, err := a.api.CreateOrUpdateAuthorizationRule(ctx, rgName, namespaceName, name,
		armrelay.AuthorizationRule{
			Properties: &armrelay.AuthorizationRuleProperties{Rights: relayAccessRights(props.Rights)},
		}, nil)
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

	propsJSON, err := json.Marshal(a.buildPropertiesFromResult(&result.AuthorizationRule, rgName, namespaceName))
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

func (a *RelayNamespaceAuthorizationRule) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, namespaceName, name, err := relayNamespaceAuthRuleIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	if _, err := a.api.DeleteAuthorizationRule(ctx, rgName, namespaceName, name, nil); err != nil && !isDeleteSuccessError(err) {
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

// Status is never reached with real work to do: every operation on an
// authorization rule is synchronous, so it echoes success.
func (a *RelayNamespaceAuthorizationRule) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

// List requires both the resource group and the namespace: ARM has no
// subscription-wide listing for authorization rules.
func (a *RelayNamespaceAuthorizationRule) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	namespaceName := request.AdditionalProperties["namespaceName"]
	if rgName == "" || namespaceName == "" {
		return &resource.ListResult{}, nil
	}

	var nativeIDs []string
	pager := a.api.NewListAuthorizationRulesPager(rgName, namespaceName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list relay namespace authorization rules: %w", err)
		}
		for _, rule := range page.Value {
			if rule.ID != nil {
				nativeIDs = append(nativeIDs, *rule.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
