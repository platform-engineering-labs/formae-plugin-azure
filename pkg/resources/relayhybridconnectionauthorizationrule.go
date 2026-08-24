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

const ResourceTypeRelayHybridConnectionAuthorizationRule = "AZURE::Relay::HybridConnectionAuthorizationRule"

// relayHybridConnectionAuthRulesAPI is the armrelay surface used here.
// Authorization rules hang off the hybrid connections client rather than having
// one of their own, and every call is synchronous — there is no PATCH verb, so an
// update is another CreateOrUpdate.
type relayHybridConnectionAuthRulesAPI interface {
	CreateOrUpdateAuthorizationRule(ctx context.Context, resourceGroupName string, namespaceName string, hybridConnectionName string, authorizationRuleName string, parameters armrelay.AuthorizationRule, options *armrelay.HybridConnectionsClientCreateOrUpdateAuthorizationRuleOptions) (armrelay.HybridConnectionsClientCreateOrUpdateAuthorizationRuleResponse, error)
	GetAuthorizationRule(ctx context.Context, resourceGroupName string, namespaceName string, hybridConnectionName string, authorizationRuleName string, options *armrelay.HybridConnectionsClientGetAuthorizationRuleOptions) (armrelay.HybridConnectionsClientGetAuthorizationRuleResponse, error)
	DeleteAuthorizationRule(ctx context.Context, resourceGroupName string, namespaceName string, hybridConnectionName string, authorizationRuleName string, options *armrelay.HybridConnectionsClientDeleteAuthorizationRuleOptions) (armrelay.HybridConnectionsClientDeleteAuthorizationRuleResponse, error)
	NewListAuthorizationRulesPager(resourceGroupName string, namespaceName string, hybridConnectionName string, options *armrelay.HybridConnectionsClientListAuthorizationRulesOptions) *runtime.Pager[armrelay.HybridConnectionsClientListAuthorizationRulesResponse]
}

func init() {
	registry.Register(ResourceTypeRelayHybridConnectionAuthorizationRule, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &RelayHybridConnectionAuthorizationRule{
			api:    c.RelayHybridConnectionsClient,
			config: cfg,
		}
	})
}

// RelayHybridConnectionAuthorizationRule is the provisioner for SAS rules scoped
// to a single Relay hybrid connection
// (Microsoft.Relay/namespaces/hybridConnections/authorizationRules).
//
// The rule's keys are never serialized: ARM returns them only from a separate
// ListKeys call, so putting them in resource state would persist live credentials.
type RelayHybridConnectionAuthorizationRule struct {
	api    relayHybridConnectionAuthRulesAPI
	config *config.Config
}

// relayHybridConnectionAuthRuleProps mirrors
// schema/pkl/relay/hybridconnectionauthorizationrule.pkl.
type relayHybridConnectionAuthRuleProps struct {
	Name                 string   `json:"name"`
	ResourceGroupName    string   `json:"resourceGroupName"`
	NamespaceName        string   `json:"namespaceName"`
	HybridConnectionName string   `json:"hybridConnectionName"`
	Rights               []string `json:"rights"`
}

func relayHybridConnectionAuthRuleIDParts(resourceID string) (rgName, namespaceName, hcName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "namespaces", "hybridconnections", "authorizationrules")
	if err != nil {
		return "", "", "", "", err
	}
	return rgName, names["namespaces"], names["hybridconnections"], names["authorizationrules"], nil
}

func (a *RelayHybridConnectionAuthorizationRule) buildPropertiesFromResult(rule *armrelay.AuthorizationRule, rgName, namespaceName, hcName string) map[string]any {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	props["namespaceName"] = namespaceName
	props["hybridConnectionName"] = hcName

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

func (a *RelayHybridConnectionAuthorizationRule) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props relayHybridConnectionAuthRuleProps
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	if props.NamespaceName == "" {
		return nil, fmt.Errorf("namespaceName is required")
	}
	if props.HybridConnectionName == "" {
		return nil, fmt.Errorf("hybridConnectionName is required")
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

	result, err := a.api.CreateOrUpdateAuthorizationRule(ctx, props.ResourceGroupName, props.NamespaceName,
		props.HybridConnectionName, name,
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
		props.ResourceGroupName, props.NamespaceName, props.HybridConnectionName))
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

func (a *RelayHybridConnectionAuthorizationRule) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, namespaceName, hcName, name, err := relayHybridConnectionAuthRuleIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := a.api.GetAuthorizationRule(ctx, rgName, namespaceName, hcName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(a.buildPropertiesFromResult(&result.AuthorizationRule, rgName, namespaceName, hcName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeRelayHybridConnectionAuthorizationRule,
		Properties:   string(propsJSON),
	}, nil
}

// Update re-PUTs through CreateOrUpdateAuthorizationRule: this API has no PATCH
// verb. rights is the only mutable property, so it is the only thing an update can
// carry.
func (a *RelayHybridConnectionAuthorizationRule) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, namespaceName, hcName, name, err := relayHybridConnectionAuthRuleIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props relayHybridConnectionAuthRuleProps
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	result, err := a.api.CreateOrUpdateAuthorizationRule(ctx, rgName, namespaceName, hcName, name,
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

	propsJSON, err := json.Marshal(a.buildPropertiesFromResult(&result.AuthorizationRule, rgName, namespaceName, hcName))
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

func (a *RelayHybridConnectionAuthorizationRule) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, namespaceName, hcName, name, err := relayHybridConnectionAuthRuleIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	if _, err := a.api.DeleteAuthorizationRule(ctx, rgName, namespaceName, hcName, name, nil); err != nil && !isDeleteSuccessError(err) {
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
func (a *RelayHybridConnectionAuthorizationRule) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

// List requires the resource group, the namespace and the hybrid connection: ARM
// has no listing above the connection scope.
func (a *RelayHybridConnectionAuthorizationRule) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	namespaceName := request.AdditionalProperties["namespaceName"]
	hcName := request.AdditionalProperties["hybridConnectionName"]
	if rgName == "" || namespaceName == "" || hcName == "" {
		return &resource.ListResult{}, nil
	}

	var nativeIDs []string
	pager := a.api.NewListAuthorizationRulesPager(rgName, namespaceName, hcName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list relay hybrid connection authorization rules: %w", err)
		}
		for _, rule := range page.Value {
			if rule.ID != nil {
				nativeIDs = append(nativeIDs, *rule.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
