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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/servicebus/armservicebus"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeServiceBusAuthorizationRule = "AZURE::ServiceBus::AuthorizationRule"

// serviceBusAuthorizationRulesAPI is the armservicebus surface used here. The
// authorization-rule operations hang off NamespacesClient and are all synchronous.
type serviceBusAuthorizationRulesAPI interface {
	CreateOrUpdateAuthorizationRule(ctx context.Context, resourceGroupName, namespaceName, authorizationRuleName string, parameters armservicebus.SBAuthorizationRule, options *armservicebus.NamespacesClientCreateOrUpdateAuthorizationRuleOptions) (armservicebus.NamespacesClientCreateOrUpdateAuthorizationRuleResponse, error)
	GetAuthorizationRule(ctx context.Context, resourceGroupName, namespaceName, authorizationRuleName string, options *armservicebus.NamespacesClientGetAuthorizationRuleOptions) (armservicebus.NamespacesClientGetAuthorizationRuleResponse, error)
	DeleteAuthorizationRule(ctx context.Context, resourceGroupName, namespaceName, authorizationRuleName string, options *armservicebus.NamespacesClientDeleteAuthorizationRuleOptions) (armservicebus.NamespacesClientDeleteAuthorizationRuleResponse, error)
	NewListAuthorizationRulesPager(resourceGroupName, namespaceName string, options *armservicebus.NamespacesClientListAuthorizationRulesOptions) *runtime.Pager[armservicebus.NamespacesClientListAuthorizationRulesResponse]
}

func init() {
	registry.Register(ResourceTypeServiceBusAuthorizationRule, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &ServiceBusAuthorizationRule{api: c.ServiceBusNamespacesClient, config: cfg}
	})
}

// ServiceBusAuthorizationRule provisions namespace-scoped SAS policies
// (Microsoft.ServiceBus/namespaces/<ns>/AuthorizationRules/<name>).
//
// The keys this rule mints are deliberately never serialized: ARM only returns
// them from a separate ListKeys call, so putting them in resource state would
// persist live credentials.
type ServiceBusAuthorizationRule struct {
	api    serviceBusAuthorizationRulesAPI
	config *config.Config
}

// serviceBusAuthorizationRuleProps mirrors
// schema/pkl/servicebus/servicebusauthorizationrule.pkl.
type serviceBusAuthorizationRuleProps struct {
	Name          string   `json:"name"`
	ResourceGroup string   `json:"resourceGroupName"`
	NamespaceName string   `json:"namespaceName"`
	Rights        []string `json:"rights"`
}

func serviceBusAuthorizationRuleIDParts(resourceID string) (rgName, namespaceName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "namespaces", "authorizationrules")
	if err != nil {
		return "", "", "", err
	}
	return rgName, names["namespaces"], names["authorizationrules"], nil
}

func serializeServiceBusAuthorizationRule(rule armservicebus.SBAuthorizationRule, rgName, namespaceName, name string) (json.RawMessage, error) {
	props := map[string]any{
		"resourceGroupName": rgName,
		"namespaceName":     namespaceName,
		"name":              name,
	}
	if rule.Name != nil {
		props["name"] = *rule.Name
	}
	if rule.ID != nil {
		props["id"] = *rule.ID
	}
	if rule.Properties != nil {
		rights := make([]string, 0, len(rule.Properties.Rights))
		for _, r := range rule.Properties.Rights {
			if r != nil {
				rights = append(rights, string(*r))
			}
		}
		props["rights"] = rights
	}
	return json.Marshal(props)
}

func serviceBusAuthorizationRuleParams(rights []string) armservicebus.SBAuthorizationRule {
	accessRights := make([]*armservicebus.AccessRights, 0, len(rights))
	for _, r := range rights {
		accessRights = append(accessRights, to.Ptr(armservicebus.AccessRights(r)))
	}
	return armservicebus.SBAuthorizationRule{
		Properties: &armservicebus.SBAuthorizationRuleProperties{Rights: accessRights},
	}
}

func (a *ServiceBusAuthorizationRule) upsert(ctx context.Context, payload json.RawMessage, label string) (armservicebus.SBAuthorizationRule, string, string, string, error) {
	var props serviceBusAuthorizationRuleProps
	if err := json.Unmarshal(payload, &props); err != nil {
		return armservicebus.SBAuthorizationRule{}, "", "", "", fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroup == "" {
		return armservicebus.SBAuthorizationRule{}, "", "", "", fmt.Errorf("resourceGroupName is required")
	}
	if props.NamespaceName == "" {
		return armservicebus.SBAuthorizationRule{}, "", "", "", fmt.Errorf("namespaceName is required")
	}
	if len(props.Rights) == 0 {
		return armservicebus.SBAuthorizationRule{}, "", "", "", fmt.Errorf("at least one right is required")
	}
	name := props.Name
	if name == "" {
		name = label
	}
	if name == "" {
		return armservicebus.SBAuthorizationRule{}, "", "", "", fmt.Errorf("name is required")
	}

	result, err := a.api.CreateOrUpdateAuthorizationRule(ctx, props.ResourceGroup, props.NamespaceName, name,
		serviceBusAuthorizationRuleParams(props.Rights), nil)
	if err != nil {
		return armservicebus.SBAuthorizationRule{}, props.ResourceGroup, props.NamespaceName, name, err
	}
	return result.SBAuthorizationRule, props.ResourceGroup, props.NamespaceName, name, nil
}

func (a *ServiceBusAuthorizationRule) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	rule, rgName, namespaceName, name, err := a.upsert(ctx, request.Properties, request.Label)
	if err != nil {
		if rgName == "" || namespaceName == "" || name == "" {
			return nil, err
		}
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	propsJSON, err := serializeServiceBusAuthorizationRule(rule, rgName, namespaceName, name)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize AuthorizationRule properties: %w", err)
	}

	nativeID := ""
	if rule.ID != nil {
		nativeID = *rule.ID
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

func (a *ServiceBusAuthorizationRule) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, namespaceName, name, err := serviceBusAuthorizationRuleIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := a.api.GetAuthorizationRule(ctx, rgName, namespaceName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := serializeServiceBusAuthorizationRule(result.SBAuthorizationRule, rgName, namespaceName, name)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize AuthorizationRule properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeServiceBusAuthorizationRule,
		Properties:   string(propsJSON),
	}, nil
}

// Update is the same CreateOrUpdate call: ARM replaces the rights list wholesale.
func (a *ServiceBusAuthorizationRule) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rule, rgName, namespaceName, name, err := a.upsert(ctx, request.DesiredProperties, "")
	if err != nil {
		if rgName == "" || namespaceName == "" || name == "" {
			return nil, err
		}
		return &resource.UpdateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationUpdate,
				OperationStatus: resource.OperationStatusFailure,
				NativeID:        request.NativeID,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	propsJSON, err := serializeServiceBusAuthorizationRule(rule, rgName, namespaceName, name)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize AuthorizationRule properties after update: %w", err)
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

func (a *ServiceBusAuthorizationRule) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, namespaceName, name, err := serviceBusAuthorizationRuleIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	if _, err := a.api.DeleteAuthorizationRule(ctx, rgName, namespaceName, name, nil); err != nil {
		if operationErrorCode(err) == resource.OperationErrorCodeNotFound {
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

	return &resource.DeleteResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationDelete,
			OperationStatus: resource.OperationStatusSuccess,
			NativeID:        request.NativeID,
		},
	}, nil
}

// Authorization-rule writes are synchronous, so Status just re-reads.
func (a *ServiceBusAuthorizationRule) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	rgName, namespaceName, name, err := serviceBusAuthorizationRuleIDParts(request.NativeID)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
			},
		}, err
	}

	result, err := a.api.GetAuthorizationRule(ctx, rgName, namespaceName, name, nil)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       operationErrorCode(err),
			},
		}, fmt.Errorf("failed to get AuthorizationRule status: %w", err)
	}

	propsJSON, err := serializeServiceBusAuthorizationRule(result.SBAuthorizationRule, rgName, namespaceName, name)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize AuthorizationRule properties: %w", err)
	}
	nativeID := request.NativeID
	if result.ID != nil {
		nativeID = *result.ID
	}
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus:    resource.OperationStatusSuccess,
			RequestID:          request.RequestID,
			NativeID:           nativeID,
			ResourceProperties: propsJSON,
		},
	}, nil
}

// List is scoped to one namespace via AdditionalProperties. The built-in
// RootManageSharedAccessKey rule that every namespace ships with is filtered out:
// it is created implicitly by Azure, so importing it would hand formae a resource
// it can neither have created nor safely delete.
func (a *ServiceBusAuthorizationRule) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
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
			return nil, fmt.Errorf("failed to list ServiceBus authorization rules: %w", err)
		}
		for _, rule := range page.Value {
			if rule.ID == nil {
				continue
			}
			if rule.Name != nil && *rule.Name == "RootManageSharedAccessKey" {
				continue
			}
			nativeIDs = append(nativeIDs, *rule.ID)
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
