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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/sql/armsql"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeSQLFirewallRule = "AZURE::Sql::FirewallRule"

// sqlFirewallRulesAPI is the subset of *armsql.FirewallRulesClient used here.
// SQL firewall rule operations are synchronous (no LRO/poller).
type sqlFirewallRulesAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName string, serverName string, firewallRuleName string, parameters armsql.FirewallRule, options *armsql.FirewallRulesClientCreateOrUpdateOptions) (armsql.FirewallRulesClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName string, serverName string, firewallRuleName string, options *armsql.FirewallRulesClientGetOptions) (armsql.FirewallRulesClientGetResponse, error)
	Delete(ctx context.Context, resourceGroupName string, serverName string, firewallRuleName string, options *armsql.FirewallRulesClientDeleteOptions) (armsql.FirewallRulesClientDeleteResponse, error)
	NewListByServerPager(resourceGroupName string, serverName string, options *armsql.FirewallRulesClientListByServerOptions) *runtime.Pager[armsql.FirewallRulesClientListByServerResponse]
}

func init() {
	registry.Register(ResourceTypeSQLFirewallRule, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &SqlFirewallRule{
			api:    c.SQLFirewallRulesClient,
			config: cfg,
		}
	})
}

// SqlFirewallRule is the provisioner for Azure SQL server firewall rules
// (Microsoft.Sql/servers/firewallRules). It is a child of AZURE::Sql::Server.
type SqlFirewallRule struct {
	api    sqlFirewallRulesAPI
	config *config.Config
}

func sqlFirewallRuleIDParts(resourceID string) (rgName, serverName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "servers", "firewallrules")
	if err != nil {
		return "", "", "", err
	}
	return rgName, names["servers"], names["firewallrules"], nil
}

// buildPropertiesFromResult extracts properties from a SQL FirewallRule Azure response.
func (f *SqlFirewallRule) buildPropertiesFromResult(rule *armsql.FirewallRule, rgName, serverName string) map[string]any {
	props := make(map[string]any)

	// createOnly properties
	props["resourceGroupName"] = rgName
	props["serverName"] = serverName

	if rule.Name != nil {
		props["name"] = *rule.Name
	}

	if rule.Properties != nil {
		if rule.Properties.StartIPAddress != nil {
			props["startIpAddress"] = *rule.Properties.StartIPAddress
		}
		if rule.Properties.EndIPAddress != nil {
			props["endIpAddress"] = *rule.Properties.EndIPAddress
		}
	}

	if rule.ID != nil {
		props["id"] = *rule.ID
	}

	return props
}

func (f *SqlFirewallRule) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props map[string]any
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	rgName, ok := props["resourceGroupName"].(string)
	if !ok || rgName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	serverName, ok := props["serverName"].(string)
	if !ok || serverName == "" {
		return nil, fmt.Errorf("serverName is required")
	}
	ruleName, ok := props["name"].(string)
	if !ok || ruleName == "" {
		ruleName = request.Label
	}
	startIP, ok := props["startIpAddress"].(string)
	if !ok || startIP == "" {
		return nil, fmt.Errorf("startIpAddress is required")
	}
	endIP, ok := props["endIpAddress"].(string)
	if !ok || endIP == "" {
		return nil, fmt.Errorf("endIpAddress is required")
	}

	params := armsql.FirewallRule{
		Properties: &armsql.ServerFirewallRuleProperties{
			StartIPAddress: to.Ptr(startIP),
			EndIPAddress:   to.Ptr(endIP),
		},
	}

	// SQL firewall rules are synchronous: CreateOrUpdate returns the result
	// immediately, so there is no LRO/Status polling.
	result, err := f.api.CreateOrUpdate(ctx, rgName, serverName, ruleName, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	responseProps := f.buildPropertiesFromResult(&result.FirewallRule, rgName, serverName)
	propsJSON, err := json.Marshal(responseProps)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}

	nativeID := ""
	if result.ID != nil {
		nativeID = *result.ID
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

func (f *SqlFirewallRule) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, serverName, ruleName, err := sqlFirewallRuleIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := f.api.Get(ctx, rgName, serverName, ruleName, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	responseProps := f.buildPropertiesFromResult(&result.FirewallRule, rgName, serverName)
	propsJSON, err := json.Marshal(responseProps)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}

	return &resource.ReadResult{
		ResourceType: ResourceTypeSQLFirewallRule,
		Properties:   string(propsJSON),
	}, nil
}

func (f *SqlFirewallRule) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, serverName, ruleName, err := sqlFirewallRuleIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props map[string]any
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	startIP, ok := props["startIpAddress"].(string)
	if !ok || startIP == "" {
		return nil, fmt.Errorf("startIpAddress is required")
	}
	endIP, ok := props["endIpAddress"].(string)
	if !ok || endIP == "" {
		return nil, fmt.Errorf("endIpAddress is required")
	}

	params := armsql.FirewallRule{
		Properties: &armsql.ServerFirewallRuleProperties{
			StartIPAddress: to.Ptr(startIP),
			EndIPAddress:   to.Ptr(endIP),
		},
	}

	// Synchronous: CreateOrUpdate is idempotent and returns immediately.
	result, err := f.api.CreateOrUpdate(ctx, rgName, serverName, ruleName, params, nil)
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

	responseProps := f.buildPropertiesFromResult(&result.FirewallRule, rgName, serverName)
	propsJSON, err := json.Marshal(responseProps)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}

	nativeID := request.NativeID
	if result.ID != nil {
		nativeID = *result.ID
	}

	return &resource.UpdateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:          resource.OperationUpdate,
			OperationStatus:    resource.OperationStatusSuccess,
			NativeID:           nativeID,
			ResourceProperties: propsJSON,
		},
	}, nil
}

func (f *SqlFirewallRule) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, serverName, ruleName, err := sqlFirewallRuleIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	// Synchronous delete: returns immediately. NotFound means already gone.
	_, err = f.api.Delete(ctx, rgName, serverName, ruleName, nil)
	if err != nil {
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

// Status is a no-op success passthrough: SQL firewall rule operations are
// synchronous, so Create/Update/Delete never return InProgress. It exists only
// to satisfy the Provisioner interface.
func (f *SqlFirewallRule) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

func (f *SqlFirewallRule) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	serverName := request.AdditionalProperties["serverName"]

	var nativeIDs []string

	pager := f.api.NewListByServerPager(rgName, serverName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list sql firewall rules for server %s: %w", serverName, err)
		}
		for _, rule := range page.Value {
			if rule.ID != nil {
				nativeIDs = append(nativeIDs, *rule.ID)
			}
		}
	}

	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
