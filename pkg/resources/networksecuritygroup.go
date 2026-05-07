// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v4"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeNetworkSecurityGroup = "Azure::Network::NetworkSecurityGroup"

type networkSecurityGroupsAPI interface {
	BeginCreateOrUpdate(ctx context.Context, resourceGroupName string, networkSecurityGroupName string, parameters armnetwork.SecurityGroup, options *armnetwork.SecurityGroupsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.SecurityGroupsClientCreateOrUpdateResponse], error)
	Get(ctx context.Context, resourceGroupName string, networkSecurityGroupName string, options *armnetwork.SecurityGroupsClientGetOptions) (armnetwork.SecurityGroupsClientGetResponse, error)
	BeginDelete(ctx context.Context, resourceGroupName string, networkSecurityGroupName string, options *armnetwork.SecurityGroupsClientBeginDeleteOptions) (*runtime.Poller[armnetwork.SecurityGroupsClientDeleteResponse], error)
	NewListPager(resourceGroupName string, options *armnetwork.SecurityGroupsClientListOptions) *runtime.Pager[armnetwork.SecurityGroupsClientListResponse]
	NewListAllPager(options *armnetwork.SecurityGroupsClientListAllOptions) *runtime.Pager[armnetwork.SecurityGroupsClientListAllResponse]
}

func init() {
	registry.Register(ResourceTypeNetworkSecurityGroup, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &NetworkSecurityGroup{
			api:      c.SecurityGroupsClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// NetworkSecurityGroup is the provisioner for Azure Network Security Groups.
type NetworkSecurityGroup struct {
	api      networkSecurityGroupsAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

// serializeNSGProperties converts an Azure NetworkSecurityGroup to Formae property format
func serializeNSGProperties(result armnetwork.SecurityGroup, rgName, nsgName string) (json.RawMessage, error) {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	if result.Name != nil {
		props["name"] = *result.Name
	} else {
		props["name"] = nsgName
	}

	if result.Location != nil {
		props["location"] = *result.Location
	}

	// Include id for resolvable references
	if result.ID != nil {
		props["id"] = *result.ID
	}

	// Add security rules
	if result.Properties != nil && result.Properties.SecurityRules != nil {
		rules := make([]map[string]any, 0)
		for _, rule := range result.Properties.SecurityRules {
			if rule == nil {
				continue
			}
			ruleMap := make(map[string]any)
			if rule.Name != nil {
				ruleMap["name"] = *rule.Name
			}
			if rule.Properties != nil {
				if rule.Properties.Description != nil {
					ruleMap["description"] = *rule.Properties.Description
				}
				if rule.Properties.Priority != nil {
					ruleMap["priority"] = *rule.Properties.Priority
				}
				if rule.Properties.Direction != nil {
					ruleMap["direction"] = string(*rule.Properties.Direction)
				}
				if rule.Properties.Access != nil {
					ruleMap["access"] = string(*rule.Properties.Access)
				}
				if rule.Properties.Protocol != nil {
					ruleMap["protocol"] = string(*rule.Properties.Protocol)
				}
				if rule.Properties.SourcePortRange != nil {
					ruleMap["sourcePortRange"] = *rule.Properties.SourcePortRange
				}
				if rule.Properties.DestinationPortRange != nil {
					ruleMap["destinationPortRange"] = *rule.Properties.DestinationPortRange
				}
				if rule.Properties.SourceAddressPrefix != nil {
					ruleMap["sourceAddressPrefix"] = *rule.Properties.SourceAddressPrefix
				}
				if rule.Properties.DestinationAddressPrefix != nil {
					ruleMap["destinationAddressPrefix"] = *rule.Properties.DestinationAddressPrefix
				}
			}
			rules = append(rules, ruleMap)
		}
		if len(rules) > 0 {
			props["securityRules"] = rules
		}
	}

	// Add tags
	if tags := azureTagsToFormaeTags(result.Tags); tags != nil {
		props["Tags"] = tags
	}

	return json.Marshal(props)
}

func parseNetworkSecurityGroupNativeID(nativeID string) (rgName, nsgName string, err error) {
	rgName, names, err := armIDParts(nativeID, "networksecuritygroups")
	if err != nil {
		return "", "", err
	}
	return rgName, names["networksecuritygroups"], nil
}

func (n *NetworkSecurityGroup) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props map[string]any
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	rgName, ok := props["resourceGroupName"].(string)
	if !ok || rgName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}

	location, ok := props["location"].(string)
	if !ok || location == "" {
		return nil, fmt.Errorf("location is required")
	}

	nsgName, ok := props["name"].(string)
	if !ok || nsgName == "" {
		nsgName = request.Label
	}

	params := armnetwork.SecurityGroup{
		Location: stringPtr(location),
	}

	// Parse security rules if present
	if rulesRaw, ok := props["securityRules"].([]any); ok && len(rulesRaw) > 0 {
		rules := make([]*armnetwork.SecurityRule, 0, len(rulesRaw))
		for i, ruleRaw := range rulesRaw {
			ruleMap, ok := ruleRaw.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("securityRules[%d] must be an object", i)
			}

			rule := &armnetwork.SecurityRule{
				Properties: &armnetwork.SecurityRulePropertiesFormat{},
			}

			if name, ok := ruleMap["name"].(string); ok {
				rule.Name = stringPtr(name)
			}
			if desc, ok := ruleMap["description"].(string); ok {
				rule.Properties.Description = stringPtr(desc)
			}
			if priority, ok := ruleMap["priority"].(float64); ok {
				p := int32(priority)
				rule.Properties.Priority = &p
			}
			if direction, ok := ruleMap["direction"].(string); ok {
				d := armnetwork.SecurityRuleDirection(direction)
				rule.Properties.Direction = &d
			}
			if access, ok := ruleMap["access"].(string); ok {
				a := armnetwork.SecurityRuleAccess(access)
				rule.Properties.Access = &a
			}
			if protocol, ok := ruleMap["protocol"].(string); ok {
				p := armnetwork.SecurityRuleProtocol(protocol)
				rule.Properties.Protocol = &p
			}
			if src, ok := ruleMap["sourcePortRange"].(string); ok {
				rule.Properties.SourcePortRange = stringPtr(src)
			}
			if dst, ok := ruleMap["destinationPortRange"].(string); ok {
				rule.Properties.DestinationPortRange = stringPtr(dst)
			}
			if srcAddr, ok := ruleMap["sourceAddressPrefix"].(string); ok {
				rule.Properties.SourceAddressPrefix = stringPtr(srcAddr)
			}
			if dstAddr, ok := ruleMap["destinationAddressPrefix"].(string); ok {
				rule.Properties.DestinationAddressPrefix = stringPtr(dstAddr)
			}

			rules = append(rules, rule)
		}
		params.Properties = &armnetwork.SecurityGroupPropertiesFormat{
			SecurityRules: rules,
		}
	}

	if azureTags := formaeTagsToAzureTags(request.Properties); azureTags != nil {
		params.Tags = azureTags
	}

	poller, err := n.api.BeginCreateOrUpdate(ctx, rgName, nsgName, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,

				ErrorCode: operationErrorCode(err),
			},
		}, nil
	}

	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/networkSecurityGroups/%s",
		n.config.SubscriptionId, rgName, nsgName)

	if poller.Done() {
		result, err := poller.Result(ctx)
		if err != nil {
			return &resource.CreateResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationCreate,
					OperationStatus: resource.OperationStatusFailure,

					ErrorCode: operationErrorCode(err),
				},
			}, nil
		}

		propsJSON, err := serializeNSGProperties(result.SecurityGroup, rgName, nsgName)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize NSG properties: %w", err)
		}

		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusSuccess,
				NativeID:        *result.ID,

				ResourceProperties: propsJSON,
			},
		}, nil
	}

	resumeToken, err := poller.ResumeToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get resume token: %w", err)
	}

	reqIDJSON, err := encodeLROStart(lroOpCreate, resumeToken, expectedNativeID)
	if err != nil {
		return nil, err
	}

	return &resource.CreateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationCreate,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       reqIDJSON,
			NativeID:        expectedNativeID,
		},
	}, nil
}

func (n *NetworkSecurityGroup) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, nsgName, err := parseNetworkSecurityGroupNativeID(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := n.api.Get(ctx, rgName, nsgName, nil)
	if err != nil {
		return &resource.ReadResult{

			ErrorCode: operationErrorCode(err),
		}, nil
	}

	propsJSON, err := serializeNSGProperties(result.SecurityGroup, rgName, nsgName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize NSG properties: %w", err)
	}

	return &resource.ReadResult{
		ResourceType: ResourceTypeNetworkSecurityGroup,
		Properties:   string(propsJSON),
	}, nil
}

func (n *NetworkSecurityGroup) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, nsgName, err := parseNetworkSecurityGroupNativeID(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props map[string]any
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	location, ok := props["location"].(string)
	if !ok || location == "" {
		return nil, fmt.Errorf("location is required")
	}

	params := armnetwork.SecurityGroup{
		Location: stringPtr(location),
	}

	// Parse security rules if present
	if rulesRaw, ok := props["securityRules"].([]any); ok && len(rulesRaw) > 0 {
		rules := make([]*armnetwork.SecurityRule, 0, len(rulesRaw))
		for i, ruleRaw := range rulesRaw {
			ruleMap, ok := ruleRaw.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("securityRules[%d] must be an object", i)
			}

			rule := &armnetwork.SecurityRule{
				Properties: &armnetwork.SecurityRulePropertiesFormat{},
			}

			if name, ok := ruleMap["name"].(string); ok {
				rule.Name = stringPtr(name)
			}
			if desc, ok := ruleMap["description"].(string); ok {
				rule.Properties.Description = stringPtr(desc)
			}
			if priority, ok := ruleMap["priority"].(float64); ok {
				p := int32(priority)
				rule.Properties.Priority = &p
			}
			if direction, ok := ruleMap["direction"].(string); ok {
				d := armnetwork.SecurityRuleDirection(direction)
				rule.Properties.Direction = &d
			}
			if access, ok := ruleMap["access"].(string); ok {
				a := armnetwork.SecurityRuleAccess(access)
				rule.Properties.Access = &a
			}
			if protocol, ok := ruleMap["protocol"].(string); ok {
				p := armnetwork.SecurityRuleProtocol(protocol)
				rule.Properties.Protocol = &p
			}
			if src, ok := ruleMap["sourcePortRange"].(string); ok {
				rule.Properties.SourcePortRange = stringPtr(src)
			}
			if dst, ok := ruleMap["destinationPortRange"].(string); ok {
				rule.Properties.DestinationPortRange = stringPtr(dst)
			}
			if srcAddr, ok := ruleMap["sourceAddressPrefix"].(string); ok {
				rule.Properties.SourceAddressPrefix = stringPtr(srcAddr)
			}
			if dstAddr, ok := ruleMap["destinationAddressPrefix"].(string); ok {
				rule.Properties.DestinationAddressPrefix = stringPtr(dstAddr)
			}

			rules = append(rules, rule)
		}
		params.Properties = &armnetwork.SecurityGroupPropertiesFormat{
			SecurityRules: rules,
		}
	}

	if azureTags := formaeTagsToAzureTags(request.DesiredProperties); azureTags != nil {
		params.Tags = azureTags
	}

	poller, err := n.api.BeginCreateOrUpdate(ctx, rgName, nsgName, params, nil)
	if err != nil {
		return &resource.UpdateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationUpdate,
				OperationStatus: resource.OperationStatusFailure,
				NativeID:        request.NativeID,

				ErrorCode: operationErrorCode(err),
			},
		}, nil
	}

	if poller.Done() {
		result, err := poller.Result(ctx)
		if err != nil {
			return &resource.UpdateResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationUpdate,
					OperationStatus: resource.OperationStatusFailure,
					NativeID:        request.NativeID,

					ErrorCode: operationErrorCode(err),
				},
			}, nil
		}

		propsJSON, err := serializeNSGProperties(result.SecurityGroup, rgName, nsgName)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize NSG properties: %w", err)
		}

		return &resource.UpdateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationUpdate,
				OperationStatus: resource.OperationStatusSuccess,
				NativeID:        *result.ID,

				ResourceProperties: propsJSON,
			},
		}, nil
	}

	resumeToken, err := poller.ResumeToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get resume token: %w", err)
	}

	reqIDJSON, err := encodeLROStart(lroOpUpdate, resumeToken, request.NativeID)
	if err != nil {
		return nil, err
	}

	return &resource.UpdateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationUpdate,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       reqIDJSON,
			NativeID:        request.NativeID,
		},
	}, nil
}

func (n *NetworkSecurityGroup) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, nsgName, err := parseNetworkSecurityGroupNativeID(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, err := n.api.BeginDelete(ctx, rgName, nsgName, nil)
	if err != nil {
		// If the resource is already gone (NotFound), treat as success
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

				ErrorCode: operationErrorCode(err),
			},
		}, fmt.Errorf("failed to start NSG deletion: %w", err)
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

func (n *NetworkSecurityGroup) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	reqID, err := decodeLROStatus(request.RequestID)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,

				ErrorCode: resource.OperationErrorCodeGeneralServiceException,
			},
		}, err
	}

	switch reqID.OperationType {
	case lroOpCreate, lroOpUpdate:
		return n.statusCreateOrUpdate(ctx, request, &reqID)
	case lroOpDelete:
		return n.statusDelete(ctx, request, &reqID)
	default:
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,

				ErrorCode: resource.OperationErrorCodeGeneralServiceException,
			},
		}, fmt.Errorf("unknown operation type: %s", reqID.OperationType)
	}
}

func (n *NetworkSecurityGroup) statusCreateOrUpdate(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	operation := resource.OperationCreate
	if reqID.OperationType == lroOpUpdate {
		operation = resource.OperationUpdate
	}

	return statusLRO(ctx, request, reqID, operation,
		func(token string) (*runtime.Poller[armnetwork.SecurityGroupsClientCreateOrUpdateResponse], error) {
			return resumePoller[armnetwork.SecurityGroupsClientCreateOrUpdateResponse](n.pipeline, token)
		},
		func(_ context.Context, result armnetwork.SecurityGroupsClientCreateOrUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
			rgName, nsgName, err := parseNetworkSecurityGroupNativeID(*result.ID)
			if err != nil {
				return "", nil, err
			}
			propsJSON, err := serializeNSGProperties(result.SecurityGroup, rgName, nsgName)
			if err != nil {
				return "", nil, fmt.Errorf("failed to serialize NSG properties: %w", err)
			}
			return *result.ID, propsJSON, nil
		})
}

func (n *NetworkSecurityGroup) statusDelete(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	return statusDeleteLRO(ctx, request, reqID,
		func(token string) (*runtime.Poller[armnetwork.SecurityGroupsClientDeleteResponse], error) {
			return resumePoller[armnetwork.SecurityGroupsClientDeleteResponse](n.pipeline, token)
		}, nil)
}

func (n *NetworkSecurityGroup) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	resourceGroupName := request.AdditionalProperties["resourceGroupName"]

	var nativeIDs []string

	if resourceGroupName != "" {
		pager := n.api.NewListPager(resourceGroupName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list network security groups: %w", err)
			}
			for _, nsg := range page.Value {
				if nsg.ID != nil {
					nativeIDs = append(nativeIDs, *nsg.ID)
				}
			}
		}
	} else {
		pager := n.api.NewListAllPager(nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list network security groups: %w", err)
			}
			for _, nsg := range page.Value {
				if nsg.ID != nil {
					nativeIDs = append(nativeIDs, *nsg.ID)
				}
			}
		}
	}

	return &resource.ListResult{
		NativeIDs: nativeIDs,
	}, nil
}
