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

func init() {
	registry.Register(ResourceTypeNetworkSecurityGroup, func(client *client.Client, cfg *config.Config) prov.Provisioner {
		return &NetworkSecurityGroup{client, cfg}
	})
}

// NetworkSecurityGroup is the provisioner for Azure Network Security Groups.
type NetworkSecurityGroup struct {
	Client *client.Client
	Config *config.Config
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

	poller, err := n.Client.SecurityGroupsClient.BeginCreateOrUpdate(ctx, rgName, nsgName, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,

				ErrorCode: mapAzureErrorToOperationErrorCode(err),
			},
		}, fmt.Errorf("failed to start NSG creation: %w", err)
	}

	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/networkSecurityGroups/%s",
		n.Config.SubscriptionId, rgName, nsgName)

	if poller.Done() {
		result, err := poller.Result(ctx)
		if err != nil {
			return &resource.CreateResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationCreate,
					OperationStatus: resource.OperationStatusFailure,

					ErrorCode: mapAzureErrorToOperationErrorCode(err),
				},
			}, fmt.Errorf("failed to get NSG create result: %w", err)
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

	reqID := lroRequestID{
		OperationType: "create",
		ResumeToken:   resumeToken,
		NativeID:      expectedNativeID,
	}
	reqIDJSON, err := json.Marshal(reqID)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request ID: %w", err)
	}

	return &resource.CreateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationCreate,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       string(reqIDJSON),
			NativeID:        expectedNativeID,
		},
	}, nil
}

func (n *NetworkSecurityGroup) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	parts := splitResourceID(request.NativeID)

	rgName, ok := parts["resourcegroups"]
	if !ok || rgName == "" {
		return nil, fmt.Errorf("invalid NativeID: could not extract resource group name from %s", request.NativeID)
	}

	nsgName, ok := parts["networksecuritygroups"]
	if !ok || nsgName == "" {
		return nil, fmt.Errorf("invalid NativeID: could not extract NSG name from %s", request.NativeID)
	}

	result, err := n.Client.SecurityGroupsClient.Get(ctx, rgName, nsgName, nil)
	if err != nil {
		return &resource.ReadResult{

			ErrorCode: mapAzureErrorToOperationErrorCode(err),
		}, fmt.Errorf("failed to read NSG: %w", err)
	}

	propsJSON, err := serializeNSGProperties(result.SecurityGroup, rgName, nsgName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize NSG properties: %w", err)
	}

	return &resource.ReadResult{

		Properties: string(propsJSON),
	}, nil
}

func (n *NetworkSecurityGroup) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	parts := splitResourceID(request.NativeID)

	rgName, ok := parts["resourcegroups"]
	if !ok || rgName == "" {
		return nil, fmt.Errorf("invalid NativeID: could not extract resource group name from %s", request.NativeID)
	}

	nsgName, ok := parts["networksecuritygroups"]
	if !ok || nsgName == "" {
		return nil, fmt.Errorf("invalid NativeID: could not extract NSG name from %s", request.NativeID)
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

	poller, err := n.Client.SecurityGroupsClient.BeginCreateOrUpdate(ctx, rgName, nsgName, params, nil)
	if err != nil {
		return &resource.UpdateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationUpdate,
				OperationStatus: resource.OperationStatusFailure,
				NativeID:        request.NativeID,

				ErrorCode: mapAzureErrorToOperationErrorCode(err),
			},
		}, fmt.Errorf("failed to start NSG update: %w", err)
	}

	if poller.Done() {
		result, err := poller.Result(ctx)
		if err != nil {
			return &resource.UpdateResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationUpdate,
					OperationStatus: resource.OperationStatusFailure,
					NativeID:        request.NativeID,

					ErrorCode: mapAzureErrorToOperationErrorCode(err),
				},
			}, fmt.Errorf("failed to get NSG update result: %w", err)
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

	reqID := lroRequestID{
		OperationType: "update",
		ResumeToken:   resumeToken,
		NativeID:      request.NativeID,
	}
	reqIDJSON, err := json.Marshal(reqID)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request ID: %w", err)
	}

	return &resource.UpdateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationUpdate,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       string(reqIDJSON),
			NativeID:        request.NativeID,
		},
	}, nil
}

func (n *NetworkSecurityGroup) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	parts := splitResourceID(request.NativeID)

	rgName, ok := parts["resourcegroups"]
	if !ok || rgName == "" {
		return nil, fmt.Errorf("invalid NativeID: could not extract resource group name from %s", request.NativeID)
	}

	nsgName, ok := parts["networksecuritygroups"]
	if !ok || nsgName == "" {
		return nil, fmt.Errorf("invalid NativeID: could not extract NSG name from %s", request.NativeID)
	}

	poller, err := n.Client.SecurityGroupsClient.BeginDelete(ctx, rgName, nsgName, nil)
	if err != nil {
		// If the resource is already gone (NotFound), treat as success
		if mapAzureErrorToOperationErrorCode(err) == resource.OperationErrorCodeNotFound {
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

				ErrorCode: mapAzureErrorToOperationErrorCode(err),
			},
		}, fmt.Errorf("failed to start NSG deletion: %w", err)
	}

	resumeToken, err := poller.ResumeToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get resume token: %w", err)
	}

	reqID := lroRequestID{
		OperationType: "delete",
		ResumeToken:   resumeToken,
		NativeID:      request.NativeID,
	}
	reqIDJSON, err := json.Marshal(reqID)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request ID: %w", err)
	}

	return &resource.DeleteResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationDelete,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       string(reqIDJSON),
			NativeID:        request.NativeID,
		},
	}, nil
}

func (n *NetworkSecurityGroup) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	var reqID lroRequestID
	if err := json.Unmarshal([]byte(request.RequestID), &reqID); err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,

				ErrorCode: resource.OperationErrorCodeGeneralServiceException,
			},
		}, fmt.Errorf("failed to parse request ID: %w", err)
	}

	switch reqID.OperationType {
	case "create", "update":
		return n.statusCreateOrUpdate(ctx, request, &reqID)
	case "delete":
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
	if reqID.OperationType == "update" {
		operation = resource.OperationUpdate
	}

	poller, err := n.Client.ResumeCreateSecurityGroupPoller(reqID.ResumeToken)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       operation,
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,

				ErrorCode: resource.OperationErrorCodeGeneralServiceException,
			},
		}, fmt.Errorf("failed to resume poller from token: %w", err)
	}

	if poller.Done() {
		return n.handleCreateOrUpdateComplete(ctx, request, reqID, poller, operation)
	}

	_, err = poller.Poll(ctx)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       operation,
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,

				ErrorCode: mapAzureErrorToOperationErrorCode(err),
			},
		}, nil
	}

	// Check if this poll revealed completion
	if poller.Done() {
		return n.handleCreateOrUpdateComplete(ctx, request, reqID, poller, operation)
	}

	// Still in progress - the next status check will determine if Done()
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       operation,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       request.RequestID,

			NativeID: reqID.NativeID,
		},
	}, nil
}

func (n *NetworkSecurityGroup) handleCreateOrUpdateComplete(ctx context.Context, request *resource.StatusRequest, _ *lroRequestID, poller *runtime.Poller[armnetwork.SecurityGroupsClientCreateOrUpdateResponse], operation resource.Operation) (*resource.StatusResult, error) {
	result, err := poller.Result(ctx)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       operation,
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,

				ErrorCode: mapAzureErrorToOperationErrorCode(err),
			},
		}, nil
	}

	parts := splitResourceID(*result.ID)
	rgName := parts["resourcegroups"]

	propsJSON, err := serializeNSGProperties(result.SecurityGroup, rgName, *result.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize NSG properties: %w", err)
	}

	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       operation,
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,

			NativeID:           *result.ID,
			ResourceProperties: propsJSON,
		},
	}, nil
}

func (n *NetworkSecurityGroup) statusDelete(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	poller, err := n.Client.ResumeDeleteSecurityGroupPoller(reqID.ResumeToken)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationDelete,
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,

				ErrorCode: resource.OperationErrorCodeGeneralServiceException,
			},
		}, fmt.Errorf("failed to resume poller from token: %w", err)
	}

	if poller.Done() {
		_, err := poller.Result(ctx)
		if err != nil {
			// NotFound means resource is already deleted - success
			if isDeleteSuccessError(err) {
				return &resource.StatusResult{
					ProgressResult: &resource.ProgressResult{
						Operation:       resource.OperationDelete,
						OperationStatus: resource.OperationStatusSuccess,
						RequestID:       request.RequestID,
						NativeID:        reqID.NativeID,
					},
				}, nil
			}
			return &resource.StatusResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationDelete,
					OperationStatus: resource.OperationStatusFailure,
					RequestID:       request.RequestID,
					ErrorCode:       mapAzureErrorToOperationErrorCode(err),
				},
			}, nil
		}
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationDelete,
				OperationStatus: resource.OperationStatusSuccess,
				RequestID:       request.RequestID,
				NativeID:        reqID.NativeID,
			},
		}, nil
	}

	_, err = poller.Poll(ctx)
	if err != nil {
		// NotFound means resource is already deleted - success
		if isDeleteSuccessError(err) {
			return &resource.StatusResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationDelete,
					OperationStatus: resource.OperationStatusSuccess,
					RequestID:       request.RequestID,
					NativeID:        reqID.NativeID,
				},
			}, nil
		}
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationDelete,
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       mapAzureErrorToOperationErrorCode(err),
			},
		}, nil
	}

	// Check if this poll revealed completion
	if poller.Done() {
		_, err := poller.Result(ctx)
		if err != nil {
			// NotFound means resource is already deleted - success
			if isDeleteSuccessError(err) {
				return &resource.StatusResult{
					ProgressResult: &resource.ProgressResult{
						Operation:       resource.OperationDelete,
						OperationStatus: resource.OperationStatusSuccess,
						RequestID:       request.RequestID,
						NativeID:        reqID.NativeID,
					},
				}, nil
			}
			return &resource.StatusResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationDelete,
					OperationStatus: resource.OperationStatusFailure,
					RequestID:       request.RequestID,
					ErrorCode:       mapAzureErrorToOperationErrorCode(err),
				},
			}, nil
		}
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationDelete,
				OperationStatus: resource.OperationStatusSuccess,
				RequestID:       request.RequestID,
				NativeID:        reqID.NativeID,
			},
		}, nil
	}

	// Still in progress - the next status check will determine if Done()
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationDelete,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       request.RequestID,

			NativeID: reqID.NativeID,
		},
	}, nil
}

func (n *NetworkSecurityGroup) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	resourceGroupName, ok := request.AdditionalProperties["resourceGroupName"]
	if !ok || resourceGroupName == "" {
		return nil, fmt.Errorf("resourceGroupName is required in AdditionalProperties for listing NetworkSecurityGroups")
	}

	pager := n.Client.SecurityGroupsClient.NewListPager(resourceGroupName, nil)

	var nativeIDs []string

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list network security groups in resource group %s: %w", resourceGroupName, err)
		}

		for _, nsg := range page.Value {
			if nsg.ID == nil {
				continue
			}

			nativeIDs = append(nativeIDs, *nsg.ID)
		}
	}

	return &resource.ListResult{

		NativeIDs: nativeIDs,
	}, nil
}
