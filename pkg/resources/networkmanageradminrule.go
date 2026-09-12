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

const ResourceTypeNetworkManagerAdminRule = "AZURE::Network::NetworkManagerAdminRule"

// networkManagerAdminRulesAPI is the armnetwork.AdminRulesClient surface used here.
//
// The verbs are polymorphic: they take and return BaseAdminRuleClassification,
// which is either *armnetwork.AdminRule (kind Custom) or
// *armnetwork.DefaultAdminRule (kind Default). CreateOrUpdate doubles as the
// update verb and is synchronous; only Delete is an LRO.
type networkManagerAdminRulesAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName string, networkManagerName string, configurationName string, ruleCollectionName string, ruleName string, adminRule armnetwork.BaseAdminRuleClassification, options *armnetwork.AdminRulesClientCreateOrUpdateOptions) (armnetwork.AdminRulesClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName string, networkManagerName string, configurationName string, ruleCollectionName string, ruleName string, options *armnetwork.AdminRulesClientGetOptions) (armnetwork.AdminRulesClientGetResponse, error)
	BeginDelete(ctx context.Context, resourceGroupName string, networkManagerName string, configurationName string, ruleCollectionName string, ruleName string, options *armnetwork.AdminRulesClientBeginDeleteOptions) (*runtime.Poller[armnetwork.AdminRulesClientDeleteResponse], error)
	NewListPager(resourceGroupName string, networkManagerName string, configurationName string, ruleCollectionName string, options *armnetwork.AdminRulesClientListOptions) *runtime.Pager[armnetwork.AdminRulesClientListResponse]
}

func init() {
	registry.Register(ResourceTypeNetworkManagerAdminRule, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &NetworkManagerAdminRule{
			api:      c.NetworkManagerAdminRulesClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// NetworkManagerAdminRule is the provisioner for security admin rules
// (Microsoft.Network/networkManagers/securityAdminConfigurations/ruleCollections
// /rules).
//
// Only CUSTOM rules are managed. ARM's rules endpoint is polymorphic on a
// resource-level `kind` discriminator: `Default` rules are the service-authored
// baseline a collection gains on its own, every field of them is read-only, and
// they cannot be created. This provisioner always sends `Custom`, filters
// `Default` rules out of List, and refuses to read one back rather than
// presenting a service-owned rule as managed desired state.
type NetworkManagerAdminRule struct {
	api      networkManagerAdminRulesAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

// adminRuleAddressPrefixProps mirrors the AdminRuleAddressPrefix class in
// schema/pkl/network/networkmanageradminrule.pkl.
type adminRuleAddressPrefixProps struct {
	AddressPrefix     string `json:"addressPrefix"`
	AddressPrefixType string `json:"addressPrefixType"`
}

// networkManagerAdminRuleProps mirrors
// schema/pkl/network/networkmanageradminrule.pkl.
type networkManagerAdminRuleProps struct {
	Name                           string                        `json:"name"`
	ResourceGroupName              string                        `json:"resourceGroupName"`
	NetworkManagerName             string                        `json:"networkManagerName"`
	SecurityAdminConfigurationName string                        `json:"securityAdminConfigurationName"`
	RuleCollectionName             string                        `json:"ruleCollectionName"`
	Access                         string                        `json:"access"`
	Direction                      string                        `json:"direction"`
	Priority                       *int32                        `json:"priority"`
	Protocol                       string                        `json:"protocol"`
	Sources                        []adminRuleAddressPrefixProps `json:"sources"`
	Destinations                   []adminRuleAddressPrefixProps `json:"destinations"`
	SourcePortRanges               []string                      `json:"sourcePortRanges"`
	DestinationPortRanges          []string                      `json:"destinationPortRanges"`
	Description                    *string                       `json:"description"`
}

func networkManagerAdminRuleIDParts(resourceID string) (rgName, managerName, configName, collectionName, name string, err error) {
	rgName, names, err := armIDParts(resourceID,
		"networkmanagers", "securityadminconfigurations", "rulecollections", "rules")
	if err != nil {
		return "", "", "", "", "", err
	}
	return rgName, names["networkmanagers"], names["securityadminconfigurations"],
		names["rulecollections"], names["rules"], nil
}

// customAdminRule narrows a polymorphic response to the Custom variant.
//
// A Default rule is service-authored and entirely read-only, so surfacing one as
// managed state would show as unfixable drift forever; saying so plainly is more
// useful than half-populating the schema.
func customAdminRule(rule armnetwork.BaseAdminRuleClassification) (*armnetwork.AdminRule, error) {
	switch typed := rule.(type) {
	case nil:
		return nil, fmt.Errorf("admin rule response carried no rule")
	case *armnetwork.AdminRule:
		if typed == nil {
			return nil, fmt.Errorf("admin rule response carried no rule")
		}
		return typed, nil
	case *armnetwork.DefaultAdminRule:
		return nil, fmt.Errorf("admin rule is a Default rule: default rules are created and owned by the service and cannot be managed")
	default:
		return nil, fmt.Errorf("unexpected admin rule kind %T", rule)
	}
}

// buildAdminRuleAddressPrefixes maps the schema's address-prefix list onto ARM's.
func buildAdminRuleAddressPrefixes(field string, entries []adminRuleAddressPrefixProps) ([]*armnetwork.AddressPrefixItem, error) {
	if len(entries) == 0 {
		return nil, nil
	}
	out := make([]*armnetwork.AddressPrefixItem, 0, len(entries))
	for i := range entries {
		if entries[i].AddressPrefix == "" {
			return nil, fmt.Errorf("%s.addressPrefix is required", field)
		}
		if entries[i].AddressPrefixType == "" {
			return nil, fmt.Errorf("%s.addressPrefixType is required", field)
		}
		out = append(out, &armnetwork.AddressPrefixItem{
			AddressPrefix:     to.Ptr(entries[i].AddressPrefix),
			AddressPrefixType: to.Ptr(armnetwork.AddressPrefixType(entries[i].AddressPrefixType)),
		})
	}
	return out, nil
}

// adminRuleAddressPrefixProperties is the read-path inverse.
func adminRuleAddressPrefixProperties(entries []*armnetwork.AddressPrefixItem) []map[string]any {
	if len(entries) == 0 {
		return nil
	}
	out := make([]map[string]any, 0, len(entries))
	for _, entry := range entries {
		if entry == nil {
			continue
		}
		item := make(map[string]any)
		if entry.AddressPrefix != nil {
			item["addressPrefix"] = *entry.AddressPrefix
		}
		if entry.AddressPrefixType != nil {
			item["addressPrefixType"] = canonicalizeEnum(string(*entry.AddressPrefixType), "IPPrefix", "ServiceTag")
		}
		out = append(out, item)
	}
	return out
}

func buildAdminRuleParams(props *networkManagerAdminRuleProps) (*armnetwork.AdminRule, error) {
	if props.Access == "" {
		return nil, fmt.Errorf("access is required")
	}
	if props.Direction == "" {
		return nil, fmt.Errorf("direction is required")
	}
	if props.Priority == nil {
		return nil, fmt.Errorf("priority is required")
	}
	if props.Protocol == "" {
		return nil, fmt.Errorf("protocol is required")
	}

	ruleProps := &armnetwork.AdminPropertiesFormat{
		Access:    to.Ptr(armnetwork.SecurityConfigurationRuleAccess(props.Access)),
		Direction: to.Ptr(armnetwork.SecurityConfigurationRuleDirection(props.Direction)),
		Priority:  to.Ptr(*props.Priority),
		Protocol:  to.Ptr(armnetwork.SecurityConfigurationRuleProtocol(props.Protocol)),
	}

	sources, err := buildAdminRuleAddressPrefixes("sources", props.Sources)
	if err != nil {
		return nil, err
	}
	ruleProps.Sources = sources

	destinations, err := buildAdminRuleAddressPrefixes("destinations", props.Destinations)
	if err != nil {
		return nil, err
	}
	ruleProps.Destinations = destinations

	if len(props.SourcePortRanges) > 0 {
		ruleProps.SourcePortRanges = stringPointers(props.SourcePortRanges)
	}
	if len(props.DestinationPortRanges) > 0 {
		ruleProps.DestinationPortRanges = stringPointers(props.DestinationPortRanges)
	}
	if props.Description != nil && *props.Description != "" {
		ruleProps.Description = to.Ptr(*props.Description)
	}

	// The kind discriminator sits at the resource level, not inside properties,
	// and is always Custom here: a Default rule cannot be created.
	return &armnetwork.AdminRule{
		Kind:       to.Ptr(armnetwork.AdminRuleKindCustom),
		Properties: ruleProps,
	}, nil
}

func (a *NetworkManagerAdminRule) buildPropertiesFromResult(rule *armnetwork.AdminRule, rgName, managerName, configName, collectionName string) map[string]any {
	props := make(map[string]any)

	// All four parents come from the native ID: ARM echoes none of them on the
	// rule body.
	props["resourceGroupName"] = rgName
	props["networkManagerName"] = managerName
	props["securityAdminConfigurationName"] = configName
	props["ruleCollectionName"] = collectionName

	if rule.ID != nil {
		props["id"] = *rule.ID
	}
	if rule.Name != nil {
		props["name"] = *rule.Name
	}

	p := rule.Properties
	if p == nil {
		return props
	}

	if p.Access != nil {
		props["access"] = canonicalizeEnum(string(*p.Access), "Allow", "AlwaysAllow", "Deny")
	}
	if p.Direction != nil {
		props["direction"] = canonicalizeEnum(string(*p.Direction), "Inbound", "Outbound")
	}
	if p.Priority != nil {
		props["priority"] = *p.Priority
	}
	if p.Protocol != nil {
		props["protocol"] = canonicalizeEnum(string(*p.Protocol), "Ah", "Any", "Esp", "Icmp", "Tcp", "Udp")
	}
	if sources := adminRuleAddressPrefixProperties(p.Sources); sources != nil {
		props["sources"] = sources
	}
	if destinations := adminRuleAddressPrefixProperties(p.Destinations); destinations != nil {
		props["destinations"] = destinations
	}
	if len(p.SourcePortRanges) > 0 {
		props["sourcePortRanges"] = stringsFromPointers(p.SourcePortRanges)
	}
	if len(p.DestinationPortRanges) > 0 {
		props["destinationPortRanges"] = stringsFromPointers(p.DestinationPortRanges)
	}
	if p.Description != nil && *p.Description != "" {
		props["description"] = *p.Description
	}
	// provisioningState and resourceGuid are dropped: neither is desired state.

	return props
}

func (a *NetworkManagerAdminRule) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props networkManagerAdminRuleProps
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	if props.NetworkManagerName == "" {
		return nil, fmt.Errorf("networkManagerName is required")
	}
	if props.SecurityAdminConfigurationName == "" {
		return nil, fmt.Errorf("securityAdminConfigurationName is required")
	}
	if props.RuleCollectionName == "" {
		return nil, fmt.Errorf("ruleCollectionName is required")
	}
	name := props.Name
	if name == "" {
		name = request.Label
	}
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}

	params, err := buildAdminRuleParams(&props)
	if err != nil {
		return nil, err
	}

	result, err := a.api.CreateOrUpdate(ctx, props.ResourceGroupName, props.NetworkManagerName,
		props.SecurityAdminConfigurationName, props.RuleCollectionName, name, params, nil)
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

	rule, err := customAdminRule(result.BaseAdminRuleClassification)
	if err != nil {
		return nil, err
	}

	nativeID := ""
	if rule.ID != nil {
		nativeID = *rule.ID
	}
	propsJSON, err := json.Marshal(a.buildPropertiesFromResult(rule, props.ResourceGroupName,
		props.NetworkManagerName, props.SecurityAdminConfigurationName, props.RuleCollectionName))
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

func (a *NetworkManagerAdminRule) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, managerName, configName, collectionName, name, err := networkManagerAdminRuleIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := a.api.Get(ctx, rgName, managerName, configName, collectionName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	rule, err := customAdminRule(result.BaseAdminRuleClassification)
	if err != nil {
		return nil, err
	}

	propsJSON, err := json.Marshal(a.buildPropertiesFromResult(rule, rgName, managerName, configName, collectionName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeNetworkManagerAdminRule,
		Properties:   string(propsJSON),
	}, nil
}

func (a *NetworkManagerAdminRule) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, managerName, configName, collectionName, name, err := networkManagerAdminRuleIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props networkManagerAdminRuleProps
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	params, err := buildAdminRuleParams(&props)
	if err != nil {
		return nil, err
	}

	result, err := a.api.CreateOrUpdate(ctx, rgName, managerName, configName, collectionName, name, params, nil)
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

	rule, err := customAdminRule(result.BaseAdminRuleClassification)
	if err != nil {
		return nil, err
	}

	propsJSON, err := json.Marshal(a.buildPropertiesFromResult(rule, rgName, managerName, configName, collectionName))
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

// Delete removes the rule. Force is set for the same reason as on the parent
// configuration: it is the only way past ARM's refusal to remove a rule belonging
// to a deployed (committed) configuration.
func (a *NetworkManagerAdminRule) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, managerName, configName, collectionName, name, err := networkManagerAdminRuleIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, err := a.api.BeginDelete(ctx, rgName, managerName, configName, collectionName, name,
		&armnetwork.AdminRulesClientBeginDeleteOptions{Force: to.Ptr(true)})
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
func (a *NetworkManagerAdminRule) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	reqID, err := decodeLROStatus(request.RequestID)
	if err != nil {
		return nil, err
	}

	switch reqID.OperationType {
	case lroOpDelete:
		return statusDeleteLRO(ctx, request, &reqID,
			func(token string) (*runtime.Poller[armnetwork.AdminRulesClientDeleteResponse], error) {
				return resumePoller[armnetwork.AdminRulesClientDeleteResponse](a.pipeline, token)
			}, nil)
	default:
		return nil, fmt.Errorf("unknown operation type: %s", reqID.OperationType)
	}
}

// List enumerates the CUSTOM rules of one collection. Default rules are filtered
// out: they are service-authored and read-only, so discovery must not offer them
// for import. There is no subscription-wide pager, so without all four parents
// there is nothing to enumerate.
func (a *NetworkManagerAdminRule) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	managerName := request.AdditionalProperties["networkManagerName"]
	configName := request.AdditionalProperties["securityAdminConfigurationName"]
	collectionName := request.AdditionalProperties["ruleCollectionName"]
	if rgName == "" || managerName == "" || configName == "" || collectionName == "" {
		return &resource.ListResult{}, nil
	}

	var nativeIDs []string
	pager := a.api.NewListPager(rgName, managerName, configName, collectionName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list admin rules: %w", err)
		}
		for _, entry := range page.Value {
			rule, err := customAdminRule(entry)
			if err != nil {
				continue
			}
			if rule.ID != nil {
				nativeIDs = append(nativeIDs, *rule.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
