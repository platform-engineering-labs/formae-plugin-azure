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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/dnsresolver/armdnsresolver"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeDNSForwardingRule = "AZURE::Network::DnsForwardingRule"

// dnsForwardingRulesAPI is the armdnsresolver surface used here. Unlike every
// other resource in the dnsresolver family these calls are synchronous — no
// pollers, so Status is never doing real work.
type dnsForwardingRulesAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName string, dnsForwardingRulesetName string, forwardingRuleName string, parameters armdnsresolver.ForwardingRule, options *armdnsresolver.ForwardingRulesClientCreateOrUpdateOptions) (armdnsresolver.ForwardingRulesClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName string, dnsForwardingRulesetName string, forwardingRuleName string, options *armdnsresolver.ForwardingRulesClientGetOptions) (armdnsresolver.ForwardingRulesClientGetResponse, error)
	Update(ctx context.Context, resourceGroupName string, dnsForwardingRulesetName string, forwardingRuleName string, parameters armdnsresolver.ForwardingRulePatch, options *armdnsresolver.ForwardingRulesClientUpdateOptions) (armdnsresolver.ForwardingRulesClientUpdateResponse, error)
	Delete(ctx context.Context, resourceGroupName string, dnsForwardingRulesetName string, forwardingRuleName string, options *armdnsresolver.ForwardingRulesClientDeleteOptions) (armdnsresolver.ForwardingRulesClientDeleteResponse, error)
	NewListPager(resourceGroupName string, dnsForwardingRulesetName string, options *armdnsresolver.ForwardingRulesClientListOptions) *runtime.Pager[armdnsresolver.ForwardingRulesClientListResponse]
}

func init() {
	registry.Register(ResourceTypeDNSForwardingRule, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &DNSForwardingRule{
			api:    c.DNSForwardingRulesClient,
			config: cfg,
		}
	})
}

// DNSForwardingRule is the provisioner for rules inside a DNS forwarding ruleset
// (Microsoft.Network/dnsForwardingRulesets/forwardingRules).
type DNSForwardingRule struct {
	api    dnsForwardingRulesAPI
	config *config.Config
}

// dnsForwardingRuleProps mirrors schema/pkl/network/dnsforwardingrule.pkl.
type dnsForwardingRuleProps struct {
	Name                     string                 `json:"name"`
	ResourceGroupName        string                 `json:"resourceGroupName"`
	DNSForwardingRulesetName string                 `json:"dnsForwardingRulesetName"`
	DomainName               string                 `json:"domainName"`
	TargetDNSServers         []dnsTargetServerProps `json:"targetDnsServers"`
	ForwardingRuleState      string                 `json:"forwardingRuleState"`
}

type dnsTargetServerProps struct {
	IPAddress string `json:"ipAddress"`
	Port      *int32 `json:"port"`
}

func dnsForwardingRuleIDParts(resourceID string) (rgName, rulesetName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "dnsforwardingrulesets", "forwardingrules")
	if err != nil {
		return "", "", "", err
	}
	return rgName, names["dnsforwardingrulesets"], names["forwardingrules"], nil
}

func (d *DNSForwardingRule) buildPropertiesFromResult(rule *armdnsresolver.ForwardingRule, rgName, rulesetName string) map[string]any {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	props["dnsForwardingRulesetName"] = rulesetName

	if rule.ID != nil {
		props["id"] = *rule.ID
	}
	if rule.Name != nil {
		props["name"] = *rule.Name
	}

	if p := rule.Properties; p != nil {
		if p.DomainName != nil {
			props["domainName"] = *p.DomainName
		}
		if p.ForwardingRuleState != nil {
			props["forwardingRuleState"] = canonicalizeEnum(string(*p.ForwardingRuleState), "Enabled", "Disabled")
		}
		if len(p.TargetDNSServers) > 0 {
			// Order is desired state here: ARM tries the servers in the order given,
			// so it is echoed back untouched rather than sorted.
			servers := make([]map[string]any, 0, len(p.TargetDNSServers))
			for _, server := range p.TargetDNSServers {
				if server == nil || server.IPAddress == nil {
					continue
				}
				entry := map[string]any{"ipAddress": *server.IPAddress}
				if server.Port != nil {
					entry["port"] = *server.Port
				}
				servers = append(servers, entry)
			}
			props["targetDnsServers"] = servers
		}
	}

	return props
}

// dnsTargetServers converts desired properties into the ARM shape shared by the
// create body and the patch body.
//
// port is required in the schema, so it is normally set; it stays a pointer here
// so that a caller who omits it still gets ARM's default of 53 rather than a
// rejected port 0.
func dnsTargetServers(servers []dnsTargetServerProps) []*armdnsresolver.TargetDNSServer {
	if len(servers) == 0 {
		return nil
	}
	out := make([]*armdnsresolver.TargetDNSServer, 0, len(servers))
	for _, server := range servers {
		if server.IPAddress == "" {
			continue
		}
		target := &armdnsresolver.TargetDNSServer{IPAddress: to.Ptr(server.IPAddress)}
		if server.Port != nil {
			target.Port = server.Port
		}
		out = append(out, target)
	}
	return out
}

func (d *DNSForwardingRule) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props dnsForwardingRuleProps
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	if props.DNSForwardingRulesetName == "" {
		return nil, fmt.Errorf("dnsForwardingRulesetName is required")
	}
	if props.DomainName == "" {
		return nil, fmt.Errorf("domainName is required")
	}
	if len(props.TargetDNSServers) == 0 {
		return nil, fmt.Errorf("targetDnsServers is required")
	}
	name := props.Name
	if name == "" {
		name = request.Label
	}
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}

	ruleProps := &armdnsresolver.ForwardingRuleProperties{
		DomainName:       to.Ptr(props.DomainName),
		TargetDNSServers: dnsTargetServers(props.TargetDNSServers),
	}
	if props.ForwardingRuleState != "" {
		ruleProps.ForwardingRuleState = to.Ptr(armdnsresolver.ForwardingRuleState(props.ForwardingRuleState))
	}

	result, err := d.api.CreateOrUpdate(ctx, props.ResourceGroupName, props.DNSForwardingRulesetName, name,
		armdnsresolver.ForwardingRule{Properties: ruleProps}, nil)
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
	propsJSON, err := json.Marshal(d.buildPropertiesFromResult(&result.ForwardingRule,
		props.ResourceGroupName, props.DNSForwardingRulesetName))
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

func (d *DNSForwardingRule) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, rulesetName, name, err := dnsForwardingRuleIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := d.api.Get(ctx, rgName, rulesetName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(d.buildPropertiesFromResult(&result.ForwardingRule, rgName, rulesetName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeDNSForwardingRule,
		Properties:   string(propsJSON),
	}, nil
}

// Update is a synchronous PATCH. domainName is createOnly because
// ForwardingRulePatchProperties has no field for it; the target servers and the
// rule state are the two things it can change.
func (d *DNSForwardingRule) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, rulesetName, name, err := dnsForwardingRuleIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props dnsForwardingRuleProps
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	patchProps := &armdnsresolver.ForwardingRulePatchProperties{
		TargetDNSServers: dnsTargetServers(props.TargetDNSServers),
	}
	if props.ForwardingRuleState != "" {
		patchProps.ForwardingRuleState = to.Ptr(armdnsresolver.ForwardingRuleState(props.ForwardingRuleState))
	}

	result, err := d.api.Update(ctx, rgName, rulesetName, name,
		armdnsresolver.ForwardingRulePatch{Properties: patchProps}, nil)
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

	propsJSON, err := json.Marshal(d.buildPropertiesFromResult(&result.ForwardingRule, rgName, rulesetName))
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

func (d *DNSForwardingRule) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, rulesetName, name, err := dnsForwardingRuleIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	if _, err := d.api.Delete(ctx, rgName, rulesetName, name, nil); err != nil && !isDeleteSuccessError(err) {
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
// rule is synchronous, so it echoes success.
func (d *DNSForwardingRule) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

// List requires both the resource group and the ruleset name: ARM has no
// subscription-wide listing for forwarding rules.
func (d *DNSForwardingRule) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	rulesetName := request.AdditionalProperties["dnsForwardingRulesetName"]
	if rgName == "" || rulesetName == "" {
		return &resource.ListResult{}, nil
	}

	var nativeIDs []string
	pager := d.api.NewListPager(rgName, rulesetName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list dns forwarding rules: %w", err)
		}
		for _, rule := range page.Value {
			if rule.ID != nil {
				nativeIDs = append(nativeIDs, *rule.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
