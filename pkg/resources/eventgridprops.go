// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/eventgrid/armeventgrid"
)

// Event Grid topics and domains share the same ingress-configuration shape
// (inputSchema, publicNetworkAccess, disableLocalAuth, inboundIpRules), so the
// conversion lives here instead of being duplicated in both provisioners.
//
// ponytail: inputSchemaMapping is not modelled. It is a polymorphic ARM union
// (only JSON mapping exists today) and is meaningless unless inputSchema is
// CustomEventSchema, so it is deferred rather than shipped unverified.

// eventGridInboundIPRulesToProperties converts ARM inbound IP rules into the
// Formae property shape. Order is preserved: for Event Grid the rule list is
// evaluated as given, so sorting it would change behaviour.
func eventGridInboundIPRulesToProperties(rules []*armeventgrid.InboundIPRule) []map[string]any {
	if len(rules) == 0 {
		return nil
	}
	out := make([]map[string]any, 0, len(rules))
	for _, r := range rules {
		if r == nil {
			continue
		}
		entry := map[string]any{}
		if r.IPMask != nil {
			entry["ipMask"] = *r.IPMask
		}
		if r.Action != nil {
			entry["action"] = string(*r.Action)
		}
		if len(entry) > 0 {
			out = append(out, entry)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// eventGridInboundIPRulesFromProperties is the inverse.
func eventGridInboundIPRulesFromProperties(props map[string]any) ([]*armeventgrid.InboundIPRule, error) {
	raw, ok := props["inboundIpRules"].([]any)
	if !ok || len(raw) == 0 {
		return nil, nil
	}
	rules := make([]*armeventgrid.InboundIPRule, 0, len(raw))
	for i, entry := range raw {
		m, ok := entry.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("inboundIpRules[%d] must be an object", i)
		}
		mask, _ := m["ipMask"].(string)
		if mask == "" {
			return nil, fmt.Errorf("inboundIpRules[%d].ipMask is required", i)
		}
		rule := &armeventgrid.InboundIPRule{IPMask: to.Ptr(mask)}
		if action, ok := m["action"].(string); ok && action != "" {
			rule.Action = to.Ptr(armeventgrid.IPActionType(action))
		}
		rules = append(rules, rule)
	}
	return rules, nil
}
