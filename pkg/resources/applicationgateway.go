// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v4"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeApplicationGateway = "AZURE::Network::ApplicationGateway"

type applicationGatewaysAPI interface {
	BeginCreateOrUpdate(ctx context.Context, resourceGroupName string, applicationGatewayName string, parameters armnetwork.ApplicationGateway, options *armnetwork.ApplicationGatewaysClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.ApplicationGatewaysClientCreateOrUpdateResponse], error)
	Get(ctx context.Context, resourceGroupName string, applicationGatewayName string, options *armnetwork.ApplicationGatewaysClientGetOptions) (armnetwork.ApplicationGatewaysClientGetResponse, error)
	BeginDelete(ctx context.Context, resourceGroupName string, applicationGatewayName string, options *armnetwork.ApplicationGatewaysClientBeginDeleteOptions) (*runtime.Poller[armnetwork.ApplicationGatewaysClientDeleteResponse], error)
	NewListPager(resourceGroupName string, options *armnetwork.ApplicationGatewaysClientListOptions) *runtime.Pager[armnetwork.ApplicationGatewaysClientListResponse]
	NewListAllPager(options *armnetwork.ApplicationGatewaysClientListAllOptions) *runtime.Pager[armnetwork.ApplicationGatewaysClientListAllResponse]
}

func init() {
	registry.Register(ResourceTypeApplicationGateway, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &ApplicationGateway{
			api:      c.ApplicationGatewaysClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// ApplicationGateway is the provisioner for Azure Application Gateway v2.
type ApplicationGateway struct {
	api      applicationGatewaysAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

// applicationGatewayChildID builds the ARM sub-resource ID for a child of an
// application gateway (frontendIPConfigurations / frontendPorts / backendAddressPools /
// backendHttpSettingsCollection / httpListeners / sslCertificates / probes). Used to
// construct intra-gateway references (listener→port/frontendIP/sslCert,
// rule→listener/pool/settings, settings→probe) at Create/Update time. Read-back MUST
// normalize each child ID back to its bare name via applicationGatewayChildName, or
// re-apply drifts.
func applicationGatewayChildID(subscriptionID, rgName, gwName, kind, name string) string {
	return fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/applicationGateways/%s/%s/%s",
		subscriptionID, rgName, gwName, kind, name)
}

func applicationGatewayNativeIDParts(resourceID string) (rgName, gwName string, err error) {
	rgName, names, err := armIDParts(resourceID, "applicationGateways")
	if err != nil {
		return "", "", err
	}
	return rgName, names["applicationGateways"], nil
}

func applicationGatewayChildName(resourceID, childType string) (string, error) {
	_, names, err := armIDParts(resourceID, "applicationGateways", childType)
	if err != nil {
		return "", err
	}
	return names[childType], nil
}

// resolvableString extracts a plain string from a property value that may be a
// literal string or a resolved reference. Resolved references arrive as strings
// once formae binds them, so this is a defensive string coercion.
func resolvableString(v any) (string, bool) {
	s, ok := v.(string)
	return s, ok && s != ""
}

// buildApplicationGatewayParams converts the formae property map into an
// armnetwork.ApplicationGateway suitable for BeginCreateOrUpdate. Used by both
// Create and Update so the body shape stays identical across operations.
func (gw *ApplicationGateway) buildApplicationGatewayParams(props map[string]any, rgName, gwName, location string) (armnetwork.ApplicationGateway, error) {
	sub := gw.config.SubscriptionId
	params := armnetwork.ApplicationGateway{
		Location:   stringPtr(location),
		Properties: &armnetwork.ApplicationGatewayPropertiesFormat{},
	}

	if skuRaw, ok := props["sku"].(map[string]any); ok {
		sku := &armnetwork.ApplicationGatewaySKU{}
		if name, ok := skuRaw["name"].(string); ok {
			skuName := armnetwork.ApplicationGatewaySKUName(name)
			sku.Name = &skuName
		}
		if tier, ok := skuRaw["tier"].(string); ok {
			skuTier := armnetwork.ApplicationGatewayTier(tier)
			sku.Tier = &skuTier
		}
		if capacity, ok := skuRaw["capacity"].(float64); ok {
			sku.Capacity = int32Ptr(int32(capacity))
		}
		params.Properties.SKU = sku
	}

	gwIPsRaw, ok := props["gatewayIPConfigurations"].([]any)
	if !ok || len(gwIPsRaw) == 0 {
		return params, fmt.Errorf("gatewayIPConfigurations is required")
	}
	gwIPs := make([]*armnetwork.ApplicationGatewayIPConfiguration, 0, len(gwIPsRaw))
	for i, raw := range gwIPsRaw {
		m, ok := raw.(map[string]any)
		if !ok {
			return params, fmt.Errorf("gatewayIPConfigurations[%d] must be an object", i)
		}
		name, _ := m["name"].(string)
		subnetID, _ := resolvableString(m["subnetId"])
		if name == "" || subnetID == "" {
			return params, fmt.Errorf("gatewayIPConfigurations[%d] requires name and subnetId", i)
		}
		gwIPs = append(gwIPs, &armnetwork.ApplicationGatewayIPConfiguration{
			Name: stringPtr(name),
			Properties: &armnetwork.ApplicationGatewayIPConfigurationPropertiesFormat{
				Subnet: &armnetwork.SubResource{ID: stringPtr(subnetID)},
			},
		})
	}
	params.Properties.GatewayIPConfigurations = gwIPs

	frontendsRaw, ok := props["frontendIPConfigurations"].([]any)
	if !ok || len(frontendsRaw) == 0 {
		return params, fmt.Errorf("frontendIPConfigurations is required")
	}
	frontends := make([]*armnetwork.ApplicationGatewayFrontendIPConfiguration, 0, len(frontendsRaw))
	for i, raw := range frontendsRaw {
		m, ok := raw.(map[string]any)
		if !ok {
			return params, fmt.Errorf("frontendIPConfigurations[%d] must be an object", i)
		}
		name, _ := m["name"].(string)
		if name == "" {
			return params, fmt.Errorf("frontendIPConfigurations[%d] requires name", i)
		}
		fp := &armnetwork.ApplicationGatewayFrontendIPConfigurationPropertiesFormat{}
		if pipID, ok := resolvableString(m["publicIPAddressId"]); ok {
			fp.PublicIPAddress = &armnetwork.SubResource{ID: stringPtr(pipID)}
		}
		if subnetID, ok := resolvableString(m["subnetId"]); ok {
			fp.Subnet = &armnetwork.SubResource{ID: stringPtr(subnetID)}
		}
		if privIP, ok := m["privateIPAddress"].(string); ok && privIP != "" {
			fp.PrivateIPAddress = stringPtr(privIP)
			method := armnetwork.IPAllocationMethodStatic
			fp.PrivateIPAllocationMethod = &method
		}
		frontends = append(frontends, &armnetwork.ApplicationGatewayFrontendIPConfiguration{
			Name:       stringPtr(name),
			Properties: fp,
		})
	}
	params.Properties.FrontendIPConfigurations = frontends

	portsRaw, ok := props["frontendPorts"].([]any)
	if !ok || len(portsRaw) == 0 {
		return params, fmt.Errorf("frontendPorts is required")
	}
	ports := make([]*armnetwork.ApplicationGatewayFrontendPort, 0, len(portsRaw))
	for i, raw := range portsRaw {
		m, ok := raw.(map[string]any)
		if !ok {
			return params, fmt.Errorf("frontendPorts[%d] must be an object", i)
		}
		name, _ := m["name"].(string)
		port, portOK := m["port"].(float64)
		if name == "" || !portOK {
			return params, fmt.Errorf("frontendPorts[%d] requires name and port", i)
		}
		ports = append(ports, &armnetwork.ApplicationGatewayFrontendPort{
			Name: stringPtr(name),
			Properties: &armnetwork.ApplicationGatewayFrontendPortPropertiesFormat{
				Port: int32Ptr(int32(port)),
			},
		})
	}
	params.Properties.FrontendPorts = ports

	poolsRaw, ok := props["backendAddressPools"].([]any)
	if !ok || len(poolsRaw) == 0 {
		return params, fmt.Errorf("backendAddressPools is required")
	}
	pools := make([]*armnetwork.ApplicationGatewayBackendAddressPool, 0, len(poolsRaw))
	for i, raw := range poolsRaw {
		m, ok := raw.(map[string]any)
		if !ok {
			return params, fmt.Errorf("backendAddressPools[%d] must be an object", i)
		}
		name, _ := m["name"].(string)
		if name == "" {
			return params, fmt.Errorf("backendAddressPools[%d] requires name", i)
		}
		poolProps := &armnetwork.ApplicationGatewayBackendAddressPoolPropertiesFormat{}
		if addrsRaw, ok := m["backendAddresses"].([]any); ok {
			addrs := make([]*armnetwork.ApplicationGatewayBackendAddress, 0, len(addrsRaw))
			for _, aRaw := range addrsRaw {
				aMap, ok := aRaw.(map[string]any)
				if !ok {
					continue
				}
				addr := &armnetwork.ApplicationGatewayBackendAddress{}
				if ip, ok := aMap["ipAddress"].(string); ok && ip != "" {
					addr.IPAddress = stringPtr(ip)
				}
				if fqdn, ok := aMap["fqdn"].(string); ok && fqdn != "" {
					addr.Fqdn = stringPtr(fqdn)
				}
				addrs = append(addrs, addr)
			}
			poolProps.BackendAddresses = addrs
		}
		pools = append(pools, &armnetwork.ApplicationGatewayBackendAddressPool{
			Name:       stringPtr(name),
			Properties: poolProps,
		})
	}
	params.Properties.BackendAddressPools = pools

	settingsRaw, ok := props["backendHttpSettingsCollection"].([]any)
	if !ok || len(settingsRaw) == 0 {
		return params, fmt.Errorf("backendHttpSettingsCollection is required")
	}
	settings := make([]*armnetwork.ApplicationGatewayBackendHTTPSettings, 0, len(settingsRaw))
	for i, raw := range settingsRaw {
		m, ok := raw.(map[string]any)
		if !ok {
			return params, fmt.Errorf("backendHttpSettingsCollection[%d] must be an object", i)
		}
		name, _ := m["name"].(string)
		protocol, _ := m["protocol"].(string)
		port, portOK := m["port"].(float64)
		if name == "" || protocol == "" || !portOK {
			return params, fmt.Errorf("backendHttpSettingsCollection[%d] requires name, protocol, port", i)
		}
		proto := armnetwork.ApplicationGatewayProtocol(protocol)
		sp := &armnetwork.ApplicationGatewayBackendHTTPSettingsPropertiesFormat{
			Protocol: &proto,
			Port:     int32Ptr(int32(port)),
		}
		if probeName, ok := m["probeName"].(string); ok && probeName != "" {
			sp.Probe = &armnetwork.SubResource{ID: stringPtr(applicationGatewayChildID(sub, rgName, gwName, "probes", probeName))}
		}
		if rt, ok := m["requestTimeout"].(float64); ok {
			sp.RequestTimeout = int32Ptr(int32(rt))
		}
		if aff, ok := m["cookieBasedAffinity"].(string); ok && aff != "" {
			cba := armnetwork.ApplicationGatewayCookieBasedAffinity(aff)
			sp.CookieBasedAffinity = &cba
		}
		settings = append(settings, &armnetwork.ApplicationGatewayBackendHTTPSettings{
			Name:       stringPtr(name),
			Properties: sp,
		})
	}
	params.Properties.BackendHTTPSettingsCollection = settings

	if certs, err := buildApplicationGatewaySSLCertificates(props); err != nil {
		return params, err
	} else if certs != nil {
		params.Properties.SSLCertificates = certs
	}

	if probes, err := buildApplicationGatewayProbes(props); err != nil {
		return params, err
	} else if probes != nil {
		params.Properties.Probes = probes
	}

	listenersRaw, ok := props["httpListeners"].([]any)
	if !ok || len(listenersRaw) == 0 {
		return params, fmt.Errorf("httpListeners is required")
	}
	listeners := make([]*armnetwork.ApplicationGatewayHTTPListener, 0, len(listenersRaw))
	for i, raw := range listenersRaw {
		m, ok := raw.(map[string]any)
		if !ok {
			return params, fmt.Errorf("httpListeners[%d] must be an object", i)
		}
		name, _ := m["name"].(string)
		feName, _ := m["frontendIPConfigurationName"].(string)
		portName, _ := m["frontendPortName"].(string)
		protocol, _ := m["protocol"].(string)
		if name == "" || feName == "" || portName == "" || protocol == "" {
			return params, fmt.Errorf("httpListeners[%d] requires name, frontendIPConfigurationName, frontendPortName, protocol", i)
		}
		proto := armnetwork.ApplicationGatewayProtocol(protocol)
		lp := &armnetwork.ApplicationGatewayHTTPListenerPropertiesFormat{
			Protocol:                &proto,
			FrontendIPConfiguration: &armnetwork.SubResource{ID: stringPtr(applicationGatewayChildID(sub, rgName, gwName, "frontendIPConfigurations", feName))},
			FrontendPort:            &armnetwork.SubResource{ID: stringPtr(applicationGatewayChildID(sub, rgName, gwName, "frontendPorts", portName))},
		}
		if certName, ok := m["sslCertificateName"].(string); ok && certName != "" {
			lp.SSLCertificate = &armnetwork.SubResource{ID: stringPtr(applicationGatewayChildID(sub, rgName, gwName, "sslCertificates", certName))}
		}
		if hostName, ok := m["hostName"].(string); ok && hostName != "" {
			lp.HostName = stringPtr(hostName)
		}
		listeners = append(listeners, &armnetwork.ApplicationGatewayHTTPListener{
			Name:       stringPtr(name),
			Properties: lp,
		})
	}
	params.Properties.HTTPListeners = listeners

	rulesRaw, ok := props["requestRoutingRules"].([]any)
	if !ok || len(rulesRaw) == 0 {
		return params, fmt.Errorf("requestRoutingRules is required")
	}
	rules := make([]*armnetwork.ApplicationGatewayRequestRoutingRule, 0, len(rulesRaw))
	for i, raw := range rulesRaw {
		m, ok := raw.(map[string]any)
		if !ok {
			return params, fmt.Errorf("requestRoutingRules[%d] must be an object", i)
		}
		name, _ := m["name"].(string)
		ruleType, _ := m["ruleType"].(string)
		listenerName, _ := m["httpListenerName"].(string)
		if name == "" || ruleType == "" || listenerName == "" {
			return params, fmt.Errorf("requestRoutingRules[%d] requires name, ruleType, httpListenerName", i)
		}
		rt := armnetwork.ApplicationGatewayRequestRoutingRuleType(ruleType)
		rp := &armnetwork.ApplicationGatewayRequestRoutingRulePropertiesFormat{
			RuleType:     &rt,
			HTTPListener: &armnetwork.SubResource{ID: stringPtr(applicationGatewayChildID(sub, rgName, gwName, "httpListeners", listenerName))},
		}
		if priority, ok := m["priority"].(float64); ok {
			rp.Priority = int32Ptr(int32(priority))
		}
		if poolName, ok := m["backendAddressPoolName"].(string); ok && poolName != "" {
			rp.BackendAddressPool = &armnetwork.SubResource{ID: stringPtr(applicationGatewayChildID(sub, rgName, gwName, "backendAddressPools", poolName))}
		}
		if settingsName, ok := m["backendHTTPSettingsName"].(string); ok && settingsName != "" {
			rp.BackendHTTPSettings = &armnetwork.SubResource{ID: stringPtr(applicationGatewayChildID(sub, rgName, gwName, "backendHttpSettingsCollection", settingsName))}
		}
		rules = append(rules, &armnetwork.ApplicationGatewayRequestRoutingRule{
			Name:       stringPtr(name),
			Properties: rp,
		})
	}
	params.Properties.RequestRoutingRules = rules

	if identity := buildApplicationGatewayIdentity(props); identity != nil {
		params.Identity = identity
	}

	if fpID, ok := resolvableString(props["firewallPolicyId"]); ok {
		params.Properties.FirewallPolicy = &armnetwork.SubResource{ID: stringPtr(fpID)}
	}

	return params, nil
}

func buildApplicationGatewaySSLCertificates(props map[string]any) ([]*armnetwork.ApplicationGatewaySSLCertificate, error) {
	raw, ok := props["sslCertificates"].([]any)
	if !ok {
		return nil, nil
	}
	certs := make([]*armnetwork.ApplicationGatewaySSLCertificate, 0, len(raw))
	for i, cRaw := range raw {
		m, ok := cRaw.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("sslCertificates[%d] must be an object", i)
		}
		name, _ := m["name"].(string)
		if name == "" {
			return nil, fmt.Errorf("sslCertificates[%d] requires name", i)
		}
		cp := &armnetwork.ApplicationGatewaySSLCertificatePropertiesFormat{}
		if data, ok := opaqueString(m["data"]); ok {
			cp.Data = stringPtr(data)
		}
		if password, ok := opaqueString(m["password"]); ok {
			cp.Password = stringPtr(password)
		}
		if kvID, ok := m["keyVaultSecretId"].(string); ok && kvID != "" {
			cp.KeyVaultSecretID = stringPtr(kvID)
		}
		certs = append(certs, &armnetwork.ApplicationGatewaySSLCertificate{
			Name:       stringPtr(name),
			Properties: cp,
		})
	}
	return certs, nil
}

// opaqueString extracts a secret value that may arrive as a plain string (formae
// core unwraps opaque values for top-level fields) or, for nested list fields, as
// the opaque wrapper object carrying the value under "$value" (or "value"/"Value").
func opaqueString(v any) (string, bool) {
	switch t := v.(type) {
	case string:
		return t, t != ""
	case map[string]any:
		for _, key := range []string{"$value", "value", "Value"} {
			if s, ok := t[key].(string); ok && s != "" {
				return s, true
			}
		}
	}
	return "", false
}

func buildApplicationGatewayProbes(props map[string]any) ([]*armnetwork.ApplicationGatewayProbe, error) {
	raw, ok := props["probes"].([]any)
	if !ok {
		return nil, nil
	}
	probes := make([]*armnetwork.ApplicationGatewayProbe, 0, len(raw))
	for i, pRaw := range raw {
		m, ok := pRaw.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("probes[%d] must be an object", i)
		}
		name, _ := m["name"].(string)
		protocol, _ := m["protocol"].(string)
		path, _ := m["path"].(string)
		if name == "" || protocol == "" || path == "" {
			return nil, fmt.Errorf("probes[%d] requires name, protocol, path", i)
		}
		proto := armnetwork.ApplicationGatewayProtocol(protocol)
		pp := &armnetwork.ApplicationGatewayProbePropertiesFormat{
			Protocol: &proto,
			Path:     stringPtr(path),
		}
		if host, ok := m["host"].(string); ok && host != "" {
			pp.Host = stringPtr(host)
		}
		if iv, ok := m["interval"].(float64); ok {
			pp.Interval = int32Ptr(int32(iv))
		}
		if timeout, ok := m["timeout"].(float64); ok {
			pp.Timeout = int32Ptr(int32(timeout))
		}
		if ut, ok := m["unhealthyThreshold"].(float64); ok {
			pp.UnhealthyThreshold = int32Ptr(int32(ut))
		}
		if port, ok := m["port"].(float64); ok {
			pp.Port = int32Ptr(int32(port))
		}
		probes = append(probes, &armnetwork.ApplicationGatewayProbe{
			Name:       stringPtr(name),
			Properties: pp,
		})
	}
	return probes, nil
}

// canonicalIdentityType maps Azure's returned identity type (lower-camel, e.g.
// "userAssigned", "systemAssigned, userAssigned") back to the schema's casing so
// read-back equals the desired value instead of drifting every reconcile.
func canonicalIdentityType(s string) string {
	switch strings.ToLower(strings.ReplaceAll(s, " ", "")) {
	case "none":
		return "None"
	case "systemassigned":
		return "SystemAssigned"
	case "userassigned":
		return "UserAssigned"
	case "systemassigned,userassigned":
		return "SystemAssigned,UserAssigned"
	default:
		return s
	}
}

func buildApplicationGatewayIdentity(props map[string]any) *armnetwork.ManagedServiceIdentity {
	raw, ok := props["identity"].(map[string]any)
	if !ok {
		return nil
	}
	identity := &armnetwork.ManagedServiceIdentity{}
	if v, ok := raw["type"].(string); ok && v != "" {
		identity.Type = to.Ptr(armnetwork.ResourceIdentityType(v))
	}
	if ids, ok := raw["userAssignedIdentityIds"].([]any); ok && len(ids) > 0 {
		identity.UserAssignedIdentities = make(map[string]*armnetwork.Components1Jq1T4ISchemasManagedserviceidentityPropertiesUserassignedidentitiesAdditionalproperties, len(ids))
		for _, id := range ids {
			if idStr, ok := resolvableString(id); ok {
				identity.UserAssignedIdentities[idStr] = &armnetwork.Components1Jq1T4ISchemasManagedserviceidentityPropertiesUserassignedidentitiesAdditionalproperties{}
			}
		}
	}
	return identity
}

// serializeApplicationGatewayProperties converts an Azure ApplicationGateway to
// Formae property format. All child-ID references are normalized back to bare
// names so that re-apply compares equal to the desired forma (zero drift).
func serializeApplicationGatewayProperties(result armnetwork.ApplicationGateway, rgName, gwName string) (json.RawMessage, error) {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	if result.Name != nil {
		props["name"] = *result.Name
	} else {
		props["name"] = gwName
	}
	if result.Location != nil {
		props["location"] = *result.Location
	}
	if result.ID != nil {
		props["id"] = *result.ID
	}

	if p := result.Properties; p != nil {
		if p.SKU != nil {
			sku := make(map[string]any)
			if p.SKU.Name != nil {
				sku["name"] = string(*p.SKU.Name)
			}
			if p.SKU.Tier != nil {
				sku["tier"] = string(*p.SKU.Tier)
			}
			if p.SKU.Capacity != nil {
				sku["capacity"] = *p.SKU.Capacity
			}
			props["sku"] = sku
		}

		if len(p.GatewayIPConfigurations) > 0 {
			out := make([]map[string]any, 0, len(p.GatewayIPConfigurations))
			for _, c := range p.GatewayIPConfigurations {
				if c == nil {
					continue
				}
				m := make(map[string]any)
				if c.Name != nil {
					m["name"] = *c.Name
				}
				if c.Properties != nil && c.Properties.Subnet != nil && c.Properties.Subnet.ID != nil {
					m["subnetId"] = *c.Properties.Subnet.ID
				}
				out = append(out, m)
			}
			props["gatewayIPConfigurations"] = out
		}

		if len(p.FrontendIPConfigurations) > 0 {
			out := make([]map[string]any, 0, len(p.FrontendIPConfigurations))
			for _, f := range p.FrontendIPConfigurations {
				if f == nil {
					continue
				}
				m := make(map[string]any)
				if f.Name != nil {
					m["name"] = *f.Name
				}
				if f.Properties != nil {
					if f.Properties.PublicIPAddress != nil && f.Properties.PublicIPAddress.ID != nil {
						m["publicIPAddressId"] = *f.Properties.PublicIPAddress.ID
					}
					if f.Properties.Subnet != nil && f.Properties.Subnet.ID != nil {
						m["subnetId"] = *f.Properties.Subnet.ID
					}
					if f.Properties.PrivateIPAddress != nil {
						m["privateIPAddress"] = *f.Properties.PrivateIPAddress
					}
				}
				out = append(out, m)
			}
			props["frontendIPConfigurations"] = out
		}

		if len(p.FrontendPorts) > 0 {
			out := make([]map[string]any, 0, len(p.FrontendPorts))
			for _, fp := range p.FrontendPorts {
				if fp == nil {
					continue
				}
				m := make(map[string]any)
				if fp.Name != nil {
					m["name"] = *fp.Name
				}
				if fp.Properties != nil && fp.Properties.Port != nil {
					m["port"] = *fp.Properties.Port
				}
				out = append(out, m)
			}
			props["frontendPorts"] = out
		}

		if len(p.BackendAddressPools) > 0 {
			out := make([]map[string]any, 0, len(p.BackendAddressPools))
			for _, pool := range p.BackendAddressPools {
				if pool == nil {
					continue
				}
				m := make(map[string]any)
				if pool.Name != nil {
					m["name"] = *pool.Name
				}
				if pool.Properties != nil && len(pool.Properties.BackendAddresses) > 0 {
					addrs := make([]map[string]any, 0, len(pool.Properties.BackendAddresses))
					for _, a := range pool.Properties.BackendAddresses {
						if a == nil {
							continue
						}
						am := make(map[string]any)
						if a.IPAddress != nil {
							am["ipAddress"] = *a.IPAddress
						}
						if a.Fqdn != nil {
							am["fqdn"] = *a.Fqdn
						}
						addrs = append(addrs, am)
					}
					m["backendAddresses"] = addrs
				}
				out = append(out, m)
			}
			props["backendAddressPools"] = out
		}

		if len(p.BackendHTTPSettingsCollection) > 0 {
			out := make([]map[string]any, 0, len(p.BackendHTTPSettingsCollection))
			for _, s := range p.BackendHTTPSettingsCollection {
				if s == nil {
					continue
				}
				m := make(map[string]any)
				if s.Name != nil {
					m["name"] = *s.Name
				}
				if s.Properties != nil {
					if s.Properties.Port != nil {
						m["port"] = *s.Properties.Port
					}
					if s.Properties.Protocol != nil {
						m["protocol"] = string(*s.Properties.Protocol)
					}
					if s.Properties.Probe != nil && s.Properties.Probe.ID != nil {
						name, err := applicationGatewayChildName(*s.Properties.Probe.ID, "probes")
						if err != nil {
							return nil, err
						}
						m["probeName"] = name
					}
					if s.Properties.RequestTimeout != nil {
						m["requestTimeout"] = *s.Properties.RequestTimeout
					}
					if s.Properties.CookieBasedAffinity != nil {
						m["cookieBasedAffinity"] = string(*s.Properties.CookieBasedAffinity)
					}
				}
				out = append(out, m)
			}
			props["backendHttpSettingsCollection"] = out
		}

		if len(p.HTTPListeners) > 0 {
			out := make([]map[string]any, 0, len(p.HTTPListeners))
			for _, l := range p.HTTPListeners {
				if l == nil {
					continue
				}
				m := make(map[string]any)
				if l.Name != nil {
					m["name"] = *l.Name
				}
				if l.Properties != nil {
					if l.Properties.FrontendIPConfiguration != nil && l.Properties.FrontendIPConfiguration.ID != nil {
						name, err := applicationGatewayChildName(*l.Properties.FrontendIPConfiguration.ID, "frontendIPConfigurations")
						if err != nil {
							return nil, err
						}
						m["frontendIPConfigurationName"] = name
					}
					if l.Properties.FrontendPort != nil && l.Properties.FrontendPort.ID != nil {
						name, err := applicationGatewayChildName(*l.Properties.FrontendPort.ID, "frontendPorts")
						if err != nil {
							return nil, err
						}
						m["frontendPortName"] = name
					}
					if l.Properties.Protocol != nil {
						m["protocol"] = string(*l.Properties.Protocol)
					}
					if l.Properties.SSLCertificate != nil && l.Properties.SSLCertificate.ID != nil {
						name, err := applicationGatewayChildName(*l.Properties.SSLCertificate.ID, "sslCertificates")
						if err != nil {
							return nil, err
						}
						m["sslCertificateName"] = name
					}
					if l.Properties.HostName != nil {
						m["hostName"] = *l.Properties.HostName
					}
				}
				out = append(out, m)
			}
			props["httpListeners"] = out
		}

		if len(p.RequestRoutingRules) > 0 {
			out := make([]map[string]any, 0, len(p.RequestRoutingRules))
			for _, r := range p.RequestRoutingRules {
				if r == nil {
					continue
				}
				m := make(map[string]any)
				if r.Name != nil {
					m["name"] = *r.Name
				}
				if r.Properties != nil {
					if r.Properties.RuleType != nil {
						m["ruleType"] = string(*r.Properties.RuleType)
					}
					if r.Properties.Priority != nil {
						m["priority"] = *r.Properties.Priority
					}
					if r.Properties.HTTPListener != nil && r.Properties.HTTPListener.ID != nil {
						name, err := applicationGatewayChildName(*r.Properties.HTTPListener.ID, "httpListeners")
						if err != nil {
							return nil, err
						}
						m["httpListenerName"] = name
					}
					if r.Properties.BackendAddressPool != nil && r.Properties.BackendAddressPool.ID != nil {
						name, err := applicationGatewayChildName(*r.Properties.BackendAddressPool.ID, "backendAddressPools")
						if err != nil {
							return nil, err
						}
						m["backendAddressPoolName"] = name
					}
					if r.Properties.BackendHTTPSettings != nil && r.Properties.BackendHTTPSettings.ID != nil {
						name, err := applicationGatewayChildName(*r.Properties.BackendHTTPSettings.ID, "backendHttpSettingsCollection")
						if err != nil {
							return nil, err
						}
						m["backendHTTPSettingsName"] = name
					}
				}
				out = append(out, m)
			}
			props["requestRoutingRules"] = out
		}

		if len(p.Probes) > 0 {
			out := make([]map[string]any, 0, len(p.Probes))
			for _, pr := range p.Probes {
				if pr == nil {
					continue
				}
				m := make(map[string]any)
				if pr.Name != nil {
					m["name"] = *pr.Name
				}
				if pr.Properties != nil {
					if pr.Properties.Protocol != nil {
						m["protocol"] = string(*pr.Properties.Protocol)
					}
					if pr.Properties.Path != nil {
						m["path"] = *pr.Properties.Path
					}
					if pr.Properties.Host != nil {
						m["host"] = *pr.Properties.Host
					}
					if pr.Properties.Interval != nil {
						m["interval"] = *pr.Properties.Interval
					}
					if pr.Properties.Timeout != nil {
						m["timeout"] = *pr.Properties.Timeout
					}
					if pr.Properties.UnhealthyThreshold != nil {
						m["unhealthyThreshold"] = *pr.Properties.UnhealthyThreshold
					}
					if pr.Properties.Port != nil {
						m["port"] = *pr.Properties.Port
					}
				}
				out = append(out, m)
			}
			props["probes"] = out
		}

		// SSL certificate names round-trip; data/password are write-only and
		// never returned by Azure, so only the name (and any KV reference) surfaces.
		if len(p.SSLCertificates) > 0 {
			out := make([]map[string]any, 0, len(p.SSLCertificates))
			for _, c := range p.SSLCertificates {
				if c == nil {
					continue
				}
				m := make(map[string]any)
				if c.Name != nil {
					m["name"] = *c.Name
				}
				if c.Properties != nil && c.Properties.KeyVaultSecretID != nil {
					m["keyVaultSecretId"] = *c.Properties.KeyVaultSecretID
				}
				out = append(out, m)
			}
			props["sslCertificates"] = out
		}

		// A full ARM ID reference to a WAF policy; round-trips as-is (no name
		// normalization needed since it points at a resource in another RG namespace).
		if p.FirewallPolicy != nil && p.FirewallPolicy.ID != nil {
			props["firewallPolicyId"] = *p.FirewallPolicy.ID
		}
	}

	if id := result.Identity; id != nil {
		identity := make(map[string]any)
		if id.Type != nil {
			identity["type"] = canonicalIdentityType(string(*id.Type))
		}
		if len(id.UserAssignedIdentities) > 0 {
			ids := make([]string, 0, len(id.UserAssignedIdentities))
			for k := range id.UserAssignedIdentities {
				// Emit the ID exactly as Azure returns it (MSI resource IDs use a
				// lowercase "resourcegroups" segment) — this matches the resolvable's
				// value, which resolves to the identity resource's own id. Do NOT
				// re-case it, or read-back diverges from desired and drifts.
				ids = append(ids, k)
			}
			identity["userAssignedIdentityIds"] = ids
		}
		if len(identity) > 0 {
			props["identity"] = identity
		}
	}

	if tags := azureTagsToFormaeTags(result.Tags); tags != nil {
		props["Tags"] = tags
	}

	return json.Marshal(props)
}

func (gw *ApplicationGateway) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
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
	gwName, ok := props["name"].(string)
	if !ok || gwName == "" {
		gwName = request.Label
	}

	params, err := gw.buildApplicationGatewayParams(props, rgName, gwName, location)
	if err != nil {
		return nil, err
	}
	if azureTags := formaeTagsToAzureTags(request.Properties); azureTags != nil {
		params.Tags = azureTags
	}

	poller, err := gw.api.BeginCreateOrUpdate(ctx, rgName, gwName, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/applicationGateways/%s",
		gw.config.SubscriptionId, rgName, gwName)

	if poller.Done() {
		result, err := poller.Result(ctx)
		if err != nil {
			return &resource.CreateResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationCreate,
					OperationStatus: resource.OperationStatusFailure,
					ErrorCode:       operationErrorCode(err),
				},
			}, nil
		}
		propsJSON, err := serializeApplicationGatewayProperties(result.ApplicationGateway, rgName, gwName)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize ApplicationGateway properties: %w", err)
		}
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:          resource.OperationCreate,
				OperationStatus:    resource.OperationStatusSuccess,
				NativeID:           *result.ID,
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

func (gw *ApplicationGateway) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, gwName, err := applicationGatewayNativeIDParts(request.NativeID)
	if err != nil {
		return nil, fmt.Errorf("invalid NativeID: cannot extract resourceGroup or applicationGateway name from %s: %w", request.NativeID, err)
	}

	result, err := gw.api.Get(ctx, rgName, gwName, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}
	propsJSON, err := serializeApplicationGatewayProperties(result.ApplicationGateway, rgName, gwName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize ApplicationGateway properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeApplicationGateway,
		Properties:   string(propsJSON),
	}, nil
}

func (gw *ApplicationGateway) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, gwName, err := applicationGatewayNativeIDParts(request.NativeID)
	if err != nil {
		return nil, fmt.Errorf("invalid NativeID: cannot extract resourceGroup or applicationGateway name from %s: %w", request.NativeID, err)
	}

	var props map[string]any
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	location, ok := props["location"].(string)
	if !ok || location == "" {
		return nil, fmt.Errorf("location is required")
	}

	params, err := gw.buildApplicationGatewayParams(props, rgName, gwName, location)
	if err != nil {
		return nil, err
	}
	if azureTags := formaeTagsToAzureTags(request.DesiredProperties); azureTags != nil {
		params.Tags = azureTags
	}

	poller, err := gw.api.BeginCreateOrUpdate(ctx, rgName, gwName, params, nil)
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

	if poller.Done() {
		result, err := poller.Result(ctx)
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
		propsJSON, err := serializeApplicationGatewayProperties(result.ApplicationGateway, rgName, gwName)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize ApplicationGateway properties: %w", err)
		}
		return &resource.UpdateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:          resource.OperationUpdate,
				OperationStatus:    resource.OperationStatusSuccess,
				NativeID:           *result.ID,
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

func (gw *ApplicationGateway) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, gwName, err := applicationGatewayNativeIDParts(request.NativeID)
	if err != nil {
		return nil, fmt.Errorf("invalid NativeID: cannot extract resourceGroup or applicationGateway name from %s: %w", request.NativeID, err)
	}

	poller, err := gw.api.BeginDelete(ctx, rgName, gwName, nil)
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
		}, fmt.Errorf("failed to start ApplicationGateway deletion: %w", err)
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

func (gw *ApplicationGateway) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	reqID, err := decodeLROStatus(request.RequestID)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
			},
		}, err
	}

	switch reqID.OperationType {
	case lroOpCreate, lroOpUpdate:
		return gw.statusCreateOrUpdate(ctx, request, &reqID)
	case lroOpDelete:
		return gw.statusDelete(ctx, request, &reqID)
	default:
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
			},
		}, fmt.Errorf("unknown operation type: %s", reqID.OperationType)
	}
}

func (gw *ApplicationGateway) statusCreateOrUpdate(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	operation := resource.OperationCreate
	if reqID.OperationType == lroOpUpdate {
		operation = resource.OperationUpdate
	}

	return statusLRO(ctx, request, reqID, operation,
		func(token string) (*runtime.Poller[armnetwork.ApplicationGatewaysClientCreateOrUpdateResponse], error) {
			return resumePoller[armnetwork.ApplicationGatewaysClientCreateOrUpdateResponse](gw.pipeline, token)
		},
		func(_ context.Context, result armnetwork.ApplicationGatewaysClientCreateOrUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
			rgName, gwName, err := applicationGatewayNativeIDParts(*result.ID)
			if err != nil {
				return "", nil, err
			}
			propsJSON, err := serializeApplicationGatewayProperties(result.ApplicationGateway, rgName, gwName)
			if err != nil {
				return "", nil, fmt.Errorf("failed to serialize ApplicationGateway properties: %w", err)
			}
			return *result.ID, propsJSON, nil
		})
}

func (gw *ApplicationGateway) statusDelete(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	return statusDeleteLRO(ctx, request, reqID,
		func(token string) (*runtime.Poller[armnetwork.ApplicationGatewaysClientDeleteResponse], error) {
			return resumePoller[armnetwork.ApplicationGatewaysClientDeleteResponse](gw.pipeline, token)
		}, nil)
}

func (gw *ApplicationGateway) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	resourceGroupName := request.AdditionalProperties["resourceGroupName"]

	var nativeIDs []string
	if resourceGroupName != "" {
		pager := gw.api.NewListPager(resourceGroupName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list application gateways: %w", err)
			}
			for _, x := range page.Value {
				if x != nil && x.ID != nil {
					nativeIDs = append(nativeIDs, *x.ID)
				}
			}
		}
	} else {
		pager := gw.api.NewListAllPager(nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list application gateways: %w", err)
			}
			for _, x := range page.Value {
				if x != nil && x.ID != nil {
					nativeIDs = append(nativeIDs, *x.ID)
				}
			}
		}
	}

	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
