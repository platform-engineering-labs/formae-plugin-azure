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

const ResourceTypeLoadBalancer = "Azure::Network::LoadBalancer"

type loadBalancersAPI interface {
	BeginCreateOrUpdate(ctx context.Context, resourceGroupName string, loadBalancerName string, parameters armnetwork.LoadBalancer, options *armnetwork.LoadBalancersClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.LoadBalancersClientCreateOrUpdateResponse], error)
	Get(ctx context.Context, resourceGroupName string, loadBalancerName string, options *armnetwork.LoadBalancersClientGetOptions) (armnetwork.LoadBalancersClientGetResponse, error)
	BeginDelete(ctx context.Context, resourceGroupName string, loadBalancerName string, options *armnetwork.LoadBalancersClientBeginDeleteOptions) (*runtime.Poller[armnetwork.LoadBalancersClientDeleteResponse], error)
	NewListPager(resourceGroupName string, options *armnetwork.LoadBalancersClientListOptions) *runtime.Pager[armnetwork.LoadBalancersClientListResponse]
	NewListAllPager(options *armnetwork.LoadBalancersClientListAllOptions) *runtime.Pager[armnetwork.LoadBalancersClientListAllResponse]
}

func init() {
	registry.Register(ResourceTypeLoadBalancer, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &LoadBalancer{
			api:      c.LoadBalancersClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// LoadBalancer is the provisioner for Azure Standard Load Balancers.
type LoadBalancer struct {
	api      loadBalancersAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

// loadBalancerChildID builds the ARM sub-resource ID for a child of a load
// balancer (frontendIPConfigurations / backendAddressPools / probes). Used to
// construct intra-LB references in load balancing rules at Create time.
func loadBalancerChildID(subscriptionID, rgName, lbName, kind, name string) string {
	return fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/loadBalancers/%s/%s/%s",
		subscriptionID, rgName, lbName, kind, name)
}

// buildLoadBalancerParams converts the formae property map into an armnetwork.LoadBalancer
// suitable for BeginCreateOrUpdate. Used by both Create and Update so the body shape stays
// identical across operations.
func (lb *LoadBalancer) buildLoadBalancerParams(props map[string]any, rgName, lbName, location string) (armnetwork.LoadBalancer, error) {
	params := armnetwork.LoadBalancer{
		Location:   stringPtr(location),
		Properties: &armnetwork.LoadBalancerPropertiesFormat{},
	}

	if skuRaw, ok := props["sku"].(map[string]any); ok {
		sku := &armnetwork.LoadBalancerSKU{}
		if name, ok := skuRaw["name"].(string); ok {
			skuName := armnetwork.LoadBalancerSKUName(name)
			sku.Name = &skuName
		}
		if tier, ok := skuRaw["tier"].(string); ok {
			skuTier := armnetwork.LoadBalancerSKUTier(tier)
			sku.Tier = &skuTier
		}
		params.SKU = sku
	}

	frontendsRaw, ok := props["frontendIPConfigurations"].([]any)
	if !ok || len(frontendsRaw) == 0 {
		return params, fmt.Errorf("frontendIPConfigurations is required")
	}
	frontends := make([]*armnetwork.FrontendIPConfiguration, 0, len(frontendsRaw))
	for i, fRaw := range frontendsRaw {
		fMap, ok := fRaw.(map[string]any)
		if !ok {
			return params, fmt.Errorf("frontendIPConfigurations[%d] must be an object", i)
		}
		name, _ := fMap["name"].(string)
		pipID, _ := fMap["publicIPAddressId"].(string)
		if name == "" || pipID == "" {
			return params, fmt.Errorf("frontendIPConfigurations[%d] requires name and publicIPAddressId", i)
		}
		frontends = append(frontends, &armnetwork.FrontendIPConfiguration{
			Name: stringPtr(name),
			Properties: &armnetwork.FrontendIPConfigurationPropertiesFormat{
				PublicIPAddress: &armnetwork.PublicIPAddress{ID: stringPtr(pipID)},
			},
		})
	}
	params.Properties.FrontendIPConfigurations = frontends

	if poolsRaw, ok := props["backendAddressPools"].([]any); ok {
		pools := make([]*armnetwork.BackendAddressPool, 0, len(poolsRaw))
		for i, pRaw := range poolsRaw {
			pMap, ok := pRaw.(map[string]any)
			if !ok {
				return params, fmt.Errorf("backendAddressPools[%d] must be an object", i)
			}
			name, _ := pMap["name"].(string)
			if name == "" {
				return params, fmt.Errorf("backendAddressPools[%d] requires name", i)
			}
			pools = append(pools, &armnetwork.BackendAddressPool{Name: stringPtr(name)})
		}
		params.Properties.BackendAddressPools = pools
	}

	if probesRaw, ok := props["probes"].([]any); ok {
		probes := make([]*armnetwork.Probe, 0, len(probesRaw))
		for i, prRaw := range probesRaw {
			pMap, ok := prRaw.(map[string]any)
			if !ok {
				return params, fmt.Errorf("probes[%d] must be an object", i)
			}
			name, _ := pMap["name"].(string)
			protocol, _ := pMap["protocol"].(string)
			port, _ := pMap["port"].(float64)
			if name == "" || protocol == "" || port == 0 {
				return params, fmt.Errorf("probes[%d] requires name, protocol, port", i)
			}
			proto := armnetwork.ProbeProtocol(protocol)
			p := &armnetwork.Probe{
				Name: stringPtr(name),
				Properties: &armnetwork.ProbePropertiesFormat{
					Protocol: &proto,
					Port:     int32Ptr(int32(port)),
				},
			}
			if path, ok := pMap["requestPath"].(string); ok && path != "" {
				p.Properties.RequestPath = stringPtr(path)
			}
			if iv, ok := pMap["intervalInSeconds"].(float64); ok {
				p.Properties.IntervalInSeconds = int32Ptr(int32(iv))
			}
			if n, ok := pMap["numberOfProbes"].(float64); ok {
				p.Properties.NumberOfProbes = int32Ptr(int32(n))
			}
			probes = append(probes, p)
		}
		params.Properties.Probes = probes
	}

	if rulesRaw, ok := props["loadBalancingRules"].([]any); ok {
		rules := make([]*armnetwork.LoadBalancingRule, 0, len(rulesRaw))
		for i, rRaw := range rulesRaw {
			rMap, ok := rRaw.(map[string]any)
			if !ok {
				return params, fmt.Errorf("loadBalancingRules[%d] must be an object", i)
			}
			name, _ := rMap["name"].(string)
			frontendName, _ := rMap["frontendIPConfigurationName"].(string)
			backendName, _ := rMap["backendAddressPoolName"].(string)
			probeName, _ := rMap["probeName"].(string)
			protocol, _ := rMap["protocol"].(string)
			fePort, fePortOK := rMap["frontendPort"].(float64)
			bePort, bePortOK := rMap["backendPort"].(float64)
			if name == "" || frontendName == "" || backendName == "" || probeName == "" || protocol == "" || !fePortOK || !bePortOK {
				return params, fmt.Errorf("loadBalancingRules[%d] requires name, frontendIPConfigurationName, backendAddressPoolName, probeName, protocol, frontendPort, backendPort", i)
			}
			proto := armnetwork.TransportProtocol(protocol)
			rule := &armnetwork.LoadBalancingRule{
				Name: stringPtr(name),
				Properties: &armnetwork.LoadBalancingRulePropertiesFormat{
					FrontendIPConfiguration: &armnetwork.SubResource{
						ID: stringPtr(loadBalancerChildID(lb.config.SubscriptionId, rgName, lbName, "frontendIPConfigurations", frontendName)),
					},
					BackendAddressPool: &armnetwork.SubResource{
						ID: stringPtr(loadBalancerChildID(lb.config.SubscriptionId, rgName, lbName, "backendAddressPools", backendName)),
					},
					Probe: &armnetwork.SubResource{
						ID: stringPtr(loadBalancerChildID(lb.config.SubscriptionId, rgName, lbName, "probes", probeName)),
					},
					Protocol:     &proto,
					FrontendPort: int32Ptr(int32(fePort)),
					BackendPort:  int32Ptr(int32(bePort)),
				},
			}
			if iv, ok := rMap["idleTimeoutInMinutes"].(float64); ok {
				rule.Properties.IdleTimeoutInMinutes = int32Ptr(int32(iv))
			}
			if dis, ok := rMap["disableOutboundSnat"].(bool); ok {
				rule.Properties.DisableOutboundSnat = &dis
			}
			if ld, ok := rMap["loadDistribution"].(string); ok && ld != "" {
				dist := armnetwork.LoadDistribution(ld)
				rule.Properties.LoadDistribution = &dist
			}
			rules = append(rules, rule)
		}
		params.Properties.LoadBalancingRules = rules
	}

	return params, nil
}

// serializeLoadBalancerProperties converts an Azure LoadBalancer to Formae property format.
func serializeLoadBalancerProperties(result armnetwork.LoadBalancer, rgName, lbName string) (json.RawMessage, error) {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	if result.Name != nil {
		props["name"] = *result.Name
	} else {
		props["name"] = lbName
	}
	if result.Location != nil {
		props["location"] = *result.Location
	}
	if result.ID != nil {
		props["id"] = *result.ID
	}

	if result.SKU != nil {
		sku := make(map[string]any)
		if result.SKU.Name != nil {
			sku["name"] = string(*result.SKU.Name)
		}
		if result.SKU.Tier != nil {
			sku["tier"] = string(*result.SKU.Tier)
		}
		props["sku"] = sku
	}

	if result.Properties != nil {
		if len(result.Properties.FrontendIPConfigurations) > 0 {
			out := make([]map[string]any, 0, len(result.Properties.FrontendIPConfigurations))
			for _, f := range result.Properties.FrontendIPConfigurations {
				if f == nil {
					continue
				}
				m := make(map[string]any)
				if f.Name != nil {
					m["name"] = *f.Name
				}
				if f.Properties != nil && f.Properties.PublicIPAddress != nil && f.Properties.PublicIPAddress.ID != nil {
					m["publicIPAddressId"] = *f.Properties.PublicIPAddress.ID
				}
				out = append(out, m)
			}
			props["frontendIPConfigurations"] = out
		}

		if len(result.Properties.BackendAddressPools) > 0 {
			out := make([]map[string]any, 0, len(result.Properties.BackendAddressPools))
			for _, p := range result.Properties.BackendAddressPools {
				if p == nil {
					continue
				}
				m := make(map[string]any)
				if p.Name != nil {
					m["name"] = *p.Name
				}
				out = append(out, m)
			}
			props["backendAddressPools"] = out
		}

		if len(result.Properties.Probes) > 0 {
			out := make([]map[string]any, 0, len(result.Properties.Probes))
			for _, p := range result.Properties.Probes {
				if p == nil {
					continue
				}
				m := make(map[string]any)
				if p.Name != nil {
					m["name"] = *p.Name
				}
				if p.Properties != nil {
					if p.Properties.Protocol != nil {
						m["protocol"] = string(*p.Properties.Protocol)
					}
					if p.Properties.Port != nil {
						m["port"] = *p.Properties.Port
					}
					if p.Properties.RequestPath != nil {
						m["requestPath"] = *p.Properties.RequestPath
					}
					if p.Properties.IntervalInSeconds != nil {
						m["intervalInSeconds"] = *p.Properties.IntervalInSeconds
					}
					if p.Properties.NumberOfProbes != nil {
						m["numberOfProbes"] = *p.Properties.NumberOfProbes
					}
				}
				out = append(out, m)
			}
			props["probes"] = out
		}

		if len(result.Properties.LoadBalancingRules) > 0 {
			out := make([]map[string]any, 0, len(result.Properties.LoadBalancingRules))
			for _, r := range result.Properties.LoadBalancingRules {
				if r == nil {
					continue
				}
				m := make(map[string]any)
				if r.Name != nil {
					m["name"] = *r.Name
				}
				if r.Properties != nil {
					if r.Properties.FrontendIPConfiguration != nil && r.Properties.FrontendIPConfiguration.ID != nil {
						name, err := loadBalancerChildName(*r.Properties.FrontendIPConfiguration.ID, "frontendIPConfigurations")
						if err != nil {
							return nil, err
						}
						m["frontendIPConfigurationName"] = name
					}
					if r.Properties.BackendAddressPool != nil && r.Properties.BackendAddressPool.ID != nil {
						name, err := loadBalancerChildName(*r.Properties.BackendAddressPool.ID, "backendAddressPools")
						if err != nil {
							return nil, err
						}
						m["backendAddressPoolName"] = name
					}
					if r.Properties.Probe != nil && r.Properties.Probe.ID != nil {
						name, err := loadBalancerChildName(*r.Properties.Probe.ID, "probes")
						if err != nil {
							return nil, err
						}
						m["probeName"] = name
					}
					if r.Properties.Protocol != nil {
						m["protocol"] = string(*r.Properties.Protocol)
					}
					if r.Properties.FrontendPort != nil {
						m["frontendPort"] = *r.Properties.FrontendPort
					}
					if r.Properties.BackendPort != nil {
						m["backendPort"] = *r.Properties.BackendPort
					}
					if r.Properties.IdleTimeoutInMinutes != nil {
						m["idleTimeoutInMinutes"] = *r.Properties.IdleTimeoutInMinutes
					}
					if r.Properties.DisableOutboundSnat != nil {
						m["disableOutboundSnat"] = *r.Properties.DisableOutboundSnat
					}
					if r.Properties.LoadDistribution != nil {
						m["loadDistribution"] = string(*r.Properties.LoadDistribution)
					}
				}
				out = append(out, m)
			}
			props["loadBalancingRules"] = out
		}
	}

	if tags := azureTagsToFormaeTags(result.Tags); tags != nil {
		props["Tags"] = tags
	}

	return json.Marshal(props)
}

func loadBalancerNativeIDParts(resourceID string) (rgName, lbName string, err error) {
	rgName, names, err := armIDParts(resourceID, "loadBalancers")
	if err != nil {
		return "", "", err
	}
	return rgName, names["loadBalancers"], nil
}

func loadBalancerChildName(resourceID, childType string) (string, error) {
	_, names, err := armIDParts(resourceID, "loadBalancers", childType)
	if err != nil {
		return "", err
	}
	return names[childType], nil
}

func int32Ptr(v int32) *int32 { return &v }

func (lb *LoadBalancer) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
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
	lbName, ok := props["name"].(string)
	if !ok || lbName == "" {
		lbName = request.Label
	}

	params, err := lb.buildLoadBalancerParams(props, rgName, lbName, location)
	if err != nil {
		return nil, err
	}
	if azureTags := formaeTagsToAzureTags(request.Properties); azureTags != nil {
		params.Tags = azureTags
	}

	poller, err := lb.api.BeginCreateOrUpdate(ctx, rgName, lbName, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/loadBalancers/%s",
		lb.config.SubscriptionId, rgName, lbName)

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
		propsJSON, err := serializeLoadBalancerProperties(result.LoadBalancer, rgName, lbName)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize LoadBalancer properties: %w", err)
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

func (lb *LoadBalancer) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, lbName, err := loadBalancerNativeIDParts(request.NativeID)
	if err != nil {
		return nil, fmt.Errorf("invalid NativeID: cannot extract resourceGroup or loadBalancer name from %s: %w", request.NativeID, err)
	}

	result, err := lb.api.Get(ctx, rgName, lbName, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}
	propsJSON, err := serializeLoadBalancerProperties(result.LoadBalancer, rgName, lbName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize LoadBalancer properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeLoadBalancer,
		Properties:   string(propsJSON),
	}, nil
}

func (lb *LoadBalancer) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, lbName, err := loadBalancerNativeIDParts(request.NativeID)
	if err != nil {
		return nil, fmt.Errorf("invalid NativeID: cannot extract resourceGroup or loadBalancer name from %s: %w", request.NativeID, err)
	}

	var props map[string]any
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	location, ok := props["location"].(string)
	if !ok || location == "" {
		return nil, fmt.Errorf("location is required")
	}

	params, err := lb.buildLoadBalancerParams(props, rgName, lbName, location)
	if err != nil {
		return nil, err
	}
	if azureTags := formaeTagsToAzureTags(request.DesiredProperties); azureTags != nil {
		params.Tags = azureTags
	}

	poller, err := lb.api.BeginCreateOrUpdate(ctx, rgName, lbName, params, nil)
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
		propsJSON, err := serializeLoadBalancerProperties(result.LoadBalancer, rgName, lbName)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize LoadBalancer properties: %w", err)
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

func (lb *LoadBalancer) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, lbName, err := loadBalancerNativeIDParts(request.NativeID)
	if err != nil {
		return nil, fmt.Errorf("invalid NativeID: cannot extract resourceGroup or loadBalancer name from %s: %w", request.NativeID, err)
	}

	poller, err := lb.api.BeginDelete(ctx, rgName, lbName, nil)
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
		}, fmt.Errorf("failed to start LoadBalancer deletion: %w", err)
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

func (lb *LoadBalancer) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
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
		return lb.statusCreateOrUpdate(ctx, request, &reqID)
	case lroOpDelete:
		return lb.statusDelete(ctx, request, &reqID)
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

func (lb *LoadBalancer) statusCreateOrUpdate(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	operation := resource.OperationCreate
	if reqID.OperationType == lroOpUpdate {
		operation = resource.OperationUpdate
	}

	return statusLRO(ctx, request, reqID, operation,
		func(token string) (*runtime.Poller[armnetwork.LoadBalancersClientCreateOrUpdateResponse], error) {
			return resumePoller[armnetwork.LoadBalancersClientCreateOrUpdateResponse](lb.pipeline, token)
		},
		func(_ context.Context, result armnetwork.LoadBalancersClientCreateOrUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
			rgName, lbName, err := loadBalancerNativeIDParts(*result.ID)
			if err != nil {
				return "", nil, err
			}
			propsJSON, err := serializeLoadBalancerProperties(result.LoadBalancer, rgName, lbName)
			if err != nil {
				return "", nil, fmt.Errorf("failed to serialize LoadBalancer properties: %w", err)
			}
			return *result.ID, propsJSON, nil
		})
}

func (lb *LoadBalancer) statusDelete(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	return statusDeleteLRO(ctx, request, reqID,
		func(token string) (*runtime.Poller[armnetwork.LoadBalancersClientDeleteResponse], error) {
			return resumePoller[armnetwork.LoadBalancersClientDeleteResponse](lb.pipeline, token)
		}, nil)
}

func (lb *LoadBalancer) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	resourceGroupName := request.AdditionalProperties["resourceGroupName"]

	var nativeIDs []string
	if resourceGroupName != "" {
		pager := lb.api.NewListPager(resourceGroupName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list load balancers: %w", err)
			}
			for _, x := range page.Value {
				if x != nil && x.ID != nil {
					nativeIDs = append(nativeIDs, *x.ID)
				}
			}
		}
	} else {
		pager := lb.api.NewListAllPager(nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list load balancers: %w", err)
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
