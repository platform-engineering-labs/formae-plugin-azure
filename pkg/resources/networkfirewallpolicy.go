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

const ResourceTypeNetworkFirewallPolicy = "AZURE::Network::FirewallPolicy"

// networkFirewallPoliciesAPI is the armnetwork surface used here. Create and delete
// are LROs; there is no full PATCH verb — only UpdateTags, which cannot change
// threatIntelMode or the DNS settings — so an update is another CreateOrUpdate.
type networkFirewallPoliciesAPI interface {
	BeginCreateOrUpdate(ctx context.Context, resourceGroupName string, firewallPolicyName string, parameters armnetwork.FirewallPolicy, options *armnetwork.FirewallPoliciesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.FirewallPoliciesClientCreateOrUpdateResponse], error)
	Get(ctx context.Context, resourceGroupName string, firewallPolicyName string, options *armnetwork.FirewallPoliciesClientGetOptions) (armnetwork.FirewallPoliciesClientGetResponse, error)
	BeginDelete(ctx context.Context, resourceGroupName string, firewallPolicyName string, options *armnetwork.FirewallPoliciesClientBeginDeleteOptions) (*runtime.Poller[armnetwork.FirewallPoliciesClientDeleteResponse], error)
	NewListPager(resourceGroupName string, options *armnetwork.FirewallPoliciesClientListOptions) *runtime.Pager[armnetwork.FirewallPoliciesClientListResponse]
	NewListAllPager(options *armnetwork.FirewallPoliciesClientListAllOptions) *runtime.Pager[armnetwork.FirewallPoliciesClientListAllResponse]
}

func init() {
	registry.Register(ResourceTypeNetworkFirewallPolicy, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &NetworkFirewallPolicy{
			api:      c.FirewallPoliciesClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// NetworkFirewallPolicy is the provisioner for Azure Firewall policies
// (Microsoft.Network/firewallPolicies).
type NetworkFirewallPolicy struct {
	api      networkFirewallPoliciesAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

// networkFirewallPolicyProps mirrors schema/pkl/network/firewallpolicy.pkl.
type networkFirewallPolicyProps struct {
	Name              string                           `json:"name"`
	Location          string                           `json:"location"`
	ResourceGroupName string                           `json:"resourceGroupName"`
	SKUTier           string                           `json:"skuTier"`
	ThreatIntelMode   string                           `json:"threatIntelMode"`
	DNSSettings       *networkFirewallDNSSettingsProps `json:"dnsSettings"`
}

type networkFirewallDNSSettingsProps struct {
	EnableProxy bool     `json:"enableProxy"`
	Servers     []string `json:"servers"`
}

func networkFirewallPolicyIDParts(resourceID string) (rgName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "firewallpolicies")
	if err != nil {
		return "", "", err
	}
	return rgName, names["firewallpolicies"], nil
}

func (f *NetworkFirewallPolicy) buildPropertiesFromResult(policy *armnetwork.FirewallPolicy, rgName string) map[string]any {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName

	if policy.ID != nil {
		props["id"] = *policy.ID
	}
	if policy.Name != nil {
		props["name"] = *policy.Name
	}
	if policy.Location != nil {
		props["location"] = normalizeAzureLocation(*policy.Location)
	}

	if p := policy.Properties; p != nil {
		if p.SKU != nil && p.SKU.Tier != nil {
			props["skuTier"] = canonicalizeEnum(string(*p.SKU.Tier), "Basic", "Standard", "Premium")
		}
		if p.ThreatIntelMode != nil {
			props["threatIntelMode"] = canonicalizeEnum(string(*p.ThreatIntelMode), "Alert", "Deny", "Off")
		}
		if dns := p.DNSSettings; dns != nil {
			settings := make(map[string]any)
			if dns.EnableProxy != nil {
				settings["enableProxy"] = *dns.EnableProxy
			}
			if len(dns.Servers) > 0 {
				servers := make([]string, 0, len(dns.Servers))
				for _, server := range dns.Servers {
					if server == nil {
						continue
					}
					servers = append(servers, *server)
				}
				settings["servers"] = servers
			}
			// requireProxyForNetworkRules is not modelled.
			if len(settings) > 0 {
				props["dnsSettings"] = settings
			}
		}
		// intrusionDetection, transportSecurity, explicitProxySettings, snat, sql,
		// basePolicy, threatIntelWhitelist and insights are not modelled, so they are
		// not read back. childPolicies, firewalls and ruleCollectionGroups are ARM's
		// back-references to other resources, not this one's desired state.
	}

	if tags := azureTagsToFormaeTags(policy.Tags); tags != nil {
		props["Tags"] = tags
	}

	return props
}

// networkFirewallPolicyParams builds the request body shared by create and update.
func networkFirewallPolicyParams(props networkFirewallPolicyProps) armnetwork.FirewallPolicy {
	policyProps := &armnetwork.FirewallPolicyPropertiesFormat{}

	if props.SKUTier != "" {
		policyProps.SKU = &armnetwork.FirewallPolicySKU{
			Tier: to.Ptr(armnetwork.FirewallPolicySKUTier(props.SKUTier)),
		}
	}
	if props.ThreatIntelMode != "" {
		policyProps.ThreatIntelMode = to.Ptr(armnetwork.AzureFirewallThreatIntelMode(props.ThreatIntelMode))
	}
	if dns := props.DNSSettings; dns != nil {
		settings := &armnetwork.DNSSettings{EnableProxy: to.Ptr(dns.EnableProxy)}
		if len(dns.Servers) > 0 {
			servers := make([]*string, 0, len(dns.Servers))
			for _, server := range dns.Servers {
				servers = append(servers, to.Ptr(server))
			}
			settings.Servers = servers
		}
		policyProps.DNSSettings = settings
	}

	return armnetwork.FirewallPolicy{
		Location:   to.Ptr(props.Location),
		Properties: policyProps,
	}
}

func (f *NetworkFirewallPolicy) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props networkFirewallPolicyProps
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	if props.Location == "" {
		return nil, fmt.Errorf("location is required")
	}
	name := props.Name
	if name == "" {
		name = request.Label
	}
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}

	params := networkFirewallPolicyParams(props)
	if azureTags := formaeTagsToAzureTags(request.Properties); azureTags != nil {
		params.Tags = azureTags
	}

	poller, err := f.api.BeginCreateOrUpdate(ctx, props.ResourceGroupName, name, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/firewallPolicies/%s",
		f.config.SubscriptionId, props.ResourceGroupName, name)

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
		nativeID, propsJSON, err := f.completeFromPolicy(&result.FirewallPolicy)
		if err != nil {
			return nil, err
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

func (f *NetworkFirewallPolicy) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, name, err := networkFirewallPolicyIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := f.api.Get(ctx, rgName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(f.buildPropertiesFromResult(&result.FirewallPolicy, rgName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeNetworkFirewallPolicy,
		Properties:   string(propsJSON),
	}, nil
}

// Update re-PUTs through BeginCreateOrUpdate. The SDK's only update verb is
// UpdateTags, which cannot change threatIntelMode or the DNS settings, so a full
// PUT is the one path that covers every mutable property.
func (f *NetworkFirewallPolicy) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, name, err := networkFirewallPolicyIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props networkFirewallPolicyProps
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.Location == "" {
		return nil, fmt.Errorf("location is required")
	}

	params := networkFirewallPolicyParams(props)
	if azureTags := formaeTagsToAzureTags(request.DesiredProperties); azureTags != nil {
		params.Tags = azureTags
	}

	poller, err := f.api.BeginCreateOrUpdate(ctx, rgName, name, params, nil)
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
		propsJSON, err := json.Marshal(f.buildPropertiesFromResult(&result.FirewallPolicy, rgName))
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

func (f *NetworkFirewallPolicy) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, name, err := networkFirewallPolicyIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, err := f.api.BeginDelete(ctx, rgName, name, nil)
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

func (f *NetworkFirewallPolicy) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	reqID, err := decodeLROStatus(request.RequestID)
	if err != nil {
		return nil, err
	}

	switch reqID.OperationType {
	case lroOpCreate:
		return statusLRO(ctx, request, &reqID, resource.OperationCreate,
			func(token string) (*runtime.Poller[armnetwork.FirewallPoliciesClientCreateOrUpdateResponse], error) {
				return resumePoller[armnetwork.FirewallPoliciesClientCreateOrUpdateResponse](f.pipeline, token)
			},
			func(_ context.Context, result armnetwork.FirewallPoliciesClientCreateOrUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				return f.completeFromPolicy(&result.FirewallPolicy)
			})
	case lroOpUpdate:
		// Resumed as a CreateOrUpdate response: Update issues BeginCreateOrUpdate, so
		// that is the poller whose token was handed out. Decoding it as another
		// response type kills the plugin operator mid-poll.
		return statusLRO(ctx, request, &reqID, resource.OperationUpdate,
			func(token string) (*runtime.Poller[armnetwork.FirewallPoliciesClientCreateOrUpdateResponse], error) {
				return resumePoller[armnetwork.FirewallPoliciesClientCreateOrUpdateResponse](f.pipeline, token)
			},
			func(_ context.Context, result armnetwork.FirewallPoliciesClientCreateOrUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				return f.completeFromPolicy(&result.FirewallPolicy)
			})
	case lroOpDelete:
		return statusDeleteLRO(ctx, request, &reqID,
			func(token string) (*runtime.Poller[armnetwork.FirewallPoliciesClientDeleteResponse], error) {
				return resumePoller[armnetwork.FirewallPoliciesClientDeleteResponse](f.pipeline, token)
			}, nil)
	default:
		return nil, fmt.Errorf("unknown operation type: %s", reqID.OperationType)
	}
}

func (f *NetworkFirewallPolicy) completeFromPolicy(policy *armnetwork.FirewallPolicy) (string, json.RawMessage, error) {
	nativeID := ""
	rgName := ""
	if policy.ID != nil {
		nativeID = *policy.ID
		if rg, _, err := networkFirewallPolicyIDParts(*policy.ID); err == nil {
			rgName = rg
		}
	}
	propsJSON, err := json.Marshal(f.buildPropertiesFromResult(policy, rgName))
	if err != nil {
		return "", nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return nativeID, propsJSON, nil
}

func (f *NetworkFirewallPolicy) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]

	var nativeIDs []string

	if rgName != "" {
		pager := f.api.NewListPager(rgName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list firewall policies: %w", err)
			}
			for _, policy := range page.Value {
				if policy.ID != nil {
					nativeIDs = append(nativeIDs, *policy.ID)
				}
			}
		}
		return &resource.ListResult{NativeIDs: nativeIDs}, nil
	}

	pager := f.api.NewListAllPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list firewall policies: %w", err)
		}
		for _, policy := range page.Value {
			if policy.ID != nil {
				nativeIDs = append(nativeIDs, *policy.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
