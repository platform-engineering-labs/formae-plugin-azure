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

const ResourceTypeFirewallPolicy = "AZURE::Network::FirewallPolicy"

// firewallPoliciesAPI is the subset of *armnetwork.FirewallPoliciesClient used
// here. Create/delete are LROs; UpdateTags is synchronous but unused, because the
// policy's own properties can only change through the full-body PUT.
type firewallPoliciesAPI interface {
	BeginCreateOrUpdate(ctx context.Context, resourceGroupName, firewallPolicyName string, parameters armnetwork.FirewallPolicy, options *armnetwork.FirewallPoliciesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.FirewallPoliciesClientCreateOrUpdateResponse], error)
	Get(ctx context.Context, resourceGroupName, firewallPolicyName string, options *armnetwork.FirewallPoliciesClientGetOptions) (armnetwork.FirewallPoliciesClientGetResponse, error)
	BeginDelete(ctx context.Context, resourceGroupName, firewallPolicyName string, options *armnetwork.FirewallPoliciesClientBeginDeleteOptions) (*runtime.Poller[armnetwork.FirewallPoliciesClientDeleteResponse], error)
	NewListPager(resourceGroupName string, options *armnetwork.FirewallPoliciesClientListOptions) *runtime.Pager[armnetwork.FirewallPoliciesClientListResponse]
	NewListAllPager(options *armnetwork.FirewallPoliciesClientListAllOptions) *runtime.Pager[armnetwork.FirewallPoliciesClientListAllResponse]
}

func init() {
	registry.Register(ResourceTypeFirewallPolicy, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &FirewallPolicy{api: c.FirewallPoliciesClient, config: cfg, pipeline: c.Pipeline()}
	})
}

// FirewallPolicy is the provisioner for Azure Firewall policies
// (`Microsoft.Network/firewallPolicies/<name>`) — the rule container an
// `AZURE::Network::AzureFirewall` attaches to. A policy on its own carries no
// hourly charge, which is what makes it cheap to exercise.
//
// The advanced blocks are deliberately not modelled: `insights`,
// `intrusionDetection`, `explicitProxySettings`, `sql`, `snat`,
// `transportSecurity`, `threatIntelWhitelist` and `identity`. Each is an optional
// nested tree, and ARM echoes defaults into any block that is present — since
// provider defaults are only honoured on top-level resource fields, modelling them
// half-way would guarantee drift. Add them when a consumer needs them.
//
// ponytail: rule collections live in AZURE::Network::FirewallPolicyRuleCollectionGroup,
// a separate resource, so nothing here has to deal with the polymorphic rule union.
type FirewallPolicy struct {
	api      firewallPoliciesAPI
	config   *config.Config
	pipeline runtime.Pipeline
}

func firewallPolicyIDParts(resourceID string) (rgName, name string, err error) {
	rgName, names, err := armExactIDParts(resourceID, "firewallpolicies")
	if err != nil {
		return "", "", err
	}
	return rgName, names[0], nil
}

func serializeFirewallPolicyProperties(result armnetwork.FirewallPolicy, rgName, name string) (json.RawMessage, error) {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	if result.Name != nil {
		props["name"] = *result.Name
	} else {
		props["name"] = name
	}
	if result.Location != nil {
		props["location"] = *result.Location
	}
	if result.ID != nil {
		props["id"] = *result.ID
	}

	if result.Properties != nil {
		p := result.Properties
		if p.SKU != nil && p.SKU.Tier != nil {
			props["sku"] = map[string]any{"tier": string(*p.SKU.Tier)}
		}
		if p.ThreatIntelMode != nil {
			props["threatIntelMode"] = string(*p.ThreatIntelMode)
		}
		if p.BasePolicy != nil && p.BasePolicy.ID != nil {
			props["basePolicyId"] = *p.BasePolicy.ID
		}
		// ARM returns dnsSettings unconditionally — as `{"servers": []}` even for a
		// policy that never set it — and it drops `enableProxy: false` rather than
		// echoing it back. Emitting that empty block would be permanent drift against
		// a forma that declares no dnsSettings, so only a block with real content is
		// kept.
		if p.DNSSettings != nil {
			dns := map[string]any{}
			if p.DNSSettings.EnableProxy != nil {
				dns["enableProxy"] = *p.DNSSettings.EnableProxy
			}
			if servers := stringSliceFromPtrs(p.DNSSettings.Servers); servers != nil {
				dns["servers"] = servers
			}
			if len(dns) > 0 {
				props["dnsSettings"] = dns
			}
		}
		// childPolicies, firewalls, ruleCollectionGroups, provisioningState and size
		// are read-only ARM output with no schema field.
	}

	if tags := azureTagsToFormaeTags(result.Tags); tags != nil {
		props["Tags"] = tags
	}

	return json.Marshal(props)
}

// stringSliceFromPtrs flattens a []*string, dropping nils. Order is preserved:
// unlike IpGroup.ipAddresses, ARM echoes DNS server lists back as submitted, and
// resolution order is significant.
func stringSliceFromPtrs(in []*string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s != nil {
			out = append(out, *s)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// stringPtrsFromAny is the inverse of stringSliceFromPtrs for a JSON []any.
func stringPtrsFromAny(raw []any) []*string {
	if len(raw) == 0 {
		return nil
	}
	out := make([]*string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok && s != "" {
			out = append(out, to.Ptr(s))
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func firewallPolicyParamsFromProperties(props map[string]any, rawProps json.RawMessage) (armnetwork.FirewallPolicy, error) {
	location, _ := props["location"].(string)
	if location == "" {
		return armnetwork.FirewallPolicy{}, fmt.Errorf("location is required")
	}

	fp := armnetwork.FirewallPolicy{
		Location:   to.Ptr(location),
		Properties: &armnetwork.FirewallPolicyPropertiesFormat{},
	}

	if skuMap, ok := props["sku"].(map[string]any); ok {
		if tier, ok := skuMap["tier"].(string); ok && tier != "" {
			fp.Properties.SKU = &armnetwork.FirewallPolicySKU{
				Tier: to.Ptr(armnetwork.FirewallPolicySKUTier(tier)),
			}
		}
	}
	if v, ok := props["threatIntelMode"].(string); ok && v != "" {
		fp.Properties.ThreatIntelMode = to.Ptr(armnetwork.AzureFirewallThreatIntelMode(v))
	}
	if v, ok := props["basePolicyId"].(string); ok && v != "" {
		fp.Properties.BasePolicy = &armnetwork.SubResource{ID: to.Ptr(v)}
	}
	// dnsSettings.requireProxyForNetworkRules is never sent: ARM rejects any body
	// carrying it with FirewallPolicyDeprecatedRequireProxyForNetworkRules
	// ("deprecated for all the API Versions"), so it is not modelled at all.
	if dnsMap, ok := props["dnsSettings"].(map[string]any); ok {
		dns := &armnetwork.DNSSettings{}
		if v, ok := dnsMap["enableProxy"].(bool); ok {
			dns.EnableProxy = to.Ptr(v)
		}
		if raw, ok := dnsMap["servers"].([]any); ok {
			dns.Servers = stringPtrsFromAny(raw)
		}
		fp.Properties.DNSSettings = dns
	}

	if azureTags := formaeTagsToAzureTags(rawProps); azureTags != nil {
		fp.Tags = azureTags
	}

	return fp, nil
}

func (f *FirewallPolicy) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props map[string]any
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	rgName, _ := props["resourceGroupName"].(string)
	if rgName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	name, _ := props["name"].(string)
	if name == "" {
		name = request.Label
	}
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}

	params, err := firewallPolicyParamsFromProperties(props, request.Properties)
	if err != nil {
		return nil, err
	}

	poller, err := f.api.BeginCreateOrUpdate(ctx, rgName, name, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	expectedID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/firewallPolicies/%s",
		f.config.SubscriptionId, rgName, name)

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
		propsJSON, err := serializeFirewallPolicyProperties(result.FirewallPolicy, rgName, name)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize FirewallPolicy properties: %w", err)
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

	token, err := poller.ResumeToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get resume token: %w", err)
	}
	reqID, err := encodeLROStart(lroOpCreate, token, expectedID)
	if err != nil {
		return nil, err
	}

	return &resource.CreateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationCreate,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       reqID,
			NativeID:        expectedID,
		},
	}, nil
}

func (f *FirewallPolicy) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, name, err := firewallPolicyIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := f.api.Get(ctx, rgName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := serializeFirewallPolicyProperties(result.FirewallPolicy, rgName, name)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize FirewallPolicy properties: %w", err)
	}

	return &resource.ReadResult{
		ResourceType: ResourceTypeFirewallPolicy,
		Properties:   string(propsJSON),
	}, nil
}

func (f *FirewallPolicy) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, name, err := firewallPolicyIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props map[string]any
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse desired properties: %w", err)
	}

	// The PATCH verb (UpdateTags) accepts tags only, so threatIntelMode and DNS
	// changes have to go through the full-body PUT.
	params, err := firewallPolicyParamsFromProperties(props, request.DesiredProperties)
	if err != nil {
		return nil, err
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
		propsJSON, err := serializeFirewallPolicyProperties(result.FirewallPolicy, rgName, name)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize FirewallPolicy properties: %w", err)
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

	token, err := poller.ResumeToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get resume token: %w", err)
	}
	reqID, err := encodeLROStart(lroOpUpdate, token, request.NativeID)
	if err != nil {
		return nil, err
	}

	return &resource.UpdateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationUpdate,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       reqID,
			NativeID:        request.NativeID,
		},
	}, nil
}

func (f *FirewallPolicy) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, name, err := firewallPolicyIDParts(request.NativeID)
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
		}, fmt.Errorf("failed to delete FirewallPolicy: %w", err)
	}

	if poller.Done() {
		return &resource.DeleteResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationDelete,
				OperationStatus: resource.OperationStatusSuccess,
				NativeID:        request.NativeID,
			},
		}, nil
	}

	token, err := poller.ResumeToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get resume token: %w", err)
	}
	reqID, err := encodeLROStart(lroOpDelete, token, request.NativeID)
	if err != nil {
		return nil, err
	}

	return &resource.DeleteResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationDelete,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       reqID,
			NativeID:        request.NativeID,
		},
	}, nil
}

func (f *FirewallPolicy) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
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
		return f.statusCreateOrUpdate(ctx, request, &reqID)
	case lroOpDelete:
		return statusDeleteLRO(ctx, request, &reqID,
			func(token string) (*runtime.Poller[armnetwork.FirewallPoliciesClientDeleteResponse], error) {
				return resumePoller[armnetwork.FirewallPoliciesClientDeleteResponse](f.pipeline, token)
			}, nil)
	default:
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
			},
		}, fmt.Errorf("unknown LRO operation type: %s", reqID.OperationType)
	}
}

func (f *FirewallPolicy) statusCreateOrUpdate(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	operation := resource.OperationCreate
	if reqID.OperationType == lroOpUpdate {
		operation = resource.OperationUpdate
	}

	return statusLRO(ctx, request, reqID, operation,
		func(token string) (*runtime.Poller[armnetwork.FirewallPoliciesClientCreateOrUpdateResponse], error) {
			return resumePoller[armnetwork.FirewallPoliciesClientCreateOrUpdateResponse](f.pipeline, token)
		},
		func(_ context.Context, result armnetwork.FirewallPoliciesClientCreateOrUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
			rgName, name, err := firewallPolicyIDParts(*result.ID)
			if err != nil {
				return "", nil, err
			}
			propsJSON, err := serializeFirewallPolicyProperties(result.FirewallPolicy, rgName, name)
			if err != nil {
				return "", nil, fmt.Errorf("failed to serialize FirewallPolicy properties: %w", err)
			}
			return *result.ID, propsJSON, nil
		})
}

func (f *FirewallPolicy) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]

	var nativeIDs []string
	if rgName != "" {
		pager := f.api.NewListPager(rgName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list firewall policies in resource group %s: %w", rgName, err)
			}
			for _, fp := range page.Value {
				if fp.ID != nil {
					nativeIDs = append(nativeIDs, *fp.ID)
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
		for _, fp := range page.Value {
			if fp.ID != nil {
				nativeIDs = append(nativeIDs, *fp.ID)
			}
		}
	}

	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
