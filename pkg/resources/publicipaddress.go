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

const ResourceTypePublicIPAddress = "Azure::Network::PublicIPAddress"

type publicIPAddressesAPI interface {
	BeginCreateOrUpdate(ctx context.Context, resourceGroupName string, publicIPAddressName string, parameters armnetwork.PublicIPAddress, options *armnetwork.PublicIPAddressesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.PublicIPAddressesClientCreateOrUpdateResponse], error)
	Get(ctx context.Context, resourceGroupName string, publicIPAddressName string, options *armnetwork.PublicIPAddressesClientGetOptions) (armnetwork.PublicIPAddressesClientGetResponse, error)
	BeginDelete(ctx context.Context, resourceGroupName string, publicIPAddressName string, options *armnetwork.PublicIPAddressesClientBeginDeleteOptions) (*runtime.Poller[armnetwork.PublicIPAddressesClientDeleteResponse], error)
	NewListPager(resourceGroupName string, options *armnetwork.PublicIPAddressesClientListOptions) *runtime.Pager[armnetwork.PublicIPAddressesClientListResponse]
	NewListAllPager(options *armnetwork.PublicIPAddressesClientListAllOptions) *runtime.Pager[armnetwork.PublicIPAddressesClientListAllResponse]
}

func init() {
	registry.Register(ResourceTypePublicIPAddress, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &PublicIPAddress{
			api:      c.PublicIPAddressesClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// PublicIPAddress is the provisioner for Azure Public IP Addresses.
type PublicIPAddress struct {
	api      publicIPAddressesAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

func parsePublicIPAddressNativeID(nativeID string) (rgName, pipName string, err error) {
	rgName, names, err := armIDParts(nativeID, "publicipaddresses")
	if err != nil {
		return "", "", err
	}
	return rgName, names["publicipaddresses"], nil
}

// serializePublicIPProperties converts an Azure PublicIPAddress to Formae property format
func serializePublicIPProperties(result armnetwork.PublicIPAddress, rgName, pipName string) (json.RawMessage, error) {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	if result.Name != nil {
		props["name"] = *result.Name
	} else {
		props["name"] = pipName
	}

	if result.Location != nil {
		props["location"] = *result.Location
	}

	// SKU
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

	// Properties
	if result.Properties != nil {
		if result.Properties.PublicIPAllocationMethod != nil {
			props["publicIPAllocationMethod"] = string(*result.Properties.PublicIPAllocationMethod)
		}
		if result.Properties.PublicIPAddressVersion != nil {
			props["publicIPAddressVersion"] = string(*result.Properties.PublicIPAddressVersion)
		}
		if result.Properties.IdleTimeoutInMinutes != nil {
			props["idleTimeoutInMinutes"] = *result.Properties.IdleTimeoutInMinutes
		}
		if result.Properties.IPAddress != nil {
			props["ipAddress"] = *result.Properties.IPAddress
		}
		if result.Properties.DNSSettings != nil {
			dns := make(map[string]any)
			if result.Properties.DNSSettings.DomainNameLabel != nil {
				dns["domainNameLabel"] = *result.Properties.DNSSettings.DomainNameLabel
			}
			if result.Properties.DNSSettings.Fqdn != nil {
				dns["fqdn"] = *result.Properties.DNSSettings.Fqdn
			}
			if result.Properties.DNSSettings.ReverseFqdn != nil {
				dns["reverseFqdn"] = *result.Properties.DNSSettings.ReverseFqdn
			}
			props["dnsSettings"] = dns
		}
	}

	// Add tags
	if tags := azureTagsToFormaeTags(result.Tags); tags != nil {
		props["Tags"] = tags
	}

	// Include id for resolvable references
	if result.ID != nil {
		props["id"] = *result.ID
	}

	return json.Marshal(props)
}

func (p *PublicIPAddress) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
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

	pipName, ok := props["name"].(string)
	if !ok || pipName == "" {
		pipName = request.Label
	}

	params := armnetwork.PublicIPAddress{
		Location:   stringPtr(location),
		Properties: &armnetwork.PublicIPAddressPropertiesFormat{},
	}

	// Parse SKU
	if skuRaw, ok := props["sku"].(map[string]any); ok {
		sku := &armnetwork.PublicIPAddressSKU{}
		if name, ok := skuRaw["name"].(string); ok {
			skuName := armnetwork.PublicIPAddressSKUName(name)
			sku.Name = &skuName
		}
		if tier, ok := skuRaw["tier"].(string); ok {
			skuTier := armnetwork.PublicIPAddressSKUTier(tier)
			sku.Tier = &skuTier
		}
		params.SKU = sku
	}

	// Parse allocation method
	if allocationMethod, ok := props["publicIPAllocationMethod"].(string); ok {
		method := armnetwork.IPAllocationMethod(allocationMethod)
		params.Properties.PublicIPAllocationMethod = &method
	}

	// Parse IP version
	if ipVersion, ok := props["publicIPAddressVersion"].(string); ok {
		version := armnetwork.IPVersion(ipVersion)
		params.Properties.PublicIPAddressVersion = &version
	}

	// Parse idle timeout
	if timeout, ok := props["idleTimeoutInMinutes"].(float64); ok {
		t := int32(timeout)
		params.Properties.IdleTimeoutInMinutes = &t
	}

	// Parse DNS settings
	if dnsRaw, ok := props["dnsSettings"].(map[string]any); ok {
		dns := &armnetwork.PublicIPAddressDNSSettings{}
		if label, ok := dnsRaw["domainNameLabel"].(string); ok {
			dns.DomainNameLabel = stringPtr(label)
		}
		if reverseFqdn, ok := dnsRaw["reverseFqdn"].(string); ok {
			dns.ReverseFqdn = stringPtr(reverseFqdn)
		}
		params.Properties.DNSSettings = dns
	}

	if azureTags := formaeTagsToAzureTags(request.Properties); azureTags != nil {
		params.Tags = azureTags
	}

	poller, err := p.api.BeginCreateOrUpdate(ctx, rgName, pipName, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,

				ErrorCode: operationErrorCode(err),
			},
		}, nil
	}

	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/publicIPAddresses/%s",
		p.config.SubscriptionId, rgName, pipName)

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

		propsJSON, err := serializePublicIPProperties(result.PublicIPAddress, rgName, pipName)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize PublicIP properties: %w", err)
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
			RequestID:       string(reqIDJSON),
			NativeID:        expectedNativeID,
		},
	}, nil
}

func (p *PublicIPAddress) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, pipName, err := parsePublicIPAddressNativeID(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := p.api.Get(ctx, rgName, pipName, nil)
	if err != nil {
		return &resource.ReadResult{

			ErrorCode: operationErrorCode(err),
		}, nil
	}

	propsJSON, err := serializePublicIPProperties(result.PublicIPAddress, rgName, pipName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize PublicIP properties: %w", err)
	}

	return &resource.ReadResult{
		ResourceType: ResourceTypePublicIPAddress,
		Properties:   string(propsJSON),
	}, nil
}

func (p *PublicIPAddress) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, pipName, err := parsePublicIPAddressNativeID(request.NativeID)
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

	params := armnetwork.PublicIPAddress{
		Location:   stringPtr(location),
		Properties: &armnetwork.PublicIPAddressPropertiesFormat{},
	}

	// Parse SKU (required for update too)
	if skuRaw, ok := props["sku"].(map[string]any); ok {
		sku := &armnetwork.PublicIPAddressSKU{}
		if name, ok := skuRaw["name"].(string); ok {
			skuName := armnetwork.PublicIPAddressSKUName(name)
			sku.Name = &skuName
		}
		if tier, ok := skuRaw["tier"].(string); ok {
			skuTier := armnetwork.PublicIPAddressSKUTier(tier)
			sku.Tier = &skuTier
		}
		params.SKU = sku
	}

	// Parse allocation method
	if allocationMethod, ok := props["publicIPAllocationMethod"].(string); ok {
		method := armnetwork.IPAllocationMethod(allocationMethod)
		params.Properties.PublicIPAllocationMethod = &method
	}

	// Parse IP version
	if ipVersion, ok := props["publicIPAddressVersion"].(string); ok {
		version := armnetwork.IPVersion(ipVersion)
		params.Properties.PublicIPAddressVersion = &version
	}

	// Parse idle timeout
	if timeout, ok := props["idleTimeoutInMinutes"].(float64); ok {
		t := int32(timeout)
		params.Properties.IdleTimeoutInMinutes = &t
	}

	// Parse DNS settings
	if dnsRaw, ok := props["dnsSettings"].(map[string]any); ok {
		dns := &armnetwork.PublicIPAddressDNSSettings{}
		if label, ok := dnsRaw["domainNameLabel"].(string); ok {
			dns.DomainNameLabel = stringPtr(label)
		}
		if reverseFqdn, ok := dnsRaw["reverseFqdn"].(string); ok {
			dns.ReverseFqdn = stringPtr(reverseFqdn)
		}
		params.Properties.DNSSettings = dns
	}

	if azureTags := formaeTagsToAzureTags(request.DesiredProperties); azureTags != nil {
		params.Tags = azureTags
	}

	poller, err := p.api.BeginCreateOrUpdate(ctx, rgName, pipName, params, nil)
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

		propsJSON, err := serializePublicIPProperties(result.PublicIPAddress, rgName, pipName)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize PublicIP properties: %w", err)
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
			RequestID:       string(reqIDJSON),
			NativeID:        request.NativeID,
		},
	}, nil
}

func (p *PublicIPAddress) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, pipName, err := parsePublicIPAddressNativeID(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, err := p.api.BeginDelete(ctx, rgName, pipName, nil)
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
		}, fmt.Errorf("failed to start PublicIP deletion: %w", err)
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
			RequestID:       string(reqIDJSON),
			NativeID:        request.NativeID,
		},
	}, nil
}

func (p *PublicIPAddress) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	reqID, err := decodeLROStatus(request.RequestID)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,

				ErrorCode: resource.OperationErrorCodeGeneralServiceException,
			},
		}, fmt.Errorf("failed to parse request ID: %w", err)
	}

	switch reqID.OperationType {
	case lroOpCreate, lroOpUpdate:
		return p.statusCreateOrUpdate(ctx, request, &reqID)
	case lroOpDelete:
		return p.statusDelete(ctx, request, &reqID)
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

func (p *PublicIPAddress) statusCreateOrUpdate(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	operation := resource.OperationCreate
	if reqID.OperationType == "update" {
		operation = resource.OperationUpdate
	}

	return statusLRO(ctx, request, reqID, operation,
		func(token string) (*runtime.Poller[armnetwork.PublicIPAddressesClientCreateOrUpdateResponse], error) {
			return resumePoller[armnetwork.PublicIPAddressesClientCreateOrUpdateResponse](p.pipeline, token)
		},
		func(_ context.Context, result armnetwork.PublicIPAddressesClientCreateOrUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
			nativeID := reqID.NativeID
			if result.ID != nil {
				nativeID = *result.ID
			}
			rgName, pipName, err := parsePublicIPAddressNativeID(nativeID)
			if err != nil {
				return "", nil, err
			}
			propsJSON, err := serializePublicIPProperties(result.PublicIPAddress, rgName, pipName)
			if err != nil {
				return "", nil, fmt.Errorf("failed to serialize PublicIP properties: %w", err)
			}
			return nativeID, propsJSON, nil
		})
}

func (p *PublicIPAddress) statusDelete(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	return statusDeleteLRO(ctx, request, reqID,
		func(token string) (*runtime.Poller[armnetwork.PublicIPAddressesClientDeleteResponse], error) {
			return resumePoller[armnetwork.PublicIPAddressesClientDeleteResponse](p.pipeline, token)
		},
		nil)
}

func (p *PublicIPAddress) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	resourceGroupName := request.AdditionalProperties["resourceGroupName"]

	var nativeIDs []string

	if resourceGroupName != "" {
		pager := p.api.NewListPager(resourceGroupName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list public IP addresses: %w", err)
			}
			for _, pip := range page.Value {
				if pip.ID != nil {
					nativeIDs = append(nativeIDs, *pip.ID)
				}
			}
		}
	} else {
		pager := p.api.NewListAllPager(nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list public IP addresses: %w", err)
			}
			for _, pip := range page.Value {
				if pip.ID != nil {
					nativeIDs = append(nativeIDs, *pip.ID)
				}
			}
		}
	}

	return &resource.ListResult{
		NativeIDs: nativeIDs,
	}, nil
}
