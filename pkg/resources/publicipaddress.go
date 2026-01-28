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

func init() {
	registry.Register(ResourceTypePublicIPAddress, func(client *client.Client, cfg *config.Config) prov.Provisioner {
		return &PublicIPAddress{client, cfg}
	})
}

// PublicIPAddress is the provisioner for Azure Public IP Addresses.
type PublicIPAddress struct {
	Client *client.Client
	Config *config.Config
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

	poller, err := p.Client.PublicIPAddressesClient.BeginCreateOrUpdate(ctx, rgName, pipName, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,

				ErrorCode: mapAzureErrorToOperationErrorCode(err),
			},
		}, fmt.Errorf("failed to start PublicIP creation: %w", err)
	}

	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/publicIPAddresses/%s",
		p.Config.SubscriptionId, rgName, pipName)

	if poller.Done() {
		result, err := poller.Result(ctx)
		if err != nil {
			return &resource.CreateResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationCreate,
					OperationStatus: resource.OperationStatusFailure,

					ErrorCode: mapAzureErrorToOperationErrorCode(err),
				},
			}, fmt.Errorf("failed to get PublicIP create result: %w", err)
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

func (p *PublicIPAddress) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	parts := splitResourceID(request.NativeID)

	rgName, ok := parts["resourcegroups"]
	if !ok || rgName == "" {
		return nil, fmt.Errorf("invalid NativeID: could not extract resource group name from %s", request.NativeID)
	}

	pipName, ok := parts["publicipaddresses"]
	if !ok || pipName == "" {
		return nil, fmt.Errorf("invalid NativeID: could not extract PublicIP name from %s", request.NativeID)
	}

	result, err := p.Client.PublicIPAddressesClient.Get(ctx, rgName, pipName, nil)
	if err != nil {
		return &resource.ReadResult{

			ErrorCode: mapAzureErrorToOperationErrorCode(err),
		}, fmt.Errorf("failed to read PublicIP: %w", err)
	}

	propsJSON, err := serializePublicIPProperties(result.PublicIPAddress, rgName, pipName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize PublicIP properties: %w", err)
	}

	return &resource.ReadResult{

		Properties: string(propsJSON),
	}, nil
}

func (p *PublicIPAddress) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	parts := splitResourceID(request.NativeID)

	rgName, ok := parts["resourcegroups"]
	if !ok || rgName == "" {
		return nil, fmt.Errorf("invalid NativeID: could not extract resource group name from %s", request.NativeID)
	}

	pipName, ok := parts["publicipaddresses"]
	if !ok || pipName == "" {
		return nil, fmt.Errorf("invalid NativeID: could not extract PublicIP name from %s", request.NativeID)
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

	poller, err := p.Client.PublicIPAddressesClient.BeginCreateOrUpdate(ctx, rgName, pipName, params, nil)
	if err != nil {
		return &resource.UpdateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationUpdate,
				OperationStatus: resource.OperationStatusFailure,
				NativeID:        request.NativeID,

				ErrorCode: mapAzureErrorToOperationErrorCode(err),
			},
		}, fmt.Errorf("failed to start PublicIP update: %w", err)
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
			}, fmt.Errorf("failed to get PublicIP update result: %w", err)
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

func (p *PublicIPAddress) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	parts := splitResourceID(request.NativeID)

	rgName, ok := parts["resourcegroups"]
	if !ok || rgName == "" {
		return nil, fmt.Errorf("invalid NativeID: could not extract resource group name from %s", request.NativeID)
	}

	pipName, ok := parts["publicipaddresses"]
	if !ok || pipName == "" {
		return nil, fmt.Errorf("invalid NativeID: could not extract PublicIP name from %s", request.NativeID)
	}

	poller, err := p.Client.PublicIPAddressesClient.BeginDelete(ctx, rgName, pipName, nil)
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
		}, fmt.Errorf("failed to start PublicIP deletion: %w", err)
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

func (p *PublicIPAddress) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
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
		return p.statusCreateOrUpdate(ctx, request, &reqID)
	case "delete":
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

	poller, err := p.Client.ResumeCreatePublicIPAddressPoller(reqID.ResumeToken)
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
		return p.handleCreateOrUpdateComplete(ctx, request, poller, operation)
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
		return p.handleCreateOrUpdateComplete(ctx, request, poller, operation)
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

func (p *PublicIPAddress) handleCreateOrUpdateComplete(ctx context.Context, request *resource.StatusRequest, poller *runtime.Poller[armnetwork.PublicIPAddressesClientCreateOrUpdateResponse], operation resource.Operation) (*resource.StatusResult, error) {
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

	propsJSON, err := serializePublicIPProperties(result.PublicIPAddress, rgName, *result.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize PublicIP properties: %w", err)
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

func (p *PublicIPAddress) statusDelete(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	poller, err := p.Client.ResumeDeletePublicIPAddressPoller(reqID.ResumeToken)
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

func (p *PublicIPAddress) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	resourceGroupName, ok := request.AdditionalProperties["resourceGroupName"]
	if !ok || resourceGroupName == "" {
		return nil, fmt.Errorf("resourceGroupName is required in AdditionalProperties for listing PublicIPAddresses")
	}

	pager := p.Client.PublicIPAddressesClient.NewListPager(resourceGroupName, nil)

	var nativeIDs []string

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list public IP addresses in resource group %s: %w", resourceGroupName, err)
		}

		for _, pip := range page.Value {
			if pip.ID == nil {
				continue
			}

			nativeIDs = append(nativeIDs, *pip.ID)
		}
	}

	return &resource.ListResult{

		NativeIDs: nativeIDs,
	}, nil
}
