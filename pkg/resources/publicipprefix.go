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

const ResourceTypePublicIPPrefix = "AZURE::Network::PublicIPPrefix"

// publicIPPrefixesAPI is the subset of *armnetwork.PublicIPPrefixesClient used
// here. Create/update/delete are LROs.
type publicIPPrefixesAPI interface {
	BeginCreateOrUpdate(ctx context.Context, resourceGroupName string, publicIPPrefixName string, parameters armnetwork.PublicIPPrefix, options *armnetwork.PublicIPPrefixesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.PublicIPPrefixesClientCreateOrUpdateResponse], error)
	Get(ctx context.Context, resourceGroupName string, publicIPPrefixName string, options *armnetwork.PublicIPPrefixesClientGetOptions) (armnetwork.PublicIPPrefixesClientGetResponse, error)
	BeginDelete(ctx context.Context, resourceGroupName string, publicIPPrefixName string, options *armnetwork.PublicIPPrefixesClientBeginDeleteOptions) (*runtime.Poller[armnetwork.PublicIPPrefixesClientDeleteResponse], error)
	NewListPager(resourceGroupName string, options *armnetwork.PublicIPPrefixesClientListOptions) *runtime.Pager[armnetwork.PublicIPPrefixesClientListResponse]
	NewListAllPager(options *armnetwork.PublicIPPrefixesClientListAllOptions) *runtime.Pager[armnetwork.PublicIPPrefixesClientListAllResponse]
}

func init() {
	registry.Register(ResourceTypePublicIPPrefix, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &PublicIPPrefix{
			api:      c.PublicIPPrefixesClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// PublicIPPrefix is the provisioner for Azure public IP prefixes
// (`Microsoft.Network/publicIPPrefixes/<name>`). Everything except tags is
// immutable once allocated — the prefix itself (`ipPrefix`) is assigned by Azure
// and read-only.
type PublicIPPrefix struct {
	api      publicIPPrefixesAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

func serializePublicIPPrefixProperties(result armnetwork.PublicIPPrefix, rgName, name string) (json.RawMessage, error) {
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

	if result.SKU != nil {
		sku := map[string]any{}
		if result.SKU.Name != nil {
			sku["name"] = string(*result.SKU.Name)
		}
		if result.SKU.Tier != nil {
			sku["tier"] = string(*result.SKU.Tier)
		}
		if len(sku) > 0 {
			props["sku"] = sku
		}
	}

	if result.Properties != nil {
		if result.Properties.PrefixLength != nil {
			props["prefixLength"] = int(*result.Properties.PrefixLength)
		}
		if result.Properties.PublicIPAddressVersion != nil {
			props["publicIPAddressVersion"] = string(*result.Properties.PublicIPAddressVersion)
		}
		// ipPrefix is allocated by Azure; surfaced read-only so consumers can
		// reference the assigned CIDR.
		if result.Properties.IPPrefix != nil {
			props["ipPrefix"] = *result.Properties.IPPrefix
		}
		if len(result.Properties.IPTags) > 0 {
			ipTags := make([]map[string]any, 0, len(result.Properties.IPTags))
			for _, t := range result.Properties.IPTags {
				if t == nil {
					continue
				}
				entry := map[string]any{}
				if t.IPTagType != nil {
					entry["ipTagType"] = *t.IPTagType
				}
				if t.Tag != nil {
					entry["tag"] = *t.Tag
				}
				ipTags = append(ipTags, entry)
			}
			if len(ipTags) > 0 {
				props["ipTags"] = ipTags
			}
		}
	}

	if len(result.Zones) > 0 {
		zones := make([]string, 0, len(result.Zones))
		for _, z := range result.Zones {
			if z != nil {
				zones = append(zones, *z)
			}
		}
		props["zones"] = zones
	}

	if tags := azureTagsToFormaeTags(result.Tags); tags != nil {
		props["Tags"] = tags
	}

	return json.Marshal(props)
}

func publicIPPrefixParamsFromProperties(props map[string]any, rawProps json.RawMessage) (armnetwork.PublicIPPrefix, error) {
	location, _ := props["location"].(string)
	if location == "" {
		return armnetwork.PublicIPPrefix{}, fmt.Errorf("location is required")
	}

	prefix := armnetwork.PublicIPPrefix{
		Location:   stringPtr(location),
		Properties: &armnetwork.PublicIPPrefixPropertiesFormat{},
	}

	skuMap, ok := props["sku"].(map[string]any)
	if !ok {
		return armnetwork.PublicIPPrefix{}, fmt.Errorf("sku is required")
	}
	skuName, _ := skuMap["name"].(string)
	if skuName == "" {
		return armnetwork.PublicIPPrefix{}, fmt.Errorf("sku.name is required")
	}
	prefix.SKU = &armnetwork.PublicIPPrefixSKU{
		Name: to.Ptr(armnetwork.PublicIPPrefixSKUName(skuName)),
	}
	if tier, ok := skuMap["tier"].(string); ok && tier != "" {
		prefix.SKU.Tier = to.Ptr(armnetwork.PublicIPPrefixSKUTier(tier))
	}

	prefixLength, ok := props["prefixLength"].(float64)
	if !ok {
		return armnetwork.PublicIPPrefix{}, fmt.Errorf("prefixLength is required")
	}
	prefix.Properties.PrefixLength = to.Ptr(int32(prefixLength))

	if v, ok := props["publicIPAddressVersion"].(string); ok && v != "" {
		prefix.Properties.PublicIPAddressVersion = to.Ptr(armnetwork.IPVersion(v))
	}

	if rawTags, ok := props["ipTags"].([]any); ok && len(rawTags) > 0 {
		ipTags := make([]*armnetwork.IPTag, 0, len(rawTags))
		for i, raw := range rawTags {
			entry, ok := raw.(map[string]any)
			if !ok {
				return armnetwork.PublicIPPrefix{}, fmt.Errorf("ipTags[%d] must be an object", i)
			}
			tag := &armnetwork.IPTag{}
			if v, ok := entry["ipTagType"].(string); ok && v != "" {
				tag.IPTagType = stringPtr(v)
			}
			if v, ok := entry["tag"].(string); ok && v != "" {
				tag.Tag = stringPtr(v)
			}
			ipTags = append(ipTags, tag)
		}
		prefix.Properties.IPTags = ipTags
	}

	if rawZones, ok := props["zones"].([]any); ok && len(rawZones) > 0 {
		zones := make([]*string, 0, len(rawZones))
		for _, z := range rawZones {
			if s, ok := z.(string); ok {
				zones = append(zones, stringPtr(s))
			}
		}
		prefix.Zones = zones
	}

	if azureTags := formaeTagsToAzureTags(rawProps); azureTags != nil {
		prefix.Tags = azureTags
	}

	return prefix, nil
}

func publicIPPrefixIDParts(resourceID string) (rgName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "publicipprefixes")
	if err != nil {
		return "", "", err
	}
	return rgName, names["publicipprefixes"], nil
}

func (p *PublicIPPrefix) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
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

	params, err := publicIPPrefixParamsFromProperties(props, request.Properties)
	if err != nil {
		return nil, err
	}

	poller, err := p.api.BeginCreateOrUpdate(ctx, rgName, name, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	expectedID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/publicIPPrefixes/%s",
		p.config.SubscriptionId, rgName, name)

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
		propsJSON, err := serializePublicIPPrefixProperties(result.PublicIPPrefix, rgName, name)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize PublicIPPrefix properties: %w", err)
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

func (p *PublicIPPrefix) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, name, err := publicIPPrefixIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := p.api.Get(ctx, rgName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := serializePublicIPPrefixProperties(result.PublicIPPrefix, rgName, name)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize PublicIPPrefix properties: %w", err)
	}

	return &resource.ReadResult{
		ResourceType: ResourceTypePublicIPPrefix,
		Properties:   string(propsJSON),
	}, nil
}

func (p *PublicIPPrefix) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, name, err := publicIPPrefixIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props map[string]any
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse desired properties: %w", err)
	}

	// Full-body upsert: prefixLength/SKU/version are immutable (createOnly), but
	// ARM requires them present, so the same builder is reused for Create and
	// Update. Only tags can actually differ.
	params, err := publicIPPrefixParamsFromProperties(props, request.DesiredProperties)
	if err != nil {
		return nil, err
	}

	poller, err := p.api.BeginCreateOrUpdate(ctx, rgName, name, params, nil)
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
		propsJSON, err := serializePublicIPPrefixProperties(result.PublicIPPrefix, rgName, name)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize PublicIPPrefix properties: %w", err)
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

func (p *PublicIPPrefix) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, name, err := publicIPPrefixIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, err := p.api.BeginDelete(ctx, rgName, name, nil)
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
		}, fmt.Errorf("failed to delete PublicIPPrefix: %w", err)
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

func (p *PublicIPPrefix) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
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
		return p.statusCreateOrUpdate(ctx, request, &reqID)
	case lroOpDelete:
		return p.statusDelete(ctx, request, &reqID)
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

func (p *PublicIPPrefix) statusCreateOrUpdate(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	operation := resource.OperationCreate
	if reqID.OperationType == lroOpUpdate {
		operation = resource.OperationUpdate
	}

	return statusLRO(ctx, request, reqID, operation,
		func(token string) (*runtime.Poller[armnetwork.PublicIPPrefixesClientCreateOrUpdateResponse], error) {
			return resumePoller[armnetwork.PublicIPPrefixesClientCreateOrUpdateResponse](p.pipeline, token)
		},
		func(_ context.Context, result armnetwork.PublicIPPrefixesClientCreateOrUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
			rgName, name, err := publicIPPrefixIDParts(*result.ID)
			if err != nil {
				return "", nil, err
			}
			propsJSON, err := serializePublicIPPrefixProperties(result.PublicIPPrefix, rgName, name)
			if err != nil {
				return "", nil, fmt.Errorf("failed to serialize PublicIPPrefix properties: %w", err)
			}
			return *result.ID, propsJSON, nil
		})
}

func (p *PublicIPPrefix) statusDelete(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	return statusDeleteLRO(ctx, request, reqID,
		func(token string) (*runtime.Poller[armnetwork.PublicIPPrefixesClientDeleteResponse], error) {
			return resumePoller[armnetwork.PublicIPPrefixesClientDeleteResponse](p.pipeline, token)
		}, nil)
}

func (p *PublicIPPrefix) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]

	var nativeIDs []string
	if rgName != "" {
		pager := p.api.NewListPager(rgName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list public IP prefixes in resource group %s: %w", rgName, err)
			}
			for _, prefix := range page.Value {
				if prefix.ID != nil {
					nativeIDs = append(nativeIDs, *prefix.ID)
				}
			}
		}
		return &resource.ListResult{NativeIDs: nativeIDs}, nil
	}

	pager := p.api.NewListAllPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list public IP prefixes: %w", err)
		}
		for _, prefix := range page.Value {
			if prefix.ID != nil {
				nativeIDs = append(nativeIDs, *prefix.ID)
			}
		}
	}

	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
