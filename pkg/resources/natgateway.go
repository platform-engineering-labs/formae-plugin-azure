// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v4"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeNatGateway = "AZURE::Network::NatGateway"

// natGatewaysAPI is the subset of *armnetwork.NatGatewaysClient used here.
// Create/update/delete are LROs.
type natGatewaysAPI interface {
	BeginCreateOrUpdate(ctx context.Context, resourceGroupName string, natGatewayName string, parameters armnetwork.NatGateway, options *armnetwork.NatGatewaysClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.NatGatewaysClientCreateOrUpdateResponse], error)
	Get(ctx context.Context, resourceGroupName string, natGatewayName string, options *armnetwork.NatGatewaysClientGetOptions) (armnetwork.NatGatewaysClientGetResponse, error)
	BeginDelete(ctx context.Context, resourceGroupName string, natGatewayName string, options *armnetwork.NatGatewaysClientBeginDeleteOptions) (*runtime.Poller[armnetwork.NatGatewaysClientDeleteResponse], error)
	NewListPager(resourceGroupName string, options *armnetwork.NatGatewaysClientListOptions) *runtime.Pager[armnetwork.NatGatewaysClientListResponse]
	NewListAllPager(options *armnetwork.NatGatewaysClientListAllOptions) *runtime.Pager[armnetwork.NatGatewaysClientListAllResponse]
}

func init() {
	registry.Register(ResourceTypeNatGateway, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &NatGateway{
			api:      c.NatGatewaysClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// NatGateway is the provisioner for Azure NAT gateways
// (`Microsoft.Network/natGateways/<name>`) — the outbound-SNAT resource a subnet
// attaches to instead of relying on default outbound access.
//
// Only Standard SKU public IPs / prefixes can be attached, and the association
// direction matters: the gateway holds references to its public IPs, while the
// subnet holds a reference to the gateway.
type NatGateway struct {
	api      natGatewaysAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

func natGatewayIDParts(resourceID string) (rgName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "natgateways")
	if err != nil {
		return "", "", err
	}
	return rgName, names["natgateways"], nil
}

// subResourceIDs extracts and sorts the ARM IDs out of a SubResource list. ARM
// does not promise to echo these back in submitted order, so sorting keeps drift
// detection stable.
func subResourceIDs(refs []*armnetwork.SubResource) []string {
	if len(refs) == 0 {
		return nil
	}
	ids := make([]string, 0, len(refs))
	for _, r := range refs {
		if r != nil && r.ID != nil {
			ids = append(ids, *r.ID)
		}
	}
	sort.Strings(ids)
	return ids
}

// subResourcesFromIDs is the inverse of subResourceIDs.
func subResourcesFromIDs(raw []any) []*armnetwork.SubResource {
	if len(raw) == 0 {
		return nil
	}
	ids := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok && s != "" {
			ids = append(ids, s)
		}
	}
	if len(ids) == 0 {
		return nil
	}
	sort.Strings(ids)
	refs := make([]*armnetwork.SubResource, 0, len(ids))
	for i := range ids {
		refs = append(refs, &armnetwork.SubResource{ID: &ids[i]})
	}
	return refs
}

func serializeNatGatewayProperties(result armnetwork.NatGateway, rgName, name string) (json.RawMessage, error) {
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

	if result.SKU != nil && result.SKU.Name != nil {
		props["sku"] = map[string]any{"name": string(*result.SKU.Name)}
	}

	if result.Properties != nil {
		if result.Properties.IdleTimeoutInMinutes != nil {
			props["idleTimeoutInMinutes"] = int(*result.Properties.IdleTimeoutInMinutes)
		}
		if ids := subResourceIDs(result.Properties.PublicIPAddresses); ids != nil {
			props["publicIpAddressIds"] = ids
		}
		if ids := subResourceIDs(result.Properties.PublicIPPrefixes); ids != nil {
			props["publicIpPrefixIds"] = ids
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

func natGatewayParamsFromProperties(props map[string]any, rawProps json.RawMessage) (armnetwork.NatGateway, error) {
	location, _ := props["location"].(string)
	if location == "" {
		return armnetwork.NatGateway{}, fmt.Errorf("location is required")
	}

	gw := armnetwork.NatGateway{
		Location:   stringPtr(location),
		Properties: &armnetwork.NatGatewayPropertiesFormat{},
	}

	// Only Standard exists today, but it is still required in the body.
	skuName := string(armnetwork.NatGatewaySKUNameStandard)
	if skuMap, ok := props["sku"].(map[string]any); ok {
		if v, ok := skuMap["name"].(string); ok && v != "" {
			skuName = v
		}
	}
	gw.SKU = &armnetwork.NatGatewaySKU{Name: to.Ptr(armnetwork.NatGatewaySKUName(skuName))}

	if v, ok := props["idleTimeoutInMinutes"].(float64); ok {
		gw.Properties.IdleTimeoutInMinutes = to.Ptr(int32(v))
	}
	if raw, ok := props["publicIpAddressIds"].([]any); ok {
		gw.Properties.PublicIPAddresses = subResourcesFromIDs(raw)
	}
	if raw, ok := props["publicIpPrefixIds"].([]any); ok {
		gw.Properties.PublicIPPrefixes = subResourcesFromIDs(raw)
	}

	if rawZones, ok := props["zones"].([]any); ok && len(rawZones) > 0 {
		zones := make([]*string, 0, len(rawZones))
		for _, z := range rawZones {
			if s, ok := z.(string); ok {
				zones = append(zones, stringPtr(s))
			}
		}
		gw.Zones = zones
	}

	if azureTags := formaeTagsToAzureTags(rawProps); azureTags != nil {
		gw.Tags = azureTags
	}

	return gw, nil
}

func (n *NatGateway) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
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

	params, err := natGatewayParamsFromProperties(props, request.Properties)
	if err != nil {
		return nil, err
	}

	poller, err := n.api.BeginCreateOrUpdate(ctx, rgName, name, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	expectedID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/natGateways/%s",
		n.config.SubscriptionId, rgName, name)

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
		propsJSON, err := serializeNatGatewayProperties(result.NatGateway, rgName, name)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize NatGateway properties: %w", err)
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

func (n *NatGateway) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, name, err := natGatewayIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := n.api.Get(ctx, rgName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := serializeNatGatewayProperties(result.NatGateway, rgName, name)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize NatGateway properties: %w", err)
	}

	return &resource.ReadResult{
		ResourceType: ResourceTypeNatGateway,
		Properties:   string(propsJSON),
	}, nil
}

func (n *NatGateway) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, name, err := natGatewayIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props map[string]any
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse desired properties: %w", err)
	}

	// ARM's NAT gateway PATCH (UpdateTags) only accepts tags, so idle timeout and
	// public IP association changes go through the full-body PUT.
	params, err := natGatewayParamsFromProperties(props, request.DesiredProperties)
	if err != nil {
		return nil, err
	}

	poller, err := n.api.BeginCreateOrUpdate(ctx, rgName, name, params, nil)
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
		propsJSON, err := serializeNatGatewayProperties(result.NatGateway, rgName, name)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize NatGateway properties: %w", err)
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

func (n *NatGateway) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, name, err := natGatewayIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, err := n.api.BeginDelete(ctx, rgName, name, nil)
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
		}, fmt.Errorf("failed to delete NatGateway: %w", err)
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

func (n *NatGateway) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
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
		return n.statusCreateOrUpdate(ctx, request, &reqID)
	case lroOpDelete:
		return n.statusDelete(ctx, request, &reqID)
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

func (n *NatGateway) statusCreateOrUpdate(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	operation := resource.OperationCreate
	if reqID.OperationType == lroOpUpdate {
		operation = resource.OperationUpdate
	}

	return statusLRO(ctx, request, reqID, operation,
		func(token string) (*runtime.Poller[armnetwork.NatGatewaysClientCreateOrUpdateResponse], error) {
			return resumePoller[armnetwork.NatGatewaysClientCreateOrUpdateResponse](n.pipeline, token)
		},
		func(_ context.Context, result armnetwork.NatGatewaysClientCreateOrUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
			rgName, name, err := natGatewayIDParts(*result.ID)
			if err != nil {
				return "", nil, err
			}
			propsJSON, err := serializeNatGatewayProperties(result.NatGateway, rgName, name)
			if err != nil {
				return "", nil, fmt.Errorf("failed to serialize NatGateway properties: %w", err)
			}
			return *result.ID, propsJSON, nil
		})
}

func (n *NatGateway) statusDelete(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	return statusDeleteLRO(ctx, request, reqID,
		func(token string) (*runtime.Poller[armnetwork.NatGatewaysClientDeleteResponse], error) {
			return resumePoller[armnetwork.NatGatewaysClientDeleteResponse](n.pipeline, token)
		}, nil)
}

func (n *NatGateway) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]

	var nativeIDs []string
	if rgName != "" {
		pager := n.api.NewListPager(rgName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list NAT gateways in resource group %s: %w", rgName, err)
			}
			for _, gw := range page.Value {
				if gw.ID != nil {
					nativeIDs = append(nativeIDs, *gw.ID)
				}
			}
		}
		return &resource.ListResult{NativeIDs: nativeIDs}, nil
	}

	pager := n.api.NewListAllPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list NAT gateways: %w", err)
		}
		for _, gw := range page.Value {
			if gw.ID != nil {
				nativeIDs = append(nativeIDs, *gw.ID)
			}
		}
	}

	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
