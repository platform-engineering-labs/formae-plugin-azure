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

const ResourceTypeVirtualHub = "AZURE::Network::VirtualHub"

// virtualHubsAPI is the armnetwork surface used here. UpdateTags is deliberately
// absent: it cannot change the routing preference or the branch-to-branch flag, so
// every update is a re-PUT.
type virtualHubsAPI interface {
	BeginCreateOrUpdate(ctx context.Context, resourceGroupName string, virtualHubName string, virtualHubParameters armnetwork.VirtualHub, options *armnetwork.VirtualHubsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.VirtualHubsClientCreateOrUpdateResponse], error)
	Get(ctx context.Context, resourceGroupName string, virtualHubName string, options *armnetwork.VirtualHubsClientGetOptions) (armnetwork.VirtualHubsClientGetResponse, error)
	BeginDelete(ctx context.Context, resourceGroupName string, virtualHubName string, options *armnetwork.VirtualHubsClientBeginDeleteOptions) (*runtime.Poller[armnetwork.VirtualHubsClientDeleteResponse], error)
	NewListByResourceGroupPager(resourceGroupName string, options *armnetwork.VirtualHubsClientListByResourceGroupOptions) *runtime.Pager[armnetwork.VirtualHubsClientListByResourceGroupResponse]
	NewListPager(options *armnetwork.VirtualHubsClientListOptions) *runtime.Pager[armnetwork.VirtualHubsClientListResponse]
}

func init() {
	registry.Register(ResourceTypeVirtualHub, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &VirtualHub{
			api:      c.VirtualHubsClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// VirtualHub is the provisioner for a regional hub inside a Virtual WAN
// (Microsoft.Network/virtualHubs).
type VirtualHub struct {
	api      virtualHubsAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

// virtualHubProps mirrors schema/pkl/network/virtualhub.pkl.
type virtualHubProps struct {
	Name                       string  `json:"name"`
	ResourceGroupName          string  `json:"resourceGroupName"`
	Location                   string  `json:"location"`
	VirtualWanID               string  `json:"virtualWanId"`
	AddressPrefix              string  `json:"addressPrefix"`
	SKU                        *string `json:"sku"`
	HubRoutingPreference       *string `json:"hubRoutingPreference"`
	AllowBranchToBranchTraffic *bool   `json:"allowBranchToBranchTraffic"`
}

var (
	// virtualHubSkus and virtualHubRoutingPreferences carry the canonical casing for
	// the two enums, applied on the read path because ARM echoes them back
	// inconsistently.
	virtualHubSkus               = []string{"Basic", "Standard"}
	virtualHubRoutingPreferences = []string{"ExpressRoute", "VpnGateway", "ASPath"}
)

func virtualHubIDParts(resourceID string) (rgName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "virtualhubs")
	if err != nil {
		return "", "", err
	}
	return rgName, names["virtualhubs"], nil
}

func (r *VirtualHub) buildPropertiesFromResult(hub *armnetwork.VirtualHub, rgName string) map[string]any {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName

	if hub.ID != nil {
		props["id"] = *hub.ID
	}
	if hub.Name != nil {
		props["name"] = *hub.Name
	}
	if hub.Location != nil {
		props["location"] = normalizeAzureLocation(*hub.Location)
	}
	if tags := azureTagsToFormaeTags(hub.Tags); len(tags) > 0 {
		props["Tags"] = tags
	}

	if p := hub.Properties; p != nil {
		if p.VirtualWan != nil && p.VirtualWan.ID != nil {
			props["virtualWanId"] = *p.VirtualWan.ID
		}
		if p.AddressPrefix != nil && *p.AddressPrefix != "" {
			props["addressPrefix"] = *p.AddressPrefix
		}
		if p.SKU != nil && *p.SKU != "" {
			props["sku"] = canonicalizeEnum(*p.SKU, virtualHubSkus...)
		}
		if p.HubRoutingPreference != nil && *p.HubRoutingPreference != "" {
			props["hubRoutingPreference"] = canonicalizeEnum(string(*p.HubRoutingPreference), virtualHubRoutingPreferences...)
		}
		if p.AllowBranchToBranchTraffic != nil {
			props["allowBranchToBranchTraffic"] = *p.AllowBranchToBranchTraffic
		}
		// Everything else the hub reports is service state or a back-reference owned
		// by another resource: provisioningState, routingState, virtualRouterAsn,
		// virtualRouterIPs, the route tables the service seeds, and the
		// azureFirewall / expressRouteGateway / p2sVpnGateway / vpnGateway /
		// bgpConnections / ipConfigurations / routeMaps pointers, which the
		// attaching resource owns.
	}

	return props
}

// virtualHubParams builds the request body shared by create and update.
func virtualHubParams(props virtualHubProps, payload json.RawMessage) armnetwork.VirtualHub {
	params := armnetwork.VirtualHub{
		Location: to.Ptr(props.Location),
		Properties: &armnetwork.VirtualHubProperties{
			VirtualWan:                 &armnetwork.SubResource{ID: to.Ptr(props.VirtualWanID)},
			AddressPrefix:              to.Ptr(props.AddressPrefix),
			SKU:                        props.SKU,
			AllowBranchToBranchTraffic: props.AllowBranchToBranchTraffic,
		},
	}
	if props.HubRoutingPreference != nil {
		params.Properties.HubRoutingPreference = to.Ptr(armnetwork.HubRoutingPreference(*props.HubRoutingPreference))
	}

	if tags := formaeTagsToAzureTags(payload); len(tags) > 0 {
		params.Tags = tags
	}

	return params
}

// upsert backs both Create and Update: UpdateTags cannot touch the routing
// preference, so an update is another CreateOrUpdate.
func (r *VirtualHub) upsert(ctx context.Context, payload json.RawMessage, label string) (*runtime.Poller[armnetwork.VirtualHubsClientCreateOrUpdateResponse], virtualHubProps, string, error) {
	var props virtualHubProps
	if err := json.Unmarshal(payload, &props); err != nil {
		return nil, props, "", fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return nil, props, "", fmt.Errorf("resourceGroupName is required")
	}
	if props.Location == "" {
		return nil, props, "", fmt.Errorf("location is required")
	}
	if props.VirtualWanID == "" {
		return nil, props, "", fmt.Errorf("virtualWanId is required")
	}
	if props.AddressPrefix == "" {
		return nil, props, "", fmt.Errorf("addressPrefix is required")
	}
	name := props.Name
	if name == "" {
		name = label
	}
	if name == "" {
		return nil, props, "", fmt.Errorf("name is required")
	}

	poller, err := r.api.BeginCreateOrUpdate(ctx, props.ResourceGroupName, name,
		virtualHubParams(props, payload), nil)
	return poller, props, name, err
}

func (r *VirtualHub) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	poller, props, name, err := r.upsert(ctx, request.Properties, request.Label)
	if err != nil {
		if name == "" {
			return nil, err
		}
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/virtualHubs/%s",
		r.config.SubscriptionId, props.ResourceGroupName, name)

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
		nativeID, propsJSON, err := r.completeFromHub(&result.VirtualHub)
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

func (r *VirtualHub) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, name, err := virtualHubIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := r.api.Get(ctx, rgName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(r.buildPropertiesFromResult(&result.VirtualHub, rgName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeVirtualHub,
		Properties:   string(propsJSON),
	}, nil
}

func (r *VirtualHub) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, _, err := virtualHubIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, _, name, err := r.upsert(ctx, request.DesiredProperties, "")
	if err != nil {
		if name == "" {
			return nil, err
		}
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
		propsJSON, err := json.Marshal(r.buildPropertiesFromResult(&result.VirtualHub, rgName))
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

func (r *VirtualHub) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, name, err := virtualHubIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, err := r.api.BeginDelete(ctx, rgName, name, nil)
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

func (r *VirtualHub) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	reqID, err := decodeLROStatus(request.RequestID)
	if err != nil {
		return nil, err
	}

	switch reqID.OperationType {
	case lroOpCreate, lroOpUpdate:
		// Both resume as CreateOrUpdate responses: Update re-PUTs, so the poller that
		// issued the token has the same response type in either case.
		operation := resource.OperationCreate
		if reqID.OperationType == lroOpUpdate {
			operation = resource.OperationUpdate
		}
		return statusLRO(ctx, request, &reqID, operation,
			func(token string) (*runtime.Poller[armnetwork.VirtualHubsClientCreateOrUpdateResponse], error) {
				return resumePoller[armnetwork.VirtualHubsClientCreateOrUpdateResponse](r.pipeline, token)
			},
			func(_ context.Context, result armnetwork.VirtualHubsClientCreateOrUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				return r.completeFromHub(&result.VirtualHub)
			})
	case lroOpDelete:
		return statusDeleteLRO(ctx, request, &reqID,
			func(token string) (*runtime.Poller[armnetwork.VirtualHubsClientDeleteResponse], error) {
				return resumePoller[armnetwork.VirtualHubsClientDeleteResponse](r.pipeline, token)
			}, nil)
	default:
		return nil, fmt.Errorf("unknown operation type: %s", reqID.OperationType)
	}
}

func (r *VirtualHub) completeFromHub(hub *armnetwork.VirtualHub) (string, json.RawMessage, error) {
	nativeID := ""
	rgName := ""
	if hub.ID != nil {
		nativeID = *hub.ID
		if rg, _, err := virtualHubIDParts(*hub.ID); err == nil {
			rgName = rg
		}
	}
	propsJSON, err := json.Marshal(r.buildPropertiesFromResult(hub, rgName))
	if err != nil {
		return "", nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return nativeID, propsJSON, nil
}

// List narrows to a resource group when one is supplied and otherwise sweeps the
// whole subscription.
func (r *VirtualHub) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]

	var nativeIDs []string
	if rgName != "" {
		pager := r.api.NewListByResourceGroupPager(rgName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list virtual hubs in resource group %s: %w", rgName, err)
			}
			for _, hub := range page.Value {
				if hub.ID != nil {
					nativeIDs = append(nativeIDs, *hub.ID)
				}
			}
		}
		return &resource.ListResult{NativeIDs: nativeIDs}, nil
	}

	pager := r.api.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list virtual hubs: %w", err)
		}
		for _, hub := range page.Value {
			if hub.ID != nil {
				nativeIDs = append(nativeIDs, *hub.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
