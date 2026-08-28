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

const ResourceTypeVirtualWan = "AZURE::Network::VirtualWan"

// virtualWansAPI is the armnetwork surface used here. UpdateTags is deliberately
// absent: it cannot change the tier or any of the traffic flags, so every update is
// a re-PUT.
type virtualWansAPI interface {
	BeginCreateOrUpdate(ctx context.Context, resourceGroupName string, virtualWANName string, wanParameters armnetwork.VirtualWAN, options *armnetwork.VirtualWansClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.VirtualWansClientCreateOrUpdateResponse], error)
	Get(ctx context.Context, resourceGroupName string, virtualWANName string, options *armnetwork.VirtualWansClientGetOptions) (armnetwork.VirtualWansClientGetResponse, error)
	BeginDelete(ctx context.Context, resourceGroupName string, virtualWANName string, options *armnetwork.VirtualWansClientBeginDeleteOptions) (*runtime.Poller[armnetwork.VirtualWansClientDeleteResponse], error)
	NewListByResourceGroupPager(resourceGroupName string, options *armnetwork.VirtualWansClientListByResourceGroupOptions) *runtime.Pager[armnetwork.VirtualWansClientListByResourceGroupResponse]
	NewListPager(options *armnetwork.VirtualWansClientListOptions) *runtime.Pager[armnetwork.VirtualWansClientListResponse]
}

func init() {
	registry.Register(ResourceTypeVirtualWan, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &VirtualWan{
			api:      c.VirtualWansClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// VirtualWan is the provisioner for the root of a Virtual WAN topology
// (Microsoft.Network/virtualWans).
type VirtualWan struct {
	api      virtualWansAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

// virtualWanProps mirrors schema/pkl/network/virtualwan.pkl.
type virtualWanProps struct {
	Name                       string  `json:"name"`
	ResourceGroupName          string  `json:"resourceGroupName"`
	Location                   string  `json:"location"`
	VirtualWanTier             *string `json:"virtualWanTier"`
	DisableVpnEncryption       *bool   `json:"disableVpnEncryption"`
	AllowBranchToBranchTraffic *bool   `json:"allowBranchToBranchTraffic"`
	AllowVnetToVnetTraffic     *bool   `json:"allowVnetToVnetTraffic"`
}

// virtualWanTiers is the canonical casing for the tier enum, applied on the read
// path because ARM echoes it back inconsistently.
var virtualWanTiers = []string{"Basic", "Standard"}

func virtualWanIDParts(resourceID string) (rgName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "virtualwans")
	if err != nil {
		return "", "", err
	}
	return rgName, names["virtualwans"], nil
}

func (r *VirtualWan) buildPropertiesFromResult(wan *armnetwork.VirtualWAN, rgName string) map[string]any {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName

	if wan.ID != nil {
		props["id"] = *wan.ID
	}
	if wan.Name != nil {
		props["name"] = *wan.Name
	}
	if wan.Location != nil {
		props["location"] = normalizeAzureLocation(*wan.Location)
	}
	if tags := azureTagsToFormaeTags(wan.Tags); len(tags) > 0 {
		props["Tags"] = tags
	}

	if p := wan.Properties; p != nil {
		if p.Type != nil && *p.Type != "" {
			props["virtualWanTier"] = canonicalizeEnum(*p.Type, virtualWanTiers...)
		}
		if p.DisableVPNEncryption != nil {
			props["disableVpnEncryption"] = *p.DisableVPNEncryption
		}
		if p.AllowBranchToBranchTraffic != nil {
			props["allowBranchToBranchTraffic"] = *p.AllowBranchToBranchTraffic
		}
		if p.AllowVnetToVnetTraffic != nil {
			props["allowVnetToVnetTraffic"] = *p.AllowVnetToVnetTraffic
		}
		// provisioningState, office365LocalBreakoutCategory and the vpnSites /
		// virtualHubs back-references are service state: the hubs and sites own
		// their side of the reference, so echoing them here would read as drift.
	}

	return props
}

// virtualWanParams builds the request body shared by create and update.
func virtualWanParams(props virtualWanProps, payload json.RawMessage) armnetwork.VirtualWAN {
	params := armnetwork.VirtualWAN{
		Location: to.Ptr(props.Location),
		Properties: &armnetwork.VirtualWanProperties{
			Type:                       props.VirtualWanTier,
			DisableVPNEncryption:       props.DisableVpnEncryption,
			AllowBranchToBranchTraffic: props.AllowBranchToBranchTraffic,
			AllowVnetToVnetTraffic:     props.AllowVnetToVnetTraffic,
		},
	}

	if tags := formaeTagsToAzureTags(payload); len(tags) > 0 {
		params.Tags = tags
	}

	return params
}

// upsert backs both Create and Update: UpdateTags cannot touch the tier or the
// traffic flags, so an update is another CreateOrUpdate.
func (r *VirtualWan) upsert(ctx context.Context, payload json.RawMessage, label string) (*runtime.Poller[armnetwork.VirtualWansClientCreateOrUpdateResponse], virtualWanProps, string, error) {
	var props virtualWanProps
	if err := json.Unmarshal(payload, &props); err != nil {
		return nil, props, "", fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return nil, props, "", fmt.Errorf("resourceGroupName is required")
	}
	if props.Location == "" {
		return nil, props, "", fmt.Errorf("location is required")
	}
	name := props.Name
	if name == "" {
		name = label
	}
	if name == "" {
		return nil, props, "", fmt.Errorf("name is required")
	}

	poller, err := r.api.BeginCreateOrUpdate(ctx, props.ResourceGroupName, name,
		virtualWanParams(props, payload), nil)
	return poller, props, name, err
}

func (r *VirtualWan) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
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

	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/virtualWans/%s",
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
		nativeID, propsJSON, err := r.completeFromWan(&result.VirtualWAN)
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

func (r *VirtualWan) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, name, err := virtualWanIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := r.api.Get(ctx, rgName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(r.buildPropertiesFromResult(&result.VirtualWAN, rgName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeVirtualWan,
		Properties:   string(propsJSON),
	}, nil
}

func (r *VirtualWan) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, _, err := virtualWanIDParts(request.NativeID)
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
		propsJSON, err := json.Marshal(r.buildPropertiesFromResult(&result.VirtualWAN, rgName))
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

func (r *VirtualWan) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, name, err := virtualWanIDParts(request.NativeID)
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

func (r *VirtualWan) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
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
			func(token string) (*runtime.Poller[armnetwork.VirtualWansClientCreateOrUpdateResponse], error) {
				return resumePoller[armnetwork.VirtualWansClientCreateOrUpdateResponse](r.pipeline, token)
			},
			func(_ context.Context, result armnetwork.VirtualWansClientCreateOrUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				return r.completeFromWan(&result.VirtualWAN)
			})
	case lroOpDelete:
		return statusDeleteLRO(ctx, request, &reqID,
			func(token string) (*runtime.Poller[armnetwork.VirtualWansClientDeleteResponse], error) {
				return resumePoller[armnetwork.VirtualWansClientDeleteResponse](r.pipeline, token)
			}, nil)
	default:
		return nil, fmt.Errorf("unknown operation type: %s", reqID.OperationType)
	}
}

func (r *VirtualWan) completeFromWan(wan *armnetwork.VirtualWAN) (string, json.RawMessage, error) {
	nativeID := ""
	rgName := ""
	if wan.ID != nil {
		nativeID = *wan.ID
		if rg, _, err := virtualWanIDParts(*wan.ID); err == nil {
			rgName = rg
		}
	}
	propsJSON, err := json.Marshal(r.buildPropertiesFromResult(wan, rgName))
	if err != nil {
		return "", nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return nativeID, propsJSON, nil
}

// List narrows to a resource group when one is supplied and otherwise sweeps the
// whole subscription.
func (r *VirtualWan) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]

	var nativeIDs []string
	if rgName != "" {
		pager := r.api.NewListByResourceGroupPager(rgName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list virtual WANs in resource group %s: %w", rgName, err)
			}
			for _, wan := range page.Value {
				if wan.ID != nil {
					nativeIDs = append(nativeIDs, *wan.ID)
				}
			}
		}
		return &resource.ListResult{NativeIDs: nativeIDs}, nil
	}

	pager := r.api.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list virtual WANs: %w", err)
		}
		for _, wan := range page.Value {
			if wan.ID != nil {
				nativeIDs = append(nativeIDs, *wan.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
