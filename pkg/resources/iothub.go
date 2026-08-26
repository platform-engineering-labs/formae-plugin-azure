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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/iothub/armiothub"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeIotHub = "AZURE::Devices::IotHub"

// iotHubAPI is the armiothub surface used here.
//
// Note BeginUpdate takes a TagsResource — it can ONLY change tags, not the hub
// body. Property changes therefore go through BeginCreateOrUpdate (a full upsert),
// which is why BeginUpdate is not part of this interface at all.
type iotHubAPI interface {
	BeginCreateOrUpdate(ctx context.Context, resourceGroupName string, resourceName string, iotHubDescription armiothub.Description, options *armiothub.ResourceClientBeginCreateOrUpdateOptions) (*runtime.Poller[armiothub.ResourceClientCreateOrUpdateResponse], error)
	Get(ctx context.Context, resourceGroupName string, resourceName string, options *armiothub.ResourceClientGetOptions) (armiothub.ResourceClientGetResponse, error)
	BeginDelete(ctx context.Context, resourceGroupName string, resourceName string, options *armiothub.ResourceClientBeginDeleteOptions) (*runtime.Poller[armiothub.ResourceClientDeleteResponse], error)
	NewListBySubscriptionPager(options *armiothub.ResourceClientListBySubscriptionOptions) *runtime.Pager[armiothub.ResourceClientListBySubscriptionResponse]
	NewListByResourceGroupPager(resourceGroupName string, options *armiothub.ResourceClientListByResourceGroupOptions) *runtime.Pager[armiothub.ResourceClientListByResourceGroupResponse]
}

func init() {
	registry.Register(ResourceTypeIotHub, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &IotHub{
			api:      c.IotHubResourceClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// IotHub is the provisioner for Azure IoT Hub (Microsoft.Devices/IotHubs).
//
// ARM returns the shared-access-policy keys inline under authorizationPolicies on
// a read. Those policies are deliberately not serialized at all, so the primary
// and secondary keys never reach resource state.
type IotHub struct {
	api      iotHubAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

// iotHubProps mirrors schema/pkl/devices/iothub.pkl.
type iotHubProps struct {
	Name                string          `json:"name"`
	Location            string          `json:"location"`
	ResourceGroupName   string          `json:"resourceGroupName"`
	SKU                 *iotHubSKUProps `json:"sku"`
	DisableLocalAuth    *bool           `json:"disableLocalAuth"`
	PublicNetworkAccess string          `json:"publicNetworkAccess"`
	MinTLSVersion       string          `json:"minTlsVersion"`
	Comments            string          `json:"comments"`
}

type iotHubSKUProps struct {
	Name     string `json:"name"`
	Capacity int64  `json:"capacity"`
}

func iotHubIDParts(resourceID string) (rgName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "iothubs")
	if err != nil {
		return "", "", err
	}
	return rgName, names["iothubs"], nil
}

func (h *IotHub) buildPropertiesFromResult(desc *armiothub.Description, rgName string) map[string]any {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName

	if desc.ID != nil {
		props["id"] = *desc.ID
	}
	if desc.Name != nil {
		props["name"] = *desc.Name
	}
	if desc.Location != nil {
		props["location"] = normalizeAzureLocation(*desc.Location)
	}
	if sku := desc.SKU; sku != nil {
		s := map[string]any{}
		if sku.Name != nil {
			s["name"] = canonicalizeEnum(string(*sku.Name), "F1", "B1", "B2", "B3", "S1", "S2", "S3")
		}
		if sku.Capacity != nil {
			s["capacity"] = *sku.Capacity
		}
		if len(s) > 0 {
			props["sku"] = s
		}
	}

	if p := desc.Properties; p != nil {
		if p.DisableLocalAuth != nil {
			props["disableLocalAuth"] = *p.DisableLocalAuth
		}
		if p.PublicNetworkAccess != nil {
			props["publicNetworkAccess"] = canonicalizeEnum(string(*p.PublicNetworkAccess), "Enabled", "Disabled")
		}
		if p.MinTLSVersion != nil {
			props["minTlsVersion"] = *p.MinTLSVersion
		}
		if p.Comments != nil {
			props["comments"] = *p.Comments
		}
		if p.HostName != nil {
			props["hostName"] = *p.HostName
		}
		// p.AuthorizationPolicies is deliberately NOT copied: each entry carries a
		// primaryKey/secondaryKey inline, and those must never reach state.
	}

	if tags := azureTagsToFormaeTags(desc.Tags); tags != nil {
		props["Tags"] = tags
	}

	return props
}

// iotHubDescriptionFromProps builds the full upsert body, used by both Create and
// Update since ARM's PATCH covers tags only.
func iotHubDescriptionFromProps(props iotHubProps, payload json.RawMessage) armiothub.Description {
	hubProps := &armiothub.Properties{}
	if props.DisableLocalAuth != nil {
		hubProps.DisableLocalAuth = props.DisableLocalAuth
	}
	if props.PublicNetworkAccess != "" {
		hubProps.PublicNetworkAccess = to.Ptr(armiothub.PublicNetworkAccess(props.PublicNetworkAccess))
	}
	if props.MinTLSVersion != "" {
		hubProps.MinTLSVersion = to.Ptr(props.MinTLSVersion)
	}
	if props.Comments != "" {
		hubProps.Comments = to.Ptr(props.Comments)
	}

	desc := armiothub.Description{
		Location:   to.Ptr(props.Location),
		Properties: hubProps,
	}
	if props.SKU != nil && props.SKU.Name != "" {
		capacity := props.SKU.Capacity
		if capacity < 1 {
			capacity = 1
		}
		desc.SKU = &armiothub.SKUInfo{
			Name:     to.Ptr(armiothub.IotHubSKU(props.SKU.Name)),
			Capacity: to.Ptr(capacity),
		}
	}
	if azureTags := formaeTagsToAzureTags(payload); azureTags != nil {
		desc.Tags = azureTags
	}
	return desc
}

func (h *IotHub) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props iotHubProps
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	if props.Location == "" {
		return nil, fmt.Errorf("location is required")
	}
	if props.SKU == nil || props.SKU.Name == "" {
		return nil, fmt.Errorf("sku.name is required")
	}
	name := props.Name
	if name == "" {
		name = request.Label
	}
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}

	params := iotHubDescriptionFromProps(props, request.Properties)

	poller, err := h.api.BeginCreateOrUpdate(ctx, props.ResourceGroupName, name, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Devices/IotHubs/%s",
		h.config.SubscriptionId, props.ResourceGroupName, name)

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
		propsJSON, err := json.Marshal(h.buildPropertiesFromResult(&result.Description, props.ResourceGroupName))
		if err != nil {
			return nil, fmt.Errorf("failed to marshal response properties: %w", err)
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

func (h *IotHub) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, name, err := iotHubIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := h.api.Get(ctx, rgName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(h.buildPropertiesFromResult(&result.Description, rgName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeIotHub,
		Properties:   string(propsJSON),
	}, nil
}

// Update goes through the full CreateOrUpdate upsert, not ARM's PATCH: the PATCH
// body is a TagsResource and cannot carry sku or any hub property.
func (h *IotHub) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, name, err := iotHubIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props iotHubProps
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	props.ResourceGroupName = rgName
	props.Name = name

	params := iotHubDescriptionFromProps(props, request.DesiredProperties)

	poller, err := h.api.BeginCreateOrUpdate(ctx, rgName, name, params, nil)
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
		propsJSON, err := json.Marshal(h.buildPropertiesFromResult(&result.Description, rgName))
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

func (h *IotHub) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, name, err := iotHubIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, err := h.api.BeginDelete(ctx, rgName, name, nil)
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

func (h *IotHub) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	reqID, err := decodeLROStatus(request.RequestID)
	if err != nil {
		return nil, err
	}

	switch reqID.OperationType {
	case lroOpCreate, lroOpUpdate:
		op := resource.OperationCreate
		if reqID.OperationType == lroOpUpdate {
			op = resource.OperationUpdate
		}
		return statusLRO(ctx, request, &reqID, op,
			func(token string) (*runtime.Poller[armiothub.ResourceClientCreateOrUpdateResponse], error) {
				return resumePoller[armiothub.ResourceClientCreateOrUpdateResponse](h.pipeline, token)
			},
			func(_ context.Context, result armiothub.ResourceClientCreateOrUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				return h.completeFromDescription(&result.Description)
			})
	case lroOpDelete:
		return statusDeleteLRO(ctx, request, &reqID,
			func(token string) (*runtime.Poller[armiothub.ResourceClientDeleteResponse], error) {
				return resumePoller[armiothub.ResourceClientDeleteResponse](h.pipeline, token)
			}, nil)
	default:
		return nil, fmt.Errorf("unknown operation type: %s", reqID.OperationType)
	}
}

func (h *IotHub) completeFromDescription(desc *armiothub.Description) (string, json.RawMessage, error) {
	nativeID := ""
	rgName := ""
	if desc.ID != nil {
		nativeID = *desc.ID
		if rg, _, err := iotHubIDParts(*desc.ID); err == nil {
			rgName = rg
		}
	}
	propsJSON, err := json.Marshal(h.buildPropertiesFromResult(desc, rgName))
	if err != nil {
		return "", nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return nativeID, propsJSON, nil
}

func (h *IotHub) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]

	var nativeIDs []string

	if rgName != "" {
		pager := h.api.NewListByResourceGroupPager(rgName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list iot hubs: %w", err)
			}
			for _, desc := range page.Value {
				if desc.ID != nil {
					nativeIDs = append(nativeIDs, *desc.ID)
				}
			}
		}
		return &resource.ListResult{NativeIDs: nativeIDs}, nil
	}

	pager := h.api.NewListBySubscriptionPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list iot hubs: %w", err)
		}
		for _, desc := range page.Value {
			if desc.ID != nil {
				nativeIDs = append(nativeIDs, *desc.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
