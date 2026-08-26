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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/webpubsub/armwebpubsub"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeWebPubSub = "AZURE::SignalRService::WebPubSub"

// webPubSubAPI is the armwebpubsub surface used here. Create, Update and Delete are
// all LROs, and both write verbs take the same ResourceInfo body.
type webPubSubAPI interface {
	BeginCreateOrUpdate(ctx context.Context, resourceGroupName string, resourceName string, parameters armwebpubsub.ResourceInfo, options *armwebpubsub.ClientBeginCreateOrUpdateOptions) (*runtime.Poller[armwebpubsub.ClientCreateOrUpdateResponse], error)
	Get(ctx context.Context, resourceGroupName string, resourceName string, options *armwebpubsub.ClientGetOptions) (armwebpubsub.ClientGetResponse, error)
	BeginUpdate(ctx context.Context, resourceGroupName string, resourceName string, parameters armwebpubsub.ResourceInfo, options *armwebpubsub.ClientBeginUpdateOptions) (*runtime.Poller[armwebpubsub.ClientUpdateResponse], error)
	BeginDelete(ctx context.Context, resourceGroupName string, resourceName string, options *armwebpubsub.ClientBeginDeleteOptions) (*runtime.Poller[armwebpubsub.ClientDeleteResponse], error)
	NewListBySubscriptionPager(options *armwebpubsub.ClientListBySubscriptionOptions) *runtime.Pager[armwebpubsub.ClientListBySubscriptionResponse]
	NewListByResourceGroupPager(resourceGroupName string, options *armwebpubsub.ClientListByResourceGroupOptions) *runtime.Pager[armwebpubsub.ClientListByResourceGroupResponse]
}

func init() {
	registry.Register(ResourceTypeWebPubSub, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &WebPubSub{
			api:      c.WebPubSubClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// WebPubSub is the provisioner for Azure Web PubSub
// (Microsoft.SignalRService/webPubSub).
//
// Access keys and connection strings are never serialized: ARM returns them only
// from a separate ListKeys call.
type WebPubSub struct {
	api      webPubSubAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

// webPubSubProps mirrors schema/pkl/signalrservice/webpubsub.pkl.
type webPubSubProps struct {
	Name                string        `json:"name"`
	Location            string        `json:"location"`
	ResourceGroupName   string        `json:"resourceGroupName"`
	SKU                 *webPubSubSKU `json:"sku"`
	Kind                string        `json:"kind"`
	DisableAadAuth      *bool         `json:"disableAadAuth"`
	DisableLocalAuth    *bool         `json:"disableLocalAuth"`
	PublicNetworkAccess string        `json:"publicNetworkAccess"`
}

type webPubSubSKU struct {
	Name     string `json:"name"`
	Capacity int32  `json:"capacity"`
}

func webPubSubIDParts(resourceID string) (rgName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "webpubsub")
	if err != nil {
		return "", "", err
	}
	return rgName, names["webpubsub"], nil
}

func (w *WebPubSub) buildPropertiesFromResult(info *armwebpubsub.ResourceInfo, rgName string) map[string]any {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName

	if info.ID != nil {
		props["id"] = *info.ID
	}
	if info.Name != nil {
		props["name"] = *info.Name
	}
	if info.Location != nil {
		props["location"] = normalizeAzureLocation(*info.Location)
	}
	if info.Kind != nil {
		props["kind"] = canonicalizeEnum(string(*info.Kind), "WebPubSub", "SocketIO")
	}
	if sku := info.SKU; sku != nil {
		entry := map[string]any{}
		if sku.Name != nil {
			entry["name"] = *sku.Name
		}
		if sku.Capacity != nil {
			entry["capacity"] = *sku.Capacity
		}
		if len(entry) > 0 {
			props["sku"] = entry
		}
	}

	if p := info.Properties; p != nil {
		if p.DisableLocalAuth != nil {
			props["disableLocalAuth"] = *p.DisableLocalAuth
		}
		if p.PublicNetworkAccess != nil {
			props["publicNetworkAccess"] = canonicalizeEnum(*p.PublicNetworkAccess, "Enabled", "Disabled")
		}
		if p.HostName != nil {
			props["hostName"] = *p.HostName
		}
		if p.DisableAADAuth != nil {
			props["disableAadAuth"] = *p.DisableAADAuth
		}
	}

	if tags := azureTagsToFormaeTags(info.Tags); tags != nil {
		props["Tags"] = tags
	}

	return props
}

// webPubSubResourceInfoFromProps builds the body shared by Create and Update.
func webPubSubResourceInfoFromProps(props webPubSubProps, payload json.RawMessage) armwebpubsub.ResourceInfo {
	wpsProps := &armwebpubsub.Properties{}
	if props.DisableLocalAuth != nil {
		wpsProps.DisableLocalAuth = props.DisableLocalAuth
	}
	if props.PublicNetworkAccess != "" {
		wpsProps.PublicNetworkAccess = to.Ptr(props.PublicNetworkAccess)
	}
	if props.DisableAadAuth != nil {
		wpsProps.DisableAADAuth = props.DisableAadAuth
	}

	info := armwebpubsub.ResourceInfo{
		Location:   to.Ptr(props.Location),
		Properties: wpsProps,
	}
	if props.Kind != "" {
		info.Kind = to.Ptr(armwebpubsub.ServiceKind(props.Kind))
	}
	if props.SKU != nil && props.SKU.Name != "" {
		capacity := props.SKU.Capacity
		if capacity < 1 {
			capacity = 1
		}
		info.SKU = &armwebpubsub.ResourceSKU{
			Name:     to.Ptr(props.SKU.Name),
			Capacity: to.Ptr(capacity),
		}
	}
	if azureTags := formaeTagsToAzureTags(payload); azureTags != nil {
		info.Tags = azureTags
	}
	return info
}

func (w *WebPubSub) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props webPubSubProps
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

	params := webPubSubResourceInfoFromProps(props, request.Properties)

	poller, err := w.api.BeginCreateOrUpdate(ctx, props.ResourceGroupName, name, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.SignalRService/webPubSub/%s",
		w.config.SubscriptionId, props.ResourceGroupName, name)

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
		propsJSON, err := json.Marshal(w.buildPropertiesFromResult(&result.ResourceInfo, props.ResourceGroupName))
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

func (w *WebPubSub) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, name, err := webPubSubIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := w.api.Get(ctx, rgName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(w.buildPropertiesFromResult(&result.ResourceInfo, rgName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeWebPubSub,
		Properties:   string(propsJSON),
	}, nil
}

// Update uses ARM's dedicated update verb, which takes the same body type as
// create. kind is createOnly in the schema — ARM cannot change service flavour in
// place.
func (w *WebPubSub) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, name, err := webPubSubIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props webPubSubProps
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	props.ResourceGroupName = rgName
	props.Name = name

	params := webPubSubResourceInfoFromProps(props, request.DesiredProperties)

	poller, err := w.api.BeginUpdate(ctx, rgName, name, params, nil)
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
		propsJSON, err := json.Marshal(w.buildPropertiesFromResult(&result.ResourceInfo, rgName))
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

func (w *WebPubSub) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, name, err := webPubSubIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, err := w.api.BeginDelete(ctx, rgName, name, nil)
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

func (w *WebPubSub) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	reqID, err := decodeLROStatus(request.RequestID)
	if err != nil {
		return nil, err
	}

	switch reqID.OperationType {
	case lroOpCreate:
		return statusLRO(ctx, request, &reqID, resource.OperationCreate,
			func(token string) (*runtime.Poller[armwebpubsub.ClientCreateOrUpdateResponse], error) {
				return resumePoller[armwebpubsub.ClientCreateOrUpdateResponse](w.pipeline, token)
			},
			func(_ context.Context, result armwebpubsub.ClientCreateOrUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				return w.completeFromResourceInfo(&result.ResourceInfo)
			})
	case lroOpUpdate:
		return statusLRO(ctx, request, &reqID, resource.OperationUpdate,
			func(token string) (*runtime.Poller[armwebpubsub.ClientUpdateResponse], error) {
				return resumePoller[armwebpubsub.ClientUpdateResponse](w.pipeline, token)
			},
			func(_ context.Context, result armwebpubsub.ClientUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				return w.completeFromResourceInfo(&result.ResourceInfo)
			})
	case lroOpDelete:
		return statusDeleteLRO(ctx, request, &reqID,
			func(token string) (*runtime.Poller[armwebpubsub.ClientDeleteResponse], error) {
				return resumePoller[armwebpubsub.ClientDeleteResponse](w.pipeline, token)
			}, nil)
	default:
		return nil, fmt.Errorf("unknown operation type: %s", reqID.OperationType)
	}
}

func (w *WebPubSub) completeFromResourceInfo(info *armwebpubsub.ResourceInfo) (string, json.RawMessage, error) {
	nativeID := ""
	rgName := ""
	if info.ID != nil {
		nativeID = *info.ID
		if rg, _, err := webPubSubIDParts(*info.ID); err == nil {
			rgName = rg
		}
	}
	propsJSON, err := json.Marshal(w.buildPropertiesFromResult(info, rgName))
	if err != nil {
		return "", nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return nativeID, propsJSON, nil
}

func (w *WebPubSub) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]

	var nativeIDs []string

	if rgName != "" {
		pager := w.api.NewListByResourceGroupPager(rgName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list web pubsub services: %w", err)
			}
			for _, info := range page.Value {
				if info.ID != nil {
					nativeIDs = append(nativeIDs, *info.ID)
				}
			}
		}
		return &resource.ListResult{NativeIDs: nativeIDs}, nil
	}

	pager := w.api.NewListBySubscriptionPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list web pubsub services: %w", err)
		}
		for _, info := range page.Value {
			if info.ID != nil {
				nativeIDs = append(nativeIDs, *info.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
