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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/signalr/armsignalr"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeSignalR = "AZURE::SignalRService::SignalR"

// signalRAPI is the armsignalr surface used here. Create, Update and Delete are
// all LROs, and both write verbs take the same ResourceInfo body.
type signalRAPI interface {
	BeginCreateOrUpdate(ctx context.Context, resourceGroupName string, resourceName string, parameters armsignalr.ResourceInfo, options *armsignalr.ClientBeginCreateOrUpdateOptions) (*runtime.Poller[armsignalr.ClientCreateOrUpdateResponse], error)
	Get(ctx context.Context, resourceGroupName string, resourceName string, options *armsignalr.ClientGetOptions) (armsignalr.ClientGetResponse, error)
	BeginUpdate(ctx context.Context, resourceGroupName string, resourceName string, parameters armsignalr.ResourceInfo, options *armsignalr.ClientBeginUpdateOptions) (*runtime.Poller[armsignalr.ClientUpdateResponse], error)
	BeginDelete(ctx context.Context, resourceGroupName string, resourceName string, options *armsignalr.ClientBeginDeleteOptions) (*runtime.Poller[armsignalr.ClientDeleteResponse], error)
	NewListBySubscriptionPager(options *armsignalr.ClientListBySubscriptionOptions) *runtime.Pager[armsignalr.ClientListBySubscriptionResponse]
	NewListByResourceGroupPager(resourceGroupName string, options *armsignalr.ClientListByResourceGroupOptions) *runtime.Pager[armsignalr.ClientListByResourceGroupResponse]
}

func init() {
	registry.Register(ResourceTypeSignalR, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &SignalR{
			api:      c.SignalRClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// SignalR is the provisioner for Azure SignalR Service
// (Microsoft.SignalRService/signalR).
//
// Access keys and connection strings are never serialized: ARM returns them only
// from a separate ListKeys call.
type SignalR struct {
	api      signalRAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

// signalRProps mirrors schema/pkl/signalrservice/signalr.pkl.
type signalRProps struct {
	Name                string      `json:"name"`
	Location            string      `json:"location"`
	ResourceGroupName   string      `json:"resourceGroupName"`
	SKU                 *signalRSKU `json:"sku"`
	Kind                string      `json:"kind"`
	ServiceMode         string      `json:"serviceMode"`
	DisableLocalAuth    *bool       `json:"disableLocalAuth"`
	PublicNetworkAccess string      `json:"publicNetworkAccess"`
}

type signalRSKU struct {
	Name     string `json:"name"`
	Capacity int32  `json:"capacity"`
}

func signalRIDParts(resourceID string) (rgName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "signalr")
	if err != nil {
		return "", "", err
	}
	return rgName, names["signalr"], nil
}

func (s *SignalR) buildPropertiesFromResult(info *armsignalr.ResourceInfo, rgName string) map[string]any {
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
		props["kind"] = canonicalizeEnum(string(*info.Kind), "SignalR", "RawWebSockets")
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
		// ARM returns every feature flag it knows about, each with its default
		// value. Surfacing the whole list would drift against a desired state that
		// names one flag, so only ServiceMode is extracted — the rest are not
		// modelled. Same failure shape as diagnostic-setting categories.
		for _, f := range p.Features {
			if f == nil || f.Flag == nil || f.Value == nil {
				continue
			}
			if *f.Flag == armsignalr.FeatureFlagsServiceMode {
				props["serviceMode"] = canonicalizeEnum(*f.Value, "Default", "Serverless", "Classic")
			}
		}
	}

	if tags := azureTagsToFormaeTags(info.Tags); tags != nil {
		props["Tags"] = tags
	}

	return props
}

// signalRResourceInfoFromProps builds the body shared by Create and Update.
func signalRResourceInfoFromProps(props signalRProps, payload json.RawMessage) armsignalr.ResourceInfo {
	sigProps := &armsignalr.Properties{}
	if props.DisableLocalAuth != nil {
		sigProps.DisableLocalAuth = props.DisableLocalAuth
	}
	if props.PublicNetworkAccess != "" {
		sigProps.PublicNetworkAccess = to.Ptr(props.PublicNetworkAccess)
	}
	if props.ServiceMode != "" {
		sigProps.Features = []*armsignalr.Feature{{
			Flag:  to.Ptr(armsignalr.FeatureFlagsServiceMode),
			Value: to.Ptr(props.ServiceMode),
		}}
	}

	info := armsignalr.ResourceInfo{
		Location:   to.Ptr(props.Location),
		Properties: sigProps,
	}
	if props.Kind != "" {
		info.Kind = to.Ptr(armsignalr.ServiceKind(props.Kind))
	}
	if props.SKU != nil && props.SKU.Name != "" {
		capacity := props.SKU.Capacity
		if capacity < 1 {
			capacity = 1
		}
		info.SKU = &armsignalr.ResourceSKU{
			Name:     to.Ptr(props.SKU.Name),
			Capacity: to.Ptr(capacity),
		}
	}
	if azureTags := formaeTagsToAzureTags(payload); azureTags != nil {
		info.Tags = azureTags
	}
	return info
}

func (s *SignalR) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props signalRProps
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

	params := signalRResourceInfoFromProps(props, request.Properties)

	poller, err := s.api.BeginCreateOrUpdate(ctx, props.ResourceGroupName, name, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.SignalRService/signalR/%s",
		s.config.SubscriptionId, props.ResourceGroupName, name)

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
		propsJSON, err := json.Marshal(s.buildPropertiesFromResult(&result.ResourceInfo, props.ResourceGroupName))
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

func (s *SignalR) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, name, err := signalRIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := s.api.Get(ctx, rgName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(s.buildPropertiesFromResult(&result.ResourceInfo, rgName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeSignalR,
		Properties:   string(propsJSON),
	}, nil
}

// Update uses ARM's dedicated update verb, which takes the same body type as
// create. kind is createOnly in the schema — ARM cannot change service flavour in
// place.
func (s *SignalR) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, name, err := signalRIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props signalRProps
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	props.ResourceGroupName = rgName
	props.Name = name

	params := signalRResourceInfoFromProps(props, request.DesiredProperties)

	poller, err := s.api.BeginUpdate(ctx, rgName, name, params, nil)
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
		propsJSON, err := json.Marshal(s.buildPropertiesFromResult(&result.ResourceInfo, rgName))
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

func (s *SignalR) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, name, err := signalRIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, err := s.api.BeginDelete(ctx, rgName, name, nil)
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

func (s *SignalR) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	reqID, err := decodeLROStatus(request.RequestID)
	if err != nil {
		return nil, err
	}

	switch reqID.OperationType {
	case lroOpCreate:
		return statusLRO(ctx, request, &reqID, resource.OperationCreate,
			func(token string) (*runtime.Poller[armsignalr.ClientCreateOrUpdateResponse], error) {
				return resumePoller[armsignalr.ClientCreateOrUpdateResponse](s.pipeline, token)
			},
			func(_ context.Context, result armsignalr.ClientCreateOrUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				return s.completeFromResourceInfo(&result.ResourceInfo)
			})
	case lroOpUpdate:
		return statusLRO(ctx, request, &reqID, resource.OperationUpdate,
			func(token string) (*runtime.Poller[armsignalr.ClientUpdateResponse], error) {
				return resumePoller[armsignalr.ClientUpdateResponse](s.pipeline, token)
			},
			func(_ context.Context, result armsignalr.ClientUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				return s.completeFromResourceInfo(&result.ResourceInfo)
			})
	case lroOpDelete:
		return statusDeleteLRO(ctx, request, &reqID,
			func(token string) (*runtime.Poller[armsignalr.ClientDeleteResponse], error) {
				return resumePoller[armsignalr.ClientDeleteResponse](s.pipeline, token)
			}, nil)
	default:
		return nil, fmt.Errorf("unknown operation type: %s", reqID.OperationType)
	}
}

func (s *SignalR) completeFromResourceInfo(info *armsignalr.ResourceInfo) (string, json.RawMessage, error) {
	nativeID := ""
	rgName := ""
	if info.ID != nil {
		nativeID = *info.ID
		if rg, _, err := signalRIDParts(*info.ID); err == nil {
			rgName = rg
		}
	}
	propsJSON, err := json.Marshal(s.buildPropertiesFromResult(info, rgName))
	if err != nil {
		return "", nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return nativeID, propsJSON, nil
}

func (s *SignalR) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]

	var nativeIDs []string

	if rgName != "" {
		pager := s.api.NewListByResourceGroupPager(rgName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list signalr services: %w", err)
			}
			for _, info := range page.Value {
				if info.ID != nil {
					nativeIDs = append(nativeIDs, *info.ID)
				}
			}
		}
		return &resource.ListResult{NativeIDs: nativeIDs}, nil
	}

	pager := s.api.NewListBySubscriptionPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list signalr services: %w", err)
		}
		for _, info := range page.Value {
			if info.ID != nil {
				nativeIDs = append(nativeIDs, *info.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
