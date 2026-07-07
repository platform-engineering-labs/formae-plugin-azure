// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/eventhub/armeventhub"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeEventHubNamespace = "AZURE::EventHub::Namespace"

type eventHubNamespacesAPI interface {
	BeginCreateOrUpdate(ctx context.Context, resourceGroupName string, namespaceName string, parameters armeventhub.EHNamespace, options *armeventhub.NamespacesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armeventhub.NamespacesClientCreateOrUpdateResponse], error)
	Get(ctx context.Context, resourceGroupName string, namespaceName string, options *armeventhub.NamespacesClientGetOptions) (armeventhub.NamespacesClientGetResponse, error)
	Update(ctx context.Context, resourceGroupName string, namespaceName string, parameters armeventhub.EHNamespace, options *armeventhub.NamespacesClientUpdateOptions) (armeventhub.NamespacesClientUpdateResponse, error)
	BeginDelete(ctx context.Context, resourceGroupName string, namespaceName string, options *armeventhub.NamespacesClientBeginDeleteOptions) (*runtime.Poller[armeventhub.NamespacesClientDeleteResponse], error)
	NewListPager(options *armeventhub.NamespacesClientListOptions) *runtime.Pager[armeventhub.NamespacesClientListResponse]
	NewListByResourceGroupPager(resourceGroupName string, options *armeventhub.NamespacesClientListByResourceGroupOptions) *runtime.Pager[armeventhub.NamespacesClientListByResourceGroupResponse]
}

func init() {
	registry.Register(ResourceTypeEventHubNamespace, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &EventHubNamespace{
			api:      c.EventHubNamespacesClient,
			config:   cfg,
			pipeline: c.Pipeline(),
		}
	})
}

// EventHubNamespace is the provisioner for Azure Event Hubs Namespaces.
type EventHubNamespace struct {
	api      eventHubNamespacesAPI
	config   *config.Config
	pipeline runtime.Pipeline
}

func eventHubNamespaceIDParts(resourceID string) (rgName, namespaceName string, err error) {
	rgName, names, err := armIDParts(resourceID, "namespaces")
	if err != nil {
		return "", "", err
	}
	return rgName, names["namespaces"], nil
}

func serializeEventHubNamespaceProperties(result armeventhub.EHNamespace, rgName, namespaceName string) (json.RawMessage, error) {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	if result.Name != nil {
		props["name"] = *result.Name
	} else {
		props["name"] = namespaceName
	}

	if result.Location != nil {
		props["location"] = *result.Location
	}

	if result.SKU != nil {
		sku := make(map[string]any)
		if result.SKU.Name != nil {
			sku["name"] = string(*result.SKU.Name)
		}
		if result.SKU.Tier != nil {
			sku["tier"] = string(*result.SKU.Tier)
		}
		if result.SKU.Capacity != nil {
			sku["capacity"] = *result.SKU.Capacity
		}
		props["sku"] = sku
	}

	if result.Properties != nil && result.Properties.ZoneRedundant != nil {
		props["zoneRedundant"] = *result.Properties.ZoneRedundant
	}

	if tags := azureTagsToFormaeTags(result.Tags); tags != nil {
		props["Tags"] = tags
	}

	if result.ID != nil {
		props["id"] = *result.ID
	}

	return json.Marshal(props)
}

// buildEventHubNamespaceParams maps Formae properties to an EHNamespace request body.
func buildEventHubNamespaceParams(props map[string]any) (armeventhub.EHNamespace, error) {
	location, ok := props["location"].(string)
	if !ok || location == "" {
		return armeventhub.EHNamespace{}, fmt.Errorf("location is required")
	}

	params := armeventhub.EHNamespace{
		Location:   stringPtr(location),
		Properties: &armeventhub.EHNamespaceProperties{},
	}

	params.SKU = buildEventHubNamespaceSKU(props)

	if zoneRedundant, ok := props["zoneRedundant"].(bool); ok {
		params.Properties.ZoneRedundant = &zoneRedundant
	}

	return params, nil
}

func buildEventHubNamespaceSKU(props map[string]any) *armeventhub.SKU {
	skuRaw, ok := props["sku"].(map[string]any)
	if !ok {
		return nil
	}
	sku := &armeventhub.SKU{}
	if name, ok := skuRaw["name"].(string); ok && name != "" {
		skuName := armeventhub.SKUName(name)
		sku.Name = &skuName
	}
	if tier, ok := skuRaw["tier"].(string); ok && tier != "" {
		skuTier := armeventhub.SKUTier(tier)
		sku.Tier = &skuTier
	}
	if capacity, ok := skuRaw["capacity"].(float64); ok {
		c := int32(capacity)
		sku.Capacity = &c
	}
	return sku
}

func (n *EventHubNamespace) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props map[string]any
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	rgName, ok := props["resourceGroupName"].(string)
	if !ok || rgName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}

	namespaceName, ok := props["name"].(string)
	if !ok || namespaceName == "" {
		namespaceName = request.Label
	}

	params, err := buildEventHubNamespaceParams(props)
	if err != nil {
		return nil, err
	}

	if azureTags := formaeTagsToAzureTags(request.Properties); azureTags != nil {
		params.Tags = azureTags
	}

	poller, err := n.api.BeginCreateOrUpdate(ctx, rgName, namespaceName, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.EventHub/namespaces/%s",
		n.config.SubscriptionId, rgName, namespaceName)

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

		propsJSON, err := serializeEventHubNamespaceProperties(result.EHNamespace, rgName, namespaceName)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize Event Hub Namespace properties: %w", err)
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

func (n *EventHubNamespace) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, namespaceName, err := eventHubNamespaceIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := n.api.Get(ctx, rgName, namespaceName, nil)
	if err != nil {
		return &resource.ReadResult{
			ErrorCode: operationErrorCode(err),
		}, nil
	}

	propsJSON, err := serializeEventHubNamespaceProperties(result.EHNamespace, rgName, namespaceName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize Event Hub Namespace properties: %w", err)
	}

	return &resource.ReadResult{
		ResourceType: ResourceTypeEventHubNamespace,
		Properties:   string(propsJSON),
	}, nil
}

func (n *EventHubNamespace) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, namespaceName, err := eventHubNamespaceIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props map[string]any
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	// PATCH with only the mutable fields; a full PUT would reset unmodeled
	// server-side settings (autoInflate, TLS minimum, network access) to defaults.
	params := armeventhub.EHNamespace{}
	if sku := buildEventHubNamespaceSKU(props); sku != nil {
		params.SKU = sku
	}
	if azureTags := formaeTagsToAzureTags(request.DesiredProperties); azureTags != nil {
		params.Tags = azureTags
	}

	// Event Hub Namespace update (PATCH) is synchronous.
	result, err := n.api.Update(ctx, rgName, namespaceName, params, nil)
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

	propsJSON, err := serializeEventHubNamespaceProperties(result.EHNamespace, rgName, namespaceName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize Event Hub Namespace properties: %w", err)
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

func (n *EventHubNamespace) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, namespaceName, err := eventHubNamespaceIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, err := n.api.BeginDelete(ctx, rgName, namespaceName, nil)
	if err != nil {
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
				ErrorCode:       operationErrorCode(err),
			},
		}, fmt.Errorf("failed to start Event Hub Namespace deletion: %w", err)
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
			}, fmt.Errorf("failed to get Event Hub Namespace delete result: %w", err)
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

func (n *EventHubNamespace) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
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
		}, fmt.Errorf("unexpected operation type: %s", reqID.OperationType)
	}
}

func (n *EventHubNamespace) statusCreateOrUpdate(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	operation := resource.OperationCreate
	if reqID.OperationType == lroOpUpdate {
		operation = resource.OperationUpdate
	}

	return statusLRO(ctx, request, reqID, operation,
		func(token string) (*runtime.Poller[armeventhub.NamespacesClientCreateOrUpdateResponse], error) {
			return resumePoller[armeventhub.NamespacesClientCreateOrUpdateResponse](n.pipeline, token)
		},
		func(_ context.Context, result armeventhub.NamespacesClientCreateOrUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
			rgName, namespaceName, err := eventHubNamespaceIDParts(*result.ID)
			if err != nil {
				return "", nil, err
			}
			propsJSON, err := serializeEventHubNamespaceProperties(result.EHNamespace, rgName, namespaceName)
			if err != nil {
				return "", nil, fmt.Errorf("failed to serialize Event Hub Namespace properties: %w", err)
			}
			return *result.ID, propsJSON, nil
		})
}

func (n *EventHubNamespace) statusDelete(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	return statusDeleteLRO(ctx, request, reqID,
		func(token string) (*runtime.Poller[armeventhub.NamespacesClientDeleteResponse], error) {
			return resumePoller[armeventhub.NamespacesClientDeleteResponse](n.pipeline, token)
		}, nil)
}

func (n *EventHubNamespace) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]

	var nativeIDs []string

	if rgName != "" {
		pager := n.api.NewListByResourceGroupPager(rgName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list Event Hub Namespaces: %w", err)
			}
			for _, ns := range page.Value {
				if ns.ID != nil {
					nativeIDs = append(nativeIDs, *ns.ID)
				}
			}
		}
	} else {
		pager := n.api.NewListPager(nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list Event Hub Namespaces: %w", err)
			}
			for _, ns := range page.Value {
				if ns.ID != nil {
					nativeIDs = append(nativeIDs, *ns.ID)
				}
			}
		}
	}

	return &resource.ListResult{
		NativeIDs: nativeIDs,
	}, nil
}
