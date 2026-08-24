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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/notificationhubs/armnotificationhubs"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeNotificationHubNamespace = "AZURE::NotificationHubs::Namespace"

// notificationHubNamespacesAPI is the armnotificationhubs surface used here. An
// unusual mix: create is synchronous, the update verb is called Patch rather than
// Update, and only delete is an LRO.
type notificationHubNamespacesAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName string, namespaceName string, parameters armnotificationhubs.NamespaceCreateOrUpdateParameters, options *armnotificationhubs.NamespacesClientCreateOrUpdateOptions) (armnotificationhubs.NamespacesClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName string, namespaceName string, options *armnotificationhubs.NamespacesClientGetOptions) (armnotificationhubs.NamespacesClientGetResponse, error)
	Patch(ctx context.Context, resourceGroupName string, namespaceName string, parameters armnotificationhubs.NamespacePatchParameters, options *armnotificationhubs.NamespacesClientPatchOptions) (armnotificationhubs.NamespacesClientPatchResponse, error)
	BeginDelete(ctx context.Context, resourceGroupName string, namespaceName string, options *armnotificationhubs.NamespacesClientBeginDeleteOptions) (*runtime.Poller[armnotificationhubs.NamespacesClientDeleteResponse], error)
	NewListPager(resourceGroupName string, options *armnotificationhubs.NamespacesClientListOptions) *runtime.Pager[armnotificationhubs.NamespacesClientListResponse]
	NewListAllPager(options *armnotificationhubs.NamespacesClientListAllOptions) *runtime.Pager[armnotificationhubs.NamespacesClientListAllResponse]
}

func init() {
	registry.Register(ResourceTypeNotificationHubNamespace, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &NotificationHubNamespace{
			api:      c.NotificationHubNamespacesClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// NotificationHubNamespace is the provisioner for Notification Hubs namespaces
// (Microsoft.NotificationHubs/namespaces).
//
// The shared access keys are never serialized: ARM returns them only from a
// separate ListKeys call, so putting them in resource state would persist live
// credentials.
type NotificationHubNamespace struct {
	api      notificationHubNamespacesAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

// notificationHubNamespaceProps mirrors
// schema/pkl/notificationhubs/notificationhubnamespace.pkl.
type notificationHubNamespaceProps struct {
	Name              string `json:"name"`
	Location          string `json:"location"`
	ResourceGroupName string `json:"resourceGroupName"`
	SKUName           string `json:"skuName"`
	NamespaceType     string `json:"namespaceType"`
}

func notificationHubNamespaceIDParts(resourceID string) (rgName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "namespaces")
	if err != nil {
		return "", "", err
	}
	return rgName, names["namespaces"], nil
}

// notificationHubSKU builds the ARM sku block from the scalar the schema carries.
// ARM fills in tier, size, family and capacity itself, which is exactly why the
// schema does not model them: nested fields with provider defaults read back as
// drift.
func notificationHubSKU(name string) *armnotificationhubs.SKU {
	if name == "" {
		return nil
	}
	return &armnotificationhubs.SKU{Name: to.Ptr(armnotificationhubs.SKUName(name))}
}

func (n *NotificationHubNamespace) buildPropertiesFromResult(ns *armnotificationhubs.NamespaceResource, rgName string) map[string]any {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName

	if ns.ID != nil {
		props["id"] = *ns.ID
	}
	if ns.Name != nil {
		props["name"] = *ns.Name
	}
	if ns.Location != nil {
		props["location"] = normalizeAzureLocation(*ns.Location)
	}
	if ns.SKU != nil && ns.SKU.Name != nil {
		props["skuName"] = canonicalizeEnum(string(*ns.SKU.Name), "Free", "Basic", "Standard")
	}

	if p := ns.Properties; p != nil {
		if p.NamespaceType != nil {
			props["namespaceType"] = canonicalizeEnum(string(*p.NamespaceType), "NotificationHub", "Messaging")
		}
		if p.ServiceBusEndpoint != nil {
			props["serviceBusEndpoint"] = *p.ServiceBusEndpoint
		}
		if p.MetricID != nil {
			props["metricId"] = *p.MetricID
		}
		// createdAt, updatedAt, status, provisioningState, scaleUnit, dataCenter,
		// region, subscriptionId, critical and enabled are all deliberately
		// dropped: none is desired state, and the timestamps and status move on
		// their own, so surfacing them would read back as drift on every sync.
	}

	if tags := azureTagsToFormaeTags(ns.Tags); tags != nil {
		props["Tags"] = tags
	}

	return props
}

func (n *NotificationHubNamespace) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props notificationHubNamespaceProps
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	if props.Location == "" {
		return nil, fmt.Errorf("location is required")
	}
	name := props.Name
	if name == "" {
		name = request.Label
	}
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}

	nsProps := &armnotificationhubs.NamespaceProperties{}
	if props.NamespaceType != "" {
		nsProps.NamespaceType = to.Ptr(armnotificationhubs.NamespaceType(props.NamespaceType))
	}

	params := armnotificationhubs.NamespaceCreateOrUpdateParameters{
		Location:   to.Ptr(props.Location),
		SKU:        notificationHubSKU(props.SKUName),
		Properties: nsProps,
	}
	if azureTags := formaeTagsToAzureTags(request.Properties); azureTags != nil {
		params.Tags = azureTags
	}

	result, err := n.api.CreateOrUpdate(ctx, props.ResourceGroupName, name, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	nativeID := ""
	if result.ID != nil {
		nativeID = *result.ID
	}
	propsJSON, err := json.Marshal(n.buildPropertiesFromResult(&result.NamespaceResource, props.ResourceGroupName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
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

func (n *NotificationHubNamespace) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, name, err := notificationHubNamespaceIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := n.api.Get(ctx, rgName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(n.buildPropertiesFromResult(&result.NamespaceResource, rgName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeNotificationHubNamespace,
		Properties:   string(propsJSON),
	}, nil
}

// Update goes through Patch, which is synchronous and carries only the sku and
// tags — namespaceType and location are createOnly in the schema to match.
func (n *NotificationHubNamespace) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, name, err := notificationHubNamespaceIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props notificationHubNamespaceProps
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	params := armnotificationhubs.NamespacePatchParameters{
		SKU: notificationHubSKU(props.SKUName),
	}
	if azureTags := formaeTagsToAzureTags(request.DesiredProperties); azureTags != nil {
		params.Tags = azureTags
	}

	result, err := n.api.Patch(ctx, rgName, name, params, nil)
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

	propsJSON, err := json.Marshal(n.buildPropertiesFromResult(&result.NamespaceResource, rgName))
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

func (n *NotificationHubNamespace) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, name, err := notificationHubNamespaceIDParts(request.NativeID)
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

// Status only ever handles a delete: create and update are both synchronous here.
func (n *NotificationHubNamespace) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	reqID, err := decodeLROStatus(request.RequestID)
	if err != nil {
		return nil, err
	}

	switch reqID.OperationType {
	case lroOpDelete:
		return statusDeleteLRO(ctx, request, &reqID,
			func(token string) (*runtime.Poller[armnotificationhubs.NamespacesClientDeleteResponse], error) {
				return resumePoller[armnotificationhubs.NamespacesClientDeleteResponse](n.pipeline, token)
			}, nil)
	default:
		return nil, fmt.Errorf("unknown operation type: %s", reqID.OperationType)
	}
}

func (n *NotificationHubNamespace) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]

	var nativeIDs []string

	if rgName != "" {
		pager := n.api.NewListPager(rgName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list notification hub namespaces: %w", err)
			}
			for _, ns := range page.Value {
				if ns.ID != nil {
					nativeIDs = append(nativeIDs, *ns.ID)
				}
			}
		}
		return &resource.ListResult{NativeIDs: nativeIDs}, nil
	}

	pager := n.api.NewListAllPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list notification hub namespaces: %w", err)
		}
		for _, ns := range page.Value {
			if ns.ID != nil {
				nativeIDs = append(nativeIDs, *ns.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
