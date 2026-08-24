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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/relay/armrelay"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeRelayNamespace = "AZURE::Relay::Namespace"

// relayNamespacesAPI is the armrelay surface used here. Create and Delete are
// LROs, Update is a synchronous PATCH. Create takes a Namespace and update takes
// an UpdateParameters, but both carry the same NamespaceProperties block.
type relayNamespacesAPI interface {
	BeginCreateOrUpdate(ctx context.Context, resourceGroupName string, accountName string, parameters armrelay.Namespace, options *armrelay.NamespacesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armrelay.NamespacesClientCreateOrUpdateResponse], error)
	Get(ctx context.Context, resourceGroupName string, accountName string, options *armrelay.NamespacesClientGetOptions) (armrelay.NamespacesClientGetResponse, error)
	Update(ctx context.Context, resourceGroupName string, accountName string, parameters armrelay.UpdateParameters, options *armrelay.NamespacesClientUpdateOptions) (armrelay.NamespacesClientUpdateResponse, error)
	BeginDelete(ctx context.Context, resourceGroupName string, accountName string, options *armrelay.NamespacesClientBeginDeleteOptions) (*runtime.Poller[armrelay.NamespacesClientDeleteResponse], error)
	NewListPager(options *armrelay.NamespacesClientListOptions) *runtime.Pager[armrelay.NamespacesClientListResponse]
	NewListByResourceGroupPager(resourceGroupName string, options *armrelay.NamespacesClientListByResourceGroupOptions) *runtime.Pager[armrelay.NamespacesClientListByResourceGroupResponse]
}

func init() {
	registry.Register(ResourceTypeRelayNamespace, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &RelayNamespace{
			api:      c.RelayNamespacesClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// BatchAccount is the provisioner for Azure Batch accounts
// (Microsoft.Relay/namespaces).
//
// The shared account keys are never serialized: ARM returns them only from a
// separate GetKeys call, so putting them in resource state would persist live
// credentials.
type RelayNamespace struct {
	api      relayNamespacesAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

// relayNamespaceProps mirrors schema/pkl/relay/relaynamespace.pkl.
type relayNamespaceProps struct {
	Name                string `json:"name"`
	Location            string `json:"location"`
	ResourceGroupName   string `json:"resourceGroupName"`
	SKUName             string `json:"skuName"`
	PublicNetworkAccess string `json:"publicNetworkAccess"`
}

func relayNamespaceIDParts(resourceID string) (rgName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "namespaces")
	if err != nil {
		return "", "", err
	}
	return rgName, names["namespaces"], nil
}

func (r *RelayNamespace) buildPropertiesFromResult(ns *armrelay.Namespace, rgName string) map[string]any {
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
		props["skuName"] = canonicalizeEnum(string(*ns.SKU.Name), "Standard")
	}

	if p := ns.Properties; p != nil {
		if p.PublicNetworkAccess != nil {
			props["publicNetworkAccess"] = canonicalizeEnum(string(*p.PublicNetworkAccess),
				"Enabled", "Disabled", "SecuredByPerimeter")
		}
		if p.ServiceBusEndpoint != nil {
			props["serviceBusEndpoint"] = *p.ServiceBusEndpoint
		}
		if p.MetricID != nil {
			props["metricId"] = *p.MetricID
		}
		// createdAt, updatedAt, status and provisioningState are deliberately
		// dropped: the timestamps move on their own and would read back as drift
		// on every sync, and the states are not desired state.
	}

	if tags := azureTagsToFormaeTags(ns.Tags); tags != nil {
		props["Tags"] = tags
	}

	return props
}

// relaySKU builds the ARM sku block. Relay has exactly one tier, so the schema
// carries a scalar skuName and the tier is filled in here; leaving the whole block
// out lets ARM apply its own default.
func relaySKU(name string) *armrelay.SKU {
	if name == "" {
		return nil
	}
	return &armrelay.SKU{
		Name: to.Ptr(armrelay.SKUName(name)),
		Tier: to.Ptr(armrelay.SKUTier(name)),
	}
}

func (r *RelayNamespace) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props relayNamespaceProps
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

	createProps := &armrelay.NamespaceProperties{}
	if props.PublicNetworkAccess != "" {
		createProps.PublicNetworkAccess = to.Ptr(armrelay.PublicNetworkAccess(props.PublicNetworkAccess))
	}

	params := armrelay.Namespace{
		Location:   to.Ptr(props.Location),
		SKU:        relaySKU(props.SKUName),
		Properties: createProps,
	}
	if azureTags := formaeTagsToAzureTags(request.Properties); azureTags != nil {
		params.Tags = azureTags
	}

	poller, err := r.api.BeginCreateOrUpdate(ctx, props.ResourceGroupName, name, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Relay/namespaces/%s",
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
		nativeID, propsJSON, err := r.completeFromNamespace(&result.Namespace)
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

func (r *RelayNamespace) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, name, err := relayNamespaceIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := r.api.Get(ctx, rgName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(r.buildPropertiesFromResult(&result.Namespace, rgName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeRelayNamespace,
		Properties:   string(propsJSON),
	}, nil
}

// Update is a synchronous PATCH — unlike Create there is no poller, so Status is
// never reached for an update.
func (r *RelayNamespace) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, name, err := relayNamespaceIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props relayNamespaceProps
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	updateProps := &armrelay.NamespaceProperties{}
	if props.PublicNetworkAccess != "" {
		updateProps.PublicNetworkAccess = to.Ptr(armrelay.PublicNetworkAccess(props.PublicNetworkAccess))
	}

	params := armrelay.UpdateParameters{
		SKU:        relaySKU(props.SKUName),
		Properties: updateProps,
	}
	if azureTags := formaeTagsToAzureTags(request.DesiredProperties); azureTags != nil {
		params.Tags = azureTags
	}

	result, err := r.api.Update(ctx, rgName, name, params, nil)
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

	propsJSON, err := json.Marshal(r.buildPropertiesFromResult(&result.Namespace, rgName))
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

func (r *RelayNamespace) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, name, err := relayNamespaceIDParts(request.NativeID)
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

// Status handles create and delete; Update is synchronous and never reaches here.
func (r *RelayNamespace) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	reqID, err := decodeLROStatus(request.RequestID)
	if err != nil {
		return nil, err
	}

	switch reqID.OperationType {
	case lroOpCreate:
		return statusLRO(ctx, request, &reqID, resource.OperationCreate,
			func(token string) (*runtime.Poller[armrelay.NamespacesClientCreateOrUpdateResponse], error) {
				return resumePoller[armrelay.NamespacesClientCreateOrUpdateResponse](r.pipeline, token)
			},
			func(_ context.Context, result armrelay.NamespacesClientCreateOrUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				return r.completeFromNamespace(&result.Namespace)
			})
	case lroOpDelete:
		return statusDeleteLRO(ctx, request, &reqID,
			func(token string) (*runtime.Poller[armrelay.NamespacesClientDeleteResponse], error) {
				return resumePoller[armrelay.NamespacesClientDeleteResponse](r.pipeline, token)
			}, nil)
	default:
		return nil, fmt.Errorf("unknown operation type: %s", reqID.OperationType)
	}
}

func (r *RelayNamespace) completeFromNamespace(ns *armrelay.Namespace) (string, json.RawMessage, error) {
	nativeID := ""
	rgName := ""
	if ns.ID != nil {
		nativeID = *ns.ID
		if rg, _, err := relayNamespaceIDParts(*ns.ID); err == nil {
			rgName = rg
		}
	}
	propsJSON, err := json.Marshal(r.buildPropertiesFromResult(ns, rgName))
	if err != nil {
		return "", nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return nativeID, propsJSON, nil
}

func (r *RelayNamespace) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]

	var nativeIDs []string

	if rgName != "" {
		pager := r.api.NewListByResourceGroupPager(rgName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list relay namespaces: %w", err)
			}
			for _, ns := range page.Value {
				if ns.ID != nil {
					nativeIDs = append(nativeIDs, *ns.ID)
				}
			}
		}
		return &resource.ListResult{NativeIDs: nativeIDs}, nil
	}

	pager := r.api.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list relay namespaces: %w", err)
		}
		for _, ns := range page.Value {
			if ns.ID != nil {
				nativeIDs = append(nativeIDs, *ns.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
