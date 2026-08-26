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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerregistry/armcontainerregistry"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeContainerRegistryWebhook = "AZURE::ContainerRegistry::Webhook"

// containerRegistryWebhooksAPI is the armcontainerregistry surface used here. All
// three mutating calls are LROs, and create and update take different parameter
// types (WebhookCreateParameters vs WebhookUpdateParameters) — the create body
// carries location, the update body does not.
type containerRegistryWebhooksAPI interface {
	BeginCreate(ctx context.Context, resourceGroupName string, registryName string, webhookName string, webhookCreateParameters armcontainerregistry.WebhookCreateParameters, options *armcontainerregistry.WebhooksClientBeginCreateOptions) (*runtime.Poller[armcontainerregistry.WebhooksClientCreateResponse], error)
	Get(ctx context.Context, resourceGroupName string, registryName string, webhookName string, options *armcontainerregistry.WebhooksClientGetOptions) (armcontainerregistry.WebhooksClientGetResponse, error)
	BeginUpdate(ctx context.Context, resourceGroupName string, registryName string, webhookName string, webhookUpdateParameters armcontainerregistry.WebhookUpdateParameters, options *armcontainerregistry.WebhooksClientBeginUpdateOptions) (*runtime.Poller[armcontainerregistry.WebhooksClientUpdateResponse], error)
	BeginDelete(ctx context.Context, resourceGroupName string, registryName string, webhookName string, options *armcontainerregistry.WebhooksClientBeginDeleteOptions) (*runtime.Poller[armcontainerregistry.WebhooksClientDeleteResponse], error)
	NewListPager(resourceGroupName string, registryName string, options *armcontainerregistry.WebhooksClientListOptions) *runtime.Pager[armcontainerregistry.WebhooksClientListResponse]
}

func init() {
	registry.Register(ResourceTypeContainerRegistryWebhook, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &ContainerRegistryWebhook{
			api:      c.ContainerRegistryWebhooksClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// ContainerRegistryWebhook is the provisioner for container registry webhooks
// (Microsoft.ContainerRegistry/registries/webhooks).
//
// serviceUri is write-only by ARM's design: accepted on create and update, never
// returned from Get. It is therefore never serialized into resource state, and
// drift in it cannot be detected.
type ContainerRegistryWebhook struct {
	api      containerRegistryWebhooksAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

// containerRegistryWebhookProps mirrors schema/pkl/containerregistry/webhook.pkl.
type containerRegistryWebhookProps struct {
	Name              string   `json:"name"`
	ResourceGroupName string   `json:"resourceGroupName"`
	RegistryName      string   `json:"registryName"`
	Location          string   `json:"location"`
	ServiceURI        string   `json:"serviceUri"`
	Actions           []string `json:"actions"`
	Status            string   `json:"status"`
	Scope             *string  `json:"scope"`
}

func containerRegistryWebhookIDParts(resourceID string) (rgName, registryName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "registries", "webhooks")
	if err != nil {
		return "", "", "", err
	}
	return rgName, names["registries"], names["webhooks"], nil
}

func containerRegistryWebhookActions(actions []string) []*armcontainerregistry.WebhookAction {
	if len(actions) == 0 {
		return nil
	}
	out := make([]*armcontainerregistry.WebhookAction, 0, len(actions))
	for _, action := range actions {
		if action == "" {
			continue
		}
		out = append(out, to.Ptr(armcontainerregistry.WebhookAction(action)))
	}
	return out
}

func (w *ContainerRegistryWebhook) buildPropertiesFromResult(hook *armcontainerregistry.Webhook, rgName, registryName string) map[string]any {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	props["registryName"] = registryName

	if hook.ID != nil {
		props["id"] = *hook.ID
	}
	if hook.Name != nil {
		props["name"] = *hook.Name
	}
	if hook.Location != nil {
		props["location"] = normalizeAzureLocation(*hook.Location)
	}

	if p := hook.Properties; p != nil {
		if p.Status != nil {
			props["status"] = canonicalizeEnum(string(*p.Status), "enabled", "disabled")
		}
		if p.Scope != nil && *p.Scope != "" {
			props["scope"] = *p.Scope
		}
		if len(p.Actions) > 0 {
			// Order is echoed as sent: ARM treats the actions as a set, and sorting
			// them would make a desired list written in another order look like drift.
			actions := make([]string, 0, len(p.Actions))
			for _, action := range p.Actions {
				if action == nil {
					continue
				}
				actions = append(actions, canonicalizeEnum(string(*action),
					"push", "delete", "quarantine", "chart_push", "chart_delete"))
			}
			props["actions"] = actions
		}
		// serviceUri and customHeaders are absent from this response by ARM's design
		// — they come only from GetCallbackConfig — so there is nothing to drop.
		// provisioningState is service state and is deliberately not surfaced.
	}

	if tags := azureTagsToFormaeTags(hook.Tags); tags != nil {
		props["Tags"] = tags
	}

	return props
}

func (w *ContainerRegistryWebhook) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props containerRegistryWebhookProps
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	if props.RegistryName == "" {
		return nil, fmt.Errorf("registryName is required")
	}
	if props.Location == "" {
		return nil, fmt.Errorf("location is required")
	}
	if props.ServiceURI == "" {
		return nil, fmt.Errorf("serviceUri is required")
	}
	if len(props.Actions) == 0 {
		return nil, fmt.Errorf("actions is required")
	}
	name := props.Name
	if name == "" {
		name = request.Label
	}
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}

	createProps := &armcontainerregistry.WebhookPropertiesCreateParameters{
		ServiceURI: to.Ptr(props.ServiceURI),
		Actions:    containerRegistryWebhookActions(props.Actions),
		Scope:      props.Scope,
	}
	if props.Status != "" {
		createProps.Status = to.Ptr(armcontainerregistry.WebhookStatus(props.Status))
	}

	params := armcontainerregistry.WebhookCreateParameters{
		Location:   to.Ptr(props.Location),
		Properties: createProps,
	}
	if azureTags := formaeTagsToAzureTags(request.Properties); azureTags != nil {
		params.Tags = azureTags
	}

	poller, err := w.api.BeginCreate(ctx, props.ResourceGroupName, props.RegistryName, name, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.ContainerRegistry/registries/%s/webhooks/%s",
		w.config.SubscriptionId, props.ResourceGroupName, props.RegistryName, name)

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
		nativeID, propsJSON, err := w.completeFromWebhook(&result.Webhook)
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

func (w *ContainerRegistryWebhook) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, registryName, name, err := containerRegistryWebhookIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := w.api.Get(ctx, rgName, registryName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(w.buildPropertiesFromResult(&result.Webhook, rgName, registryName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeContainerRegistryWebhook,
		Properties:   string(propsJSON),
	}, nil
}

// Update takes WebhookUpdateParameters, which unlike the create body has no
// location field — the webhook cannot move region. serviceUri rides along so a
// changed endpoint is pushed even though drift in it cannot be observed.
func (w *ContainerRegistryWebhook) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, registryName, name, err := containerRegistryWebhookIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props containerRegistryWebhookProps
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	updateProps := &armcontainerregistry.WebhookPropertiesUpdateParameters{
		Actions: containerRegistryWebhookActions(props.Actions),
		Scope:   props.Scope,
	}
	if props.ServiceURI != "" {
		updateProps.ServiceURI = to.Ptr(props.ServiceURI)
	}
	if props.Status != "" {
		updateProps.Status = to.Ptr(armcontainerregistry.WebhookStatus(props.Status))
	}

	params := armcontainerregistry.WebhookUpdateParameters{Properties: updateProps}
	if azureTags := formaeTagsToAzureTags(request.DesiredProperties); azureTags != nil {
		params.Tags = azureTags
	}

	poller, err := w.api.BeginUpdate(ctx, rgName, registryName, name, params, nil)
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
		propsJSON, err := json.Marshal(w.buildPropertiesFromResult(&result.Webhook, rgName, registryName))
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

func (w *ContainerRegistryWebhook) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, registryName, name, err := containerRegistryWebhookIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, err := w.api.BeginDelete(ctx, rgName, registryName, name, nil)
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

func (w *ContainerRegistryWebhook) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	reqID, err := decodeLROStatus(request.RequestID)
	if err != nil {
		return nil, err
	}

	switch reqID.OperationType {
	case lroOpCreate:
		return statusLRO(ctx, request, &reqID, resource.OperationCreate,
			func(token string) (*runtime.Poller[armcontainerregistry.WebhooksClientCreateResponse], error) {
				return resumePoller[armcontainerregistry.WebhooksClientCreateResponse](w.pipeline, token)
			},
			func(_ context.Context, result armcontainerregistry.WebhooksClientCreateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				return w.completeFromWebhook(&result.Webhook)
			})
	case lroOpUpdate:
		// Resumed as an Update response, matching the BeginUpdate poller that handed
		// out this token — Update really does use the SDK's update verb here.
		return statusLRO(ctx, request, &reqID, resource.OperationUpdate,
			func(token string) (*runtime.Poller[armcontainerregistry.WebhooksClientUpdateResponse], error) {
				return resumePoller[armcontainerregistry.WebhooksClientUpdateResponse](w.pipeline, token)
			},
			func(_ context.Context, result armcontainerregistry.WebhooksClientUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				return w.completeFromWebhook(&result.Webhook)
			})
	case lroOpDelete:
		return statusDeleteLRO(ctx, request, &reqID,
			func(token string) (*runtime.Poller[armcontainerregistry.WebhooksClientDeleteResponse], error) {
				return resumePoller[armcontainerregistry.WebhooksClientDeleteResponse](w.pipeline, token)
			}, nil)
	default:
		return nil, fmt.Errorf("unknown operation type: %s", reqID.OperationType)
	}
}

func (w *ContainerRegistryWebhook) completeFromWebhook(hook *armcontainerregistry.Webhook) (string, json.RawMessage, error) {
	nativeID := ""
	rgName := ""
	registryName := ""
	if hook.ID != nil {
		nativeID = *hook.ID
		if rg, registry, _, err := containerRegistryWebhookIDParts(*hook.ID); err == nil {
			rgName = rg
			registryName = registry
		}
	}
	propsJSON, err := json.Marshal(w.buildPropertiesFromResult(hook, rgName, registryName))
	if err != nil {
		return "", nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return nativeID, propsJSON, nil
}

// List requires both the resource group and the registry: ARM has no
// subscription-wide listing for webhooks.
func (w *ContainerRegistryWebhook) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	registryName := request.AdditionalProperties["registryName"]
	if rgName == "" || registryName == "" {
		return &resource.ListResult{}, nil
	}

	var nativeIDs []string
	pager := w.api.NewListPager(rgName, registryName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list container registry webhooks: %w", err)
		}
		for _, hook := range page.Value {
			if hook.ID != nil {
				nativeIDs = append(nativeIDs, *hook.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
