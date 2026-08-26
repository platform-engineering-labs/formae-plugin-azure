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

const ResourceTypeContainerRegistryToken = "AZURE::ContainerRegistry::Token"

// containerRegistryTokensAPI is the armcontainerregistry surface used here. As with
// scope maps all three writes are LROs and there is a real update verb, whose patch
// body carries only the mutable fields.
type containerRegistryTokensAPI interface {
	BeginCreate(ctx context.Context, resourceGroupName, registryName, tokenName string, tokenCreateParameters armcontainerregistry.Token, options *armcontainerregistry.TokensClientBeginCreateOptions) (*runtime.Poller[armcontainerregistry.TokensClientCreateResponse], error)
	Get(ctx context.Context, resourceGroupName, registryName, tokenName string, options *armcontainerregistry.TokensClientGetOptions) (armcontainerregistry.TokensClientGetResponse, error)
	BeginUpdate(ctx context.Context, resourceGroupName, registryName, tokenName string, tokenUpdateParameters armcontainerregistry.TokenUpdateParameters, options *armcontainerregistry.TokensClientBeginUpdateOptions) (*runtime.Poller[armcontainerregistry.TokensClientUpdateResponse], error)
	BeginDelete(ctx context.Context, resourceGroupName, registryName, tokenName string, options *armcontainerregistry.TokensClientBeginDeleteOptions) (*runtime.Poller[armcontainerregistry.TokensClientDeleteResponse], error)
	NewListPager(resourceGroupName, registryName string, options *armcontainerregistry.TokensClientListOptions) *runtime.Pager[armcontainerregistry.TokensClientListResponse]
}

func init() {
	registry.Register(ResourceTypeContainerRegistryToken, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &ContainerRegistryToken{
			api:      c.ContainerRegistryTokensClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// ContainerRegistryToken is the provisioner for registry tokens
// (Microsoft.ContainerRegistry/registries/tokens). It is a child of
// AZURE::ContainerRegistry::Registry and requires a Premium registry.
type ContainerRegistryToken struct {
	api      containerRegistryTokensAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

// containerRegistryTokenProps mirrors
// schema/pkl/containerregistry/token.pkl.
//
// There is no credentials field on purpose: ARM's credentials block carries password
// values, and passwords are issued by a separate generateCredentials call on the
// registry. Nothing here sends or reads them.
type containerRegistryTokenProps struct {
	Name              string  `json:"name"`
	ResourceGroupName string  `json:"resourceGroupName"`
	RegistryName      string  `json:"registryName"`
	ScopeMapID        string  `json:"scopeMapId"`
	Status            *string `json:"status"`
}

func containerRegistryTokenIDParts(resourceID string) (rgName, registryName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "registries", "tokens")
	if err != nil {
		return "", "", "", err
	}
	return rgName, names["registries"], names["tokens"], nil
}

func (t *ContainerRegistryToken) buildPropertiesFromResult(token *armcontainerregistry.Token, rgName, registryName string) map[string]any {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	props["registryName"] = registryName

	if token.ID != nil {
		props["id"] = *token.ID
	}
	if token.Name != nil {
		props["name"] = *token.Name
	}

	if p := token.Properties; p != nil {
		if p.ScopeMapID != nil {
			props["scopeMapId"] = *p.ScopeMapID
		}
		if p.Status != nil {
			props["status"] = canonicalizeEnum(string(*p.Status), "enabled", "disabled")
		}
		// credentials is never read back. Password entries carry secret values, and
		// their presence is decided by generateCredentials rather than by this
		// resource — so a credential issued out of band survives every apply instead
		// of reading as drift. Certificates are not modelled either.
		//
		// creationDate and provisioningState are service state.
	}

	return props
}

func (t *ContainerRegistryToken) parseProps(payload json.RawMessage, label string) (containerRegistryTokenProps, string, error) {
	var props containerRegistryTokenProps
	if err := json.Unmarshal(payload, &props); err != nil {
		return props, "", fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return props, "", fmt.Errorf("resourceGroupName is required")
	}
	if props.RegistryName == "" {
		return props, "", fmt.Errorf("registryName is required")
	}
	if props.ScopeMapID == "" {
		return props, "", fmt.Errorf("scopeMapId is required")
	}
	name := props.Name
	if name == "" {
		name = label
	}
	if name == "" {
		return props, "", fmt.Errorf("name is required")
	}
	return props, name, nil
}

func (t *ContainerRegistryToken) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	props, name, err := t.parseProps(request.Properties, request.Label)
	if err != nil {
		return nil, err
	}

	params := armcontainerregistry.Token{
		Properties: &armcontainerregistry.TokenProperties{
			ScopeMapID: to.Ptr(props.ScopeMapID),
		},
	}
	if props.Status != nil && *props.Status != "" {
		params.Properties.Status = to.Ptr(armcontainerregistry.TokenStatus(*props.Status))
	}

	poller, err := t.api.BeginCreate(ctx, props.ResourceGroupName, props.RegistryName, name, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.ContainerRegistry/registries/%s/tokens/%s",
		t.config.SubscriptionId, props.ResourceGroupName, props.RegistryName, name)

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
		nativeID, propsJSON, err := t.completeFromToken(&result.Token)
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

func (t *ContainerRegistryToken) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, registryName, name, err := containerRegistryTokenIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := t.api.Get(ctx, rgName, registryName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(t.buildPropertiesFromResult(&result.Token, rgName, registryName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeContainerRegistryToken,
		Properties:   string(propsJSON),
	}, nil
}

// Update patches through BeginUpdate. Only the scope map and the status are mutable,
// and the patch body carries no credentials — so an existing password is untouched
// by a status flip.
func (t *ContainerRegistryToken) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, registryName, name, err := containerRegistryTokenIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	props, _, err := t.parseProps(request.DesiredProperties, name)
	if err != nil {
		return nil, err
	}

	params := armcontainerregistry.TokenUpdateParameters{
		Properties: &armcontainerregistry.TokenUpdateProperties{
			ScopeMapID: to.Ptr(props.ScopeMapID),
		},
	}
	if props.Status != nil && *props.Status != "" {
		params.Properties.Status = to.Ptr(armcontainerregistry.TokenStatus(*props.Status))
	}

	poller, err := t.api.BeginUpdate(ctx, rgName, registryName, name, params, nil)
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
		propsJSON, err := json.Marshal(t.buildPropertiesFromResult(&result.Token, rgName, registryName))
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

func (t *ContainerRegistryToken) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, registryName, name, err := containerRegistryTokenIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, err := t.api.BeginDelete(ctx, rgName, registryName, name, nil)
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

func (t *ContainerRegistryToken) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	reqID, err := decodeLROStatus(request.RequestID)
	if err != nil {
		return nil, err
	}

	switch reqID.OperationType {
	case lroOpCreate:
		return statusLRO(ctx, request, &reqID, resource.OperationCreate,
			func(token string) (*runtime.Poller[armcontainerregistry.TokensClientCreateResponse], error) {
				return resumePoller[armcontainerregistry.TokensClientCreateResponse](t.pipeline, token)
			},
			func(_ context.Context, result armcontainerregistry.TokensClientCreateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				return t.completeFromToken(&result.Token)
			})
	case lroOpUpdate:
		// Its own case: this API has a real update verb, so the token was issued by a
		// poller with the Update response type. Resuming it as a Create response
		// would kill the plugin operator mid-apply.
		return statusLRO(ctx, request, &reqID, resource.OperationUpdate,
			func(token string) (*runtime.Poller[armcontainerregistry.TokensClientUpdateResponse], error) {
				return resumePoller[armcontainerregistry.TokensClientUpdateResponse](t.pipeline, token)
			},
			func(_ context.Context, result armcontainerregistry.TokensClientUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				return t.completeFromToken(&result.Token)
			})
	case lroOpDelete:
		return statusDeleteLRO(ctx, request, &reqID,
			func(token string) (*runtime.Poller[armcontainerregistry.TokensClientDeleteResponse], error) {
				return resumePoller[armcontainerregistry.TokensClientDeleteResponse](t.pipeline, token)
			}, nil)
	default:
		return nil, fmt.Errorf("unknown operation type: %s", reqID.OperationType)
	}
}

func (t *ContainerRegistryToken) completeFromToken(token *armcontainerregistry.Token) (string, json.RawMessage, error) {
	nativeID := ""
	rgName := ""
	registryName := ""
	if token.ID != nil {
		nativeID = *token.ID
		if rg, registryName2, _, err := containerRegistryTokenIDParts(*token.ID); err == nil {
			rgName = rg
			registryName = registryName2
		}
	}
	propsJSON, err := json.Marshal(t.buildPropertiesFromResult(token, rgName, registryName))
	if err != nil {
		return "", nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return nativeID, propsJSON, nil
}

// List requires both the resource group and the registry: tokens only exist inside
// one.
func (t *ContainerRegistryToken) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	registryName := request.AdditionalProperties["registryName"]
	if rgName == "" || registryName == "" {
		return &resource.ListResult{}, nil
	}

	var nativeIDs []string
	pager := t.api.NewListPager(rgName, registryName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list tokens: %w", err)
		}
		for _, token := range page.Value {
			if token != nil && token.ID != nil {
				nativeIDs = append(nativeIDs, *token.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
