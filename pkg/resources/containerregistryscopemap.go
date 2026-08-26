// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerregistry/armcontainerregistry"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeContainerRegistryScopeMap = "AZURE::ContainerRegistry::ScopeMap"

// containerRegistryScopeMapsAPI is the armcontainerregistry surface used here. All
// three writes are LROs, and unlike most resources in this plugin there is a real
// update verb — BeginUpdate takes a patch body carrying only the mutable fields.
type containerRegistryScopeMapsAPI interface {
	BeginCreate(ctx context.Context, resourceGroupName, registryName, scopeMapName string, scopeMapCreateParameters armcontainerregistry.ScopeMap, options *armcontainerregistry.ScopeMapsClientBeginCreateOptions) (*runtime.Poller[armcontainerregistry.ScopeMapsClientCreateResponse], error)
	Get(ctx context.Context, resourceGroupName, registryName, scopeMapName string, options *armcontainerregistry.ScopeMapsClientGetOptions) (armcontainerregistry.ScopeMapsClientGetResponse, error)
	BeginUpdate(ctx context.Context, resourceGroupName, registryName, scopeMapName string, scopeMapUpdateParameters armcontainerregistry.ScopeMapUpdateParameters, options *armcontainerregistry.ScopeMapsClientBeginUpdateOptions) (*runtime.Poller[armcontainerregistry.ScopeMapsClientUpdateResponse], error)
	BeginDelete(ctx context.Context, resourceGroupName, registryName, scopeMapName string, options *armcontainerregistry.ScopeMapsClientBeginDeleteOptions) (*runtime.Poller[armcontainerregistry.ScopeMapsClientDeleteResponse], error)
	NewListPager(resourceGroupName, registryName string, options *armcontainerregistry.ScopeMapsClientListOptions) *runtime.Pager[armcontainerregistry.ScopeMapsClientListResponse]
}

func init() {
	registry.Register(ResourceTypeContainerRegistryScopeMap, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &ContainerRegistryScopeMap{
			api:      c.ContainerRegistryScopeMapsClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// ContainerRegistryScopeMap is the provisioner for registry scope maps
// (Microsoft.ContainerRegistry/registries/scopeMaps). It is a child of
// AZURE::ContainerRegistry::Registry and requires a Premium registry.
type ContainerRegistryScopeMap struct {
	api      containerRegistryScopeMapsAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

// containerRegistryScopeMapProps mirrors
// schema/pkl/containerregistry/scopemap.pkl.
type containerRegistryScopeMapProps struct {
	Name              string   `json:"name"`
	ResourceGroupName string   `json:"resourceGroupName"`
	RegistryName      string   `json:"registryName"`
	Actions           []string `json:"actions"`
	Description       *string  `json:"description"`
}

func containerRegistryScopeMapIDParts(resourceID string) (rgName, registryName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "registries", "scopemaps")
	if err != nil {
		return "", "", "", err
	}
	return rgName, names["registries"], names["scopemaps"], nil
}

func (s *ContainerRegistryScopeMap) buildPropertiesFromResult(scopeMap *armcontainerregistry.ScopeMap, rgName, registryName string) map[string]any {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	props["registryName"] = registryName

	if scopeMap.ID != nil {
		props["id"] = *scopeMap.ID
	}
	if scopeMap.Name != nil {
		props["name"] = *scopeMap.Name
	}

	if p := scopeMap.Properties; p != nil {
		if actions := stringsFromPointers(p.Actions); actions != nil {
			props["actions"] = actions
		}
		if p.Description != nil && *p.Description != "" {
			props["description"] = *p.Description
		}
		// creationDate, provisioningState and type — the last of which says whether
		// the registry built the map itself — are service state.
	}

	return props
}

func (s *ContainerRegistryScopeMap) parseProps(payload json.RawMessage, label string) (containerRegistryScopeMapProps, string, error) {
	var props containerRegistryScopeMapProps
	if err := json.Unmarshal(payload, &props); err != nil {
		return props, "", fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return props, "", fmt.Errorf("resourceGroupName is required")
	}
	if props.RegistryName == "" {
		return props, "", fmt.Errorf("registryName is required")
	}
	if len(props.Actions) == 0 {
		return props, "", fmt.Errorf("actions is required")
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

func (s *ContainerRegistryScopeMap) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	props, name, err := s.parseProps(request.Properties, request.Label)
	if err != nil {
		return nil, err
	}

	params := armcontainerregistry.ScopeMap{
		Properties: &armcontainerregistry.ScopeMapProperties{
			Actions:     stringPointers(props.Actions),
			Description: props.Description,
		},
	}

	poller, err := s.api.BeginCreate(ctx, props.ResourceGroupName, props.RegistryName, name, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.ContainerRegistry/registries/%s/scopeMaps/%s",
		s.config.SubscriptionId, props.ResourceGroupName, props.RegistryName, name)

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
		nativeID, propsJSON, err := s.completeFromScopeMap(&result.ScopeMap)
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

func (s *ContainerRegistryScopeMap) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, registryName, name, err := containerRegistryScopeMapIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := s.api.Get(ctx, rgName, registryName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(s.buildPropertiesFromResult(&result.ScopeMap, rgName, registryName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeContainerRegistryScopeMap,
		Properties:   string(propsJSON),
	}, nil
}

// Update patches through BeginUpdate. Only actions and description are mutable, and
// the patch body has no place for anything else — so unlike most resources here this
// is a real PATCH rather than a re-PUT.
func (s *ContainerRegistryScopeMap) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, registryName, name, err := containerRegistryScopeMapIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	props, _, err := s.parseProps(request.DesiredProperties, name)
	if err != nil {
		return nil, err
	}

	params := armcontainerregistry.ScopeMapUpdateParameters{
		Properties: &armcontainerregistry.ScopeMapPropertiesUpdateParameters{
			Actions:     stringPointers(props.Actions),
			Description: props.Description,
		},
	}

	poller, err := s.api.BeginUpdate(ctx, rgName, registryName, name, params, nil)
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
		propsJSON, err := json.Marshal(s.buildPropertiesFromResult(&result.ScopeMap, rgName, registryName))
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

func (s *ContainerRegistryScopeMap) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, registryName, name, err := containerRegistryScopeMapIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, err := s.api.BeginDelete(ctx, rgName, registryName, name, nil)
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

func (s *ContainerRegistryScopeMap) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	reqID, err := decodeLROStatus(request.RequestID)
	if err != nil {
		return nil, err
	}

	switch reqID.OperationType {
	case lroOpCreate:
		return statusLRO(ctx, request, &reqID, resource.OperationCreate,
			func(token string) (*runtime.Poller[armcontainerregistry.ScopeMapsClientCreateResponse], error) {
				return resumePoller[armcontainerregistry.ScopeMapsClientCreateResponse](s.pipeline, token)
			},
			func(_ context.Context, result armcontainerregistry.ScopeMapsClientCreateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				return s.completeFromScopeMap(&result.ScopeMap)
			})
	case lroOpUpdate:
		// A separate case from create: this API has its own update verb, so the
		// token was issued by a poller with the Update response type. Resuming it as
		// a Create response would kill the plugin operator mid-apply.
		return statusLRO(ctx, request, &reqID, resource.OperationUpdate,
			func(token string) (*runtime.Poller[armcontainerregistry.ScopeMapsClientUpdateResponse], error) {
				return resumePoller[armcontainerregistry.ScopeMapsClientUpdateResponse](s.pipeline, token)
			},
			func(_ context.Context, result armcontainerregistry.ScopeMapsClientUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				return s.completeFromScopeMap(&result.ScopeMap)
			})
	case lroOpDelete:
		return statusDeleteLRO(ctx, request, &reqID,
			func(token string) (*runtime.Poller[armcontainerregistry.ScopeMapsClientDeleteResponse], error) {
				return resumePoller[armcontainerregistry.ScopeMapsClientDeleteResponse](s.pipeline, token)
			}, nil)
	default:
		return nil, fmt.Errorf("unknown operation type: %s", reqID.OperationType)
	}
}

func (s *ContainerRegistryScopeMap) completeFromScopeMap(scopeMap *armcontainerregistry.ScopeMap) (string, json.RawMessage, error) {
	nativeID := ""
	rgName := ""
	registryName := ""
	if scopeMap.ID != nil {
		nativeID = *scopeMap.ID
		if rg, registry, _, err := containerRegistryScopeMapIDParts(*scopeMap.ID); err == nil {
			rgName = rg
			registryName = registry
		}
	}
	propsJSON, err := json.Marshal(s.buildPropertiesFromResult(scopeMap, rgName, registryName))
	if err != nil {
		return "", nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return nativeID, propsJSON, nil
}

// List requires both the resource group and the registry: scope maps only exist
// inside one.
func (s *ContainerRegistryScopeMap) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	registryName := request.AdditionalProperties["registryName"]
	if rgName == "" || registryName == "" {
		return &resource.ListResult{}, nil
	}

	var nativeIDs []string
	pager := s.api.NewListPager(rgName, registryName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list scope maps: %w", err)
		}
		for _, scopeMap := range page.Value {
			if scopeMap != nil && scopeMap.ID != nil {
				nativeIDs = append(nativeIDs, *scopeMap.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
