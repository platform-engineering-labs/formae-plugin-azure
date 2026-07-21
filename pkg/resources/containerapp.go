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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appcontainers/armappcontainers"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeContainerApp = "AZURE::App::ContainerApp"

type containerAppsAPI interface {
	BeginCreateOrUpdate(ctx context.Context, resourceGroupName string, containerAppName string, containerAppEnvelope armappcontainers.ContainerApp, options *armappcontainers.ContainerAppsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armappcontainers.ContainerAppsClientCreateOrUpdateResponse], error)
	Get(ctx context.Context, resourceGroupName string, containerAppName string, options *armappcontainers.ContainerAppsClientGetOptions) (armappcontainers.ContainerAppsClientGetResponse, error)
	BeginDelete(ctx context.Context, resourceGroupName string, containerAppName string, options *armappcontainers.ContainerAppsClientBeginDeleteOptions) (*runtime.Poller[armappcontainers.ContainerAppsClientDeleteResponse], error)
	NewListByResourceGroupPager(resourceGroupName string, options *armappcontainers.ContainerAppsClientListByResourceGroupOptions) *runtime.Pager[armappcontainers.ContainerAppsClientListByResourceGroupResponse]
	NewListBySubscriptionPager(options *armappcontainers.ContainerAppsClientListBySubscriptionOptions) *runtime.Pager[armappcontainers.ContainerAppsClientListBySubscriptionResponse]
}

func init() {
	registry.Register(ResourceTypeContainerApp, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &ContainerApp{
			api:      c.ContainerAppsClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// ContainerApp is the provisioner for Azure Container Apps
// (Microsoft.App/containerApps). LRO create/update/delete via ContainerAppsClient.
//
// The default conformance fixture (testdata/container-app.pkl) runs a public
// image with a plain env var and NO secrets, because container secret `value`
// is write-only — Azure never returns it, so serializing it back would produce
// false drift in the conformance harness (which cannot strip a write-only field
// nested inside an array). The secret path is covered by the marshaller
// round-trip unit test and a documented manual live gate.
type ContainerApp struct {
	api      containerAppsAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

func containerAppIDParts(resourceID string) (rgName, appName string, err error) {
	rgName, names, err := armIDParts(resourceID, "containerApps")
	if err != nil {
		return "", "", err
	}
	return rgName, names["containerApps"], nil
}

// buildContainerAppParams converts the formae property map into an
// armappcontainers.ContainerApp for BeginCreateOrUpdate. Shared by Create and
// Update so the body shape stays identical across operations.
func (app *ContainerApp) buildContainerAppParams(props map[string]any, location string) (armappcontainers.ContainerApp, error) {
	params := armappcontainers.ContainerApp{
		Location:   stringPtr(location),
		Properties: &armappcontainers.ContainerAppProperties{},
	}

	if envID, ok := resolvableString(props["managedEnvironmentId"]); ok {
		params.Properties.ManagedEnvironmentID = stringPtr(envID)
	} else {
		return params, fmt.Errorf("managedEnvironmentId is required")
	}

	if cfgRaw, ok := props["configuration"].(map[string]any); ok {
		cfg, err := buildContainerAppConfiguration(cfgRaw)
		if err != nil {
			return params, err
		}
		params.Properties.Configuration = cfg
	}

	if tmplRaw, ok := props["template"].(map[string]any); ok {
		tmpl, err := buildContainerAppTemplate(tmplRaw)
		if err != nil {
			return params, err
		}
		params.Properties.Template = tmpl
	}

	return params, nil
}

func buildContainerAppConfiguration(cfgRaw map[string]any) (*armappcontainers.Configuration, error) {
	cfg := &armappcontainers.Configuration{}

	if ingRaw, ok := cfgRaw["ingress"].(map[string]any); ok {
		ing := &armappcontainers.Ingress{}
		if external, ok := ingRaw["external"].(bool); ok {
			ing.External = to.Ptr(external)
		}
		if targetPort, ok := ingRaw["targetPort"].(float64); ok {
			ing.TargetPort = int32Ptr(int32(targetPort))
		}
		if transport, ok := ingRaw["transport"].(string); ok && transport != "" {
			ing.Transport = to.Ptr(armappcontainers.IngressTransportMethod(transport))
		}
		if allowInsecure, ok := ingRaw["allowInsecure"].(bool); ok {
			ing.AllowInsecure = to.Ptr(allowInsecure)
		}
		cfg.Ingress = ing
	}

	if secretsRaw, ok := cfgRaw["secrets"].([]any); ok {
		secrets := make([]*armappcontainers.Secret, 0, len(secretsRaw))
		for i, raw := range secretsRaw {
			m, ok := raw.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("configuration.secrets[%d] must be an object", i)
			}
			name, _ := m["name"].(string)
			if name == "" {
				return nil, fmt.Errorf("configuration.secrets[%d] requires name", i)
			}
			s := &armappcontainers.Secret{Name: stringPtr(name)}
			// value is write-only. Accept a plain string or an opaque wrapper;
			// never serialize it back (Azure never returns it).
			if value, ok := opaqueString(m["value"]); ok {
				s.Value = stringPtr(value)
			}
			secrets = append(secrets, s)
		}
		cfg.Secrets = secrets
	}

	return cfg, nil
}

func buildContainerAppTemplate(tmplRaw map[string]any) (*armappcontainers.Template, error) {
	tmpl := &armappcontainers.Template{}

	containersRaw, ok := tmplRaw["containers"].([]any)
	if !ok || len(containersRaw) == 0 {
		return nil, fmt.Errorf("template.containers requires at least one container")
	}
	containers := make([]*armappcontainers.Container, 0, len(containersRaw))
	for i, raw := range containersRaw {
		m, ok := raw.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("template.containers[%d] must be an object", i)
		}
		name, _ := m["name"].(string)
		image, _ := m["image"].(string)
		if name == "" || image == "" {
			return nil, fmt.Errorf("template.containers[%d] requires name and image", i)
		}
		c := &armappcontainers.Container{
			Name:  stringPtr(name),
			Image: stringPtr(image),
		}
		if resRaw, ok := m["resources"].(map[string]any); ok {
			res := &armappcontainers.ContainerResources{}
			if cpu, ok := resRaw["cpu"].(float64); ok {
				res.CPU = to.Ptr(cpu)
			}
			if memory, ok := resRaw["memory"].(string); ok && memory != "" {
				res.Memory = stringPtr(memory)
			}
			c.Resources = res
		}
		if envRaw, ok := m["env"].([]any); ok {
			envs := make([]*armappcontainers.EnvironmentVar, 0, len(envRaw))
			for j, eRaw := range envRaw {
				em, ok := eRaw.(map[string]any)
				if !ok {
					return nil, fmt.Errorf("template.containers[%d].env[%d] must be an object", i, j)
				}
				eName, _ := em["name"].(string)
				if eName == "" {
					return nil, fmt.Errorf("template.containers[%d].env[%d] requires name", i, j)
				}
				ev := &armappcontainers.EnvironmentVar{Name: stringPtr(eName)}
				if value, ok := em["value"].(string); ok && value != "" {
					ev.Value = stringPtr(value)
				}
				if secretRef, ok := em["secretRef"].(string); ok && secretRef != "" {
					ev.SecretRef = stringPtr(secretRef)
				}
				envs = append(envs, ev)
			}
			c.Env = envs
		}
		containers = append(containers, c)
	}
	tmpl.Containers = containers

	if scaleRaw, ok := tmplRaw["scale"].(map[string]any); ok {
		scale := &armappcontainers.Scale{}
		if minReplicas, ok := scaleRaw["minReplicas"].(float64); ok {
			scale.MinReplicas = int32Ptr(int32(minReplicas))
		}
		if maxReplicas, ok := scaleRaw["maxReplicas"].(float64); ok {
			scale.MaxReplicas = int32Ptr(int32(maxReplicas))
		}
		tmpl.Scale = scale
	}

	return tmpl, nil
}

// serializeContainerAppProperties converts an Azure ContainerApp to Formae
// property format. Secret values are write-only and never returned by Azure, so
// only the secret name surfaces. The ingress FQDN is surfaced as a top-level
// read-only `fqdn` output for the resolvable.
func serializeContainerAppProperties(result armappcontainers.ContainerApp, rgName, appName string) (json.RawMessage, error) {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	if result.Name != nil {
		props["name"] = *result.Name
	} else {
		props["name"] = appName
	}
	if result.Location != nil {
		props["location"] = *result.Location
	}
	if result.ID != nil {
		props["id"] = *result.ID
	}

	if p := result.Properties; p != nil {
		if p.ManagedEnvironmentID != nil {
			props["managedEnvironmentId"] = *p.ManagedEnvironmentID
		}

		if cfg := p.Configuration; cfg != nil {
			cfgMap := make(map[string]any)
			if ing := cfg.Ingress; ing != nil {
				ingMap := make(map[string]any)
				if ing.External != nil {
					ingMap["external"] = *ing.External
				}
				if ing.TargetPort != nil {
					ingMap["targetPort"] = *ing.TargetPort
				}
				if ing.Transport != nil {
					ingMap["transport"] = string(*ing.Transport)
				}
				if ing.AllowInsecure != nil {
					ingMap["allowInsecure"] = *ing.AllowInsecure
				}
				if len(ingMap) > 0 {
					cfgMap["ingress"] = ingMap
				}
				// Surface the read-only ingress FQDN as a top-level output.
				if ing.Fqdn != nil {
					props["fqdn"] = *ing.Fqdn
				}
			}
			if len(cfg.Secrets) > 0 {
				secrets := make([]map[string]any, 0, len(cfg.Secrets))
				for _, s := range cfg.Secrets {
					if s == nil {
						continue
					}
					m := make(map[string]any)
					if s.Name != nil {
						m["name"] = *s.Name
					}
					// value is write-only and never read back — do not serialize.
					secrets = append(secrets, m)
				}
				cfgMap["secrets"] = secrets
			}
			if len(cfgMap) > 0 {
				props["configuration"] = cfgMap
			}
		}

		if tmpl := p.Template; tmpl != nil {
			tmplMap := make(map[string]any)
			if len(tmpl.Containers) > 0 {
				containers := make([]map[string]any, 0, len(tmpl.Containers))
				for _, c := range tmpl.Containers {
					if c == nil {
						continue
					}
					m := make(map[string]any)
					if c.Name != nil {
						m["name"] = *c.Name
					}
					if c.Image != nil {
						m["image"] = *c.Image
					}
					if c.Resources != nil {
						res := make(map[string]any)
						if c.Resources.CPU != nil {
							res["cpu"] = *c.Resources.CPU
						}
						if c.Resources.Memory != nil {
							res["memory"] = *c.Resources.Memory
						}
						if len(res) > 0 {
							m["resources"] = res
						}
					}
					if len(c.Env) > 0 {
						envs := make([]map[string]any, 0, len(c.Env))
						for _, e := range c.Env {
							if e == nil {
								continue
							}
							em := make(map[string]any)
							if e.Name != nil {
								em["name"] = *e.Name
							}
							if e.Value != nil {
								em["value"] = *e.Value
							}
							if e.SecretRef != nil {
								em["secretRef"] = *e.SecretRef
							}
							envs = append(envs, em)
						}
						m["env"] = envs
					}
					containers = append(containers, m)
				}
				tmplMap["containers"] = containers
			}
			if scale := tmpl.Scale; scale != nil {
				scaleMap := make(map[string]any)
				if scale.MinReplicas != nil {
					scaleMap["minReplicas"] = *scale.MinReplicas
				}
				if scale.MaxReplicas != nil {
					scaleMap["maxReplicas"] = *scale.MaxReplicas
				}
				if len(scaleMap) > 0 {
					tmplMap["scale"] = scaleMap
				}
			}
			if len(tmplMap) > 0 {
				props["template"] = tmplMap
			}
		}
	}

	if tags := azureTagsToFormaeTags(result.Tags); tags != nil {
		props["Tags"] = tags
	}

	return json.Marshal(props)
}

func (app *ContainerApp) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props map[string]any
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	rgName, ok := props["resourceGroupName"].(string)
	if !ok || rgName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	location, ok := props["location"].(string)
	if !ok || location == "" {
		return nil, fmt.Errorf("location is required")
	}
	appName, ok := props["name"].(string)
	if !ok || appName == "" {
		appName = request.Label
	}

	params, err := app.buildContainerAppParams(props, location)
	if err != nil {
		return nil, err
	}
	if azureTags := formaeTagsToAzureTags(request.Properties); azureTags != nil {
		params.Tags = azureTags
	}

	poller, err := app.api.BeginCreateOrUpdate(ctx, rgName, appName, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.App/containerApps/%s",
		app.config.SubscriptionId, rgName, appName)

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
		propsJSON, err := serializeContainerAppProperties(result.ContainerApp, rgName, appName)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize ContainerApp properties: %w", err)
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

func (app *ContainerApp) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, appName, err := containerAppIDParts(request.NativeID)
	if err != nil {
		return nil, fmt.Errorf("invalid NativeID: cannot extract resourceGroup or containerApp name from %s: %w", request.NativeID, err)
	}

	result, err := app.api.Get(ctx, rgName, appName, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}
	propsJSON, err := serializeContainerAppProperties(result.ContainerApp, rgName, appName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize ContainerApp properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeContainerApp,
		Properties:   string(propsJSON),
	}, nil
}

func (app *ContainerApp) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, appName, err := containerAppIDParts(request.NativeID)
	if err != nil {
		return nil, fmt.Errorf("invalid NativeID: cannot extract resourceGroup or containerApp name from %s: %w", request.NativeID, err)
	}

	var props map[string]any
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	location, ok := props["location"].(string)
	if !ok || location == "" {
		return nil, fmt.Errorf("location is required")
	}

	params, err := app.buildContainerAppParams(props, location)
	if err != nil {
		return nil, err
	}
	if azureTags := formaeTagsToAzureTags(request.DesiredProperties); azureTags != nil {
		params.Tags = azureTags
	}

	poller, err := app.api.BeginCreateOrUpdate(ctx, rgName, appName, params, nil)
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
		propsJSON, err := serializeContainerAppProperties(result.ContainerApp, rgName, appName)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize ContainerApp properties: %w", err)
		}
		return &resource.UpdateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:          resource.OperationUpdate,
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

func (app *ContainerApp) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, appName, err := containerAppIDParts(request.NativeID)
	if err != nil {
		return nil, fmt.Errorf("invalid NativeID: cannot extract resourceGroup or containerApp name from %s: %w", request.NativeID, err)
	}

	poller, err := app.api.BeginDelete(ctx, rgName, appName, nil)
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
		}, fmt.Errorf("failed to start ContainerApp deletion: %w", err)
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

func (app *ContainerApp) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
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
		return app.statusCreateOrUpdate(ctx, request, &reqID)
	case lroOpDelete:
		return app.statusDelete(ctx, request, &reqID)
	default:
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
			},
		}, fmt.Errorf("unknown operation type: %s", reqID.OperationType)
	}
}

func (app *ContainerApp) statusCreateOrUpdate(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	operation := resource.OperationCreate
	if reqID.OperationType == lroOpUpdate {
		operation = resource.OperationUpdate
	}

	return statusLRO(ctx, request, reqID, operation,
		func(token string) (*runtime.Poller[armappcontainers.ContainerAppsClientCreateOrUpdateResponse], error) {
			return resumePoller[armappcontainers.ContainerAppsClientCreateOrUpdateResponse](app.pipeline, token)
		},
		func(_ context.Context, result armappcontainers.ContainerAppsClientCreateOrUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
			rgName, appName, err := containerAppIDParts(*result.ID)
			if err != nil {
				return "", nil, err
			}
			propsJSON, err := serializeContainerAppProperties(result.ContainerApp, rgName, appName)
			if err != nil {
				return "", nil, fmt.Errorf("failed to serialize ContainerApp properties: %w", err)
			}
			return *result.ID, propsJSON, nil
		})
}

func (app *ContainerApp) statusDelete(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	return statusDeleteLRO(ctx, request, reqID,
		func(token string) (*runtime.Poller[armappcontainers.ContainerAppsClientDeleteResponse], error) {
			return resumePoller[armappcontainers.ContainerAppsClientDeleteResponse](app.pipeline, token)
		}, nil)
}

func (app *ContainerApp) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	resourceGroupName := request.AdditionalProperties["resourceGroupName"]

	var nativeIDs []string
	if resourceGroupName != "" {
		pager := app.api.NewListByResourceGroupPager(resourceGroupName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list container apps: %w", err)
			}
			for _, x := range page.Value {
				if x != nil && x.ID != nil {
					nativeIDs = append(nativeIDs, *x.ID)
				}
			}
		}
	} else {
		pager := app.api.NewListBySubscriptionPager(nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list container apps: %w", err)
			}
			for _, x := range page.Value {
				if x != nil && x.ID != nil {
					nativeIDs = append(nativeIDs, *x.ID)
				}
			}
		}
	}

	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
