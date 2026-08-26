// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerinstance/armcontainerinstance/v2"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeContainerGroup = "AZURE::ContainerInstance::ContainerGroup"

// containerGroupsAPI is the armcontainerinstance surface used here. Create and
// Delete are LROs; Update is a synchronous tags-only PATCH.
type containerGroupsAPI interface {
	BeginCreateOrUpdate(ctx context.Context, resourceGroupName string, containerGroupName string, containerGroup armcontainerinstance.ContainerGroup, options *armcontainerinstance.ContainerGroupsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armcontainerinstance.ContainerGroupsClientCreateOrUpdateResponse], error)
	Get(ctx context.Context, resourceGroupName string, containerGroupName string, options *armcontainerinstance.ContainerGroupsClientGetOptions) (armcontainerinstance.ContainerGroupsClientGetResponse, error)
	Update(ctx context.Context, resourceGroupName string, containerGroupName string, resource armcontainerinstance.Resource, options *armcontainerinstance.ContainerGroupsClientUpdateOptions) (armcontainerinstance.ContainerGroupsClientUpdateResponse, error)
	BeginDelete(ctx context.Context, resourceGroupName string, containerGroupName string, options *armcontainerinstance.ContainerGroupsClientBeginDeleteOptions) (*runtime.Poller[armcontainerinstance.ContainerGroupsClientDeleteResponse], error)
	NewListPager(options *armcontainerinstance.ContainerGroupsClientListOptions) *runtime.Pager[armcontainerinstance.ContainerGroupsClientListResponse]
	NewListByResourceGroupPager(resourceGroupName string, options *armcontainerinstance.ContainerGroupsClientListByResourceGroupOptions) *runtime.Pager[armcontainerinstance.ContainerGroupsClientListByResourceGroupResponse]
}

func init() {
	registry.Register(ResourceTypeContainerGroup, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &ContainerGroup{
			api:      c.ContainerGroupsClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// ContainerGroup is the provisioner for Azure Container Instances container
// groups (Microsoft.ContainerInstance/containerGroups).
type ContainerGroup struct {
	api      containerGroupsAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

// containerGroupProps mirrors schema/pkl/containerinstance/containergroup.pkl.
type containerGroupProps struct {
	Name              string              `json:"name"`
	Location          string              `json:"location"`
	ResourceGroupName string              `json:"resourceGroupName"`
	OSType            string              `json:"osType"`
	RestartPolicy     string              `json:"restartPolicy"`
	Containers        []containerSpec     `json:"containers"`
	IPAddress         *containerIPAddress `json:"ipAddress"`
}

type containerSpec struct {
	Name                 string                `json:"name"`
	Image                string                `json:"image"`
	Resources            containerResources    `json:"resources"`
	Ports                []containerPortSpec   `json:"ports"`
	Command              []string              `json:"command"`
	EnvironmentVariables []containerEnvVarSpec `json:"environmentVariables"`
}

type containerResources struct {
	CPU        float64 `json:"cpu"`
	MemoryInGB float64 `json:"memoryInGB"`
}

type containerPortSpec struct {
	Port     int32  `json:"port"`
	Protocol string `json:"protocol"`
}

type containerEnvVarSpec struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type containerIPAddress struct {
	Type         string              `json:"type"`
	Ports        []containerPortSpec `json:"ports"`
	DNSNameLabel string              `json:"dnsNameLabel"`
}

func containerGroupIDParts(resourceID string) (rgName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "containergroups")
	if err != nil {
		return "", "", err
	}
	return rgName, names["containergroups"], nil
}

func (c *ContainerGroup) buildPropertiesFromResult(cg *armcontainerinstance.ContainerGroup, rgName string) map[string]any {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName

	if cg.ID != nil {
		props["id"] = *cg.ID
	}
	if cg.Name != nil {
		props["name"] = *cg.Name
	}
	if cg.Location != nil {
		props["location"] = strings.ToLower(strings.ReplaceAll(*cg.Location, " ", ""))
	}

	if p := cg.Properties; p != nil {
		if p.OSType != nil {
			props["osType"] = string(*p.OSType)
		}
		if p.RestartPolicy != nil {
			props["restartPolicy"] = string(*p.RestartPolicy)
		}

		containers := make([]map[string]any, 0, len(p.Containers))
		for _, ctr := range p.Containers {
			if ctr == nil {
				continue
			}
			entry := map[string]any{}
			if ctr.Name != nil {
				entry["name"] = *ctr.Name
			}
			if cp := ctr.Properties; cp != nil {
				if cp.Image != nil {
					entry["image"] = *cp.Image
				}
				if cp.Resources != nil && cp.Resources.Requests != nil {
					res := map[string]any{}
					if cp.Resources.Requests.CPU != nil {
						res["cpu"] = *cp.Resources.Requests.CPU
					}
					if cp.Resources.Requests.MemoryInGB != nil {
						res["memoryInGB"] = *cp.Resources.Requests.MemoryInGB
					}
					entry["resources"] = res
				}
				ports := make([]map[string]any, 0, len(cp.Ports))
				for _, port := range cp.Ports {
					if port == nil || port.Port == nil {
						continue
					}
					p := map[string]any{"port": *port.Port}
					if port.Protocol != nil {
						p["protocol"] = string(*port.Protocol)
					}
					ports = append(ports, p)
				}
				if len(ports) > 0 {
					entry["ports"] = ports
				}
				cmd := make([]string, 0, len(cp.Command))
				for _, arg := range cp.Command {
					if arg != nil {
						cmd = append(cmd, *arg)
					}
				}
				if len(cmd) > 0 {
					entry["command"] = cmd
				}
				envs := make([]map[string]any, 0, len(cp.EnvironmentVariables))
				for _, env := range cp.EnvironmentVariables {
					// secureValue env vars are never returned by ARM, so an entry
					// without a plain value is not round-trippable desired state.
					if env == nil || env.Name == nil || env.Value == nil {
						continue
					}
					envs = append(envs, map[string]any{"name": *env.Name, "value": *env.Value})
				}
				if len(envs) > 0 {
					entry["environmentVariables"] = envs
				}
			}
			containers = append(containers, entry)
		}
		if len(containers) > 0 {
			props["containers"] = containers
		}

		if ip := p.IPAddress; ip != nil {
			addr := map[string]any{}
			if ip.Type != nil {
				addr["type"] = string(*ip.Type)
			}
			if ip.DNSNameLabel != nil {
				addr["dnsNameLabel"] = *ip.DNSNameLabel
			}
			ports := make([]map[string]any, 0, len(ip.Ports))
			for _, port := range ip.Ports {
				if port == nil || port.Port == nil {
					continue
				}
				entry := map[string]any{"port": *port.Port}
				if port.Protocol != nil {
					entry["protocol"] = string(*port.Protocol)
				}
				ports = append(ports, entry)
			}
			if len(ports) > 0 {
				addr["ports"] = ports
			}
			props["ipAddress"] = addr
			if ip.Fqdn != nil {
				props["fqdn"] = *ip.Fqdn
			}
		}
	}

	if tags := azureTagsToFormaeTags(cg.Tags); tags != nil {
		props["Tags"] = tags
	}

	return props
}

func containerGroupParams(props containerGroupProps) armcontainerinstance.ContainerGroup {
	containers := make([]*armcontainerinstance.Container, 0, len(props.Containers))
	for _, spec := range props.Containers {
		ctrProps := &armcontainerinstance.ContainerProperties{
			Image: to.Ptr(spec.Image),
			Resources: &armcontainerinstance.ResourceRequirements{
				Requests: &armcontainerinstance.ResourceRequests{
					CPU:        to.Ptr(spec.Resources.CPU),
					MemoryInGB: to.Ptr(spec.Resources.MemoryInGB),
				},
			},
		}
		for _, port := range spec.Ports {
			protocol := port.Protocol
			if protocol == "" {
				protocol = "TCP"
			}
			ctrProps.Ports = append(ctrProps.Ports, &armcontainerinstance.ContainerPort{
				Port:     to.Ptr(port.Port),
				Protocol: to.Ptr(armcontainerinstance.ContainerNetworkProtocol(protocol)),
			})
		}
		for _, arg := range spec.Command {
			ctrProps.Command = append(ctrProps.Command, to.Ptr(arg))
		}
		for _, env := range spec.EnvironmentVariables {
			ctrProps.EnvironmentVariables = append(ctrProps.EnvironmentVariables, &armcontainerinstance.EnvironmentVariable{
				Name:  to.Ptr(env.Name),
				Value: to.Ptr(env.Value),
			})
		}
		containers = append(containers, &armcontainerinstance.Container{
			Name:       to.Ptr(spec.Name),
			Properties: ctrProps,
		})
	}

	groupProps := &armcontainerinstance.ContainerGroupPropertiesProperties{
		Containers: containers,
		OSType:     to.Ptr(armcontainerinstance.OperatingSystemTypes(props.OSType)),
	}
	if props.RestartPolicy != "" {
		groupProps.RestartPolicy = to.Ptr(armcontainerinstance.ContainerGroupRestartPolicy(props.RestartPolicy))
	}
	if props.IPAddress != nil {
		addrType := props.IPAddress.Type
		if addrType == "" {
			addrType = "Public"
		}
		addr := &armcontainerinstance.IPAddress{
			Type: to.Ptr(armcontainerinstance.ContainerGroupIPAddressType(addrType)),
		}
		if props.IPAddress.DNSNameLabel != "" {
			addr.DNSNameLabel = to.Ptr(props.IPAddress.DNSNameLabel)
		}
		for _, port := range props.IPAddress.Ports {
			protocol := port.Protocol
			if protocol == "" {
				protocol = "TCP"
			}
			addr.Ports = append(addr.Ports, &armcontainerinstance.Port{
				Port:     to.Ptr(port.Port),
				Protocol: to.Ptr(armcontainerinstance.ContainerGroupNetworkProtocol(protocol)),
			})
		}
		groupProps.IPAddress = addr
	}

	return armcontainerinstance.ContainerGroup{
		Location:   to.Ptr(props.Location),
		Properties: groupProps,
	}
}

func (c *ContainerGroup) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props containerGroupProps
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	if props.Location == "" {
		return nil, fmt.Errorf("location is required")
	}
	if props.OSType == "" {
		return nil, fmt.Errorf("osType is required")
	}
	if len(props.Containers) == 0 {
		return nil, fmt.Errorf("at least one container is required")
	}
	name := props.Name
	if name == "" {
		name = request.Label
	}
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}

	params := containerGroupParams(props)
	if azureTags := formaeTagsToAzureTags(request.Properties); azureTags != nil {
		params.Tags = azureTags
	}

	poller, err := c.api.BeginCreateOrUpdate(ctx, props.ResourceGroupName, name, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.ContainerInstance/containerGroups/%s",
		c.config.SubscriptionId, props.ResourceGroupName, name)

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
		_, propsJSON, err := c.completeFromContainerGroup(ctx, &result.ContainerGroup)
		if err != nil {
			return nil, err
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

func (c *ContainerGroup) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, name, err := containerGroupIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := c.api.Get(ctx, rgName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(c.buildPropertiesFromResult(&result.ContainerGroup, rgName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeContainerGroup,
		Properties:   string(propsJSON),
	}, nil
}

// Update re-runs CreateOrUpdate. Only tags are truly mutable — every other field
// is createOnly in the schema, so core replaces the group for anything else.
// Update patches tags only — and must use ARM's PATCH, not CreateOrUpdate.
//
// ACI's PUT (CreateOrUpdate) silently DROPS the tags property: sending a full body
// with tags returns success and leaves the group untagged, which failed conformance
// [Update] with "Property Tags should exist in actual resource (after update)".
// The tags-only PATCH is the only operation ACI honours in place, which is also
// why `az container create` has no --tags flag. Every other field is createOnly in
// the schema, so core replaces the group for anything else.
func (c *ContainerGroup) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, name, err := containerGroupIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	patch := armcontainerinstance.Resource{}
	if azureTags := formaeTagsToAzureTags(request.DesiredProperties); azureTags != nil {
		patch.Tags = azureTags
	}

	if _, err := c.api.Update(ctx, rgName, name, patch, nil); err != nil {
		return &resource.UpdateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationUpdate,
				OperationStatus: resource.OperationStatusFailure,
				NativeID:        request.NativeID,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	// The PATCH response body is partial, so report the state from a fresh read.
	result, err := c.api.Get(ctx, rgName, name, nil)
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
	propsJSON, err := json.Marshal(c.buildPropertiesFromResult(&result.ContainerGroup, rgName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties after update: %w", err)
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

func (c *ContainerGroup) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, name, err := containerGroupIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, err := c.api.BeginDelete(ctx, rgName, name, nil)
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

func (c *ContainerGroup) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	reqID, err := decodeLROStatus(request.RequestID)
	if err != nil {
		return nil, err
	}

	switch reqID.OperationType {
	case lroOpCreate:
		return statusLRO(ctx, request, &reqID, resource.OperationCreate,
			func(token string) (*runtime.Poller[armcontainerinstance.ContainerGroupsClientCreateOrUpdateResponse], error) {
				return resumePoller[armcontainerinstance.ContainerGroupsClientCreateOrUpdateResponse](c.pipeline, token)
			},
			func(ctx context.Context, result armcontainerinstance.ContainerGroupsClientCreateOrUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				return c.completeFromContainerGroup(ctx, &result.ContainerGroup)
			})
	case lroOpDelete:
		return statusDeleteLRO(ctx, request, &reqID,
			func(token string) (*runtime.Poller[armcontainerinstance.ContainerGroupsClientDeleteResponse], error) {
				return resumePoller[armcontainerinstance.ContainerGroupsClientDeleteResponse](c.pipeline, token)
			}, nil)
	default:
		return nil, fmt.Errorf("unknown operation type: %s", reqID.OperationType)
	}
}

// completeFromContainerGroup reports the state of a finished create/update.
//
// It re-reads rather than trusting the poller's terminal body: ACI's LRO response
// omits tags, so serializing that body straight through reports a group with no
// tags right after a tag update. A fresh Get is the only view that matches ARM.
func (c *ContainerGroup) completeFromContainerGroup(ctx context.Context, cg *armcontainerinstance.ContainerGroup) (string, json.RawMessage, error) {
	nativeID := ""
	rgName, name := "", ""
	if cg.ID != nil {
		nativeID = *cg.ID
		if rg, n, err := containerGroupIDParts(*cg.ID); err == nil {
			rgName, name = rg, n
		}
	}
	body := cg
	if rgName != "" && name != "" {
		if fresh, err := c.api.Get(ctx, rgName, name, nil); err == nil {
			body = &fresh.ContainerGroup
			if body.ID != nil {
				nativeID = *body.ID
			}
		}
	}
	propsJSON, err := json.Marshal(c.buildPropertiesFromResult(body, rgName))
	if err != nil {
		return "", nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return nativeID, propsJSON, nil
}

func (c *ContainerGroup) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]

	var nativeIDs []string

	if rgName != "" {
		pager := c.api.NewListByResourceGroupPager(rgName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list container groups: %w", err)
			}
			for _, cg := range page.Value {
				if cg.ID != nil {
					nativeIDs = append(nativeIDs, *cg.ID)
				}
			}
		}
		return &resource.ListResult{NativeIDs: nativeIDs}, nil
	}

	pager := c.api.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list container groups: %w", err)
		}
		for _, cg := range page.Value {
			if cg.ID != nil {
				nativeIDs = append(nativeIDs, *cg.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
