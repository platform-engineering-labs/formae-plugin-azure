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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/eventhub/armeventhub"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeEventHubSchemaGroup = "AZURE::EventHub::SchemaGroup"

// eventHubSchemaGroupsAPI is the subset of *armeventhub.SchemaRegistryClient used
// here. Every operation is synchronous and CreateOrUpdate is also the update verb.
type eventHubSchemaGroupsAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName, namespaceName, schemaGroupName string, parameters armeventhub.SchemaGroup, options *armeventhub.SchemaRegistryClientCreateOrUpdateOptions) (armeventhub.SchemaRegistryClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName, namespaceName, schemaGroupName string, options *armeventhub.SchemaRegistryClientGetOptions) (armeventhub.SchemaRegistryClientGetResponse, error)
	Delete(ctx context.Context, resourceGroupName, namespaceName, schemaGroupName string, options *armeventhub.SchemaRegistryClientDeleteOptions) (armeventhub.SchemaRegistryClientDeleteResponse, error)
	NewListByNamespacePager(resourceGroupName, namespaceName string, options *armeventhub.SchemaRegistryClientListByNamespaceOptions) *runtime.Pager[armeventhub.SchemaRegistryClientListByNamespaceResponse]
}

func init() {
	registry.Register(ResourceTypeEventHubSchemaGroup, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &EventHubSchemaGroup{api: c.EventHubSchemaRegistryClient, config: cfg}
	})
}

// EventHubSchemaGroup is the provisioner for schema registry groups
// (Microsoft.EventHub/namespaces/schemagroups). It is a child of
// AZURE::EventHub::Namespace and requires a Standard or higher namespace.
type EventHubSchemaGroup struct {
	api    eventHubSchemaGroupsAPI
	config *config.Config
}

// eventHubSchemaGroupProps mirrors schema/pkl/eventhub/schemagroup.pkl.
type eventHubSchemaGroupProps struct {
	Name                string `json:"name"`
	ResourceGroupName   string `json:"resourceGroupName"`
	NamespaceName       string `json:"namespaceName"`
	SchemaType          string `json:"schemaType"`
	SchemaCompatibility string `json:"schemaCompatibility"`
}

func eventHubSchemaGroupIDParts(resourceID string) (rgName, namespaceName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "namespaces", "schemagroups")
	if err != nil {
		return "", "", "", err
	}
	return rgName, names["namespaces"], names["schemagroups"], nil
}

func (e *EventHubSchemaGroup) buildPropertiesFromResult(group *armeventhub.SchemaGroup, rgName, namespaceName string) map[string]any {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	props["namespaceName"] = namespaceName

	if group.ID != nil {
		props["id"] = *group.ID
	}
	if group.Name != nil {
		props["name"] = *group.Name
	}

	if p := group.Properties; p != nil {
		if p.SchemaType != nil {
			props["schemaType"] = canonicalizeEnum(string(*p.SchemaType), "Avro", "Unknown")
		}
		if p.SchemaCompatibility != nil {
			props["schemaCompatibility"] = canonicalizeEnum(string(*p.SchemaCompatibility), "Backward", "Forward", "None")
		}
		// groupProperties is a free-form string map the service echoes back and the
		// schema does not model; createdAtUtc, updatedAtUtc and eTag are service
		// state. The resource's own location is the namespace's and is not settable.
	}

	return props
}

func (e *EventHubSchemaGroup) parseProps(payload json.RawMessage, label string) (eventHubSchemaGroupProps, string, error) {
	var props eventHubSchemaGroupProps
	if err := json.Unmarshal(payload, &props); err != nil {
		return props, "", fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return props, "", fmt.Errorf("resourceGroupName is required")
	}
	if props.NamespaceName == "" {
		return props, "", fmt.Errorf("namespaceName is required")
	}
	if props.SchemaType == "" {
		return props, "", fmt.Errorf("schemaType is required")
	}
	if props.SchemaCompatibility == "" {
		return props, "", fmt.Errorf("schemaCompatibility is required")
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

func eventHubSchemaGroupParams(props eventHubSchemaGroupProps) armeventhub.SchemaGroup {
	return armeventhub.SchemaGroup{
		Properties: &armeventhub.SchemaGroupProperties{
			SchemaType:          to.Ptr(armeventhub.SchemaType(props.SchemaType)),
			SchemaCompatibility: to.Ptr(armeventhub.SchemaCompatibility(props.SchemaCompatibility)),
		},
	}
}

func (e *EventHubSchemaGroup) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	props, name, err := e.parseProps(request.Properties, request.Label)
	if err != nil {
		return nil, err
	}

	result, err := e.api.CreateOrUpdate(ctx, props.ResourceGroupName, props.NamespaceName, name,
		eventHubSchemaGroupParams(props), nil)
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
	propsJSON, err := json.Marshal(e.buildPropertiesFromResult(&result.SchemaGroup, props.ResourceGroupName, props.NamespaceName))
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

func (e *EventHubSchemaGroup) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, namespaceName, name, err := eventHubSchemaGroupIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := e.api.Get(ctx, rgName, namespaceName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(e.buildPropertiesFromResult(&result.SchemaGroup, rgName, namespaceName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeEventHubSchemaGroup,
		Properties:   string(propsJSON),
	}, nil
}

// Update reissues CreateOrUpdate, but nothing this schema models can actually change
// through it. The PUT accepts a new compatibility rule and then refuses it:
//
//	MessagingGatewayForbidden: SubCode=40301, Cannot change compatibility in a group.
//
// and schemaType is fixed at creation too, so every field is createOnly and core
// replaces the group instead of calling this. The path is kept for a future mutable
// field or a stored in-flight update token.
func (e *EventHubSchemaGroup) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, namespaceName, name, err := eventHubSchemaGroupIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	props, _, err := e.parseProps(request.DesiredProperties, name)
	if err != nil {
		return nil, err
	}

	result, err := e.api.CreateOrUpdate(ctx, rgName, namespaceName, name,
		eventHubSchemaGroupParams(props), nil)
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

	propsJSON, err := json.Marshal(e.buildPropertiesFromResult(&result.SchemaGroup, rgName, namespaceName))
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

func (e *EventHubSchemaGroup) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, namespaceName, name, err := eventHubSchemaGroupIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	if _, err := e.api.Delete(ctx, rgName, namespaceName, name, nil); err != nil && !isDeleteSuccessError(err) {
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

// Status can only ever be asked about an operation that already finished: every
// write here is synchronous.
func (e *EventHubSchemaGroup) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

// List requires both the resource group and the namespace: a schema group only
// exists inside one.
func (e *EventHubSchemaGroup) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	namespaceName := request.AdditionalProperties["namespaceName"]
	if rgName == "" || namespaceName == "" {
		return &resource.ListResult{}, nil
	}

	var nativeIDs []string
	pager := e.api.NewListByNamespacePager(rgName, namespaceName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list schema groups: %w", err)
		}
		for _, group := range page.Value {
			if group != nil && group.ID != nil {
				nativeIDs = append(nativeIDs, *group.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
