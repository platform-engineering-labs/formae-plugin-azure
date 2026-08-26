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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeRoleDefinition = "AZURE::Authorization::RoleDefinition"

// roleDefinitionsAPI is the subset of *armauthorization.RoleDefinitionsClient used
// here. Everything is synchronous, and CreateOrUpdate is also the update verb.
//
// Unlike role assignments, there is no DeleteByID: delete needs the scope and the
// GUID separately, so both are recovered from the native ID.
type roleDefinitionsAPI interface {
	CreateOrUpdate(ctx context.Context, scope, roleDefinitionID string, roleDefinition armauthorization.RoleDefinition, options *armauthorization.RoleDefinitionsClientCreateOrUpdateOptions) (armauthorization.RoleDefinitionsClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, scope, roleDefinitionID string, options *armauthorization.RoleDefinitionsClientGetOptions) (armauthorization.RoleDefinitionsClientGetResponse, error)
	Delete(ctx context.Context, scope, roleDefinitionID string, options *armauthorization.RoleDefinitionsClientDeleteOptions) (armauthorization.RoleDefinitionsClientDeleteResponse, error)
	NewListPager(scope string, options *armauthorization.RoleDefinitionsClientListOptions) *runtime.Pager[armauthorization.RoleDefinitionsClientListResponse]
}

func init() {
	registry.Register(ResourceTypeRoleDefinition, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &RoleDefinition{api: c.RoleDefinitionsClient, config: cfg}
	})
}

// RoleDefinition is the provisioner for custom RBAC roles
// (Microsoft.Authorization/roleDefinitions).
type RoleDefinition struct {
	api    roleDefinitionsAPI
	config *config.Config
}

// roleDefinitionProps mirrors schema/pkl/authorization/roledefinition.pkl.
type roleDefinitionProps struct {
	Name             string                      `json:"name"`
	Scope            string                      `json:"scope"`
	RoleName         string                      `json:"roleName"`
	Description      *string                     `json:"description"`
	AssignableScopes []string                    `json:"assignableScopes"`
	Permissions      []roleDefinitionPermissions `json:"permissions"`
}

type roleDefinitionPermissions struct {
	Actions        []string `json:"actions"`
	NotActions     []string `json:"notActions"`
	DataActions    []string `json:"dataActions"`
	NotDataActions []string `json:"notDataActions"`
}

// roleDefinitionSegment is the provider path that separates a role definition's
// scope from its GUID. A definition can hang off a subscription, a management group
// or a resource group, so armIDParts — which assumes a resource-group path — cannot
// be used here.
const roleDefinitionSegment = "/providers/microsoft.authorization/roledefinitions/"

func roleDefinitionIDParts(resourceID string) (scope, name string, err error) {
	idx := strings.Index(strings.ToLower(resourceID), roleDefinitionSegment)
	if idx < 0 {
		return "", "", fmt.Errorf("not a role definition resource ID: %s", resourceID)
	}
	scope = resourceID[:idx]
	name = resourceID[idx+len(roleDefinitionSegment):]
	if scope == "" || name == "" {
		return "", "", fmt.Errorf("not a role definition resource ID: %s", resourceID)
	}
	return scope, name, nil
}

func (r *RoleDefinition) buildPropertiesFromResult(definition *armauthorization.RoleDefinition, scope string) map[string]any {
	props := make(map[string]any)

	props["scope"] = scope

	if definition.ID != nil {
		props["id"] = *definition.ID
	}
	if definition.Name != nil {
		props["name"] = *definition.Name
	}

	if p := definition.Properties; p != nil {
		if p.RoleName != nil {
			props["roleName"] = *p.RoleName
		}
		if p.Description != nil && *p.Description != "" {
			props["description"] = *p.Description
		}
		if p.RoleType != nil {
			props["roleType"] = *p.RoleType
		}
		if scopes := stringsFromPointers(p.AssignableScopes); scopes != nil {
			props["assignableScopes"] = scopes
		}

		permissions := make([]map[string]any, 0, len(p.Permissions))
		for _, permission := range p.Permissions {
			if permission == nil {
				continue
			}
			entry := make(map[string]any)
			if actions := stringsFromPointers(permission.Actions); actions != nil {
				entry["actions"] = actions
			}
			// ARM echoes the three subtractive lists as empty arrays. Reporting them
			// as set would drift against a role that never declared them.
			if notActions := stringsFromPointers(permission.NotActions); notActions != nil {
				entry["notActions"] = notActions
			}
			if dataActions := stringsFromPointers(permission.DataActions); dataActions != nil {
				entry["dataActions"] = dataActions
			}
			if notDataActions := stringsFromPointers(permission.NotDataActions); notDataActions != nil {
				entry["notDataActions"] = notDataActions
			}
			permissions = append(permissions, entry)
		}
		if len(permissions) > 0 {
			props["permissions"] = permissions
		}
	}

	return props
}

// roleDefinitionParams builds the request body shared by create and update.
func roleDefinitionParams(props roleDefinitionProps) armauthorization.RoleDefinition {
	permissions := make([]*armauthorization.Permission, 0, len(props.Permissions))
	for _, permission := range props.Permissions {
		permissions = append(permissions, &armauthorization.Permission{
			Actions:        stringPointers(permission.Actions),
			NotActions:     stringPointers(permission.NotActions),
			DataActions:    stringPointers(permission.DataActions),
			NotDataActions: stringPointers(permission.NotDataActions),
		})
	}

	return armauthorization.RoleDefinition{
		Properties: &armauthorization.RoleDefinitionProperties{
			RoleName:         to.Ptr(props.RoleName),
			Description:      props.Description,
			AssignableScopes: stringPointers(props.AssignableScopes),
			Permissions:      permissions,
			// ARM only accepts CustomRole here: built-in roles are read-only, so a
			// definition this provider writes is always custom.
			RoleType: to.Ptr("CustomRole"),
		},
	}
}

func (r *RoleDefinition) parseProps(payload json.RawMessage, label string) (roleDefinitionProps, string, error) {
	var props roleDefinitionProps
	if err := json.Unmarshal(payload, &props); err != nil {
		return props, "", fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.Scope == "" {
		return props, "", fmt.Errorf("scope is required")
	}
	if props.RoleName == "" {
		return props, "", fmt.Errorf("roleName is required")
	}
	if len(props.AssignableScopes) == 0 {
		return props, "", fmt.Errorf("assignableScopes is required")
	}
	if len(props.Permissions) == 0 {
		return props, "", fmt.Errorf("permissions is required")
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

func (r *RoleDefinition) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	props, name, err := r.parseProps(request.Properties, request.Label)
	if err != nil {
		return nil, err
	}

	result, err := r.api.CreateOrUpdate(ctx, props.Scope, name, roleDefinitionParams(props), nil)
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
	propsJSON, err := json.Marshal(r.buildPropertiesFromResult(&result.RoleDefinition, props.Scope))
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

func (r *RoleDefinition) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	scope, name, err := roleDefinitionIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := r.api.Get(ctx, scope, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(r.buildPropertiesFromResult(&result.RoleDefinition, scope))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeRoleDefinition,
		Properties:   string(propsJSON),
	}, nil
}

// Update reissues CreateOrUpdate: it is the API's only write verb.
func (r *RoleDefinition) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	scope, name, err := roleDefinitionIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	props, _, err := r.parseProps(request.DesiredProperties, name)
	if err != nil {
		return nil, err
	}

	result, err := r.api.CreateOrUpdate(ctx, scope, name, roleDefinitionParams(props), nil)
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

	propsJSON, err := json.Marshal(r.buildPropertiesFromResult(&result.RoleDefinition, scope))
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

func (r *RoleDefinition) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	scope, name, err := roleDefinitionIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	if _, err := r.api.Delete(ctx, scope, name, nil); err != nil && !isDeleteSuccessError(err) {
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
func (r *RoleDefinition) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

// List enumerates definitions visible at a scope, defaulting to the subscription.
//
// A role definition is not a child of a resource group, so discovery has no parent
// to hand down a scope from — without the default it would ask with no scope, get
// nothing back, and never see the role at all.
//
// The listing is filtered to custom roles — the scope also surfaces every built-in
// role, which this provider cannot manage.
func (r *RoleDefinition) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	scope := request.AdditionalProperties["scope"]
	if scope == "" {
		scope = "/subscriptions/" + r.config.SubscriptionId
	}

	var nativeIDs []string
	pager := r.api.NewListPager(scope, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list role definitions: %w", err)
		}
		for _, definition := range page.Value {
			if definition == nil || definition.ID == nil {
				continue
			}
			if p := definition.Properties; p == nil || p.RoleType == nil || !strings.EqualFold(*p.RoleType, "CustomRole") {
				continue
			}
			nativeIDs = append(nativeIDs, *definition.ID)
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
