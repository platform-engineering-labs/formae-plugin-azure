// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"
	"github.com/google/uuid"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
)

const ResourceTypeRoleAssignment = "Azure::Authorization::RoleAssignment"

func init() {
	registry.Register(ResourceTypeRoleAssignment, func(client *client.Client, cfg *config.Config) prov.Provisioner {
		return &RoleAssignment{client, cfg}
	})
}

// RoleAssignment is the provisioner for Azure Role Assignments.
type RoleAssignment struct {
	Client *client.Client
	Config *config.Config
}

// serializeRoleAssignmentProperties converts an Azure RoleAssignment to Formae property format
func serializeRoleAssignmentProperties(result armauthorization.RoleAssignment) (json.RawMessage, error) {
	props := make(map[string]any)

	if result.Name != nil {
		props["name"] = *result.Name
	}

	if result.Properties != nil {
		if result.Properties.Scope != nil {
			props["scope"] = *result.Properties.Scope
		}
		if result.Properties.PrincipalID != nil {
			props["principalId"] = *result.Properties.PrincipalID
		}
		if result.Properties.RoleDefinitionID != nil {
			props["roleDefinitionId"] = *result.Properties.RoleDefinitionID
		}
		if result.Properties.PrincipalType != nil {
			props["principalType"] = string(*result.Properties.PrincipalType)
		}
		if result.Properties.Description != nil {
			props["description"] = *result.Properties.Description
		}
		if result.Properties.Condition != nil {
			props["condition"] = *result.Properties.Condition
		}
		if result.Properties.ConditionVersion != nil {
			props["conditionVersion"] = *result.Properties.ConditionVersion
		}
	}

	// Include id for resolvable references
	if result.ID != nil {
		props["id"] = *result.ID
	}

	return json.Marshal(props)
}

func (r *RoleAssignment) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props map[string]any
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	scope, ok := props["scope"].(string)
	if !ok || scope == "" {
		return nil, fmt.Errorf("scope is required")
	}

	roleAssignmentName, ok := props["name"].(string)
	if !ok || roleAssignmentName == "" {
		// Azure requires role assignment names to be UUIDs. Generate one if not provided.
		// Formae tracks resources by label, so this generated UUID only matters for the initial create.
		roleAssignmentName = uuid.New().String()
	}

	principalID, ok := props["principalId"].(string)
	if !ok || principalID == "" {
		return nil, fmt.Errorf("principalId is required")
	}

	roleDefinitionID, ok := props["roleDefinitionId"].(string)
	if !ok || roleDefinitionID == "" {
		return nil, fmt.Errorf("roleDefinitionId is required")
	}

	params := armauthorization.RoleAssignmentCreateParameters{
		Properties: &armauthorization.RoleAssignmentProperties{
			PrincipalID:      stringPtr(principalID),
			RoleDefinitionID: stringPtr(roleDefinitionID),
		},
	}

	// Optional: principal type
	if principalType, ok := props["principalType"].(string); ok && principalType != "" {
		pt := armauthorization.PrincipalType(principalType)
		params.Properties.PrincipalType = &pt
	}

	// Optional: description
	if description, ok := props["description"].(string); ok && description != "" {
		params.Properties.Description = stringPtr(description)
	}

	// Optional: condition
	if condition, ok := props["condition"].(string); ok && condition != "" {
		params.Properties.Condition = stringPtr(condition)
	}

	// Optional: condition version
	if conditionVersion, ok := props["conditionVersion"].(string); ok && conditionVersion != "" {
		params.Properties.ConditionVersion = stringPtr(conditionVersion)
	}

	// Role assignment creation is synchronous
	result, err := r.Client.RoleAssignmentsClient.Create(ctx, scope, roleAssignmentName, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       mapAzureErrorToOperationErrorCode(err),
			},
		}, fmt.Errorf("failed to create RoleAssignment: %w", err)
	}

	// Return success without ResourceProperties per Lesson 1
	return &resource.CreateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationCreate,
			OperationStatus: resource.OperationStatusSuccess,
			NativeID:        *result.ID,
		},
	}, nil
}

func (r *RoleAssignment) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	// RoleAssignment NativeID is the full resource ID which serves as the scope
	result, err := r.Client.RoleAssignmentsClient.GetByID(ctx, request.NativeID, nil)
	if err != nil {
		return &resource.ReadResult{
			ErrorCode: mapAzureErrorToOperationErrorCode(err),
		}, fmt.Errorf("failed to read RoleAssignment: %w", err)
	}

	propsJSON, err := serializeRoleAssignmentProperties(result.RoleAssignment)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize RoleAssignment properties: %w", err)
	}

	return &resource.ReadResult{
		Properties: string(propsJSON),
	}, nil
}

func (r *RoleAssignment) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	// Role assignments are immutable - they cannot be updated
	// If properties need to change, the resource must be deleted and recreated
	return &resource.UpdateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationUpdate,
			OperationStatus: resource.OperationStatusFailure,
			NativeID:        request.NativeID,
			ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
			StatusMessage:   "RoleAssignments are immutable and cannot be updated. Delete and recreate instead.",
		},
	}, fmt.Errorf("RoleAssignments are immutable and cannot be updated")
}

func (r *RoleAssignment) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	// Role assignment deletion uses the full resource ID
	_, err := r.Client.RoleAssignmentsClient.DeleteByID(ctx, request.NativeID, nil)
	if err != nil {
		// If the resource is already gone (NotFound), treat as success
		if mapAzureErrorToOperationErrorCode(err) == resource.OperationErrorCodeNotFound {
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
				ErrorCode:       mapAzureErrorToOperationErrorCode(err),
			},
		}, fmt.Errorf("failed to delete RoleAssignment: %w", err)
	}

	return &resource.DeleteResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationDelete,
			OperationStatus: resource.OperationStatusSuccess,
			NativeID:        request.NativeID,
		},
	}, nil
}

func (r *RoleAssignment) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	// Role assignment operations are synchronous, so Status should not normally be called
	// If it is called, do a Read to get current state
	result, err := r.Client.RoleAssignmentsClient.GetByID(ctx, request.NativeID, nil)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       mapAzureErrorToOperationErrorCode(err),
			},
		}, fmt.Errorf("failed to get RoleAssignment status: %w", err)
	}

	propsJSON, err := serializeRoleAssignmentProperties(result.RoleAssignment)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize RoleAssignment properties: %w", err)
	}

	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus:    resource.OperationStatusSuccess,
			RequestID:          request.RequestID,
			NativeID:           *result.ID,
			ResourceProperties: propsJSON,
		},
	}, nil
}

func (r *RoleAssignment) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	// RoleAssignments can be listed at different scopes
	// The scope should be provided in AdditionalProperties
	scope, ok := request.AdditionalProperties["scope"]
	if !ok || scope == "" {
		// Default to subscription scope
		scope = fmt.Sprintf("/subscriptions/%s", r.Config.SubscriptionId)
	}

	pager := r.Client.RoleAssignmentsClient.NewListForScopePager(scope, nil)

	var nativeIDs []string

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list role assignments at scope %s: %w", scope, err)
		}

		for _, assignment := range page.Value {
			if assignment.ID == nil {
				continue
			}

			nativeIDs = append(nativeIDs, *assignment.ID)
		}
	}

	return &resource.ListResult{
		NativeIDs: nativeIDs,
	}, nil
}
