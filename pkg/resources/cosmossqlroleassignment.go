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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/cosmos/armcosmos/v3"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeCosmosSqlRoleAssignment = "AZURE::DocumentDB::SqlRoleAssignment"

// cosmosSQLRoleAssignmentAPI is the armcosmos.SQLResourcesClient surface used
// here. As with role definitions, roleAssignmentID comes first in the signature.
type cosmosSQLRoleAssignmentAPI interface {
	BeginCreateUpdateSQLRoleAssignment(ctx context.Context, roleAssignmentID string, resourceGroupName string, accountName string, createUpdateSQLRoleAssignmentParameters armcosmos.SQLRoleAssignmentCreateUpdateParameters, options *armcosmos.SQLResourcesClientBeginCreateUpdateSQLRoleAssignmentOptions) (*runtime.Poller[armcosmos.SQLResourcesClientCreateUpdateSQLRoleAssignmentResponse], error)
	GetSQLRoleAssignment(ctx context.Context, roleAssignmentID string, resourceGroupName string, accountName string, options *armcosmos.SQLResourcesClientGetSQLRoleAssignmentOptions) (armcosmos.SQLResourcesClientGetSQLRoleAssignmentResponse, error)
	BeginDeleteSQLRoleAssignment(ctx context.Context, roleAssignmentID string, resourceGroupName string, accountName string, options *armcosmos.SQLResourcesClientBeginDeleteSQLRoleAssignmentOptions) (*runtime.Poller[armcosmos.SQLResourcesClientDeleteSQLRoleAssignmentResponse], error)
	NewListSQLRoleAssignmentsPager(resourceGroupName string, accountName string, options *armcosmos.SQLResourcesClientListSQLRoleAssignmentsOptions) *runtime.Pager[armcosmos.SQLResourcesClientListSQLRoleAssignmentsResponse]
}

func init() {
	registry.Register(ResourceTypeCosmosSqlRoleAssignment, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &CosmosSqlRoleAssignment{
			api:      c.CosmosSQLResourcesClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// CosmosSqlRoleAssignment is the provisioner for Cosmos DB data-plane RBAC role
// assignments (`.../databaseAccounts/<account>/sqlRoleAssignments/<guid>`).
//
// The resource name is a GUID the caller supplies; ARM does not generate one, and
// re-PUTting the same GUID with different properties updates the assignment in
// place rather than creating a second one.
type CosmosSqlRoleAssignment struct {
	api      cosmosSQLRoleAssignmentAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

// cosmosSqlRoleAssignmentProps mirrors
// schema/pkl/documentdb/cosmossqlroleassignment.pkl.
type cosmosSqlRoleAssignmentProps struct {
	Name              string `json:"name"`
	ResourceGroupName string `json:"resourceGroupName"`
	AccountName       string `json:"accountName"`
	RoleDefinitionID  string `json:"roleDefinitionId"`
	PrincipalID       string `json:"principalId"`
	Scope             string `json:"scope"`
}

func cosmosSqlRoleAssignmentIDParts(resourceID string) (rgName, accountName, roleAssignmentID string, err error) {
	rgName, names, err := armExactIDParts(resourceID, "databaseAccounts", "sqlRoleAssignments")
	if err != nil {
		return "", "", "", err
	}
	return rgName, names[0], names[1], nil
}

func cosmosSqlRoleAssignmentProperties(result armcosmos.SQLRoleAssignmentGetResults, rgName, accountName, roleAssignmentID string) (json.RawMessage, error) {
	props := map[string]any{
		"resourceGroupName": rgName,
		"accountName":       accountName,
		"name":              roleAssignmentID,
	}
	if result.ID != nil {
		props["id"] = *result.ID
	}
	if result.Name != nil && *result.Name != "" {
		props["name"] = *result.Name
	}

	if p := result.Properties; p != nil {
		if p.RoleDefinitionID != nil {
			props["roleDefinitionId"] = *p.RoleDefinitionID
		}
		if p.PrincipalID != nil {
			props["principalId"] = *p.PrincipalID
		}
		if p.Scope != nil {
			props["scope"] = *p.Scope
		}
	}

	out, err := json.Marshal(props)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return out, nil
}

func cosmosSqlRoleAssignmentParams(props cosmosSqlRoleAssignmentProps) armcosmos.SQLRoleAssignmentCreateUpdateParameters {
	res := &armcosmos.SQLRoleAssignmentResource{}
	if props.RoleDefinitionID != "" {
		res.RoleDefinitionID = to.Ptr(props.RoleDefinitionID)
	}
	if props.PrincipalID != "" {
		res.PrincipalID = to.Ptr(props.PrincipalID)
	}
	if props.Scope != "" {
		res.Scope = to.Ptr(props.Scope)
	}
	return armcosmos.SQLRoleAssignmentCreateUpdateParameters{Properties: res}
}

func (a *CosmosSqlRoleAssignment) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props cosmosSqlRoleAssignmentProps
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	if props.AccountName == "" {
		return nil, fmt.Errorf("accountName is required")
	}
	if props.Name == "" {
		props.Name = request.Label
	}
	if props.Name == "" {
		return nil, fmt.Errorf("name is required")
	}
	if props.RoleDefinitionID == "" {
		return nil, fmt.Errorf("roleDefinitionId is required")
	}
	if props.PrincipalID == "" {
		return nil, fmt.Errorf("principalId is required")
	}

	poller, err := a.api.BeginCreateUpdateSQLRoleAssignment(ctx, props.Name, props.ResourceGroupName,
		props.AccountName, cosmosSqlRoleAssignmentParams(props), nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	expectedNativeID := cosmosChildNativeID(a.config.SubscriptionId, props.ResourceGroupName, props.AccountName,
		"sqlRoleAssignments", props.Name)

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
		propsJSON, err := cosmosSqlRoleAssignmentProperties(result.SQLRoleAssignmentGetResults,
			props.ResourceGroupName, props.AccountName, props.Name)
		if err != nil {
			return nil, err
		}
		nativeID := expectedNativeID
		if result.ID != nil {
			nativeID = *result.ID
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

func (a *CosmosSqlRoleAssignment) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, accountName, roleAssignmentID, err := cosmosSqlRoleAssignmentIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := a.api.GetSQLRoleAssignment(ctx, roleAssignmentID, rgName, accountName, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := cosmosSqlRoleAssignmentProperties(result.SQLRoleAssignmentGetResults, rgName, accountName, roleAssignmentID)
	if err != nil {
		return nil, err
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeCosmosSqlRoleAssignment,
		Properties:   string(propsJSON),
	}, nil
}

// Update re-PUTs the assignment. Only roleDefinitionId moves in practice:
// principalId and scope are createOnly in the schema, because changing either is a
// different grant to a different identity and re-pointing the existing GUID would
// silently repurpose it.
func (a *CosmosSqlRoleAssignment) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, accountName, roleAssignmentID, err := cosmosSqlRoleAssignmentIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props cosmosSqlRoleAssignmentProps
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	poller, err := a.api.BeginCreateUpdateSQLRoleAssignment(ctx, roleAssignmentID, rgName, accountName,
		cosmosSqlRoleAssignmentParams(props), nil)
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
		propsJSON, err := cosmosSqlRoleAssignmentProperties(result.SQLRoleAssignmentGetResults, rgName, accountName, roleAssignmentID)
		if err != nil {
			return nil, err
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

func (a *CosmosSqlRoleAssignment) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, accountName, roleAssignmentID, err := cosmosSqlRoleAssignmentIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, err := a.api.BeginDeleteSQLRoleAssignment(ctx, roleAssignmentID, rgName, accountName, nil)
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

func (a *CosmosSqlRoleAssignment) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	reqID, err := decodeLROStatus(request.RequestID)
	if err != nil {
		return nil, err
	}

	complete := func(_ context.Context, result armcosmos.SQLResourcesClientCreateUpdateSQLRoleAssignmentResponse, _ resource.Operation) (string, json.RawMessage, error) {
		nativeID := reqID.NativeID
		if result.ID != nil {
			nativeID = *result.ID
		}
		rgName, accountName, roleAssignmentID, err := cosmosSqlRoleAssignmentIDParts(nativeID)
		if err != nil {
			return "", nil, err
		}
		propsJSON, err := cosmosSqlRoleAssignmentProperties(result.SQLRoleAssignmentGetResults, rgName, accountName, roleAssignmentID)
		if err != nil {
			return "", nil, err
		}
		return nativeID, propsJSON, nil
	}
	resume := func(token string) (*runtime.Poller[armcosmos.SQLResourcesClientCreateUpdateSQLRoleAssignmentResponse], error) {
		return resumePoller[armcosmos.SQLResourcesClientCreateUpdateSQLRoleAssignmentResponse](a.pipeline, token)
	}

	switch reqID.OperationType {
	case lroOpCreate:
		return statusLRO(ctx, request, &reqID, resource.OperationCreate, resume, complete)
	case lroOpUpdate:
		return statusLRO(ctx, request, &reqID, resource.OperationUpdate, resume, complete)
	case lroOpDelete:
		return statusDeleteLRO(ctx, request, &reqID,
			func(token string) (*runtime.Poller[armcosmos.SQLResourcesClientDeleteSQLRoleAssignmentResponse], error) {
				return resumePoller[armcosmos.SQLResourcesClientDeleteSQLRoleAssignmentResponse](a.pipeline, token)
			}, nil)
	default:
		return nil, fmt.Errorf("unknown operation type: %s", reqID.OperationType)
	}
}

func (a *CosmosSqlRoleAssignment) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	accountName := request.AdditionalProperties["accountName"]

	var nativeIDs []string
	pager := a.api.NewListSQLRoleAssignmentsPager(rgName, accountName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list Cosmos SQL role assignments in account %s: %w", accountName, err)
		}
		for _, assignment := range page.Value {
			if assignment.ID != nil {
				nativeIDs = append(nativeIDs, *assignment.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
