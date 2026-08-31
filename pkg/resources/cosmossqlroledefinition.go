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

const ResourceTypeCosmosSqlRoleDefinition = "AZURE::DocumentDB::SqlRoleDefinition"

// cosmosSQLRoleDefinitionAPI is the armcosmos.SQLResourcesClient surface used
// here. Note that roleDefinitionID comes FIRST in every signature, before the
// resource group — the generated client is inconsistent with the rest of the
// package on that.
type cosmosSQLRoleDefinitionAPI interface {
	BeginCreateUpdateSQLRoleDefinition(ctx context.Context, roleDefinitionID string, resourceGroupName string, accountName string, createUpdateSQLRoleDefinitionParameters armcosmos.SQLRoleDefinitionCreateUpdateParameters, options *armcosmos.SQLResourcesClientBeginCreateUpdateSQLRoleDefinitionOptions) (*runtime.Poller[armcosmos.SQLResourcesClientCreateUpdateSQLRoleDefinitionResponse], error)
	GetSQLRoleDefinition(ctx context.Context, roleDefinitionID string, resourceGroupName string, accountName string, options *armcosmos.SQLResourcesClientGetSQLRoleDefinitionOptions) (armcosmos.SQLResourcesClientGetSQLRoleDefinitionResponse, error)
	BeginDeleteSQLRoleDefinition(ctx context.Context, roleDefinitionID string, resourceGroupName string, accountName string, options *armcosmos.SQLResourcesClientBeginDeleteSQLRoleDefinitionOptions) (*runtime.Poller[armcosmos.SQLResourcesClientDeleteSQLRoleDefinitionResponse], error)
	NewListSQLRoleDefinitionsPager(resourceGroupName string, accountName string, options *armcosmos.SQLResourcesClientListSQLRoleDefinitionsOptions) *runtime.Pager[armcosmos.SQLResourcesClientListSQLRoleDefinitionsResponse]
}

func init() {
	registry.Register(ResourceTypeCosmosSqlRoleDefinition, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &CosmosSqlRoleDefinition{
			api:      c.CosmosSQLResourcesClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// CosmosSqlRoleDefinition is the provisioner for Cosmos DB data-plane RBAC role
// definitions (`.../databaseAccounts/<account>/sqlRoleDefinitions/<guid>`).
//
// These govern the NoSQL *data plane* — reading and writing documents — which is a
// different permission system from ARM RBAC (AZURE::Authorization::RoleDefinition).
// The resource name is a GUID the caller supplies; ARM does not generate one.
type CosmosSqlRoleDefinition struct {
	api      cosmosSQLRoleDefinitionAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

// cosmosSqlRoleDefinitionProps mirrors
// schema/pkl/documentdb/cosmossqlroledefinition.pkl.
type cosmosSqlRoleDefinitionProps struct {
	Name              string                      `json:"name"`
	ResourceGroupName string                      `json:"resourceGroupName"`
	AccountName       string                      `json:"accountName"`
	RoleName          string                      `json:"roleName"`
	Type              string                      `json:"type"`
	AssignableScopes  []string                    `json:"assignableScopes"`
	Permissions       []cosmosRolePermissionProps `json:"permissions"`
}

type cosmosRolePermissionProps struct {
	DataActions    []string `json:"dataActions"`
	NotDataActions []string `json:"notDataActions"`
}

func cosmosSqlRoleDefinitionIDParts(resourceID string) (rgName, accountName, roleDefinitionID string, err error) {
	rgName, names, err := armExactIDParts(resourceID, "databaseAccounts", "sqlRoleDefinitions")
	if err != nil {
		return "", "", "", err
	}
	return rgName, names[0], names[1], nil
}

func cosmosSqlRoleDefinitionProperties(result armcosmos.SQLRoleDefinitionGetResults, rgName, accountName, roleDefinitionID string) (json.RawMessage, error) {
	props := map[string]any{
		"resourceGroupName": rgName,
		"accountName":       accountName,
		"name":              roleDefinitionID,
	}
	if result.ID != nil {
		props["id"] = *result.ID
	}
	if result.Name != nil && *result.Name != "" {
		props["name"] = *result.Name
	}

	if p := result.Properties; p != nil {
		if p.RoleName != nil {
			props["roleName"] = *p.RoleName
		}
		if p.Type != nil {
			props["type"] = canonicalizeEnum(string(*p.Type), "BuiltInRole", "CustomRole")
		}
		if scopes := stringsFromPointers(p.AssignableScopes); len(scopes) > 0 {
			props["assignableScopes"] = scopes
		}
		permissions := make([]map[string]any, 0, len(p.Permissions))
		for _, permission := range p.Permissions {
			if permission == nil {
				continue
			}
			entry := map[string]any{}
			if actions := stringsFromPointers(permission.DataActions); len(actions) > 0 {
				entry["dataActions"] = actions
			}
			if actions := stringsFromPointers(permission.NotDataActions); len(actions) > 0 {
				entry["notDataActions"] = actions
			}
			if len(entry) > 0 {
				permissions = append(permissions, entry)
			}
		}
		if len(permissions) > 0 {
			props["permissions"] = permissions
		}
	}

	out, err := json.Marshal(props)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return out, nil
}

func cosmosSqlRoleDefinitionParams(props cosmosSqlRoleDefinitionProps) armcosmos.SQLRoleDefinitionCreateUpdateParameters {
	res := &armcosmos.SQLRoleDefinitionResource{
		AssignableScopes: stringPointers(props.AssignableScopes),
	}
	if props.RoleName != "" {
		res.RoleName = to.Ptr(props.RoleName)
	}
	if props.Type != "" {
		res.Type = to.Ptr(armcosmos.RoleDefinitionType(props.Type))
	}
	for _, permission := range props.Permissions {
		res.Permissions = append(res.Permissions, &armcosmos.Permission{
			DataActions:    stringPointers(permission.DataActions),
			NotDataActions: stringPointers(permission.NotDataActions),
		})
	}
	return armcosmos.SQLRoleDefinitionCreateUpdateParameters{Properties: res}
}

func (r *CosmosSqlRoleDefinition) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props cosmosSqlRoleDefinitionProps
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
	if len(props.AssignableScopes) == 0 {
		return nil, fmt.Errorf("at least one assignableScope is required")
	}
	if len(props.Permissions) == 0 {
		return nil, fmt.Errorf("at least one permission is required")
	}

	poller, err := r.api.BeginCreateUpdateSQLRoleDefinition(ctx, props.Name, props.ResourceGroupName,
		props.AccountName, cosmosSqlRoleDefinitionParams(props), nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	expectedNativeID := cosmosChildNativeID(r.config.SubscriptionId, props.ResourceGroupName, props.AccountName,
		"sqlRoleDefinitions", props.Name)

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
		propsJSON, err := cosmosSqlRoleDefinitionProperties(result.SQLRoleDefinitionGetResults,
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

func (r *CosmosSqlRoleDefinition) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, accountName, roleDefinitionID, err := cosmosSqlRoleDefinitionIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := r.api.GetSQLRoleDefinition(ctx, roleDefinitionID, rgName, accountName, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := cosmosSqlRoleDefinitionProperties(result.SQLRoleDefinitionGetResults, rgName, accountName, roleDefinitionID)
	if err != nil {
		return nil, err
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeCosmosSqlRoleDefinition,
		Properties:   string(propsJSON),
	}, nil
}

func (r *CosmosSqlRoleDefinition) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, accountName, roleDefinitionID, err := cosmosSqlRoleDefinitionIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props cosmosSqlRoleDefinitionProps
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	poller, err := r.api.BeginCreateUpdateSQLRoleDefinition(ctx, roleDefinitionID, rgName, accountName,
		cosmosSqlRoleDefinitionParams(props), nil)
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
		propsJSON, err := cosmosSqlRoleDefinitionProperties(result.SQLRoleDefinitionGetResults, rgName, accountName, roleDefinitionID)
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

func (r *CosmosSqlRoleDefinition) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, accountName, roleDefinitionID, err := cosmosSqlRoleDefinitionIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, err := r.api.BeginDeleteSQLRoleDefinition(ctx, roleDefinitionID, rgName, accountName, nil)
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

func (r *CosmosSqlRoleDefinition) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	reqID, err := decodeLROStatus(request.RequestID)
	if err != nil {
		return nil, err
	}

	complete := func(_ context.Context, result armcosmos.SQLResourcesClientCreateUpdateSQLRoleDefinitionResponse, _ resource.Operation) (string, json.RawMessage, error) {
		nativeID := reqID.NativeID
		if result.ID != nil {
			nativeID = *result.ID
		}
		rgName, accountName, roleDefinitionID, err := cosmosSqlRoleDefinitionIDParts(nativeID)
		if err != nil {
			return "", nil, err
		}
		propsJSON, err := cosmosSqlRoleDefinitionProperties(result.SQLRoleDefinitionGetResults, rgName, accountName, roleDefinitionID)
		if err != nil {
			return "", nil, err
		}
		return nativeID, propsJSON, nil
	}
	resume := func(token string) (*runtime.Poller[armcosmos.SQLResourcesClientCreateUpdateSQLRoleDefinitionResponse], error) {
		return resumePoller[armcosmos.SQLResourcesClientCreateUpdateSQLRoleDefinitionResponse](r.pipeline, token)
	}

	switch reqID.OperationType {
	case lroOpCreate:
		return statusLRO(ctx, request, &reqID, resource.OperationCreate, resume, complete)
	case lroOpUpdate:
		return statusLRO(ctx, request, &reqID, resource.OperationUpdate, resume, complete)
	case lroOpDelete:
		return statusDeleteLRO(ctx, request, &reqID,
			func(token string) (*runtime.Poller[armcosmos.SQLResourcesClientDeleteSQLRoleDefinitionResponse], error) {
				return resumePoller[armcosmos.SQLResourcesClientDeleteSQLRoleDefinitionResponse](r.pipeline, token)
			}, nil)
	default:
		return nil, fmt.Errorf("unknown operation type: %s", reqID.OperationType)
	}
}

func (r *CosmosSqlRoleDefinition) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	accountName := request.AdditionalProperties["accountName"]

	var nativeIDs []string
	pager := r.api.NewListSQLRoleDefinitionsPager(rgName, accountName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list Cosmos SQL role definitions in account %s: %w", accountName, err)
		}
		for _, definition := range page.Value {
			if definition.ID == nil {
				continue
			}
			// Every account also exposes the two built-in data-plane roles
			// (Data Reader and Data Contributor). ARM refuses to delete them,
			// so surfacing them to discovery would hand formae resources it can
			// never reconcile.
			if definition.Properties != nil && definition.Properties.Type != nil &&
				*definition.Properties.Type == armcosmos.RoleDefinitionTypeBuiltInRole {
				continue
			}
			nativeIDs = append(nativeIDs, *definition.ID)
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
