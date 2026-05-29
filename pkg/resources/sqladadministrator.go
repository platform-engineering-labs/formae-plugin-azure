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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/sql/armsql"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeSQLADAdministrator = "AZURE::Sql::ServerAzureADAdministrator"

// sqlADAdministratorsAPI is the subset of *armsql.ServerAzureADAdministratorsClient
// the provisioner relies on, kept narrow so tests can supply a fake.
type sqlADAdministratorsAPI interface {
	BeginCreateOrUpdate(ctx context.Context, resourceGroupName string, serverName string, administratorName armsql.AdministratorName, parameters armsql.ServerAzureADAdministrator, options *armsql.ServerAzureADAdministratorsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armsql.ServerAzureADAdministratorsClientCreateOrUpdateResponse], error)
	Get(ctx context.Context, resourceGroupName string, serverName string, administratorName armsql.AdministratorName, options *armsql.ServerAzureADAdministratorsClientGetOptions) (armsql.ServerAzureADAdministratorsClientGetResponse, error)
	BeginDelete(ctx context.Context, resourceGroupName string, serverName string, administratorName armsql.AdministratorName, options *armsql.ServerAzureADAdministratorsClientBeginDeleteOptions) (*runtime.Poller[armsql.ServerAzureADAdministratorsClientDeleteResponse], error)
	NewListByServerPager(resourceGroupName string, serverName string, options *armsql.ServerAzureADAdministratorsClientListByServerOptions) *runtime.Pager[armsql.ServerAzureADAdministratorsClientListByServerResponse]
}

func init() {
	registry.Register(ResourceTypeSQLADAdministrator, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &SqlADAdministrator{
			api:      c.SQLServerAzureADAdministratorsClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// SqlADAdministrator is the provisioner for the standalone Azure AD administrator
// child resource of a SQL logical server (Microsoft.Sql/servers/administrators).
// Setting it is what enables AAD / workload-identity logins on the server.
type SqlADAdministrator struct {
	api      sqlADAdministratorsAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

// sqlADAdministratorIDParts extracts the resource group and parent server name
// from a Microsoft.Sql/servers/administrators ARM ID. The trailing
// "administrators" segment is always the fixed "ActiveDirectory" name.
func sqlADAdministratorIDParts(resourceID string) (rgName, serverName string, err error) {
	rgName, names, err := armIDParts(resourceID, "servers", "administrators")
	if err != nil {
		return "", "", err
	}
	return rgName, names["servers"], nil
}

// buildPropertiesFromResult extracts properties from an AAD administrator response.
func (s *SqlADAdministrator) buildPropertiesFromResult(admin *armsql.ServerAzureADAdministrator, rgName, serverName string) map[string]any {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	props["serverName"] = serverName

	if admin.ID != nil {
		props["id"] = *admin.ID
	}
	if admin.Name != nil {
		props["name"] = *admin.Name
	}

	if admin.Properties != nil {
		if admin.Properties.AdministratorType != nil {
			props["administratorType"] = string(*admin.Properties.AdministratorType)
		}
		if admin.Properties.Login != nil {
			props["login"] = *admin.Properties.Login
		}
		if admin.Properties.Sid != nil {
			props["sid"] = *admin.Properties.Sid
		}
		if admin.Properties.TenantID != nil {
			props["tenantId"] = *admin.Properties.TenantID
		}
		if admin.Properties.AzureADOnlyAuthentication != nil {
			props["azureADOnlyAuthentication"] = *admin.Properties.AzureADOnlyAuthentication
		}
	}

	return props
}

// buildAdministratorParams constructs the create/update payload. AdministratorType
// is always "ActiveDirectory" — the only external administrator type Azure supports.
func buildAdministratorParams(props map[string]any) armsql.ServerAzureADAdministrator {
	adminProps := &armsql.AdministratorProperties{
		AdministratorType: to.Ptr(armsql.AdministratorTypeActiveDirectory),
	}
	if v, ok := props["login"].(string); ok && v != "" {
		adminProps.Login = to.Ptr(v)
	}
	if v, ok := props["sid"].(string); ok && v != "" {
		adminProps.Sid = to.Ptr(v)
	}
	if v, ok := props["tenantId"].(string); ok && v != "" {
		adminProps.TenantID = to.Ptr(v)
	}
	return armsql.ServerAzureADAdministrator{Properties: adminProps}
}

func (s *SqlADAdministrator) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props map[string]any
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	rgName, ok := props["resourceGroupName"].(string)
	if !ok || rgName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	serverName, ok := props["serverName"].(string)
	if !ok || serverName == "" {
		return nil, fmt.Errorf("serverName is required")
	}

	params := buildAdministratorParams(props)

	poller, err := s.api.BeginCreateOrUpdate(ctx, rgName, serverName, armsql.AdministratorNameActiveDirectory, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Sql/servers/%s/administrators/ActiveDirectory",
		s.config.SubscriptionId, rgName, serverName)

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
		nativeID, propsJSON, err := s.completeFromAdministrator(&result.ServerAzureADAdministrator)
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

func (s *SqlADAdministrator) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, serverName, err := sqlADAdministratorIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := s.api.Get(ctx, rgName, serverName, armsql.AdministratorNameActiveDirectory, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	responseProps := s.buildPropertiesFromResult(&result.ServerAzureADAdministrator, rgName, serverName)
	propsJSON, err := json.Marshal(responseProps)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeSQLADAdministrator,
		Properties:   string(propsJSON),
	}, nil
}

func (s *SqlADAdministrator) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, serverName, err := sqlADAdministratorIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props map[string]any
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	// CreateOrUpdate is idempotent — Azure replaces the single AAD administrator.
	params := buildAdministratorParams(props)

	poller, err := s.api.BeginCreateOrUpdate(ctx, rgName, serverName, armsql.AdministratorNameActiveDirectory, params, nil)
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
		nativeID, propsJSON, err := s.completeFromAdministrator(&result.ServerAzureADAdministrator)
		if err != nil {
			return nil, err
		}
		return &resource.UpdateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:          resource.OperationUpdate,
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

func (s *SqlADAdministrator) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, serverName, err := sqlADAdministratorIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, err := s.api.BeginDelete(ctx, rgName, serverName, armsql.AdministratorNameActiveDirectory, nil)
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

func (s *SqlADAdministrator) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	reqID, err := decodeLROStatus(request.RequestID)
	if err != nil {
		return nil, err
	}

	switch reqID.OperationType {
	case lroOpCreate:
		return statusLRO(ctx, request, &reqID, resource.OperationCreate,
			func(token string) (*runtime.Poller[armsql.ServerAzureADAdministratorsClientCreateOrUpdateResponse], error) {
				return resumePoller[armsql.ServerAzureADAdministratorsClientCreateOrUpdateResponse](s.pipeline, token)
			},
			func(_ context.Context, result armsql.ServerAzureADAdministratorsClientCreateOrUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				return s.completeFromAdministrator(&result.ServerAzureADAdministrator)
			})
	case lroOpUpdate:
		return statusLRO(ctx, request, &reqID, resource.OperationUpdate,
			func(token string) (*runtime.Poller[armsql.ServerAzureADAdministratorsClientCreateOrUpdateResponse], error) {
				return resumePoller[armsql.ServerAzureADAdministratorsClientCreateOrUpdateResponse](s.pipeline, token)
			},
			func(_ context.Context, result armsql.ServerAzureADAdministratorsClientCreateOrUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				return s.completeFromAdministrator(&result.ServerAzureADAdministrator)
			})
	case lroOpDelete:
		return statusDeleteLRO(ctx, request, &reqID,
			func(token string) (*runtime.Poller[armsql.ServerAzureADAdministratorsClientDeleteResponse], error) {
				return resumePoller[armsql.ServerAzureADAdministratorsClientDeleteResponse](s.pipeline, token)
			}, nil)
	default:
		return nil, fmt.Errorf("unknown operation type: %s", reqID.OperationType)
	}
}

func (s *SqlADAdministrator) completeFromAdministrator(admin *armsql.ServerAzureADAdministrator) (string, json.RawMessage, error) {
	nativeID := ""
	rgName, serverName := "", ""
	if admin.ID != nil {
		nativeID = *admin.ID
		rgName, serverName, _ = sqlADAdministratorIDParts(*admin.ID)
	}
	propsJSON, err := json.Marshal(s.buildPropertiesFromResult(admin, rgName, serverName))
	if err != nil {
		return "", nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return nativeID, propsJSON, nil
}

func (s *SqlADAdministrator) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	serverName := request.AdditionalProperties["serverName"]
	if rgName == "" || serverName == "" {
		return nil, fmt.Errorf("resourceGroupName and serverName are required to list SQL server AAD administrators")
	}

	var nativeIDs []string
	pager := s.api.NewListByServerPager(rgName, serverName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list sql server AAD administrators for server %s: %w", serverName, err)
		}
		for _, admin := range page.Value {
			if admin.ID != nil {
				nativeIDs = append(nativeIDs, *admin.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
