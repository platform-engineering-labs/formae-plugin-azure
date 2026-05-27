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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/sql/armsql"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeSQLServer = "AZURE::Sql::Server"

type sqlServersAPI interface {
	BeginCreateOrUpdate(ctx context.Context, resourceGroupName string, serverName string, parameters armsql.Server, options *armsql.ServersClientBeginCreateOrUpdateOptions) (*runtime.Poller[armsql.ServersClientCreateOrUpdateResponse], error)
	Get(ctx context.Context, resourceGroupName string, serverName string, options *armsql.ServersClientGetOptions) (armsql.ServersClientGetResponse, error)
	BeginUpdate(ctx context.Context, resourceGroupName string, serverName string, parameters armsql.ServerUpdate, options *armsql.ServersClientBeginUpdateOptions) (*runtime.Poller[armsql.ServersClientUpdateResponse], error)
	BeginDelete(ctx context.Context, resourceGroupName string, serverName string, options *armsql.ServersClientBeginDeleteOptions) (*runtime.Poller[armsql.ServersClientDeleteResponse], error)
	NewListByResourceGroupPager(resourceGroupName string, options *armsql.ServersClientListByResourceGroupOptions) *runtime.Pager[armsql.ServersClientListByResourceGroupResponse]
	NewListPager(options *armsql.ServersClientListOptions) *runtime.Pager[armsql.ServersClientListResponse]
}

func init() {
	registry.Register(ResourceTypeSQLServer, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &SqlServer{
			api:      c.SQLServersClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// SqlServer is the provisioner for Azure SQL logical server (Microsoft.Sql/servers).
type SqlServer struct {
	api      sqlServersAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

func sqlServerIDParts(resourceID string) (rgName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "servers")
	if err != nil {
		return "", "", err
	}
	return rgName, names["servers"], nil
}

// buildPropertiesFromResult extracts properties from a SQL Server Azure response.
func (s *SqlServer) buildPropertiesFromResult(server *armsql.Server) map[string]any {
	props := make(map[string]any)

	if server.ID != nil {
		if rgName, _, err := sqlServerIDParts(*server.ID); err == nil {
			props["resourceGroupName"] = rgName
		}
		props["id"] = *server.ID
	}

	if server.Name != nil {
		props["name"] = *server.Name
	}

	// Normalize location to "name" format (lowercase, no spaces).
	if server.Location != nil {
		props["location"] = strings.ToLower(strings.ReplaceAll(*server.Location, " ", ""))
	}

	if server.Properties != nil {
		if server.Properties.Version != nil {
			props["version"] = *server.Properties.Version
		}
		if server.Properties.AdministratorLogin != nil {
			props["administratorLogin"] = *server.Properties.AdministratorLogin
		}
		if server.Properties.MinimalTLSVersion != nil {
			props["minimalTlsVersion"] = *server.Properties.MinimalTLSVersion
		}
		if server.Properties.PublicNetworkAccess != nil {
			props["publicNetworkAccess"] = string(*server.Properties.PublicNetworkAccess)
		}
		if server.Properties.PrimaryUserAssignedIdentityID != nil {
			props["primaryUserAssignedIdentityId"] = *server.Properties.PrimaryUserAssignedIdentityID
		}

		// AAD administrator block.
		if admin := server.Properties.Administrators; admin != nil {
			a := make(map[string]any)
			if admin.AdministratorType != nil {
				a["administratorType"] = string(*admin.AdministratorType)
			}
			if admin.Login != nil {
				a["login"] = *admin.Login
			}
			if admin.Sid != nil {
				a["sid"] = *admin.Sid
			}
			if admin.TenantID != nil {
				a["tenantId"] = *admin.TenantID
			}
			if admin.PrincipalType != nil {
				a["principalType"] = string(*admin.PrincipalType)
			}
			if admin.AzureADOnlyAuthentication != nil {
				a["azureADOnlyAuthentication"] = *admin.AzureADOnlyAuthentication
			}
			if len(a) > 0 {
				props["administrators"] = a
			}
		}

		// Read-only output.
		if server.Properties.FullyQualifiedDomainName != nil {
			props["fullyQualifiedDomainName"] = *server.Properties.FullyQualifiedDomainName
		}
		if server.Properties.State != nil {
			props["state"] = *server.Properties.State
		}
	}

	// Identity block.
	if id := server.Identity; id != nil {
		identity := make(map[string]any)
		if id.Type != nil {
			identity["type"] = string(*id.Type)
		}
		if len(id.UserAssignedIdentities) > 0 {
			ids := make([]string, 0, len(id.UserAssignedIdentities))
			for k := range id.UserAssignedIdentities {
				ids = append(ids, k)
			}
			identity["userAssignedIdentityIds"] = ids
		}
		if len(identity) > 0 {
			props["identity"] = identity
		}
	}

	if tags := azureTagsToFormaeTags(server.Tags); tags != nil {
		props["Tags"] = tags
	}

	return props
}

// buildServerParams constructs the armsql.Server create/update payload from
// parsed Formae properties.
func buildServerParams(props map[string]any, location string) armsql.Server {
	serverProps := &armsql.ServerProperties{}

	if v, ok := props["version"].(string); ok && v != "" {
		serverProps.Version = to.Ptr(v)
	}
	if v, ok := props["administratorLogin"].(string); ok && v != "" {
		serverProps.AdministratorLogin = to.Ptr(v)
	}
	if v, ok := props["administratorLoginPassword"].(string); ok && v != "" {
		serverProps.AdministratorLoginPassword = to.Ptr(v)
	}
	if v, ok := props["minimalTlsVersion"].(string); ok && v != "" {
		serverProps.MinimalTLSVersion = to.Ptr(v)
	}
	if v, ok := props["publicNetworkAccess"].(string); ok && v != "" {
		serverProps.PublicNetworkAccess = to.Ptr(armsql.ServerNetworkAccessFlag(v))
	}
	if v, ok := props["primaryUserAssignedIdentityId"].(string); ok && v != "" {
		serverProps.PrimaryUserAssignedIdentityID = to.Ptr(v)
	}
	if admin := buildAdministrators(props); admin != nil {
		serverProps.Administrators = admin
	}

	params := armsql.Server{
		Location:   to.Ptr(location),
		Properties: serverProps,
	}
	if identity := buildServerIdentity(props); identity != nil {
		params.Identity = identity
	}
	return params
}

func buildAdministrators(props map[string]any) *armsql.ServerExternalAdministrator {
	raw, ok := props["administrators"].(map[string]any)
	if !ok {
		return nil
	}
	admin := &armsql.ServerExternalAdministrator{
		// AAD admin is the only external administrator type Azure supports today.
		AdministratorType: to.Ptr(armsql.AdministratorTypeActiveDirectory),
	}
	if v, ok := raw["login"].(string); ok && v != "" {
		admin.Login = to.Ptr(v)
	}
	if v, ok := raw["sid"].(string); ok && v != "" {
		admin.Sid = to.Ptr(v)
	}
	if v, ok := raw["tenantId"].(string); ok && v != "" {
		admin.TenantID = to.Ptr(v)
	}
	if v, ok := raw["principalType"].(string); ok && v != "" {
		admin.PrincipalType = to.Ptr(armsql.PrincipalType(v))
	}
	if v, ok := raw["azureADOnlyAuthentication"].(bool); ok {
		admin.AzureADOnlyAuthentication = to.Ptr(v)
	}
	return admin
}

func buildServerIdentity(props map[string]any) *armsql.ResourceIdentity {
	raw, ok := props["identity"].(map[string]any)
	if !ok {
		return nil
	}
	identity := &armsql.ResourceIdentity{}
	if v, ok := raw["type"].(string); ok && v != "" {
		identity.Type = to.Ptr(armsql.IdentityType(v))
	}
	if ids, ok := raw["userAssignedIdentityIds"].([]any); ok && len(ids) > 0 {
		identity.UserAssignedIdentities = make(map[string]*armsql.UserIdentity, len(ids))
		for _, id := range ids {
			if idStr, ok := id.(string); ok && idStr != "" {
				identity.UserAssignedIdentities[idStr] = &armsql.UserIdentity{}
			}
		}
	}
	return identity
}

func (s *SqlServer) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
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
	serverName, ok := props["name"].(string)
	if !ok || serverName == "" {
		serverName = request.Label
	}

	params := buildServerParams(props, location)
	if azureTags := formaeTagsToAzureTags(request.Properties); azureTags != nil {
		params.Tags = azureTags
	}

	poller, err := s.api.BeginCreateOrUpdate(ctx, rgName, serverName, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Sql/servers/%s",
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
		responseProps := s.buildPropertiesFromResult(&result.Server)
		propsJSON, err := json.Marshal(responseProps)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal response properties: %w", err)
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

func (s *SqlServer) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, serverName, err := sqlServerIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := s.api.Get(ctx, rgName, serverName, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	responseProps := s.buildPropertiesFromResult(&result.Server)
	propsJSON, err := json.Marshal(responseProps)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{Properties: string(propsJSON)}, nil
}

func (s *SqlServer) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, serverName, err := sqlServerIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props map[string]any
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	updateProps := &armsql.ServerProperties{}
	if v, ok := props["administratorLoginPassword"].(string); ok && v != "" {
		updateProps.AdministratorLoginPassword = to.Ptr(v)
	}
	if v, ok := props["minimalTlsVersion"].(string); ok && v != "" {
		updateProps.MinimalTLSVersion = to.Ptr(v)
	}
	if v, ok := props["publicNetworkAccess"].(string); ok && v != "" {
		updateProps.PublicNetworkAccess = to.Ptr(armsql.ServerNetworkAccessFlag(v))
	}
	if admin := buildAdministrators(props); admin != nil {
		updateProps.Administrators = admin
	}

	params := armsql.ServerUpdate{Properties: updateProps}
	if identity := buildServerIdentity(props); identity != nil {
		params.Identity = identity
	}
	if azureTags := formaeTagsToAzureTags(request.DesiredProperties); azureTags != nil {
		params.Tags = azureTags
	}

	poller, err := s.api.BeginUpdate(ctx, rgName, serverName, params, nil)
	if err != nil {
		return &resource.UpdateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationUpdate,
				OperationStatus: resource.OperationStatusFailure,
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
					ErrorCode:       operationErrorCode(err),
				},
			}, nil
		}
		responseProps := s.buildPropertiesFromResult(&result.Server)
		propsJSON, err := json.Marshal(responseProps)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal response properties: %w", err)
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

func (s *SqlServer) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, serverName, err := sqlServerIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, err := s.api.BeginDelete(ctx, rgName, serverName, nil)
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

func (s *SqlServer) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	reqID, err := decodeLROStatus(request.RequestID)
	if err != nil {
		return nil, err
	}

	switch reqID.OperationType {
	case lroOpCreate:
		return statusLRO(ctx, request, &reqID, resource.OperationCreate,
			func(token string) (*runtime.Poller[armsql.ServersClientCreateOrUpdateResponse], error) {
				return resumePoller[armsql.ServersClientCreateOrUpdateResponse](s.pipeline, token)
			},
			func(ctx context.Context, result armsql.ServersClientCreateOrUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				return s.completeFromServer(&result.Server)
			})
	case lroOpUpdate:
		return statusLRO(ctx, request, &reqID, resource.OperationUpdate,
			func(token string) (*runtime.Poller[armsql.ServersClientUpdateResponse], error) {
				return resumePoller[armsql.ServersClientUpdateResponse](s.pipeline, token)
			},
			func(ctx context.Context, result armsql.ServersClientUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				return s.completeFromServer(&result.Server)
			})
	case lroOpDelete:
		return statusDeleteLRO(ctx, request, &reqID,
			func(token string) (*runtime.Poller[armsql.ServersClientDeleteResponse], error) {
				return resumePoller[armsql.ServersClientDeleteResponse](s.pipeline, token)
			}, nil)
	default:
		return nil, fmt.Errorf("unknown operation type: %s", reqID.OperationType)
	}
}

func (s *SqlServer) completeFromServer(server *armsql.Server) (string, json.RawMessage, error) {
	nativeID := ""
	if server.ID != nil {
		nativeID = *server.ID
	}
	propsJSON, err := json.Marshal(s.buildPropertiesFromResult(server))
	if err != nil {
		return "", nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return nativeID, propsJSON, nil
}

func (s *SqlServer) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	var nativeIDs []string

	rgName, ok := request.AdditionalProperties["resourceGroupName"]
	if ok && rgName != "" {
		pager := s.api.NewListByResourceGroupPager(rgName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list sql servers: %w", err)
			}
			for _, server := range page.Value {
				if server.ID != nil {
					nativeIDs = append(nativeIDs, *server.ID)
				}
			}
		}
		return &resource.ListResult{NativeIDs: nativeIDs}, nil
	}

	pager := s.api.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list sql servers: %w", err)
		}
		for _, server := range page.Value {
			if server.ID != nil {
				nativeIDs = append(nativeIDs, *server.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
