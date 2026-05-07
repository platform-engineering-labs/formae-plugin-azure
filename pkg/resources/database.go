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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/postgresql/armpostgresqlflexibleservers/v4"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeDatabase = "Azure::DBforPostgreSQL::Database"

type databasesAPI interface {
	BeginCreate(ctx context.Context, resourceGroupName string, serverName string, databaseName string, parameters armpostgresqlflexibleservers.Database, options *armpostgresqlflexibleservers.DatabasesClientBeginCreateOptions) (*runtime.Poller[armpostgresqlflexibleservers.DatabasesClientCreateResponse], error)
	Get(ctx context.Context, resourceGroupName string, serverName string, databaseName string, options *armpostgresqlflexibleservers.DatabasesClientGetOptions) (armpostgresqlflexibleservers.DatabasesClientGetResponse, error)
	BeginDelete(ctx context.Context, resourceGroupName string, serverName string, databaseName string, options *armpostgresqlflexibleservers.DatabasesClientBeginDeleteOptions) (*runtime.Poller[armpostgresqlflexibleservers.DatabasesClientDeleteResponse], error)
	NewListByServerPager(resourceGroupName string, serverName string, options *armpostgresqlflexibleservers.DatabasesClientListByServerOptions) *runtime.Pager[armpostgresqlflexibleservers.DatabasesClientListByServerResponse]
	NewListServersPager(options *armpostgresqlflexibleservers.ServersClientListOptions) *runtime.Pager[armpostgresqlflexibleservers.ServersClientListResponse]
}

// databasesClientWrapper composes the SDK client with server discovery.
type databasesClientWrapper struct {
	*armpostgresqlflexibleservers.DatabasesClient
	serversClient *armpostgresqlflexibleservers.ServersClient
}

func (w *databasesClientWrapper) NewListServersPager(options *armpostgresqlflexibleservers.ServersClientListOptions) *runtime.Pager[armpostgresqlflexibleservers.ServersClientListResponse] {
	return w.serversClient.NewListPager(options)
}

func init() {
	registry.Register(ResourceTypeDatabase, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &Database{
			api: &databasesClientWrapper{
				DatabasesClient: c.DatabasesClient,
				serversClient:   c.FlexibleServersClient,
			},
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// Database is the provisioner for Azure Database for PostgreSQL Flexible Server Databases.
type Database struct {
	api      databasesAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

func databaseIDParts(resourceID string) (rgName, parentName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "flexibleservers", "databases")
	if err != nil {
		return "", "", "", err
	}
	return rgName, names["flexibleservers"], names["databases"], nil
}

// buildPropertiesFromResult extracts properties from a Database Azure response.
func (d *Database) buildPropertiesFromResult(db *armpostgresqlflexibleservers.Database, rgName, serverName string) map[string]any {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	props["serverName"] = serverName

	if db.Name != nil {
		props["name"] = *db.Name
	}

	if db.Properties != nil {
		if db.Properties.Charset != nil {
			props["charset"] = *db.Properties.Charset
		}
		if db.Properties.Collation != nil {
			props["collation"] = *db.Properties.Collation
		}
	}

	if db.ID != nil {
		props["id"] = *db.ID
	}

	return props
}

func (d *Database) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
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

	dbName, ok := props["name"].(string)
	if !ok || dbName == "" {
		dbName = request.Label
	}

	params := armpostgresqlflexibleservers.Database{
		Properties: &armpostgresqlflexibleservers.DatabaseProperties{},
	}

	if charset, ok := props["charset"].(string); ok && charset != "" {
		params.Properties.Charset = to.Ptr(charset)
	}
	if collation, ok := props["collation"].(string); ok && collation != "" {
		params.Properties.Collation = to.Ptr(collation)
	}

	poller, err := d.api.BeginCreate(ctx, rgName, serverName, dbName, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.DBforPostgreSQL/flexibleServers/%s/databases/%s",
		d.config.SubscriptionId, rgName, serverName, dbName)

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

		responseProps := d.buildPropertiesFromResult(&result.Database, rgName, serverName)
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

	reqID := lroRequestID{
		OperationType: "create",
		ResumeToken:   resumeToken,
		NativeID:      expectedNativeID,
	}
	reqIDJSON, err := json.Marshal(reqID)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request ID: %w", err)
	}

	return &resource.CreateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationCreate,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       string(reqIDJSON),
			NativeID:        expectedNativeID,
		},
	}, nil
}

func (d *Database) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, serverName, dbName, err := databaseIDParts(request.NativeID)
	if err != nil {
		return nil, fmt.Errorf("invalid NativeID: could not extract resource group, server, or database name from %s: %w", request.NativeID, err)
	}

	result, err := d.api.Get(ctx, rgName, serverName, dbName, nil)
	if err != nil {
		return &resource.ReadResult{
			ErrorCode: operationErrorCode(err),
		}, nil
	}

	responseProps := d.buildPropertiesFromResult(&result.Database, rgName, serverName)
	propsJSON, err := json.Marshal(responseProps)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}

	return &resource.ReadResult{
		ResourceType: ResourceTypeDatabase,
		Properties:   string(propsJSON),
	}, nil
}

func (d *Database) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	// Database properties (charset, collation) are create-only in Azure.
	// An update is effectively a no-op or requires recreate.
	// We use BeginCreate which is CreateOrUpdate (idempotent).
	rgName, serverName, dbName, err := databaseIDParts(request.NativeID)
	if err != nil {
		return nil, fmt.Errorf("invalid NativeID: could not extract resource group, server, or database name from %s: %w", request.NativeID, err)
	}

	var props map[string]any
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	params := armpostgresqlflexibleservers.Database{
		Properties: &armpostgresqlflexibleservers.DatabaseProperties{},
	}

	if charset, ok := props["charset"].(string); ok && charset != "" {
		params.Properties.Charset = to.Ptr(charset)
	}
	if collation, ok := props["collation"].(string); ok && collation != "" {
		params.Properties.Collation = to.Ptr(collation)
	}

	poller, err := d.api.BeginCreate(ctx, rgName, serverName, dbName, params, nil)
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

		responseProps := d.buildPropertiesFromResult(&result.Database, rgName, serverName)
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

	reqID := lroRequestID{
		OperationType: "update",
		ResumeToken:   resumeToken,
		NativeID:      request.NativeID,
	}
	reqIDJSON, err := json.Marshal(reqID)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request ID: %w", err)
	}

	return &resource.UpdateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationUpdate,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       string(reqIDJSON),
			NativeID:        request.NativeID,
		},
	}, nil
}

func (d *Database) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, serverName, dbName, err := databaseIDParts(request.NativeID)
	if err != nil {
		return nil, fmt.Errorf("invalid NativeID: could not extract resource group, server, or database name from %s: %w", request.NativeID, err)
	}

	poller, err := d.api.BeginDelete(ctx, rgName, serverName, dbName, nil)
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
		}, fmt.Errorf("failed to start Database deletion: %w", err)
	}

	resumeToken, err := poller.ResumeToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get resume token: %w", err)
	}

	reqID := lroRequestID{
		OperationType: "delete",
		ResumeToken:   resumeToken,
		NativeID:      request.NativeID,
	}
	reqIDJSON, err := json.Marshal(reqID)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request ID: %w", err)
	}

	return &resource.DeleteResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationDelete,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       string(reqIDJSON),
			NativeID:        request.NativeID,
		},
	}, nil
}

func (d *Database) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	reqID, err := decodeLROStatus(request.RequestID)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
				StatusMessage:   err.Error(),
			},
		}, err
	}

	switch reqID.OperationType {
	case lroOpCreate, lroOpUpdate:
		return d.statusCreateOrUpdate(ctx, request, &reqID)
	case lroOpDelete:
		return d.statusDelete(ctx, request, &reqID)
	default:
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
				StatusMessage:   fmt.Sprintf("unknown operation type: %s", reqID.OperationType),
			},
		}, fmt.Errorf("unknown operation type: %s", reqID.OperationType)
	}
}

func (d *Database) statusCreateOrUpdate(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	operation := resource.OperationCreate
	if reqID.OperationType == lroOpUpdate {
		operation = resource.OperationUpdate
	}

	return statusLRO(ctx, request, reqID, operation,
		func(token string) (*runtime.Poller[armpostgresqlflexibleservers.DatabasesClientCreateResponse], error) {
			return resumePoller[armpostgresqlflexibleservers.DatabasesClientCreateResponse](d.pipeline, token)
		},
		func(_ context.Context, result armpostgresqlflexibleservers.DatabasesClientCreateResponse, _ resource.Operation) (string, json.RawMessage, error) {
			rgName, serverName, _, err := databaseIDParts(*result.ID)
			if err != nil {
				return "", nil, err
			}
			responseProps := d.buildPropertiesFromResult(&result.Database, rgName, serverName)
			propsJSON, err := json.Marshal(responseProps)
			if err != nil {
				return "", nil, fmt.Errorf("failed to marshal response properties: %w", err)
			}
			return *result.ID, propsJSON, nil
		})
}

func (d *Database) statusDelete(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	return statusDeleteLRO(ctx, request, reqID,
		func(token string) (*runtime.Poller[armpostgresqlflexibleservers.DatabasesClientDeleteResponse], error) {
			return resumePoller[armpostgresqlflexibleservers.DatabasesClientDeleteResponse](d.pipeline, token)
		}, nil)
}

func (d *Database) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	resourceGroupName := request.AdditionalProperties["resourceGroupName"]
	serverName := request.AdditionalProperties["serverName"]

	var nativeIDs []string

	if resourceGroupName != "" && serverName != "" {
		ids, err := d.listByServer(ctx, resourceGroupName, serverName)
		if err != nil {
			return nil, err
		}
		nativeIDs = ids
	} else {
		serverPager := d.api.NewListServersPager(nil)
		for serverPager.More() {
			page, err := serverPager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list flexible servers for database discovery: %w", err)
			}
			for _, server := range page.Value {
				if server.ID == nil {
					continue
				}
				rgName, srvName, err := flexibleServerIDParts(*server.ID)
				if err != nil {
					continue
				}
				ids, err := d.listByServer(ctx, rgName, srvName)
				if err != nil {
					return nil, err
				}
				nativeIDs = append(nativeIDs, ids...)
			}
		}
	}

	return &resource.ListResult{
		NativeIDs: nativeIDs,
	}, nil
}

func (d *Database) listByServer(ctx context.Context, resourceGroupName, serverName string) ([]string, error) {
	pager := d.api.NewListByServerPager(resourceGroupName, serverName, nil)

	var nativeIDs []string

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list databases for server %s: %w", serverName, err)
		}
		for _, db := range page.Value {
			if db.ID != nil {
				nativeIDs = append(nativeIDs, *db.ID)
			}
		}
	}

	return nativeIDs, nil
}
