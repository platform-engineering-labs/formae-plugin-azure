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

const ResourceTypeSQLDatabase = "AZURE::Sql::Database"

type sqlDatabasesAPI interface {
	BeginCreateOrUpdate(ctx context.Context, resourceGroupName string, serverName string, databaseName string, parameters armsql.Database, options *armsql.DatabasesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armsql.DatabasesClientCreateOrUpdateResponse], error)
	Get(ctx context.Context, resourceGroupName string, serverName string, databaseName string, options *armsql.DatabasesClientGetOptions) (armsql.DatabasesClientGetResponse, error)
	BeginUpdate(ctx context.Context, resourceGroupName string, serverName string, databaseName string, parameters armsql.DatabaseUpdate, options *armsql.DatabasesClientBeginUpdateOptions) (*runtime.Poller[armsql.DatabasesClientUpdateResponse], error)
	BeginDelete(ctx context.Context, resourceGroupName string, serverName string, databaseName string, options *armsql.DatabasesClientBeginDeleteOptions) (*runtime.Poller[armsql.DatabasesClientDeleteResponse], error)
	NewListByServerPager(resourceGroupName string, serverName string, options *armsql.DatabasesClientListByServerOptions) *runtime.Pager[armsql.DatabasesClientListByServerResponse]
	// NewListServersPager enumerates SQL servers so databases can be discovered
	// even when no parent server is supplied via AdditionalProperties.
	NewListServersPager(options *armsql.ServersClientListOptions) *runtime.Pager[armsql.ServersClientListResponse]
}

// sqlDatabasesClientWrapper composes the SDK Databases client with the parent
// Servers client so List can fall back to enumerating servers.
type sqlDatabasesClientWrapper struct {
	*armsql.DatabasesClient
	serversClient *armsql.ServersClient
}

func (w *sqlDatabasesClientWrapper) NewListServersPager(options *armsql.ServersClientListOptions) *runtime.Pager[armsql.ServersClientListResponse] {
	return w.serversClient.NewListPager(options)
}

func init() {
	registry.Register(ResourceTypeSQLDatabase, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &SqlDatabase{
			api: &sqlDatabasesClientWrapper{
				DatabasesClient: c.SQLDatabasesClient,
				serversClient:   c.SQLServersClient,
			},
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// SqlDatabase is the provisioner for Azure SQL Database (Microsoft.Sql/servers/databases).
type SqlDatabase struct {
	api      sqlDatabasesAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

func sqlDatabaseIDParts(resourceID string) (rgName, serverName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "servers", "databases")
	if err != nil {
		return "", "", "", err
	}
	return rgName, names["servers"], names["databases"], nil
}

// buildPropertiesFromResult extracts properties from a SQL Database Azure response.
func (d *SqlDatabase) buildPropertiesFromResult(db *armsql.Database, rgName, serverName string) map[string]any {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	props["serverName"] = serverName

	if db.ID != nil {
		props["id"] = *db.ID
	}
	if db.Name != nil {
		props["name"] = *db.Name
	}
	if db.Location != nil {
		props["location"] = strings.ToLower(strings.ReplaceAll(*db.Location, " ", ""))
	}

	if sku := db.SKU; sku != nil {
		s := make(map[string]any)
		if sku.Name != nil {
			s["name"] = *sku.Name
		}
		if sku.Tier != nil {
			s["tier"] = *sku.Tier
		}
		if sku.Capacity != nil {
			s["capacity"] = *sku.Capacity
		}
		if len(s) > 0 {
			props["sku"] = s
		}
	}

	if db.Properties != nil {
		if db.Properties.Collation != nil {
			props["collation"] = *db.Properties.Collation
		}
		if db.Properties.MaxSizeBytes != nil {
			props["maxSizeBytes"] = *db.Properties.MaxSizeBytes
		}
		if db.Properties.Status != nil {
			props["status"] = string(*db.Properties.Status)
		}
		if db.Properties.DatabaseID != nil {
			props["databaseId"] = *db.Properties.DatabaseID
		}
	}

	if tags := azureTagsToFormaeTags(db.Tags); tags != nil {
		props["Tags"] = tags
	}

	return props
}

// buildDatabaseParams constructs the armsql.Database create/update payload.
func buildDatabaseParams(props map[string]any, location string) armsql.Database {
	dbProps := &armsql.DatabaseProperties{}
	if v, ok := props["collation"].(string); ok && v != "" {
		dbProps.Collation = to.Ptr(v)
	}
	if v, ok := maxSizeBytes(props["maxSizeBytes"]); ok {
		dbProps.MaxSizeBytes = to.Ptr(v)
	}

	params := armsql.Database{
		Location:   to.Ptr(location),
		Properties: dbProps,
	}
	if sku := buildDatabaseSKU(props); sku != nil {
		params.SKU = sku
	}
	return params
}

func buildDatabaseSKU(props map[string]any) *armsql.SKU {
	raw, ok := props["sku"].(map[string]any)
	if !ok {
		return nil
	}
	sku := &armsql.SKU{}
	if v, ok := raw["name"].(string); ok && v != "" {
		sku.Name = to.Ptr(v)
	}
	if v, ok := raw["tier"].(string); ok && v != "" {
		sku.Tier = to.Ptr(v)
	}
	if v, ok := capacity(raw["capacity"]); ok {
		sku.Capacity = to.Ptr(v)
	}
	if sku.Name == nil {
		return nil
	}
	return sku
}

// maxSizeBytes coerces a JSON number (float64) into an int64.
func maxSizeBytes(v any) (int64, bool) {
	switch n := v.(type) {
	case float64:
		return int64(n), true
	case int64:
		return n, true
	case int:
		return int64(n), true
	default:
		return 0, false
	}
}

// capacity coerces a JSON number (float64) into an int32.
func capacity(v any) (int32, bool) {
	switch n := v.(type) {
	case float64:
		return int32(n), true
	case int32:
		return n, true
	case int:
		return int32(n), true
	default:
		return 0, false
	}
}

func (d *SqlDatabase) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
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
	location, ok := props["location"].(string)
	if !ok || location == "" {
		return nil, fmt.Errorf("location is required")
	}
	dbName, ok := props["name"].(string)
	if !ok || dbName == "" {
		dbName = request.Label
	}

	params := buildDatabaseParams(props, location)
	if azureTags := formaeTagsToAzureTags(request.Properties); azureTags != nil {
		params.Tags = azureTags
	}

	poller, err := d.api.BeginCreateOrUpdate(ctx, rgName, serverName, dbName, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Sql/servers/%s/databases/%s",
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

func (d *SqlDatabase) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, serverName, dbName, err := sqlDatabaseIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := d.api.Get(ctx, rgName, serverName, dbName, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	responseProps := d.buildPropertiesFromResult(&result.Database, rgName, serverName)
	propsJSON, err := json.Marshal(responseProps)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeSQLDatabase,
		Properties:   string(propsJSON),
	}, nil
}

func (d *SqlDatabase) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, serverName, dbName, err := sqlDatabaseIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props map[string]any
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	updateProps := &armsql.DatabaseUpdateProperties{}
	if v, ok := maxSizeBytes(props["maxSizeBytes"]); ok {
		updateProps.MaxSizeBytes = to.Ptr(v)
	}

	params := armsql.DatabaseUpdate{Properties: updateProps}
	if sku := buildDatabaseSKU(props); sku != nil {
		params.SKU = sku
	}
	if azureTags := formaeTagsToAzureTags(request.DesiredProperties); azureTags != nil {
		params.Tags = azureTags
	}

	poller, err := d.api.BeginUpdate(ctx, rgName, serverName, dbName, params, nil)
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

func (d *SqlDatabase) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, serverName, dbName, err := sqlDatabaseIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, err := d.api.BeginDelete(ctx, rgName, serverName, dbName, nil)
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

func (d *SqlDatabase) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	reqID, err := decodeLROStatus(request.RequestID)
	if err != nil {
		return nil, err
	}

	switch reqID.OperationType {
	case lroOpCreate:
		return statusLRO(ctx, request, &reqID, resource.OperationCreate,
			func(token string) (*runtime.Poller[armsql.DatabasesClientCreateOrUpdateResponse], error) {
				return resumePoller[armsql.DatabasesClientCreateOrUpdateResponse](d.pipeline, token)
			},
			func(_ context.Context, result armsql.DatabasesClientCreateOrUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				return d.completeFromDatabase(&result.Database)
			})
	case lroOpUpdate:
		return statusLRO(ctx, request, &reqID, resource.OperationUpdate,
			func(token string) (*runtime.Poller[armsql.DatabasesClientUpdateResponse], error) {
				return resumePoller[armsql.DatabasesClientUpdateResponse](d.pipeline, token)
			},
			func(_ context.Context, result armsql.DatabasesClientUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				return d.completeFromDatabase(&result.Database)
			})
	case lroOpDelete:
		return statusDeleteLRO(ctx, request, &reqID,
			func(token string) (*runtime.Poller[armsql.DatabasesClientDeleteResponse], error) {
				return resumePoller[armsql.DatabasesClientDeleteResponse](d.pipeline, token)
			}, nil)
	default:
		return nil, fmt.Errorf("unknown operation type: %s", reqID.OperationType)
	}
}

func (d *SqlDatabase) completeFromDatabase(db *armsql.Database) (string, json.RawMessage, error) {
	nativeID := ""
	rgName, serverName := "", ""
	if db.ID != nil {
		nativeID = *db.ID
		if rg, srv, _, err := sqlDatabaseIDParts(*db.ID); err == nil {
			rgName, serverName = rg, srv
		}
	}
	propsJSON, err := json.Marshal(d.buildPropertiesFromResult(db, rgName, serverName))
	if err != nil {
		return "", nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return nativeID, propsJSON, nil
}

func (d *SqlDatabase) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	serverName := request.AdditionalProperties["serverName"]

	var nativeIDs []string

	if rgName != "" && serverName != "" {
		ids, err := d.listByServer(ctx, rgName, serverName)
		if err != nil {
			return nil, err
		}
		return &resource.ListResult{NativeIDs: ids}, nil
	}

	serverPager := d.api.NewListServersPager(nil)
	for serverPager.More() {
		page, err := serverPager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list sql servers for database discovery: %w", err)
		}
		for _, server := range page.Value {
			if server.ID == nil {
				continue
			}
			rg, srv, err := sqlServerIDParts(*server.ID)
			if err != nil {
				continue
			}
			ids, err := d.listByServer(ctx, rg, srv)
			if err != nil {
				return nil, err
			}
			nativeIDs = append(nativeIDs, ids...)
		}
	}

	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}

func (d *SqlDatabase) listByServer(ctx context.Context, rgName, serverName string) ([]string, error) {
	pager := d.api.NewListByServerPager(rgName, serverName, nil)

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
