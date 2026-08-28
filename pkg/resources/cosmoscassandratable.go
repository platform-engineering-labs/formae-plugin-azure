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

const ResourceTypeCosmosCassandraTable = "AZURE::DocumentDB::CassandraTable"

// cosmosCassandraTableAPI is the armcosmos.CassandraResourcesClient surface used here.
type cosmosCassandraTableAPI interface {
	BeginCreateUpdateCassandraTable(ctx context.Context, resourceGroupName string, accountName string, keyspaceName string, tableName string, createUpdateCassandraTableParameters armcosmos.CassandraTableCreateUpdateParameters, options *armcosmos.CassandraResourcesClientBeginCreateUpdateCassandraTableOptions) (*runtime.Poller[armcosmos.CassandraResourcesClientCreateUpdateCassandraTableResponse], error)
	GetCassandraTable(ctx context.Context, resourceGroupName string, accountName string, keyspaceName string, tableName string, options *armcosmos.CassandraResourcesClientGetCassandraTableOptions) (armcosmos.CassandraResourcesClientGetCassandraTableResponse, error)
	GetCassandraTableThroughput(ctx context.Context, resourceGroupName string, accountName string, keyspaceName string, tableName string, options *armcosmos.CassandraResourcesClientGetCassandraTableThroughputOptions) (armcosmos.CassandraResourcesClientGetCassandraTableThroughputResponse, error)
	BeginDeleteCassandraTable(ctx context.Context, resourceGroupName string, accountName string, keyspaceName string, tableName string, options *armcosmos.CassandraResourcesClientBeginDeleteCassandraTableOptions) (*runtime.Poller[armcosmos.CassandraResourcesClientDeleteCassandraTableResponse], error)
	NewListCassandraTablesPager(resourceGroupName string, accountName string, keyspaceName string, options *armcosmos.CassandraResourcesClientListCassandraTablesOptions) *runtime.Pager[armcosmos.CassandraResourcesClientListCassandraTablesResponse]
}

func init() {
	registry.Register(ResourceTypeCosmosCassandraTable, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &CosmosCassandraTable{
			api:      c.CosmosCassandraResourcesClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// CosmosCassandraTable is the provisioner for Cosmos DB Cassandra-API tables
// (`.../databaseAccounts/<account>/cassandraKeyspaces/<keyspace>/tables/<name>`).
//
// It is a child of AZURE::DocumentDB::CassandraKeyspace.
type CosmosCassandraTable struct {
	api      cosmosCassandraTableAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

// cosmosCassandraTableProps mirrors
// schema/pkl/documentdb/cosmoscassandratable.pkl.
type cosmosCassandraTableProps struct {
	Name                 string                      `json:"name"`
	ResourceGroupName    string                      `json:"resourceGroupName"`
	AccountName          string                      `json:"accountName"`
	KeyspaceName         string                      `json:"keyspaceName"`
	Schema               *cosmosCassandraSchemaProps `json:"schema"`
	DefaultTtl           *int32                      `json:"defaultTtl"`
	AnalyticalStorageTtl *int32                      `json:"analyticalStorageTtl"`
	cosmosChildThroughput
}

type cosmosCassandraSchemaProps struct {
	Columns       []cosmosCassandraColumnProps     `json:"columns"`
	PartitionKeys []cosmosCassandraPartitionKey    `json:"partitionKeys"`
	ClusterKeys   []cosmosCassandraClusterKeyProps `json:"clusterKeys"`
}

type cosmosCassandraColumnProps struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type cosmosCassandraPartitionKey struct {
	Name string `json:"name"`
}

type cosmosCassandraClusterKeyProps struct {
	Name    string `json:"name"`
	OrderBy string `json:"orderBy"`
}

func cosmosCassandraTableIDParts(resourceID string) (rgName, accountName, keyspaceName, tableName string, err error) {
	rgName, names, err := armExactIDParts(resourceID, "databaseAccounts", "cassandraKeyspaces", "tables")
	if err != nil {
		return "", "", "", "", err
	}
	return rgName, names[0], names[1], names[2], nil
}

func (t *CosmosCassandraTable) throughput(ctx context.Context, rgName, accountName, keyspaceName, tableName string) *armcosmos.ThroughputSettingsGetPropertiesResource {
	result, err := t.api.GetCassandraTableThroughput(ctx, rgName, accountName, keyspaceName, tableName, nil)
	if err != nil || result.Properties == nil {
		return nil
	}
	return result.Properties.Resource
}

func (t *CosmosCassandraTable) serialize(ctx context.Context, result armcosmos.CassandraTableGetResults, rgName, accountName, keyspaceName, tableName string) (json.RawMessage, error) {
	props := map[string]any{
		"resourceGroupName": rgName,
		"accountName":       accountName,
		"keyspaceName":      keyspaceName,
		"name":              tableName,
	}
	if result.ID != nil {
		props["id"] = *result.ID
	}
	if result.Name != nil && *result.Name != "" {
		props["name"] = *result.Name
	}

	if result.Properties != nil && result.Properties.Resource != nil {
		res := result.Properties.Resource
		if schema := cosmosCassandraSchemaFromARM(res.Schema); schema != nil {
			props["schema"] = schema
		}
		if res.DefaultTTL != nil {
			props["defaultTtl"] = *res.DefaultTTL
		}
		if res.AnalyticalStorageTTL != nil {
			props["analyticalStorageTtl"] = *res.AnalyticalStorageTTL
		}
	}

	cosmosPutThroughput(props, t.throughput(ctx, rgName, accountName, keyspaceName, tableName))

	out, err := json.Marshal(props)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return out, nil
}

func cosmosCassandraSchemaToARM(schema *cosmosCassandraSchemaProps) *armcosmos.CassandraSchema {
	if schema == nil {
		return nil
	}
	out := &armcosmos.CassandraSchema{}
	for _, column := range schema.Columns {
		out.Columns = append(out.Columns, &armcosmos.Column{
			Name: to.Ptr(column.Name),
			Type: to.Ptr(column.Type),
		})
	}
	for _, key := range schema.PartitionKeys {
		out.PartitionKeys = append(out.PartitionKeys, &armcosmos.CassandraPartitionKey{Name: to.Ptr(key.Name)})
	}
	for _, key := range schema.ClusterKeys {
		entry := &armcosmos.ClusterKey{Name: to.Ptr(key.Name)}
		if key.OrderBy != "" {
			entry.OrderBy = to.Ptr(key.OrderBy)
		}
		out.ClusterKeys = append(out.ClusterKeys, entry)
	}
	return out
}

func cosmosCassandraSchemaFromARM(schema *armcosmos.CassandraSchema) map[string]any {
	if schema == nil {
		return nil
	}
	entry := map[string]any{}

	columns := make([]map[string]any, 0, len(schema.Columns))
	for _, column := range schema.Columns {
		if column == nil || column.Name == nil {
			continue
		}
		rendered := map[string]any{"name": *column.Name}
		if column.Type != nil {
			rendered["type"] = *column.Type
		}
		columns = append(columns, rendered)
	}
	if len(columns) > 0 {
		entry["columns"] = columns
	}

	partitionKeys := make([]map[string]any, 0, len(schema.PartitionKeys))
	for _, key := range schema.PartitionKeys {
		if key == nil || key.Name == nil {
			continue
		}
		partitionKeys = append(partitionKeys, map[string]any{"name": *key.Name})
	}
	if len(partitionKeys) > 0 {
		entry["partitionKeys"] = partitionKeys
	}

	clusterKeys := make([]map[string]any, 0, len(schema.ClusterKeys))
	for _, key := range schema.ClusterKeys {
		if key == nil || key.Name == nil {
			continue
		}
		rendered := map[string]any{"name": *key.Name}
		if key.OrderBy != nil {
			rendered["orderBy"] = canonicalizeEnum(*key.OrderBy, "Asc", "Desc")
		}
		clusterKeys = append(clusterKeys, rendered)
	}
	if len(clusterKeys) > 0 {
		entry["clusterKeys"] = clusterKeys
	}

	if len(entry) == 0 {
		return nil
	}
	return entry
}

func cosmosCassandraTableResource(props cosmosCassandraTableProps, name string) *armcosmos.CassandraTableResource {
	return &armcosmos.CassandraTableResource{
		ID:                   to.Ptr(name),
		Schema:               cosmosCassandraSchemaToARM(props.Schema),
		DefaultTTL:           props.DefaultTtl,
		AnalyticalStorageTTL: props.AnalyticalStorageTtl,
	}
}

func (t *CosmosCassandraTable) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props cosmosCassandraTableProps
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	if props.AccountName == "" {
		return nil, fmt.Errorf("accountName is required")
	}
	if props.KeyspaceName == "" {
		return nil, fmt.Errorf("keyspaceName is required")
	}
	if props.Name == "" {
		props.Name = request.Label
	}
	if props.Name == "" {
		return nil, fmt.Errorf("name is required")
	}
	if props.Schema == nil || len(props.Schema.Columns) == 0 || len(props.Schema.PartitionKeys) == 0 {
		return nil, fmt.Errorf("schema with at least one column and one partitionKey is required")
	}

	options, err := cosmosCreateUpdateOptions(props.cosmosChildThroughput)
	if err != nil {
		return nil, err
	}
	params := armcosmos.CassandraTableCreateUpdateParameters{
		Properties: &armcosmos.CassandraTableCreateUpdateProperties{
			Resource: cosmosCassandraTableResource(props, props.Name),
			Options:  options,
		},
	}

	poller, err := t.api.BeginCreateUpdateCassandraTable(ctx, props.ResourceGroupName, props.AccountName,
		props.KeyspaceName, props.Name, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	expectedNativeID := cosmosChildNativeID(t.config.SubscriptionId, props.ResourceGroupName, props.AccountName,
		"cassandraKeyspaces", props.KeyspaceName, "tables", props.Name)

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
		propsJSON, err := t.serialize(ctx, result.CassandraTableGetResults, props.ResourceGroupName,
			props.AccountName, props.KeyspaceName, props.Name)
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

func (t *CosmosCassandraTable) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, accountName, keyspaceName, tableName, err := cosmosCassandraTableIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := t.api.GetCassandraTable(ctx, rgName, accountName, keyspaceName, tableName, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := t.serialize(ctx, result.CassandraTableGetResults, rgName, accountName, keyspaceName, tableName)
	if err != nil {
		return nil, err
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeCosmosCassandraTable,
		Properties:   string(propsJSON),
	}, nil
}

// Update re-PUTs the table body. Cassandra permits adding columns in place but not
// changing the partition or cluster keys, so `schema` stays updatable while the
// rest of the identity-shaped fields are createOnly.
func (t *CosmosCassandraTable) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, accountName, keyspaceName, tableName, err := cosmosCassandraTableIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props cosmosCassandraTableProps
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	params := armcosmos.CassandraTableCreateUpdateParameters{
		Properties: &armcosmos.CassandraTableCreateUpdateProperties{
			Resource: cosmosCassandraTableResource(props, tableName),
		},
	}

	poller, err := t.api.BeginCreateUpdateCassandraTable(ctx, rgName, accountName, keyspaceName, tableName, params, nil)
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
		propsJSON, err := t.serialize(ctx, result.CassandraTableGetResults, rgName, accountName, keyspaceName, tableName)
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

func (t *CosmosCassandraTable) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, accountName, keyspaceName, tableName, err := cosmosCassandraTableIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, err := t.api.BeginDeleteCassandraTable(ctx, rgName, accountName, keyspaceName, tableName, nil)
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

func (t *CosmosCassandraTable) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	reqID, err := decodeLROStatus(request.RequestID)
	if err != nil {
		return nil, err
	}

	complete := func(ctx context.Context, result armcosmos.CassandraResourcesClientCreateUpdateCassandraTableResponse, _ resource.Operation) (string, json.RawMessage, error) {
		nativeID := reqID.NativeID
		if result.ID != nil {
			nativeID = *result.ID
		}
		rgName, accountName, keyspaceName, tableName, err := cosmosCassandraTableIDParts(nativeID)
		if err != nil {
			return "", nil, err
		}
		propsJSON, err := t.serialize(ctx, result.CassandraTableGetResults, rgName, accountName, keyspaceName, tableName)
		if err != nil {
			return "", nil, err
		}
		return nativeID, propsJSON, nil
	}
	resume := func(token string) (*runtime.Poller[armcosmos.CassandraResourcesClientCreateUpdateCassandraTableResponse], error) {
		return resumePoller[armcosmos.CassandraResourcesClientCreateUpdateCassandraTableResponse](t.pipeline, token)
	}

	switch reqID.OperationType {
	case lroOpCreate:
		return statusLRO(ctx, request, &reqID, resource.OperationCreate, resume, complete)
	case lroOpUpdate:
		return statusLRO(ctx, request, &reqID, resource.OperationUpdate, resume, complete)
	case lroOpDelete:
		return statusDeleteLRO(ctx, request, &reqID,
			func(token string) (*runtime.Poller[armcosmos.CassandraResourcesClientDeleteCassandraTableResponse], error) {
				return resumePoller[armcosmos.CassandraResourcesClientDeleteCassandraTableResponse](t.pipeline, token)
			}, nil)
	default:
		return nil, fmt.Errorf("unknown operation type: %s", reqID.OperationType)
	}
}

func (t *CosmosCassandraTable) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	accountName := request.AdditionalProperties["accountName"]
	keyspaceName := request.AdditionalProperties["keyspaceName"]

	var nativeIDs []string
	pager := t.api.NewListCassandraTablesPager(rgName, accountName, keyspaceName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list Cosmos Cassandra tables in keyspace %s: %w", keyspaceName, err)
		}
		for _, table := range page.Value {
			if table.ID != nil {
				nativeIDs = append(nativeIDs, *table.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
