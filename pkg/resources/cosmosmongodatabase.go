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

const ResourceTypeCosmosMongoDatabase = "AZURE::DocumentDB::MongoDatabase"

// cosmosMongoDatabaseAPI is the armcosmos.MongoDBResourcesClient surface used here.
type cosmosMongoDatabaseAPI interface {
	BeginCreateUpdateMongoDBDatabase(ctx context.Context, resourceGroupName string, accountName string, databaseName string, createUpdateMongoDBDatabaseParameters armcosmos.MongoDBDatabaseCreateUpdateParameters, options *armcosmos.MongoDBResourcesClientBeginCreateUpdateMongoDBDatabaseOptions) (*runtime.Poller[armcosmos.MongoDBResourcesClientCreateUpdateMongoDBDatabaseResponse], error)
	GetMongoDBDatabase(ctx context.Context, resourceGroupName string, accountName string, databaseName string, options *armcosmos.MongoDBResourcesClientGetMongoDBDatabaseOptions) (armcosmos.MongoDBResourcesClientGetMongoDBDatabaseResponse, error)
	GetMongoDBDatabaseThroughput(ctx context.Context, resourceGroupName string, accountName string, databaseName string, options *armcosmos.MongoDBResourcesClientGetMongoDBDatabaseThroughputOptions) (armcosmos.MongoDBResourcesClientGetMongoDBDatabaseThroughputResponse, error)
	BeginDeleteMongoDBDatabase(ctx context.Context, resourceGroupName string, accountName string, databaseName string, options *armcosmos.MongoDBResourcesClientBeginDeleteMongoDBDatabaseOptions) (*runtime.Poller[armcosmos.MongoDBResourcesClientDeleteMongoDBDatabaseResponse], error)
	NewListMongoDBDatabasesPager(resourceGroupName string, accountName string, options *armcosmos.MongoDBResourcesClientListMongoDBDatabasesOptions) *runtime.Pager[armcosmos.MongoDBResourcesClientListMongoDBDatabasesResponse]
}

func init() {
	registry.Register(ResourceTypeCosmosMongoDatabase, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &CosmosMongoDatabase{
			api:      c.CosmosMongoDBResourcesClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// CosmosMongoDatabase is the provisioner for Cosmos DB MongoDB-API databases
// (`.../databaseAccounts/<account>/mongodbDatabases/<name>`).
//
// The parent account must have been created with `kind = "MongoDB"`; a
// GlobalDocumentDB account rejects these.
type CosmosMongoDatabase struct {
	api      cosmosMongoDatabaseAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

// cosmosMongoDatabaseProps mirrors schema/pkl/documentdb/cosmosmongodatabase.pkl.
type cosmosMongoDatabaseProps struct {
	Name              string `json:"name"`
	ResourceGroupName string `json:"resourceGroupName"`
	AccountName       string `json:"accountName"`
	cosmosChildThroughput
}

func cosmosMongoDatabaseIDParts(resourceID string) (rgName, accountName, dbName string, err error) {
	rgName, names, err := armExactIDParts(resourceID, "databaseAccounts", "mongodbDatabases")
	if err != nil {
		return "", "", "", err
	}
	return rgName, names[0], names[1], nil
}

// throughput reads shared database RU/s back; any error means there is none. See
// CosmosSqlDatabase.throughput for why the error is swallowed.
func (d *CosmosMongoDatabase) throughput(ctx context.Context, rgName, accountName, dbName string) *armcosmos.ThroughputSettingsGetPropertiesResource {
	result, err := d.api.GetMongoDBDatabaseThroughput(ctx, rgName, accountName, dbName, nil)
	if err != nil || result.Properties == nil {
		return nil
	}
	return result.Properties.Resource
}

func (d *CosmosMongoDatabase) serialize(ctx context.Context, result armcosmos.MongoDBDatabaseGetResults, rgName, accountName, dbName string) (json.RawMessage, error) {
	props := map[string]any{
		"resourceGroupName": rgName,
		"accountName":       accountName,
		"name":              dbName,
	}
	if result.ID != nil {
		props["id"] = *result.ID
	}
	if result.Name != nil && *result.Name != "" {
		props["name"] = *result.Name
	}
	cosmosPutThroughput(props, d.throughput(ctx, rgName, accountName, dbName))

	out, err := json.Marshal(props)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return out, nil
}

func (d *CosmosMongoDatabase) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props cosmosMongoDatabaseProps
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

	options, err := cosmosCreateUpdateOptions(props.cosmosChildThroughput)
	if err != nil {
		return nil, err
	}
	params := armcosmos.MongoDBDatabaseCreateUpdateParameters{
		Properties: &armcosmos.MongoDBDatabaseCreateUpdateProperties{
			Resource: &armcosmos.MongoDBDatabaseResource{ID: to.Ptr(props.Name)},
			Options:  options,
		},
	}

	poller, err := d.api.BeginCreateUpdateMongoDBDatabase(ctx, props.ResourceGroupName, props.AccountName, props.Name, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	expectedNativeID := cosmosChildNativeID(d.config.SubscriptionId, props.ResourceGroupName, props.AccountName,
		"mongodbDatabases", props.Name)

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
		propsJSON, err := d.serialize(ctx, result.MongoDBDatabaseGetResults, props.ResourceGroupName, props.AccountName, props.Name)
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

func (d *CosmosMongoDatabase) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, accountName, dbName, err := cosmosMongoDatabaseIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := d.api.GetMongoDBDatabase(ctx, rgName, accountName, dbName, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := d.serialize(ctx, result.MongoDBDatabaseGetResults, rgName, accountName, dbName)
	if err != nil {
		return nil, err
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeCosmosMongoDatabase,
		Properties:   string(propsJSON),
	}, nil
}

// Update re-PUTs the database body. Throughput is not sent: both throughput fields
// are createOnly, and `options` only takes effect at create time.
func (d *CosmosMongoDatabase) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, accountName, dbName, err := cosmosMongoDatabaseIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	params := armcosmos.MongoDBDatabaseCreateUpdateParameters{
		Properties: &armcosmos.MongoDBDatabaseCreateUpdateProperties{
			Resource: &armcosmos.MongoDBDatabaseResource{ID: to.Ptr(dbName)},
		},
	}

	poller, err := d.api.BeginCreateUpdateMongoDBDatabase(ctx, rgName, accountName, dbName, params, nil)
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
		propsJSON, err := d.serialize(ctx, result.MongoDBDatabaseGetResults, rgName, accountName, dbName)
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

func (d *CosmosMongoDatabase) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, accountName, dbName, err := cosmosMongoDatabaseIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, err := d.api.BeginDeleteMongoDBDatabase(ctx, rgName, accountName, dbName, nil)
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

func (d *CosmosMongoDatabase) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	reqID, err := decodeLROStatus(request.RequestID)
	if err != nil {
		return nil, err
	}

	complete := func(ctx context.Context, result armcosmos.MongoDBResourcesClientCreateUpdateMongoDBDatabaseResponse, _ resource.Operation) (string, json.RawMessage, error) {
		nativeID := reqID.NativeID
		if result.ID != nil {
			nativeID = *result.ID
		}
		rgName, accountName, dbName, err := cosmosMongoDatabaseIDParts(nativeID)
		if err != nil {
			return "", nil, err
		}
		propsJSON, err := d.serialize(ctx, result.MongoDBDatabaseGetResults, rgName, accountName, dbName)
		if err != nil {
			return "", nil, err
		}
		return nativeID, propsJSON, nil
	}
	resume := func(token string) (*runtime.Poller[armcosmos.MongoDBResourcesClientCreateUpdateMongoDBDatabaseResponse], error) {
		return resumePoller[armcosmos.MongoDBResourcesClientCreateUpdateMongoDBDatabaseResponse](d.pipeline, token)
	}

	switch reqID.OperationType {
	case lroOpCreate:
		return statusLRO(ctx, request, &reqID, resource.OperationCreate, resume, complete)
	case lroOpUpdate:
		return statusLRO(ctx, request, &reqID, resource.OperationUpdate, resume, complete)
	case lroOpDelete:
		return statusDeleteLRO(ctx, request, &reqID,
			func(token string) (*runtime.Poller[armcosmos.MongoDBResourcesClientDeleteMongoDBDatabaseResponse], error) {
				return resumePoller[armcosmos.MongoDBResourcesClientDeleteMongoDBDatabaseResponse](d.pipeline, token)
			}, nil)
	default:
		return nil, fmt.Errorf("unknown operation type: %s", reqID.OperationType)
	}
}

func (d *CosmosMongoDatabase) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	accountName := request.AdditionalProperties["accountName"]

	var nativeIDs []string
	pager := d.api.NewListMongoDBDatabasesPager(rgName, accountName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list Cosmos MongoDB databases in account %s: %w", accountName, err)
		}
		for _, db := range page.Value {
			if db.ID != nil {
				nativeIDs = append(nativeIDs, *db.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
