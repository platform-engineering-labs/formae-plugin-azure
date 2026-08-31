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

const ResourceTypeCosmosMongoCollection = "AZURE::DocumentDB::MongoCollection"

// cosmosMongoCollectionAPI is the armcosmos.MongoDBResourcesClient surface used here.
type cosmosMongoCollectionAPI interface {
	BeginCreateUpdateMongoDBCollection(ctx context.Context, resourceGroupName string, accountName string, databaseName string, collectionName string, createUpdateMongoDBCollectionParameters armcosmos.MongoDBCollectionCreateUpdateParameters, options *armcosmos.MongoDBResourcesClientBeginCreateUpdateMongoDBCollectionOptions) (*runtime.Poller[armcosmos.MongoDBResourcesClientCreateUpdateMongoDBCollectionResponse], error)
	GetMongoDBCollection(ctx context.Context, resourceGroupName string, accountName string, databaseName string, collectionName string, options *armcosmos.MongoDBResourcesClientGetMongoDBCollectionOptions) (armcosmos.MongoDBResourcesClientGetMongoDBCollectionResponse, error)
	GetMongoDBCollectionThroughput(ctx context.Context, resourceGroupName string, accountName string, databaseName string, collectionName string, options *armcosmos.MongoDBResourcesClientGetMongoDBCollectionThroughputOptions) (armcosmos.MongoDBResourcesClientGetMongoDBCollectionThroughputResponse, error)
	BeginDeleteMongoDBCollection(ctx context.Context, resourceGroupName string, accountName string, databaseName string, collectionName string, options *armcosmos.MongoDBResourcesClientBeginDeleteMongoDBCollectionOptions) (*runtime.Poller[armcosmos.MongoDBResourcesClientDeleteMongoDBCollectionResponse], error)
	NewListMongoDBCollectionsPager(resourceGroupName string, accountName string, databaseName string, options *armcosmos.MongoDBResourcesClientListMongoDBCollectionsOptions) *runtime.Pager[armcosmos.MongoDBResourcesClientListMongoDBCollectionsResponse]
}

func init() {
	registry.Register(ResourceTypeCosmosMongoCollection, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &CosmosMongoCollection{
			api:      c.CosmosMongoDBResourcesClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// CosmosMongoCollection is the provisioner for Cosmos DB MongoDB-API collections
// (`.../databaseAccounts/<account>/mongodbDatabases/<database>/collections/<name>`).
//
// It is a child of AZURE::DocumentDB::MongoDatabase.
type CosmosMongoCollection struct {
	api      cosmosMongoCollectionAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

// cosmosMongoCollectionProps mirrors
// schema/pkl/documentdb/cosmosmongocollection.pkl.
type cosmosMongoCollectionProps struct {
	Name                 string                  `json:"name"`
	ResourceGroupName    string                  `json:"resourceGroupName"`
	AccountName          string                  `json:"accountName"`
	DatabaseName         string                  `json:"databaseName"`
	ShardKey             []cosmosMongoShardKey   `json:"shardKey"`
	Indexes              []cosmosMongoIndexProps `json:"indexes"`
	AnalyticalStorageTtl *int32                  `json:"analyticalStorageTtl"`
	cosmosChildThroughput
}

// cosmosMongoShardKey is the entity-set rendering of ARM's `shardKey` map. ARM
// takes `{"<field>": "Hash"}`; formae models maps as a Key/Value listing so the
// entries are individually addressable.
//
// The key is a MongoDB field name, not a SQL-API partition key path: the Mongo RP
// uses it verbatim as an index key, so a leading slash fails the create with
// `BadRequest: Invalid index key '/<field>' specified.`
type cosmosMongoShardKey struct {
	Key   string `json:"Key"`
	Value string `json:"Value"`
}

type cosmosMongoIndexProps struct {
	Keys               []string `json:"keys"`
	Unique             *bool    `json:"unique"`
	ExpireAfterSeconds *int32   `json:"expireAfterSeconds"`
}

func cosmosMongoCollectionIDParts(resourceID string) (rgName, accountName, dbName, collectionName string, err error) {
	rgName, names, err := armExactIDParts(resourceID, "databaseAccounts", "mongodbDatabases", "collections")
	if err != nil {
		return "", "", "", "", err
	}
	return rgName, names[0], names[1], names[2], nil
}

func (c *CosmosMongoCollection) throughput(ctx context.Context, rgName, accountName, dbName, collectionName string) *armcosmos.ThroughputSettingsGetPropertiesResource {
	result, err := c.api.GetMongoDBCollectionThroughput(ctx, rgName, accountName, dbName, collectionName, nil)
	if err != nil || result.Properties == nil {
		return nil
	}
	return result.Properties.Resource
}

func (c *CosmosMongoCollection) serialize(ctx context.Context, result armcosmos.MongoDBCollectionGetResults, rgName, accountName, dbName, collectionName string) (json.RawMessage, error) {
	props := map[string]any{
		"resourceGroupName": rgName,
		"accountName":       accountName,
		"databaseName":      dbName,
		"name":              collectionName,
	}
	if result.ID != nil {
		props["id"] = *result.ID
	}
	if result.Name != nil && *result.Name != "" {
		props["name"] = *result.Name
	}

	if result.Properties != nil && result.Properties.Resource != nil {
		res := result.Properties.Resource
		shardKeys := make([]map[string]string, 0, len(res.ShardKey))
		for key, value := range res.ShardKey {
			if value == nil {
				continue
			}
			shardKeys = append(shardKeys, map[string]string{"Key": key, "Value": *value})
		}
		if len(shardKeys) > 0 {
			props["shardKey"] = shardKeys
		}

		indexes := make([]map[string]any, 0, len(res.Indexes))
		for _, index := range res.Indexes {
			if index == nil {
				continue
			}
			entry := map[string]any{}
			if index.Key != nil {
				if keys := stringsFromPointers(index.Key.Keys); len(keys) > 0 {
					entry["keys"] = keys
				}
			}
			if index.Options != nil {
				if index.Options.Unique != nil {
					entry["unique"] = *index.Options.Unique
				}
				if index.Options.ExpireAfterSeconds != nil {
					entry["expireAfterSeconds"] = *index.Options.ExpireAfterSeconds
				}
			}
			if len(entry) > 0 {
				indexes = append(indexes, entry)
			}
		}
		if len(indexes) > 0 {
			props["indexes"] = indexes
		}

		if res.AnalyticalStorageTTL != nil {
			props["analyticalStorageTtl"] = *res.AnalyticalStorageTTL
		}
	}

	cosmosPutThroughput(props, c.throughput(ctx, rgName, accountName, dbName, collectionName))

	out, err := json.Marshal(props)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return out, nil
}

func cosmosMongoCollectionResource(props cosmosMongoCollectionProps, name string) *armcosmos.MongoDBCollectionResource {
	res := &armcosmos.MongoDBCollectionResource{
		ID:                   to.Ptr(name),
		AnalyticalStorageTTL: props.AnalyticalStorageTtl,
	}
	if len(props.ShardKey) > 0 {
		res.ShardKey = make(map[string]*string, len(props.ShardKey))
		for _, entry := range props.ShardKey {
			if entry.Key == "" {
				continue
			}
			value := entry.Value
			if value == "" {
				// ARM only accepts "Hash" here; default it so a caller can write
				// just the field name.
				value = "Hash"
			}
			res.ShardKey[entry.Key] = to.Ptr(value)
		}
	}
	for _, index := range props.Indexes {
		entry := &armcosmos.MongoIndex{
			Key: &armcosmos.MongoIndexKeys{Keys: stringPointers(index.Keys)},
		}
		if index.Unique != nil || index.ExpireAfterSeconds != nil {
			entry.Options = &armcosmos.MongoIndexOptions{
				Unique:             index.Unique,
				ExpireAfterSeconds: index.ExpireAfterSeconds,
			}
		}
		res.Indexes = append(res.Indexes, entry)
	}
	return res
}

func (c *CosmosMongoCollection) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props cosmosMongoCollectionProps
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	if props.AccountName == "" {
		return nil, fmt.Errorf("accountName is required")
	}
	if props.DatabaseName == "" {
		return nil, fmt.Errorf("databaseName is required")
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
	params := armcosmos.MongoDBCollectionCreateUpdateParameters{
		Properties: &armcosmos.MongoDBCollectionCreateUpdateProperties{
			Resource: cosmosMongoCollectionResource(props, props.Name),
			Options:  options,
		},
	}

	poller, err := c.api.BeginCreateUpdateMongoDBCollection(ctx, props.ResourceGroupName, props.AccountName,
		props.DatabaseName, props.Name, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	expectedNativeID := cosmosChildNativeID(c.config.SubscriptionId, props.ResourceGroupName, props.AccountName,
		"mongodbDatabases", props.DatabaseName, "collections", props.Name)

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
		propsJSON, err := c.serialize(ctx, result.MongoDBCollectionGetResults, props.ResourceGroupName,
			props.AccountName, props.DatabaseName, props.Name)
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

func (c *CosmosMongoCollection) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, accountName, dbName, collectionName, err := cosmosMongoCollectionIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := c.api.GetMongoDBCollection(ctx, rgName, accountName, dbName, collectionName, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := c.serialize(ctx, result.MongoDBCollectionGetResults, rgName, accountName, dbName, collectionName)
	if err != nil {
		return nil, err
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeCosmosMongoCollection,
		Properties:   string(propsJSON),
	}, nil
}

// Update re-PUTs the collection body. shardKey and analyticalStorageTtl are
// createOnly, so only `indexes` actually moves — but the whole body is still sent,
// because a PUT that omits shardKey would ask ARM to unshard the collection.
func (c *CosmosMongoCollection) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, accountName, dbName, collectionName, err := cosmosMongoCollectionIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props cosmosMongoCollectionProps
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	params := armcosmos.MongoDBCollectionCreateUpdateParameters{
		Properties: &armcosmos.MongoDBCollectionCreateUpdateProperties{
			Resource: cosmosMongoCollectionResource(props, collectionName),
		},
	}

	poller, err := c.api.BeginCreateUpdateMongoDBCollection(ctx, rgName, accountName, dbName, collectionName, params, nil)
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
		propsJSON, err := c.serialize(ctx, result.MongoDBCollectionGetResults, rgName, accountName, dbName, collectionName)
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

func (c *CosmosMongoCollection) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, accountName, dbName, collectionName, err := cosmosMongoCollectionIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, err := c.api.BeginDeleteMongoDBCollection(ctx, rgName, accountName, dbName, collectionName, nil)
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

func (c *CosmosMongoCollection) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	reqID, err := decodeLROStatus(request.RequestID)
	if err != nil {
		return nil, err
	}

	complete := func(ctx context.Context, result armcosmos.MongoDBResourcesClientCreateUpdateMongoDBCollectionResponse, _ resource.Operation) (string, json.RawMessage, error) {
		nativeID := reqID.NativeID
		if result.ID != nil {
			nativeID = *result.ID
		}
		rgName, accountName, dbName, collectionName, err := cosmosMongoCollectionIDParts(nativeID)
		if err != nil {
			return "", nil, err
		}
		propsJSON, err := c.serialize(ctx, result.MongoDBCollectionGetResults, rgName, accountName, dbName, collectionName)
		if err != nil {
			return "", nil, err
		}
		return nativeID, propsJSON, nil
	}
	resume := func(token string) (*runtime.Poller[armcosmos.MongoDBResourcesClientCreateUpdateMongoDBCollectionResponse], error) {
		return resumePoller[armcosmos.MongoDBResourcesClientCreateUpdateMongoDBCollectionResponse](c.pipeline, token)
	}

	switch reqID.OperationType {
	case lroOpCreate:
		return statusLRO(ctx, request, &reqID, resource.OperationCreate, resume, complete)
	case lroOpUpdate:
		return statusLRO(ctx, request, &reqID, resource.OperationUpdate, resume, complete)
	case lroOpDelete:
		return statusDeleteLRO(ctx, request, &reqID,
			func(token string) (*runtime.Poller[armcosmos.MongoDBResourcesClientDeleteMongoDBCollectionResponse], error) {
				return resumePoller[armcosmos.MongoDBResourcesClientDeleteMongoDBCollectionResponse](c.pipeline, token)
			}, nil)
	default:
		return nil, fmt.Errorf("unknown operation type: %s", reqID.OperationType)
	}
}

func (c *CosmosMongoCollection) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	accountName := request.AdditionalProperties["accountName"]
	dbName := request.AdditionalProperties["databaseName"]

	var nativeIDs []string
	pager := c.api.NewListMongoDBCollectionsPager(rgName, accountName, dbName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list Cosmos MongoDB collections in database %s: %w", dbName, err)
		}
		for _, collection := range page.Value {
			if collection.ID != nil {
				nativeIDs = append(nativeIDs, *collection.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
