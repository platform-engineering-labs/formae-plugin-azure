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

const ResourceTypeCosmosGremlinGraph = "AZURE::DocumentDB::GremlinGraph"

// cosmosGremlinGraphAPI is the armcosmos.GremlinResourcesClient surface used here.
type cosmosGremlinGraphAPI interface {
	BeginCreateUpdateGremlinGraph(ctx context.Context, resourceGroupName string, accountName string, databaseName string, graphName string, createUpdateGremlinGraphParameters armcosmos.GremlinGraphCreateUpdateParameters, options *armcosmos.GremlinResourcesClientBeginCreateUpdateGremlinGraphOptions) (*runtime.Poller[armcosmos.GremlinResourcesClientCreateUpdateGremlinGraphResponse], error)
	GetGremlinGraph(ctx context.Context, resourceGroupName string, accountName string, databaseName string, graphName string, options *armcosmos.GremlinResourcesClientGetGremlinGraphOptions) (armcosmos.GremlinResourcesClientGetGremlinGraphResponse, error)
	GetGremlinGraphThroughput(ctx context.Context, resourceGroupName string, accountName string, databaseName string, graphName string, options *armcosmos.GremlinResourcesClientGetGremlinGraphThroughputOptions) (armcosmos.GremlinResourcesClientGetGremlinGraphThroughputResponse, error)
	BeginDeleteGremlinGraph(ctx context.Context, resourceGroupName string, accountName string, databaseName string, graphName string, options *armcosmos.GremlinResourcesClientBeginDeleteGremlinGraphOptions) (*runtime.Poller[armcosmos.GremlinResourcesClientDeleteGremlinGraphResponse], error)
	NewListGremlinGraphsPager(resourceGroupName string, accountName string, databaseName string, options *armcosmos.GremlinResourcesClientListGremlinGraphsOptions) *runtime.Pager[armcosmos.GremlinResourcesClientListGremlinGraphsResponse]
}

func init() {
	registry.Register(ResourceTypeCosmosGremlinGraph, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &CosmosGremlinGraph{
			api:      c.CosmosGremlinResourcesClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// CosmosGremlinGraph is the provisioner for Cosmos DB Gremlin-API graphs
// (`.../databaseAccounts/<account>/gremlinDatabases/<database>/graphs/<name>`).
//
// It is a child of AZURE::DocumentDB::GremlinDatabase. A graph is a SQL container
// underneath, which is why it carries the same partition-key, indexing-policy and
// conflict-resolution shapes.
type CosmosGremlinGraph struct {
	api      cosmosGremlinGraphAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

// cosmosGremlinGraphProps mirrors schema/pkl/documentdb/cosmosgremlingraph.pkl.
type cosmosGremlinGraphProps struct {
	Name                     string                               `json:"name"`
	ResourceGroupName        string                               `json:"resourceGroupName"`
	AccountName              string                               `json:"accountName"`
	DatabaseName             string                               `json:"databaseName"`
	PartitionKey             *cosmosPartitionKeyProps             `json:"partitionKey"`
	IndexingPolicy           *cosmosIndexingPolicyProps           `json:"indexingPolicy"`
	ConflictResolutionPolicy *cosmosConflictResolutionPolicyProps `json:"conflictResolutionPolicy"`
	DefaultTtl               *int32                               `json:"defaultTtl"`
	AnalyticalStorageTtl     *int64                               `json:"analyticalStorageTtl"`
	cosmosChildThroughput
}

func cosmosGremlinGraphIDParts(resourceID string) (rgName, accountName, dbName, graphName string, err error) {
	rgName, names, err := armExactIDParts(resourceID, "databaseAccounts", "gremlinDatabases", "graphs")
	if err != nil {
		return "", "", "", "", err
	}
	return rgName, names[0], names[1], names[2], nil
}

func (g *CosmosGremlinGraph) throughput(ctx context.Context, rgName, accountName, dbName, graphName string) *armcosmos.ThroughputSettingsGetPropertiesResource {
	result, err := g.api.GetGremlinGraphThroughput(ctx, rgName, accountName, dbName, graphName, nil)
	if err != nil || result.Properties == nil {
		return nil
	}
	return result.Properties.Resource
}

func (g *CosmosGremlinGraph) serialize(ctx context.Context, result armcosmos.GremlinGraphGetResults, rgName, accountName, dbName, graphName string) (json.RawMessage, error) {
	props := map[string]any{
		"resourceGroupName": rgName,
		"accountName":       accountName,
		"databaseName":      dbName,
		"name":              graphName,
	}
	if result.ID != nil {
		props["id"] = *result.ID
	}
	if result.Name != nil && *result.Name != "" {
		props["name"] = *result.Name
	}

	if result.Properties != nil && result.Properties.Resource != nil {
		res := result.Properties.Resource
		if pk := cosmosPartitionKeyFromARM(res.PartitionKey); pk != nil {
			props["partitionKey"] = pk
		}
		if policy := cosmosIndexingPolicyFromARM(res.IndexingPolicy); policy != nil {
			props["indexingPolicy"] = policy
		}
		if policy := cosmosConflictResolutionPolicyFromARM(res.ConflictResolutionPolicy); policy != nil {
			props["conflictResolutionPolicy"] = policy
		}
		if res.DefaultTTL != nil {
			props["defaultTtl"] = *res.DefaultTTL
		}
		if res.AnalyticalStorageTTL != nil {
			props["analyticalStorageTtl"] = *res.AnalyticalStorageTTL
		}
	}

	cosmosPutThroughput(props, g.throughput(ctx, rgName, accountName, dbName, graphName))

	out, err := json.Marshal(props)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return out, nil
}

func cosmosGremlinGraphResource(props cosmosGremlinGraphProps, name string) *armcosmos.GremlinGraphResource {
	return &armcosmos.GremlinGraphResource{
		ID:                       to.Ptr(name),
		PartitionKey:             cosmosPartitionKeyToARM(props.PartitionKey),
		IndexingPolicy:           cosmosIndexingPolicyToARM(props.IndexingPolicy),
		ConflictResolutionPolicy: cosmosConflictResolutionPolicyToARM(props.ConflictResolutionPolicy),
		DefaultTTL:               props.DefaultTtl,
		AnalyticalStorageTTL:     props.AnalyticalStorageTtl,
	}
}

func (g *CosmosGremlinGraph) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props cosmosGremlinGraphProps
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
	if props.PartitionKey == nil || len(props.PartitionKey.Paths) == 0 {
		return nil, fmt.Errorf("partitionKey with at least one path is required")
	}

	options, err := cosmosCreateUpdateOptions(props.cosmosChildThroughput)
	if err != nil {
		return nil, err
	}
	params := armcosmos.GremlinGraphCreateUpdateParameters{
		Properties: &armcosmos.GremlinGraphCreateUpdateProperties{
			Resource: cosmosGremlinGraphResource(props, props.Name),
			Options:  options,
		},
	}

	poller, err := g.api.BeginCreateUpdateGremlinGraph(ctx, props.ResourceGroupName, props.AccountName,
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

	expectedNativeID := cosmosChildNativeID(g.config.SubscriptionId, props.ResourceGroupName, props.AccountName,
		"gremlinDatabases", props.DatabaseName, "graphs", props.Name)

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
		propsJSON, err := g.serialize(ctx, result.GremlinGraphGetResults, props.ResourceGroupName,
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

func (g *CosmosGremlinGraph) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, accountName, dbName, graphName, err := cosmosGremlinGraphIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := g.api.GetGremlinGraph(ctx, rgName, accountName, dbName, graphName, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := g.serialize(ctx, result.GremlinGraphGetResults, rgName, accountName, dbName, graphName)
	if err != nil {
		return nil, err
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeCosmosGremlinGraph,
		Properties:   string(propsJSON),
	}, nil
}

// Update re-PUTs the graph body. Only defaultTtl, indexingPolicy and
// conflictResolutionPolicy move; the rest is createOnly. The whole body still has
// to be sent, because a PUT that omits a policy resets it to the service default.
func (g *CosmosGremlinGraph) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, accountName, dbName, graphName, err := cosmosGremlinGraphIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props cosmosGremlinGraphProps
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	params := armcosmos.GremlinGraphCreateUpdateParameters{
		Properties: &armcosmos.GremlinGraphCreateUpdateProperties{
			Resource: cosmosGremlinGraphResource(props, graphName),
		},
	}

	poller, err := g.api.BeginCreateUpdateGremlinGraph(ctx, rgName, accountName, dbName, graphName, params, nil)
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
		propsJSON, err := g.serialize(ctx, result.GremlinGraphGetResults, rgName, accountName, dbName, graphName)
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

func (g *CosmosGremlinGraph) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, accountName, dbName, graphName, err := cosmosGremlinGraphIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, err := g.api.BeginDeleteGremlinGraph(ctx, rgName, accountName, dbName, graphName, nil)
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

func (g *CosmosGremlinGraph) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	reqID, err := decodeLROStatus(request.RequestID)
	if err != nil {
		return nil, err
	}

	complete := func(ctx context.Context, result armcosmos.GremlinResourcesClientCreateUpdateGremlinGraphResponse, _ resource.Operation) (string, json.RawMessage, error) {
		nativeID := reqID.NativeID
		if result.ID != nil {
			nativeID = *result.ID
		}
		rgName, accountName, dbName, graphName, err := cosmosGremlinGraphIDParts(nativeID)
		if err != nil {
			return "", nil, err
		}
		propsJSON, err := g.serialize(ctx, result.GremlinGraphGetResults, rgName, accountName, dbName, graphName)
		if err != nil {
			return "", nil, err
		}
		return nativeID, propsJSON, nil
	}
	resume := func(token string) (*runtime.Poller[armcosmos.GremlinResourcesClientCreateUpdateGremlinGraphResponse], error) {
		return resumePoller[armcosmos.GremlinResourcesClientCreateUpdateGremlinGraphResponse](g.pipeline, token)
	}

	switch reqID.OperationType {
	case lroOpCreate:
		return statusLRO(ctx, request, &reqID, resource.OperationCreate, resume, complete)
	case lroOpUpdate:
		return statusLRO(ctx, request, &reqID, resource.OperationUpdate, resume, complete)
	case lroOpDelete:
		return statusDeleteLRO(ctx, request, &reqID,
			func(token string) (*runtime.Poller[armcosmos.GremlinResourcesClientDeleteGremlinGraphResponse], error) {
				return resumePoller[armcosmos.GremlinResourcesClientDeleteGremlinGraphResponse](g.pipeline, token)
			}, nil)
	default:
		return nil, fmt.Errorf("unknown operation type: %s", reqID.OperationType)
	}
}

func (g *CosmosGremlinGraph) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	accountName := request.AdditionalProperties["accountName"]
	dbName := request.AdditionalProperties["databaseName"]

	var nativeIDs []string
	pager := g.api.NewListGremlinGraphsPager(rgName, accountName, dbName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list Cosmos Gremlin graphs in database %s: %w", dbName, err)
		}
		for _, graph := range page.Value {
			if graph.ID != nil {
				nativeIDs = append(nativeIDs, *graph.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
