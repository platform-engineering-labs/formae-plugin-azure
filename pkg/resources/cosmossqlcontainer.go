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

const ResourceTypeCosmosSqlContainer = "AZURE::DocumentDB::SqlContainer"

// cosmosSQLContainerAPI is the armcosmos.SQLResourcesClient surface used here.
type cosmosSQLContainerAPI interface {
	BeginCreateUpdateSQLContainer(ctx context.Context, resourceGroupName string, accountName string, databaseName string, containerName string, createUpdateSQLContainerParameters armcosmos.SQLContainerCreateUpdateParameters, options *armcosmos.SQLResourcesClientBeginCreateUpdateSQLContainerOptions) (*runtime.Poller[armcosmos.SQLResourcesClientCreateUpdateSQLContainerResponse], error)
	GetSQLContainer(ctx context.Context, resourceGroupName string, accountName string, databaseName string, containerName string, options *armcosmos.SQLResourcesClientGetSQLContainerOptions) (armcosmos.SQLResourcesClientGetSQLContainerResponse, error)
	GetSQLContainerThroughput(ctx context.Context, resourceGroupName string, accountName string, databaseName string, containerName string, options *armcosmos.SQLResourcesClientGetSQLContainerThroughputOptions) (armcosmos.SQLResourcesClientGetSQLContainerThroughputResponse, error)
	BeginDeleteSQLContainer(ctx context.Context, resourceGroupName string, accountName string, databaseName string, containerName string, options *armcosmos.SQLResourcesClientBeginDeleteSQLContainerOptions) (*runtime.Poller[armcosmos.SQLResourcesClientDeleteSQLContainerResponse], error)
	NewListSQLContainersPager(resourceGroupName string, accountName string, databaseName string, options *armcosmos.SQLResourcesClientListSQLContainersOptions) *runtime.Pager[armcosmos.SQLResourcesClientListSQLContainersResponse]
}

func init() {
	registry.Register(ResourceTypeCosmosSqlContainer, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &CosmosSqlContainer{
			api:      c.CosmosSQLResourcesClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// CosmosSqlContainer is the provisioner for Cosmos DB SQL (core API) containers
// (`.../databaseAccounts/<account>/sqlDatabases/<database>/containers/<name>`).
//
// It is a child of AZURE::DocumentDB::SqlDatabase.
//
// A container create is the slowest operation in this namespace — a partitioned
// container regularly takes minutes — so conformance runs against it want a raised
// FORMAE_TEST_TIMEOUT.
type CosmosSqlContainer struct {
	api      cosmosSQLContainerAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

// cosmosSqlContainerProps mirrors schema/pkl/documentdb/sqlcontainer.pkl.
type cosmosSqlContainerProps struct {
	Name                     string                               `json:"name"`
	ResourceGroupName        string                               `json:"resourceGroupName"`
	AccountName              string                               `json:"accountName"`
	DatabaseName             string                               `json:"databaseName"`
	PartitionKey             *cosmosPartitionKeyProps             `json:"partitionKey"`
	IndexingPolicy           *cosmosIndexingPolicyProps           `json:"indexingPolicy"`
	UniqueKeyPolicy          *cosmosUniqueKeyPolicyProps          `json:"uniqueKeyPolicy"`
	ConflictResolutionPolicy *cosmosConflictResolutionPolicyProps `json:"conflictResolutionPolicy"`
	DefaultTtl               *int32                               `json:"defaultTtl"`
	AnalyticalStorageTtl     *int64                               `json:"analyticalStorageTtl"`
	cosmosChildThroughput
}

func cosmosSqlContainerIDParts(resourceID string) (rgName, accountName, dbName, containerName string, err error) {
	rgName, names, err := armExactIDParts(resourceID, "databaseAccounts", "sqlDatabases", "containers")
	if err != nil {
		return "", "", "", "", err
	}
	return rgName, names[0], names[1], names[2], nil
}

// throughput reads dedicated container RU/s back. Any error means the container has
// none of its own — a container inside a shared-throughput database answers 404 and
// a serverless account answers 400 — so it is swallowed rather than failing the read.
func (c *CosmosSqlContainer) throughput(ctx context.Context, rgName, accountName, dbName, containerName string) *armcosmos.ThroughputSettingsGetPropertiesResource {
	result, err := c.api.GetSQLContainerThroughput(ctx, rgName, accountName, dbName, containerName, nil)
	if err != nil || result.Properties == nil {
		return nil
	}
	return result.Properties.Resource
}

func (c *CosmosSqlContainer) serialize(ctx context.Context, result armcosmos.SQLContainerGetResults, rgName, accountName, dbName, containerName string) (json.RawMessage, error) {
	props := map[string]any{
		"resourceGroupName": rgName,
		"accountName":       accountName,
		"databaseName":      dbName,
		"name":              containerName,
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
		if policy := cosmosUniqueKeyPolicyFromARM(res.UniqueKeyPolicy); policy != nil {
			props["uniqueKeyPolicy"] = policy
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

	cosmosPutThroughput(props, c.throughput(ctx, rgName, accountName, dbName, containerName))

	out, err := json.Marshal(props)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return out, nil
}

// resourceBody renders the container body ARM PUTs. It is shared by create and
// update: an update is a full re-PUT of the same body, and omitting a policy on
// update would reset it to the service default.
func cosmosSqlContainerResource(props cosmosSqlContainerProps, name string) *armcosmos.SQLContainerResource {
	return &armcosmos.SQLContainerResource{
		ID:                       to.Ptr(name),
		PartitionKey:             cosmosPartitionKeyToARM(props.PartitionKey),
		IndexingPolicy:           cosmosIndexingPolicyToARM(props.IndexingPolicy),
		UniqueKeyPolicy:          cosmosUniqueKeyPolicyToARM(props.UniqueKeyPolicy),
		ConflictResolutionPolicy: cosmosConflictResolutionPolicyToARM(props.ConflictResolutionPolicy),
		DefaultTTL:               props.DefaultTtl,
		AnalyticalStorageTTL:     props.AnalyticalStorageTtl,
	}
}

func (c *CosmosSqlContainer) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props cosmosSqlContainerProps
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
	params := armcosmos.SQLContainerCreateUpdateParameters{
		Properties: &armcosmos.SQLContainerCreateUpdateProperties{
			Resource: cosmosSqlContainerResource(props, props.Name),
			Options:  options,
		},
	}

	poller, err := c.api.BeginCreateUpdateSQLContainer(ctx, props.ResourceGroupName, props.AccountName,
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
		"sqlDatabases", props.DatabaseName, "containers", props.Name)

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
		propsJSON, err := c.serialize(ctx, result.SQLContainerGetResults, props.ResourceGroupName,
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

func (c *CosmosSqlContainer) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, accountName, dbName, containerName, err := cosmosSqlContainerIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := c.api.GetSQLContainer(ctx, rgName, accountName, dbName, containerName, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := c.serialize(ctx, result.SQLContainerGetResults, rgName, accountName, dbName, containerName)
	if err != nil {
		return nil, err
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeCosmosSqlContainer,
		Properties:   string(propsJSON),
	}, nil
}

// Update re-PUTs the container body. partitionKey, uniqueKeyPolicy,
// analyticalStorageTtl and the throughput fields are createOnly in the schema, so
// only defaultTtl, indexingPolicy and conflictResolutionPolicy actually move here —
// but the whole body still has to be sent, because a PUT that omits a policy resets
// it to the service default.
func (c *CosmosSqlContainer) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, accountName, dbName, containerName, err := cosmosSqlContainerIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props cosmosSqlContainerProps
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	params := armcosmos.SQLContainerCreateUpdateParameters{
		Properties: &armcosmos.SQLContainerCreateUpdateProperties{
			Resource: cosmosSqlContainerResource(props, containerName),
		},
	}

	poller, err := c.api.BeginCreateUpdateSQLContainer(ctx, rgName, accountName, dbName, containerName, params, nil)
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
		propsJSON, err := c.serialize(ctx, result.SQLContainerGetResults, rgName, accountName, dbName, containerName)
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

func (c *CosmosSqlContainer) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, accountName, dbName, containerName, err := cosmosSqlContainerIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, err := c.api.BeginDeleteSQLContainer(ctx, rgName, accountName, dbName, containerName, nil)
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

func (c *CosmosSqlContainer) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	reqID, err := decodeLROStatus(request.RequestID)
	if err != nil {
		return nil, err
	}

	complete := func(ctx context.Context, result armcosmos.SQLResourcesClientCreateUpdateSQLContainerResponse, _ resource.Operation) (string, json.RawMessage, error) {
		nativeID := reqID.NativeID
		if result.ID != nil {
			nativeID = *result.ID
		}
		rgName, accountName, dbName, containerName, err := cosmosSqlContainerIDParts(nativeID)
		if err != nil {
			return "", nil, err
		}
		propsJSON, err := c.serialize(ctx, result.SQLContainerGetResults, rgName, accountName, dbName, containerName)
		if err != nil {
			return "", nil, err
		}
		return nativeID, propsJSON, nil
	}
	resume := func(token string) (*runtime.Poller[armcosmos.SQLResourcesClientCreateUpdateSQLContainerResponse], error) {
		return resumePoller[armcosmos.SQLResourcesClientCreateUpdateSQLContainerResponse](c.pipeline, token)
	}

	switch reqID.OperationType {
	case lroOpCreate:
		return statusLRO(ctx, request, &reqID, resource.OperationCreate, resume, complete)
	case lroOpUpdate:
		return statusLRO(ctx, request, &reqID, resource.OperationUpdate, resume, complete)
	case lroOpDelete:
		return statusDeleteLRO(ctx, request, &reqID,
			func(token string) (*runtime.Poller[armcosmos.SQLResourcesClientDeleteSQLContainerResponse], error) {
				return resumePoller[armcosmos.SQLResourcesClientDeleteSQLContainerResponse](c.pipeline, token)
			}, nil)
	default:
		return nil, fmt.Errorf("unknown operation type: %s", reqID.OperationType)
	}
}

func (c *CosmosSqlContainer) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	accountName := request.AdditionalProperties["accountName"]
	dbName := request.AdditionalProperties["databaseName"]

	var nativeIDs []string
	pager := c.api.NewListSQLContainersPager(rgName, accountName, dbName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list Cosmos SQL containers in database %s: %w", dbName, err)
		}
		for _, container := range page.Value {
			if container.ID != nil {
				nativeIDs = append(nativeIDs, *container.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
