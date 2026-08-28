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

const ResourceTypeCosmosSqlDatabase = "AZURE::DocumentDB::SqlDatabase"

// cosmosSQLDatabaseAPI is the armcosmos.SQLResourcesClient surface used here.
// Create/update and delete are both LROs; GetSQLDatabaseThroughput is a plain
// call used only to read provisioned RU/s back.
type cosmosSQLDatabaseAPI interface {
	BeginCreateUpdateSQLDatabase(ctx context.Context, resourceGroupName string, accountName string, databaseName string, createUpdateSQLDatabaseParameters armcosmos.SQLDatabaseCreateUpdateParameters, options *armcosmos.SQLResourcesClientBeginCreateUpdateSQLDatabaseOptions) (*runtime.Poller[armcosmos.SQLResourcesClientCreateUpdateSQLDatabaseResponse], error)
	GetSQLDatabase(ctx context.Context, resourceGroupName string, accountName string, databaseName string, options *armcosmos.SQLResourcesClientGetSQLDatabaseOptions) (armcosmos.SQLResourcesClientGetSQLDatabaseResponse, error)
	GetSQLDatabaseThroughput(ctx context.Context, resourceGroupName string, accountName string, databaseName string, options *armcosmos.SQLResourcesClientGetSQLDatabaseThroughputOptions) (armcosmos.SQLResourcesClientGetSQLDatabaseThroughputResponse, error)
	BeginDeleteSQLDatabase(ctx context.Context, resourceGroupName string, accountName string, databaseName string, options *armcosmos.SQLResourcesClientBeginDeleteSQLDatabaseOptions) (*runtime.Poller[armcosmos.SQLResourcesClientDeleteSQLDatabaseResponse], error)
	NewListSQLDatabasesPager(resourceGroupName string, accountName string, options *armcosmos.SQLResourcesClientListSQLDatabasesOptions) *runtime.Pager[armcosmos.SQLResourcesClientListSQLDatabasesResponse]
}

func init() {
	registry.Register(ResourceTypeCosmosSqlDatabase, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &CosmosSqlDatabase{
			api:      c.CosmosSQLResourcesClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// CosmosSqlDatabase is the provisioner for Cosmos DB SQL (core API) databases
// (`Microsoft.DocumentDB/databaseAccounts/<account>/sqlDatabases/<name>`).
//
// It is a child of AZURE::DocumentDB::DatabaseAccount, and the account must be
// running the NoSQL/core API — an account carrying EnableCassandra, EnableGremlin,
// EnableTable or kind=MongoDB rejects SQL databases outright.
//
// Stored procedures, triggers, user-defined functions and client encryption keys
// are separate ARM sub-resources and are not modelled here.
type CosmosSqlDatabase struct {
	api      cosmosSQLDatabaseAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

// cosmosSqlDatabaseProps mirrors schema/pkl/documentdb/sqldatabase.pkl.
type cosmosSqlDatabaseProps struct {
	Name              string `json:"name"`
	ResourceGroupName string `json:"resourceGroupName"`
	AccountName       string `json:"accountName"`
	cosmosChildThroughput
}

func cosmosSqlDatabaseIDParts(resourceID string) (rgName, accountName, dbName string, err error) {
	rgName, names, err := armExactIDParts(resourceID, "databaseAccounts", "sqlDatabases")
	if err != nil {
		return "", "", "", err
	}
	return rgName, names[0], names[1], nil
}

// throughput reads the provisioned RU/s back so a fixture that declares
// throughput or autoscaleMaxThroughput round-trips. Any error means "no dedicated
// throughput on this resource" — serverless accounts answer 400 and a database
// without provisioned throughput answers 404 — so it is swallowed rather than
// failing the read.
func (d *CosmosSqlDatabase) throughput(ctx context.Context, rgName, accountName, dbName string) *armcosmos.ThroughputSettingsGetPropertiesResource {
	result, err := d.api.GetSQLDatabaseThroughput(ctx, rgName, accountName, dbName, nil)
	if err != nil || result.Properties == nil {
		return nil
	}
	return result.Properties.Resource
}

func (d *CosmosSqlDatabase) serialize(ctx context.Context, result armcosmos.SQLDatabaseGetResults, rgName, accountName, dbName string) (json.RawMessage, error) {
	props := map[string]any{
		"resourceGroupName": rgName,
		"accountName":       accountName,
		"name":              dbName,
	}
	if result.ID != nil {
		props["id"] = *result.ID
	}
	// ARM's `name` is the ARM resource name; the body's resource.id repeats it.
	// Prefer the ARM name and fall back to the path segment.
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

func (d *CosmosSqlDatabase) params(props cosmosSqlDatabaseProps) (armcosmos.SQLDatabaseCreateUpdateParameters, error) {
	options, err := cosmosCreateUpdateOptions(props.cosmosChildThroughput)
	if err != nil {
		return armcosmos.SQLDatabaseCreateUpdateParameters{}, err
	}
	return armcosmos.SQLDatabaseCreateUpdateParameters{
		Properties: &armcosmos.SQLDatabaseCreateUpdateProperties{
			Resource: &armcosmos.SQLDatabaseResource{ID: to.Ptr(props.Name)},
			Options:  options,
		},
	}, nil
}

func (d *CosmosSqlDatabase) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props cosmosSqlDatabaseProps
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

	params, err := d.params(props)
	if err != nil {
		return nil, err
	}

	poller, err := d.api.BeginCreateUpdateSQLDatabase(ctx, props.ResourceGroupName, props.AccountName, props.Name, params, nil)
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
		"sqlDatabases", props.Name)

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
		propsJSON, err := d.serialize(ctx, result.SQLDatabaseGetResults, props.ResourceGroupName, props.AccountName, props.Name)
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

func (d *CosmosSqlDatabase) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, accountName, dbName, err := cosmosSqlDatabaseIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := d.api.GetSQLDatabase(ctx, rgName, accountName, dbName, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := d.serialize(ctx, result.SQLDatabaseGetResults, rgName, accountName, dbName)
	if err != nil {
		return nil, err
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeCosmosSqlDatabase,
		Properties:   string(propsJSON),
	}, nil
}

// Update re-PUTs the database body. Throughput is deliberately not sent: both
// throughput fields are createOnly (see cosmosChildThroughput), and `options` on a
// CreateUpdate maps to create-time request headers that ARM ignores here.
func (d *CosmosSqlDatabase) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, accountName, dbName, err := cosmosSqlDatabaseIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	params := armcosmos.SQLDatabaseCreateUpdateParameters{
		Properties: &armcosmos.SQLDatabaseCreateUpdateProperties{
			Resource: &armcosmos.SQLDatabaseResource{ID: to.Ptr(dbName)},
		},
	}

	poller, err := d.api.BeginCreateUpdateSQLDatabase(ctx, rgName, accountName, dbName, params, nil)
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
		propsJSON, err := d.serialize(ctx, result.SQLDatabaseGetResults, rgName, accountName, dbName)
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

func (d *CosmosSqlDatabase) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, accountName, dbName, err := cosmosSqlDatabaseIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, err := d.api.BeginDeleteSQLDatabase(ctx, rgName, accountName, dbName, nil)
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

func (d *CosmosSqlDatabase) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	reqID, err := decodeLROStatus(request.RequestID)
	if err != nil {
		return nil, err
	}

	// Create and update share one ARM operation, so they share one response type.
	complete := func(ctx context.Context, result armcosmos.SQLResourcesClientCreateUpdateSQLDatabaseResponse, _ resource.Operation) (string, json.RawMessage, error) {
		nativeID := reqID.NativeID
		if result.ID != nil {
			nativeID = *result.ID
		}
		rgName, accountName, dbName, err := cosmosSqlDatabaseIDParts(nativeID)
		if err != nil {
			return "", nil, err
		}
		propsJSON, err := d.serialize(ctx, result.SQLDatabaseGetResults, rgName, accountName, dbName)
		if err != nil {
			return "", nil, err
		}
		return nativeID, propsJSON, nil
	}
	resume := func(token string) (*runtime.Poller[armcosmos.SQLResourcesClientCreateUpdateSQLDatabaseResponse], error) {
		return resumePoller[armcosmos.SQLResourcesClientCreateUpdateSQLDatabaseResponse](d.pipeline, token)
	}

	switch reqID.OperationType {
	case lroOpCreate:
		return statusLRO(ctx, request, &reqID, resource.OperationCreate, resume, complete)
	case lroOpUpdate:
		return statusLRO(ctx, request, &reqID, resource.OperationUpdate, resume, complete)
	case lroOpDelete:
		return statusDeleteLRO(ctx, request, &reqID,
			func(token string) (*runtime.Poller[armcosmos.SQLResourcesClientDeleteSQLDatabaseResponse], error) {
				return resumePoller[armcosmos.SQLResourcesClientDeleteSQLDatabaseResponse](d.pipeline, token)
			}, nil)
	default:
		return nil, fmt.Errorf("unknown operation type: %s", reqID.OperationType)
	}
}

func (d *CosmosSqlDatabase) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	accountName := request.AdditionalProperties["accountName"]

	var nativeIDs []string
	pager := d.api.NewListSQLDatabasesPager(rgName, accountName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list Cosmos SQL databases in account %s: %w", accountName, err)
		}
		for _, db := range page.Value {
			if db.ID != nil {
				nativeIDs = append(nativeIDs, *db.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
