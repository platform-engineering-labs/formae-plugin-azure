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

const ResourceTypeCosmosTable = "AZURE::DocumentDB::Table"

// cosmosTableAPI is the armcosmos.TableResourcesClient surface used here.
type cosmosTableAPI interface {
	BeginCreateUpdateTable(ctx context.Context, resourceGroupName string, accountName string, tableName string, createUpdateTableParameters armcosmos.TableCreateUpdateParameters, options *armcosmos.TableResourcesClientBeginCreateUpdateTableOptions) (*runtime.Poller[armcosmos.TableResourcesClientCreateUpdateTableResponse], error)
	GetTable(ctx context.Context, resourceGroupName string, accountName string, tableName string, options *armcosmos.TableResourcesClientGetTableOptions) (armcosmos.TableResourcesClientGetTableResponse, error)
	GetTableThroughput(ctx context.Context, resourceGroupName string, accountName string, tableName string, options *armcosmos.TableResourcesClientGetTableThroughputOptions) (armcosmos.TableResourcesClientGetTableThroughputResponse, error)
	BeginDeleteTable(ctx context.Context, resourceGroupName string, accountName string, tableName string, options *armcosmos.TableResourcesClientBeginDeleteTableOptions) (*runtime.Poller[armcosmos.TableResourcesClientDeleteTableResponse], error)
	NewListTablesPager(resourceGroupName string, accountName string, options *armcosmos.TableResourcesClientListTablesOptions) *runtime.Pager[armcosmos.TableResourcesClientListTablesResponse]
}

func init() {
	registry.Register(ResourceTypeCosmosTable, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &CosmosTable{
			api:      c.CosmosTableResourcesClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// CosmosTable is the provisioner for Cosmos DB Table-API tables
// (`.../databaseAccounts/<account>/tables/<name>`).
//
// This is the Cosmos Table API, not Azure Storage tables (AZURE::Storage::Table).
// The parent account must carry the `EnableTable` capability; an account without it
// rejects these. Table-API tables hang directly off the account — there is no
// intermediate database.
type CosmosTable struct {
	api      cosmosTableAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

// cosmosTableProps mirrors schema/pkl/documentdb/cosmostable.pkl.
type cosmosTableProps struct {
	Name              string `json:"name"`
	ResourceGroupName string `json:"resourceGroupName"`
	AccountName       string `json:"accountName"`
	cosmosChildThroughput
}

func cosmosTableIDParts(resourceID string) (rgName, accountName, tableName string, err error) {
	rgName, names, err := armExactIDParts(resourceID, "databaseAccounts", "tables")
	if err != nil {
		return "", "", "", err
	}
	return rgName, names[0], names[1], nil
}

func (t *CosmosTable) throughput(ctx context.Context, rgName, accountName, tableName string) *armcosmos.ThroughputSettingsGetPropertiesResource {
	result, err := t.api.GetTableThroughput(ctx, rgName, accountName, tableName, nil)
	if err != nil || result.Properties == nil {
		return nil
	}
	return result.Properties.Resource
}

func (t *CosmosTable) serialize(ctx context.Context, result armcosmos.TableGetResults, rgName, accountName, tableName string) (json.RawMessage, error) {
	props := map[string]any{
		"resourceGroupName": rgName,
		"accountName":       accountName,
		"name":              tableName,
	}
	if result.ID != nil {
		props["id"] = *result.ID
	}
	if result.Name != nil && *result.Name != "" {
		props["name"] = *result.Name
	}
	cosmosPutThroughput(props, t.throughput(ctx, rgName, accountName, tableName))

	out, err := json.Marshal(props)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return out, nil
}

func (t *CosmosTable) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props cosmosTableProps
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
	params := armcosmos.TableCreateUpdateParameters{
		Properties: &armcosmos.TableCreateUpdateProperties{
			Resource: &armcosmos.TableResource{ID: to.Ptr(props.Name)},
			Options:  options,
		},
	}

	poller, err := t.api.BeginCreateUpdateTable(ctx, props.ResourceGroupName, props.AccountName, props.Name, params, nil)
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
		"tables", props.Name)

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
		propsJSON, err := t.serialize(ctx, result.TableGetResults, props.ResourceGroupName, props.AccountName, props.Name)
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

func (t *CosmosTable) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, accountName, tableName, err := cosmosTableIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := t.api.GetTable(ctx, rgName, accountName, tableName, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := t.serialize(ctx, result.TableGetResults, rgName, accountName, tableName)
	if err != nil {
		return nil, err
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeCosmosTable,
		Properties:   string(propsJSON),
	}, nil
}

// Update re-PUTs the table body. A Table-API table has no mutable properties beyond
// throughput, and throughput is createOnly, so this exists to keep the provisioner
// contract honest rather than to move anything.
func (t *CosmosTable) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, accountName, tableName, err := cosmosTableIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	params := armcosmos.TableCreateUpdateParameters{
		Properties: &armcosmos.TableCreateUpdateProperties{
			Resource: &armcosmos.TableResource{ID: to.Ptr(tableName)},
		},
	}

	poller, err := t.api.BeginCreateUpdateTable(ctx, rgName, accountName, tableName, params, nil)
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
		propsJSON, err := t.serialize(ctx, result.TableGetResults, rgName, accountName, tableName)
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

func (t *CosmosTable) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, accountName, tableName, err := cosmosTableIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, err := t.api.BeginDeleteTable(ctx, rgName, accountName, tableName, nil)
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

func (t *CosmosTable) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	reqID, err := decodeLROStatus(request.RequestID)
	if err != nil {
		return nil, err
	}

	complete := func(ctx context.Context, result armcosmos.TableResourcesClientCreateUpdateTableResponse, _ resource.Operation) (string, json.RawMessage, error) {
		nativeID := reqID.NativeID
		if result.ID != nil {
			nativeID = *result.ID
		}
		rgName, accountName, tableName, err := cosmosTableIDParts(nativeID)
		if err != nil {
			return "", nil, err
		}
		propsJSON, err := t.serialize(ctx, result.TableGetResults, rgName, accountName, tableName)
		if err != nil {
			return "", nil, err
		}
		return nativeID, propsJSON, nil
	}
	resume := func(token string) (*runtime.Poller[armcosmos.TableResourcesClientCreateUpdateTableResponse], error) {
		return resumePoller[armcosmos.TableResourcesClientCreateUpdateTableResponse](t.pipeline, token)
	}

	switch reqID.OperationType {
	case lroOpCreate:
		return statusLRO(ctx, request, &reqID, resource.OperationCreate, resume, complete)
	case lroOpUpdate:
		return statusLRO(ctx, request, &reqID, resource.OperationUpdate, resume, complete)
	case lroOpDelete:
		return statusDeleteLRO(ctx, request, &reqID,
			func(token string) (*runtime.Poller[armcosmos.TableResourcesClientDeleteTableResponse], error) {
				return resumePoller[armcosmos.TableResourcesClientDeleteTableResponse](t.pipeline, token)
			}, nil)
	default:
		return nil, fmt.Errorf("unknown operation type: %s", reqID.OperationType)
	}
}

func (t *CosmosTable) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	accountName := request.AdditionalProperties["accountName"]

	var nativeIDs []string
	pager := t.api.NewListTablesPager(rgName, accountName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list Cosmos tables in account %s: %w", accountName, err)
		}
		for _, table := range page.Value {
			if table.ID != nil {
				nativeIDs = append(nativeIDs, *table.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
