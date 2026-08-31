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

const ResourceTypeCosmosCassandraKeyspace = "AZURE::DocumentDB::CassandraKeyspace"

// cosmosCassandraKeyspaceAPI is the armcosmos.CassandraResourcesClient surface
// used here.
type cosmosCassandraKeyspaceAPI interface {
	BeginCreateUpdateCassandraKeyspace(ctx context.Context, resourceGroupName string, accountName string, keyspaceName string, createUpdateCassandraKeyspaceParameters armcosmos.CassandraKeyspaceCreateUpdateParameters, options *armcosmos.CassandraResourcesClientBeginCreateUpdateCassandraKeyspaceOptions) (*runtime.Poller[armcosmos.CassandraResourcesClientCreateUpdateCassandraKeyspaceResponse], error)
	GetCassandraKeyspace(ctx context.Context, resourceGroupName string, accountName string, keyspaceName string, options *armcosmos.CassandraResourcesClientGetCassandraKeyspaceOptions) (armcosmos.CassandraResourcesClientGetCassandraKeyspaceResponse, error)
	GetCassandraKeyspaceThroughput(ctx context.Context, resourceGroupName string, accountName string, keyspaceName string, options *armcosmos.CassandraResourcesClientGetCassandraKeyspaceThroughputOptions) (armcosmos.CassandraResourcesClientGetCassandraKeyspaceThroughputResponse, error)
	BeginDeleteCassandraKeyspace(ctx context.Context, resourceGroupName string, accountName string, keyspaceName string, options *armcosmos.CassandraResourcesClientBeginDeleteCassandraKeyspaceOptions) (*runtime.Poller[armcosmos.CassandraResourcesClientDeleteCassandraKeyspaceResponse], error)
	NewListCassandraKeyspacesPager(resourceGroupName string, accountName string, options *armcosmos.CassandraResourcesClientListCassandraKeyspacesOptions) *runtime.Pager[armcosmos.CassandraResourcesClientListCassandraKeyspacesResponse]
}

func init() {
	registry.Register(ResourceTypeCosmosCassandraKeyspace, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &CosmosCassandraKeyspace{
			api:      c.CosmosCassandraResourcesClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// CosmosCassandraKeyspace is the provisioner for Cosmos DB Cassandra-API keyspaces
// (`.../databaseAccounts/<account>/cassandraKeyspaces/<name>`).
//
// The parent account must carry the `EnableCassandra` capability; an account
// without it rejects these.
type CosmosCassandraKeyspace struct {
	api      cosmosCassandraKeyspaceAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

// cosmosCassandraKeyspaceProps mirrors
// schema/pkl/documentdb/cosmoscassandrakeyspace.pkl.
type cosmosCassandraKeyspaceProps struct {
	Name              string `json:"name"`
	ResourceGroupName string `json:"resourceGroupName"`
	AccountName       string `json:"accountName"`
	cosmosChildThroughput
}

func cosmosCassandraKeyspaceIDParts(resourceID string) (rgName, accountName, keyspaceName string, err error) {
	rgName, names, err := armExactIDParts(resourceID, "databaseAccounts", "cassandraKeyspaces")
	if err != nil {
		return "", "", "", err
	}
	return rgName, names[0], names[1], nil
}

func (k *CosmosCassandraKeyspace) throughput(ctx context.Context, rgName, accountName, keyspaceName string) *armcosmos.ThroughputSettingsGetPropertiesResource {
	result, err := k.api.GetCassandraKeyspaceThroughput(ctx, rgName, accountName, keyspaceName, nil)
	if err != nil || result.Properties == nil {
		return nil
	}
	return result.Properties.Resource
}

func (k *CosmosCassandraKeyspace) serialize(ctx context.Context, result armcosmos.CassandraKeyspaceGetResults, rgName, accountName, keyspaceName string) (json.RawMessage, error) {
	props := map[string]any{
		"resourceGroupName": rgName,
		"accountName":       accountName,
		"name":              keyspaceName,
	}
	if result.ID != nil {
		props["id"] = *result.ID
	}
	if result.Name != nil && *result.Name != "" {
		props["name"] = *result.Name
	}
	cosmosPutThroughput(props, k.throughput(ctx, rgName, accountName, keyspaceName))

	out, err := json.Marshal(props)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return out, nil
}

func (k *CosmosCassandraKeyspace) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props cosmosCassandraKeyspaceProps
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
	params := armcosmos.CassandraKeyspaceCreateUpdateParameters{
		Properties: &armcosmos.CassandraKeyspaceCreateUpdateProperties{
			Resource: &armcosmos.CassandraKeyspaceResource{ID: to.Ptr(props.Name)},
			Options:  options,
		},
	}

	poller, err := k.api.BeginCreateUpdateCassandraKeyspace(ctx, props.ResourceGroupName, props.AccountName, props.Name, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	expectedNativeID := cosmosChildNativeID(k.config.SubscriptionId, props.ResourceGroupName, props.AccountName,
		"cassandraKeyspaces", props.Name)

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
		propsJSON, err := k.serialize(ctx, result.CassandraKeyspaceGetResults, props.ResourceGroupName, props.AccountName, props.Name)
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

func (k *CosmosCassandraKeyspace) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, accountName, keyspaceName, err := cosmosCassandraKeyspaceIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := k.api.GetCassandraKeyspace(ctx, rgName, accountName, keyspaceName, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := k.serialize(ctx, result.CassandraKeyspaceGetResults, rgName, accountName, keyspaceName)
	if err != nil {
		return nil, err
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeCosmosCassandraKeyspace,
		Properties:   string(propsJSON),
	}, nil
}

// Update re-PUTs the keyspace body. A keyspace has no mutable properties beyond
// throughput, and throughput is createOnly, so this exists to keep the provisioner
// contract honest rather than to move anything.
func (k *CosmosCassandraKeyspace) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, accountName, keyspaceName, err := cosmosCassandraKeyspaceIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	params := armcosmos.CassandraKeyspaceCreateUpdateParameters{
		Properties: &armcosmos.CassandraKeyspaceCreateUpdateProperties{
			Resource: &armcosmos.CassandraKeyspaceResource{ID: to.Ptr(keyspaceName)},
		},
	}

	poller, err := k.api.BeginCreateUpdateCassandraKeyspace(ctx, rgName, accountName, keyspaceName, params, nil)
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
		propsJSON, err := k.serialize(ctx, result.CassandraKeyspaceGetResults, rgName, accountName, keyspaceName)
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

func (k *CosmosCassandraKeyspace) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, accountName, keyspaceName, err := cosmosCassandraKeyspaceIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, err := k.api.BeginDeleteCassandraKeyspace(ctx, rgName, accountName, keyspaceName, nil)
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

func (k *CosmosCassandraKeyspace) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	reqID, err := decodeLROStatus(request.RequestID)
	if err != nil {
		return nil, err
	}

	complete := func(ctx context.Context, result armcosmos.CassandraResourcesClientCreateUpdateCassandraKeyspaceResponse, _ resource.Operation) (string, json.RawMessage, error) {
		nativeID := reqID.NativeID
		if result.ID != nil {
			nativeID = *result.ID
		}
		rgName, accountName, keyspaceName, err := cosmosCassandraKeyspaceIDParts(nativeID)
		if err != nil {
			return "", nil, err
		}
		propsJSON, err := k.serialize(ctx, result.CassandraKeyspaceGetResults, rgName, accountName, keyspaceName)
		if err != nil {
			return "", nil, err
		}
		return nativeID, propsJSON, nil
	}
	resume := func(token string) (*runtime.Poller[armcosmos.CassandraResourcesClientCreateUpdateCassandraKeyspaceResponse], error) {
		return resumePoller[armcosmos.CassandraResourcesClientCreateUpdateCassandraKeyspaceResponse](k.pipeline, token)
	}

	switch reqID.OperationType {
	case lroOpCreate:
		return statusLRO(ctx, request, &reqID, resource.OperationCreate, resume, complete)
	case lroOpUpdate:
		return statusLRO(ctx, request, &reqID, resource.OperationUpdate, resume, complete)
	case lroOpDelete:
		return statusDeleteLRO(ctx, request, &reqID,
			func(token string) (*runtime.Poller[armcosmos.CassandraResourcesClientDeleteCassandraKeyspaceResponse], error) {
				return resumePoller[armcosmos.CassandraResourcesClientDeleteCassandraKeyspaceResponse](k.pipeline, token)
			}, nil)
	default:
		return nil, fmt.Errorf("unknown operation type: %s", reqID.OperationType)
	}
}

func (k *CosmosCassandraKeyspace) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	accountName := request.AdditionalProperties["accountName"]

	var nativeIDs []string
	pager := k.api.NewListCassandraKeyspacesPager(rgName, accountName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list Cosmos Cassandra keyspaces in account %s: %w", accountName, err)
		}
		for _, keyspace := range page.Value {
			if keyspace.ID != nil {
				nativeIDs = append(nativeIDs, *keyspace.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
