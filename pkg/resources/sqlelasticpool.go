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

const ResourceTypeSQLElasticPool = "AZURE::Sql::ElasticPool"

type sqlElasticPoolsAPI interface {
	BeginCreateOrUpdate(ctx context.Context, resourceGroupName string, serverName string, elasticPoolName string, parameters armsql.ElasticPool, options *armsql.ElasticPoolsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armsql.ElasticPoolsClientCreateOrUpdateResponse], error)
	Get(ctx context.Context, resourceGroupName string, serverName string, elasticPoolName string, options *armsql.ElasticPoolsClientGetOptions) (armsql.ElasticPoolsClientGetResponse, error)
	BeginUpdate(ctx context.Context, resourceGroupName string, serverName string, elasticPoolName string, parameters armsql.ElasticPoolUpdate, options *armsql.ElasticPoolsClientBeginUpdateOptions) (*runtime.Poller[armsql.ElasticPoolsClientUpdateResponse], error)
	BeginDelete(ctx context.Context, resourceGroupName string, serverName string, elasticPoolName string, options *armsql.ElasticPoolsClientBeginDeleteOptions) (*runtime.Poller[armsql.ElasticPoolsClientDeleteResponse], error)
	NewListByServerPager(resourceGroupName string, serverName string, options *armsql.ElasticPoolsClientListByServerOptions) *runtime.Pager[armsql.ElasticPoolsClientListByServerResponse]
	// NewListServersPager enumerates SQL servers so pools can be discovered even
	// when no parent server is supplied via AdditionalProperties (mirrors SqlDatabase).
	NewListServersPager(options *armsql.ServersClientListOptions) *runtime.Pager[armsql.ServersClientListResponse]
}

// sqlElasticPoolsClientWrapper composes the SDK ElasticPools client with the
// parent Servers client so List can fall back to enumerating servers.
type sqlElasticPoolsClientWrapper struct {
	*armsql.ElasticPoolsClient
	serversClient *armsql.ServersClient
}

func (w *sqlElasticPoolsClientWrapper) NewListServersPager(options *armsql.ServersClientListOptions) *runtime.Pager[armsql.ServersClientListResponse] {
	return w.serversClient.NewListPager(options)
}

func init() {
	registry.Register(ResourceTypeSQLElasticPool, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &SqlElasticPool{
			api: &sqlElasticPoolsClientWrapper{
				ElasticPoolsClient: c.SQLElasticPoolsClient,
				serversClient:      c.SQLServersClient,
			},
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// SqlElasticPool is the provisioner for Azure SQL elastic pools
// (Microsoft.Sql/servers/elasticPools).
type SqlElasticPool struct {
	api      sqlElasticPoolsAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

func sqlElasticPoolIDParts(resourceID string) (rgName, serverName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "servers", "elasticpools")
	if err != nil {
		return "", "", "", err
	}
	return rgName, names["servers"], names["elasticpools"], nil
}

func (p *SqlElasticPool) buildPropertiesFromResult(pool *armsql.ElasticPool, rgName, serverName string) map[string]any {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	props["serverName"] = serverName

	if pool.ID != nil {
		props["id"] = *pool.ID
	}
	if pool.Name != nil {
		props["name"] = *pool.Name
	}
	if pool.Location != nil {
		props["location"] = strings.ToLower(strings.ReplaceAll(*pool.Location, " ", ""))
	}

	if sku := pool.SKU; sku != nil {
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

	if pool.Properties != nil {
		if pool.Properties.MaxSizeBytes != nil {
			props["maxSizeBytes"] = *pool.Properties.MaxSizeBytes
		}
		if pool.Properties.ZoneRedundant != nil {
			props["zoneRedundant"] = *pool.Properties.ZoneRedundant
		}
		if pool.Properties.State != nil {
			props["state"] = string(*pool.Properties.State)
		}
		if pds := pool.Properties.PerDatabaseSettings; pds != nil {
			s := make(map[string]any)
			if pds.MinCapacity != nil {
				s["minCapacity"] = *pds.MinCapacity
			}
			if pds.MaxCapacity != nil {
				s["maxCapacity"] = *pds.MaxCapacity
			}
			if len(s) > 0 {
				props["perDatabaseSettings"] = s
			}
		}
	}

	if tags := azureTagsToFormaeTags(pool.Tags); tags != nil {
		props["Tags"] = tags
	}

	return props
}

func buildElasticPoolSKU(props map[string]any) *armsql.SKU {
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

func buildPerDatabaseSettings(props map[string]any) *armsql.ElasticPoolPerDatabaseSettings {
	raw, ok := props["perDatabaseSettings"].(map[string]any)
	if !ok {
		return nil
	}
	pds := &armsql.ElasticPoolPerDatabaseSettings{}
	if v, ok := raw["minCapacity"].(float64); ok {
		pds.MinCapacity = to.Ptr(v)
	}
	if v, ok := raw["maxCapacity"].(float64); ok {
		pds.MaxCapacity = to.Ptr(v)
	}
	if pds.MinCapacity == nil && pds.MaxCapacity == nil {
		return nil
	}
	return pds
}

func buildElasticPoolParams(props map[string]any, location string) armsql.ElasticPool {
	poolProps := &armsql.ElasticPoolProperties{}
	if v, ok := maxSizeBytes(props["maxSizeBytes"]); ok {
		poolProps.MaxSizeBytes = to.Ptr(v)
	}
	if v, ok := props["zoneRedundant"].(bool); ok {
		poolProps.ZoneRedundant = to.Ptr(v)
	}
	poolProps.PerDatabaseSettings = buildPerDatabaseSettings(props)

	params := armsql.ElasticPool{
		Location:   to.Ptr(location),
		Properties: poolProps,
	}
	if sku := buildElasticPoolSKU(props); sku != nil {
		params.SKU = sku
	}
	return params
}

func (p *SqlElasticPool) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
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
	poolName, ok := props["name"].(string)
	if !ok || poolName == "" {
		poolName = request.Label
	}

	params := buildElasticPoolParams(props, location)
	if azureTags := formaeTagsToAzureTags(request.Properties); azureTags != nil {
		params.Tags = azureTags
	}

	poller, err := p.api.BeginCreateOrUpdate(ctx, rgName, serverName, poolName, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Sql/servers/%s/elasticPools/%s",
		p.config.SubscriptionId, rgName, serverName, poolName)

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
		propsJSON, err := json.Marshal(p.buildPropertiesFromResult(&result.ElasticPool, rgName, serverName))
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

func (p *SqlElasticPool) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, serverName, poolName, err := sqlElasticPoolIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := p.api.Get(ctx, rgName, serverName, poolName, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(p.buildPropertiesFromResult(&result.ElasticPool, rgName, serverName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeSQLElasticPool,
		Properties:   string(propsJSON),
	}, nil
}

// Update resizes in place: a SKU or per-database-settings change is an ARM
// update, never a replace, so member databases keep running.
func (p *SqlElasticPool) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, serverName, poolName, err := sqlElasticPoolIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props map[string]any
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	updateProps := &armsql.ElasticPoolUpdateProperties{}
	if v, ok := maxSizeBytes(props["maxSizeBytes"]); ok {
		updateProps.MaxSizeBytes = to.Ptr(v)
	}
	if v, ok := props["zoneRedundant"].(bool); ok {
		updateProps.ZoneRedundant = to.Ptr(v)
	}
	updateProps.PerDatabaseSettings = buildPerDatabaseSettings(props)

	params := armsql.ElasticPoolUpdate{Properties: updateProps}
	if sku := buildElasticPoolSKU(props); sku != nil {
		params.SKU = sku
	}
	if azureTags := formaeTagsToAzureTags(request.DesiredProperties); azureTags != nil {
		params.Tags = azureTags
	}

	poller, err := p.api.BeginUpdate(ctx, rgName, serverName, poolName, params, nil)
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
		propsJSON, err := json.Marshal(p.buildPropertiesFromResult(&result.ElasticPool, rgName, serverName))
		if err != nil {
			return nil, fmt.Errorf("failed to marshal response properties: %w", err)
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

func (p *SqlElasticPool) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, serverName, poolName, err := sqlElasticPoolIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, err := p.api.BeginDelete(ctx, rgName, serverName, poolName, nil)
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

func (p *SqlElasticPool) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	reqID, err := decodeLROStatus(request.RequestID)
	if err != nil {
		return nil, err
	}

	switch reqID.OperationType {
	case lroOpCreate:
		return statusLRO(ctx, request, &reqID, resource.OperationCreate,
			func(token string) (*runtime.Poller[armsql.ElasticPoolsClientCreateOrUpdateResponse], error) {
				return resumePoller[armsql.ElasticPoolsClientCreateOrUpdateResponse](p.pipeline, token)
			},
			func(_ context.Context, result armsql.ElasticPoolsClientCreateOrUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				return p.completeFromElasticPool(&result.ElasticPool)
			})
	case lroOpUpdate:
		return statusLRO(ctx, request, &reqID, resource.OperationUpdate,
			func(token string) (*runtime.Poller[armsql.ElasticPoolsClientUpdateResponse], error) {
				return resumePoller[armsql.ElasticPoolsClientUpdateResponse](p.pipeline, token)
			},
			func(_ context.Context, result armsql.ElasticPoolsClientUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				return p.completeFromElasticPool(&result.ElasticPool)
			})
	case lroOpDelete:
		return statusDeleteLRO(ctx, request, &reqID,
			func(token string) (*runtime.Poller[armsql.ElasticPoolsClientDeleteResponse], error) {
				return resumePoller[armsql.ElasticPoolsClientDeleteResponse](p.pipeline, token)
			}, nil)
	default:
		return nil, fmt.Errorf("unknown operation type: %s", reqID.OperationType)
	}
}

func (p *SqlElasticPool) completeFromElasticPool(pool *armsql.ElasticPool) (string, json.RawMessage, error) {
	nativeID := ""
	rgName, serverName := "", ""
	if pool.ID != nil {
		nativeID = *pool.ID
		if rg, srv, _, err := sqlElasticPoolIDParts(*pool.ID); err == nil {
			rgName, serverName = rg, srv
		}
	}
	propsJSON, err := json.Marshal(p.buildPropertiesFromResult(pool, rgName, serverName))
	if err != nil {
		return "", nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return nativeID, propsJSON, nil
}

func (p *SqlElasticPool) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	serverName := request.AdditionalProperties["serverName"]

	if rgName != "" && serverName != "" {
		ids, err := p.listByServer(ctx, rgName, serverName)
		if err != nil {
			return nil, err
		}
		return &resource.ListResult{NativeIDs: ids}, nil
	}

	var nativeIDs []string
	serverPager := p.api.NewListServersPager(nil)
	for serverPager.More() {
		page, err := serverPager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list sql servers for elastic pool discovery: %w", err)
		}
		for _, server := range page.Value {
			if server.ID == nil {
				continue
			}
			rg, srv, err := sqlServerIDParts(*server.ID)
			if err != nil {
				continue
			}
			ids, err := p.listByServer(ctx, rg, srv)
			if err != nil {
				return nil, err
			}
			nativeIDs = append(nativeIDs, ids...)
		}
	}

	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}

func (p *SqlElasticPool) listByServer(ctx context.Context, rgName, serverName string) ([]string, error) {
	pager := p.api.NewListByServerPager(rgName, serverName, nil)

	var nativeIDs []string
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list elastic pools for server %s: %w", serverName, err)
		}
		for _, pool := range page.Value {
			if pool.ID != nil {
				nativeIDs = append(nativeIDs, *pool.ID)
			}
		}
	}
	return nativeIDs, nil
}
