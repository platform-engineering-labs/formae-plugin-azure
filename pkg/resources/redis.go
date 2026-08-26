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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/redis/armredis/v3"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeRedis = "AZURE::Cache::Redis"

// redisAPI is the armredis surface used here. Create, Update and Delete are all
// LROs, and they are slow: a Basic C0 create takes 15-20 minutes.
type redisAPI interface {
	BeginCreate(ctx context.Context, resourceGroupName string, name string, parameters armredis.CreateParameters, options *armredis.ClientBeginCreateOptions) (*runtime.Poller[armredis.ClientCreateResponse], error)
	Get(ctx context.Context, resourceGroupName string, name string, options *armredis.ClientGetOptions) (armredis.ClientGetResponse, error)
	BeginUpdate(ctx context.Context, resourceGroupName string, name string, parameters armredis.UpdateParameters, options *armredis.ClientBeginUpdateOptions) (*runtime.Poller[armredis.ClientUpdateResponse], error)
	BeginDelete(ctx context.Context, resourceGroupName string, name string, options *armredis.ClientBeginDeleteOptions) (*runtime.Poller[armredis.ClientDeleteResponse], error)
	NewListBySubscriptionPager(options *armredis.ClientListBySubscriptionOptions) *runtime.Pager[armredis.ClientListBySubscriptionResponse]
	NewListByResourceGroupPager(resourceGroupName string, options *armredis.ClientListByResourceGroupOptions) *runtime.Pager[armredis.ClientListByResourceGroupResponse]
}

func init() {
	registry.Register(ResourceTypeRedis, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &Redis{
			api:      c.RedisClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// Redis is the provisioner for Azure Cache for Redis (Microsoft.Cache/redis).
//
// Unlike most Azure services, ARM returns the access keys INLINE on the resource
// read rather than only from a separate ListKeys call. buildPropertiesFromResult
// therefore has to actively omit them: serializing the response straight through
// would write live credentials into resource state.
type Redis struct {
	api      redisAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

// redisProps mirrors schema/pkl/cache/redis.pkl.
type redisProps struct {
	Name                           string         `json:"name"`
	Location                       string         `json:"location"`
	ResourceGroupName              string         `json:"resourceGroupName"`
	SKU                            *redisSKUProps `json:"sku"`
	EnableNonSslPort               *bool          `json:"enableNonSslPort"`
	MinimumTLSVersion              string         `json:"minimumTlsVersion"`
	PublicNetworkAccess            string         `json:"publicNetworkAccess"`
	DisableAccessKeyAuthentication *bool          `json:"disableAccessKeyAuthentication"`
	ShardCount                     *int32         `json:"shardCount"`
	ReplicasPerPrimary             *int32         `json:"replicasPerPrimary"`
}

type redisSKUProps struct {
	Name     string `json:"name"`
	Family   string `json:"family"`
	Capacity int32  `json:"capacity"`
}

func redisIDParts(resourceID string) (rgName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "redis")
	if err != nil {
		return "", "", err
	}
	return rgName, names["redis"], nil
}

func (r *Redis) buildPropertiesFromResult(info *armredis.ResourceInfo, rgName string) map[string]any {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName

	if info.ID != nil {
		props["id"] = *info.ID
	}
	if info.Name != nil {
		props["name"] = *info.Name
	}
	if info.Location != nil {
		props["location"] = normalizeAzureLocation(*info.Location)
	}

	if p := info.Properties; p != nil {
		if sku := p.SKU; sku != nil {
			s := map[string]any{}
			if sku.Name != nil {
				s["name"] = canonicalizeEnum(string(*sku.Name), "Basic", "Standard", "Premium")
			}
			if sku.Family != nil {
				s["family"] = canonicalizeEnum(string(*sku.Family), "C", "P")
			}
			if sku.Capacity != nil {
				s["capacity"] = *sku.Capacity
			}
			if len(s) > 0 {
				props["sku"] = s
			}
		}
		if p.EnableNonSSLPort != nil {
			props["enableNonSslPort"] = *p.EnableNonSSLPort
		}
		if p.MinimumTLSVersion != nil {
			props["minimumTlsVersion"] = string(*p.MinimumTLSVersion)
		}
		if p.PublicNetworkAccess != nil {
			props["publicNetworkAccess"] = canonicalizeEnum(string(*p.PublicNetworkAccess), "Enabled", "Disabled")
		}
		if p.DisableAccessKeyAuthentication != nil {
			props["disableAccessKeyAuthentication"] = *p.DisableAccessKeyAuthentication
		}
		if p.ShardCount != nil {
			props["shardCount"] = *p.ShardCount
		}
		if p.ReplicasPerPrimary != nil {
			props["replicasPerPrimary"] = *p.ReplicasPerPrimary
		}
		if p.HostName != nil {
			props["hostName"] = *p.HostName
		}
		if p.SSLPort != nil {
			props["sslPort"] = *p.SSLPort
		}
		// p.AccessKeys is deliberately NOT copied: ARM returns the primary and
		// secondary keys inline here, and they must never reach resource state.
	}

	if tags := azureTagsToFormaeTags(info.Tags); tags != nil {
		props["Tags"] = tags
	}

	return props
}

func redisSKUFromProps(props redisProps) *armredis.SKU {
	if props.SKU == nil || props.SKU.Name == "" || props.SKU.Family == "" {
		return nil
	}
	return &armredis.SKU{
		Name:     to.Ptr(armredis.SKUName(props.SKU.Name)),
		Family:   to.Ptr(armredis.SKUFamily(props.SKU.Family)),
		Capacity: to.Ptr(props.SKU.Capacity),
	}
}

func (r *Redis) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props redisProps
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	if props.Location == "" {
		return nil, fmt.Errorf("location is required")
	}
	sku := redisSKUFromProps(props)
	if sku == nil {
		return nil, fmt.Errorf("sku.name and sku.family are required")
	}
	name := props.Name
	if name == "" {
		name = request.Label
	}
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}

	createProps := &armredis.CreateProperties{SKU: sku}
	if props.EnableNonSslPort != nil {
		createProps.EnableNonSSLPort = props.EnableNonSslPort
	}
	if props.MinimumTLSVersion != "" {
		createProps.MinimumTLSVersion = to.Ptr(armredis.TLSVersion(props.MinimumTLSVersion))
	}
	if props.PublicNetworkAccess != "" {
		createProps.PublicNetworkAccess = to.Ptr(armredis.PublicNetworkAccess(props.PublicNetworkAccess))
	}
	if props.DisableAccessKeyAuthentication != nil {
		createProps.DisableAccessKeyAuthentication = props.DisableAccessKeyAuthentication
	}
	if props.ShardCount != nil {
		createProps.ShardCount = props.ShardCount
	}
	if props.ReplicasPerPrimary != nil {
		createProps.ReplicasPerPrimary = props.ReplicasPerPrimary
	}

	params := armredis.CreateParameters{
		Location:   to.Ptr(props.Location),
		Properties: createProps,
	}
	if azureTags := formaeTagsToAzureTags(request.Properties); azureTags != nil {
		params.Tags = azureTags
	}

	poller, err := r.api.BeginCreate(ctx, props.ResourceGroupName, name, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Cache/redis/%s",
		r.config.SubscriptionId, props.ResourceGroupName, name)

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
		propsJSON, err := json.Marshal(r.buildPropertiesFromResult(&result.ResourceInfo, props.ResourceGroupName))
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

func (r *Redis) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, name, err := redisIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := r.api.Get(ctx, rgName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(r.buildPropertiesFromResult(&result.ResourceInfo, rgName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeRedis,
		Properties:   string(propsJSON),
	}, nil
}

// Update patches in place. A SKU change is a scale operation, not a replace, and
// takes as long as a create.
func (r *Redis) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, name, err := redisIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props redisProps
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	updateProps := &armredis.UpdateProperties{}
	if sku := redisSKUFromProps(props); sku != nil {
		updateProps.SKU = sku
	}
	if props.EnableNonSslPort != nil {
		updateProps.EnableNonSSLPort = props.EnableNonSslPort
	}
	if props.MinimumTLSVersion != "" {
		updateProps.MinimumTLSVersion = to.Ptr(armredis.TLSVersion(props.MinimumTLSVersion))
	}
	if props.PublicNetworkAccess != "" {
		updateProps.PublicNetworkAccess = to.Ptr(armredis.PublicNetworkAccess(props.PublicNetworkAccess))
	}
	if props.DisableAccessKeyAuthentication != nil {
		updateProps.DisableAccessKeyAuthentication = props.DisableAccessKeyAuthentication
	}
	if props.ShardCount != nil {
		updateProps.ShardCount = props.ShardCount
	}
	if props.ReplicasPerPrimary != nil {
		updateProps.ReplicasPerPrimary = props.ReplicasPerPrimary
	}

	params := armredis.UpdateParameters{Properties: updateProps}
	if azureTags := formaeTagsToAzureTags(request.DesiredProperties); azureTags != nil {
		params.Tags = azureTags
	}

	poller, err := r.api.BeginUpdate(ctx, rgName, name, params, nil)
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
		propsJSON, err := json.Marshal(r.buildPropertiesFromResult(&result.ResourceInfo, rgName))
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

func (r *Redis) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, name, err := redisIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, err := r.api.BeginDelete(ctx, rgName, name, nil)
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

func (r *Redis) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	reqID, err := decodeLROStatus(request.RequestID)
	if err != nil {
		return nil, err
	}

	switch reqID.OperationType {
	case lroOpCreate:
		return statusLRO(ctx, request, &reqID, resource.OperationCreate,
			func(token string) (*runtime.Poller[armredis.ClientCreateResponse], error) {
				return resumePoller[armredis.ClientCreateResponse](r.pipeline, token)
			},
			func(_ context.Context, result armredis.ClientCreateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				return r.completeFromResourceInfo(&result.ResourceInfo)
			})
	case lroOpUpdate:
		return statusLRO(ctx, request, &reqID, resource.OperationUpdate,
			func(token string) (*runtime.Poller[armredis.ClientUpdateResponse], error) {
				return resumePoller[armredis.ClientUpdateResponse](r.pipeline, token)
			},
			func(_ context.Context, result armredis.ClientUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				return r.completeFromResourceInfo(&result.ResourceInfo)
			})
	case lroOpDelete:
		return statusDeleteLRO(ctx, request, &reqID,
			func(token string) (*runtime.Poller[armredis.ClientDeleteResponse], error) {
				return resumePoller[armredis.ClientDeleteResponse](r.pipeline, token)
			}, nil)
	default:
		return nil, fmt.Errorf("unknown operation type: %s", reqID.OperationType)
	}
}

func (r *Redis) completeFromResourceInfo(info *armredis.ResourceInfo) (string, json.RawMessage, error) {
	nativeID := ""
	rgName := ""
	if info.ID != nil {
		nativeID = *info.ID
		if rg, _, err := redisIDParts(*info.ID); err == nil {
			rgName = rg
		}
	}
	propsJSON, err := json.Marshal(r.buildPropertiesFromResult(info, rgName))
	if err != nil {
		return "", nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return nativeID, propsJSON, nil
}

func (r *Redis) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]

	var nativeIDs []string

	if rgName != "" {
		pager := r.api.NewListByResourceGroupPager(rgName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list redis caches: %w", err)
			}
			for _, info := range page.Value {
				if info.ID != nil {
					nativeIDs = append(nativeIDs, *info.ID)
				}
			}
		}
		return &resource.ListResult{NativeIDs: nativeIDs}, nil
	}

	pager := r.api.NewListBySubscriptionPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list redis caches: %w", err)
		}
		for _, info := range page.Value {
			if info.ID != nil {
				nativeIDs = append(nativeIDs, *info.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
