// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v4"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypePrivateDnsZoneGroup = "Azure::Network::PrivateDnsZoneGroup"

type privateDnsZoneGroupsAPI interface {
	BeginCreateOrUpdate(ctx context.Context, resourceGroupName string, privateEndpointName string, privateDNSZoneGroupName string, parameters armnetwork.PrivateDNSZoneGroup, options *armnetwork.PrivateDNSZoneGroupsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.PrivateDNSZoneGroupsClientCreateOrUpdateResponse], error)
	Get(ctx context.Context, resourceGroupName string, privateEndpointName string, privateDNSZoneGroupName string, options *armnetwork.PrivateDNSZoneGroupsClientGetOptions) (armnetwork.PrivateDNSZoneGroupsClientGetResponse, error)
	BeginDelete(ctx context.Context, resourceGroupName string, privateEndpointName string, privateDNSZoneGroupName string, options *armnetwork.PrivateDNSZoneGroupsClientBeginDeleteOptions) (*runtime.Poller[armnetwork.PrivateDNSZoneGroupsClientDeleteResponse], error)
	NewListPager(privateEndpointName string, resourceGroupName string, options *armnetwork.PrivateDNSZoneGroupsClientListOptions) *runtime.Pager[armnetwork.PrivateDNSZoneGroupsClientListResponse]
}

func init() {
	registry.Register(ResourceTypePrivateDnsZoneGroup, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &PrivateDnsZoneGroup{
			api:      c.PrivateDnsZoneGroupsClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// PrivateDnsZoneGroup is the provisioner for the binding between a Private
// Endpoint and one or more Private DNS Zones.
type PrivateDnsZoneGroup struct {
	api      privateDnsZoneGroupsAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

func zoneGroupPathParts(nativeID string) (rg, peName, groupName string, err error) {
	parts := splitResourceID(nativeID)
	rg = parts["resourcegroups"]
	peName = parts["privateendpoints"]
	groupName = parts["privatednszonegroups"]
	if rg == "" || peName == "" || groupName == "" {
		return "", "", "", fmt.Errorf("invalid NativeID: cannot extract resourceGroup/privateEndpoint/zoneGroup from %s", nativeID)
	}
	return rg, peName, groupName, nil
}

func (g *PrivateDnsZoneGroup) buildParams(props map[string]any) (armnetwork.PrivateDNSZoneGroup, error) {
	configsRaw, ok := props["privateDnsZoneConfigs"].([]any)
	if !ok || len(configsRaw) == 0 {
		return armnetwork.PrivateDNSZoneGroup{}, fmt.Errorf("privateDnsZoneConfigs is required")
	}
	configs := make([]*armnetwork.PrivateDNSZoneConfig, 0, len(configsRaw))
	for i, cRaw := range configsRaw {
		cMap, ok := cRaw.(map[string]any)
		if !ok {
			return armnetwork.PrivateDNSZoneGroup{}, fmt.Errorf("privateDnsZoneConfigs[%d] must be an object", i)
		}
		name, _ := cMap["name"].(string)
		zoneID, _ := cMap["privateDnsZoneId"].(string)
		if name == "" || zoneID == "" {
			return armnetwork.PrivateDNSZoneGroup{}, fmt.Errorf("privateDnsZoneConfigs[%d] requires name and privateDnsZoneId", i)
		}
		configs = append(configs, &armnetwork.PrivateDNSZoneConfig{
			Name: stringPtr(name),
			Properties: &armnetwork.PrivateDNSZonePropertiesFormat{
				PrivateDNSZoneID: stringPtr(zoneID),
			},
		})
	}
	return armnetwork.PrivateDNSZoneGroup{
		Properties: &armnetwork.PrivateDNSZoneGroupPropertiesFormat{
			PrivateDNSZoneConfigs: configs,
		},
	}, nil
}

func serializePrivateDnsZoneGroupProperties(result armnetwork.PrivateDNSZoneGroup, rgName, peName, groupName string) (json.RawMessage, error) {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	props["privateEndpointName"] = peName
	if result.Name != nil {
		props["name"] = *result.Name
	} else {
		props["name"] = groupName
	}
	if result.ID != nil {
		props["id"] = *result.ID
	}
	if result.Properties != nil && len(result.Properties.PrivateDNSZoneConfigs) > 0 {
		out := make([]map[string]any, 0, len(result.Properties.PrivateDNSZoneConfigs))
		for _, c := range result.Properties.PrivateDNSZoneConfigs {
			if c == nil {
				continue
			}
			m := make(map[string]any)
			if c.Name != nil {
				m["name"] = *c.Name
			}
			if c.Properties != nil && c.Properties.PrivateDNSZoneID != nil {
				m["privateDnsZoneId"] = *c.Properties.PrivateDNSZoneID
			}
			out = append(out, m)
		}
		props["privateDnsZoneConfigs"] = out
	}
	return json.Marshal(props)
}

func (g *PrivateDnsZoneGroup) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props map[string]any
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	rgName, ok := props["resourceGroupName"].(string)
	if !ok || rgName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	peName, ok := props["privateEndpointName"].(string)
	if !ok || peName == "" {
		return nil, fmt.Errorf("privateEndpointName is required")
	}
	groupName, ok := props["name"].(string)
	if !ok || groupName == "" {
		groupName = request.Label
	}

	params, err := g.buildParams(props)
	if err != nil {
		return nil, err
	}

	poller, err := g.api.BeginCreateOrUpdate(ctx, rgName, peName, groupName, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       mapAzureErrorToOperationErrorCode(err),
			},
		}, nil
	}
	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/privateEndpoints/%s/privateDnsZoneGroups/%s",
		g.config.SubscriptionId, rgName, peName, groupName)

	if poller.Done() {
		result, err := poller.Result(ctx)
		if err != nil {
			return &resource.CreateResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationCreate,
					OperationStatus: resource.OperationStatusFailure,
					ErrorCode:       mapAzureErrorToOperationErrorCode(err),
				},
			}, nil
		}
		propsJSON, err := serializePrivateDnsZoneGroupProperties(result.PrivateDNSZoneGroup, rgName, peName, groupName)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize PrivateDnsZoneGroup properties: %w", err)
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

func (g *PrivateDnsZoneGroup) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, peName, groupName, err := zoneGroupPathParts(request.NativeID)
	if err != nil {
		return nil, err
	}
	result, err := g.api.Get(ctx, rgName, peName, groupName, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: mapAzureErrorToOperationErrorCode(err)}, nil
	}
	propsJSON, err := serializePrivateDnsZoneGroupProperties(result.PrivateDNSZoneGroup, rgName, peName, groupName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize PrivateDnsZoneGroup properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypePrivateDnsZoneGroup,
		Properties:   string(propsJSON),
	}, nil
}

func (g *PrivateDnsZoneGroup) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, peName, groupName, err := zoneGroupPathParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props map[string]any
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	params, err := g.buildParams(props)
	if err != nil {
		return nil, err
	}

	poller, err := g.api.BeginCreateOrUpdate(ctx, rgName, peName, groupName, params, nil)
	if err != nil {
		return &resource.UpdateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationUpdate,
				OperationStatus: resource.OperationStatusFailure,
				NativeID:        request.NativeID,
				ErrorCode:       mapAzureErrorToOperationErrorCode(err),
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
					ErrorCode:       mapAzureErrorToOperationErrorCode(err),
				},
			}, nil
		}
		propsJSON, err := serializePrivateDnsZoneGroupProperties(result.PrivateDNSZoneGroup, rgName, peName, groupName)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize PrivateDnsZoneGroup properties: %w", err)
		}
		return &resource.UpdateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:          resource.OperationUpdate,
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

func (g *PrivateDnsZoneGroup) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, peName, groupName, err := zoneGroupPathParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, err := g.api.BeginDelete(ctx, rgName, peName, groupName, nil)
	if err != nil {
		if mapAzureErrorToOperationErrorCode(err) == resource.OperationErrorCodeNotFound {
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
				ErrorCode:       mapAzureErrorToOperationErrorCode(err),
			},
		}, fmt.Errorf("failed to start PrivateDnsZoneGroup deletion: %w", err)
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

func (g *PrivateDnsZoneGroup) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	reqID, err := decodeLROStatus(request.RequestID)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
			},
		}, err
	}

	switch reqID.OperationType {
	case lroOpCreate, lroOpUpdate:
		return g.statusCreateOrUpdate(ctx, request, &reqID)
	case lroOpDelete:
		return g.statusDelete(ctx, request, &reqID)
	default:
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
			},
		}, fmt.Errorf("unknown operation type: %s", reqID.OperationType)
	}
}

func (g *PrivateDnsZoneGroup) statusCreateOrUpdate(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	operation := resource.OperationCreate
	if reqID.OperationType == lroOpUpdate {
		operation = resource.OperationUpdate
	}
	poller, err := resumePoller[armnetwork.PrivateDNSZoneGroupsClientCreateOrUpdateResponse](g.pipeline, reqID.ResumeToken)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       operation,
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
			},
		}, fmt.Errorf("failed to resume poller: %w", err)
	}
	if poller.Done() {
		return g.handleCreateOrUpdateComplete(ctx, request, poller, operation)
	}
	if _, err = poller.Poll(ctx); err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       operation,
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       mapAzureErrorToOperationErrorCode(err),
			},
		}, nil
	}
	if poller.Done() {
		return g.handleCreateOrUpdateComplete(ctx, request, poller, operation)
	}
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       operation,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       request.RequestID,
			NativeID:        reqID.NativeID,
		},
	}, nil
}

func (g *PrivateDnsZoneGroup) handleCreateOrUpdateComplete(ctx context.Context, request *resource.StatusRequest, poller *runtime.Poller[armnetwork.PrivateDNSZoneGroupsClientCreateOrUpdateResponse], operation resource.Operation) (*resource.StatusResult, error) {
	result, err := poller.Result(ctx)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       operation,
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       mapAzureErrorToOperationErrorCode(err),
			},
		}, nil
	}
	parts := splitResourceID(*result.ID)
	rgName := parts["resourcegroups"]
	peName := parts["privateendpoints"]
	propsJSON, err := serializePrivateDnsZoneGroupProperties(result.PrivateDNSZoneGroup, rgName, peName, *result.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize PrivateDnsZoneGroup properties: %w", err)
	}
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			Operation:          operation,
			OperationStatus:    resource.OperationStatusSuccess,
			RequestID:          request.RequestID,
			NativeID:           *result.ID,
			ResourceProperties: propsJSON,
		},
	}, nil
}

// verifyZoneGroupGone bridges Azure's eventual-consistency window between
// "zone group LRO Done" and "parent private endpoint observes the zone group
// is removed". Same shape as PrivateDnsZoneVNetLink.verifyLinkGone — synchronous
// bounded poll until Get returns 404, then a small settle buffer.
func (g *PrivateDnsZoneGroup) verifyZoneGroupGone(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) *resource.StatusResult {
	success := &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationDelete,
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
			NativeID:        reqID.NativeID,
		},
	}

	rgName, peName, groupName, err := zoneGroupPathParts(reqID.NativeID)
	if err != nil {
		return success
	}

	const (
		pollInterval = 2 * time.Second
		maxAttempts  = 15 // up to 30s
		settleBuffer = 3 * time.Second
	)
	for i := 0; i < maxAttempts; i++ {
		if _, err := g.api.Get(ctx, rgName, peName, groupName, nil); err != nil && isDeleteSuccessError(err) {
			select {
			case <-ctx.Done():
			case <-time.After(settleBuffer):
			}
			return success
		}
		select {
		case <-ctx.Done():
			return success
		case <-time.After(pollInterval):
		}
	}
	return success
}

func (g *PrivateDnsZoneGroup) statusDelete(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	poller, err := resumePoller[armnetwork.PrivateDNSZoneGroupsClientDeleteResponse](g.pipeline, reqID.ResumeToken)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationDelete,
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
			},
		}, fmt.Errorf("failed to resume poller: %w", err)
	}
	failure := func(err error) *resource.StatusResult {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationDelete,
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       mapAzureErrorToOperationErrorCode(err),
			},
		}
	}
	if poller.Done() {
		_, err := poller.Result(ctx)
		if err != nil && !isDeleteSuccessError(err) {
			return failure(err), nil
		}
		return g.verifyZoneGroupGone(ctx, request, reqID), nil
	}
	if _, err = poller.Poll(ctx); err != nil {
		if isDeleteSuccessError(err) {
			return g.verifyZoneGroupGone(ctx, request, reqID), nil
		}
		return failure(err), nil
	}
	if poller.Done() {
		_, err := poller.Result(ctx)
		if err != nil && !isDeleteSuccessError(err) {
			return failure(err), nil
		}
		return g.verifyZoneGroupGone(ctx, request, reqID), nil
	}
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationDelete,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       request.RequestID,
			NativeID:        reqID.NativeID,
		},
	}, nil
}

func (g *PrivateDnsZoneGroup) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	peName := request.AdditionalProperties["privateEndpointName"]
	if rgName == "" || peName == "" {
		return &resource.ListResult{}, nil
	}
	pager := g.api.NewListPager(peName, rgName, nil)
	var nativeIDs []string
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list private dns zone groups: %w", err)
		}
		for _, x := range page.Value {
			if x != nil && x.ID != nil {
				nativeIDs = append(nativeIDs, *x.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
