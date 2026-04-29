// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v4"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypePrivateEndpoint = "Azure::Network::PrivateEndpoint"

type privateEndpointsAPI interface {
	BeginCreateOrUpdate(ctx context.Context, resourceGroupName string, privateEndpointName string, parameters armnetwork.PrivateEndpoint, options *armnetwork.PrivateEndpointsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.PrivateEndpointsClientCreateOrUpdateResponse], error)
	Get(ctx context.Context, resourceGroupName string, privateEndpointName string, options *armnetwork.PrivateEndpointsClientGetOptions) (armnetwork.PrivateEndpointsClientGetResponse, error)
	BeginDelete(ctx context.Context, resourceGroupName string, privateEndpointName string, options *armnetwork.PrivateEndpointsClientBeginDeleteOptions) (*runtime.Poller[armnetwork.PrivateEndpointsClientDeleteResponse], error)
	NewListPager(resourceGroupName string, options *armnetwork.PrivateEndpointsClientListOptions) *runtime.Pager[armnetwork.PrivateEndpointsClientListResponse]
	NewListBySubscriptionPager(options *armnetwork.PrivateEndpointsClientListBySubscriptionOptions) *runtime.Pager[armnetwork.PrivateEndpointsClientListBySubscriptionResponse]
}

func init() {
	registry.Register(ResourceTypePrivateEndpoint, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &PrivateEndpoint{
			api:      c.PrivateEndpointsClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// PrivateEndpoint is the provisioner for Azure Private Endpoints.
type PrivateEndpoint struct {
	api      privateEndpointsAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

func (p *PrivateEndpoint) buildParams(props map[string]any, location string) (armnetwork.PrivateEndpoint, error) {
	params := armnetwork.PrivateEndpoint{
		Location:   stringPtr(location),
		Properties: &armnetwork.PrivateEndpointProperties{},
	}

	subnetID, ok := props["subnetId"].(string)
	if !ok || subnetID == "" {
		return params, fmt.Errorf("subnetId is required")
	}
	params.Properties.Subnet = &armnetwork.Subnet{ID: stringPtr(subnetID)}

	if cnif, ok := props["customNetworkInterfaceName"].(string); ok && cnif != "" {
		params.Properties.CustomNetworkInterfaceName = stringPtr(cnif)
	}

	connsRaw, ok := props["privateLinkServiceConnections"].([]any)
	if !ok || len(connsRaw) == 0 {
		return params, fmt.Errorf("privateLinkServiceConnections is required")
	}
	conns := make([]*armnetwork.PrivateLinkServiceConnection, 0, len(connsRaw))
	for i, cRaw := range connsRaw {
		cMap, ok := cRaw.(map[string]any)
		if !ok {
			return params, fmt.Errorf("privateLinkServiceConnections[%d] must be an object", i)
		}
		name, _ := cMap["name"].(string)
		linkID, _ := cMap["privateLinkServiceId"].(string)
		if name == "" || linkID == "" {
			return params, fmt.Errorf("privateLinkServiceConnections[%d] requires name and privateLinkServiceId", i)
		}
		groupIDsRaw, _ := cMap["groupIds"].([]any)
		groupIDs := make([]*string, 0, len(groupIDsRaw))
		for _, g := range groupIDsRaw {
			if gs, ok := g.(string); ok {
				groupIDs = append(groupIDs, stringPtr(gs))
			}
		}
		conn := &armnetwork.PrivateLinkServiceConnection{
			Name: stringPtr(name),
			Properties: &armnetwork.PrivateLinkServiceConnectionProperties{
				PrivateLinkServiceID: stringPtr(linkID),
				GroupIDs:             groupIDs,
			},
		}
		if rm, ok := cMap["requestMessage"].(string); ok && rm != "" {
			conn.Properties.RequestMessage = stringPtr(rm)
		}
		conns = append(conns, conn)
	}
	params.Properties.PrivateLinkServiceConnections = conns

	return params, nil
}

func serializePrivateEndpointProperties(result armnetwork.PrivateEndpoint, rgName, peName string) (json.RawMessage, error) {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	if result.Name != nil {
		props["name"] = *result.Name
	} else {
		props["name"] = peName
	}
	if result.Location != nil {
		props["location"] = *result.Location
	}
	if result.ID != nil {
		props["id"] = *result.ID
	}
	if result.Properties != nil {
		if result.Properties.Subnet != nil && result.Properties.Subnet.ID != nil {
			props["subnetId"] = *result.Properties.Subnet.ID
		}
		if result.Properties.CustomNetworkInterfaceName != nil && *result.Properties.CustomNetworkInterfaceName != "" {
			props["customNetworkInterfaceName"] = *result.Properties.CustomNetworkInterfaceName
		}
		if len(result.Properties.PrivateLinkServiceConnections) > 0 {
			out := make([]map[string]any, 0, len(result.Properties.PrivateLinkServiceConnections))
			for _, c := range result.Properties.PrivateLinkServiceConnections {
				if c == nil {
					continue
				}
				m := make(map[string]any)
				if c.Name != nil {
					m["name"] = *c.Name
				}
				if c.Properties != nil {
					if c.Properties.PrivateLinkServiceID != nil {
						m["privateLinkServiceId"] = *c.Properties.PrivateLinkServiceID
					}
					if len(c.Properties.GroupIDs) > 0 {
						gs := make([]string, 0, len(c.Properties.GroupIDs))
						for _, g := range c.Properties.GroupIDs {
							if g != nil {
								gs = append(gs, *g)
							}
						}
						m["groupIds"] = gs
					}
					if c.Properties.RequestMessage != nil && *c.Properties.RequestMessage != "" {
						m["requestMessage"] = *c.Properties.RequestMessage
					}
				}
				out = append(out, m)
			}
			props["privateLinkServiceConnections"] = out
		}
	}
	if tags := azureTagsToFormaeTags(result.Tags); tags != nil {
		props["Tags"] = tags
	}
	return json.Marshal(props)
}

func (p *PrivateEndpoint) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props map[string]any
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	rgName, ok := props["resourceGroupName"].(string)
	if !ok || rgName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	location, ok := props["location"].(string)
	if !ok || location == "" {
		return nil, fmt.Errorf("location is required")
	}
	peName, ok := props["name"].(string)
	if !ok || peName == "" {
		peName = request.Label
	}

	params, err := p.buildParams(props, location)
	if err != nil {
		return nil, err
	}
	if azureTags := formaeTagsToAzureTags(request.Properties); azureTags != nil {
		params.Tags = azureTags
	}

	poller, err := p.api.BeginCreateOrUpdate(ctx, rgName, peName, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       mapAzureErrorToOperationErrorCode(err),
			},
		}, nil
	}
	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/privateEndpoints/%s",
		p.config.SubscriptionId, rgName, peName)

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
		propsJSON, err := serializePrivateEndpointProperties(result.PrivateEndpoint, rgName, peName)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize PrivateEndpoint properties: %w", err)
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

func (p *PrivateEndpoint) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	parts := splitResourceID(request.NativeID)
	rgName := parts["resourcegroups"]
	peName := parts["privateendpoints"]
	if rgName == "" || peName == "" {
		return nil, fmt.Errorf("invalid NativeID: cannot extract resourceGroup or privateEndpoint name from %s", request.NativeID)
	}
	result, err := p.api.Get(ctx, rgName, peName, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: mapAzureErrorToOperationErrorCode(err)}, nil
	}
	propsJSON, err := serializePrivateEndpointProperties(result.PrivateEndpoint, rgName, peName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize PrivateEndpoint properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypePrivateEndpoint,
		Properties:   string(propsJSON),
	}, nil
}

func (p *PrivateEndpoint) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	parts := splitResourceID(request.NativeID)
	rgName := parts["resourcegroups"]
	peName := parts["privateendpoints"]
	if rgName == "" || peName == "" {
		return nil, fmt.Errorf("invalid NativeID: cannot extract resourceGroup or privateEndpoint name from %s", request.NativeID)
	}

	var props map[string]any
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	location, ok := props["location"].(string)
	if !ok || location == "" {
		return nil, fmt.Errorf("location is required")
	}

	params, err := p.buildParams(props, location)
	if err != nil {
		return nil, err
	}
	if azureTags := formaeTagsToAzureTags(request.DesiredProperties); azureTags != nil {
		params.Tags = azureTags
	}

	poller, err := p.api.BeginCreateOrUpdate(ctx, rgName, peName, params, nil)
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
		propsJSON, err := serializePrivateEndpointProperties(result.PrivateEndpoint, rgName, peName)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize PrivateEndpoint properties: %w", err)
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

func (p *PrivateEndpoint) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	parts := splitResourceID(request.NativeID)
	rgName := parts["resourcegroups"]
	peName := parts["privateendpoints"]
	if rgName == "" || peName == "" {
		return nil, fmt.Errorf("invalid NativeID: cannot extract resourceGroup or privateEndpoint name from %s", request.NativeID)
	}

	poller, err := p.api.BeginDelete(ctx, rgName, peName, nil)
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
		}, fmt.Errorf("failed to start PrivateEndpoint deletion: %w", err)
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

func (p *PrivateEndpoint) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
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
		return p.statusCreateOrUpdate(ctx, request, &reqID)
	case lroOpDelete:
		return p.statusDelete(ctx, request, &reqID)
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

func (p *PrivateEndpoint) statusCreateOrUpdate(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	operation := resource.OperationCreate
	if reqID.OperationType == lroOpUpdate {
		operation = resource.OperationUpdate
	}
	poller, err := resumePoller[armnetwork.PrivateEndpointsClientCreateOrUpdateResponse](p.pipeline, reqID.ResumeToken)
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
		return p.handleCreateOrUpdateComplete(ctx, request, poller, operation)
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
		return p.handleCreateOrUpdateComplete(ctx, request, poller, operation)
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

func (p *PrivateEndpoint) handleCreateOrUpdateComplete(ctx context.Context, request *resource.StatusRequest, poller *runtime.Poller[armnetwork.PrivateEndpointsClientCreateOrUpdateResponse], operation resource.Operation) (*resource.StatusResult, error) {
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
	propsJSON, err := serializePrivateEndpointProperties(result.PrivateEndpoint, rgName, *result.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize PrivateEndpoint properties: %w", err)
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

func (p *PrivateEndpoint) statusDelete(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	poller, err := resumePoller[armnetwork.PrivateEndpointsClientDeleteResponse](p.pipeline, reqID.ResumeToken)
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
	success := func() *resource.StatusResult {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationDelete,
				OperationStatus: resource.OperationStatusSuccess,
				RequestID:       request.RequestID,
				NativeID:        reqID.NativeID,
			},
		}
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
		return success(), nil
	}
	if _, err = poller.Poll(ctx); err != nil {
		if isDeleteSuccessError(err) {
			return success(), nil
		}
		return failure(err), nil
	}
	if poller.Done() {
		_, err := poller.Result(ctx)
		if err != nil && !isDeleteSuccessError(err) {
			return failure(err), nil
		}
		return success(), nil
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

func (p *PrivateEndpoint) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	resourceGroupName := request.AdditionalProperties["resourceGroupName"]
	var nativeIDs []string
	if resourceGroupName != "" {
		pager := p.api.NewListPager(resourceGroupName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list private endpoints: %w", err)
			}
			for _, x := range page.Value {
				if x != nil && x.ID != nil {
					nativeIDs = append(nativeIDs, *x.ID)
				}
			}
		}
	} else {
		pager := p.api.NewListBySubscriptionPager(nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list private endpoints: %w", err)
			}
			for _, x := range page.Value {
				if x != nil && x.ID != nil {
					nativeIDs = append(nativeIDs, *x.ID)
				}
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
