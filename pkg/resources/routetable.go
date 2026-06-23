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

const ResourceTypeRouteTable = "AZURE::Network::RouteTable"

type routeTablesAPI interface {
	BeginCreateOrUpdate(ctx context.Context, resourceGroupName string, routeTableName string, parameters armnetwork.RouteTable, options *armnetwork.RouteTablesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.RouteTablesClientCreateOrUpdateResponse], error)
	Get(ctx context.Context, resourceGroupName string, routeTableName string, options *armnetwork.RouteTablesClientGetOptions) (armnetwork.RouteTablesClientGetResponse, error)
	BeginDelete(ctx context.Context, resourceGroupName string, routeTableName string, options *armnetwork.RouteTablesClientBeginDeleteOptions) (*runtime.Poller[armnetwork.RouteTablesClientDeleteResponse], error)
	NewListPager(resourceGroupName string, options *armnetwork.RouteTablesClientListOptions) *runtime.Pager[armnetwork.RouteTablesClientListResponse]
	NewListAllPager(options *armnetwork.RouteTablesClientListAllOptions) *runtime.Pager[armnetwork.RouteTablesClientListAllResponse]
}

func init() {
	registry.Register(ResourceTypeRouteTable, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &RouteTable{
			api:      c.RouteTablesClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// RouteTable is the provisioner for Azure Route Tables.
type RouteTable struct {
	api      routeTablesAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

func routeTableIDParts(resourceID string) (rgName, routeTableName string, err error) {
	rgName, names, err := armIDParts(resourceID, "routetables")
	if err != nil {
		return "", "", err
	}
	return rgName, names["routetables"], nil
}

func routesFromProperties(props map[string]any) []*armnetwork.Route {
	raw, ok := props["routes"].([]any)
	if !ok {
		return nil
	}
	routes := make([]*armnetwork.Route, 0, len(raw))
	for _, item := range raw {
		entry, ok := item.(map[string]any)
		if !ok {
			continue
		}
		route := &armnetwork.Route{
			Properties: &armnetwork.RoutePropertiesFormat{},
		}
		if name, ok := entry["name"].(string); ok {
			route.Name = stringPtr(name)
		}
		if prefix, ok := entry["addressPrefix"].(string); ok {
			route.Properties.AddressPrefix = stringPtr(prefix)
		}
		if hopType, ok := entry["nextHopType"].(string); ok {
			nh := armnetwork.RouteNextHopType(hopType)
			route.Properties.NextHopType = &nh
		}
		if hopIP, ok := entry["nextHopIpAddress"].(string); ok {
			route.Properties.NextHopIPAddress = stringPtr(hopIP)
		}
		routes = append(routes, route)
	}
	return routes
}

// serializeRouteTableProperties converts an Azure RouteTable to Formae property format.
func serializeRouteTableProperties(result armnetwork.RouteTable, rgName, routeTableName string) (json.RawMessage, error) {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	if result.Name != nil {
		props["name"] = *result.Name
	} else {
		props["name"] = routeTableName
	}

	if result.Location != nil {
		props["location"] = *result.Location
	}

	if result.Properties != nil {
		if result.Properties.DisableBgpRoutePropagation != nil {
			props["disableBgpRoutePropagation"] = *result.Properties.DisableBgpRoutePropagation
		}
		if len(result.Properties.Routes) > 0 {
			routes := make([]map[string]any, 0, len(result.Properties.Routes))
			for _, route := range result.Properties.Routes {
				if route == nil {
					continue
				}
				entry := make(map[string]any)
				if route.Name != nil {
					entry["name"] = *route.Name
				}
				if route.Properties != nil {
					if route.Properties.AddressPrefix != nil {
						entry["addressPrefix"] = *route.Properties.AddressPrefix
					}
					if route.Properties.NextHopType != nil {
						entry["nextHopType"] = string(*route.Properties.NextHopType)
					}
					if route.Properties.NextHopIPAddress != nil {
						entry["nextHopIpAddress"] = *route.Properties.NextHopIPAddress
					}
				}
				routes = append(routes, entry)
			}
			props["routes"] = routes
		}
	}

	if tags := azureTagsToFormaeTags(result.Tags); tags != nil {
		props["Tags"] = tags
	}

	// Include id for resolvable references
	if result.ID != nil {
		props["id"] = *result.ID
	}

	return json.Marshal(props)
}

func (rt *RouteTable) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
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

	routeTableName, ok := props["name"].(string)
	if !ok || routeTableName == "" {
		routeTableName = request.Label
	}

	params := armnetwork.RouteTable{
		Location:   stringPtr(location),
		Properties: &armnetwork.RouteTablePropertiesFormat{},
	}
	if disable, ok := props["disableBgpRoutePropagation"].(bool); ok {
		params.Properties.DisableBgpRoutePropagation = &disable
	}
	if routes := routesFromProperties(props); routes != nil {
		params.Properties.Routes = routes
	}
	if azureTags := formaeTagsToAzureTags(request.Properties); azureTags != nil {
		params.Tags = azureTags
	}

	poller, err := rt.api.BeginCreateOrUpdate(ctx, rgName, routeTableName, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/routeTables/%s",
		rt.config.SubscriptionId, rgName, routeTableName)

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

		propsJSON, err := serializeRouteTableProperties(result.RouteTable, rgName, routeTableName)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize Route Table properties: %w", err)
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

func (rt *RouteTable) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, routeTableName, err := routeTableIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := rt.api.Get(ctx, rgName, routeTableName, nil)
	if err != nil {
		return &resource.ReadResult{
			ErrorCode: operationErrorCode(err),
		}, nil
	}

	propsJSON, err := serializeRouteTableProperties(result.RouteTable, rgName, routeTableName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize Route Table properties: %w", err)
	}

	return &resource.ReadResult{
		ResourceType: ResourceTypeRouteTable,
		Properties:   string(propsJSON),
	}, nil
}

func (rt *RouteTable) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, routeTableName, err := routeTableIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props map[string]any
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	location, ok := props["location"].(string)
	if !ok || location == "" {
		return nil, fmt.Errorf("location is required")
	}

	params := armnetwork.RouteTable{
		Location:   stringPtr(location),
		Properties: &armnetwork.RouteTablePropertiesFormat{},
	}
	if disable, ok := props["disableBgpRoutePropagation"].(bool); ok {
		params.Properties.DisableBgpRoutePropagation = &disable
	}
	if routes := routesFromProperties(props); routes != nil {
		params.Properties.Routes = routes
	}
	if azureTags := formaeTagsToAzureTags(request.DesiredProperties); azureTags != nil {
		params.Tags = azureTags
	}

	// CreateOrUpdate is idempotent and serves as the update path.
	poller, err := rt.api.BeginCreateOrUpdate(ctx, rgName, routeTableName, params, nil)
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

		propsJSON, err := serializeRouteTableProperties(result.RouteTable, rgName, routeTableName)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize Route Table properties: %w", err)
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

func (rt *RouteTable) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, routeTableName, err := routeTableIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, err := rt.api.BeginDelete(ctx, rgName, routeTableName, nil)
	if err != nil {
		// If the resource is already gone (NotFound), treat as success
		if operationErrorCode(err) == resource.OperationErrorCodeNotFound {
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
		}, fmt.Errorf("failed to start Route Table deletion: %w", err)
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

func (rt *RouteTable) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
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
		return rt.statusCreateOrUpdate(ctx, request, &reqID)
	case lroOpDelete:
		return rt.statusDelete(ctx, request, &reqID)
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

func (rt *RouteTable) statusCreateOrUpdate(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	operation := resource.OperationCreate
	if reqID.OperationType == lroOpUpdate {
		operation = resource.OperationUpdate
	}

	return statusLRO(ctx, request, reqID, operation,
		func(token string) (*runtime.Poller[armnetwork.RouteTablesClientCreateOrUpdateResponse], error) {
			return resumePoller[armnetwork.RouteTablesClientCreateOrUpdateResponse](rt.pipeline, token)
		},
		func(_ context.Context, result armnetwork.RouteTablesClientCreateOrUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
			rgName, routeTableName, err := routeTableIDParts(*result.ID)
			if err != nil {
				return "", nil, err
			}
			propsJSON, err := serializeRouteTableProperties(result.RouteTable, rgName, routeTableName)
			if err != nil {
				return "", nil, fmt.Errorf("failed to serialize Route Table properties: %w", err)
			}
			return *result.ID, propsJSON, nil
		})
}

func (rt *RouteTable) statusDelete(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	return statusDeleteLRO(ctx, request, reqID,
		func(token string) (*runtime.Poller[armnetwork.RouteTablesClientDeleteResponse], error) {
			return resumePoller[armnetwork.RouteTablesClientDeleteResponse](rt.pipeline, token)
		}, nil)
}

func (rt *RouteTable) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]

	var nativeIDs []string

	if rgName != "" {
		pager := rt.api.NewListPager(rgName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list Route Tables: %w", err)
			}
			for _, routeTable := range page.Value {
				if routeTable.ID != nil {
					nativeIDs = append(nativeIDs, *routeTable.ID)
				}
			}
		}
	} else {
		pager := rt.api.NewListAllPager(nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list Route Tables: %w", err)
			}
			for _, routeTable := range page.Value {
				if routeTable.ID != nil {
					nativeIDs = append(nativeIDs, *routeTable.ID)
				}
			}
		}
	}

	return &resource.ListResult{
		NativeIDs: nativeIDs,
	}, nil
}
