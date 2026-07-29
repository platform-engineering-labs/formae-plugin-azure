// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v4"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeIPGroup = "AZURE::Network::IpGroup"

// ipGroupsAPI is the subset of *armnetwork.IPGroupsClient used here.
// Create/update/delete are LROs.
type ipGroupsAPI interface {
	BeginCreateOrUpdate(ctx context.Context, resourceGroupName string, ipGroupsName string, parameters armnetwork.IPGroup, options *armnetwork.IPGroupsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.IPGroupsClientCreateOrUpdateResponse], error)
	Get(ctx context.Context, resourceGroupName string, ipGroupsName string, options *armnetwork.IPGroupsClientGetOptions) (armnetwork.IPGroupsClientGetResponse, error)
	BeginDelete(ctx context.Context, resourceGroupName string, ipGroupsName string, options *armnetwork.IPGroupsClientBeginDeleteOptions) (*runtime.Poller[armnetwork.IPGroupsClientDeleteResponse], error)
	NewListByResourceGroupPager(resourceGroupName string, options *armnetwork.IPGroupsClientListByResourceGroupOptions) *runtime.Pager[armnetwork.IPGroupsClientListByResourceGroupResponse]
	NewListPager(options *armnetwork.IPGroupsClientListOptions) *runtime.Pager[armnetwork.IPGroupsClientListResponse]
}

func init() {
	registry.Register(ResourceTypeIPGroup, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &IPGroup{
			api:      c.IPGroupsClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// IPGroup is the provisioner for Azure IP groups
// (`Microsoft.Network/ipGroups/<name>`) — reusable lists of IP addresses and
// CIDRs that Azure Firewall rules reference instead of inline prefixes.
type IPGroup struct {
	api      ipGroupsAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

func serializeIPGroupProperties(result armnetwork.IPGroup, rgName, name string) (json.RawMessage, error) {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	if result.Name != nil {
		props["name"] = *result.Name
	} else {
		props["name"] = name
	}
	if result.Location != nil {
		props["location"] = *result.Location
	}
	if result.ID != nil {
		props["id"] = *result.ID
	}

	if result.Properties != nil && len(result.Properties.IPAddresses) > 0 {
		addresses := make([]string, 0, len(result.Properties.IPAddresses))
		for _, a := range result.Properties.IPAddresses {
			if a != nil {
				addresses = append(addresses, *a)
			}
		}
		// ARM does not preserve the submitted order of ipAddresses, so sort both
		// on the way in and on the way out — otherwise every Read reports drift
		// against an identical set.
		sort.Strings(addresses)
		props["ipAddresses"] = addresses
	}

	if tags := azureTagsToFormaeTags(result.Tags); tags != nil {
		props["Tags"] = tags
	}

	return json.Marshal(props)
}

func ipGroupParamsFromProperties(props map[string]any, rawProps json.RawMessage) (armnetwork.IPGroup, error) {
	location, _ := props["location"].(string)
	if location == "" {
		return armnetwork.IPGroup{}, fmt.Errorf("location is required")
	}

	group := armnetwork.IPGroup{
		Location:   stringPtr(location),
		Properties: &armnetwork.IPGroupPropertiesFormat{},
	}

	if rawAddrs, ok := props["ipAddresses"].([]any); ok && len(rawAddrs) > 0 {
		addresses := make([]string, 0, len(rawAddrs))
		for _, a := range rawAddrs {
			if s, ok := a.(string); ok && s != "" {
				addresses = append(addresses, s)
			}
		}
		sort.Strings(addresses)
		ptrs := make([]*string, 0, len(addresses))
		for i := range addresses {
			ptrs = append(ptrs, &addresses[i])
		}
		group.Properties.IPAddresses = ptrs
	}

	if azureTags := formaeTagsToAzureTags(rawProps); azureTags != nil {
		group.Tags = azureTags
	}

	return group, nil
}

func ipGroupIDParts(resourceID string) (rgName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "ipgroups")
	if err != nil {
		return "", "", err
	}
	return rgName, names["ipgroups"], nil
}

func (g *IPGroup) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props map[string]any
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	rgName, _ := props["resourceGroupName"].(string)
	if rgName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	name, _ := props["name"].(string)
	if name == "" {
		name = request.Label
	}
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}

	params, err := ipGroupParamsFromProperties(props, request.Properties)
	if err != nil {
		return nil, err
	}

	poller, err := g.api.BeginCreateOrUpdate(ctx, rgName, name, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	expectedID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/ipGroups/%s",
		g.config.SubscriptionId, rgName, name)

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
		propsJSON, err := serializeIPGroupProperties(result.IPGroup, rgName, name)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize IpGroup properties: %w", err)
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

	token, err := poller.ResumeToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get resume token: %w", err)
	}
	reqID, err := encodeLROStart(lroOpCreate, token, expectedID)
	if err != nil {
		return nil, err
	}

	return &resource.CreateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationCreate,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       reqID,
			NativeID:        expectedID,
		},
	}, nil
}

func (g *IPGroup) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, name, err := ipGroupIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := g.api.Get(ctx, rgName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := serializeIPGroupProperties(result.IPGroup, rgName, name)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize IpGroup properties: %w", err)
	}

	return &resource.ReadResult{
		ResourceType: ResourceTypeIPGroup,
		Properties:   string(propsJSON),
	}, nil
}

func (g *IPGroup) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, name, err := ipGroupIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props map[string]any
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse desired properties: %w", err)
	}

	// ARM's IPGroups PATCH (UpdateGroups) only accepts tags, so member changes go
	// through the full-body PUT.
	params, err := ipGroupParamsFromProperties(props, request.DesiredProperties)
	if err != nil {
		return nil, err
	}

	poller, err := g.api.BeginCreateOrUpdate(ctx, rgName, name, params, nil)
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
		propsJSON, err := serializeIPGroupProperties(result.IPGroup, rgName, name)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize IpGroup properties: %w", err)
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

	token, err := poller.ResumeToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get resume token: %w", err)
	}
	reqID, err := encodeLROStart(lroOpUpdate, token, request.NativeID)
	if err != nil {
		return nil, err
	}

	return &resource.UpdateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationUpdate,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       reqID,
			NativeID:        request.NativeID,
		},
	}, nil
}

func (g *IPGroup) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, name, err := ipGroupIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, err := g.api.BeginDelete(ctx, rgName, name, nil)
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
		}, fmt.Errorf("failed to delete IpGroup: %w", err)
	}

	if poller.Done() {
		return &resource.DeleteResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationDelete,
				OperationStatus: resource.OperationStatusSuccess,
				NativeID:        request.NativeID,
			},
		}, nil
	}

	token, err := poller.ResumeToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get resume token: %w", err)
	}
	reqID, err := encodeLROStart(lroOpDelete, token, request.NativeID)
	if err != nil {
		return nil, err
	}

	return &resource.DeleteResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationDelete,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       reqID,
			NativeID:        request.NativeID,
		},
	}, nil
}

func (g *IPGroup) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
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
		}, fmt.Errorf("unknown LRO operation type: %s", reqID.OperationType)
	}
}

func (g *IPGroup) statusCreateOrUpdate(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	operation := resource.OperationCreate
	if reqID.OperationType == lroOpUpdate {
		operation = resource.OperationUpdate
	}

	return statusLRO(ctx, request, reqID, operation,
		func(token string) (*runtime.Poller[armnetwork.IPGroupsClientCreateOrUpdateResponse], error) {
			return resumePoller[armnetwork.IPGroupsClientCreateOrUpdateResponse](g.pipeline, token)
		},
		func(_ context.Context, result armnetwork.IPGroupsClientCreateOrUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
			rgName, name, err := ipGroupIDParts(*result.ID)
			if err != nil {
				return "", nil, err
			}
			propsJSON, err := serializeIPGroupProperties(result.IPGroup, rgName, name)
			if err != nil {
				return "", nil, fmt.Errorf("failed to serialize IpGroup properties: %w", err)
			}
			return *result.ID, propsJSON, nil
		})
}

func (g *IPGroup) statusDelete(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	return statusDeleteLRO(ctx, request, reqID,
		func(token string) (*runtime.Poller[armnetwork.IPGroupsClientDeleteResponse], error) {
			return resumePoller[armnetwork.IPGroupsClientDeleteResponse](g.pipeline, token)
		}, nil)
}

func (g *IPGroup) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]

	var nativeIDs []string
	if rgName != "" {
		pager := g.api.NewListByResourceGroupPager(rgName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list IP groups in resource group %s: %w", rgName, err)
			}
			for _, group := range page.Value {
				if group.ID != nil {
					nativeIDs = append(nativeIDs, *group.ID)
				}
			}
		}
		return &resource.ListResult{NativeIDs: nativeIDs}, nil
	}

	pager := g.api.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list IP groups: %w", err)
		}
		for _, group := range page.Value {
			if group.ID != nil {
				nativeIDs = append(nativeIDs, *group.ID)
			}
		}
	}

	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
