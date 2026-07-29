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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v4"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeNetworkWatcher = "AZURE::Network::NetworkWatcher"

// networkWatchersAPI is the subset of *armnetwork.WatchersClient used here.
// Note the asymmetry: CreateOrUpdate and UpdateTags are plain synchronous calls,
// only Delete is an LRO.
type networkWatchersAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName, networkWatcherName string, parameters armnetwork.Watcher, options *armnetwork.WatchersClientCreateOrUpdateOptions) (armnetwork.WatchersClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName, networkWatcherName string, options *armnetwork.WatchersClientGetOptions) (armnetwork.WatchersClientGetResponse, error)
	UpdateTags(ctx context.Context, resourceGroupName, networkWatcherName string, parameters armnetwork.TagsObject, options *armnetwork.WatchersClientUpdateTagsOptions) (armnetwork.WatchersClientUpdateTagsResponse, error)
	BeginDelete(ctx context.Context, resourceGroupName, networkWatcherName string, options *armnetwork.WatchersClientBeginDeleteOptions) (*runtime.Poller[armnetwork.WatchersClientDeleteResponse], error)
	NewListPager(resourceGroupName string, options *armnetwork.WatchersClientListOptions) *runtime.Pager[armnetwork.WatchersClientListResponse]
	NewListAllPager(options *armnetwork.WatchersClientListAllOptions) *runtime.Pager[armnetwork.WatchersClientListAllResponse]
}

func init() {
	registry.Register(ResourceTypeNetworkWatcher, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &NetworkWatcher{api: c.WatchersClient, config: cfg, pipeline: c.Pipeline()}
	})
}

// NetworkWatcher is the provisioner for Azure Network Watchers
// (`Microsoft.Network/networkWatchers/<name>`) — the regional service instance that
// flow logs, connection monitors and packet capture hang off.
//
// Two things make it unusual:
//   - **One per region per subscription.** Declaring a watcher in a region that
//     already has one fails; there is nothing to work around in the plugin, the
//     forma has to reference the existing watcher instead.
//   - **Azure auto-creates `NetworkWatcher_<region>` in the `NetworkWatcherRG`
//     resource group** the first time a VNet appears in a region. Those are real,
//     deletable resources, so `List` surfaces them and discovery can adopt one —
//     unlike, say, Event Hubs' `$Default` consumer group, they need no filter.
//
// The body is just `{location, tags}`; every property ARM reports back is read-only.
type NetworkWatcher struct {
	api      networkWatchersAPI
	config   *config.Config
	pipeline runtime.Pipeline
}

func networkWatcherIDParts(resourceID string) (rgName, name string, err error) {
	rgName, names, err := armExactIDParts(resourceID, "networkwatchers")
	if err != nil {
		return "", "", err
	}
	return rgName, names[0], nil
}

func serializeNetworkWatcherProperties(result armnetwork.Watcher, rgName, name string) (json.RawMessage, error) {
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

	// properties.provisioningState and etag are read-only with no schema field.
	if tags := azureTagsToFormaeTags(result.Tags); tags != nil {
		props["Tags"] = tags
	}

	return json.Marshal(props)
}

func (w *NetworkWatcher) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
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
	location, _ := props["location"].(string)
	if location == "" {
		return nil, fmt.Errorf("location is required")
	}

	// CreateOrUpdate is a clean upsert, which is what makes adopting an
	// already-existing (auto-created) watcher work.
	params := armnetwork.Watcher{
		Location:   to.Ptr(location),
		Properties: &armnetwork.WatcherPropertiesFormat{},
	}
	if azureTags := formaeTagsToAzureTags(request.Properties); azureTags != nil {
		params.Tags = azureTags
	}

	result, err := w.api.CreateOrUpdate(ctx, rgName, name, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	propsJSON, err := serializeNetworkWatcherProperties(result.Watcher, rgName, name)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize NetworkWatcher properties: %w", err)
	}

	nativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/networkWatchers/%s",
		w.config.SubscriptionId, rgName, name)
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

func (w *NetworkWatcher) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, name, err := networkWatcherIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := w.api.Get(ctx, rgName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := serializeNetworkWatcherProperties(result.Watcher, rgName, name)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize NetworkWatcher properties: %w", err)
	}

	return &resource.ReadResult{
		ResourceType: ResourceTypeNetworkWatcher,
		Properties:   string(propsJSON),
	}, nil
}

func (w *NetworkWatcher) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, name, err := networkWatcherIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	// Location is the only other field and it is immutable, so tags are all an
	// update can carry.
	tags := armnetwork.TagsObject{}
	if azureTags := formaeTagsToAzureTags(request.DesiredProperties); azureTags != nil {
		tags.Tags = azureTags
	}

	result, err := w.api.UpdateTags(ctx, rgName, name, tags, nil)
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

	propsJSON, err := serializeNetworkWatcherProperties(result.Watcher, rgName, name)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize NetworkWatcher properties: %w", err)
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

func (w *NetworkWatcher) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, name, err := networkWatcherIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, err := w.api.BeginDelete(ctx, rgName, name, nil)
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
		}, fmt.Errorf("failed to delete NetworkWatcher: %w", err)
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

// Status only ever polls a delete: Create and Update are synchronous, so they
// never hand back a RequestID.
func (w *NetworkWatcher) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
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

	if reqID.OperationType != lroOpDelete {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
			},
		}, fmt.Errorf("unknown LRO operation type: %s", reqID.OperationType)
	}

	return statusDeleteLRO(ctx, request, &reqID,
		func(token string) (*runtime.Poller[armnetwork.WatchersClientDeleteResponse], error) {
			return resumePoller[armnetwork.WatchersClientDeleteResponse](w.pipeline, token)
		}, nil)
}

func (w *NetworkWatcher) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]

	var nativeIDs []string
	if rgName != "" {
		pager := w.api.NewListPager(rgName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list network watchers in resource group %s: %w", rgName, err)
			}
			for _, watcher := range page.Value {
				if watcher.ID != nil {
					nativeIDs = append(nativeIDs, *watcher.ID)
				}
			}
		}
		return &resource.ListResult{NativeIDs: nativeIDs}, nil
	}

	pager := w.api.NewListAllPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list network watchers: %w", err)
		}
		for _, watcher := range page.Value {
			if watcher.ID != nil {
				nativeIDs = append(nativeIDs, *watcher.ID)
			}
		}
	}

	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
