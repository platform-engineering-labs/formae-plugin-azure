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

const ResourceTypeFlowLog = "AZURE::Network::FlowLog"

// flowLogsAPI is the subset of *armnetwork.FlowLogsClient used here, plus the
// watcher enumeration discovery needs: flow logs can only be listed per-watcher.
type flowLogsAPI interface {
	BeginCreateOrUpdate(ctx context.Context, resourceGroupName, networkWatcherName, flowLogName string, parameters armnetwork.FlowLog, options *armnetwork.FlowLogsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.FlowLogsClientCreateOrUpdateResponse], error)
	Get(ctx context.Context, resourceGroupName, networkWatcherName, flowLogName string, options *armnetwork.FlowLogsClientGetOptions) (armnetwork.FlowLogsClientGetResponse, error)
	BeginDelete(ctx context.Context, resourceGroupName, networkWatcherName, flowLogName string, options *armnetwork.FlowLogsClientBeginDeleteOptions) (*runtime.Poller[armnetwork.FlowLogsClientDeleteResponse], error)
	NewListPager(resourceGroupName, networkWatcherName string, options *armnetwork.FlowLogsClientListOptions) *runtime.Pager[armnetwork.FlowLogsClientListResponse]
	NewListAllWatchersPager(options *armnetwork.WatchersClientListAllOptions) *runtime.Pager[armnetwork.WatchersClientListAllResponse]
}

// flowLogsWrapper composes the FlowLogs SDK client with subscription-wide watcher
// discovery.
type flowLogsWrapper struct {
	*armnetwork.FlowLogsClient
	watchersClient *armnetwork.WatchersClient
}

func (w *flowLogsWrapper) NewListAllWatchersPager(options *armnetwork.WatchersClientListAllOptions) *runtime.Pager[armnetwork.WatchersClientListAllResponse] {
	return w.watchersClient.NewListAllPager(options)
}

func init() {
	registry.Register(ResourceTypeFlowLog, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &FlowLog{
			api: &flowLogsWrapper{
				FlowLogsClient: c.FlowLogsClient,
				watchersClient: c.WatchersClient,
			},
			config:   cfg,
			pipeline: c.Pipeline(),
		}
	})
}

// FlowLog is the provisioner for Network Watcher flow logs
// (`Microsoft.Network/networkWatchers/<watcher>/flowLogs/<name>`) — the traffic
// capture that writes to a storage account.
//
// It sits under a watcher but points at the captured resource somewhere else:
// `targetResourceId` and the storage account both have to be in the watcher's
// region.
//
// `targetResourceId` should name a virtual network, subnet or NIC. Azure blocked
// creation of new *NSG* flow logs on 2025-06-30 (`NsgFlowLogCreationBlocked`)
// ahead of retiring them on 2027-09-30; existing NSG flow logs still read and
// update, so the plugin passes whatever target it is given rather than validating
// the type itself.
type FlowLog struct {
	api      flowLogsAPI
	config   *config.Config
	pipeline runtime.Pipeline
}

func flowLogIDParts(resourceID string) (rgName, watcherName, name string, err error) {
	rgName, names, err := armExactIDParts(resourceID, "networkwatchers", "flowlogs")
	if err != nil {
		return "", "", "", err
	}
	return rgName, names[0], names[1], nil
}

func serializeFlowLogProperties(result armnetwork.FlowLog, rgName, watcherName, name string) (json.RawMessage, error) {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	props["networkWatcherName"] = watcherName
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

	if result.Properties != nil {
		p := result.Properties
		if p.StorageID != nil {
			props["storageId"] = *p.StorageID
		}
		if p.TargetResourceID != nil {
			props["targetResourceId"] = *p.TargetResourceID
		}
		if p.Enabled != nil {
			props["enabled"] = *p.Enabled
		}
		// ARM always echoes format and retentionPolicy with its own defaults. They
		// are nested, and provider defaults are only honoured on top-level resource
		// fields, so a forma that omits them would show permanent drift — the PKL
		// docs tell callers to pin both.
		if p.Format != nil {
			format := map[string]any{}
			if p.Format.Type != nil {
				format["type"] = string(*p.Format.Type)
			}
			if p.Format.Version != nil {
				format["version"] = int(*p.Format.Version)
			}
			props["format"] = format
		}
		if p.RetentionPolicy != nil {
			retention := map[string]any{}
			if p.RetentionPolicy.Days != nil {
				retention["days"] = int(*p.RetentionPolicy.Days)
			}
			if p.RetentionPolicy.Enabled != nil {
				retention["enabled"] = *p.RetentionPolicy.Enabled
			}
			props["retentionPolicy"] = retention
		}
		// targetResourceGuid and provisioningState are read-only with no schema field.
	}

	if tags := azureTagsToFormaeTags(result.Tags); tags != nil {
		props["Tags"] = tags
	}

	return json.Marshal(props)
}

func flowLogParamsFromProperties(props map[string]any, rawProps json.RawMessage) (armnetwork.FlowLog, error) {
	location, _ := props["location"].(string)
	if location == "" {
		return armnetwork.FlowLog{}, fmt.Errorf("location is required")
	}
	storageID, _ := props["storageId"].(string)
	if storageID == "" {
		return armnetwork.FlowLog{}, fmt.Errorf("storageId is required")
	}
	targetResourceID, _ := props["targetResourceId"].(string)
	if targetResourceID == "" {
		return armnetwork.FlowLog{}, fmt.Errorf("targetResourceId is required")
	}

	fl := armnetwork.FlowLog{
		Location: to.Ptr(location),
		Properties: &armnetwork.FlowLogPropertiesFormat{
			StorageID:        to.Ptr(storageID),
			TargetResourceID: to.Ptr(targetResourceID),
		},
	}

	if v, ok := props["enabled"].(bool); ok {
		fl.Properties.Enabled = to.Ptr(v)
	}
	if formatMap, ok := props["format"].(map[string]any); ok {
		format := &armnetwork.FlowLogFormatParameters{}
		if v, ok := formatMap["type"].(string); ok && v != "" {
			format.Type = to.Ptr(armnetwork.FlowLogFormatType(v))
		}
		if v, ok := formatMap["version"].(float64); ok {
			format.Version = to.Ptr(int32(v))
		}
		fl.Properties.Format = format
	}
	if retentionMap, ok := props["retentionPolicy"].(map[string]any); ok {
		retention := &armnetwork.RetentionPolicyParameters{}
		if v, ok := retentionMap["days"].(float64); ok {
			retention.Days = to.Ptr(int32(v))
		}
		if v, ok := retentionMap["enabled"].(bool); ok {
			retention.Enabled = to.Ptr(v)
		}
		fl.Properties.RetentionPolicy = retention
	}

	if azureTags := formaeTagsToAzureTags(rawProps); azureTags != nil {
		fl.Tags = azureTags
	}

	return fl, nil
}

func (f *FlowLog) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props map[string]any
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	rgName, _ := props["resourceGroupName"].(string)
	if rgName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	watcherName, _ := props["networkWatcherName"].(string)
	if watcherName == "" {
		return nil, fmt.Errorf("networkWatcherName is required")
	}
	name, _ := props["name"].(string)
	if name == "" {
		name = request.Label
	}
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}

	params, err := flowLogParamsFromProperties(props, request.Properties)
	if err != nil {
		return nil, err
	}

	poller, err := f.api.BeginCreateOrUpdate(ctx, rgName, watcherName, name, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	expectedID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/networkWatchers/%s/flowLogs/%s",
		f.config.SubscriptionId, rgName, watcherName, name)

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
		propsJSON, err := serializeFlowLogProperties(result.FlowLog, rgName, watcherName, name)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize FlowLog properties: %w", err)
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

func (f *FlowLog) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, watcherName, name, err := flowLogIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := f.api.Get(ctx, rgName, watcherName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := serializeFlowLogProperties(result.FlowLog, rgName, watcherName, name)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize FlowLog properties: %w", err)
	}

	return &resource.ReadResult{
		ResourceType: ResourceTypeFlowLog,
		Properties:   string(propsJSON),
	}, nil
}

func (f *FlowLog) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, watcherName, name, err := flowLogIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props map[string]any
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse desired properties: %w", err)
	}

	// The PATCH verb (UpdateTags) only carries tags, so retention and enabled
	// changes go through the full-body PUT — which means echoing the immutable
	// storage and target references back.
	params, err := flowLogParamsFromProperties(props, request.DesiredProperties)
	if err != nil {
		return nil, err
	}

	poller, err := f.api.BeginCreateOrUpdate(ctx, rgName, watcherName, name, params, nil)
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
		propsJSON, err := serializeFlowLogProperties(result.FlowLog, rgName, watcherName, name)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize FlowLog properties: %w", err)
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

func (f *FlowLog) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, watcherName, name, err := flowLogIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, err := f.api.BeginDelete(ctx, rgName, watcherName, name, nil)
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
		}, fmt.Errorf("failed to delete FlowLog: %w", err)
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

func (f *FlowLog) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
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
		return f.statusCreateOrUpdate(ctx, request, &reqID)
	case lroOpDelete:
		return statusDeleteLRO(ctx, request, &reqID,
			func(token string) (*runtime.Poller[armnetwork.FlowLogsClientDeleteResponse], error) {
				return resumePoller[armnetwork.FlowLogsClientDeleteResponse](f.pipeline, token)
			}, nil)
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

func (f *FlowLog) statusCreateOrUpdate(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	operation := resource.OperationCreate
	if reqID.OperationType == lroOpUpdate {
		operation = resource.OperationUpdate
	}

	return statusLRO(ctx, request, reqID, operation,
		func(token string) (*runtime.Poller[armnetwork.FlowLogsClientCreateOrUpdateResponse], error) {
			return resumePoller[armnetwork.FlowLogsClientCreateOrUpdateResponse](f.pipeline, token)
		},
		func(_ context.Context, result armnetwork.FlowLogsClientCreateOrUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
			rgName, watcherName, name, err := flowLogIDParts(*result.ID)
			if err != nil {
				return "", nil, err
			}
			propsJSON, err := serializeFlowLogProperties(result.FlowLog, rgName, watcherName, name)
			if err != nil {
				return "", nil, fmt.Errorf("failed to serialize FlowLog properties: %w", err)
			}
			return *result.ID, propsJSON, nil
		})
}

func (f *FlowLog) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	watcherName := request.AdditionalProperties["networkWatcherName"]

	if rgName != "" && watcherName != "" {
		ids, err := f.listByWatcher(ctx, rgName, watcherName)
		if err != nil {
			return nil, err
		}
		return &resource.ListResult{NativeIDs: ids}, nil
	}

	// Discovery path: flow logs can only be listed per-watcher.
	var nativeIDs []string
	pager := f.api.NewListAllWatchersPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list network watchers for flow log discovery: %w", err)
		}
		for _, watcher := range page.Value {
			if watcher.ID == nil {
				continue
			}
			watcherRG, name, err := networkWatcherIDParts(*watcher.ID)
			if err != nil {
				continue
			}
			ids, err := f.listByWatcher(ctx, watcherRG, name)
			if err != nil {
				return nil, err
			}
			nativeIDs = append(nativeIDs, ids...)
		}
	}

	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}

func (f *FlowLog) listByWatcher(ctx context.Context, rgName, watcherName string) ([]string, error) {
	pager := f.api.NewListPager(rgName, watcherName, nil)

	var nativeIDs []string
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list flow logs in watcher %s/%s: %w", rgName, watcherName, err)
		}
		for _, fl := range page.Value {
			if fl.ID != nil {
				nativeIDs = append(nativeIDs, *fl.ID)
			}
		}
	}

	return nativeIDs, nil
}
