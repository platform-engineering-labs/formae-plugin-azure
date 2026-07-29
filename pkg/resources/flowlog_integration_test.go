// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build integration

package resources

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v4"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const (
	testFlowLogNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/networkWatchers/nw-1/flowLogs/fl-1"
	// A virtual network target: new NSG flow logs are blocked by ARM since
	// 2025-06-30, so VNet/subnet/NIC is the only target worth exercising.
	testFlowLogVNetID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/virtualNetworks/vnet-1"
	testFlowLogSAID   = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Storage/storageAccounts/sa1"
)

func TestFlowLog_CRUD(t *testing.T) {
	model := armnetwork.FlowLog{
		ID:       to.Ptr(testFlowLogNativeID),
		Name:     to.Ptr("fl-1"),
		Location: to.Ptr("japaneast"),
		Etag:     to.Ptr("W/\"etag-1\""),
		Properties: &armnetwork.FlowLogPropertiesFormat{
			StorageID:        to.Ptr(testFlowLogSAID),
			TargetResourceID: to.Ptr(testFlowLogVNetID),
			Enabled:          to.Ptr(true),
			Format: &armnetwork.FlowLogFormatParameters{
				Type:    to.Ptr(armnetwork.FlowLogFormatTypeJSON),
				Version: to.Ptr(int32(2)),
			},
			RetentionPolicy: &armnetwork.RetentionPolicyParameters{
				Days:    to.Ptr(int32(0)),
				Enabled: to.Ptr(false),
			},
			// Read-only ARM output with no schema field.
			ProvisioningState:  to.Ptr(armnetwork.ProvisioningStateSucceeded),
			TargetResourceGUID: to.Ptr("00000000-0000-0000-0000-000000000000"),
		},
		Tags: map[string]*string{"Environment": to.Ptr("test")},
	}
	fake := &fakeFlowLogsAPI{
		beginCreateOrUpdateFn: func(_ context.Context, _, _, _ string, _ armnetwork.FlowLog, _ *armnetwork.FlowLogsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.FlowLogsClientCreateOrUpdateResponse], error) {
			return newDonePoller(armnetwork.FlowLogsClientCreateOrUpdateResponse{FlowLog: model}), nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ *armnetwork.FlowLogsClientGetOptions) (armnetwork.FlowLogsClientGetResponse, error) {
			return armnetwork.FlowLogsClientGetResponse{FlowLog: model}, nil
		},
		beginDeleteFn: func(_ context.Context, _, _, _ string, _ *armnetwork.FlowLogsClientBeginDeleteOptions) (*runtime.Poller[armnetwork.FlowLogsClientDeleteResponse], error) {
			return newInProgressPoller[armnetwork.FlowLogsClientDeleteResponse](), nil
		},
		newListPagerFn: func(_, _ string, _ *armnetwork.FlowLogsClientListOptions) *runtime.Pager[armnetwork.FlowLogsClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armnetwork.FlowLogsClientListResponse]{
				More: func(_ armnetwork.FlowLogsClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armnetwork.FlowLogsClientListResponse) (armnetwork.FlowLogsClientListResponse, error) {
					return armnetwork.FlowLogsClientListResponse{
						FlowLogListResult: armnetwork.FlowLogListResult{
							Value: []*armnetwork.FlowLog{{ID: to.Ptr(testFlowLogNativeID)}},
						},
					}, nil
				},
			})
		},
		newListAllWatchersPagerFn: func(_ *armnetwork.WatchersClientListAllOptions) *runtime.Pager[armnetwork.WatchersClientListAllResponse] {
			return runtime.NewPager(runtime.PagingHandler[armnetwork.WatchersClientListAllResponse]{
				More: func(_ armnetwork.WatchersClientListAllResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armnetwork.WatchersClientListAllResponse) (armnetwork.WatchersClientListAllResponse, error) {
					return armnetwork.WatchersClientListAllResponse{
						WatcherListResult: armnetwork.WatcherListResult{
							Value: []*armnetwork.Watcher{{ID: to.Ptr(testNetworkWatcherNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestFlowLog(fake)

	mkProps := func() json.RawMessage {
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName":  "rg-1",
			"networkWatcherName": "nw-1",
			"name":               "fl-1",
			"location":           "japaneast",
			"storageId":          testFlowLogSAID,
			"targetResourceId":   testFlowLogVNetID,
			"enabled":            true,
			"format":             map[string]any{"type": "JSON", "version": 2},
			"retentionPolicy":    map[string]any{"days": 0, "enabled": false},
			"Tags":               []map[string]string{{"Key": "Environment", "Value": "test"}},
		})
		return props
	}

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testFlowLogNativeID, got.ProgressResult.NativeID)

		var serialized map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &serialized))
		require.Equal(t, "fl-1", serialized["name"])
		require.Equal(t, "nw-1", serialized["networkWatcherName"])
		require.Equal(t, testFlowLogSAID, serialized["storageId"])
		require.Equal(t, testFlowLogVNetID, serialized["targetResourceId"])
		require.Equal(t, map[string]any{"type": "JSON", "version": float64(2)}, serialized["format"])
		require.Equal(t, map[string]any{"days": float64(0), "enabled": false}, serialized["retentionPolicy"])
	})

	// etag, provisioningState and targetResourceGuid have no schema field.
	t.Run("Serialize_omits_unmodelled_readonly_fields", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testFlowLogNativeID})
		require.NoError(t, err)
		var serialized map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &serialized))
		require.NotContains(t, serialized, "etag")
		require.NotContains(t, serialized, "provisioningState")
		require.NotContains(t, serialized, "targetResourceGuid")
	})

	t.Run("Create_forwards_params_to_ARM", func(t *testing.T) {
		var seen armnetwork.FlowLog
		var seenRG, seenWatcher, seenName string
		fake.beginCreateOrUpdateFn = func(_ context.Context, rg, watcher, name string, params armnetwork.FlowLog, _ *armnetwork.FlowLogsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.FlowLogsClientCreateOrUpdateResponse], error) {
			seen, seenRG, seenWatcher, seenName = params, rg, watcher, name
			return newDonePoller(armnetwork.FlowLogsClientCreateOrUpdateResponse{FlowLog: model}), nil
		}
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, "rg-1", seenRG)
		require.Equal(t, "nw-1", seenWatcher)
		require.Equal(t, "fl-1", seenName)
		require.Equal(t, testFlowLogSAID, *seen.Properties.StorageID)
		require.Equal(t, testFlowLogVNetID, *seen.Properties.TargetResourceID)
		require.True(t, *seen.Properties.Enabled)
		require.Equal(t, armnetwork.FlowLogFormatTypeJSON, *seen.Properties.Format.Type)
		require.Equal(t, int32(2), *seen.Properties.Format.Version)
		require.Equal(t, int32(0), *seen.Properties.RetentionPolicy.Days)
		require.False(t, *seen.Properties.RetentionPolicy.Enabled)

		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _, _ string, _ armnetwork.FlowLog, _ *armnetwork.FlowLogsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.FlowLogsClientCreateOrUpdateResponse], error) {
			return newDonePoller(armnetwork.FlowLogsClientCreateOrUpdateResponse{FlowLog: model}), nil
		}
	})

	t.Run("Create_requires_storageId", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName": "rg-1", "networkWatcherName": "nw-1", "name": "fl-1",
			"location": "japaneast", "targetResourceId": testFlowLogVNetID,
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "storageId is required")
	})

	t.Run("Create_requires_targetResourceId", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName": "rg-1", "networkWatcherName": "nw-1", "name": "fl-1",
			"location": "japaneast", "storageId": testFlowLogSAID,
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "targetResourceId is required")
	})

	t.Run("Create_requires_networkWatcherName", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"resourceGroupName": "rg-1", "name": "fl-1", "location": "japaneast"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "networkWatcherName is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testFlowLogNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
		require.Equal(t, ResourceTypeFlowLog, got.ResourceType)
	})

	t.Run("Read_not_found", func(t *testing.T) {
		fake.getFn = func(_ context.Context, _, _, _ string, _ *armnetwork.FlowLogsClientGetOptions) (armnetwork.FlowLogsClientGetResponse, error) {
			return armnetwork.FlowLogsClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testFlowLogNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)

		fake.getFn = func(_ context.Context, _, _, _ string, _ *armnetwork.FlowLogsClientGetOptions) (armnetwork.FlowLogsClientGetResponse, error) {
			return armnetwork.FlowLogsClientGetResponse{FlowLog: model}, nil
		}
	})

	// The PATCH verb only carries tags, so retention changes go through the
	// full-body PUT — which has to echo the immutable references back.
	t.Run("Update_sends_full_body_put", func(t *testing.T) {
		var seen armnetwork.FlowLog
		var seenRG, seenWatcher, seenName string
		fake.beginCreateOrUpdateFn = func(_ context.Context, rg, watcher, name string, params armnetwork.FlowLog, _ *armnetwork.FlowLogsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.FlowLogsClientCreateOrUpdateResponse], error) {
			seen, seenRG, seenWatcher, seenName = params, rg, watcher, name
			return newDonePoller(armnetwork.FlowLogsClientCreateOrUpdateResponse{FlowLog: model}), nil
		}
		desired, _ := json.Marshal(map[string]any{
			// Wrong parents in the payload — the native ID must win.
			"resourceGroupName":  "wrong-rg",
			"networkWatcherName": "wrong-watcher",
			"name":               "wrong-name",
			"location":           "japaneast",
			"storageId":          testFlowLogSAID,
			"targetResourceId":   testFlowLogVNetID,
			"enabled":            true,
			"format":             map[string]any{"type": "JSON", "version": 2},
			"retentionPolicy":    map[string]any{"days": 7, "enabled": true},
			"Tags":               []map[string]string{{"Key": "Environment", "Value": "updated"}},
		})
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testFlowLogNativeID,
			DesiredProperties: desired,
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, "rg-1", seenRG)
		require.Equal(t, "nw-1", seenWatcher)
		require.Equal(t, "fl-1", seenName)
		require.Equal(t, testFlowLogSAID, *seen.Properties.StorageID)
		require.Equal(t, testFlowLogVNetID, *seen.Properties.TargetResourceID)
		require.Equal(t, int32(7), *seen.Properties.RetentionPolicy.Days)
		require.True(t, *seen.Properties.RetentionPolicy.Enabled)
		require.Equal(t, "updated", *seen.Tags["Environment"])
	})

	t.Run("Delete_in_progress_returns_lro_request_id", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testFlowLogNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusInProgress, got.ProgressResult.OperationStatus)
		reqID, err := decodeLROStatus(got.ProgressResult.RequestID)
		require.NoError(t, err)
		require.Equal(t, lroOpDelete, reqID.OperationType)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _, _ string, _ *armnetwork.FlowLogsClientBeginDeleteOptions) (*runtime.Poller[armnetwork.FlowLogsClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testFlowLogNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Status_rejects_unknown_operation", func(t *testing.T) {
		reqID, err := encodeLROStart("bogus", "token", testFlowLogNativeID)
		require.NoError(t, err)
		got, err := prov.Status(context.Background(), &resource.StatusRequest{RequestID: reqID})
		require.Error(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_watcher", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "networkWatcherName": "nw-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testFlowLogNativeID}, got.NativeIDs)
	})

	// Flow logs cannot be listed subscription-wide, so discovery walks every watcher.
	t.Run("List_all_walks_watchers", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Equal(t, []string{testFlowLogNativeID}, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _, _ string, _ armnetwork.FlowLog, _ *armnetwork.FlowLogsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.FlowLogsClientCreateOrUpdateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 403}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

func TestFlowLogIDParts(t *testing.T) {
	rg, watcher, name, err := flowLogIDParts(testFlowLogNativeID)
	require.NoError(t, err)
	require.Equal(t, "rg-1", rg)
	require.Equal(t, "nw-1", watcher)
	require.Equal(t, "fl-1", name)

	// A bare watcher ID has no flow log segment.
	_, _, _, err = flowLogIDParts(testNetworkWatcherNativeID)
	require.Error(t, err)
}

// --- Test helpers ---

func newTestFlowLog(api flowLogsAPI) *FlowLog {
	return &FlowLog{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

type fakeFlowLogsAPI struct {
	beginCreateOrUpdateFn     func(ctx context.Context, rgName, watcherName, name string, params armnetwork.FlowLog, opts *armnetwork.FlowLogsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.FlowLogsClientCreateOrUpdateResponse], error)
	getFn                     func(ctx context.Context, rgName, watcherName, name string, opts *armnetwork.FlowLogsClientGetOptions) (armnetwork.FlowLogsClientGetResponse, error)
	beginDeleteFn             func(ctx context.Context, rgName, watcherName, name string, opts *armnetwork.FlowLogsClientBeginDeleteOptions) (*runtime.Poller[armnetwork.FlowLogsClientDeleteResponse], error)
	newListPagerFn            func(rgName, watcherName string, opts *armnetwork.FlowLogsClientListOptions) *runtime.Pager[armnetwork.FlowLogsClientListResponse]
	newListAllWatchersPagerFn func(opts *armnetwork.WatchersClientListAllOptions) *runtime.Pager[armnetwork.WatchersClientListAllResponse]
}

func (f *fakeFlowLogsAPI) BeginCreateOrUpdate(ctx context.Context, rgName, watcherName, name string, params armnetwork.FlowLog, opts *armnetwork.FlowLogsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.FlowLogsClientCreateOrUpdateResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, rgName, watcherName, name, params, opts)
}

func (f *fakeFlowLogsAPI) Get(ctx context.Context, rgName, watcherName, name string, opts *armnetwork.FlowLogsClientGetOptions) (armnetwork.FlowLogsClientGetResponse, error) {
	return f.getFn(ctx, rgName, watcherName, name, opts)
}

func (f *fakeFlowLogsAPI) BeginDelete(ctx context.Context, rgName, watcherName, name string, opts *armnetwork.FlowLogsClientBeginDeleteOptions) (*runtime.Poller[armnetwork.FlowLogsClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, watcherName, name, opts)
}

func (f *fakeFlowLogsAPI) NewListPager(rgName, watcherName string, opts *armnetwork.FlowLogsClientListOptions) *runtime.Pager[armnetwork.FlowLogsClientListResponse] {
	return f.newListPagerFn(rgName, watcherName, opts)
}

func (f *fakeFlowLogsAPI) NewListAllWatchersPager(opts *armnetwork.WatchersClientListAllOptions) *runtime.Pager[armnetwork.WatchersClientListAllResponse] {
	return f.newListAllWatchersPagerFn(opts)
}
