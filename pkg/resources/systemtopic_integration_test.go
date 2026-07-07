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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/eventgrid/armeventgrid"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testSTNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.EventGrid/systemTopics/my-topic"
const testSTSource = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Storage/storageAccounts/mysa"

func TestSystemTopic_CRUD(t *testing.T) {
	fake := &fakeSystemTopicsAPI{
		beginCreateOrUpdateFn: func(_ context.Context, _, topicName string, info armeventgrid.SystemTopic, _ *armeventgrid.SystemTopicsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armeventgrid.SystemTopicsClientCreateOrUpdateResponse], error) {
			return newDonePoller(armeventgrid.SystemTopicsClientCreateOrUpdateResponse{
				SystemTopic: armeventgrid.SystemTopic{
					ID:       to.Ptr(testSTNativeID),
					Name:     to.Ptr(topicName),
					Location: info.Location,
					Properties: &armeventgrid.SystemTopicProperties{
						Source:    info.Properties.Source,
						TopicType: info.Properties.TopicType,
					},
				},
			}), nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armeventgrid.SystemTopicsClientGetOptions) (armeventgrid.SystemTopicsClientGetResponse, error) {
			return armeventgrid.SystemTopicsClientGetResponse{
				SystemTopic: armeventgrid.SystemTopic{
					ID:       to.Ptr(testSTNativeID),
					Name:     to.Ptr("my-topic"),
					Location: to.Ptr("eastus"),
					Properties: &armeventgrid.SystemTopicProperties{
						Source:    to.Ptr(testSTSource),
						TopicType: to.Ptr("Microsoft.Storage.StorageAccounts"),
					},
				},
			}, nil
		},
		beginUpdateFn: func(_ context.Context, _, _ string, params armeventgrid.SystemTopicUpdateParameters, _ *armeventgrid.SystemTopicsClientBeginUpdateOptions) (*runtime.Poller[armeventgrid.SystemTopicsClientUpdateResponse], error) {
			return newDonePoller(armeventgrid.SystemTopicsClientUpdateResponse{
				SystemTopic: armeventgrid.SystemTopic{
					ID:       to.Ptr(testSTNativeID),
					Name:     to.Ptr("my-topic"),
					Location: to.Ptr("eastus"),
					Tags:     params.Tags,
					Properties: &armeventgrid.SystemTopicProperties{
						Source:    to.Ptr(testSTSource),
						TopicType: to.Ptr("Microsoft.Storage.StorageAccounts"),
					},
				},
			}), nil
		},
		beginDeleteFn: func(_ context.Context, _, _ string, _ *armeventgrid.SystemTopicsClientBeginDeleteOptions) (*runtime.Poller[armeventgrid.SystemTopicsClientDeleteResponse], error) {
			return newDonePoller(armeventgrid.SystemTopicsClientDeleteResponse{}), nil
		},
		newListByResourceGroupPagerFn: func(_ string, _ *armeventgrid.SystemTopicsClientListByResourceGroupOptions) *runtime.Pager[armeventgrid.SystemTopicsClientListByResourceGroupResponse] {
			return runtime.NewPager(runtime.PagingHandler[armeventgrid.SystemTopicsClientListByResourceGroupResponse]{
				More: func(_ armeventgrid.SystemTopicsClientListByResourceGroupResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armeventgrid.SystemTopicsClientListByResourceGroupResponse) (armeventgrid.SystemTopicsClientListByResourceGroupResponse, error) {
					return armeventgrid.SystemTopicsClientListByResourceGroupResponse{
						SystemTopicsListResult: armeventgrid.SystemTopicsListResult{
							Value: []*armeventgrid.SystemTopic{
								{ID: to.Ptr(testSTNativeID)},
								{ID: to.Ptr("/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.EventGrid/systemTopics/other-topic")},
							},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestSystemTopic(fake)

	createProps := func() json.RawMessage {
		p, _ := json.Marshal(map[string]any{
			"resourceGroupName": "rg-1",
			"location":          "eastus",
			"name":              "my-topic",
			"source":            testSTSource,
			"topicType":         "Microsoft.Storage.StorageAccounts",
		})
		return p
	}

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "my-topic", Properties: createProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testSTNativeID, got.ProgressResult.NativeID)

		var props map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &props))
		require.Equal(t, testSTSource, props["source"])
		require.Equal(t, "Microsoft.Storage.StorageAccounts", props["topicType"])
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testSTNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "my-topic", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "eastus", props["location"])
		require.Equal(t, testSTSource, props["source"])
		require.Equal(t, "Microsoft.Storage.StorageAccounts", props["topicType"])
	})

	t.Run("Update_keeps_native_id", func(t *testing.T) {
		desired, _ := json.Marshal(map[string]any{
			"resourceGroupName": "rg-1",
			"location":          "eastus",
			"name":              "my-topic",
			"source":            testSTSource,
			"topicType":         "Microsoft.Storage.StorageAccounts",
			"Tags":              []map[string]string{{"Key": "Environment", "Value": "updated"}},
		})
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{NativeID: testSTNativeID, DesiredProperties: desired})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testSTNativeID, got.ProgressResult.NativeID)
	})

	t.Run("Delete", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testSTNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testSTNativeID, got.ProgressResult.NativeID)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _ string, _ *armeventgrid.SystemTopicsClientBeginDeleteOptions) (*runtime.Poller[armeventgrid.SystemTopicsClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testSTNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 2)
		require.Equal(t, testSTNativeID, got.NativeIDs[0])
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, _ armeventgrid.SystemTopic, _ *armeventgrid.SystemTopicsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armeventgrid.SystemTopicsClientCreateOrUpdateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 403}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: createProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

// --- Test helpers ---

func newTestSystemTopic(api systemTopicsAPI) *SystemTopic {
	return &SystemTopic{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

type fakeSystemTopicsAPI struct {
	beginCreateOrUpdateFn         func(ctx context.Context, resourceGroupName string, systemTopicName string, systemTopicInfo armeventgrid.SystemTopic, options *armeventgrid.SystemTopicsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armeventgrid.SystemTopicsClientCreateOrUpdateResponse], error)
	getFn                         func(ctx context.Context, resourceGroupName string, systemTopicName string, options *armeventgrid.SystemTopicsClientGetOptions) (armeventgrid.SystemTopicsClientGetResponse, error)
	beginUpdateFn                 func(ctx context.Context, resourceGroupName string, systemTopicName string, systemTopicUpdateParameters armeventgrid.SystemTopicUpdateParameters, options *armeventgrid.SystemTopicsClientBeginUpdateOptions) (*runtime.Poller[armeventgrid.SystemTopicsClientUpdateResponse], error)
	beginDeleteFn                 func(ctx context.Context, resourceGroupName string, systemTopicName string, options *armeventgrid.SystemTopicsClientBeginDeleteOptions) (*runtime.Poller[armeventgrid.SystemTopicsClientDeleteResponse], error)
	newListByResourceGroupPagerFn func(resourceGroupName string, options *armeventgrid.SystemTopicsClientListByResourceGroupOptions) *runtime.Pager[armeventgrid.SystemTopicsClientListByResourceGroupResponse]
}

func (f *fakeSystemTopicsAPI) BeginCreateOrUpdate(ctx context.Context, resourceGroupName string, systemTopicName string, systemTopicInfo armeventgrid.SystemTopic, options *armeventgrid.SystemTopicsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armeventgrid.SystemTopicsClientCreateOrUpdateResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, resourceGroupName, systemTopicName, systemTopicInfo, options)
}

func (f *fakeSystemTopicsAPI) Get(ctx context.Context, resourceGroupName string, systemTopicName string, options *armeventgrid.SystemTopicsClientGetOptions) (armeventgrid.SystemTopicsClientGetResponse, error) {
	return f.getFn(ctx, resourceGroupName, systemTopicName, options)
}

func (f *fakeSystemTopicsAPI) BeginUpdate(ctx context.Context, resourceGroupName string, systemTopicName string, systemTopicUpdateParameters armeventgrid.SystemTopicUpdateParameters, options *armeventgrid.SystemTopicsClientBeginUpdateOptions) (*runtime.Poller[armeventgrid.SystemTopicsClientUpdateResponse], error) {
	return f.beginUpdateFn(ctx, resourceGroupName, systemTopicName, systemTopicUpdateParameters, options)
}

func (f *fakeSystemTopicsAPI) BeginDelete(ctx context.Context, resourceGroupName string, systemTopicName string, options *armeventgrid.SystemTopicsClientBeginDeleteOptions) (*runtime.Poller[armeventgrid.SystemTopicsClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, resourceGroupName, systemTopicName, options)
}

func (f *fakeSystemTopicsAPI) NewListByResourceGroupPager(resourceGroupName string, options *armeventgrid.SystemTopicsClientListByResourceGroupOptions) *runtime.Pager[armeventgrid.SystemTopicsClientListByResourceGroupResponse] {
	return f.newListByResourceGroupPagerFn(resourceGroupName, options)
}
