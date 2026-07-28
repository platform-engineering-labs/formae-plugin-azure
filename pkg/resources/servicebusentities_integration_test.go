// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build integration

// Tests for the three Service Bus entity provisioners (queue, topic,
// subscription). They share the sbOpt*/sbPut* property helpers, so they are
// covered together.
package resources

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/servicebus/armservicebus"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const (
	testSBQueueNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.ServiceBus/namespaces/ns-1/queues/queue-1"
	testSBTopicNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.ServiceBus/namespaces/ns-1/topics/topic-1"
	testSBSubNativeID   = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.ServiceBus/namespaces/ns-1/topics/topic-1/subscriptions/sub-a"
)

// --- property helpers ---

// Omitted properties must stay out of the ARM body entirely: Service Bus treats an
// explicit 0/"" very differently from "not specified".
func TestServiceBusPropHelpers(t *testing.T) {
	t.Run("readers return nil when absent", func(t *testing.T) {
		empty := map[string]any{}
		require.Nil(t, sbOptString(empty, "k"))
		require.Nil(t, sbOptBool(empty, "k"))
		require.Nil(t, sbOptInt32(empty, "k"))
		require.Nil(t, sbOptInt64(empty, "k"))
	})

	t.Run("readers treat empty string as absent", func(t *testing.T) {
		require.Nil(t, sbOptString(map[string]any{"k": ""}, "k"))
	})

	t.Run("readers pass through false and zero", func(t *testing.T) {
		require.Equal(t, false, *sbOptBool(map[string]any{"k": false}, "k"))
		require.Equal(t, int32(0), *sbOptInt32(map[string]any{"k": float64(0)}, "k"))
		require.Equal(t, int64(0), *sbOptInt64(map[string]any{"k": float64(0)}, "k"))
	})

	t.Run("writers skip nil", func(t *testing.T) {
		props := map[string]any{}
		sbPutString(props, "s", nil)
		sbPutBool(props, "b", nil)
		sbPutInt32(props, "i", nil)
		sbPutInt64(props, "l", nil)
		require.Empty(t, props)
	})

	t.Run("writers emit present values", func(t *testing.T) {
		props := map[string]any{}
		sbPutString(props, "s", to.Ptr("v"))
		sbPutBool(props, "b", to.Ptr(false))
		sbPutInt32(props, "i", to.Ptr(int32(7)))
		sbPutInt64(props, "l", to.Ptr(int64(8)))
		require.Equal(t, map[string]any{"s": "v", "b": false, "i": 7, "l": 8}, props)
	})
}

// --- Queue ---

func TestServiceBusQueue_CRUD(t *testing.T) {
	model := armservicebus.SBQueue{
		ID:   to.Ptr(testSBQueueNativeID),
		Name: to.Ptr("queue-1"),
		Properties: &armservicebus.SBQueueProperties{
			LockDuration:                     to.Ptr("PT1M"),
			DefaultMessageTimeToLive:         to.Ptr("P14D"),
			MaxSizeInMegabytes:               to.Ptr(int32(1024)),
			MaxDeliveryCount:                 to.Ptr(int32(10)),
			RequiresSession:                  to.Ptr(false),
			RequiresDuplicateDetection:       to.Ptr(false),
			DeadLetteringOnMessageExpiration: to.Ptr(true),
			EnableBatchedOperations:          to.Ptr(true),
			Status:                           to.Ptr(armservicebus.EntityStatusActive),
		},
	}
	fake := &fakeServiceBusQueuesAPI{
		createOrUpdateFn: func(_ context.Context, _, _, _ string, _ armservicebus.SBQueue, _ *armservicebus.QueuesClientCreateOrUpdateOptions) (armservicebus.QueuesClientCreateOrUpdateResponse, error) {
			return armservicebus.QueuesClientCreateOrUpdateResponse{SBQueue: model}, nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ *armservicebus.QueuesClientGetOptions) (armservicebus.QueuesClientGetResponse, error) {
			return armservicebus.QueuesClientGetResponse{SBQueue: model}, nil
		},
		deleteFn: func(_ context.Context, _, _, _ string, _ *armservicebus.QueuesClientDeleteOptions) (armservicebus.QueuesClientDeleteResponse, error) {
			return armservicebus.QueuesClientDeleteResponse{}, nil
		},
		newListByNamespacePagerFn: func(_, _ string, _ *armservicebus.QueuesClientListByNamespaceOptions) *runtime.Pager[armservicebus.QueuesClientListByNamespaceResponse] {
			return runtime.NewPager(runtime.PagingHandler[armservicebus.QueuesClientListByNamespaceResponse]{
				More: func(_ armservicebus.QueuesClientListByNamespaceResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armservicebus.QueuesClientListByNamespaceResponse) (armservicebus.QueuesClientListByNamespaceResponse, error) {
					return armservicebus.QueuesClientListByNamespaceResponse{
						SBQueueListResult: armservicebus.SBQueueListResult{
							Value: []*armservicebus.SBQueue{{ID: to.Ptr(testSBQueueNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := &ServiceBusQueue{api: fake, config: &config.Config{SubscriptionId: "sub-1"}}

	mkProps := func() json.RawMessage {
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName":                "rg-1",
			"namespaceName":                    "ns-1",
			"name":                             "queue-1",
			"lockDuration":                     "PT1M",
			"defaultMessageTimeToLive":         "P14D",
			"maxSizeInMegabytes":               1024,
			"maxDeliveryCount":                 10,
			"deadLetteringOnMessageExpiration": true,
			"enableBatchedOperations":          true,
			"status":                           "Active",
		})
		return props
	}

	t.Run("Create round-trips ISO-8601 durations", func(t *testing.T) {
		var seen armservicebus.SBQueue
		fake.createOrUpdateFn = func(_ context.Context, _, _, _ string, params armservicebus.SBQueue, _ *armservicebus.QueuesClientCreateOrUpdateOptions) (armservicebus.QueuesClientCreateOrUpdateResponse, error) {
			seen = params
			return armservicebus.QueuesClientCreateOrUpdateResponse{SBQueue: model}, nil
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testSBQueueNativeID, got.ProgressResult.NativeID)
		require.Equal(t, "PT1M", *seen.Properties.LockDuration)
		require.Equal(t, "P14D", *seen.Properties.DefaultMessageTimeToLive)
		require.Equal(t, int32(1024), *seen.Properties.MaxSizeInMegabytes)
		require.Equal(t, armservicebus.EntityStatusActive, *seen.Properties.Status)

		var serialized map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &serialized))
		require.Equal(t, "queue-1", serialized["name"])
		require.Equal(t, "ns-1", serialized["namespaceName"])
		require.Equal(t, "rg-1", serialized["resourceGroupName"])
		require.Equal(t, "PT1M", serialized["lockDuration"])
		require.Equal(t, "P14D", serialized["defaultMessageTimeToLive"])
		require.Equal(t, float64(10), serialized["maxDeliveryCount"])
		require.Equal(t, true, serialized["deadLetteringOnMessageExpiration"])
		require.Equal(t, "Active", serialized["status"])
	})

	t.Run("Create omits unspecified properties", func(t *testing.T) {
		var seen armservicebus.SBQueue
		fake.createOrUpdateFn = func(_ context.Context, _, _, _ string, params armservicebus.SBQueue, _ *armservicebus.QueuesClientCreateOrUpdateOptions) (armservicebus.QueuesClientCreateOrUpdateResponse, error) {
			seen = params
			return armservicebus.QueuesClientCreateOrUpdateResponse{SBQueue: model}, nil
		}
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName": "rg-1", "namespaceName": "ns-1", "name": "queue-1",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.Nil(t, seen.Properties.LockDuration)
		require.Nil(t, seen.Properties.MaxSizeInMegabytes)
		require.Nil(t, seen.Properties.EnablePartitioning)
		require.Nil(t, seen.Properties.Status)
	})

	t.Run("Create requires namespaceName", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"resourceGroupName": "rg-1", "name": "queue-1"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "namespaceName is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testSBQueueNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
		require.Equal(t, ResourceTypeServiceBusQueue, got.ResourceType)
	})

	t.Run("Read_not_found", func(t *testing.T) {
		fake.getFn = func(_ context.Context, _, _, _ string, _ *armservicebus.QueuesClientGetOptions) (armservicebus.QueuesClientGetResponse, error) {
			return armservicebus.QueuesClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testSBQueueNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)

		fake.getFn = func(_ context.Context, _, _, _ string, _ *armservicebus.QueuesClientGetOptions) (armservicebus.QueuesClientGetResponse, error) {
			return armservicebus.QueuesClientGetResponse{SBQueue: model}, nil
		}
	})

	t.Run("Update derives names from native ID", func(t *testing.T) {
		var seenRG, seenNS, seenQueue string
		fake.createOrUpdateFn = func(_ context.Context, rg, ns, q string, _ armservicebus.SBQueue, _ *armservicebus.QueuesClientCreateOrUpdateOptions) (armservicebus.QueuesClientCreateOrUpdateResponse, error) {
			seenRG, seenNS, seenQueue = rg, ns, q
			return armservicebus.QueuesClientCreateOrUpdateResponse{SBQueue: model}, nil
		}
		desired, _ := json.Marshal(map[string]any{"maxDeliveryCount": 20})
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID: testSBQueueNativeID, DesiredProperties: desired,
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, "rg-1", seenRG)
		require.Equal(t, "ns-1", seenNS)
		require.Equal(t, "queue-1", seenQueue)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _, _ string, _ *armservicebus.QueuesClientDeleteOptions) (armservicebus.QueuesClientDeleteResponse, error) {
			return armservicebus.QueuesClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testSBQueueNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Status_is_sync_success", func(t *testing.T) {
		got, err := prov.Status(context.Background(), &resource.StatusRequest{RequestID: "anything"})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_namespace", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "namespaceName": "ns-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testSBQueueNativeID}, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.createOrUpdateFn = func(_ context.Context, _, _, _ string, _ armservicebus.SBQueue, _ *armservicebus.QueuesClientCreateOrUpdateOptions) (armservicebus.QueuesClientCreateOrUpdateResponse, error) {
			return armservicebus.QueuesClientCreateOrUpdateResponse{}, &azcore.ResponseError{StatusCode: 403}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

// --- Topic ---

func TestServiceBusTopic_CRUD(t *testing.T) {
	model := armservicebus.SBTopic{
		ID:   to.Ptr(testSBTopicNativeID),
		Name: to.Ptr("topic-1"),
		Properties: &armservicebus.SBTopicProperties{
			DefaultMessageTimeToLive: to.Ptr("P14D"),
			MaxSizeInMegabytes:       to.Ptr(int32(1024)),
			SupportOrdering:          to.Ptr(true),
			EnableBatchedOperations:  to.Ptr(true),
			Status:                   to.Ptr(armservicebus.EntityStatusActive),
		},
	}
	fake := &fakeServiceBusTopicsAPI{
		createOrUpdateFn: func(_ context.Context, _, _, _ string, _ armservicebus.SBTopic, _ *armservicebus.TopicsClientCreateOrUpdateOptions) (armservicebus.TopicsClientCreateOrUpdateResponse, error) {
			return armservicebus.TopicsClientCreateOrUpdateResponse{SBTopic: model}, nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ *armservicebus.TopicsClientGetOptions) (armservicebus.TopicsClientGetResponse, error) {
			return armservicebus.TopicsClientGetResponse{SBTopic: model}, nil
		},
		deleteFn: func(_ context.Context, _, _, _ string, _ *armservicebus.TopicsClientDeleteOptions) (armservicebus.TopicsClientDeleteResponse, error) {
			return armservicebus.TopicsClientDeleteResponse{}, nil
		},
		newListByNamespacePagerFn: func(_, _ string, _ *armservicebus.TopicsClientListByNamespaceOptions) *runtime.Pager[armservicebus.TopicsClientListByNamespaceResponse] {
			return runtime.NewPager(runtime.PagingHandler[armservicebus.TopicsClientListByNamespaceResponse]{
				More: func(_ armservicebus.TopicsClientListByNamespaceResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armservicebus.TopicsClientListByNamespaceResponse) (armservicebus.TopicsClientListByNamespaceResponse, error) {
					return armservicebus.TopicsClientListByNamespaceResponse{
						SBTopicListResult: armservicebus.SBTopicListResult{
							Value: []*armservicebus.SBTopic{{ID: to.Ptr(testSBTopicNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := &ServiceBusTopic{api: fake, config: &config.Config{SubscriptionId: "sub-1"}}

	mkProps := func() json.RawMessage {
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName":        "rg-1",
			"namespaceName":            "ns-1",
			"name":                     "topic-1",
			"defaultMessageTimeToLive": "P14D",
			"maxSizeInMegabytes":       1024,
			"supportOrdering":          true,
			"enableBatchedOperations":  true,
			"status":                   "Active",
		})
		return props
	}

	t.Run("Create", func(t *testing.T) {
		var seen armservicebus.SBTopic
		fake.createOrUpdateFn = func(_ context.Context, _, _, _ string, params armservicebus.SBTopic, _ *armservicebus.TopicsClientCreateOrUpdateOptions) (armservicebus.TopicsClientCreateOrUpdateResponse, error) {
			seen = params
			return armservicebus.TopicsClientCreateOrUpdateResponse{SBTopic: model}, nil
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testSBTopicNativeID, got.ProgressResult.NativeID)
		require.Equal(t, "P14D", *seen.Properties.DefaultMessageTimeToLive)
		require.Equal(t, true, *seen.Properties.SupportOrdering)

		var serialized map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &serialized))
		require.Equal(t, "topic-1", serialized["name"])
		require.Equal(t, "P14D", serialized["defaultMessageTimeToLive"])
		require.Equal(t, true, serialized["supportOrdering"])
	})

	t.Run("Create requires resourceGroupName", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"namespaceName": "ns-1", "name": "topic-1"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "resourceGroupName is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testSBTopicNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
		require.Equal(t, ResourceTypeServiceBusTopic, got.ResourceType)
	})

	t.Run("Read_not_found", func(t *testing.T) {
		fake.getFn = func(_ context.Context, _, _, _ string, _ *armservicebus.TopicsClientGetOptions) (armservicebus.TopicsClientGetResponse, error) {
			return armservicebus.TopicsClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testSBTopicNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)

		fake.getFn = func(_ context.Context, _, _, _ string, _ *armservicebus.TopicsClientGetOptions) (armservicebus.TopicsClientGetResponse, error) {
			return armservicebus.TopicsClientGetResponse{SBTopic: model}, nil
		}
	})

	t.Run("Update derives names from native ID", func(t *testing.T) {
		var seenRG, seenNS, seenTopic string
		fake.createOrUpdateFn = func(_ context.Context, rg, ns, tp string, _ armservicebus.SBTopic, _ *armservicebus.TopicsClientCreateOrUpdateOptions) (armservicebus.TopicsClientCreateOrUpdateResponse, error) {
			seenRG, seenNS, seenTopic = rg, ns, tp
			return armservicebus.TopicsClientCreateOrUpdateResponse{SBTopic: model}, nil
		}
		desired, _ := json.Marshal(map[string]any{"supportOrdering": false})
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID: testSBTopicNativeID, DesiredProperties: desired,
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, "rg-1", seenRG)
		require.Equal(t, "ns-1", seenNS)
		require.Equal(t, "topic-1", seenTopic)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _, _ string, _ *armservicebus.TopicsClientDeleteOptions) (armservicebus.TopicsClientDeleteResponse, error) {
			return armservicebus.TopicsClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testSBTopicNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_namespace", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "namespaceName": "ns-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testSBTopicNativeID}, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.createOrUpdateFn = func(_ context.Context, _, _, _ string, _ armservicebus.SBTopic, _ *armservicebus.TopicsClientCreateOrUpdateOptions) (armservicebus.TopicsClientCreateOrUpdateResponse, error) {
			return armservicebus.TopicsClientCreateOrUpdateResponse{}, &azcore.ResponseError{StatusCode: 403}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

// --- Subscription ---

func TestServiceBusSubscription_CRUD(t *testing.T) {
	model := armservicebus.SBSubscription{
		ID:   to.Ptr(testSBSubNativeID),
		Name: to.Ptr("sub-a"),
		Properties: &armservicebus.SBSubscriptionProperties{
			LockDuration:                     to.Ptr("PT1M"),
			DefaultMessageTimeToLive:         to.Ptr("P14D"),
			MaxDeliveryCount:                 to.Ptr(int32(10)),
			RequiresSession:                  to.Ptr(false),
			DeadLetteringOnMessageExpiration: to.Ptr(true),
			EnableBatchedOperations:          to.Ptr(true),
			Status:                           to.Ptr(armservicebus.EntityStatusActive),
		},
	}
	fake := &fakeServiceBusSubscriptionsAPI{
		createOrUpdateFn: func(_ context.Context, _, _, _, _ string, _ armservicebus.SBSubscription, _ *armservicebus.SubscriptionsClientCreateOrUpdateOptions) (armservicebus.SubscriptionsClientCreateOrUpdateResponse, error) {
			return armservicebus.SubscriptionsClientCreateOrUpdateResponse{SBSubscription: model}, nil
		},
		getFn: func(_ context.Context, _, _, _, _ string, _ *armservicebus.SubscriptionsClientGetOptions) (armservicebus.SubscriptionsClientGetResponse, error) {
			return armservicebus.SubscriptionsClientGetResponse{SBSubscription: model}, nil
		},
		deleteFn: func(_ context.Context, _, _, _, _ string, _ *armservicebus.SubscriptionsClientDeleteOptions) (armservicebus.SubscriptionsClientDeleteResponse, error) {
			return armservicebus.SubscriptionsClientDeleteResponse{}, nil
		},
		newListByTopicPagerFn: func(_, _, _ string, _ *armservicebus.SubscriptionsClientListByTopicOptions) *runtime.Pager[armservicebus.SubscriptionsClientListByTopicResponse] {
			return runtime.NewPager(runtime.PagingHandler[armservicebus.SubscriptionsClientListByTopicResponse]{
				More: func(_ armservicebus.SubscriptionsClientListByTopicResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armservicebus.SubscriptionsClientListByTopicResponse) (armservicebus.SubscriptionsClientListByTopicResponse, error) {
					return armservicebus.SubscriptionsClientListByTopicResponse{
						SBSubscriptionListResult: armservicebus.SBSubscriptionListResult{
							Value: []*armservicebus.SBSubscription{{ID: to.Ptr(testSBSubNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := &ServiceBusSubscription{api: fake, config: &config.Config{SubscriptionId: "sub-1"}}

	mkProps := func() json.RawMessage {
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName":                "rg-1",
			"namespaceName":                    "ns-1",
			"topicName":                        "topic-1",
			"name":                             "sub-a",
			"lockDuration":                     "PT1M",
			"defaultMessageTimeToLive":         "P14D",
			"maxDeliveryCount":                 10,
			"deadLetteringOnMessageExpiration": true,
			"enableBatchedOperations":          true,
			"status":                           "Active",
		})
		return props
	}

	t.Run("Create", func(t *testing.T) {
		var seen armservicebus.SBSubscription
		var seenRG, seenNS, seenTopic, seenSub string
		fake.createOrUpdateFn = func(_ context.Context, rg, ns, tp, sb string, params armservicebus.SBSubscription, _ *armservicebus.SubscriptionsClientCreateOrUpdateOptions) (armservicebus.SubscriptionsClientCreateOrUpdateResponse, error) {
			seen, seenRG, seenNS, seenTopic, seenSub = params, rg, ns, tp, sb
			return armservicebus.SubscriptionsClientCreateOrUpdateResponse{SBSubscription: model}, nil
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testSBSubNativeID, got.ProgressResult.NativeID)
		require.Equal(t, "rg-1", seenRG)
		require.Equal(t, "ns-1", seenNS)
		require.Equal(t, "topic-1", seenTopic)
		require.Equal(t, "sub-a", seenSub)
		require.Equal(t, "PT1M", *seen.Properties.LockDuration)

		var serialized map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &serialized))
		require.Equal(t, "sub-a", serialized["name"])
		require.Equal(t, "topic-1", serialized["topicName"])
		require.Equal(t, "ns-1", serialized["namespaceName"])
		require.Equal(t, "PT1M", serialized["lockDuration"])
		require.Equal(t, float64(10), serialized["maxDeliveryCount"])
	})

	t.Run("Create requires topicName", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName": "rg-1", "namespaceName": "ns-1", "name": "sub-a",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "topicName is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testSBSubNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
		require.Equal(t, ResourceTypeServiceBusSubscription, got.ResourceType)
	})

	t.Run("Read_not_found", func(t *testing.T) {
		fake.getFn = func(_ context.Context, _, _, _, _ string, _ *armservicebus.SubscriptionsClientGetOptions) (armservicebus.SubscriptionsClientGetResponse, error) {
			return armservicebus.SubscriptionsClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testSBSubNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)

		fake.getFn = func(_ context.Context, _, _, _, _ string, _ *armservicebus.SubscriptionsClientGetOptions) (armservicebus.SubscriptionsClientGetResponse, error) {
			return armservicebus.SubscriptionsClientGetResponse{SBSubscription: model}, nil
		}
	})

	t.Run("Update derives names from native ID", func(t *testing.T) {
		var seenRG, seenNS, seenTopic, seenSub string
		fake.createOrUpdateFn = func(_ context.Context, rg, ns, tp, sb string, _ armservicebus.SBSubscription, _ *armservicebus.SubscriptionsClientCreateOrUpdateOptions) (armservicebus.SubscriptionsClientCreateOrUpdateResponse, error) {
			seenRG, seenNS, seenTopic, seenSub = rg, ns, tp, sb
			return armservicebus.SubscriptionsClientCreateOrUpdateResponse{SBSubscription: model}, nil
		}
		desired, _ := json.Marshal(map[string]any{"maxDeliveryCount": 20})
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID: testSBSubNativeID, DesiredProperties: desired,
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, "rg-1", seenRG)
		require.Equal(t, "ns-1", seenNS)
		require.Equal(t, "topic-1", seenTopic)
		require.Equal(t, "sub-a", seenSub)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _, _, _ string, _ *armservicebus.SubscriptionsClientDeleteOptions) (armservicebus.SubscriptionsClientDeleteResponse, error) {
			return armservicebus.SubscriptionsClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testSBSubNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_topic", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{
				"resourceGroupName": "rg-1", "namespaceName": "ns-1", "topicName": "topic-1",
			},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testSBSubNativeID}, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.createOrUpdateFn = func(_ context.Context, _, _, _, _ string, _ armservicebus.SBSubscription, _ *armservicebus.SubscriptionsClientCreateOrUpdateOptions) (armservicebus.SubscriptionsClientCreateOrUpdateResponse, error) {
			return armservicebus.SubscriptionsClientCreateOrUpdateResponse{}, &azcore.ResponseError{StatusCode: 403}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

// --- ARM ID parsing ---

func TestServiceBusEntityIDParts(t *testing.T) {
	rg, ns, q, err := serviceBusQueueIDParts(testSBQueueNativeID)
	require.NoError(t, err)
	require.Equal(t, []string{"rg-1", "ns-1", "queue-1"}, []string{rg, ns, q})

	rg, ns, tp, err := serviceBusTopicIDParts(testSBTopicNativeID)
	require.NoError(t, err)
	require.Equal(t, []string{"rg-1", "ns-1", "topic-1"}, []string{rg, ns, tp})

	rg, ns, tp, sb, err := serviceBusSubscriptionIDParts(testSBSubNativeID)
	require.NoError(t, err)
	require.Equal(t, []string{"rg-1", "ns-1", "topic-1", "sub-a"}, []string{rg, ns, tp, sb})

	// A topic ID is not a subscription ID.
	_, _, _, _, err = serviceBusSubscriptionIDParts(testSBTopicNativeID)
	require.Error(t, err)
	_, _, _, err = serviceBusQueueIDParts(testSBTopicNativeID)
	require.Error(t, err)
}

// --- Fakes ---

type fakeServiceBusQueuesAPI struct {
	createOrUpdateFn          func(ctx context.Context, rgName, nsName, queueName string, params armservicebus.SBQueue, opts *armservicebus.QueuesClientCreateOrUpdateOptions) (armservicebus.QueuesClientCreateOrUpdateResponse, error)
	getFn                     func(ctx context.Context, rgName, nsName, queueName string, opts *armservicebus.QueuesClientGetOptions) (armservicebus.QueuesClientGetResponse, error)
	deleteFn                  func(ctx context.Context, rgName, nsName, queueName string, opts *armservicebus.QueuesClientDeleteOptions) (armservicebus.QueuesClientDeleteResponse, error)
	newListByNamespacePagerFn func(rgName, nsName string, opts *armservicebus.QueuesClientListByNamespaceOptions) *runtime.Pager[armservicebus.QueuesClientListByNamespaceResponse]
}

func (f *fakeServiceBusQueuesAPI) CreateOrUpdate(ctx context.Context, rgName, nsName, queueName string, params armservicebus.SBQueue, opts *armservicebus.QueuesClientCreateOrUpdateOptions) (armservicebus.QueuesClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, nsName, queueName, params, opts)
}

func (f *fakeServiceBusQueuesAPI) Get(ctx context.Context, rgName, nsName, queueName string, opts *armservicebus.QueuesClientGetOptions) (armservicebus.QueuesClientGetResponse, error) {
	return f.getFn(ctx, rgName, nsName, queueName, opts)
}

func (f *fakeServiceBusQueuesAPI) Delete(ctx context.Context, rgName, nsName, queueName string, opts *armservicebus.QueuesClientDeleteOptions) (armservicebus.QueuesClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, nsName, queueName, opts)
}

func (f *fakeServiceBusQueuesAPI) NewListByNamespacePager(rgName, nsName string, opts *armservicebus.QueuesClientListByNamespaceOptions) *runtime.Pager[armservicebus.QueuesClientListByNamespaceResponse] {
	return f.newListByNamespacePagerFn(rgName, nsName, opts)
}

type fakeServiceBusTopicsAPI struct {
	createOrUpdateFn          func(ctx context.Context, rgName, nsName, topicName string, params armservicebus.SBTopic, opts *armservicebus.TopicsClientCreateOrUpdateOptions) (armservicebus.TopicsClientCreateOrUpdateResponse, error)
	getFn                     func(ctx context.Context, rgName, nsName, topicName string, opts *armservicebus.TopicsClientGetOptions) (armservicebus.TopicsClientGetResponse, error)
	deleteFn                  func(ctx context.Context, rgName, nsName, topicName string, opts *armservicebus.TopicsClientDeleteOptions) (armservicebus.TopicsClientDeleteResponse, error)
	newListByNamespacePagerFn func(rgName, nsName string, opts *armservicebus.TopicsClientListByNamespaceOptions) *runtime.Pager[armservicebus.TopicsClientListByNamespaceResponse]
}

func (f *fakeServiceBusTopicsAPI) CreateOrUpdate(ctx context.Context, rgName, nsName, topicName string, params armservicebus.SBTopic, opts *armservicebus.TopicsClientCreateOrUpdateOptions) (armservicebus.TopicsClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, nsName, topicName, params, opts)
}

func (f *fakeServiceBusTopicsAPI) Get(ctx context.Context, rgName, nsName, topicName string, opts *armservicebus.TopicsClientGetOptions) (armservicebus.TopicsClientGetResponse, error) {
	return f.getFn(ctx, rgName, nsName, topicName, opts)
}

func (f *fakeServiceBusTopicsAPI) Delete(ctx context.Context, rgName, nsName, topicName string, opts *armservicebus.TopicsClientDeleteOptions) (armservicebus.TopicsClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, nsName, topicName, opts)
}

func (f *fakeServiceBusTopicsAPI) NewListByNamespacePager(rgName, nsName string, opts *armservicebus.TopicsClientListByNamespaceOptions) *runtime.Pager[armservicebus.TopicsClientListByNamespaceResponse] {
	return f.newListByNamespacePagerFn(rgName, nsName, opts)
}

type fakeServiceBusSubscriptionsAPI struct {
	createOrUpdateFn      func(ctx context.Context, rgName, nsName, topicName, subName string, params armservicebus.SBSubscription, opts *armservicebus.SubscriptionsClientCreateOrUpdateOptions) (armservicebus.SubscriptionsClientCreateOrUpdateResponse, error)
	getFn                 func(ctx context.Context, rgName, nsName, topicName, subName string, opts *armservicebus.SubscriptionsClientGetOptions) (armservicebus.SubscriptionsClientGetResponse, error)
	deleteFn              func(ctx context.Context, rgName, nsName, topicName, subName string, opts *armservicebus.SubscriptionsClientDeleteOptions) (armservicebus.SubscriptionsClientDeleteResponse, error)
	newListByTopicPagerFn func(rgName, nsName, topicName string, opts *armservicebus.SubscriptionsClientListByTopicOptions) *runtime.Pager[armservicebus.SubscriptionsClientListByTopicResponse]
}

func (f *fakeServiceBusSubscriptionsAPI) CreateOrUpdate(ctx context.Context, rgName, nsName, topicName, subName string, params armservicebus.SBSubscription, opts *armservicebus.SubscriptionsClientCreateOrUpdateOptions) (armservicebus.SubscriptionsClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, nsName, topicName, subName, params, opts)
}

func (f *fakeServiceBusSubscriptionsAPI) Get(ctx context.Context, rgName, nsName, topicName, subName string, opts *armservicebus.SubscriptionsClientGetOptions) (armservicebus.SubscriptionsClientGetResponse, error) {
	return f.getFn(ctx, rgName, nsName, topicName, subName, opts)
}

func (f *fakeServiceBusSubscriptionsAPI) Delete(ctx context.Context, rgName, nsName, topicName, subName string, opts *armservicebus.SubscriptionsClientDeleteOptions) (armservicebus.SubscriptionsClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, nsName, topicName, subName, opts)
}

func (f *fakeServiceBusSubscriptionsAPI) NewListByTopicPager(rgName, nsName, topicName string, opts *armservicebus.SubscriptionsClientListByTopicOptions) *runtime.Pager[armservicebus.SubscriptionsClientListByTopicResponse] {
	return f.newListByTopicPagerFn(rgName, nsName, topicName, opts)
}
