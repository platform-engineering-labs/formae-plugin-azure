// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build integration

// Tests for the three Event Grid ingress types (custom topic, domain, domain
// topic). They share the inbound-IP-rule conversion, and their ARM IDs both end in
// a "topics" segment, so they are covered together.
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

const (
	testEGTopicNativeID       = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.EventGrid/topics/topic-1"
	testEGDomainNativeID      = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.EventGrid/domains/domain-1"
	testEGDomainTopicNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.EventGrid/domains/domain-1/topics/dt-1"
)

// --- shared inbound IP rule conversion ---

func TestEventGridInboundIPRules(t *testing.T) {
	t.Run("order is preserved both ways", func(t *testing.T) {
		// Event Grid evaluates the rule list as given, so this must NOT be sorted
		// (unlike IpGroup.ipAddresses / NatGateway references, which ARM reorders).
		props := map[string]any{"inboundIpRules": []any{
			map[string]any{"ipMask": "10.9.0.0/24", "action": "Allow"},
			map[string]any{"ipMask": "10.1.0.0/24", "action": "Allow"},
		}}
		rules, err := eventGridInboundIPRulesFromProperties(props)
		require.NoError(t, err)
		require.Len(t, rules, 2)
		require.Equal(t, "10.9.0.0/24", *rules[0].IPMask)
		require.Equal(t, "10.1.0.0/24", *rules[1].IPMask)

		back := eventGridInboundIPRulesToProperties(rules)
		require.Equal(t, []map[string]any{
			{"ipMask": "10.9.0.0/24", "action": "Allow"},
			{"ipMask": "10.1.0.0/24", "action": "Allow"},
		}, back)
	})

	t.Run("nil when absent or empty", func(t *testing.T) {
		rules, err := eventGridInboundIPRulesFromProperties(map[string]any{})
		require.NoError(t, err)
		require.Nil(t, rules)
		require.Nil(t, eventGridInboundIPRulesToProperties(nil))
	})

	t.Run("ipMask is required", func(t *testing.T) {
		_, err := eventGridInboundIPRulesFromProperties(map[string]any{
			"inboundIpRules": []any{map[string]any{"action": "Allow"}},
		})
		require.ErrorContains(t, err, "inboundIpRules[0].ipMask is required")
	})

	t.Run("rejects non-object entries", func(t *testing.T) {
		_, err := eventGridInboundIPRulesFromProperties(map[string]any{
			"inboundIpRules": []any{"10.0.0.0/8"},
		})
		require.ErrorContains(t, err, "must be an object")
	})
}

// --- ARM ID strictness: both types end in a "topics" segment ---

func TestEventGridIDPartsDoNotCollide(t *testing.T) {
	rg, name, err := eventGridTopicIDParts(testEGTopicNativeID)
	require.NoError(t, err)
	require.Equal(t, "rg-1", rg)
	require.Equal(t, "topic-1", name)

	rg, domain, topic, err := eventGridDomainTopicIDParts(testEGDomainTopicNativeID)
	require.NoError(t, err)
	require.Equal(t, []string{"rg-1", "domain-1", "dt-1"}, []string{rg, domain, topic})

	rg, dname, err := eventGridDomainIDParts(testEGDomainNativeID)
	require.NoError(t, err)
	require.Equal(t, []string{"rg-1", "domain-1"}, []string{rg, dname})

	// The important pair: a domain topic ID must not parse as a top-level topic, and
	// a top-level topic ID must not parse as a domain topic. armIDParts would match
	// the trailing "topics" segment in both directions.
	_, _, err = eventGridTopicIDParts(testEGDomainTopicNativeID)
	require.Error(t, err)
	_, _, _, err = eventGridDomainTopicIDParts(testEGTopicNativeID)
	require.Error(t, err)
}

// --- custom topic ---

func TestEventGridTopic_CRUD(t *testing.T) {
	model := armeventgrid.Topic{
		ID:       to.Ptr(testEGTopicNativeID),
		Name:     to.Ptr("topic-1"),
		Location: to.Ptr("eastus"),
		Properties: &armeventgrid.TopicProperties{
			InputSchema:         to.Ptr(armeventgrid.InputSchemaEventGridSchema),
			PublicNetworkAccess: to.Ptr(armeventgrid.PublicNetworkAccessEnabled),
			DisableLocalAuth:    to.Ptr(false),
			Endpoint:            to.Ptr("https://topic-1.eastus-1.eventgrid.azure.net/api/events"),
		},
		Tags: map[string]*string{"Environment": to.Ptr("test")},
	}
	fake := &fakeEventGridTopicsAPI{
		beginCreateOrUpdateFn: func(_ context.Context, _, _ string, _ armeventgrid.Topic, _ *armeventgrid.TopicsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armeventgrid.TopicsClientCreateOrUpdateResponse], error) {
			return newDonePoller(armeventgrid.TopicsClientCreateOrUpdateResponse{Topic: model}), nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armeventgrid.TopicsClientGetOptions) (armeventgrid.TopicsClientGetResponse, error) {
			return armeventgrid.TopicsClientGetResponse{Topic: model}, nil
		},
		beginDeleteFn: func(_ context.Context, _, _ string, _ *armeventgrid.TopicsClientBeginDeleteOptions) (*runtime.Poller[armeventgrid.TopicsClientDeleteResponse], error) {
			return newInProgressPoller[armeventgrid.TopicsClientDeleteResponse](), nil
		},
		newListByResourceGroupPagerFn: func(_ string, _ *armeventgrid.TopicsClientListByResourceGroupOptions) *runtime.Pager[armeventgrid.TopicsClientListByResourceGroupResponse] {
			return runtime.NewPager(runtime.PagingHandler[armeventgrid.TopicsClientListByResourceGroupResponse]{
				More: func(_ armeventgrid.TopicsClientListByResourceGroupResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armeventgrid.TopicsClientListByResourceGroupResponse) (armeventgrid.TopicsClientListByResourceGroupResponse, error) {
					return armeventgrid.TopicsClientListByResourceGroupResponse{
						TopicsListResult: armeventgrid.TopicsListResult{
							Value: []*armeventgrid.Topic{{ID: to.Ptr(testEGTopicNativeID)}},
						},
					}, nil
				},
			})
		},
		newListBySubscriptionPagerFn: func(_ *armeventgrid.TopicsClientListBySubscriptionOptions) *runtime.Pager[armeventgrid.TopicsClientListBySubscriptionResponse] {
			return runtime.NewPager(runtime.PagingHandler[armeventgrid.TopicsClientListBySubscriptionResponse]{
				More: func(_ armeventgrid.TopicsClientListBySubscriptionResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armeventgrid.TopicsClientListBySubscriptionResponse) (armeventgrid.TopicsClientListBySubscriptionResponse, error) {
					return armeventgrid.TopicsClientListBySubscriptionResponse{
						TopicsListResult: armeventgrid.TopicsListResult{
							Value: []*armeventgrid.Topic{{ID: to.Ptr(testEGTopicNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := &EventGridTopic{api: fake, config: &config.Config{SubscriptionId: "sub-1"}}

	mkProps := func() json.RawMessage {
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName":   "rg-1",
			"name":                "topic-1",
			"location":            "eastus",
			"inputSchema":         "EventGridSchema",
			"publicNetworkAccess": "Enabled",
			"disableLocalAuth":    false,
			"Tags":                []map[string]string{{"Key": "Environment", "Value": "test"}},
		})
		return props
	}

	t.Run("Create", func(t *testing.T) {
		var seen armeventgrid.Topic
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, params armeventgrid.Topic, _ *armeventgrid.TopicsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armeventgrid.TopicsClientCreateOrUpdateResponse], error) {
			seen = params
			return newDonePoller(armeventgrid.TopicsClientCreateOrUpdateResponse{Topic: model}), nil
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testEGTopicNativeID, got.ProgressResult.NativeID)
		require.Equal(t, "eastus", *seen.Location)
		require.Equal(t, armeventgrid.InputSchemaEventGridSchema, *seen.Properties.InputSchema)
		require.Equal(t, false, *seen.Properties.DisableLocalAuth)
		require.Equal(t, "test", *seen.Tags["Environment"])

		var serialized map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &serialized))
		require.Equal(t, "topic-1", serialized["name"])
		require.Equal(t, "rg-1", serialized["resourceGroupName"])
		require.Equal(t, "EventGridSchema", serialized["inputSchema"])
		require.Equal(t, "Enabled", serialized["publicNetworkAccess"])
		// The publish endpoint is Azure-assigned and surfaced for publishers.
		require.Equal(t, "https://topic-1.eastus-1.eventgrid.azure.net/api/events", serialized["endpoint"])
	})

	t.Run("Create requires location", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"resourceGroupName": "rg-1", "name": "topic-1"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "location is required")
	})

	t.Run("Create requires resourceGroupName", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "topic-1", "location": "eastus"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "resourceGroupName is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testEGTopicNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
		require.Equal(t, ResourceTypeEventGridTopic, got.ResourceType)
	})

	t.Run("Read_not_found", func(t *testing.T) {
		fake.getFn = func(_ context.Context, _, _ string, _ *armeventgrid.TopicsClientGetOptions) (armeventgrid.TopicsClientGetResponse, error) {
			return armeventgrid.TopicsClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testEGTopicNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)

		fake.getFn = func(_ context.Context, _, _ string, _ *armeventgrid.TopicsClientGetOptions) (armeventgrid.TopicsClientGetResponse, error) {
			return armeventgrid.TopicsClientGetResponse{Topic: model}, nil
		}
	})

	t.Run("Update forwards inbound IP rules", func(t *testing.T) {
		var seen armeventgrid.Topic
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, params armeventgrid.Topic, _ *armeventgrid.TopicsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armeventgrid.TopicsClientCreateOrUpdateResponse], error) {
			seen = params
			return newDonePoller(armeventgrid.TopicsClientCreateOrUpdateResponse{Topic: model}), nil
		}
		desired, _ := json.Marshal(map[string]any{
			"resourceGroupName":   "rg-1",
			"name":                "topic-1",
			"location":            "eastus",
			"publicNetworkAccess": "Enabled",
			"inboundIpRules": []map[string]any{
				{"ipMask": "203.0.113.0/24", "action": "Allow"},
			},
		})
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID: testEGTopicNativeID, DesiredProperties: desired,
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Len(t, seen.Properties.InboundIPRules, 1)
		require.Equal(t, "203.0.113.0/24", *seen.Properties.InboundIPRules[0].IPMask)
	})

	t.Run("Delete_in_progress_returns_lro_request_id", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testEGTopicNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusInProgress, got.ProgressResult.OperationStatus)
		reqID, err := decodeLROStatus(got.ProgressResult.RequestID)
		require.NoError(t, err)
		require.Equal(t, lroOpDelete, reqID.OperationType)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _ string, _ *armeventgrid.TopicsClientBeginDeleteOptions) (*runtime.Poller[armeventgrid.TopicsClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testEGTopicNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Status_rejects_unknown_operation", func(t *testing.T) {
		reqID, err := encodeLROStart("bogus", "token", testEGTopicNativeID)
		require.NoError(t, err)
		got, err := prov.Status(context.Background(), &resource.StatusRequest{RequestID: reqID})
		require.Error(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_resource_group_and_subscription", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testEGTopicNativeID}, got.NativeIDs)

		got, err = prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Equal(t, []string{testEGTopicNativeID}, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, _ armeventgrid.Topic, _ *armeventgrid.TopicsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armeventgrid.TopicsClientCreateOrUpdateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 403}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

// --- domain ---

func TestEventGridDomain_CRUD(t *testing.T) {
	model := armeventgrid.Domain{
		ID:       to.Ptr(testEGDomainNativeID),
		Name:     to.Ptr("domain-1"),
		Location: to.Ptr("eastus"),
		Properties: &armeventgrid.DomainProperties{
			InputSchema:                          to.Ptr(armeventgrid.InputSchemaEventGridSchema),
			PublicNetworkAccess:                  to.Ptr(armeventgrid.PublicNetworkAccessEnabled),
			DisableLocalAuth:                     to.Ptr(false),
			AutoCreateTopicWithFirstSubscription: to.Ptr(true),
			AutoDeleteTopicWithLastSubscription:  to.Ptr(false),
			Endpoint:                             to.Ptr("https://domain-1.eastus-1.eventgrid.azure.net/api/events"),
		},
	}
	fake := &fakeEventGridDomainsAPI{
		beginCreateOrUpdateFn: func(_ context.Context, _, _ string, _ armeventgrid.Domain, _ *armeventgrid.DomainsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armeventgrid.DomainsClientCreateOrUpdateResponse], error) {
			return newDonePoller(armeventgrid.DomainsClientCreateOrUpdateResponse{Domain: model}), nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armeventgrid.DomainsClientGetOptions) (armeventgrid.DomainsClientGetResponse, error) {
			return armeventgrid.DomainsClientGetResponse{Domain: model}, nil
		},
		beginDeleteFn: func(_ context.Context, _, _ string, _ *armeventgrid.DomainsClientBeginDeleteOptions) (*runtime.Poller[armeventgrid.DomainsClientDeleteResponse], error) {
			return newInProgressPoller[armeventgrid.DomainsClientDeleteResponse](), nil
		},
		newListByResourceGroupPagerFn: func(_ string, _ *armeventgrid.DomainsClientListByResourceGroupOptions) *runtime.Pager[armeventgrid.DomainsClientListByResourceGroupResponse] {
			return runtime.NewPager(runtime.PagingHandler[armeventgrid.DomainsClientListByResourceGroupResponse]{
				More: func(_ armeventgrid.DomainsClientListByResourceGroupResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armeventgrid.DomainsClientListByResourceGroupResponse) (armeventgrid.DomainsClientListByResourceGroupResponse, error) {
					return armeventgrid.DomainsClientListByResourceGroupResponse{
						DomainsListResult: armeventgrid.DomainsListResult{
							Value: []*armeventgrid.Domain{{ID: to.Ptr(testEGDomainNativeID)}},
						},
					}, nil
				},
			})
		},
		newListBySubscriptionPagerFn: func(_ *armeventgrid.DomainsClientListBySubscriptionOptions) *runtime.Pager[armeventgrid.DomainsClientListBySubscriptionResponse] {
			return runtime.NewPager(runtime.PagingHandler[armeventgrid.DomainsClientListBySubscriptionResponse]{
				More: func(_ armeventgrid.DomainsClientListBySubscriptionResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armeventgrid.DomainsClientListBySubscriptionResponse) (armeventgrid.DomainsClientListBySubscriptionResponse, error) {
					return armeventgrid.DomainsClientListBySubscriptionResponse{
						DomainsListResult: armeventgrid.DomainsListResult{
							Value: []*armeventgrid.Domain{{ID: to.Ptr(testEGDomainNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := &EventGridDomain{api: fake, config: &config.Config{SubscriptionId: "sub-1"}}

	t.Run("Create forwards the domain-only auto-topic flags", func(t *testing.T) {
		var seen armeventgrid.Domain
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, params armeventgrid.Domain, _ *armeventgrid.DomainsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armeventgrid.DomainsClientCreateOrUpdateResponse], error) {
			seen = params
			return newDonePoller(armeventgrid.DomainsClientCreateOrUpdateResponse{Domain: model}), nil
		}
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName":                    "rg-1",
			"name":                                 "domain-1",
			"location":                             "eastus",
			"inputSchema":                          "EventGridSchema",
			"autoCreateTopicWithFirstSubscription": true,
			"autoDeleteTopicWithLastSubscription":  false,
		})
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testEGDomainNativeID, got.ProgressResult.NativeID)
		require.Equal(t, true, *seen.Properties.AutoCreateTopicWithFirstSubscription)
		require.Equal(t, false, *seen.Properties.AutoDeleteTopicWithLastSubscription)

		var serialized map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &serialized))
		require.Equal(t, "domain-1", serialized["name"])
		require.Equal(t, true, serialized["autoCreateTopicWithFirstSubscription"])
		require.Equal(t, false, serialized["autoDeleteTopicWithLastSubscription"])
		require.Equal(t, "https://domain-1.eastus-1.eventgrid.azure.net/api/events", serialized["endpoint"])
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testEGDomainNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
		require.Equal(t, ResourceTypeEventGridDomain, got.ResourceType)
	})

	t.Run("Read_not_found", func(t *testing.T) {
		fake.getFn = func(_ context.Context, _, _ string, _ *armeventgrid.DomainsClientGetOptions) (armeventgrid.DomainsClientGetResponse, error) {
			return armeventgrid.DomainsClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testEGDomainNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)

		fake.getFn = func(_ context.Context, _, _ string, _ *armeventgrid.DomainsClientGetOptions) (armeventgrid.DomainsClientGetResponse, error) {
			return armeventgrid.DomainsClientGetResponse{Domain: model}, nil
		}
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _ string, _ *armeventgrid.DomainsClientBeginDeleteOptions) (*runtime.Poller[armeventgrid.DomainsClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testEGDomainNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_resource_group_and_subscription", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testEGDomainNativeID}, got.NativeIDs)

		got, err = prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Equal(t, []string{testEGDomainNativeID}, got.NativeIDs)
	})
}

// --- domain topic ---

func TestEventGridDomainTopic_CRUD(t *testing.T) {
	model := armeventgrid.DomainTopic{
		ID:   to.Ptr(testEGDomainTopicNativeID),
		Name: to.Ptr("dt-1"),
	}
	fake := &fakeEventGridDomainTopicsAPI{
		beginCreateOrUpdateFn: func(_ context.Context, _, _, _ string, _ *armeventgrid.DomainTopicsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armeventgrid.DomainTopicsClientCreateOrUpdateResponse], error) {
			return newDonePoller(armeventgrid.DomainTopicsClientCreateOrUpdateResponse{DomainTopic: model}), nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ *armeventgrid.DomainTopicsClientGetOptions) (armeventgrid.DomainTopicsClientGetResponse, error) {
			return armeventgrid.DomainTopicsClientGetResponse{DomainTopic: model}, nil
		},
		beginDeleteFn: func(_ context.Context, _, _, _ string, _ *armeventgrid.DomainTopicsClientBeginDeleteOptions) (*runtime.Poller[armeventgrid.DomainTopicsClientDeleteResponse], error) {
			return newInProgressPoller[armeventgrid.DomainTopicsClientDeleteResponse](), nil
		},
		newListByDomainPagerFn: func(_, _ string, _ *armeventgrid.DomainTopicsClientListByDomainOptions) *runtime.Pager[armeventgrid.DomainTopicsClientListByDomainResponse] {
			return runtime.NewPager(runtime.PagingHandler[armeventgrid.DomainTopicsClientListByDomainResponse]{
				More: func(_ armeventgrid.DomainTopicsClientListByDomainResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armeventgrid.DomainTopicsClientListByDomainResponse) (armeventgrid.DomainTopicsClientListByDomainResponse, error) {
					return armeventgrid.DomainTopicsClientListByDomainResponse{
						DomainTopicsListResult: armeventgrid.DomainTopicsListResult{
							Value: []*armeventgrid.DomainTopic{{ID: to.Ptr(testEGDomainTopicNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := &EventGridDomainTopic{api: fake, config: &config.Config{SubscriptionId: "sub-1"}}

	mkProps := func() json.RawMessage {
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName": "rg-1",
			"domainName":        "domain-1",
			"name":              "dt-1",
		})
		return props
	}

	// A domain topic has no request body at all — the SDK create takes only names.
	t.Run("Create sends names only", func(t *testing.T) {
		var seenRG, seenDomain, seenTopic string
		fake.beginCreateOrUpdateFn = func(_ context.Context, rg, domain, topic string, opts *armeventgrid.DomainTopicsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armeventgrid.DomainTopicsClientCreateOrUpdateResponse], error) {
			seenRG, seenDomain, seenTopic = rg, domain, topic
			require.Nil(t, opts)
			return newDonePoller(armeventgrid.DomainTopicsClientCreateOrUpdateResponse{DomainTopic: model}), nil
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testEGDomainTopicNativeID, got.ProgressResult.NativeID)
		require.Equal(t, []string{"rg-1", "domain-1", "dt-1"}, []string{seenRG, seenDomain, seenTopic})

		var serialized map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &serialized))
		require.Equal(t, "dt-1", serialized["name"])
		require.Equal(t, "domain-1", serialized["domainName"])
		require.Equal(t, "rg-1", serialized["resourceGroupName"])
	})

	t.Run("Create requires domainName", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"resourceGroupName": "rg-1", "name": "dt-1"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "domainName is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testEGDomainTopicNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
		require.Equal(t, ResourceTypeEventGridDomainTopic, got.ResourceType)
	})

	t.Run("Read_not_found", func(t *testing.T) {
		fake.getFn = func(_ context.Context, _, _, _ string, _ *armeventgrid.DomainTopicsClientGetOptions) (armeventgrid.DomainTopicsClientGetResponse, error) {
			return armeventgrid.DomainTopicsClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testEGDomainTopicNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)

		fake.getFn = func(_ context.Context, _, _, _ string, _ *armeventgrid.DomainTopicsClientGetOptions) (armeventgrid.DomainTopicsClientGetResponse, error) {
			return armeventgrid.DomainTopicsClientGetResponse{DomainTopic: model}, nil
		}
	})

	// Nothing is writable, so Update must not issue a create/delete — only a re-read.
	t.Run("Update only re-reads, never writes", func(t *testing.T) {
		wrote := false
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _, _ string, _ *armeventgrid.DomainTopicsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armeventgrid.DomainTopicsClientCreateOrUpdateResponse], error) {
			wrote = true
			return newDonePoller(armeventgrid.DomainTopicsClientCreateOrUpdateResponse{DomainTopic: model}), nil
		}
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testEGDomainTopicNativeID,
			DesiredProperties: mkProps(),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testEGDomainTopicNativeID, got.ProgressResult.NativeID)
		require.False(t, wrote, "Update must not call BeginCreateOrUpdate")
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _, _ string, _ *armeventgrid.DomainTopicsClientBeginDeleteOptions) (*runtime.Poller[armeventgrid.DomainTopicsClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testEGDomainTopicNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_domain", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "domainName": "domain-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testEGDomainTopicNativeID}, got.NativeIDs)
	})
}

// --- Fakes ---

type fakeEventGridTopicsAPI struct {
	beginCreateOrUpdateFn         func(ctx context.Context, rgName, name string, params armeventgrid.Topic, opts *armeventgrid.TopicsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armeventgrid.TopicsClientCreateOrUpdateResponse], error)
	getFn                         func(ctx context.Context, rgName, name string, opts *armeventgrid.TopicsClientGetOptions) (armeventgrid.TopicsClientGetResponse, error)
	beginDeleteFn                 func(ctx context.Context, rgName, name string, opts *armeventgrid.TopicsClientBeginDeleteOptions) (*runtime.Poller[armeventgrid.TopicsClientDeleteResponse], error)
	newListByResourceGroupPagerFn func(rgName string, opts *armeventgrid.TopicsClientListByResourceGroupOptions) *runtime.Pager[armeventgrid.TopicsClientListByResourceGroupResponse]
	newListBySubscriptionPagerFn  func(opts *armeventgrid.TopicsClientListBySubscriptionOptions) *runtime.Pager[armeventgrid.TopicsClientListBySubscriptionResponse]
}

func (f *fakeEventGridTopicsAPI) BeginCreateOrUpdate(ctx context.Context, rgName, name string, params armeventgrid.Topic, opts *armeventgrid.TopicsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armeventgrid.TopicsClientCreateOrUpdateResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, rgName, name, params, opts)
}

func (f *fakeEventGridTopicsAPI) Get(ctx context.Context, rgName, name string, opts *armeventgrid.TopicsClientGetOptions) (armeventgrid.TopicsClientGetResponse, error) {
	return f.getFn(ctx, rgName, name, opts)
}

func (f *fakeEventGridTopicsAPI) BeginDelete(ctx context.Context, rgName, name string, opts *armeventgrid.TopicsClientBeginDeleteOptions) (*runtime.Poller[armeventgrid.TopicsClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, name, opts)
}

func (f *fakeEventGridTopicsAPI) NewListByResourceGroupPager(rgName string, opts *armeventgrid.TopicsClientListByResourceGroupOptions) *runtime.Pager[armeventgrid.TopicsClientListByResourceGroupResponse] {
	return f.newListByResourceGroupPagerFn(rgName, opts)
}

func (f *fakeEventGridTopicsAPI) NewListBySubscriptionPager(opts *armeventgrid.TopicsClientListBySubscriptionOptions) *runtime.Pager[armeventgrid.TopicsClientListBySubscriptionResponse] {
	return f.newListBySubscriptionPagerFn(opts)
}

type fakeEventGridDomainsAPI struct {
	beginCreateOrUpdateFn         func(ctx context.Context, rgName, name string, params armeventgrid.Domain, opts *armeventgrid.DomainsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armeventgrid.DomainsClientCreateOrUpdateResponse], error)
	getFn                         func(ctx context.Context, rgName, name string, opts *armeventgrid.DomainsClientGetOptions) (armeventgrid.DomainsClientGetResponse, error)
	beginDeleteFn                 func(ctx context.Context, rgName, name string, opts *armeventgrid.DomainsClientBeginDeleteOptions) (*runtime.Poller[armeventgrid.DomainsClientDeleteResponse], error)
	newListByResourceGroupPagerFn func(rgName string, opts *armeventgrid.DomainsClientListByResourceGroupOptions) *runtime.Pager[armeventgrid.DomainsClientListByResourceGroupResponse]
	newListBySubscriptionPagerFn  func(opts *armeventgrid.DomainsClientListBySubscriptionOptions) *runtime.Pager[armeventgrid.DomainsClientListBySubscriptionResponse]
}

func (f *fakeEventGridDomainsAPI) BeginCreateOrUpdate(ctx context.Context, rgName, name string, params armeventgrid.Domain, opts *armeventgrid.DomainsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armeventgrid.DomainsClientCreateOrUpdateResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, rgName, name, params, opts)
}

func (f *fakeEventGridDomainsAPI) Get(ctx context.Context, rgName, name string, opts *armeventgrid.DomainsClientGetOptions) (armeventgrid.DomainsClientGetResponse, error) {
	return f.getFn(ctx, rgName, name, opts)
}

func (f *fakeEventGridDomainsAPI) BeginDelete(ctx context.Context, rgName, name string, opts *armeventgrid.DomainsClientBeginDeleteOptions) (*runtime.Poller[armeventgrid.DomainsClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, name, opts)
}

func (f *fakeEventGridDomainsAPI) NewListByResourceGroupPager(rgName string, opts *armeventgrid.DomainsClientListByResourceGroupOptions) *runtime.Pager[armeventgrid.DomainsClientListByResourceGroupResponse] {
	return f.newListByResourceGroupPagerFn(rgName, opts)
}

func (f *fakeEventGridDomainsAPI) NewListBySubscriptionPager(opts *armeventgrid.DomainsClientListBySubscriptionOptions) *runtime.Pager[armeventgrid.DomainsClientListBySubscriptionResponse] {
	return f.newListBySubscriptionPagerFn(opts)
}

type fakeEventGridDomainTopicsAPI struct {
	beginCreateOrUpdateFn  func(ctx context.Context, rgName, domainName, topicName string, opts *armeventgrid.DomainTopicsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armeventgrid.DomainTopicsClientCreateOrUpdateResponse], error)
	getFn                  func(ctx context.Context, rgName, domainName, topicName string, opts *armeventgrid.DomainTopicsClientGetOptions) (armeventgrid.DomainTopicsClientGetResponse, error)
	beginDeleteFn          func(ctx context.Context, rgName, domainName, topicName string, opts *armeventgrid.DomainTopicsClientBeginDeleteOptions) (*runtime.Poller[armeventgrid.DomainTopicsClientDeleteResponse], error)
	newListByDomainPagerFn func(rgName, domainName string, opts *armeventgrid.DomainTopicsClientListByDomainOptions) *runtime.Pager[armeventgrid.DomainTopicsClientListByDomainResponse]
}

func (f *fakeEventGridDomainTopicsAPI) BeginCreateOrUpdate(ctx context.Context, rgName, domainName, topicName string, opts *armeventgrid.DomainTopicsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armeventgrid.DomainTopicsClientCreateOrUpdateResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, rgName, domainName, topicName, opts)
}

func (f *fakeEventGridDomainTopicsAPI) Get(ctx context.Context, rgName, domainName, topicName string, opts *armeventgrid.DomainTopicsClientGetOptions) (armeventgrid.DomainTopicsClientGetResponse, error) {
	return f.getFn(ctx, rgName, domainName, topicName, opts)
}

func (f *fakeEventGridDomainTopicsAPI) BeginDelete(ctx context.Context, rgName, domainName, topicName string, opts *armeventgrid.DomainTopicsClientBeginDeleteOptions) (*runtime.Poller[armeventgrid.DomainTopicsClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, domainName, topicName, opts)
}

func (f *fakeEventGridDomainTopicsAPI) NewListByDomainPager(rgName, domainName string, opts *armeventgrid.DomainTopicsClientListByDomainOptions) *runtime.Pager[armeventgrid.DomainTopicsClientListByDomainResponse] {
	return f.newListByDomainPagerFn(rgName, domainName, opts)
}
