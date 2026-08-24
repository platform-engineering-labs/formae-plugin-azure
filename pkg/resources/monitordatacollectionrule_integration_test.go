// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/monitor/armmonitor"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const (
	testDataCollectionRuleNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Insights/dataCollectionRules/dcr1"
	testDCRWorkspaceID             = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.OperationalInsights/workspaces/ws1"
)

type fakeDataCollectionRulesAPI struct {
	createFn      func(ctx context.Context, rgName, name string, body armmonitor.DataCollectionRuleResource, options *armmonitor.DataCollectionRulesClientCreateOptions) (armmonitor.DataCollectionRulesClientCreateResponse, error)
	getFn         func(ctx context.Context, rgName, name string, options *armmonitor.DataCollectionRulesClientGetOptions) (armmonitor.DataCollectionRulesClientGetResponse, error)
	deleteFn      func(ctx context.Context, rgName, name string, options *armmonitor.DataCollectionRulesClientDeleteOptions) (armmonitor.DataCollectionRulesClientDeleteResponse, error)
	listByGroupFn func(rgName string, options *armmonitor.DataCollectionRulesClientListByResourceGroupOptions) *runtime.Pager[armmonitor.DataCollectionRulesClientListByResourceGroupResponse]
	listBySubFn   func(options *armmonitor.DataCollectionRulesClientListBySubscriptionOptions) *runtime.Pager[armmonitor.DataCollectionRulesClientListBySubscriptionResponse]
}

func (f *fakeDataCollectionRulesAPI) Create(ctx context.Context, rgName, name string, body armmonitor.DataCollectionRuleResource, options *armmonitor.DataCollectionRulesClientCreateOptions) (armmonitor.DataCollectionRulesClientCreateResponse, error) {
	return f.createFn(ctx, rgName, name, body, options)
}

func (f *fakeDataCollectionRulesAPI) Get(ctx context.Context, rgName, name string, options *armmonitor.DataCollectionRulesClientGetOptions) (armmonitor.DataCollectionRulesClientGetResponse, error) {
	return f.getFn(ctx, rgName, name, options)
}

func (f *fakeDataCollectionRulesAPI) Delete(ctx context.Context, rgName, name string, options *armmonitor.DataCollectionRulesClientDeleteOptions) (armmonitor.DataCollectionRulesClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, name, options)
}

func (f *fakeDataCollectionRulesAPI) NewListByResourceGroupPager(rgName string, options *armmonitor.DataCollectionRulesClientListByResourceGroupOptions) *runtime.Pager[armmonitor.DataCollectionRulesClientListByResourceGroupResponse] {
	return f.listByGroupFn(rgName, options)
}

func (f *fakeDataCollectionRulesAPI) NewListBySubscriptionPager(options *armmonitor.DataCollectionRulesClientListBySubscriptionOptions) *runtime.Pager[armmonitor.DataCollectionRulesClientListBySubscriptionResponse] {
	return f.listBySubFn(options)
}

func newTestDataCollectionRule(api monitorDataCollectionRulesAPI) *MonitorDataCollectionRule {
	return &MonitorDataCollectionRule{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func dataCollectionRuleDesired(counters []any, frequency int) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":              "dcr1",
		"resourceGroupName": "rg-1",
		"location":          "eastus",
		"kind":              "Linux",
		"description":       "cpu sampling",
		"performanceCounters": []any{map[string]any{
			"name":                       "perf-counters",
			"streams":                    []any{"Microsoft-Perf"},
			"samplingFrequencyInSeconds": frequency,
			"counterSpecifiers":          counters,
		}},
		"logAnalyticsDestinations": []any{map[string]any{
			"name":                "law-destination",
			"workspaceResourceId": testDCRWorkspaceID,
		}},
		"dataFlows": []any{map[string]any{
			"streams":      []any{"Microsoft-Perf"},
			"destinations": []any{"law-destination"},
		}},
		"Tags": []any{map[string]any{"Key": "env", "Value": "test"}},
	})
	return out
}

func TestMonitorDataCollectionRule_CRUD(t *testing.T) {
	ruleResult := armmonitor.DataCollectionRuleResource{
		ID:       to.Ptr(testDataCollectionRuleNativeID),
		Name:     to.Ptr("dcr1"),
		Location: to.Ptr("East US"),
		Kind:     to.Ptr(armmonitor.KnownDataCollectionRuleResourceKindLinux),
		Properties: &armmonitor.DataCollectionRuleResourceProperties{
			Description: to.Ptr("cpu sampling"),
			ImmutableID: to.Ptr("dcr-1a2b3c4d"),
			DataSources: &armmonitor.DataCollectionRuleDataSources{
				PerformanceCounters: []*armmonitor.PerfCounterDataSource{{
					Name:                       to.Ptr("perf-counters"),
					Streams:                    []*armmonitor.KnownPerfCounterDataSourceStreams{to.Ptr(armmonitor.KnownPerfCounterDataSourceStreamsMicrosoftPerf)},
					SamplingFrequencyInSeconds: to.Ptr(int32(60)),
					CounterSpecifiers:          []*string{to.Ptr(`\Processor(_Total)\% Processor Time`)},
				}},
				// Unmodelled data source kinds must never reach state.
				Syslog: []*armmonitor.SyslogDataSource{{
					Name:          to.Ptr("unmodelled-syslog"),
					FacilityNames: []*armmonitor.KnownSyslogDataSourceFacilityNames{to.Ptr(armmonitor.KnownSyslogDataSourceFacilityNamesCron)},
				}},
			},
			Destinations: &armmonitor.DataCollectionRuleDestinations{
				LogAnalytics: []*armmonitor.LogAnalyticsDestination{{
					Name:                to.Ptr("law-destination"),
					WorkspaceResourceID: to.Ptr(testDCRWorkspaceID),
					// The service's own GUID for the workspace. It sits on a nested
					// class, where hasProviderDefault is not honored.
					WorkspaceID: to.Ptr("4f2c1b7e-1111-2222-3333-444455556666"),
				}},
				// Unmodelled destination kinds must never reach state either.
				AzureMonitorMetrics: &armmonitor.DestinationsSpecAzureMonitorMetrics{
					Name: to.Ptr("unmodelled-metrics"),
				},
			},
			DataFlows: []*armmonitor.DataFlow{{
				Streams:      []*armmonitor.KnownDataFlowStreams{to.Ptr(armmonitor.KnownDataFlowStreamsMicrosoftPerf)},
				Destinations: []*string{to.Ptr("law-destination")},
			}},
			ProvisioningState: to.Ptr(armmonitor.KnownDataCollectionRuleProvisioningStateSucceeded),
		},
		Tags: map[string]*string{"env": to.Ptr("test")},
		Etag: to.Ptr("\"etag\""),
	}

	var sent armmonitor.DataCollectionRuleResource
	writeCalls := 0
	deleteCalls := 0
	fake := &fakeDataCollectionRulesAPI{
		createFn: func(_ context.Context, rgName, name string, body armmonitor.DataCollectionRuleResource, _ *armmonitor.DataCollectionRulesClientCreateOptions) (armmonitor.DataCollectionRulesClientCreateResponse, error) {
			require.Equal(t, "rg-1", rgName)
			require.Equal(t, "dcr1", name)
			sent = body
			writeCalls++
			return armmonitor.DataCollectionRulesClientCreateResponse{DataCollectionRuleResource: ruleResult}, nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armmonitor.DataCollectionRulesClientGetOptions) (armmonitor.DataCollectionRulesClientGetResponse, error) {
			return armmonitor.DataCollectionRulesClientGetResponse{DataCollectionRuleResource: ruleResult}, nil
		},
		deleteFn: func(_ context.Context, _, _ string, _ *armmonitor.DataCollectionRulesClientDeleteOptions) (armmonitor.DataCollectionRulesClientDeleteResponse, error) {
			deleteCalls++
			return armmonitor.DataCollectionRulesClientDeleteResponse{}, nil
		},
		listByGroupFn: func(_ string, _ *armmonitor.DataCollectionRulesClientListByResourceGroupOptions) *runtime.Pager[armmonitor.DataCollectionRulesClientListByResourceGroupResponse] {
			return runtime.NewPager(runtime.PagingHandler[armmonitor.DataCollectionRulesClientListByResourceGroupResponse]{
				More: func(_ armmonitor.DataCollectionRulesClientListByResourceGroupResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armmonitor.DataCollectionRulesClientListByResourceGroupResponse) (armmonitor.DataCollectionRulesClientListByResourceGroupResponse, error) {
					return armmonitor.DataCollectionRulesClientListByResourceGroupResponse{
						DataCollectionRuleResourceListResult: armmonitor.DataCollectionRuleResourceListResult{
							Value: []*armmonitor.DataCollectionRuleResource{
								{ID: to.Ptr(testDataCollectionRuleNativeID)},
								// A nil entry must not panic the walk.
								nil,
							},
						},
					}, nil
				},
			})
		},
		listBySubFn: func(_ *armmonitor.DataCollectionRulesClientListBySubscriptionOptions) *runtime.Pager[armmonitor.DataCollectionRulesClientListBySubscriptionResponse] {
			return runtime.NewPager(runtime.PagingHandler[armmonitor.DataCollectionRulesClientListBySubscriptionResponse]{
				More: func(_ armmonitor.DataCollectionRulesClientListBySubscriptionResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armmonitor.DataCollectionRulesClientListBySubscriptionResponse) (armmonitor.DataCollectionRulesClientListBySubscriptionResponse, error) {
					return armmonitor.DataCollectionRulesClientListBySubscriptionResponse{
						DataCollectionRuleResourceListResult: armmonitor.DataCollectionRuleResourceListResult{
							Value: []*armmonitor.DataCollectionRuleResource{
								{ID: to.Ptr(testDataCollectionRuleNativeID)},
								{ID: to.Ptr("/subscriptions/sub-1/resourceGroups/rg-2/providers/Microsoft.Insights/dataCollectionRules/dcr2")},
							},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestDataCollectionRule(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "dcr1", Properties: dataCollectionRuleDesired([]any{`\Processor(_Total)\% Processor Time`}, 60),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testDataCollectionRuleNativeID, got.ProgressResult.NativeID)

		require.Equal(t, "eastus", *sent.Location)
		require.Equal(t, armmonitor.KnownDataCollectionRuleResourceKindLinux, *sent.Kind)

		counter := sent.Properties.DataSources.PerformanceCounters[0]
		require.Equal(t, "perf-counters", *counter.Name)
		require.Equal(t, int32(60), *counter.SamplingFrequencyInSeconds)
		require.Equal(t, armmonitor.KnownPerfCounterDataSourceStreamsMicrosoftPerf, *counter.Streams[0])
		require.Equal(t, `\Processor(_Total)\% Processor Time`, *counter.CounterSpecifiers[0])

		destination := sent.Properties.Destinations.LogAnalytics[0]
		require.Equal(t, "law-destination", *destination.Name)
		require.Equal(t, testDCRWorkspaceID, *destination.WorkspaceResourceID)
		// The workspace GUID is the service's to fill in.
		require.Nil(t, destination.WorkspaceID)

		flow := sent.Properties.DataFlows[0]
		require.Equal(t, armmonitor.KnownDataFlowStreamsMicrosoftPerf, *flow.Streams[0])
		require.Equal(t, "law-destination", *flow.Destinations[0])

		// Unmodelled union members must not be invented on the way out.
		require.Nil(t, sent.Properties.DataSources.Syslog)
		require.Nil(t, sent.Properties.Destinations.AzureMonitorMetrics)
	})

	t.Run("Create_requires_performance_counters", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "dcr1", "resourceGroupName": "rg-1", "location": "eastus",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "performanceCounters is required")
	})

	t.Run("Create_requires_destinations_and_flows", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "dcr1", "resourceGroupName": "rg-1", "location": "eastus",
			"performanceCounters": []any{map[string]any{
				"name": "c", "streams": []any{"Microsoft-Perf"},
				"samplingFrequencyInSeconds": 60, "counterSpecifiers": []any{`\Processor(*)\*`},
			}},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "logAnalyticsDestinations is required")
	})

	t.Run("Create_requires_sampling_frequency", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "dcr1", "resourceGroupName": "rg-1", "location": "eastus",
			"performanceCounters": []any{map[string]any{
				"name": "c", "streams": []any{"Microsoft-Perf"}, "counterSpecifiers": []any{`\Processor(*)\*`},
			}},
			"logAnalyticsDestinations": []any{map[string]any{"name": "d", "workspaceResourceId": testDCRWorkspaceID}},
			"dataFlows":                []any{map[string]any{"streams": []any{"Microsoft-Perf"}, "destinations": []any{"d"}}},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "samplingFrequencyInSeconds is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testDataCollectionRuleNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "dcr1", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		// ARM returns "East US"; read must normalise or desired state drifts.
		require.Equal(t, "eastus", props["location"])
		require.Equal(t, "Linux", props["kind"])
		require.Equal(t, "cpu sampling", props["description"])
		require.Equal(t, "dcr-1a2b3c4d", props["immutableId"])

		counters := props["performanceCounters"].([]any)
		counter := counters[0].(map[string]any)
		require.Equal(t, "perf-counters", counter["name"])
		require.EqualValues(t, 60, counter["samplingFrequencyInSeconds"])
		require.Equal(t, []any{"Microsoft-Perf"}, counter["streams"])
		require.Equal(t, []any{`\Processor(_Total)\% Processor Time`}, counter["counterSpecifiers"])

		destinations := props["logAnalyticsDestinations"].([]any)
		destination := destinations[0].(map[string]any)
		require.Equal(t, "law-destination", destination["name"])
		require.Equal(t, testDCRWorkspaceID, destination["workspaceResourceId"])

		flows := props["dataFlows"].([]any)
		flow := flows[0].(map[string]any)
		require.Equal(t, []any{"Microsoft-Perf"}, flow["streams"])
		require.Equal(t, []any{"law-destination"}, flow["destinations"])
	})

	// The unmodelled union members and the nested service-assigned GUID would each
	// read as permanent drift.
	t.Run("Read_skips_unmodelled_and_service_state", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testDataCollectionRuleNativeID})
		require.NoError(t, err)
		for _, key := range []string{
			"unmodelled-syslog", "unmodelled-metrics", "syslog", "azureMonitorMetrics",
			"workspaceId", "4f2c1b7e", "provisioningState", "etag", "systemData",
		} {
			require.NotContains(t, got.Properties, key)
		}
	})

	// ResourceForUpdate carries only tags and identity, so any change to the rule
	// itself goes through another PUT.
	t.Run("Update_reissues_create", func(t *testing.T) {
		before := writeCalls
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID: testDataCollectionRuleNativeID,
			DesiredProperties: dataCollectionRuleDesired([]any{
				`\Processor(_Total)\% Processor Time`, `\Memory\Available MBytes`,
			}, 300),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, writeCalls)

		counter := sent.Properties.DataSources.PerformanceCounters[0]
		require.Len(t, counter.CounterSpecifiers, 2)
		require.Equal(t, int32(300), *counter.SamplingFrequencyInSeconds)
		// Location must ride along: a PUT without it is rejected.
		require.Equal(t, "eastus", *sent.Location)
	})

	t.Run("Delete", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testDataCollectionRuleNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _ string, _ *armmonitor.DataCollectionRulesClientDeleteOptions) (armmonitor.DataCollectionRulesClientDeleteResponse, error) {
			return armmonitor.DataCollectionRulesClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testDataCollectionRuleNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Status_is_always_success", func(t *testing.T) {
		got, err := prov.Status(context.Background(), &resource.StatusRequest{RequestID: "whatever"})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_resource_group", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testDataCollectionRuleNativeID}, got.NativeIDs)
	})

	t.Run("List_without_group_is_subscription_wide", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 2)
	})

	t.Run("Read_NotFound", func(t *testing.T) {
		fake.getFn = func(_ context.Context, _, _ string, _ *armmonitor.DataCollectionRulesClientGetOptions) (armmonitor.DataCollectionRulesClientGetResponse, error) {
			return armmonitor.DataCollectionRulesClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testDataCollectionRuleNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
	})
}
