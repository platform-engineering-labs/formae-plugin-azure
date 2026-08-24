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

const testDataCollectionEndpointNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Insights/dataCollectionEndpoints/dce1"

type fakeDataCollectionEndpointsAPI struct {
	createFn      func(ctx context.Context, rgName, name string, body armmonitor.DataCollectionEndpointResource, options *armmonitor.DataCollectionEndpointsClientCreateOptions) (armmonitor.DataCollectionEndpointsClientCreateResponse, error)
	getFn         func(ctx context.Context, rgName, name string, options *armmonitor.DataCollectionEndpointsClientGetOptions) (armmonitor.DataCollectionEndpointsClientGetResponse, error)
	deleteFn      func(ctx context.Context, rgName, name string, options *armmonitor.DataCollectionEndpointsClientDeleteOptions) (armmonitor.DataCollectionEndpointsClientDeleteResponse, error)
	listByGroupFn func(rgName string, options *armmonitor.DataCollectionEndpointsClientListByResourceGroupOptions) *runtime.Pager[armmonitor.DataCollectionEndpointsClientListByResourceGroupResponse]
	listBySubFn   func(options *armmonitor.DataCollectionEndpointsClientListBySubscriptionOptions) *runtime.Pager[armmonitor.DataCollectionEndpointsClientListBySubscriptionResponse]
}

func (f *fakeDataCollectionEndpointsAPI) Create(ctx context.Context, rgName, name string, body armmonitor.DataCollectionEndpointResource, options *armmonitor.DataCollectionEndpointsClientCreateOptions) (armmonitor.DataCollectionEndpointsClientCreateResponse, error) {
	return f.createFn(ctx, rgName, name, body, options)
}

func (f *fakeDataCollectionEndpointsAPI) Get(ctx context.Context, rgName, name string, options *armmonitor.DataCollectionEndpointsClientGetOptions) (armmonitor.DataCollectionEndpointsClientGetResponse, error) {
	return f.getFn(ctx, rgName, name, options)
}

func (f *fakeDataCollectionEndpointsAPI) Delete(ctx context.Context, rgName, name string, options *armmonitor.DataCollectionEndpointsClientDeleteOptions) (armmonitor.DataCollectionEndpointsClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, name, options)
}

func (f *fakeDataCollectionEndpointsAPI) NewListByResourceGroupPager(rgName string, options *armmonitor.DataCollectionEndpointsClientListByResourceGroupOptions) *runtime.Pager[armmonitor.DataCollectionEndpointsClientListByResourceGroupResponse] {
	return f.listByGroupFn(rgName, options)
}

func (f *fakeDataCollectionEndpointsAPI) NewListBySubscriptionPager(options *armmonitor.DataCollectionEndpointsClientListBySubscriptionOptions) *runtime.Pager[armmonitor.DataCollectionEndpointsClientListBySubscriptionResponse] {
	return f.listBySubFn(options)
}

func newTestDataCollectionEndpoint(api monitorDataCollectionEndpointsAPI) *MonitorDataCollectionEndpoint {
	return &MonitorDataCollectionEndpoint{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func dataCollectionEndpointDesired(description string) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":                "dce1",
		"resourceGroupName":   "rg-1",
		"location":            "eastus",
		"kind":                "Linux",
		"description":         description,
		"publicNetworkAccess": "Enabled",
		"Tags":                []any{map[string]any{"Key": "env", "Value": "test"}},
	})
	return out
}

func TestMonitorDataCollectionEndpoint_CRUD(t *testing.T) {
	endpointResult := armmonitor.DataCollectionEndpointResource{
		ID:       to.Ptr(testDataCollectionEndpointNativeID),
		Name:     to.Ptr("dce1"),
		Location: to.Ptr("East US"),
		Kind:     to.Ptr(armmonitor.KnownDataCollectionEndpointResourceKindLinux),
		Properties: &armmonitor.DataCollectionEndpointResourceProperties{
			Description: to.Ptr("ingestion front door"),
			ImmutableID: to.Ptr("dce-8f1c2b3a4d5e"),
			NetworkACLs: &armmonitor.DataCollectionEndpointNetworkACLs{
				PublicNetworkAccess: to.Ptr(armmonitor.KnownPublicNetworkAccessOptionsEnabled),
			},
			// Service-assigned addresses agents and rules use.
			LogsIngestion:       &armmonitor.DataCollectionEndpointLogsIngestion{Endpoint: to.Ptr("https://dce1-abc.eastus-1.ingest.monitor.azure.com")},
			MetricsIngestion:    &armmonitor.DataCollectionEndpointMetricsIngestion{Endpoint: to.Ptr("https://dce1-abc.eastus-1.metrics.ingest.monitor.azure.com")},
			ConfigurationAccess: &armmonitor.DataCollectionEndpointConfigurationAccess{Endpoint: to.Ptr("https://dce1-abc.eastus-1.handler.control.monitor.azure.com")},
			ProvisioningState:   to.Ptr(armmonitor.KnownDataCollectionEndpointProvisioningStateSucceeded),
		},
		Tags: map[string]*string{"env": to.Ptr("test")},
		Etag: to.Ptr("\"etag\""),
	}

	var sent armmonitor.DataCollectionEndpointResource
	writeCalls := 0
	deleteCalls := 0
	fake := &fakeDataCollectionEndpointsAPI{
		createFn: func(_ context.Context, rgName, name string, body armmonitor.DataCollectionEndpointResource, _ *armmonitor.DataCollectionEndpointsClientCreateOptions) (armmonitor.DataCollectionEndpointsClientCreateResponse, error) {
			require.Equal(t, "rg-1", rgName)
			require.Equal(t, "dce1", name)
			sent = body
			writeCalls++
			return armmonitor.DataCollectionEndpointsClientCreateResponse{DataCollectionEndpointResource: endpointResult}, nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armmonitor.DataCollectionEndpointsClientGetOptions) (armmonitor.DataCollectionEndpointsClientGetResponse, error) {
			return armmonitor.DataCollectionEndpointsClientGetResponse{DataCollectionEndpointResource: endpointResult}, nil
		},
		deleteFn: func(_ context.Context, _, _ string, _ *armmonitor.DataCollectionEndpointsClientDeleteOptions) (armmonitor.DataCollectionEndpointsClientDeleteResponse, error) {
			deleteCalls++
			return armmonitor.DataCollectionEndpointsClientDeleteResponse{}, nil
		},
		listByGroupFn: func(_ string, _ *armmonitor.DataCollectionEndpointsClientListByResourceGroupOptions) *runtime.Pager[armmonitor.DataCollectionEndpointsClientListByResourceGroupResponse] {
			return runtime.NewPager(runtime.PagingHandler[armmonitor.DataCollectionEndpointsClientListByResourceGroupResponse]{
				More: func(_ armmonitor.DataCollectionEndpointsClientListByResourceGroupResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armmonitor.DataCollectionEndpointsClientListByResourceGroupResponse) (armmonitor.DataCollectionEndpointsClientListByResourceGroupResponse, error) {
					return armmonitor.DataCollectionEndpointsClientListByResourceGroupResponse{
						DataCollectionEndpointResourceListResult: armmonitor.DataCollectionEndpointResourceListResult{
							Value: []*armmonitor.DataCollectionEndpointResource{
								{ID: to.Ptr(testDataCollectionEndpointNativeID)},
								// A nil entry must not panic the walk.
								nil,
							},
						},
					}, nil
				},
			})
		},
		listBySubFn: func(_ *armmonitor.DataCollectionEndpointsClientListBySubscriptionOptions) *runtime.Pager[armmonitor.DataCollectionEndpointsClientListBySubscriptionResponse] {
			return runtime.NewPager(runtime.PagingHandler[armmonitor.DataCollectionEndpointsClientListBySubscriptionResponse]{
				More: func(_ armmonitor.DataCollectionEndpointsClientListBySubscriptionResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armmonitor.DataCollectionEndpointsClientListBySubscriptionResponse) (armmonitor.DataCollectionEndpointsClientListBySubscriptionResponse, error) {
					return armmonitor.DataCollectionEndpointsClientListBySubscriptionResponse{
						DataCollectionEndpointResourceListResult: armmonitor.DataCollectionEndpointResourceListResult{
							Value: []*armmonitor.DataCollectionEndpointResource{
								{ID: to.Ptr(testDataCollectionEndpointNativeID)},
								{ID: to.Ptr("/subscriptions/sub-1/resourceGroups/rg-2/providers/Microsoft.Insights/dataCollectionEndpoints/dce2")},
							},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestDataCollectionEndpoint(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "dce1", Properties: dataCollectionEndpointDesired("ingestion front door"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testDataCollectionEndpointNativeID, got.ProgressResult.NativeID)

		require.Equal(t, "eastus", *sent.Location)
		require.Equal(t, armmonitor.KnownDataCollectionEndpointResourceKindLinux, *sent.Kind)
		require.Equal(t, "ingestion front door", *sent.Properties.Description)
		require.Equal(t, armmonitor.KnownPublicNetworkAccessOptionsEnabled, *sent.Properties.NetworkACLs.PublicNetworkAccess)
		require.Equal(t, "test", *sent.Tags["env"])
	})

	t.Run("Create_requires_location", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "dce1", "resourceGroupName": "rg-1"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "location is required")
	})

	t.Run("Create_requires_resource_group", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "dce1", "location": "eastus"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "resourceGroupName is required")
	})

	// An endpoint that declares neither must not carry an empty networkAcls block or
	// an empty kind into the request.
	t.Run("Create_omits_unset_optionals", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "dce1", "resourceGroupName": "rg-1", "location": "eastus",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.Nil(t, sent.Kind)
		require.Nil(t, sent.Properties.NetworkACLs)
		require.Nil(t, sent.Properties.Description)
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testDataCollectionEndpointNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "dce1", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		// ARM returns "East US"; read must normalise or desired state drifts.
		require.Equal(t, "eastus", props["location"])
		require.Equal(t, "Linux", props["kind"])
		require.Equal(t, "ingestion front door", props["description"])
		require.Equal(t, "Enabled", props["publicNetworkAccess"])
		// The service-assigned addresses are the point of the resource.
		require.Equal(t, "dce-8f1c2b3a4d5e", props["immutableId"])
		require.Contains(t, props["logsIngestionEndpoint"], "ingest.monitor.azure.com")
		require.Contains(t, props["metricsIngestionEndpoint"], "metrics.ingest.monitor.azure.com")
		require.Contains(t, props["configurationAccessEndpoint"], "control.monitor.azure.com")
	})

	t.Run("Read_drops_service_state", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testDataCollectionEndpointNativeID})
		require.NoError(t, err)
		for _, key := range []string{"provisioningState", "etag", "systemData", "networkAcls", "failoverConfiguration", "privateLinkScopedResources"} {
			require.NotContains(t, got.Properties, key)
		}
	})

	// ResourceForUpdate carries only tags and identity, so a description change has
	// to go through another PUT.
	t.Run("Update_reissues_create", func(t *testing.T) {
		before := writeCalls
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testDataCollectionEndpointNativeID,
			DesiredProperties: dataCollectionEndpointDesired("ingestion front door, revised"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, writeCalls)
		require.Equal(t, "ingestion front door, revised", *sent.Properties.Description)
		// Location must ride along: a PUT without it is rejected.
		require.Equal(t, "eastus", *sent.Location)
	})

	t.Run("Delete", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testDataCollectionEndpointNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _ string, _ *armmonitor.DataCollectionEndpointsClientDeleteOptions) (armmonitor.DataCollectionEndpointsClientDeleteResponse, error) {
			return armmonitor.DataCollectionEndpointsClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testDataCollectionEndpointNativeID})
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
		require.Equal(t, []string{testDataCollectionEndpointNativeID}, got.NativeIDs)
	})

	t.Run("List_without_group_is_subscription_wide", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 2)
	})

	t.Run("Read_NotFound", func(t *testing.T) {
		fake.getFn = func(_ context.Context, _, _ string, _ *armmonitor.DataCollectionEndpointsClientGetOptions) (armmonitor.DataCollectionEndpointsClientGetResponse, error) {
			return armmonitor.DataCollectionEndpointsClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testDataCollectionEndpointNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
	})
}
