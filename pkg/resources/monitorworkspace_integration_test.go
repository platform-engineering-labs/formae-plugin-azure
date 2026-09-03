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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/monitor/armmonitorworkspaces"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

// Microsoft.Monitor/accounts, not Microsoft.Insights.
const testMonitorWorkspaceNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Monitor/accounts/amw1"

type fakeMonitorWorkspacesAPI struct {
	createFn      func(ctx context.Context, rgName, name string, body armmonitorworkspaces.AzureMonitorWorkspaceResource, options *armmonitorworkspaces.AzureMonitorWorkspacesClientCreateOrUpdateOptions) (armmonitorworkspaces.AzureMonitorWorkspacesClientCreateOrUpdateResponse, error)
	getFn         func(ctx context.Context, rgName, name string, options *armmonitorworkspaces.AzureMonitorWorkspacesClientGetOptions) (armmonitorworkspaces.AzureMonitorWorkspacesClientGetResponse, error)
	beginDeleteFn func(ctx context.Context, rgName, name string, options *armmonitorworkspaces.AzureMonitorWorkspacesClientBeginDeleteOptions) (*runtime.Poller[armmonitorworkspaces.AzureMonitorWorkspacesClientDeleteResponse], error)
	listByGroupFn func(rgName string, options *armmonitorworkspaces.AzureMonitorWorkspacesClientListByResourceGroupOptions) *runtime.Pager[armmonitorworkspaces.AzureMonitorWorkspacesClientListByResourceGroupResponse]
	listBySubFn   func(options *armmonitorworkspaces.AzureMonitorWorkspacesClientListBySubscriptionOptions) *runtime.Pager[armmonitorworkspaces.AzureMonitorWorkspacesClientListBySubscriptionResponse]
}

func (f *fakeMonitorWorkspacesAPI) CreateOrUpdate(ctx context.Context, rgName, name string, body armmonitorworkspaces.AzureMonitorWorkspaceResource, options *armmonitorworkspaces.AzureMonitorWorkspacesClientCreateOrUpdateOptions) (armmonitorworkspaces.AzureMonitorWorkspacesClientCreateOrUpdateResponse, error) {
	return f.createFn(ctx, rgName, name, body, options)
}

func (f *fakeMonitorWorkspacesAPI) Get(ctx context.Context, rgName, name string, options *armmonitorworkspaces.AzureMonitorWorkspacesClientGetOptions) (armmonitorworkspaces.AzureMonitorWorkspacesClientGetResponse, error) {
	return f.getFn(ctx, rgName, name, options)
}

func (f *fakeMonitorWorkspacesAPI) BeginDelete(ctx context.Context, rgName, name string, options *armmonitorworkspaces.AzureMonitorWorkspacesClientBeginDeleteOptions) (*runtime.Poller[armmonitorworkspaces.AzureMonitorWorkspacesClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, name, options)
}

func (f *fakeMonitorWorkspacesAPI) NewListByResourceGroupPager(rgName string, options *armmonitorworkspaces.AzureMonitorWorkspacesClientListByResourceGroupOptions) *runtime.Pager[armmonitorworkspaces.AzureMonitorWorkspacesClientListByResourceGroupResponse] {
	return f.listByGroupFn(rgName, options)
}

func (f *fakeMonitorWorkspacesAPI) NewListBySubscriptionPager(options *armmonitorworkspaces.AzureMonitorWorkspacesClientListBySubscriptionOptions) *runtime.Pager[armmonitorworkspaces.AzureMonitorWorkspacesClientListBySubscriptionResponse] {
	return f.listBySubFn(options)
}

func newTestMonitorWorkspace(api monitorWorkspacesAPI) *MonitorWorkspace {
	return &MonitorWorkspace{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func monitorWorkspaceDesired(publicNetworkAccess string) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":                "amw1",
		"resourceGroupName":   "rg-1",
		"location":            "eastus",
		"publicNetworkAccess": publicNetworkAccess,
		"Tags":                []any{map[string]any{"Key": "env", "Value": "test"}},
	})
	return out
}

func TestMonitorWorkspace_CRUD(t *testing.T) {
	workspaceResult := armmonitorworkspaces.AzureMonitorWorkspaceResource{
		ID:       to.Ptr(testMonitorWorkspaceNativeID),
		Name:     to.Ptr("amw1"),
		Location: to.Ptr("East US"),
		Properties: &armmonitorworkspaces.AzureMonitorWorkspace{
			PublicNetworkAccess: to.Ptr(armmonitorworkspaces.PublicNetworkAccessEnabled),
			AccountID:           to.Ptr("2b0f1e1e-0000-4000-8000-abcdefabcdef"),
			ProvisioningState:   to.Ptr(armmonitorworkspaces.ResourceProvisioningStateSucceeded),
			Metrics: &armmonitorworkspaces.AzureMonitorWorkspaceMetrics{
				PrometheusQueryEndpoint: to.Ptr("https://amw1-abcd.eastus.prometheus.monitor.azure.com"),
				InternalID:              to.Ptr("system-only"),
			},
			// The service stands up a data collection endpoint and rule alongside the
			// workspace, in a resource group it manages itself.
			DefaultIngestionSettings: &armmonitorworkspaces.AzureMonitorWorkspaceDefaultIngestionSettings{
				DataCollectionEndpointResourceID: to.Ptr("/subscriptions/sub-1/resourceGroups/MA_amw1_eastus_managed/providers/Microsoft.Insights/dataCollectionEndpoints/amw1"),
				DataCollectionRuleResourceID:     to.Ptr("/subscriptions/sub-1/resourceGroups/MA_amw1_eastus_managed/providers/Microsoft.Insights/dataCollectionRules/amw1"),
				DataCollectionRuleImmutableID:    to.Ptr("dcr-0123456789abcdef"),
				IngestionEndpoints: &armmonitorworkspaces.IngestionEndpoints{
					Metrics: to.Ptr("https://amw1-abcd.eastus.ingest.monitor.azure.com"),
				},
			},
		},
		Tags: map[string]*string{"env": to.Ptr("test")},
		Etag: to.Ptr("\"etag\""),
	}

	var sent armmonitorworkspaces.AzureMonitorWorkspaceResource
	writeCalls := 0
	deleteCalls := 0
	fake := &fakeMonitorWorkspacesAPI{
		createFn: func(_ context.Context, rgName, name string, body armmonitorworkspaces.AzureMonitorWorkspaceResource, _ *armmonitorworkspaces.AzureMonitorWorkspacesClientCreateOrUpdateOptions) (armmonitorworkspaces.AzureMonitorWorkspacesClientCreateOrUpdateResponse, error) {
			require.Equal(t, "rg-1", rgName)
			require.Equal(t, "amw1", name)
			sent = body
			writeCalls++
			return armmonitorworkspaces.AzureMonitorWorkspacesClientCreateOrUpdateResponse{AzureMonitorWorkspaceResource: workspaceResult}, nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armmonitorworkspaces.AzureMonitorWorkspacesClientGetOptions) (armmonitorworkspaces.AzureMonitorWorkspacesClientGetResponse, error) {
			return armmonitorworkspaces.AzureMonitorWorkspacesClientGetResponse{AzureMonitorWorkspaceResource: workspaceResult}, nil
		},
		beginDeleteFn: func(_ context.Context, _, _ string, _ *armmonitorworkspaces.AzureMonitorWorkspacesClientBeginDeleteOptions) (*runtime.Poller[armmonitorworkspaces.AzureMonitorWorkspacesClientDeleteResponse], error) {
			deleteCalls++
			return newDonePoller(armmonitorworkspaces.AzureMonitorWorkspacesClientDeleteResponse{}), nil
		},
		listByGroupFn: func(_ string, _ *armmonitorworkspaces.AzureMonitorWorkspacesClientListByResourceGroupOptions) *runtime.Pager[armmonitorworkspaces.AzureMonitorWorkspacesClientListByResourceGroupResponse] {
			return runtime.NewPager(runtime.PagingHandler[armmonitorworkspaces.AzureMonitorWorkspacesClientListByResourceGroupResponse]{
				More: func(_ armmonitorworkspaces.AzureMonitorWorkspacesClientListByResourceGroupResponse) bool {
					return false
				},
				Fetcher: func(_ context.Context, _ *armmonitorworkspaces.AzureMonitorWorkspacesClientListByResourceGroupResponse) (armmonitorworkspaces.AzureMonitorWorkspacesClientListByResourceGroupResponse, error) {
					return armmonitorworkspaces.AzureMonitorWorkspacesClientListByResourceGroupResponse{
						AzureMonitorWorkspaceResourceListResult: armmonitorworkspaces.AzureMonitorWorkspaceResourceListResult{
							Value: []*armmonitorworkspaces.AzureMonitorWorkspaceResource{
								{ID: to.Ptr(testMonitorWorkspaceNativeID)},
								// A nil entry must not panic the walk.
								nil,
							},
						},
					}, nil
				},
			})
		},
		listBySubFn: func(_ *armmonitorworkspaces.AzureMonitorWorkspacesClientListBySubscriptionOptions) *runtime.Pager[armmonitorworkspaces.AzureMonitorWorkspacesClientListBySubscriptionResponse] {
			return runtime.NewPager(runtime.PagingHandler[armmonitorworkspaces.AzureMonitorWorkspacesClientListBySubscriptionResponse]{
				More: func(_ armmonitorworkspaces.AzureMonitorWorkspacesClientListBySubscriptionResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armmonitorworkspaces.AzureMonitorWorkspacesClientListBySubscriptionResponse) (armmonitorworkspaces.AzureMonitorWorkspacesClientListBySubscriptionResponse, error) {
					return armmonitorworkspaces.AzureMonitorWorkspacesClientListBySubscriptionResponse{
						AzureMonitorWorkspaceResourceListResult: armmonitorworkspaces.AzureMonitorWorkspaceResourceListResult{
							Value: []*armmonitorworkspaces.AzureMonitorWorkspaceResource{
								{ID: to.Ptr(testMonitorWorkspaceNativeID)},
								{ID: to.Ptr("/subscriptions/sub-1/resourceGroups/rg-2/providers/Microsoft.Monitor/accounts/amw2")},
							},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestMonitorWorkspace(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "amw1", Properties: monitorWorkspaceDesired("Enabled"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testMonitorWorkspaceNativeID, got.ProgressResult.NativeID)

		require.Equal(t, "eastus", *sent.Location)
		require.Equal(t, armmonitorworkspaces.PublicNetworkAccessEnabled, *sent.Properties.PublicNetworkAccess)
		require.Equal(t, "test", *sent.Tags["env"])
	})

	t.Run("Create_requires_location", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "amw1", "resourceGroupName": "rg-1"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "location is required")
	})

	t.Run("Create_omits_unset_public_network_access", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "amw1", "resourceGroupName": "rg-1", "location": "eastus",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.Nil(t, sent.Properties.PublicNetworkAccess)
	})

	t.Run("Create_failure_carries_the_provider_error", func(t *testing.T) {
		fake.createFn = func(_ context.Context, _, _ string, _ armmonitorworkspaces.AzureMonitorWorkspaceResource, _ *armmonitorworkspaces.AzureMonitorWorkspacesClientCreateOrUpdateOptions) (armmonitorworkspaces.AzureMonitorWorkspacesClientCreateOrUpdateResponse, error) {
			return armmonitorworkspaces.AzureMonitorWorkspacesClientCreateOrUpdateResponse{}, &azcore.ResponseError{
				StatusCode: 409, ErrorCode: "Conflict",
			}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "amw1", Properties: monitorWorkspaceDesired("Enabled"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.Equal(t, resource.OperationErrorCodeResourceConflict, got.ProgressResult.ErrorCode)
		require.Contains(t, got.ProgressResult.StatusMessage, "Conflict")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testMonitorWorkspaceNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "amw1", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		// ARM returns "East US"; read must normalise or desired state drifts.
		require.Equal(t, "eastus", props["location"])
		require.Equal(t, "Enabled", props["publicNetworkAccess"])
		require.Equal(t, "2b0f1e1e-0000-4000-8000-abcdefabcdef", props["accountId"])
		require.Contains(t, props["prometheusQueryEndpoint"], "prometheus.monitor.azure.com")
		require.Contains(t, props["metricsIngestionEndpoint"], "ingest.monitor.azure.com")
		require.Contains(t, props["defaultDataCollectionEndpointId"], "/dataCollectionEndpoints/amw1")
		require.Contains(t, props["defaultDataCollectionRuleId"], "/dataCollectionRules/amw1")
	})

	t.Run("Read_drops_service_state", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testMonitorWorkspaceNativeID})
		require.NoError(t, err)
		for _, key := range []string{"provisioningState", "etag", "systemData", "internalId", "privateEndpointConnections"} {
			require.NotContains(t, got.Properties, key)
		}
	})

	t.Run("Update_reissues_create", func(t *testing.T) {
		fake.createFn = func(_ context.Context, _, _ string, body armmonitorworkspaces.AzureMonitorWorkspaceResource, _ *armmonitorworkspaces.AzureMonitorWorkspacesClientCreateOrUpdateOptions) (armmonitorworkspaces.AzureMonitorWorkspacesClientCreateOrUpdateResponse, error) {
			sent = body
			writeCalls++
			return armmonitorworkspaces.AzureMonitorWorkspacesClientCreateOrUpdateResponse{AzureMonitorWorkspaceResource: workspaceResult}, nil
		}
		before := writeCalls
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testMonitorWorkspaceNativeID,
			DesiredProperties: monitorWorkspaceDesired("Disabled"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, writeCalls)
		require.Equal(t, armmonitorworkspaces.PublicNetworkAccessDisabled, *sent.Properties.PublicNetworkAccess)
		// Location must ride along: a PUT without it is rejected.
		require.Equal(t, "eastus", *sent.Location)
	})

	// The delete is an LRO even though the writes are synchronous.
	t.Run("Delete", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testMonitorWorkspaceNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
	})

	t.Run("PendingDeleteReportsInProgress", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _ string, _ *armmonitorworkspaces.AzureMonitorWorkspacesClientBeginDeleteOptions) (*runtime.Poller[armmonitorworkspaces.AzureMonitorWorkspacesClientDeleteResponse], error) {
			return newPendingPoller[armmonitorworkspaces.AzureMonitorWorkspacesClientDeleteResponse](), nil
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testMonitorWorkspaceNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusInProgress, got.ProgressResult.OperationStatus)

		reqID, err := decodeLROStatus(got.ProgressResult.RequestID)
		require.NoError(t, err)
		require.Equal(t, lroOpDelete, reqID.OperationType)
		require.Equal(t, testMonitorWorkspaceNativeID, reqID.NativeID)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _ string, _ *armmonitorworkspaces.AzureMonitorWorkspacesClientBeginDeleteOptions) (*runtime.Poller[armmonitorworkspaces.AzureMonitorWorkspacesClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testMonitorWorkspaceNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_resource_group", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testMonitorWorkspaceNativeID}, got.NativeIDs)
	})

	t.Run("List_without_group_is_subscription_wide", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 2)
	})

	t.Run("Read_NotFound", func(t *testing.T) {
		fake.getFn = func(_ context.Context, _, _ string, _ *armmonitorworkspaces.AzureMonitorWorkspacesClientGetOptions) (armmonitorworkspaces.AzureMonitorWorkspacesClientGetResponse, error) {
			return armmonitorworkspaces.AzureMonitorWorkspacesClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testMonitorWorkspaceNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
	})
}
