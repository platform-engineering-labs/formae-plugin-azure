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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/operationalinsights/armoperationalinsights"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testLogAnalyticsClusterNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.OperationalInsights/clusters/lac1"

type fakeLogAnalyticsClustersAPI struct {
	beginCreateOrUpdateFn         func(ctx context.Context, rgName, clusterName string, params armoperationalinsights.Cluster, options *armoperationalinsights.ClustersClientBeginCreateOrUpdateOptions) (*runtime.Poller[armoperationalinsights.ClustersClientCreateOrUpdateResponse], error)
	getFn                         func(ctx context.Context, rgName, clusterName string, options *armoperationalinsights.ClustersClientGetOptions) (armoperationalinsights.ClustersClientGetResponse, error)
	beginUpdateFn                 func(ctx context.Context, rgName, clusterName string, params armoperationalinsights.ClusterPatch, options *armoperationalinsights.ClustersClientBeginUpdateOptions) (*runtime.Poller[armoperationalinsights.ClustersClientUpdateResponse], error)
	beginDeleteFn                 func(ctx context.Context, rgName, clusterName string, options *armoperationalinsights.ClustersClientBeginDeleteOptions) (*runtime.Poller[armoperationalinsights.ClustersClientDeleteResponse], error)
	newListPagerFn                func(options *armoperationalinsights.ClustersClientListOptions) *runtime.Pager[armoperationalinsights.ClustersClientListResponse]
	newListByResourceGroupPagerFn func(rgName string, options *armoperationalinsights.ClustersClientListByResourceGroupOptions) *runtime.Pager[armoperationalinsights.ClustersClientListByResourceGroupResponse]
}

func (f *fakeLogAnalyticsClustersAPI) BeginCreateOrUpdate(ctx context.Context, rgName, clusterName string, params armoperationalinsights.Cluster, options *armoperationalinsights.ClustersClientBeginCreateOrUpdateOptions) (*runtime.Poller[armoperationalinsights.ClustersClientCreateOrUpdateResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, rgName, clusterName, params, options)
}

func (f *fakeLogAnalyticsClustersAPI) Get(ctx context.Context, rgName, clusterName string, options *armoperationalinsights.ClustersClientGetOptions) (armoperationalinsights.ClustersClientGetResponse, error) {
	return f.getFn(ctx, rgName, clusterName, options)
}

func (f *fakeLogAnalyticsClustersAPI) BeginUpdate(ctx context.Context, rgName, clusterName string, params armoperationalinsights.ClusterPatch, options *armoperationalinsights.ClustersClientBeginUpdateOptions) (*runtime.Poller[armoperationalinsights.ClustersClientUpdateResponse], error) {
	return f.beginUpdateFn(ctx, rgName, clusterName, params, options)
}

func (f *fakeLogAnalyticsClustersAPI) BeginDelete(ctx context.Context, rgName, clusterName string, options *armoperationalinsights.ClustersClientBeginDeleteOptions) (*runtime.Poller[armoperationalinsights.ClustersClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, clusterName, options)
}

func (f *fakeLogAnalyticsClustersAPI) NewListPager(options *armoperationalinsights.ClustersClientListOptions) *runtime.Pager[armoperationalinsights.ClustersClientListResponse] {
	return f.newListPagerFn(options)
}

func (f *fakeLogAnalyticsClustersAPI) NewListByResourceGroupPager(rgName string, options *armoperationalinsights.ClustersClientListByResourceGroupOptions) *runtime.Pager[armoperationalinsights.ClustersClientListByResourceGroupResponse] {
	return f.newListByResourceGroupPagerFn(rgName, options)
}

func newTestLogAnalyticsCluster(api logAnalyticsClustersAPI) *LogAnalyticsCluster {
	return &LogAnalyticsCluster{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func logAnalyticsClusterDesired(tagValue string) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":              "lac1",
		"location":          "eastus",
		"resourceGroupName": "rg-1",
		"sku": map[string]any{
			"name":     "CapacityReservation",
			"capacity": 500,
		},
		"billingType":               "Cluster",
		"isDoubleEncryptionEnabled": true,
		"Tags":                      []any{map[string]any{"Key": "purpose", "Value": tagValue}},
	})
	return out
}

func TestLogAnalyticsCluster_CRUD(t *testing.T) {
	clusterResult := armoperationalinsights.Cluster{
		ID:       to.Ptr(testLogAnalyticsClusterNativeID),
		Name:     to.Ptr("lac1"),
		Location: to.Ptr("East US"),
		SKU: &armoperationalinsights.ClusterSKU{
			Name:     to.Ptr(armoperationalinsights.ClusterSKUNameEnumCapacityReservation),
			Capacity: to.Ptr(armoperationalinsights.CapacityFiveHundred),
		},
		Properties: &armoperationalinsights.ClusterProperties{
			BillingType:                to.Ptr(armoperationalinsights.BillingTypeCluster),
			IsDoubleEncryptionEnabled:  to.Ptr(true),
			IsAvailabilityZonesEnabled: to.Ptr(true),
			// Service state, and ARM's back-reference to workspaces that linked
			// themselves in. None of it is modelled.
			ClusterID:         to.Ptr("11111111-2222-3333-4444-555555555555"),
			CreatedDate:       to.Ptr("Thu, 21 Aug 2026 12:00:00 GMT"),
			LastModifiedDate:  to.Ptr("Thu, 21 Aug 2026 15:00:00 GMT"),
			ProvisioningState: to.Ptr(armoperationalinsights.ClusterEntityStatusSucceeded),
			AssociatedWorkspaces: []*armoperationalinsights.AssociatedWorkspace{
				{WorkspaceName: to.Ptr("ws1")},
			},
			CapacityReservationProperties: &armoperationalinsights.CapacityReservationProperties{
				MinCapacity: to.Ptr(int64(500)),
			},
		},
		Tags: map[string]*string{"purpose": to.Ptr("conformance")},
	}

	var sentCreate armoperationalinsights.Cluster
	var sentPatch armoperationalinsights.ClusterPatch
	deleteCalls := 0
	fake := &fakeLogAnalyticsClustersAPI{
		beginCreateOrUpdateFn: func(_ context.Context, rgName, clusterName string, params armoperationalinsights.Cluster, _ *armoperationalinsights.ClustersClientBeginCreateOrUpdateOptions) (*runtime.Poller[armoperationalinsights.ClustersClientCreateOrUpdateResponse], error) {
			require.Equal(t, "rg-1", rgName)
			require.Equal(t, "lac1", clusterName)
			sentCreate = params
			return newDonePoller(armoperationalinsights.ClustersClientCreateOrUpdateResponse{Cluster: clusterResult}), nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armoperationalinsights.ClustersClientGetOptions) (armoperationalinsights.ClustersClientGetResponse, error) {
			return armoperationalinsights.ClustersClientGetResponse{Cluster: clusterResult}, nil
		},
		beginUpdateFn: func(_ context.Context, _, _ string, params armoperationalinsights.ClusterPatch, _ *armoperationalinsights.ClustersClientBeginUpdateOptions) (*runtime.Poller[armoperationalinsights.ClustersClientUpdateResponse], error) {
			sentPatch = params
			return newDonePoller(armoperationalinsights.ClustersClientUpdateResponse{Cluster: clusterResult}), nil
		},
		beginDeleteFn: func(_ context.Context, _, _ string, _ *armoperationalinsights.ClustersClientBeginDeleteOptions) (*runtime.Poller[armoperationalinsights.ClustersClientDeleteResponse], error) {
			deleteCalls++
			return newDonePoller(armoperationalinsights.ClustersClientDeleteResponse{}), nil
		},
		newListPagerFn: func(_ *armoperationalinsights.ClustersClientListOptions) *runtime.Pager[armoperationalinsights.ClustersClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armoperationalinsights.ClustersClientListResponse]{
				More: func(_ armoperationalinsights.ClustersClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armoperationalinsights.ClustersClientListResponse) (armoperationalinsights.ClustersClientListResponse, error) {
					return armoperationalinsights.ClustersClientListResponse{
						ClusterListResult: armoperationalinsights.ClusterListResult{
							Value: []*armoperationalinsights.Cluster{
								{ID: to.Ptr(testLogAnalyticsClusterNativeID)},
								{ID: to.Ptr("/subscriptions/sub-1/resourceGroups/rg-2/providers/Microsoft.OperationalInsights/clusters/lac2")},
								// A nil entry must not panic the walk.
								nil,
							},
						},
					}, nil
				},
			})
		},
		newListByResourceGroupPagerFn: func(_ string, _ *armoperationalinsights.ClustersClientListByResourceGroupOptions) *runtime.Pager[armoperationalinsights.ClustersClientListByResourceGroupResponse] {
			return runtime.NewPager(runtime.PagingHandler[armoperationalinsights.ClustersClientListByResourceGroupResponse]{
				More: func(_ armoperationalinsights.ClustersClientListByResourceGroupResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armoperationalinsights.ClustersClientListByResourceGroupResponse) (armoperationalinsights.ClustersClientListByResourceGroupResponse, error) {
					return armoperationalinsights.ClustersClientListByResourceGroupResponse{
						ClusterListResult: armoperationalinsights.ClusterListResult{
							Value: []*armoperationalinsights.Cluster{{ID: to.Ptr(testLogAnalyticsClusterNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestLogAnalyticsCluster(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "lac1", Properties: logAnalyticsClusterDesired("conformance"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testLogAnalyticsClusterNativeID, got.ProgressResult.NativeID)

		require.Equal(t, "eastus", *sentCreate.Location)
		require.Equal(t, armoperationalinsights.ClusterSKUNameEnumCapacityReservation, *sentCreate.SKU.Name)
		require.Equal(t, armoperationalinsights.CapacityFiveHundred, *sentCreate.SKU.Capacity)
		require.Equal(t, armoperationalinsights.BillingTypeCluster, *sentCreate.Properties.BillingType)
		require.True(t, *sentCreate.Properties.IsDoubleEncryptionEnabled)
		// Not declared, so not sent: the service picks it per region.
		require.Nil(t, sentCreate.Properties.IsAvailabilityZonesEnabled)
		require.Equal(t, "conformance", *sentCreate.Tags["purpose"])
	})

	// The capacity reservation is the whole resource; there is no default to fall
	// back on, so the handler refuses rather than sending a body ARM rejects.
	t.Run("Create_requires_sku_capacity", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "lac1", "location": "eastus", "resourceGroupName": "rg-1",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "sku.capacity is required")
	})

	t.Run("Create_requires_location", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "lac1", "resourceGroupName": "rg-1",
			"sku": map[string]any{"capacity": 500},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "location is required")
	})

	// Provisioning runs for hours, so the in-progress result has to pin the ID ARM
	// will finally assign and say why it is taking so long.
	t.Run("Create_in_progress_pins_the_expected_native_id", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, _ armoperationalinsights.Cluster, _ *armoperationalinsights.ClustersClientBeginCreateOrUpdateOptions) (*runtime.Poller[armoperationalinsights.ClustersClientCreateOrUpdateResponse], error) {
			return newInProgressPoller[armoperationalinsights.ClustersClientCreateOrUpdateResponse](), nil
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "lac1", Properties: logAnalyticsClusterDesired("conformance"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusInProgress, got.ProgressResult.OperationStatus)
		require.Equal(t, testLogAnalyticsClusterNativeID, got.ProgressResult.NativeID)
		require.Contains(t, got.ProgressResult.StatusMessage, "1-3 hours")

		reqID, err := decodeLROStatus(got.ProgressResult.RequestID)
		require.NoError(t, err)
		require.Equal(t, lroOpCreate, reqID.OperationType)
		require.Equal(t, testLogAnalyticsClusterNativeID, reqID.NativeID)

		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, params armoperationalinsights.Cluster, _ *armoperationalinsights.ClustersClientBeginCreateOrUpdateOptions) (*runtime.Poller[armoperationalinsights.ClustersClientCreateOrUpdateResponse], error) {
			sentCreate = params
			return newDonePoller(armoperationalinsights.ClustersClientCreateOrUpdateResponse{Cluster: clusterResult}), nil
		}
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testLogAnalyticsClusterNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
		require.Equal(t, ResourceTypeLogAnalyticsCluster, got.ResourceType)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "lac1", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		// "East US" from the wire has to normalise to the region slug a forma
		// declares, or every sync drifts.
		require.Equal(t, "eastus", props["location"])
		require.Equal(t, map[string]any{"name": "CapacityReservation", "capacity": float64(500)}, props["sku"])
		require.Equal(t, "Cluster", props["billingType"])
		require.Equal(t, true, props["isDoubleEncryptionEnabled"])
		require.Equal(t, true, props["isAvailabilityZonesEnabled"])
	})

	t.Run("Read_drops_service_state", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testLogAnalyticsClusterNativeID})
		require.NoError(t, err)
		for _, key := range []string{"clusterId", "createdDate", "lastModifiedDate", "provisioningState", "associatedWorkspaces", "capacityReservationProperties"} {
			require.NotContains(t, got.Properties, key)
		}
	})

	// ClusterPatch reaches only the billing type, the SKU and the tags.
	t.Run("Update_sends_a_cluster_patch", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testLogAnalyticsClusterNativeID,
			DesiredProperties: logAnalyticsClusterDesired("conformance-updated"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, armoperationalinsights.CapacityFiveHundred, *sentPatch.SKU.Capacity)
		require.Equal(t, armoperationalinsights.BillingTypeCluster, *sentPatch.Properties.BillingType)
		require.Equal(t, "conformance-updated", *sentPatch.Tags["purpose"])
	})

	t.Run("Delete", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testLogAnalyticsClusterNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
	})

	t.Run("Delete_in_progress_reports_a_resume_token", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _ string, _ *armoperationalinsights.ClustersClientBeginDeleteOptions) (*runtime.Poller[armoperationalinsights.ClustersClientDeleteResponse], error) {
			return newInProgressPoller[armoperationalinsights.ClustersClientDeleteResponse](), nil
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testLogAnalyticsClusterNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusInProgress, got.ProgressResult.OperationStatus)
		reqID, err := decodeLROStatus(got.ProgressResult.RequestID)
		require.NoError(t, err)
		require.Equal(t, lroOpDelete, reqID.OperationType)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _ string, _ *armoperationalinsights.ClustersClientBeginDeleteOptions) (*runtime.Poller[armoperationalinsights.ClustersClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testLogAnalyticsClusterNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Status_rejects_an_unknown_operation", func(t *testing.T) {
		reqID, err := encodeLROStart("nonsense", "token", testLogAnalyticsClusterNativeID)
		require.NoError(t, err)
		_, err = prov.Status(context.Background(), &resource.StatusRequest{RequestID: reqID})
		require.ErrorContains(t, err, "unknown operation type")
	})

	t.Run("List_by_resource_group", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testLogAnalyticsClusterNativeID}, got.NativeIDs)
	})

	t.Run("List_falls_back_to_the_subscription", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 2)
	})

	t.Run("Read_NotFound", func(t *testing.T) {
		fake.getFn = func(_ context.Context, _, _ string, _ *armoperationalinsights.ClustersClientGetOptions) (armoperationalinsights.ClustersClientGetResponse, error) {
			return armoperationalinsights.ClustersClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testLogAnalyticsClusterNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
	})

	// A quota refusal is the likeliest live failure here, and its reason must
	// survive into the progress result.
	t.Run("Create_failure_reports_the_provider_error", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, _ armoperationalinsights.Cluster, _ *armoperationalinsights.ClustersClientBeginCreateOrUpdateOptions) (*runtime.Poller[armoperationalinsights.ClustersClientCreateOrUpdateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 400}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "lac1", Properties: logAnalyticsClusterDesired("conformance"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.Equal(t, resource.OperationErrorCodeInvalidRequest, got.ProgressResult.ErrorCode)
		require.NotEmpty(t, got.ProgressResult.StatusMessage)
	})
}
