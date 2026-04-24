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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerservice/armcontainerservice/v4"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testMCNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.ContainerService/managedClusters/aks-1/maintenanceConfigurations/default"

func TestMaintenanceConfiguration_CRUD(t *testing.T) {
	day := armcontainerservice.WeekDayTuesday
	fake := &fakeMaintenanceConfigurationsAPI{
		createOrUpdateFn: func(_ context.Context, _, _, _ string, _ armcontainerservice.MaintenanceConfiguration, _ *armcontainerservice.MaintenanceConfigurationsClientCreateOrUpdateOptions) (armcontainerservice.MaintenanceConfigurationsClientCreateOrUpdateResponse, error) {
			return armcontainerservice.MaintenanceConfigurationsClientCreateOrUpdateResponse{
				MaintenanceConfiguration: armcontainerservice.MaintenanceConfiguration{
					ID:   to.Ptr(testMCNativeID),
					Name: to.Ptr("default"),
					Properties: &armcontainerservice.MaintenanceConfigurationProperties{
						TimeInWeek: []*armcontainerservice.TimeInWeek{
							{Day: &day, HourSlots: []*int32{to.Ptr(int32(1))}},
						},
					},
				},
			}, nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ *armcontainerservice.MaintenanceConfigurationsClientGetOptions) (armcontainerservice.MaintenanceConfigurationsClientGetResponse, error) {
			return armcontainerservice.MaintenanceConfigurationsClientGetResponse{
				MaintenanceConfiguration: armcontainerservice.MaintenanceConfiguration{
					ID:         to.Ptr(testMCNativeID),
					Name:       to.Ptr("default"),
					Properties: &armcontainerservice.MaintenanceConfigurationProperties{},
				},
			}, nil
		},
		deleteFn: func(_ context.Context, _, _, _ string, _ *armcontainerservice.MaintenanceConfigurationsClientDeleteOptions) (armcontainerservice.MaintenanceConfigurationsClientDeleteResponse, error) {
			return armcontainerservice.MaintenanceConfigurationsClientDeleteResponse{}, nil
		},
		listFn: func(_, _ string, _ *armcontainerservice.MaintenanceConfigurationsClientListByManagedClusterOptions) *runtime.Pager[armcontainerservice.MaintenanceConfigurationsClientListByManagedClusterResponse] {
			return runtime.NewPager(runtime.PagingHandler[armcontainerservice.MaintenanceConfigurationsClientListByManagedClusterResponse]{
				More: func(_ armcontainerservice.MaintenanceConfigurationsClientListByManagedClusterResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armcontainerservice.MaintenanceConfigurationsClientListByManagedClusterResponse) (armcontainerservice.MaintenanceConfigurationsClientListByManagedClusterResponse, error) {
					return armcontainerservice.MaintenanceConfigurationsClientListByManagedClusterResponse{
						MaintenanceConfigurationListResult: armcontainerservice.MaintenanceConfigurationListResult{
							Value: []*armcontainerservice.MaintenanceConfiguration{{ID: to.Ptr(testMCNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestMaintenanceConfiguration(fake)

	t.Run("Create", func(t *testing.T) {
		props, _ := json.Marshal(map[string]interface{}{
			"resourceGroupName": "rg-1", "clusterName": "aks-1", "name": "default",
			"timeInWeek": []map[string]interface{}{{"day": "Tuesday", "hourSlots": []float64{1}}},
		})
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testMCNativeID, got.ProgressResult.NativeID)
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testMCNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
		var props map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "default", props["name"])
	})

	t.Run("Delete", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testMCNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _, _ string, _ *armcontainerservice.MaintenanceConfigurationsClientDeleteOptions) (armcontainerservice.MaintenanceConfigurationsClientDeleteResponse, error) {
			return armcontainerservice.MaintenanceConfigurationsClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testMCNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "clusterName": "aks-1"},
		})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 1)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.createOrUpdateFn = func(_ context.Context, _, _, _ string, _ armcontainerservice.MaintenanceConfiguration, _ *armcontainerservice.MaintenanceConfigurationsClientCreateOrUpdateOptions) (armcontainerservice.MaintenanceConfigurationsClientCreateOrUpdateResponse, error) {
			return armcontainerservice.MaintenanceConfigurationsClientCreateOrUpdateResponse{}, &azcore.ResponseError{StatusCode: 403}
		}
		props, _ := json.Marshal(map[string]interface{}{"resourceGroupName": "rg-1", "clusterName": "aks-1", "name": "x"})
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

// --- Test helpers ---

func newTestMaintenanceConfiguration(api maintenanceConfigurationsAPI) *MaintenanceConfiguration {
	return &MaintenanceConfiguration{api: api, config: nil}
}

type fakeMaintenanceConfigurationsAPI struct {
	createOrUpdateFn func(ctx context.Context, rgName, clusterName, configName string, params armcontainerservice.MaintenanceConfiguration, opts *armcontainerservice.MaintenanceConfigurationsClientCreateOrUpdateOptions) (armcontainerservice.MaintenanceConfigurationsClientCreateOrUpdateResponse, error)
	getFn            func(ctx context.Context, rgName, clusterName, configName string, opts *armcontainerservice.MaintenanceConfigurationsClientGetOptions) (armcontainerservice.MaintenanceConfigurationsClientGetResponse, error)
	deleteFn         func(ctx context.Context, rgName, clusterName, configName string, opts *armcontainerservice.MaintenanceConfigurationsClientDeleteOptions) (armcontainerservice.MaintenanceConfigurationsClientDeleteResponse, error)
	listFn           func(rgName, clusterName string, opts *armcontainerservice.MaintenanceConfigurationsClientListByManagedClusterOptions) *runtime.Pager[armcontainerservice.MaintenanceConfigurationsClientListByManagedClusterResponse]
}

func (f *fakeMaintenanceConfigurationsAPI) CreateOrUpdate(ctx context.Context, rgName, clusterName, configName string, params armcontainerservice.MaintenanceConfiguration, opts *armcontainerservice.MaintenanceConfigurationsClientCreateOrUpdateOptions) (armcontainerservice.MaintenanceConfigurationsClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, clusterName, configName, params, opts)
}

func (f *fakeMaintenanceConfigurationsAPI) Get(ctx context.Context, rgName, clusterName, configName string, opts *armcontainerservice.MaintenanceConfigurationsClientGetOptions) (armcontainerservice.MaintenanceConfigurationsClientGetResponse, error) {
	return f.getFn(ctx, rgName, clusterName, configName, opts)
}

func (f *fakeMaintenanceConfigurationsAPI) Delete(ctx context.Context, rgName, clusterName, configName string, opts *armcontainerservice.MaintenanceConfigurationsClientDeleteOptions) (armcontainerservice.MaintenanceConfigurationsClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, clusterName, configName, opts)
}

func (f *fakeMaintenanceConfigurationsAPI) NewListByManagedClusterPager(rgName, clusterName string, opts *armcontainerservice.MaintenanceConfigurationsClientListByManagedClusterOptions) *runtime.Pager[armcontainerservice.MaintenanceConfigurationsClientListByManagedClusterResponse] {
	return f.listFn(rgName, clusterName, opts)
}
