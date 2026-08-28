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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appservice/armappservice/v5"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testServicePlanNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Web/serverfarms/plan-1"

func newTestServicePlan(api appServicePlansAPI) *ServicePlan {
	return &ServicePlan{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func servicePlanDesired(capacity int, perSiteScaling bool) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":              "plan-1",
		"resourceGroupName": "rg-1",
		"location":          "eastus",
		"kind":              "linux",
		"reserved":          true,
		"perSiteScaling":    perSiteScaling,
		"sku": map[string]any{
			"name":     "B1",
			"tier":     "Basic",
			"capacity": capacity,
		},
	})
	return out
}

func servicePlanResult() armappservice.Plan {
	return armappservice.Plan{
		ID:       to.Ptr(testServicePlanNativeID),
		Name:     to.Ptr("plan-1"),
		Location: to.Ptr("East US"),
		Kind:     to.Ptr("linux"),
		SKU: &armappservice.SKUDescription{
			Name:     to.Ptr("B1"),
			Tier:     to.Ptr("Basic"),
			Capacity: to.Ptr(int32(1)),
		},
		Properties: &armappservice.PlanProperties{
			Reserved:                  to.Ptr(true),
			ZoneRedundant:             to.Ptr(false),
			PerSiteScaling:            to.Ptr(false),
			ElasticScaleEnabled:       to.Ptr(false),
			MaximumElasticWorkerCount: to.Ptr(int32(1)),
		},
		Tags: map[string]*string{"env": to.Ptr("test")},
	}
}

func TestServicePlan_CRUD(t *testing.T) {
	result := servicePlanResult()
	doneResponse := armappservice.PlansClientCreateOrUpdateResponse{Plan: result}

	var sent armappservice.Plan
	fake := &fakeAppServicePlansAPI{
		beginCreateOrUpdateFn: func(_ context.Context, rgName, name string, params armappservice.Plan, _ *armappservice.PlansClientBeginCreateOrUpdateOptions) (*runtime.Poller[armappservice.PlansClientCreateOrUpdateResponse], error) {
			require.Equal(t, "rg-1", rgName)
			require.Equal(t, "plan-1", name)
			sent = params
			return newDonePoller(doneResponse), nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armappservice.PlansClientGetOptions) (armappservice.PlansClientGetResponse, error) {
			return armappservice.PlansClientGetResponse{Plan: result}, nil
		},
		deleteFn: func(_ context.Context, _, _ string, _ *armappservice.PlansClientDeleteOptions) (armappservice.PlansClientDeleteResponse, error) {
			return armappservice.PlansClientDeleteResponse{}, nil
		},
		newListByResourceGroupPagerFn: func(_ string, _ *armappservice.PlansClientListByResourceGroupOptions) *runtime.Pager[armappservice.PlansClientListByResourceGroupResponse] {
			return runtime.NewPager(runtime.PagingHandler[armappservice.PlansClientListByResourceGroupResponse]{
				More: func(_ armappservice.PlansClientListByResourceGroupResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armappservice.PlansClientListByResourceGroupResponse) (armappservice.PlansClientListByResourceGroupResponse, error) {
					return armappservice.PlansClientListByResourceGroupResponse{
						PlanCollection: armappservice.PlanCollection{
							Value: []*armappservice.Plan{{ID: to.Ptr(testServicePlanNativeID)}},
						},
					}, nil
				},
			})
		},
		newListPagerFn: func(_ *armappservice.PlansClientListOptions) *runtime.Pager[armappservice.PlansClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armappservice.PlansClientListResponse]{
				More: func(_ armappservice.PlansClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armappservice.PlansClientListResponse) (armappservice.PlansClientListResponse, error) {
					return armappservice.PlansClientListResponse{
						PlanCollection: armappservice.PlanCollection{
							Value: []*armappservice.Plan{
								{ID: to.Ptr(testServicePlanNativeID)},
								{ID: to.Ptr("/subscriptions/sub-1/resourceGroups/rg-2/providers/Microsoft.Web/serverfarms/plan-2")},
							},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestServicePlan(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "plan-1",
			Properties: servicePlanDesired(1, false),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testServicePlanNativeID, got.ProgressResult.NativeID)

		require.Equal(t, "eastus", *sent.Location)
		require.Equal(t, "linux", *sent.Kind)
		require.Equal(t, "B1", *sent.SKU.Name)
		require.Equal(t, "Basic", *sent.SKU.Tier)
		require.EqualValues(t, 1, *sent.SKU.Capacity)
		require.True(t, *sent.Properties.Reserved)
		require.False(t, *sent.Properties.PerSiteScaling)
	})

	t.Run("Create_requires_sku", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "plan-1", "resourceGroupName": "rg-1", "location": "eastus",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "sku is required")
	})

	t.Run("Create_requires_sku_name", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "plan-1", "resourceGroupName": "rg-1", "location": "eastus",
			"sku": map[string]any{"tier": "Basic"},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "sku.name is required")
	})

	t.Run("Read_round_trips_properties", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testServicePlanNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "plan-1", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		// ARM hands back "East US"; desired state carries the compact form.
		require.Equal(t, "eastus", props["location"])
		require.Equal(t, "linux", props["kind"])
		require.Equal(t, true, props["reserved"])
		require.Equal(t, false, props["perSiteScaling"])
		require.EqualValues(t, 1, props["maximumElasticWorkerCount"])
		sku := props["sku"].(map[string]any)
		require.Equal(t, "B1", sku["name"])
		require.Equal(t, "Basic", sku["tier"])
		require.EqualValues(t, 1, sku["capacity"])
		tags := props["Tags"].([]any)
		require.Len(t, tags, 1)
	})

	t.Run("Update_keeps_native_id", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testServicePlanNativeID,
			DesiredProperties: servicePlanDesired(1, true),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testServicePlanNativeID, got.ProgressResult.NativeID)
		require.True(t, *sent.Properties.PerSiteScaling)
	})

	t.Run("Delete", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testServicePlanNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _ string, _ *armappservice.PlansClientDeleteOptions) (armappservice.PlansClientDeleteResponse, error) {
			return armappservice.PlansClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testServicePlanNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_resource_group", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testServicePlanNativeID}, got.NativeIDs)
	})

	t.Run("List_without_group_is_subscription_wide", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 2)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, _ armappservice.Plan, _ *armappservice.PlansClientBeginCreateOrUpdateOptions) (*runtime.Poller[armappservice.PlansClientCreateOrUpdateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 409}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "plan-1",
			Properties: servicePlanDesired(1, false),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

// An in-flight create must report the ARM ID the plan will end up at, otherwise the
// resource is orphaned when the operation completes.
func TestServicePlan_CreateInProgressPinsNativeID(t *testing.T) {
	fake := &fakeAppServicePlansAPI{
		beginCreateOrUpdateFn: func(_ context.Context, _, _ string, _ armappservice.Plan, _ *armappservice.PlansClientBeginCreateOrUpdateOptions) (*runtime.Poller[armappservice.PlansClientCreateOrUpdateResponse], error) {
			return newInProgressPoller[armappservice.PlansClientCreateOrUpdateResponse](), nil
		},
	}
	got, err := newTestServicePlan(fake).Create(context.Background(), &resource.CreateRequest{
		Label:      "plan-1",
		Properties: servicePlanDesired(1, false),
	})
	require.NoError(t, err)
	require.Equal(t, resource.OperationStatusInProgress, got.ProgressResult.OperationStatus)
	require.Equal(t, testServicePlanNativeID, got.ProgressResult.NativeID)
	require.NotEmpty(t, got.ProgressResult.RequestID)
}

func TestServicePlan_ReadNotFound(t *testing.T) {
	fake := &fakeAppServicePlansAPI{
		getFn: func(_ context.Context, _, _ string, _ *armappservice.PlansClientGetOptions) (armappservice.PlansClientGetResponse, error) {
			return armappservice.PlansClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestServicePlan(fake).Read(context.Background(), &resource.ReadRequest{NativeID: testServicePlanNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

func TestServicePlan_IDParts(t *testing.T) {
	rgName, planName, err := servicePlanIDParts(testServicePlanNativeID)
	require.NoError(t, err)
	require.Equal(t, "rg-1", rgName)
	require.Equal(t, "plan-1", planName)

	_, _, err = servicePlanIDParts("/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Web/sites/app-1")
	require.Error(t, err)
}

// --- Test helpers ---

type fakeAppServicePlansAPI struct {
	beginCreateOrUpdateFn         func(ctx context.Context, rgName, name string, params armappservice.Plan, options *armappservice.PlansClientBeginCreateOrUpdateOptions) (*runtime.Poller[armappservice.PlansClientCreateOrUpdateResponse], error)
	getFn                         func(ctx context.Context, rgName, name string, options *armappservice.PlansClientGetOptions) (armappservice.PlansClientGetResponse, error)
	deleteFn                      func(ctx context.Context, rgName, name string, options *armappservice.PlansClientDeleteOptions) (armappservice.PlansClientDeleteResponse, error)
	newListByResourceGroupPagerFn func(rgName string, options *armappservice.PlansClientListByResourceGroupOptions) *runtime.Pager[armappservice.PlansClientListByResourceGroupResponse]
	newListPagerFn                func(options *armappservice.PlansClientListOptions) *runtime.Pager[armappservice.PlansClientListResponse]
}

func (f *fakeAppServicePlansAPI) BeginCreateOrUpdate(ctx context.Context, rgName string, name string, params armappservice.Plan, options *armappservice.PlansClientBeginCreateOrUpdateOptions) (*runtime.Poller[armappservice.PlansClientCreateOrUpdateResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, rgName, name, params, options)
}

func (f *fakeAppServicePlansAPI) Get(ctx context.Context, rgName string, name string, options *armappservice.PlansClientGetOptions) (armappservice.PlansClientGetResponse, error) {
	return f.getFn(ctx, rgName, name, options)
}

func (f *fakeAppServicePlansAPI) Delete(ctx context.Context, rgName string, name string, options *armappservice.PlansClientDeleteOptions) (armappservice.PlansClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, name, options)
}

func (f *fakeAppServicePlansAPI) NewListByResourceGroupPager(rgName string, options *armappservice.PlansClientListByResourceGroupOptions) *runtime.Pager[armappservice.PlansClientListByResourceGroupResponse] {
	return f.newListByResourceGroupPagerFn(rgName, options)
}

func (f *fakeAppServicePlansAPI) NewListPager(options *armappservice.PlansClientListOptions) *runtime.Pager[armappservice.PlansClientListResponse] {
	return f.newListPagerFn(options)
}
