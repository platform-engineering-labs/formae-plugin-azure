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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v5"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testPPGNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Compute/proximityPlacementGroups/ppg-1"

func testProximityPlacementGroupModel() armcompute.ProximityPlacementGroup {
	return armcompute.ProximityPlacementGroup{
		ID:       to.Ptr(testPPGNativeID),
		Name:     to.Ptr("ppg-1"),
		Location: to.Ptr("eastus"),
		Properties: &armcompute.ProximityPlacementGroupProperties{
			ProximityPlacementGroupType: to.Ptr(armcompute.ProximityPlacementGroupTypeStandard),
			Intent: &armcompute.ProximityPlacementGroupPropertiesIntent{
				VMSizes: []*string{to.Ptr("Standard_B1s")},
			},
		},
		Zones: []*string{to.Ptr("1")},
		Tags:  map[string]*string{"Environment": to.Ptr("test")},
	}
}

func TestProximityPlacementGroup_CRUD(t *testing.T) {
	model := testProximityPlacementGroupModel()
	fake := &fakeProximityPlacementGroupsAPI{
		createOrUpdateFn: func(_ context.Context, _, _ string, _ armcompute.ProximityPlacementGroup, _ *armcompute.ProximityPlacementGroupsClientCreateOrUpdateOptions) (armcompute.ProximityPlacementGroupsClientCreateOrUpdateResponse, error) {
			return armcompute.ProximityPlacementGroupsClientCreateOrUpdateResponse{ProximityPlacementGroup: model}, nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armcompute.ProximityPlacementGroupsClientGetOptions) (armcompute.ProximityPlacementGroupsClientGetResponse, error) {
			return armcompute.ProximityPlacementGroupsClientGetResponse{ProximityPlacementGroup: model}, nil
		},
		updateFn: func(_ context.Context, _, _ string, _ armcompute.ProximityPlacementGroupUpdate, _ *armcompute.ProximityPlacementGroupsClientUpdateOptions) (armcompute.ProximityPlacementGroupsClientUpdateResponse, error) {
			return armcompute.ProximityPlacementGroupsClientUpdateResponse{ProximityPlacementGroup: model}, nil
		},
		deleteFn: func(_ context.Context, _, _ string, _ *armcompute.ProximityPlacementGroupsClientDeleteOptions) (armcompute.ProximityPlacementGroupsClientDeleteResponse, error) {
			return armcompute.ProximityPlacementGroupsClientDeleteResponse{}, nil
		},
		newListByResourceGroupPagerFn: func(_ string, _ *armcompute.ProximityPlacementGroupsClientListByResourceGroupOptions) *runtime.Pager[armcompute.ProximityPlacementGroupsClientListByResourceGroupResponse] {
			return runtime.NewPager(runtime.PagingHandler[armcompute.ProximityPlacementGroupsClientListByResourceGroupResponse]{
				More: func(_ armcompute.ProximityPlacementGroupsClientListByResourceGroupResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armcompute.ProximityPlacementGroupsClientListByResourceGroupResponse) (armcompute.ProximityPlacementGroupsClientListByResourceGroupResponse, error) {
					return armcompute.ProximityPlacementGroupsClientListByResourceGroupResponse{
						ProximityPlacementGroupListResult: armcompute.ProximityPlacementGroupListResult{
							Value: []*armcompute.ProximityPlacementGroup{{ID: to.Ptr(testPPGNativeID)}},
						},
					}, nil
				},
			})
		},
		newListBySubscriptionPagerFn: func(_ *armcompute.ProximityPlacementGroupsClientListBySubscriptionOptions) *runtime.Pager[armcompute.ProximityPlacementGroupsClientListBySubscriptionResponse] {
			return runtime.NewPager(runtime.PagingHandler[armcompute.ProximityPlacementGroupsClientListBySubscriptionResponse]{
				More: func(_ armcompute.ProximityPlacementGroupsClientListBySubscriptionResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armcompute.ProximityPlacementGroupsClientListBySubscriptionResponse) (armcompute.ProximityPlacementGroupsClientListBySubscriptionResponse, error) {
					return armcompute.ProximityPlacementGroupsClientListBySubscriptionResponse{
						ProximityPlacementGroupListResult: armcompute.ProximityPlacementGroupListResult{
							Value: []*armcompute.ProximityPlacementGroup{{ID: to.Ptr(testPPGNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestProximityPlacementGroup(fake)

	mkProps := func() json.RawMessage {
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName":           "rg-1",
			"name":                        "ppg-1",
			"location":                    "eastus",
			"proximityPlacementGroupType": "Standard",
			"intent":                      map[string]any{"vmSizes": []any{"Standard_B1s"}},
			"zones":                       []any{"1"},
			"Tags":                        []map[string]string{{"Key": "Environment", "Value": "test"}},
		})
		return props
	}

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testPPGNativeID, got.ProgressResult.NativeID)

		var serialized map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &serialized))
		require.Equal(t, "ppg-1", serialized["name"])
		require.Equal(t, "rg-1", serialized["resourceGroupName"])
		require.Equal(t, "Standard", serialized["proximityPlacementGroupType"])
		require.Equal(t, map[string]any{"vmSizes": []any{"Standard_B1s"}}, serialized["intent"])
		require.Equal(t, []any{"1"}, serialized["zones"])
	})

	t.Run("Create_forwards_params_to_ARM", func(t *testing.T) {
		var seen armcompute.ProximityPlacementGroup
		var seenRG, seenName string
		fake.createOrUpdateFn = func(_ context.Context, rg, name string, params armcompute.ProximityPlacementGroup, _ *armcompute.ProximityPlacementGroupsClientCreateOrUpdateOptions) (armcompute.ProximityPlacementGroupsClientCreateOrUpdateResponse, error) {
			seen, seenRG, seenName = params, rg, name
			return armcompute.ProximityPlacementGroupsClientCreateOrUpdateResponse{ProximityPlacementGroup: model}, nil
		}
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, "rg-1", seenRG)
		require.Equal(t, "ppg-1", seenName)
		require.Equal(t, "eastus", *seen.Location)
		require.Equal(t, armcompute.ProximityPlacementGroupTypeStandard, *seen.Properties.ProximityPlacementGroupType)
		require.Len(t, seen.Properties.Intent.VMSizes, 1)
		require.Equal(t, "Standard_B1s", *seen.Properties.Intent.VMSizes[0])
		require.Len(t, seen.Zones, 1)
		require.Equal(t, "test", *seen.Tags["Environment"])

		fake.createOrUpdateFn = func(_ context.Context, _, _ string, _ armcompute.ProximityPlacementGroup, _ *armcompute.ProximityPlacementGroupsClientCreateOrUpdateOptions) (armcompute.ProximityPlacementGroupsClientCreateOrUpdateResponse, error) {
			return armcompute.ProximityPlacementGroupsClientCreateOrUpdateResponse{ProximityPlacementGroup: model}, nil
		}
	})

	t.Run("Create_requires_location", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"resourceGroupName": "rg-1", "name": "ppg-1"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "location is required")
	})

	t.Run("Create_requires_resourceGroupName", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "ppg-1", "location": "eastus"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "resourceGroupName is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testPPGNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
		require.Equal(t, ResourceTypeProximityPlacementGroup, got.ResourceType)
	})

	t.Run("Read_not_found", func(t *testing.T) {
		fake.getFn = func(_ context.Context, _, _ string, _ *armcompute.ProximityPlacementGroupsClientGetOptions) (armcompute.ProximityPlacementGroupsClientGetResponse, error) {
			return armcompute.ProximityPlacementGroupsClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testPPGNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)

		fake.getFn = func(_ context.Context, _, _ string, _ *armcompute.ProximityPlacementGroupsClientGetOptions) (armcompute.ProximityPlacementGroupsClientGetResponse, error) {
			return armcompute.ProximityPlacementGroupsClientGetResponse{ProximityPlacementGroup: model}, nil
		}
	})

	// ARM's PATCH shape for a PPG (ProximityPlacementGroupUpdate) carries tags only.
	t.Run("Update_sends_tags_only", func(t *testing.T) {
		var seen armcompute.ProximityPlacementGroupUpdate
		fake.updateFn = func(_ context.Context, _, _ string, params armcompute.ProximityPlacementGroupUpdate, _ *armcompute.ProximityPlacementGroupsClientUpdateOptions) (armcompute.ProximityPlacementGroupsClientUpdateResponse, error) {
			seen = params
			return armcompute.ProximityPlacementGroupsClientUpdateResponse{ProximityPlacementGroup: model}, nil
		}
		desired, _ := json.Marshal(map[string]any{
			"resourceGroupName": "rg-1",
			"name":              "ppg-1",
			"location":          "eastus",
			"Tags":              []map[string]string{{"Key": "Environment", "Value": "updated"}},
		})
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testPPGNativeID,
			DesiredProperties: desired,
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, "updated", *seen.Tags["Environment"])
	})

	t.Run("Delete", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testPPGNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _ string, _ *armcompute.ProximityPlacementGroupsClientDeleteOptions) (armcompute.ProximityPlacementGroupsClientDeleteResponse, error) {
			return armcompute.ProximityPlacementGroupsClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testPPGNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Status_is_sync_success", func(t *testing.T) {
		got, err := prov.Status(context.Background(), &resource.StatusRequest{RequestID: "anything"})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_resource_group", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testPPGNativeID}, got.NativeIDs)
	})

	t.Run("List_by_subscription", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Equal(t, []string{testPPGNativeID}, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.createOrUpdateFn = func(_ context.Context, _, _ string, _ armcompute.ProximityPlacementGroup, _ *armcompute.ProximityPlacementGroupsClientCreateOrUpdateOptions) (armcompute.ProximityPlacementGroupsClientCreateOrUpdateResponse, error) {
			return armcompute.ProximityPlacementGroupsClientCreateOrUpdateResponse{}, &azcore.ResponseError{StatusCode: 403}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

func TestProximityPlacementGroupIDParts(t *testing.T) {
	rg, name, err := proximityPlacementGroupIDParts(testPPGNativeID)
	require.NoError(t, err)
	require.Equal(t, "rg-1", rg)
	require.Equal(t, "ppg-1", name)

	_, _, err = proximityPlacementGroupIDParts("/subscriptions/sub-1/resourceGroups/rg-1")
	require.Error(t, err)
}

// --- Test helpers ---

func newTestProximityPlacementGroup(api proximityPlacementGroupsAPI) *ProximityPlacementGroup {
	return &ProximityPlacementGroup{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

type fakeProximityPlacementGroupsAPI struct {
	createOrUpdateFn              func(ctx context.Context, rgName, name string, params armcompute.ProximityPlacementGroup, opts *armcompute.ProximityPlacementGroupsClientCreateOrUpdateOptions) (armcompute.ProximityPlacementGroupsClientCreateOrUpdateResponse, error)
	getFn                         func(ctx context.Context, rgName, name string, opts *armcompute.ProximityPlacementGroupsClientGetOptions) (armcompute.ProximityPlacementGroupsClientGetResponse, error)
	updateFn                      func(ctx context.Context, rgName, name string, params armcompute.ProximityPlacementGroupUpdate, opts *armcompute.ProximityPlacementGroupsClientUpdateOptions) (armcompute.ProximityPlacementGroupsClientUpdateResponse, error)
	deleteFn                      func(ctx context.Context, rgName, name string, opts *armcompute.ProximityPlacementGroupsClientDeleteOptions) (armcompute.ProximityPlacementGroupsClientDeleteResponse, error)
	newListByResourceGroupPagerFn func(rgName string, opts *armcompute.ProximityPlacementGroupsClientListByResourceGroupOptions) *runtime.Pager[armcompute.ProximityPlacementGroupsClientListByResourceGroupResponse]
	newListBySubscriptionPagerFn  func(opts *armcompute.ProximityPlacementGroupsClientListBySubscriptionOptions) *runtime.Pager[armcompute.ProximityPlacementGroupsClientListBySubscriptionResponse]
}

func (f *fakeProximityPlacementGroupsAPI) CreateOrUpdate(ctx context.Context, rgName, name string, params armcompute.ProximityPlacementGroup, opts *armcompute.ProximityPlacementGroupsClientCreateOrUpdateOptions) (armcompute.ProximityPlacementGroupsClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, name, params, opts)
}

func (f *fakeProximityPlacementGroupsAPI) Get(ctx context.Context, rgName, name string, opts *armcompute.ProximityPlacementGroupsClientGetOptions) (armcompute.ProximityPlacementGroupsClientGetResponse, error) {
	return f.getFn(ctx, rgName, name, opts)
}

func (f *fakeProximityPlacementGroupsAPI) Update(ctx context.Context, rgName, name string, params armcompute.ProximityPlacementGroupUpdate, opts *armcompute.ProximityPlacementGroupsClientUpdateOptions) (armcompute.ProximityPlacementGroupsClientUpdateResponse, error) {
	return f.updateFn(ctx, rgName, name, params, opts)
}

func (f *fakeProximityPlacementGroupsAPI) Delete(ctx context.Context, rgName, name string, opts *armcompute.ProximityPlacementGroupsClientDeleteOptions) (armcompute.ProximityPlacementGroupsClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, name, opts)
}

func (f *fakeProximityPlacementGroupsAPI) NewListByResourceGroupPager(rgName string, opts *armcompute.ProximityPlacementGroupsClientListByResourceGroupOptions) *runtime.Pager[armcompute.ProximityPlacementGroupsClientListByResourceGroupResponse] {
	return f.newListByResourceGroupPagerFn(rgName, opts)
}

func (f *fakeProximityPlacementGroupsAPI) NewListBySubscriptionPager(opts *armcompute.ProximityPlacementGroupsClientListBySubscriptionOptions) *runtime.Pager[armcompute.ProximityPlacementGroupsClientListBySubscriptionResponse] {
	return f.newListBySubscriptionPagerFn(opts)
}
