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

const testAvailabilitySetNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Compute/availabilitySets/avset-1"

func testAvailabilitySetModel() armcompute.AvailabilitySet {
	return armcompute.AvailabilitySet{
		ID:       to.Ptr(testAvailabilitySetNativeID),
		Name:     to.Ptr("avset-1"),
		Location: to.Ptr("eastus"),
		SKU:      &armcompute.SKU{Name: to.Ptr("Aligned")},
		Properties: &armcompute.AvailabilitySetProperties{
			PlatformFaultDomainCount:  to.Ptr(int32(2)),
			PlatformUpdateDomainCount: to.Ptr(int32(5)),
		},
		Tags: map[string]*string{"Environment": to.Ptr("test")},
	}
}

func TestAvailabilitySet_CRUD(t *testing.T) {
	model := testAvailabilitySetModel()
	fake := &fakeAvailabilitySetsAPI{
		createOrUpdateFn: func(_ context.Context, _, _ string, _ armcompute.AvailabilitySet, _ *armcompute.AvailabilitySetsClientCreateOrUpdateOptions) (armcompute.AvailabilitySetsClientCreateOrUpdateResponse, error) {
			return armcompute.AvailabilitySetsClientCreateOrUpdateResponse{AvailabilitySet: model}, nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armcompute.AvailabilitySetsClientGetOptions) (armcompute.AvailabilitySetsClientGetResponse, error) {
			return armcompute.AvailabilitySetsClientGetResponse{AvailabilitySet: model}, nil
		},
		updateFn: func(_ context.Context, _, _ string, _ armcompute.AvailabilitySetUpdate, _ *armcompute.AvailabilitySetsClientUpdateOptions) (armcompute.AvailabilitySetsClientUpdateResponse, error) {
			return armcompute.AvailabilitySetsClientUpdateResponse{AvailabilitySet: model}, nil
		},
		deleteFn: func(_ context.Context, _, _ string, _ *armcompute.AvailabilitySetsClientDeleteOptions) (armcompute.AvailabilitySetsClientDeleteResponse, error) {
			return armcompute.AvailabilitySetsClientDeleteResponse{}, nil
		},
		newListPagerFn: func(_ string, _ *armcompute.AvailabilitySetsClientListOptions) *runtime.Pager[armcompute.AvailabilitySetsClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armcompute.AvailabilitySetsClientListResponse]{
				More: func(_ armcompute.AvailabilitySetsClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armcompute.AvailabilitySetsClientListResponse) (armcompute.AvailabilitySetsClientListResponse, error) {
					return armcompute.AvailabilitySetsClientListResponse{
						AvailabilitySetListResult: armcompute.AvailabilitySetListResult{
							Value: []*armcompute.AvailabilitySet{{ID: to.Ptr(testAvailabilitySetNativeID)}},
						},
					}, nil
				},
			})
		},
		newListBySubscriptionPagerFn: func(_ *armcompute.AvailabilitySetsClientListBySubscriptionOptions) *runtime.Pager[armcompute.AvailabilitySetsClientListBySubscriptionResponse] {
			return runtime.NewPager(runtime.PagingHandler[armcompute.AvailabilitySetsClientListBySubscriptionResponse]{
				More: func(_ armcompute.AvailabilitySetsClientListBySubscriptionResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armcompute.AvailabilitySetsClientListBySubscriptionResponse) (armcompute.AvailabilitySetsClientListBySubscriptionResponse, error) {
					return armcompute.AvailabilitySetsClientListBySubscriptionResponse{
						AvailabilitySetListResult: armcompute.AvailabilitySetListResult{
							Value: []*armcompute.AvailabilitySet{{ID: to.Ptr(testAvailabilitySetNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestAvailabilitySet(fake)

	mkProps := func() json.RawMessage {
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName":         "rg-1",
			"name":                      "avset-1",
			"location":                  "eastus",
			"sku":                       map[string]any{"name": "Aligned"},
			"platformFaultDomainCount":  2,
			"platformUpdateDomainCount": 5,
			"Tags":                      []map[string]string{{"Key": "Environment", "Value": "test"}},
		})
		return props
	}

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testAvailabilitySetNativeID, got.ProgressResult.NativeID)

		var serialized map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &serialized))
		require.Equal(t, "avset-1", serialized["name"])
		require.Equal(t, "rg-1", serialized["resourceGroupName"])
		require.Equal(t, "eastus", serialized["location"])
		require.Equal(t, float64(2), serialized["platformFaultDomainCount"])
		require.Equal(t, float64(5), serialized["platformUpdateDomainCount"])
		require.Equal(t, map[string]any{"name": "Aligned"}, serialized["sku"])
		require.Equal(t, []any{map[string]any{"Key": "Environment", "Value": "test"}}, serialized["Tags"])
	})

	t.Run("Create_forwards_params_to_ARM", func(t *testing.T) {
		var seen armcompute.AvailabilitySet
		var seenRG, seenName string
		fake.createOrUpdateFn = func(_ context.Context, rg, name string, params armcompute.AvailabilitySet, _ *armcompute.AvailabilitySetsClientCreateOrUpdateOptions) (armcompute.AvailabilitySetsClientCreateOrUpdateResponse, error) {
			seen, seenRG, seenName = params, rg, name
			return armcompute.AvailabilitySetsClientCreateOrUpdateResponse{AvailabilitySet: model}, nil
		}
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, "rg-1", seenRG)
		require.Equal(t, "avset-1", seenName)
		require.Equal(t, "eastus", *seen.Location)
		require.Equal(t, "Aligned", *seen.SKU.Name)
		require.Equal(t, int32(2), *seen.Properties.PlatformFaultDomainCount)
		require.Equal(t, int32(5), *seen.Properties.PlatformUpdateDomainCount)
		require.Equal(t, "test", *seen.Tags["Environment"])

		// restore
		fake.createOrUpdateFn = func(_ context.Context, _, _ string, _ armcompute.AvailabilitySet, _ *armcompute.AvailabilitySetsClientCreateOrUpdateOptions) (armcompute.AvailabilitySetsClientCreateOrUpdateResponse, error) {
			return armcompute.AvailabilitySetsClientCreateOrUpdateResponse{AvailabilitySet: model}, nil
		}
	})

	t.Run("Create_requires_name", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"resourceGroupName": "rg-1", "location": "eastus"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.Error(t, err)
	})

	t.Run("Create_requires_location", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"resourceGroupName": "rg-1", "name": "avset-1"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.Error(t, err)
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testAvailabilitySetNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
		require.Equal(t, ResourceTypeAvailabilitySet, got.ResourceType)

		var serialized map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &serialized))
		require.Equal(t, "avset-1", serialized["name"])
		require.Equal(t, testAvailabilitySetNativeID, serialized["id"])
	})

	t.Run("Read_not_found", func(t *testing.T) {
		fake.getFn = func(_ context.Context, _, _ string, _ *armcompute.AvailabilitySetsClientGetOptions) (armcompute.AvailabilitySetsClientGetResponse, error) {
			return armcompute.AvailabilitySetsClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testAvailabilitySetNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)

		fake.getFn = func(_ context.Context, _, _ string, _ *armcompute.AvailabilitySetsClientGetOptions) (armcompute.AvailabilitySetsClientGetResponse, error) {
			return armcompute.AvailabilitySetsClientGetResponse{AvailabilitySet: model}, nil
		}
	})

	// ARM requires platformFaultDomainCount in the PATCH body even though it is
	// immutable; omitting it fails with
	// `InvalidParameter: Required parameter 'platformFaultDomainCount' is missing (null)`.
	t.Run("Update_echoes_required_immutable_domain_counts", func(t *testing.T) {
		var seen armcompute.AvailabilitySetUpdate
		fake.updateFn = func(_ context.Context, _, _ string, params armcompute.AvailabilitySetUpdate, _ *armcompute.AvailabilitySetsClientUpdateOptions) (armcompute.AvailabilitySetsClientUpdateResponse, error) {
			seen = params
			return armcompute.AvailabilitySetsClientUpdateResponse{AvailabilitySet: model}, nil
		}
		desired, _ := json.Marshal(map[string]any{
			"resourceGroupName":         "rg-1",
			"name":                      "avset-1",
			"location":                  "eastus",
			"sku":                       map[string]any{"name": "Aligned"},
			"platformFaultDomainCount":  2,
			"platformUpdateDomainCount": 5,
			"Tags":                      []map[string]string{{"Key": "Environment", "Value": "updated"}},
		})
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testAvailabilitySetNativeID,
			DesiredProperties: desired,
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, "Aligned", *seen.SKU.Name)
		require.Equal(t, "updated", *seen.Tags["Environment"])
		require.NotNil(t, seen.Properties)
		require.Equal(t, int32(2), *seen.Properties.PlatformFaultDomainCount)
		require.Equal(t, int32(5), *seen.Properties.PlatformUpdateDomainCount)
	})

	t.Run("Delete", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testAvailabilitySetNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _ string, _ *armcompute.AvailabilitySetsClientDeleteOptions) (armcompute.AvailabilitySetsClientDeleteResponse, error) {
			return armcompute.AvailabilitySetsClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testAvailabilitySetNativeID})
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
		require.Equal(t, []string{testAvailabilitySetNativeID}, got.NativeIDs)
	})

	t.Run("List_by_subscription", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Equal(t, []string{testAvailabilitySetNativeID}, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.createOrUpdateFn = func(_ context.Context, _, _ string, _ armcompute.AvailabilitySet, _ *armcompute.AvailabilitySetsClientCreateOrUpdateOptions) (armcompute.AvailabilitySetsClientCreateOrUpdateResponse, error) {
			return armcompute.AvailabilitySetsClientCreateOrUpdateResponse{}, &azcore.ResponseError{StatusCode: 403}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

func TestAvailabilitySetIDParts(t *testing.T) {
	rg, name, err := availabilitySetIDParts(testAvailabilitySetNativeID)
	require.NoError(t, err)
	require.Equal(t, "rg-1", rg)
	require.Equal(t, "avset-1", name)

	_, _, err = availabilitySetIDParts("/subscriptions/sub-1/resourceGroups/rg-1")
	require.Error(t, err)
}

// --- Test helpers ---

func newTestAvailabilitySet(api availabilitySetsAPI) *AvailabilitySet {
	return &AvailabilitySet{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

type fakeAvailabilitySetsAPI struct {
	createOrUpdateFn             func(ctx context.Context, rgName, name string, params armcompute.AvailabilitySet, opts *armcompute.AvailabilitySetsClientCreateOrUpdateOptions) (armcompute.AvailabilitySetsClientCreateOrUpdateResponse, error)
	getFn                        func(ctx context.Context, rgName, name string, opts *armcompute.AvailabilitySetsClientGetOptions) (armcompute.AvailabilitySetsClientGetResponse, error)
	updateFn                     func(ctx context.Context, rgName, name string, params armcompute.AvailabilitySetUpdate, opts *armcompute.AvailabilitySetsClientUpdateOptions) (armcompute.AvailabilitySetsClientUpdateResponse, error)
	deleteFn                     func(ctx context.Context, rgName, name string, opts *armcompute.AvailabilitySetsClientDeleteOptions) (armcompute.AvailabilitySetsClientDeleteResponse, error)
	newListPagerFn               func(rgName string, opts *armcompute.AvailabilitySetsClientListOptions) *runtime.Pager[armcompute.AvailabilitySetsClientListResponse]
	newListBySubscriptionPagerFn func(opts *armcompute.AvailabilitySetsClientListBySubscriptionOptions) *runtime.Pager[armcompute.AvailabilitySetsClientListBySubscriptionResponse]
}

func (f *fakeAvailabilitySetsAPI) CreateOrUpdate(ctx context.Context, rgName, name string, params armcompute.AvailabilitySet, opts *armcompute.AvailabilitySetsClientCreateOrUpdateOptions) (armcompute.AvailabilitySetsClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, name, params, opts)
}

func (f *fakeAvailabilitySetsAPI) Get(ctx context.Context, rgName, name string, opts *armcompute.AvailabilitySetsClientGetOptions) (armcompute.AvailabilitySetsClientGetResponse, error) {
	return f.getFn(ctx, rgName, name, opts)
}

func (f *fakeAvailabilitySetsAPI) Update(ctx context.Context, rgName, name string, params armcompute.AvailabilitySetUpdate, opts *armcompute.AvailabilitySetsClientUpdateOptions) (armcompute.AvailabilitySetsClientUpdateResponse, error) {
	return f.updateFn(ctx, rgName, name, params, opts)
}

func (f *fakeAvailabilitySetsAPI) Delete(ctx context.Context, rgName, name string, opts *armcompute.AvailabilitySetsClientDeleteOptions) (armcompute.AvailabilitySetsClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, name, opts)
}

func (f *fakeAvailabilitySetsAPI) NewListPager(rgName string, opts *armcompute.AvailabilitySetsClientListOptions) *runtime.Pager[armcompute.AvailabilitySetsClientListResponse] {
	return f.newListPagerFn(rgName, opts)
}

func (f *fakeAvailabilitySetsAPI) NewListBySubscriptionPager(opts *armcompute.AvailabilitySetsClientListBySubscriptionOptions) *runtime.Pager[armcompute.AvailabilitySetsClientListBySubscriptionResponse] {
	return f.newListBySubscriptionPagerFn(opts)
}
