// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v5"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testDiskAccessNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Compute/diskAccesses/da1"

func newTestDiskAccess(api computeDiskAccessesAPI) *ComputeDiskAccess {
	return &ComputeDiskAccess{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func diskAccessDesired(tagValue string) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":              "da1",
		"location":          "eastus",
		"resourceGroupName": "rg-1",
		"Tags":              []any{map[string]any{"Key": "env", "Value": tagValue}},
	})
	return out
}

func TestComputeDiskAccess_CRUD(t *testing.T) {
	accessResult := armcompute.DiskAccess{
		ID:       to.Ptr(testDiskAccessNativeID),
		Name:     to.Ptr("da1"),
		Location: to.Ptr("East US"),
		Properties: &armcompute.DiskAccessProperties{
			// All service state or separately-managed children.
			ProvisioningState: to.Ptr("Succeeded"),
			TimeCreated:       to.Ptr(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)),
			PrivateEndpointConnections: []*armcompute.PrivateEndpointConnection{{
				ID:   to.Ptr(testDiskAccessNativeID + "/privateEndpointConnections/pe1"),
				Name: to.Ptr("pe1"),
			}},
		},
		Tags: map[string]*string{"env": to.Ptr("test")},
	}

	var sentCreate armcompute.DiskAccess
	var sentUpdate armcompute.DiskAccessUpdate
	deleteCalls := 0
	fake := &fakeDiskAccessesAPI{
		beginCreateOrUpdateFn: func(_ context.Context, rgName, name string, access armcompute.DiskAccess, _ *armcompute.DiskAccessesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armcompute.DiskAccessesClientCreateOrUpdateResponse], error) {
			require.Equal(t, "rg-1", rgName)
			require.Equal(t, "da1", name)
			sentCreate = access
			return newDonePoller(armcompute.DiskAccessesClientCreateOrUpdateResponse{DiskAccess: accessResult}), nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armcompute.DiskAccessesClientGetOptions) (armcompute.DiskAccessesClientGetResponse, error) {
			return armcompute.DiskAccessesClientGetResponse{DiskAccess: accessResult}, nil
		},
		beginUpdateFn: func(_ context.Context, _, _ string, access armcompute.DiskAccessUpdate, _ *armcompute.DiskAccessesClientBeginUpdateOptions) (*runtime.Poller[armcompute.DiskAccessesClientUpdateResponse], error) {
			sentUpdate = access
			return newDonePoller(armcompute.DiskAccessesClientUpdateResponse{DiskAccess: accessResult}), nil
		},
		beginDeleteFn: func(_ context.Context, _, _ string, _ *armcompute.DiskAccessesClientBeginDeleteOptions) (*runtime.Poller[armcompute.DiskAccessesClientDeleteResponse], error) {
			deleteCalls++
			return newDonePoller(armcompute.DiskAccessesClientDeleteResponse{}), nil
		},
		newListByResourceGroupPagerFn: func(_ string, _ *armcompute.DiskAccessesClientListByResourceGroupOptions) *runtime.Pager[armcompute.DiskAccessesClientListByResourceGroupResponse] {
			return runtime.NewPager(runtime.PagingHandler[armcompute.DiskAccessesClientListByResourceGroupResponse]{
				More: func(_ armcompute.DiskAccessesClientListByResourceGroupResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armcompute.DiskAccessesClientListByResourceGroupResponse) (armcompute.DiskAccessesClientListByResourceGroupResponse, error) {
					return armcompute.DiskAccessesClientListByResourceGroupResponse{
						DiskAccessList: armcompute.DiskAccessList{
							Value: []*armcompute.DiskAccess{{ID: to.Ptr(testDiskAccessNativeID)}},
						},
					}, nil
				},
			})
		},
		newListPagerFn: func(_ *armcompute.DiskAccessesClientListOptions) *runtime.Pager[armcompute.DiskAccessesClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armcompute.DiskAccessesClientListResponse]{
				More: func(_ armcompute.DiskAccessesClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armcompute.DiskAccessesClientListResponse) (armcompute.DiskAccessesClientListResponse, error) {
					return armcompute.DiskAccessesClientListResponse{
						DiskAccessList: armcompute.DiskAccessList{
							Value: []*armcompute.DiskAccess{
								{ID: to.Ptr(testDiskAccessNativeID)},
								{ID: to.Ptr("/subscriptions/sub-1/resourceGroups/rg-2/providers/Microsoft.Compute/diskAccesses/da2")},
							},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestDiskAccess(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "da1", Properties: diskAccessDesired("test"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testDiskAccessNativeID, got.ProgressResult.NativeID)

		require.Equal(t, "eastus", *sentCreate.Location)
		require.Equal(t, "test", *sentCreate.Tags["env"])
		// This resource has no settable properties block at all.
		require.Nil(t, sentCreate.Properties)
	})

	t.Run("Create_requires_location", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "da1", "resourceGroupName": "rg-1"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "location is required")
	})

	t.Run("Create_requires_resource_group", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "da1", "location": "eastus"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "resourceGroupName is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testDiskAccessNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "da1", props["name"])
		// ARM returns "East US"; read must normalise or desired state drifts.
		require.Equal(t, "eastus", props["location"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
	})

	// Private endpoint connections have their own lifecycle, and the timestamps are
	// service state — none of it belongs in this resource's state.
	t.Run("Read_drops_connections_and_service_state", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testDiskAccessNativeID})
		require.NoError(t, err)
		for _, key := range []string{"privateEndpointConnections", "provisioningState", "timeCreated"} {
			require.NotContains(t, got.Properties, key)
		}
		require.NotContains(t, got.Properties, "pe1")
	})

	// Tags are the only mutable property: DiskAccessUpdate has no other field.
	t.Run("Update_sends_tags_only", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testDiskAccessNativeID,
			DesiredProperties: diskAccessDesired("updated"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, "updated", *sentUpdate.Tags["env"])
	})

	t.Run("Delete", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testDiskAccessNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _ string, _ *armcompute.DiskAccessesClientBeginDeleteOptions) (*runtime.Poller[armcompute.DiskAccessesClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testDiskAccessNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_resource_group", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testDiskAccessNativeID}, got.NativeIDs)
	})

	t.Run("List_without_group_is_subscription_wide", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 2)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, _ armcompute.DiskAccess, _ *armcompute.DiskAccessesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armcompute.DiskAccessesClientCreateOrUpdateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 409}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "da1", Properties: diskAccessDesired("test"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

// The native ID reported for an in-flight create must match the path ARM returns.
func TestComputeDiskAccess_PendingCreateReportsRealNativeID(t *testing.T) {
	fake := &fakeDiskAccessesAPI{
		beginCreateOrUpdateFn: func(_ context.Context, _, _ string, _ armcompute.DiskAccess, _ *armcompute.DiskAccessesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armcompute.DiskAccessesClientCreateOrUpdateResponse], error) {
			return newPendingPoller[armcompute.DiskAccessesClientCreateOrUpdateResponse](), nil
		},
	}
	got, err := newTestDiskAccess(fake).Create(context.Background(), &resource.CreateRequest{
		Label: "da1", Properties: diskAccessDesired("test"),
	})
	require.NoError(t, err)
	require.Equal(t, resource.OperationStatusInProgress, got.ProgressResult.OperationStatus)
	require.Equal(t, testDiskAccessNativeID, got.ProgressResult.NativeID)
}

func TestComputeDiskAccess_ReadNotFound(t *testing.T) {
	fake := &fakeDiskAccessesAPI{
		getFn: func(_ context.Context, _, _ string, _ *armcompute.DiskAccessesClientGetOptions) (armcompute.DiskAccessesClientGetResponse, error) {
			return armcompute.DiskAccessesClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestDiskAccess(fake).Read(context.Background(), &resource.ReadRequest{NativeID: testDiskAccessNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeDiskAccessesAPI struct {
	beginCreateOrUpdateFn         func(ctx context.Context, rgName, name string, access armcompute.DiskAccess, options *armcompute.DiskAccessesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armcompute.DiskAccessesClientCreateOrUpdateResponse], error)
	getFn                         func(ctx context.Context, rgName, name string, options *armcompute.DiskAccessesClientGetOptions) (armcompute.DiskAccessesClientGetResponse, error)
	beginUpdateFn                 func(ctx context.Context, rgName, name string, access armcompute.DiskAccessUpdate, options *armcompute.DiskAccessesClientBeginUpdateOptions) (*runtime.Poller[armcompute.DiskAccessesClientUpdateResponse], error)
	beginDeleteFn                 func(ctx context.Context, rgName, name string, options *armcompute.DiskAccessesClientBeginDeleteOptions) (*runtime.Poller[armcompute.DiskAccessesClientDeleteResponse], error)
	newListByResourceGroupPagerFn func(rgName string, options *armcompute.DiskAccessesClientListByResourceGroupOptions) *runtime.Pager[armcompute.DiskAccessesClientListByResourceGroupResponse]
	newListPagerFn                func(options *armcompute.DiskAccessesClientListOptions) *runtime.Pager[armcompute.DiskAccessesClientListResponse]
}

func (f *fakeDiskAccessesAPI) BeginCreateOrUpdate(ctx context.Context, rgName, name string, access armcompute.DiskAccess, options *armcompute.DiskAccessesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armcompute.DiskAccessesClientCreateOrUpdateResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, rgName, name, access, options)
}

func (f *fakeDiskAccessesAPI) Get(ctx context.Context, rgName, name string, options *armcompute.DiskAccessesClientGetOptions) (armcompute.DiskAccessesClientGetResponse, error) {
	return f.getFn(ctx, rgName, name, options)
}

func (f *fakeDiskAccessesAPI) BeginUpdate(ctx context.Context, rgName, name string, access armcompute.DiskAccessUpdate, options *armcompute.DiskAccessesClientBeginUpdateOptions) (*runtime.Poller[armcompute.DiskAccessesClientUpdateResponse], error) {
	return f.beginUpdateFn(ctx, rgName, name, access, options)
}

func (f *fakeDiskAccessesAPI) BeginDelete(ctx context.Context, rgName, name string, options *armcompute.DiskAccessesClientBeginDeleteOptions) (*runtime.Poller[armcompute.DiskAccessesClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, name, options)
}

func (f *fakeDiskAccessesAPI) NewListByResourceGroupPager(rgName string, options *armcompute.DiskAccessesClientListByResourceGroupOptions) *runtime.Pager[armcompute.DiskAccessesClientListByResourceGroupResponse] {
	return f.newListByResourceGroupPagerFn(rgName, options)
}

func (f *fakeDiskAccessesAPI) NewListPager(options *armcompute.DiskAccessesClientListOptions) *runtime.Pager[armcompute.DiskAccessesClientListResponse] {
	return f.newListPagerFn(options)
}
