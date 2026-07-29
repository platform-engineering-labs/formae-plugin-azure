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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v4"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testIPGroupNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/ipGroups/ipg-1"

func TestIPGroup_CRUD(t *testing.T) {
	// Azure returns members in its own order; the model deliberately uses a
	// different order than the fixture to prove serialize sorts.
	model := armnetwork.IPGroup{
		ID:       to.Ptr(testIPGroupNativeID),
		Name:     to.Ptr("ipg-1"),
		Location: to.Ptr("eastus"),
		Properties: &armnetwork.IPGroupPropertiesFormat{
			IPAddresses: []*string{to.Ptr("10.2.0.0/24"), to.Ptr("10.1.0.0/24")},
		},
		Tags: map[string]*string{"Environment": to.Ptr("test")},
	}
	fake := &fakeIPGroupsAPI{
		beginCreateOrUpdateFn: func(_ context.Context, _, _ string, _ armnetwork.IPGroup, _ *armnetwork.IPGroupsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.IPGroupsClientCreateOrUpdateResponse], error) {
			return newDonePoller(armnetwork.IPGroupsClientCreateOrUpdateResponse{IPGroup: model}), nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armnetwork.IPGroupsClientGetOptions) (armnetwork.IPGroupsClientGetResponse, error) {
			return armnetwork.IPGroupsClientGetResponse{IPGroup: model}, nil
		},
		beginDeleteFn: func(_ context.Context, _, _ string, _ *armnetwork.IPGroupsClientBeginDeleteOptions) (*runtime.Poller[armnetwork.IPGroupsClientDeleteResponse], error) {
			return newInProgressPoller[armnetwork.IPGroupsClientDeleteResponse](), nil
		},
		newListByResourceGroupPagerFn: func(_ string, _ *armnetwork.IPGroupsClientListByResourceGroupOptions) *runtime.Pager[armnetwork.IPGroupsClientListByResourceGroupResponse] {
			return runtime.NewPager(runtime.PagingHandler[armnetwork.IPGroupsClientListByResourceGroupResponse]{
				More: func(_ armnetwork.IPGroupsClientListByResourceGroupResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armnetwork.IPGroupsClientListByResourceGroupResponse) (armnetwork.IPGroupsClientListByResourceGroupResponse, error) {
					return armnetwork.IPGroupsClientListByResourceGroupResponse{
						IPGroupListResult: armnetwork.IPGroupListResult{
							Value: []*armnetwork.IPGroup{{ID: to.Ptr(testIPGroupNativeID)}},
						},
					}, nil
				},
			})
		},
		newListPagerFn: func(_ *armnetwork.IPGroupsClientListOptions) *runtime.Pager[armnetwork.IPGroupsClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armnetwork.IPGroupsClientListResponse]{
				More: func(_ armnetwork.IPGroupsClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armnetwork.IPGroupsClientListResponse) (armnetwork.IPGroupsClientListResponse, error) {
					return armnetwork.IPGroupsClientListResponse{
						IPGroupListResult: armnetwork.IPGroupListResult{
							Value: []*armnetwork.IPGroup{{ID: to.Ptr(testIPGroupNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestIPGroup(fake)

	mkProps := func() json.RawMessage {
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName": "rg-1",
			"name":              "ipg-1",
			"location":          "eastus",
			"ipAddresses":       []any{"10.1.0.0/24", "10.2.0.0/24"},
			"Tags":              []map[string]string{{"Key": "Environment", "Value": "test"}},
		})
		return props
	}

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testIPGroupNativeID, got.ProgressResult.NativeID)

		var serialized map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &serialized))
		require.Equal(t, "ipg-1", serialized["name"])
		require.Equal(t, "rg-1", serialized["resourceGroupName"])
	})

	// ARM does not preserve submitted order, so both directions sort — otherwise
	// Read reports drift against an identical set.
	t.Run("Serialize_sorts_ipAddresses", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testIPGroupNativeID})
		require.NoError(t, err)
		var serialized map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &serialized))
		require.Equal(t, []any{"10.1.0.0/24", "10.2.0.0/24"}, serialized["ipAddresses"])
	})

	t.Run("Create_sorts_and_forwards_ipAddresses", func(t *testing.T) {
		var seen armnetwork.IPGroup
		var seenRG, seenName string
		fake.beginCreateOrUpdateFn = func(_ context.Context, rg, name string, params armnetwork.IPGroup, _ *armnetwork.IPGroupsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.IPGroupsClientCreateOrUpdateResponse], error) {
			seen, seenRG, seenName = params, rg, name
			return newDonePoller(armnetwork.IPGroupsClientCreateOrUpdateResponse{IPGroup: model}), nil
		}
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName": "rg-1",
			"name":              "ipg-1",
			"location":          "eastus",
			"ipAddresses":       []any{"10.9.0.0/24", "10.1.0.0/24", "203.0.113.4"},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.Equal(t, "rg-1", seenRG)
		require.Equal(t, "ipg-1", seenName)
		require.Equal(t, "eastus", *seen.Location)
		require.Len(t, seen.Properties.IPAddresses, 3)
		require.Equal(t, "10.1.0.0/24", *seen.Properties.IPAddresses[0])
		require.Equal(t, "10.9.0.0/24", *seen.Properties.IPAddresses[1])
		require.Equal(t, "203.0.113.4", *seen.Properties.IPAddresses[2])

		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, _ armnetwork.IPGroup, _ *armnetwork.IPGroupsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.IPGroupsClientCreateOrUpdateResponse], error) {
			return newDonePoller(armnetwork.IPGroupsClientCreateOrUpdateResponse{IPGroup: model}), nil
		}
	})

	t.Run("Create_requires_location", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"resourceGroupName": "rg-1", "name": "ipg-1"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "location is required")
	})

	t.Run("Create_requires_resourceGroupName", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "ipg-1", "location": "eastus"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "resourceGroupName is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testIPGroupNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
		require.Equal(t, ResourceTypeIPGroup, got.ResourceType)
	})

	t.Run("Read_not_found", func(t *testing.T) {
		fake.getFn = func(_ context.Context, _, _ string, _ *armnetwork.IPGroupsClientGetOptions) (armnetwork.IPGroupsClientGetResponse, error) {
			return armnetwork.IPGroupsClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testIPGroupNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)

		fake.getFn = func(_ context.Context, _, _ string, _ *armnetwork.IPGroupsClientGetOptions) (armnetwork.IPGroupsClientGetResponse, error) {
			return armnetwork.IPGroupsClientGetResponse{IPGroup: model}, nil
		}
	})

	// Member changes need the full-body PUT: ARM's IPGroups PATCH accepts tags only.
	t.Run("Update_sends_members_via_full_body_put", func(t *testing.T) {
		var seen armnetwork.IPGroup
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, params armnetwork.IPGroup, _ *armnetwork.IPGroupsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.IPGroupsClientCreateOrUpdateResponse], error) {
			seen = params
			return newDonePoller(armnetwork.IPGroupsClientCreateOrUpdateResponse{IPGroup: model}), nil
		}
		desired, _ := json.Marshal(map[string]any{
			"resourceGroupName": "rg-1",
			"name":              "ipg-1",
			"location":          "eastus",
			"ipAddresses":       []any{"10.1.0.0/24", "10.2.0.0/24", "10.3.0.0/24"},
			"Tags":              []map[string]string{{"Key": "Environment", "Value": "updated"}},
		})
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testIPGroupNativeID,
			DesiredProperties: desired,
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Len(t, seen.Properties.IPAddresses, 3)
		require.Equal(t, "updated", *seen.Tags["Environment"])
	})

	t.Run("Delete_in_progress_returns_lro_request_id", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testIPGroupNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusInProgress, got.ProgressResult.OperationStatus)
		reqID, err := decodeLROStatus(got.ProgressResult.RequestID)
		require.NoError(t, err)
		require.Equal(t, lroOpDelete, reqID.OperationType)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _ string, _ *armnetwork.IPGroupsClientBeginDeleteOptions) (*runtime.Poller[armnetwork.IPGroupsClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testIPGroupNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Status_rejects_unknown_operation", func(t *testing.T) {
		reqID, err := encodeLROStart("bogus", "token", testIPGroupNativeID)
		require.NoError(t, err)
		got, err := prov.Status(context.Background(), &resource.StatusRequest{RequestID: reqID})
		require.Error(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_resource_group", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testIPGroupNativeID}, got.NativeIDs)
	})

	t.Run("List_by_subscription", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Equal(t, []string{testIPGroupNativeID}, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, _ armnetwork.IPGroup, _ *armnetwork.IPGroupsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.IPGroupsClientCreateOrUpdateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 403}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

func TestIPGroupIDParts(t *testing.T) {
	rg, name, err := ipGroupIDParts(testIPGroupNativeID)
	require.NoError(t, err)
	require.Equal(t, "rg-1", rg)
	require.Equal(t, "ipg-1", name)

	_, _, err = ipGroupIDParts("/subscriptions/sub-1/resourceGroups/rg-1")
	require.Error(t, err)
}

// --- Test helpers ---

func newTestIPGroup(api ipGroupsAPI) *IPGroup {
	return &IPGroup{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

type fakeIPGroupsAPI struct {
	beginCreateOrUpdateFn         func(ctx context.Context, rgName, name string, params armnetwork.IPGroup, opts *armnetwork.IPGroupsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.IPGroupsClientCreateOrUpdateResponse], error)
	getFn                         func(ctx context.Context, rgName, name string, opts *armnetwork.IPGroupsClientGetOptions) (armnetwork.IPGroupsClientGetResponse, error)
	beginDeleteFn                 func(ctx context.Context, rgName, name string, opts *armnetwork.IPGroupsClientBeginDeleteOptions) (*runtime.Poller[armnetwork.IPGroupsClientDeleteResponse], error)
	newListByResourceGroupPagerFn func(rgName string, opts *armnetwork.IPGroupsClientListByResourceGroupOptions) *runtime.Pager[armnetwork.IPGroupsClientListByResourceGroupResponse]
	newListPagerFn                func(opts *armnetwork.IPGroupsClientListOptions) *runtime.Pager[armnetwork.IPGroupsClientListResponse]
}

func (f *fakeIPGroupsAPI) BeginCreateOrUpdate(ctx context.Context, rgName, name string, params armnetwork.IPGroup, opts *armnetwork.IPGroupsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.IPGroupsClientCreateOrUpdateResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, rgName, name, params, opts)
}

func (f *fakeIPGroupsAPI) Get(ctx context.Context, rgName, name string, opts *armnetwork.IPGroupsClientGetOptions) (armnetwork.IPGroupsClientGetResponse, error) {
	return f.getFn(ctx, rgName, name, opts)
}

func (f *fakeIPGroupsAPI) BeginDelete(ctx context.Context, rgName, name string, opts *armnetwork.IPGroupsClientBeginDeleteOptions) (*runtime.Poller[armnetwork.IPGroupsClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, name, opts)
}

func (f *fakeIPGroupsAPI) NewListByResourceGroupPager(rgName string, opts *armnetwork.IPGroupsClientListByResourceGroupOptions) *runtime.Pager[armnetwork.IPGroupsClientListByResourceGroupResponse] {
	return f.newListByResourceGroupPagerFn(rgName, opts)
}

func (f *fakeIPGroupsAPI) NewListPager(opts *armnetwork.IPGroupsClientListOptions) *runtime.Pager[armnetwork.IPGroupsClientListResponse] {
	return f.newListPagerFn(opts)
}
