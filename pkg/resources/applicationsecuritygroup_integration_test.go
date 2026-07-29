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

const testASGNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/applicationSecurityGroups/asg-1"

func TestApplicationSecurityGroup_CRUD(t *testing.T) {
	model := armnetwork.ApplicationSecurityGroup{
		ID:       to.Ptr(testASGNativeID),
		Name:     to.Ptr("asg-1"),
		Location: to.Ptr("eastus"),
		Tags:     map[string]*string{"Environment": to.Ptr("test")},
	}
	fake := &fakeApplicationSecurityGroupsAPI{
		beginCreateOrUpdateFn: func(_ context.Context, _, _ string, _ armnetwork.ApplicationSecurityGroup, _ *armnetwork.ApplicationSecurityGroupsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.ApplicationSecurityGroupsClientCreateOrUpdateResponse], error) {
			return newDonePoller(armnetwork.ApplicationSecurityGroupsClientCreateOrUpdateResponse{ApplicationSecurityGroup: model}), nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armnetwork.ApplicationSecurityGroupsClientGetOptions) (armnetwork.ApplicationSecurityGroupsClientGetResponse, error) {
			return armnetwork.ApplicationSecurityGroupsClientGetResponse{ApplicationSecurityGroup: model}, nil
		},
		beginDeleteFn: func(_ context.Context, _, _ string, _ *armnetwork.ApplicationSecurityGroupsClientBeginDeleteOptions) (*runtime.Poller[armnetwork.ApplicationSecurityGroupsClientDeleteResponse], error) {
			return newInProgressPoller[armnetwork.ApplicationSecurityGroupsClientDeleteResponse](), nil
		},
		newListPagerFn: func(_ string, _ *armnetwork.ApplicationSecurityGroupsClientListOptions) *runtime.Pager[armnetwork.ApplicationSecurityGroupsClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armnetwork.ApplicationSecurityGroupsClientListResponse]{
				More: func(_ armnetwork.ApplicationSecurityGroupsClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armnetwork.ApplicationSecurityGroupsClientListResponse) (armnetwork.ApplicationSecurityGroupsClientListResponse, error) {
					return armnetwork.ApplicationSecurityGroupsClientListResponse{
						ApplicationSecurityGroupListResult: armnetwork.ApplicationSecurityGroupListResult{
							Value: []*armnetwork.ApplicationSecurityGroup{{ID: to.Ptr(testASGNativeID)}},
						},
					}, nil
				},
			})
		},
		newListAllPagerFn: func(_ *armnetwork.ApplicationSecurityGroupsClientListAllOptions) *runtime.Pager[armnetwork.ApplicationSecurityGroupsClientListAllResponse] {
			return runtime.NewPager(runtime.PagingHandler[armnetwork.ApplicationSecurityGroupsClientListAllResponse]{
				More: func(_ armnetwork.ApplicationSecurityGroupsClientListAllResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armnetwork.ApplicationSecurityGroupsClientListAllResponse) (armnetwork.ApplicationSecurityGroupsClientListAllResponse, error) {
					return armnetwork.ApplicationSecurityGroupsClientListAllResponse{
						ApplicationSecurityGroupListResult: armnetwork.ApplicationSecurityGroupListResult{
							Value: []*armnetwork.ApplicationSecurityGroup{{ID: to.Ptr(testASGNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestApplicationSecurityGroup(fake)

	mkProps := func() json.RawMessage {
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName": "rg-1",
			"name":              "asg-1",
			"location":          "eastus",
			"Tags":              []map[string]string{{"Key": "Environment", "Value": "test"}},
		})
		return props
	}

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testASGNativeID, got.ProgressResult.NativeID)

		var serialized map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &serialized))
		require.Equal(t, "asg-1", serialized["name"])
		require.Equal(t, "rg-1", serialized["resourceGroupName"])
		require.Equal(t, "eastus", serialized["location"])
		require.Equal(t, testASGNativeID, serialized["id"])
		require.Equal(t, []any{map[string]any{"Key": "Environment", "Value": "test"}}, serialized["Tags"])
	})

	t.Run("Create_forwards_location_and_tags", func(t *testing.T) {
		var seen armnetwork.ApplicationSecurityGroup
		var seenRG, seenName string
		fake.beginCreateOrUpdateFn = func(_ context.Context, rg, name string, params armnetwork.ApplicationSecurityGroup, _ *armnetwork.ApplicationSecurityGroupsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.ApplicationSecurityGroupsClientCreateOrUpdateResponse], error) {
			seen, seenRG, seenName = params, rg, name
			return newDonePoller(armnetwork.ApplicationSecurityGroupsClientCreateOrUpdateResponse{ApplicationSecurityGroup: model}), nil
		}
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, "rg-1", seenRG)
		require.Equal(t, "asg-1", seenName)
		require.Equal(t, "eastus", *seen.Location)
		require.Equal(t, "test", *seen.Tags["Environment"])
	})

	t.Run("Create_in_progress_returns_lro_request_id", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, _ armnetwork.ApplicationSecurityGroup, _ *armnetwork.ApplicationSecurityGroupsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.ApplicationSecurityGroupsClientCreateOrUpdateResponse], error) {
			return newInProgressPoller[armnetwork.ApplicationSecurityGroupsClientCreateOrUpdateResponse](), nil
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusInProgress, got.ProgressResult.OperationStatus)
		require.Equal(t, testASGNativeID, got.ProgressResult.NativeID)

		reqID, err := decodeLROStatus(got.ProgressResult.RequestID)
		require.NoError(t, err)
		require.Equal(t, lroOpCreate, reqID.OperationType)
		require.Equal(t, testASGNativeID, reqID.NativeID)

		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, _ armnetwork.ApplicationSecurityGroup, _ *armnetwork.ApplicationSecurityGroupsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.ApplicationSecurityGroupsClientCreateOrUpdateResponse], error) {
			return newDonePoller(armnetwork.ApplicationSecurityGroupsClientCreateOrUpdateResponse{ApplicationSecurityGroup: model}), nil
		}
	})

	t.Run("Create_requires_location", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"resourceGroupName": "rg-1", "name": "asg-1"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.Error(t, err)
	})

	t.Run("Create_requires_resourceGroupName", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "asg-1", "location": "eastus"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.Error(t, err)
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testASGNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
		require.Equal(t, ResourceTypeApplicationSecurityGroup, got.ResourceType)
	})

	t.Run("Read_not_found", func(t *testing.T) {
		fake.getFn = func(_ context.Context, _, _ string, _ *armnetwork.ApplicationSecurityGroupsClientGetOptions) (armnetwork.ApplicationSecurityGroupsClientGetResponse, error) {
			return armnetwork.ApplicationSecurityGroupsClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testASGNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)

		fake.getFn = func(_ context.Context, _, _ string, _ *armnetwork.ApplicationSecurityGroupsClientGetOptions) (armnetwork.ApplicationSecurityGroupsClientGetResponse, error) {
			return armnetwork.ApplicationSecurityGroupsClientGetResponse{ApplicationSecurityGroup: model}, nil
		}
	})

	t.Run("Update_upserts_via_CreateOrUpdate", func(t *testing.T) {
		var seen armnetwork.ApplicationSecurityGroup
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, params armnetwork.ApplicationSecurityGroup, _ *armnetwork.ApplicationSecurityGroupsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.ApplicationSecurityGroupsClientCreateOrUpdateResponse], error) {
			seen = params
			return newDonePoller(armnetwork.ApplicationSecurityGroupsClientCreateOrUpdateResponse{ApplicationSecurityGroup: model}), nil
		}
		desired, _ := json.Marshal(map[string]any{
			"resourceGroupName": "rg-1",
			"name":              "asg-1",
			"location":          "eastus",
			"Tags":              []map[string]string{{"Key": "Environment", "Value": "updated"}},
		})
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testASGNativeID,
			DesiredProperties: desired,
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, "updated", *seen.Tags["Environment"])
	})

	t.Run("Delete_in_progress_returns_lro_request_id", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testASGNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusInProgress, got.ProgressResult.OperationStatus)
		reqID, err := decodeLROStatus(got.ProgressResult.RequestID)
		require.NoError(t, err)
		require.Equal(t, lroOpDelete, reqID.OperationType)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _ string, _ *armnetwork.ApplicationSecurityGroupsClientBeginDeleteOptions) (*runtime.Poller[armnetwork.ApplicationSecurityGroupsClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testASGNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Status_rejects_unknown_operation", func(t *testing.T) {
		reqID, err := encodeLROStart("bogus", "token", testASGNativeID)
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
		require.Equal(t, []string{testASGNativeID}, got.NativeIDs)
	})

	t.Run("List_all", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Equal(t, []string{testASGNativeID}, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, _ armnetwork.ApplicationSecurityGroup, _ *armnetwork.ApplicationSecurityGroupsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.ApplicationSecurityGroupsClientCreateOrUpdateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 403}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

func TestApplicationSecurityGroupIDParts(t *testing.T) {
	rg, name, err := applicationSecurityGroupIDParts(testASGNativeID)
	require.NoError(t, err)
	require.Equal(t, "rg-1", rg)
	require.Equal(t, "asg-1", name)

	_, _, err = applicationSecurityGroupIDParts("/subscriptions/sub-1/resourceGroups/rg-1")
	require.Error(t, err)
}

// --- Test helpers ---

func newTestApplicationSecurityGroup(api applicationSecurityGroupsAPI) *ApplicationSecurityGroup {
	return &ApplicationSecurityGroup{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

type fakeApplicationSecurityGroupsAPI struct {
	beginCreateOrUpdateFn func(ctx context.Context, rgName, name string, params armnetwork.ApplicationSecurityGroup, opts *armnetwork.ApplicationSecurityGroupsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.ApplicationSecurityGroupsClientCreateOrUpdateResponse], error)
	getFn                 func(ctx context.Context, rgName, name string, opts *armnetwork.ApplicationSecurityGroupsClientGetOptions) (armnetwork.ApplicationSecurityGroupsClientGetResponse, error)
	beginDeleteFn         func(ctx context.Context, rgName, name string, opts *armnetwork.ApplicationSecurityGroupsClientBeginDeleteOptions) (*runtime.Poller[armnetwork.ApplicationSecurityGroupsClientDeleteResponse], error)
	newListPagerFn        func(rgName string, opts *armnetwork.ApplicationSecurityGroupsClientListOptions) *runtime.Pager[armnetwork.ApplicationSecurityGroupsClientListResponse]
	newListAllPagerFn     func(opts *armnetwork.ApplicationSecurityGroupsClientListAllOptions) *runtime.Pager[armnetwork.ApplicationSecurityGroupsClientListAllResponse]
}

func (f *fakeApplicationSecurityGroupsAPI) BeginCreateOrUpdate(ctx context.Context, rgName, name string, params armnetwork.ApplicationSecurityGroup, opts *armnetwork.ApplicationSecurityGroupsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.ApplicationSecurityGroupsClientCreateOrUpdateResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, rgName, name, params, opts)
}

func (f *fakeApplicationSecurityGroupsAPI) Get(ctx context.Context, rgName, name string, opts *armnetwork.ApplicationSecurityGroupsClientGetOptions) (armnetwork.ApplicationSecurityGroupsClientGetResponse, error) {
	return f.getFn(ctx, rgName, name, opts)
}

func (f *fakeApplicationSecurityGroupsAPI) BeginDelete(ctx context.Context, rgName, name string, opts *armnetwork.ApplicationSecurityGroupsClientBeginDeleteOptions) (*runtime.Poller[armnetwork.ApplicationSecurityGroupsClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, name, opts)
}

func (f *fakeApplicationSecurityGroupsAPI) NewListPager(rgName string, opts *armnetwork.ApplicationSecurityGroupsClientListOptions) *runtime.Pager[armnetwork.ApplicationSecurityGroupsClientListResponse] {
	return f.newListPagerFn(rgName, opts)
}

func (f *fakeApplicationSecurityGroupsAPI) NewListAllPager(opts *armnetwork.ApplicationSecurityGroupsClientListAllOptions) *runtime.Pager[armnetwork.ApplicationSecurityGroupsClientListAllResponse] {
	return f.newListAllPagerFn(opts)
}
