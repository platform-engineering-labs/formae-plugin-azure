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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/desktopvirtualization/armdesktopvirtualization"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testAvdHostPoolNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.DesktopVirtualization/hostPools/hp-1"

func newTestAvdHostPool(api avdHostPoolsAPI) *AvdHostPool {
	return &AvdHostPool{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func avdHostPoolDesired(tagValue string) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":                  "hp-1",
		"location":              "eastus",
		"resourceGroupName":     "rg-1",
		"hostPoolType":          "Pooled",
		"loadBalancerType":      "BreadthFirst",
		"preferredAppGroupType": "RailApplications",
		"maxSessionLimit":       10,
		"startVmOnConnect":      false,
		"validationEnvironment": false,
		"description":           "conformance host pool",
		"friendlyName":          "hp one",
		"registrationInfo": map[string]any{
			"registrationTokenOperation": "None",
		},
		"Tags": []map[string]string{{"Key": "env", "Value": tagValue}},
	})
	return out
}

func TestAvdHostPool_CRUD(t *testing.T) {
	// The response deliberately carries the service-managed fields the read path
	// must drop — the token, the application group back-references and the
	// internal ids — plus the spaced-out region form ARM answers with.
	poolResult := armdesktopvirtualization.HostPool{
		ID:       to.Ptr(testAvdHostPoolNativeID),
		Name:     to.Ptr("hp-1"),
		Location: to.Ptr("East US"),
		Properties: &armdesktopvirtualization.HostPoolProperties{
			HostPoolType:          to.Ptr(armdesktopvirtualization.HostPoolTypePooled),
			LoadBalancerType:      to.Ptr(armdesktopvirtualization.LoadBalancerTypeBreadthFirst),
			PreferredAppGroupType: to.Ptr(armdesktopvirtualization.PreferredAppGroupTypeRailApplications),
			MaxSessionLimit:       to.Ptr(int32(10)),
			StartVMOnConnect:      to.Ptr(false),
			ValidationEnvironment: to.Ptr(false),
			Description:           to.Ptr("conformance host pool"),
			FriendlyName:          to.Ptr("hp one"),
			RegistrationInfo: &armdesktopvirtualization.RegistrationInfo{
				Token:                      to.Ptr("a-live-joining-credential"),
				RegistrationTokenOperation: to.Ptr(armdesktopvirtualization.RegistrationTokenOperationNone),
			},
			ApplicationGroupReferences: []*string{to.Ptr("/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.DesktopVirtualization/applicationGroups/ag-1")},
			ObjectID:                   to.Ptr("00000000-0000-0000-0000-000000000001"),
			CloudPcResource:            to.Ptr(false),
		},
		Tags: map[string]*string{"env": to.Ptr("conformance")},
	}

	var sentCreate armdesktopvirtualization.HostPool
	var sentUpdate *armdesktopvirtualization.HostPoolPatch
	var sentDeleteForce *bool
	deleteCalls := 0
	fake := &fakeAvdHostPoolsAPI{
		createOrUpdateFn: func(_ context.Context, rgName, name string, params armdesktopvirtualization.HostPool, _ *armdesktopvirtualization.HostPoolsClientCreateOrUpdateOptions) (armdesktopvirtualization.HostPoolsClientCreateOrUpdateResponse, error) {
			require.Equal(t, "rg-1", rgName)
			require.Equal(t, "hp-1", name)
			sentCreate = params
			return armdesktopvirtualization.HostPoolsClientCreateOrUpdateResponse{HostPool: poolResult}, nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armdesktopvirtualization.HostPoolsClientGetOptions) (armdesktopvirtualization.HostPoolsClientGetResponse, error) {
			return armdesktopvirtualization.HostPoolsClientGetResponse{HostPool: poolResult}, nil
		},
		updateFn: func(_ context.Context, _, _ string, options *armdesktopvirtualization.HostPoolsClientUpdateOptions) (armdesktopvirtualization.HostPoolsClientUpdateResponse, error) {
			sentUpdate = options.HostPool
			return armdesktopvirtualization.HostPoolsClientUpdateResponse{HostPool: poolResult}, nil
		},
		deleteFn: func(_ context.Context, _, _ string, options *armdesktopvirtualization.HostPoolsClientDeleteOptions) (armdesktopvirtualization.HostPoolsClientDeleteResponse, error) {
			deleteCalls++
			if options != nil {
				sentDeleteForce = options.Force
			}
			return armdesktopvirtualization.HostPoolsClientDeleteResponse{}, nil
		},
		newListPagerFn: func(_ *armdesktopvirtualization.HostPoolsClientListOptions) *runtime.Pager[armdesktopvirtualization.HostPoolsClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armdesktopvirtualization.HostPoolsClientListResponse]{
				More: func(armdesktopvirtualization.HostPoolsClientListResponse) bool { return false },
				Fetcher: func(context.Context, *armdesktopvirtualization.HostPoolsClientListResponse) (armdesktopvirtualization.HostPoolsClientListResponse, error) {
					return armdesktopvirtualization.HostPoolsClientListResponse{
						HostPoolList: armdesktopvirtualization.HostPoolList{
							Value: []*armdesktopvirtualization.HostPool{{ID: to.Ptr(testAvdHostPoolNativeID)}},
						},
					}, nil
				},
			})
		},
		newListByResourceGroupPagerFn: func(rgName string, _ *armdesktopvirtualization.HostPoolsClientListByResourceGroupOptions) *runtime.Pager[armdesktopvirtualization.HostPoolsClientListByResourceGroupResponse] {
			require.Equal(t, "rg-1", rgName)
			return runtime.NewPager(runtime.PagingHandler[armdesktopvirtualization.HostPoolsClientListByResourceGroupResponse]{
				More: func(armdesktopvirtualization.HostPoolsClientListByResourceGroupResponse) bool { return false },
				Fetcher: func(context.Context, *armdesktopvirtualization.HostPoolsClientListByResourceGroupResponse) (armdesktopvirtualization.HostPoolsClientListByResourceGroupResponse, error) {
					return armdesktopvirtualization.HostPoolsClientListByResourceGroupResponse{
						HostPoolList: armdesktopvirtualization.HostPoolList{
							Value: []*armdesktopvirtualization.HostPool{{ID: to.Ptr(testAvdHostPoolNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestAvdHostPool(fake)

	t.Run("Create_is_synchronous", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "hp-1",
			Properties: avdHostPoolDesired("conformance"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testAvdHostPoolNativeID, got.ProgressResult.NativeID)
		// armdesktopvirtualization has no BeginX anywhere, so no resume token is
		// minted for any AVD type.
		require.Empty(t, got.ProgressResult.RequestID)

		require.Equal(t, "eastus", *sentCreate.Location)
		require.Equal(t, armdesktopvirtualization.HostPoolTypePooled, *sentCreate.Properties.HostPoolType)
		require.Equal(t, armdesktopvirtualization.LoadBalancerTypeBreadthFirst, *sentCreate.Properties.LoadBalancerType)
		require.Equal(t, armdesktopvirtualization.PreferredAppGroupTypeRailApplications, *sentCreate.Properties.PreferredAppGroupType)
		require.Equal(t, int32(10), *sentCreate.Properties.MaxSessionLimit)
		require.False(t, *sentCreate.Properties.StartVMOnConnect)
		require.Equal(t, "conformance", *sentCreate.Tags["env"])
		// A "None" registration-token operation reaches ARM without an expiry.
		require.Equal(t, armdesktopvirtualization.RegistrationTokenOperationNone,
			*sentCreate.Properties.RegistrationInfo.RegistrationTokenOperation)
		require.Nil(t, sentCreate.Properties.RegistrationInfo.ExpirationTime)
	})

	t.Run("Create_requires_resource_group", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "hp-1", "location": "eastus", "hostPoolType": "Pooled",
			"loadBalancerType": "BreadthFirst", "preferredAppGroupType": "Desktop",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "resourceGroupName is required")
	})

	t.Run("Create_requires_location", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "hp-1", "resourceGroupName": "rg-1", "hostPoolType": "Pooled",
			"loadBalancerType": "BreadthFirst", "preferredAppGroupType": "Desktop",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "location is required")
	})

	t.Run("Create_requires_host_pool_type", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "hp-1", "resourceGroupName": "rg-1", "location": "eastus",
			"loadBalancerType": "BreadthFirst", "preferredAppGroupType": "Desktop",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "hostPoolType is required")
	})

	// ARM demands an expiry in the 1-hour-to-30-day window whenever it is asked
	// to mint a token, so an Update with no expirationTime is refused here rather
	// than sent and rejected with an opaque BadRequest.
	t.Run("Create_rejects_token_update_without_expiry", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "hp-1", "resourceGroupName": "rg-1", "location": "eastus",
			"hostPoolType": "Pooled", "loadBalancerType": "BreadthFirst",
			"preferredAppGroupType": "RailApplications",
			"registrationInfo":      map[string]any{"registrationTokenOperation": "Update"},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "registrationInfo.expirationTime is required")
	})

	t.Run("Create_accepts_token_update_with_expiry", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "hp-1", "resourceGroupName": "rg-1", "location": "eastus",
			"hostPoolType": "Pooled", "loadBalancerType": "BreadthFirst",
			"preferredAppGroupType": "RailApplications",
			"registrationInfo": map[string]any{
				"registrationTokenOperation": "Update",
				"expirationTime":             "2026-09-03T12:00:00Z",
			},
		})
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, 2026, sentCreate.Properties.RegistrationInfo.ExpirationTime.Year())
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testAvdHostPoolNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "hp-1", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "Pooled", props["hostPoolType"])
		require.Equal(t, "BreadthFirst", props["loadBalancerType"])
		require.Equal(t, "RailApplications", props["preferredAppGroupType"])
		require.Equal(t, float64(10), props["maxSessionLimit"])
		require.Equal(t, false, props["startVmOnConnect"])
		require.Equal(t, false, props["validationEnvironment"])
		// ARM answers "East US"; desired state carries the compact form.
		require.Equal(t, "eastus", props["location"])
		require.Equal(t, []any{map[string]any{"Key": "env", "Value": "conformance"}}, props["Tags"])
	})

	// The registration token is a live joining credential and the operation is an
	// imperative verb rather than state, so the whole block is write-only. The
	// application group back-references grow every time an application group
	// points at this pool, so surfacing them would report drift the moment one
	// exists.
	t.Run("Read_drops_write_only_and_service_state", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testAvdHostPoolNativeID})
		require.NoError(t, err)
		for _, key := range []string{
			"registrationInfo", "token", "a-live-joining-credential",
			"applicationGroupReferences", "objectId", "cloudPcResource",
		} {
			require.NotContains(t, got.Properties, key)
		}
	})

	// ARM answers Get with "" for a description that was never set, and desired
	// state carries the field absent, so the empty string must not be emitted.
	t.Run("Read_drops_empty_free_text", func(t *testing.T) {
		fake.getFn = func(context.Context, string, string, *armdesktopvirtualization.HostPoolsClientGetOptions) (armdesktopvirtualization.HostPoolsClientGetResponse, error) {
			return armdesktopvirtualization.HostPoolsClientGetResponse{HostPool: armdesktopvirtualization.HostPool{
				ID:   to.Ptr(testAvdHostPoolNativeID),
				Name: to.Ptr("hp-1"),
				Properties: &armdesktopvirtualization.HostPoolProperties{
					HostPoolType: to.Ptr(armdesktopvirtualization.HostPoolTypePooled),
					Description:  to.Ptr(""),
					FriendlyName: to.Ptr(""),
				},
			}}, nil
		}
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testAvdHostPoolNativeID})
		require.NoError(t, err)
		require.NotContains(t, got.Properties, "description")
		require.NotContains(t, got.Properties, "friendlyName")
		fake.getFn = func(context.Context, string, string, *armdesktopvirtualization.HostPoolsClientGetOptions) (armdesktopvirtualization.HostPoolsClientGetResponse, error) {
			return armdesktopvirtualization.HostPoolsClientGetResponse{HostPool: poolResult}, nil
		}
	})

	// hostPoolType is createOnly because ARM's HostPoolPatchProperties has no
	// field for it: a PATCH that appeared to change it would silently do nothing.
	t.Run("Update_patches_mutable_fields_only", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testAvdHostPoolNativeID,
			DesiredProperties: avdHostPoolDesired("conformance-updated"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, armdesktopvirtualization.LoadBalancerTypeBreadthFirst, *sentUpdate.Properties.LoadBalancerType)
		require.Equal(t, int32(10), *sentUpdate.Properties.MaxSessionLimit)
		require.Equal(t, "conformance-updated", *sentUpdate.Tags["env"])
		require.Equal(t, armdesktopvirtualization.RegistrationTokenOperationNone,
			*sentUpdate.Properties.RegistrationInfo.RegistrationTokenOperation)
	})

	// A pool with a session host still registered is refused without force, and
	// since no session host is modelled here such a host can only have arrived
	// out of band — leaving the pool undeletable would leak it.
	t.Run("Delete_forces", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testAvdHostPoolNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Empty(t, got.ProgressResult.RequestID)
		require.Equal(t, before+1, deleteCalls)
		require.NotNil(t, sentDeleteForce)
		require.True(t, *sentDeleteForce)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(context.Context, string, string, *armdesktopvirtualization.HostPoolsClientDeleteOptions) (armdesktopvirtualization.HostPoolsClientDeleteResponse, error) {
			return armdesktopvirtualization.HostPoolsClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testAvdHostPoolNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_resource_group", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testAvdHostPoolNativeID}, got.NativeIDs)
	})

	t.Run("List_falls_back_to_subscription_wide", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Equal(t, []string{testAvdHostPoolNativeID}, got.NativeIDs)
	})

	// A dropped provider error is the failure this plugin has 51 existing
	// instances of, so assert the cause survives onto StatusMessage.
	t.Run("Azure_error_maps_to_failure_with_cause", func(t *testing.T) {
		fake.createOrUpdateFn = func(context.Context, string, string, armdesktopvirtualization.HostPool, *armdesktopvirtualization.HostPoolsClientCreateOrUpdateOptions) (armdesktopvirtualization.HostPoolsClientCreateOrUpdateResponse, error) {
			return armdesktopvirtualization.HostPoolsClientCreateOrUpdateResponse{}, &azcore.ResponseError{StatusCode: 409, ErrorCode: "Conflict"}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "hp-1", Properties: avdHostPoolDesired("conformance"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.Contains(t, got.ProgressResult.StatusMessage, "Conflict")
	})
}

func TestAvdHostPool_ReadNotFound(t *testing.T) {
	fake := &fakeAvdHostPoolsAPI{
		getFn: func(context.Context, string, string, *armdesktopvirtualization.HostPoolsClientGetOptions) (armdesktopvirtualization.HostPoolsClientGetResponse, error) {
			return armdesktopvirtualization.HostPoolsClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestAvdHostPool(fake).Read(context.Background(),
		&resource.ReadRequest{NativeID: testAvdHostPoolNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeAvdHostPoolsAPI struct {
	createOrUpdateFn              func(ctx context.Context, rgName, name string, params armdesktopvirtualization.HostPool, options *armdesktopvirtualization.HostPoolsClientCreateOrUpdateOptions) (armdesktopvirtualization.HostPoolsClientCreateOrUpdateResponse, error)
	getFn                         func(ctx context.Context, rgName, name string, options *armdesktopvirtualization.HostPoolsClientGetOptions) (armdesktopvirtualization.HostPoolsClientGetResponse, error)
	updateFn                      func(ctx context.Context, rgName, name string, options *armdesktopvirtualization.HostPoolsClientUpdateOptions) (armdesktopvirtualization.HostPoolsClientUpdateResponse, error)
	deleteFn                      func(ctx context.Context, rgName, name string, options *armdesktopvirtualization.HostPoolsClientDeleteOptions) (armdesktopvirtualization.HostPoolsClientDeleteResponse, error)
	newListPagerFn                func(options *armdesktopvirtualization.HostPoolsClientListOptions) *runtime.Pager[armdesktopvirtualization.HostPoolsClientListResponse]
	newListByResourceGroupPagerFn func(rgName string, options *armdesktopvirtualization.HostPoolsClientListByResourceGroupOptions) *runtime.Pager[armdesktopvirtualization.HostPoolsClientListByResourceGroupResponse]
}

func (f *fakeAvdHostPoolsAPI) CreateOrUpdate(ctx context.Context, rgName, name string, params armdesktopvirtualization.HostPool, options *armdesktopvirtualization.HostPoolsClientCreateOrUpdateOptions) (armdesktopvirtualization.HostPoolsClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, name, params, options)
}

func (f *fakeAvdHostPoolsAPI) Get(ctx context.Context, rgName, name string, options *armdesktopvirtualization.HostPoolsClientGetOptions) (armdesktopvirtualization.HostPoolsClientGetResponse, error) {
	return f.getFn(ctx, rgName, name, options)
}

func (f *fakeAvdHostPoolsAPI) Update(ctx context.Context, rgName, name string, options *armdesktopvirtualization.HostPoolsClientUpdateOptions) (armdesktopvirtualization.HostPoolsClientUpdateResponse, error) {
	return f.updateFn(ctx, rgName, name, options)
}

func (f *fakeAvdHostPoolsAPI) Delete(ctx context.Context, rgName, name string, options *armdesktopvirtualization.HostPoolsClientDeleteOptions) (armdesktopvirtualization.HostPoolsClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, name, options)
}

func (f *fakeAvdHostPoolsAPI) NewListPager(options *armdesktopvirtualization.HostPoolsClientListOptions) *runtime.Pager[armdesktopvirtualization.HostPoolsClientListResponse] {
	return f.newListPagerFn(options)
}

func (f *fakeAvdHostPoolsAPI) NewListByResourceGroupPager(rgName string, options *armdesktopvirtualization.HostPoolsClientListByResourceGroupOptions) *runtime.Pager[armdesktopvirtualization.HostPoolsClientListByResourceGroupResponse] {
	return f.newListByResourceGroupPagerFn(rgName, options)
}
