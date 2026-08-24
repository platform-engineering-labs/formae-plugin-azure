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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/notificationhubs/armnotificationhubs"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testNHNamespaceNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.NotificationHubs/namespaces/nh1"

func newTestNHNamespace(api notificationHubNamespacesAPI) *NotificationHubNamespace {
	return &NotificationHubNamespace{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func nhNamespaceDesired(tagValue string) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":              "nh1",
		"location":          "eastus",
		"resourceGroupName": "rg-1",
		"skuName":           "Basic",
		"namespaceType":     "NotificationHub",
		"Tags":              []any{map[string]any{"Key": "env", "Value": tagValue}},
	})
	return out
}

func TestNotificationHubNamespace_CRUD(t *testing.T) {
	nsResult := armnotificationhubs.NamespaceResource{
		ID:       to.Ptr(testNHNamespaceNativeID),
		Name:     to.Ptr("nh1"),
		Location: to.Ptr("East US"),
		SKU: &armnotificationhubs.SKU{
			Name: to.Ptr(armnotificationhubs.SKUNameBasic),
			Tier: to.Ptr("Basic"),
		},
		Properties: &armnotificationhubs.NamespaceProperties{
			NamespaceType:      to.Ptr(armnotificationhubs.NamespaceTypeNotificationHub),
			ServiceBusEndpoint: to.Ptr("https://nh1.servicebus.windows.net:443/"),
			MetricID:           to.Ptr("sub-1:nh1"),
			Status:             to.Ptr("Active"),
			ProvisioningState:  to.Ptr("Succeeded"),
			ScaleUnit:          to.Ptr("eu-1"),
			Region:             to.Ptr("East US"),
			DataCenter:         to.Ptr("eastus"),
			SubscriptionID:     to.Ptr("sub-1"),
			Enabled:            to.Ptr(true),
			Critical:           to.Ptr(false),
			CreatedAt:          to.Ptr(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)),
			UpdatedAt:          to.Ptr(time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)),
		},
		Tags: map[string]*string{"env": to.Ptr("test")},
	}

	var sentCreate armnotificationhubs.NamespaceCreateOrUpdateParameters
	var sentPatch armnotificationhubs.NamespacePatchParameters
	deleteCalls := 0
	fake := &fakeNHNamespacesAPI{
		createOrUpdateFn: func(_ context.Context, _, name string, params armnotificationhubs.NamespaceCreateOrUpdateParameters, _ *armnotificationhubs.NamespacesClientCreateOrUpdateOptions) (armnotificationhubs.NamespacesClientCreateOrUpdateResponse, error) {
			require.Equal(t, "nh1", name)
			sentCreate = params
			return armnotificationhubs.NamespacesClientCreateOrUpdateResponse{NamespaceResource: nsResult}, nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armnotificationhubs.NamespacesClientGetOptions) (armnotificationhubs.NamespacesClientGetResponse, error) {
			return armnotificationhubs.NamespacesClientGetResponse{NamespaceResource: nsResult}, nil
		},
		patchFn: func(_ context.Context, _, _ string, params armnotificationhubs.NamespacePatchParameters, _ *armnotificationhubs.NamespacesClientPatchOptions) (armnotificationhubs.NamespacesClientPatchResponse, error) {
			sentPatch = params
			return armnotificationhubs.NamespacesClientPatchResponse{NamespaceResource: nsResult}, nil
		},
		beginDeleteFn: func(_ context.Context, _, _ string, _ *armnotificationhubs.NamespacesClientBeginDeleteOptions) (*runtime.Poller[armnotificationhubs.NamespacesClientDeleteResponse], error) {
			deleteCalls++
			return newDonePoller(armnotificationhubs.NamespacesClientDeleteResponse{}), nil
		},
		newListPagerFn: func(_ string, _ *armnotificationhubs.NamespacesClientListOptions) *runtime.Pager[armnotificationhubs.NamespacesClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armnotificationhubs.NamespacesClientListResponse]{
				More: func(_ armnotificationhubs.NamespacesClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armnotificationhubs.NamespacesClientListResponse) (armnotificationhubs.NamespacesClientListResponse, error) {
					return armnotificationhubs.NamespacesClientListResponse{
						NamespaceListResult: armnotificationhubs.NamespaceListResult{
							Value: []*armnotificationhubs.NamespaceResource{{ID: to.Ptr(testNHNamespaceNativeID)}},
						},
					}, nil
				},
			})
		},
		newListAllPagerFn: func(_ *armnotificationhubs.NamespacesClientListAllOptions) *runtime.Pager[armnotificationhubs.NamespacesClientListAllResponse] {
			return runtime.NewPager(runtime.PagingHandler[armnotificationhubs.NamespacesClientListAllResponse]{
				More: func(_ armnotificationhubs.NamespacesClientListAllResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armnotificationhubs.NamespacesClientListAllResponse) (armnotificationhubs.NamespacesClientListAllResponse, error) {
					return armnotificationhubs.NamespacesClientListAllResponse{
						NamespaceListResult: armnotificationhubs.NamespaceListResult{
							Value: []*armnotificationhubs.NamespaceResource{
								{ID: to.Ptr(testNHNamespaceNativeID)},
								{ID: to.Ptr("/subscriptions/sub-1/resourceGroups/rg-2/providers/Microsoft.NotificationHubs/namespaces/nh2")},
							},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestNHNamespace(fake)

	// Create is synchronous here: success comes back directly, with no resume token.
	t.Run("Create_is_synchronous", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "nh1", Properties: nhNamespaceDesired("test"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testNHNamespaceNativeID, got.ProgressResult.NativeID)
		require.Empty(t, got.ProgressResult.RequestID)

		require.Equal(t, armnotificationhubs.SKUNameBasic, *sentCreate.SKU.Name)
		// Only the sku NAME is sent: ARM fills in tier/size/family/capacity, and
		// sending our own would read back as drift.
		require.Nil(t, sentCreate.SKU.Tier)
		require.Equal(t, armnotificationhubs.NamespaceTypeNotificationHub, *sentCreate.Properties.NamespaceType)
		require.Equal(t, "test", *sentCreate.Tags["env"])
	})

	t.Run("Create_requires_location", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "nh1", "resourceGroupName": "rg-1"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "location is required")
	})

	t.Run("Create_requires_resource_group", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "nh1", "location": "eastus"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "resourceGroupName is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testNHNamespaceNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "nh1", props["name"])
		// ARM returns "East US"; read must normalise or desired state drifts.
		require.Equal(t, "eastus", props["location"])
		require.Equal(t, "Basic", props["skuName"])
		require.Equal(t, "NotificationHub", props["namespaceType"])
		require.Equal(t, "https://nh1.servicebus.windows.net:443/", props["serviceBusEndpoint"])
		require.Equal(t, "sub-1:nh1", props["metricId"])
	})

	// This ARM type returns a lot of service bookkeeping. None of it is desired
	// state, and the timestamps and status move on their own, so all of it must be
	// dropped or every sync would report drift.
	t.Run("Read_drops_service_bookkeeping", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testNHNamespaceNativeID})
		require.NoError(t, err)
		for _, key := range []string{
			"createdAt", "updatedAt", "status", "provisioningState",
			"scaleUnit", "dataCenter", "region", "subscriptionId", "enabled", "critical",
		} {
			require.NotContains(t, got.Properties, key)
		}
	})

	// Keys come from a separate ListKeys call and must not reach state on any path.
	t.Run("keys_never_serialized", func(t *testing.T) {
		read, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testNHNamespaceNativeID})
		require.NoError(t, err)
		for _, key := range []string{"primaryKey", "secondaryKey", "primaryConnectionString"} {
			require.NotContains(t, read.Properties, key)
		}
	})

	// The update verb is Patch, not Update, and it is synchronous — never
	// InProgress with a resume token.
	t.Run("Update_uses_patch", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testNHNamespaceNativeID,
			DesiredProperties: nhNamespaceDesired("updated"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Empty(t, got.ProgressResult.RequestID)
		require.Equal(t, "updated", *sentPatch.Tags["env"])
		require.Equal(t, armnotificationhubs.SKUNameBasic, *sentPatch.SKU.Name)
	})

	// Delete is the only LRO on this API.
	t.Run("Delete", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testNHNamespaceNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _ string, _ *armnotificationhubs.NamespacesClientBeginDeleteOptions) (*runtime.Poller[armnotificationhubs.NamespacesClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testNHNamespaceNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_resource_group", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testNHNamespaceNativeID}, got.NativeIDs)
	})

	t.Run("List_without_group_is_subscription_wide", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 2)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.createOrUpdateFn = func(_ context.Context, _, _ string, _ armnotificationhubs.NamespaceCreateOrUpdateParameters, _ *armnotificationhubs.NamespacesClientCreateOrUpdateOptions) (armnotificationhubs.NamespacesClientCreateOrUpdateResponse, error) {
			return armnotificationhubs.NamespacesClientCreateOrUpdateResponse{}, &azcore.ResponseError{StatusCode: 409}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "nh1", Properties: nhNamespaceDesired("test"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

func TestNotificationHubNamespace_ReadNotFound(t *testing.T) {
	fake := &fakeNHNamespacesAPI{
		getFn: func(_ context.Context, _, _ string, _ *armnotificationhubs.NamespacesClientGetOptions) (armnotificationhubs.NamespacesClientGetResponse, error) {
			return armnotificationhubs.NamespacesClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestNHNamespace(fake).Read(context.Background(), &resource.ReadRequest{NativeID: testNHNamespaceNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeNHNamespacesAPI struct {
	createOrUpdateFn  func(ctx context.Context, rgName, name string, params armnotificationhubs.NamespaceCreateOrUpdateParameters, options *armnotificationhubs.NamespacesClientCreateOrUpdateOptions) (armnotificationhubs.NamespacesClientCreateOrUpdateResponse, error)
	getFn             func(ctx context.Context, rgName, name string, options *armnotificationhubs.NamespacesClientGetOptions) (armnotificationhubs.NamespacesClientGetResponse, error)
	patchFn           func(ctx context.Context, rgName, name string, params armnotificationhubs.NamespacePatchParameters, options *armnotificationhubs.NamespacesClientPatchOptions) (armnotificationhubs.NamespacesClientPatchResponse, error)
	beginDeleteFn     func(ctx context.Context, rgName, name string, options *armnotificationhubs.NamespacesClientBeginDeleteOptions) (*runtime.Poller[armnotificationhubs.NamespacesClientDeleteResponse], error)
	newListPagerFn    func(rgName string, options *armnotificationhubs.NamespacesClientListOptions) *runtime.Pager[armnotificationhubs.NamespacesClientListResponse]
	newListAllPagerFn func(options *armnotificationhubs.NamespacesClientListAllOptions) *runtime.Pager[armnotificationhubs.NamespacesClientListAllResponse]
}

func (f *fakeNHNamespacesAPI) CreateOrUpdate(ctx context.Context, rgName, name string, params armnotificationhubs.NamespaceCreateOrUpdateParameters, options *armnotificationhubs.NamespacesClientCreateOrUpdateOptions) (armnotificationhubs.NamespacesClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, name, params, options)
}

func (f *fakeNHNamespacesAPI) Get(ctx context.Context, rgName, name string, options *armnotificationhubs.NamespacesClientGetOptions) (armnotificationhubs.NamespacesClientGetResponse, error) {
	return f.getFn(ctx, rgName, name, options)
}

func (f *fakeNHNamespacesAPI) Patch(ctx context.Context, rgName, name string, params armnotificationhubs.NamespacePatchParameters, options *armnotificationhubs.NamespacesClientPatchOptions) (armnotificationhubs.NamespacesClientPatchResponse, error) {
	return f.patchFn(ctx, rgName, name, params, options)
}

func (f *fakeNHNamespacesAPI) BeginDelete(ctx context.Context, rgName, name string, options *armnotificationhubs.NamespacesClientBeginDeleteOptions) (*runtime.Poller[armnotificationhubs.NamespacesClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, name, options)
}

func (f *fakeNHNamespacesAPI) NewListPager(rgName string, options *armnotificationhubs.NamespacesClientListOptions) *runtime.Pager[armnotificationhubs.NamespacesClientListResponse] {
	return f.newListPagerFn(rgName, options)
}

func (f *fakeNHNamespacesAPI) NewListAllPager(options *armnotificationhubs.NamespacesClientListAllOptions) *runtime.Pager[armnotificationhubs.NamespacesClientListAllResponse] {
	return f.newListAllPagerFn(options)
}
