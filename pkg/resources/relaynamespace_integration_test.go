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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/relay/armrelay"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testRelayNamespaceNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Relay/namespaces/relay1"

func newTestRelayNamespace(api relayNamespacesAPI) *RelayNamespace {
	return &RelayNamespace{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func relayDesired(access string) []byte {
	out, _ := json.Marshal(map[string]any{
		"Tags":                []any{map[string]any{"Key": "env", "Value": "conformance"}},
		"name":                "relay1",
		"location":            "eastus",
		"resourceGroupName":   "rg-1",
		"skuName":             "Standard",
		"publicNetworkAccess": access,
	})
	return out
}

func TestRelayNamespace_CRUD(t *testing.T) {
	nsResult := armrelay.Namespace{
		ID:       to.Ptr(testRelayNamespaceNativeID),
		Name:     to.Ptr("relay1"),
		Location: to.Ptr("East US"),
		SKU: &armrelay.SKU{
			Name: to.Ptr(armrelay.SKUNameStandard),
			Tier: to.Ptr(armrelay.SKUTierStandard),
		},
		Properties: &armrelay.NamespaceProperties{
			PublicNetworkAccess: to.Ptr(armrelay.PublicNetworkAccessEnabled),
			ServiceBusEndpoint:  to.Ptr("https://relay1.servicebus.windows.net:443/"),
			MetricID:            to.Ptr("sub-1:relay1"),
			Status:              to.Ptr("Active"),
			ProvisioningState:   to.Ptr("Succeeded"),
			CreatedAt:           to.Ptr(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)),
			UpdatedAt:           to.Ptr(time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)),
		},
	}

	var sentCreate armrelay.Namespace
	var sentUpdate armrelay.UpdateParameters
	deleteCalls := 0
	fake := &fakeRelayNamespacesAPI{
		beginCreateOrUpdateFn: func(_ context.Context, _, name string, params armrelay.Namespace, _ *armrelay.NamespacesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armrelay.NamespacesClientCreateOrUpdateResponse], error) {
			require.Equal(t, "relay1", name)
			sentCreate = params
			return newDonePoller(armrelay.NamespacesClientCreateOrUpdateResponse{Namespace: nsResult}), nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armrelay.NamespacesClientGetOptions) (armrelay.NamespacesClientGetResponse, error) {
			return armrelay.NamespacesClientGetResponse{Namespace: nsResult}, nil
		},
		updateFn: func(_ context.Context, _, _ string, params armrelay.UpdateParameters, _ *armrelay.NamespacesClientUpdateOptions) (armrelay.NamespacesClientUpdateResponse, error) {
			sentUpdate = params
			return armrelay.NamespacesClientUpdateResponse{Namespace: nsResult}, nil
		},
		beginDeleteFn: func(_ context.Context, _, _ string, _ *armrelay.NamespacesClientBeginDeleteOptions) (*runtime.Poller[armrelay.NamespacesClientDeleteResponse], error) {
			deleteCalls++
			return newDonePoller(armrelay.NamespacesClientDeleteResponse{}), nil
		},
		newListPagerFn: func(_ *armrelay.NamespacesClientListOptions) *runtime.Pager[armrelay.NamespacesClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armrelay.NamespacesClientListResponse]{
				More: func(_ armrelay.NamespacesClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armrelay.NamespacesClientListResponse) (armrelay.NamespacesClientListResponse, error) {
					return armrelay.NamespacesClientListResponse{
						NamespaceListResult: armrelay.NamespaceListResult{
							Value: []*armrelay.Namespace{
								{ID: to.Ptr(testRelayNamespaceNativeID)},
								{ID: to.Ptr("/subscriptions/sub-1/resourceGroups/rg-2/providers/Microsoft.Relay/namespaces/relay2")},
							},
						},
					}, nil
				},
			})
		},
		newListByResourceGroupPagerFn: func(_ string, _ *armrelay.NamespacesClientListByResourceGroupOptions) *runtime.Pager[armrelay.NamespacesClientListByResourceGroupResponse] {
			return runtime.NewPager(runtime.PagingHandler[armrelay.NamespacesClientListByResourceGroupResponse]{
				More: func(_ armrelay.NamespacesClientListByResourceGroupResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armrelay.NamespacesClientListByResourceGroupResponse) (armrelay.NamespacesClientListByResourceGroupResponse, error) {
					return armrelay.NamespacesClientListByResourceGroupResponse{
						NamespaceListResult: armrelay.NamespaceListResult{
							Value: []*armrelay.Namespace{{ID: to.Ptr(testRelayNamespaceNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestRelayNamespace(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "relay1",
			Properties: relayDesired("Enabled"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testRelayNamespaceNativeID, got.ProgressResult.NativeID)

		require.Equal(t, armrelay.SKUNameStandard, *sentCreate.SKU.Name)
		// Relay has one tier; the schema carries a scalar skuName and the handler
		// fills in the matching tier.
		require.Equal(t, armrelay.SKUTierStandard, *sentCreate.SKU.Tier)
		require.Equal(t, armrelay.PublicNetworkAccessEnabled, *sentCreate.Properties.PublicNetworkAccess)
	})

	t.Run("Create_requires_location", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "relay1", "resourceGroupName": "rg-1"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "location is required")
	})

	t.Run("Create_requires_resource_group", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "relay1", "location": "eastus"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "resourceGroupName is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testRelayNamespaceNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "relay1", props["name"])
		// ARM returns "East US"; read must normalise or desired state drifts.
		require.Equal(t, "eastus", props["location"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "https://relay1.servicebus.windows.net:443/", props["serviceBusEndpoint"])
		require.Equal(t, "sub-1:relay1", props["metricId"])
		require.Equal(t, "Standard", props["skuName"])
		require.Equal(t, "Enabled", props["publicNetworkAccess"])
	})

	// Shared keys come from a separate GetKeys call and must not reach state on any
	// path.
	t.Run("keys_never_serialized", func(t *testing.T) {
		read, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testRelayNamespaceNativeID})
		require.NoError(t, err)
		for _, key := range []string{"primary", "secondary", "accountKey", "keyName"} {
			require.NotContains(t, read.Properties, key)
		}
	})

	// Update is a synchronous PATCH: it must report Success directly, never
	// InProgress with a resume token.
	t.Run("Update_is_synchronous", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testRelayNamespaceNativeID,
			DesiredProperties: relayDesired("Disabled"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testRelayNamespaceNativeID, got.ProgressResult.NativeID)
		require.Empty(t, got.ProgressResult.RequestID)
		require.Equal(t, armrelay.PublicNetworkAccessDisabled, *sentUpdate.Properties.PublicNetworkAccess)
		// Tags must ride along on the update body: without them ARM leaves the old
		// tags in place and conformance [Update] fails with "Array Tags[0] has no
		// matching element in actual".
		require.Equal(t, "conformance", *sentUpdate.Tags["env"])
	})

	t.Run("Delete", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testRelayNamespaceNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _ string, _ *armrelay.NamespacesClientBeginDeleteOptions) (*runtime.Poller[armrelay.NamespacesClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testRelayNamespaceNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_resource_group", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testRelayNamespaceNativeID}, got.NativeIDs)
	})

	t.Run("List_without_group_is_subscription_wide", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 2)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, _ armrelay.Namespace, _ *armrelay.NamespacesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armrelay.NamespacesClientCreateOrUpdateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 409}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "relay1", Properties: relayDesired("Disabled"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

// createdAt/updatedAt are timestamps the service moves on its own, and
// status/provisioningState are not desired state: surfacing any of them would read
// back as drift on every sync.
func TestRelayNamespace_ReadDropsServiceBookkeeping(t *testing.T) {
	fake := &fakeRelayNamespacesAPI{
		getFn: func(_ context.Context, _, _ string, _ *armrelay.NamespacesClientGetOptions) (armrelay.NamespacesClientGetResponse, error) {
			return armrelay.NamespacesClientGetResponse{Namespace: armrelay.Namespace{
				ID:   to.Ptr(testRelayNamespaceNativeID),
				Name: to.Ptr("relay1"),
				Properties: &armrelay.NamespaceProperties{
					CreatedAt:         to.Ptr(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)),
					UpdatedAt:         to.Ptr(time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)),
					Status:            to.Ptr("Active"),
					ProvisioningState: to.Ptr("Succeeded"),
				},
			}}, nil
		},
	}
	got, err := newTestRelayNamespace(fake).Read(context.Background(), &resource.ReadRequest{NativeID: testRelayNamespaceNativeID})
	require.NoError(t, err)
	for _, key := range []string{"createdAt", "updatedAt", "status", "provisioningState"} {
		require.NotContains(t, got.Properties, key)
	}
}

func TestRelayNamespace_ReadNotFound(t *testing.T) {
	fake := &fakeRelayNamespacesAPI{
		getFn: func(_ context.Context, _, _ string, _ *armrelay.NamespacesClientGetOptions) (armrelay.NamespacesClientGetResponse, error) {
			return armrelay.NamespacesClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestRelayNamespace(fake).Read(context.Background(), &resource.ReadRequest{NativeID: testRelayNamespaceNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeRelayNamespacesAPI struct {
	beginCreateOrUpdateFn         func(ctx context.Context, rgName, name string, params armrelay.Namespace, options *armrelay.NamespacesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armrelay.NamespacesClientCreateOrUpdateResponse], error)
	getFn                         func(ctx context.Context, rgName, name string, options *armrelay.NamespacesClientGetOptions) (armrelay.NamespacesClientGetResponse, error)
	updateFn                      func(ctx context.Context, rgName, name string, params armrelay.UpdateParameters, options *armrelay.NamespacesClientUpdateOptions) (armrelay.NamespacesClientUpdateResponse, error)
	beginDeleteFn                 func(ctx context.Context, rgName, name string, options *armrelay.NamespacesClientBeginDeleteOptions) (*runtime.Poller[armrelay.NamespacesClientDeleteResponse], error)
	newListPagerFn                func(options *armrelay.NamespacesClientListOptions) *runtime.Pager[armrelay.NamespacesClientListResponse]
	newListByResourceGroupPagerFn func(rgName string, options *armrelay.NamespacesClientListByResourceGroupOptions) *runtime.Pager[armrelay.NamespacesClientListByResourceGroupResponse]
}

func (f *fakeRelayNamespacesAPI) BeginCreateOrUpdate(ctx context.Context, rgName, name string, params armrelay.Namespace, options *armrelay.NamespacesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armrelay.NamespacesClientCreateOrUpdateResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, rgName, name, params, options)
}

func (f *fakeRelayNamespacesAPI) Get(ctx context.Context, rgName, name string, options *armrelay.NamespacesClientGetOptions) (armrelay.NamespacesClientGetResponse, error) {
	return f.getFn(ctx, rgName, name, options)
}

func (f *fakeRelayNamespacesAPI) Update(ctx context.Context, rgName, name string, params armrelay.UpdateParameters, options *armrelay.NamespacesClientUpdateOptions) (armrelay.NamespacesClientUpdateResponse, error) {
	return f.updateFn(ctx, rgName, name, params, options)
}

func (f *fakeRelayNamespacesAPI) BeginDelete(ctx context.Context, rgName, name string, options *armrelay.NamespacesClientBeginDeleteOptions) (*runtime.Poller[armrelay.NamespacesClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, name, options)
}

func (f *fakeRelayNamespacesAPI) NewListPager(options *armrelay.NamespacesClientListOptions) *runtime.Pager[armrelay.NamespacesClientListResponse] {
	return f.newListPagerFn(options)
}

func (f *fakeRelayNamespacesAPI) NewListByResourceGroupPager(rgName string, options *armrelay.NamespacesClientListByResourceGroupOptions) *runtime.Pager[armrelay.NamespacesClientListByResourceGroupResponse] {
	return f.newListByResourceGroupPagerFn(rgName, options)
}
