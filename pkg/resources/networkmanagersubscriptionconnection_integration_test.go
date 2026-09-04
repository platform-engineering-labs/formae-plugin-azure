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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v4"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const (
	testNMConnectionNativeID = "/subscriptions/sub-1/providers/Microsoft.Network/networkManagerConnections/conn-1"
	testNMConnectionManager  = "/subscriptions/sub-2/resourceGroups/rg-2/providers/Microsoft.Network/networkManagers/nm-2"
)

func newTestNetworkManagerSubscriptionConnection(api networkManagerSubscriptionConnectionsAPI) *NetworkManagerSubscriptionConnection {
	return &NetworkManagerSubscriptionConnection{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

func nmConnectionDesired(description string) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":             "conn-1",
		"networkManagerId": testNMConnectionManager,
		"description":      description,
	})
	return out
}

func TestNetworkManagerSubscriptionConnection_CRUD(t *testing.T) {
	connResult := armnetwork.ManagerConnection{
		ID:   to.Ptr(testNMConnectionNativeID),
		Name: to.Ptr("conn-1"),
		Properties: &armnetwork.ManagerConnectionProperties{
			NetworkManagerID: to.Ptr(testNMConnectionManager),
			Description:      to.Ptr("conformance"),
			ConnectionState:  to.Ptr(armnetwork.ScopeConnectionStateConnected),
		},
	}

	var sent armnetwork.ManagerConnection
	var sawName string
	deleteCalls := 0
	fake := &fakeNMSubscriptionConnectionsAPI{
		createOrUpdateFn: func(_ context.Context, name string, params armnetwork.ManagerConnection, _ *armnetwork.SubscriptionNetworkManagerConnectionsClientCreateOrUpdateOptions) (armnetwork.SubscriptionNetworkManagerConnectionsClientCreateOrUpdateResponse, error) {
			sawName = name
			sent = params
			return armnetwork.SubscriptionNetworkManagerConnectionsClientCreateOrUpdateResponse{ManagerConnection: connResult}, nil
		},
		getFn: func(_ context.Context, _ string, _ *armnetwork.SubscriptionNetworkManagerConnectionsClientGetOptions) (armnetwork.SubscriptionNetworkManagerConnectionsClientGetResponse, error) {
			return armnetwork.SubscriptionNetworkManagerConnectionsClientGetResponse{ManagerConnection: connResult}, nil
		},
		deleteFn: func(_ context.Context, _ string, _ *armnetwork.SubscriptionNetworkManagerConnectionsClientDeleteOptions) (armnetwork.SubscriptionNetworkManagerConnectionsClientDeleteResponse, error) {
			deleteCalls++
			return armnetwork.SubscriptionNetworkManagerConnectionsClientDeleteResponse{}, nil
		},
		newListPagerFn: func(_ *armnetwork.SubscriptionNetworkManagerConnectionsClientListOptions) *runtime.Pager[armnetwork.SubscriptionNetworkManagerConnectionsClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armnetwork.SubscriptionNetworkManagerConnectionsClientListResponse]{
				More: func(_ armnetwork.SubscriptionNetworkManagerConnectionsClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armnetwork.SubscriptionNetworkManagerConnectionsClientListResponse) (armnetwork.SubscriptionNetworkManagerConnectionsClientListResponse, error) {
					return armnetwork.SubscriptionNetworkManagerConnectionsClientListResponse{
						ManagerConnectionListResult: armnetwork.ManagerConnectionListResult{
							Value: []*armnetwork.ManagerConnection{{ID: to.Ptr(testNMConnectionNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestNetworkManagerSubscriptionConnection(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "conn-1",
			Properties: nmConnectionDesired("conformance"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testNMConnectionNativeID, got.ProgressResult.NativeID)
		require.Equal(t, "conn-1", sawName)
		require.Equal(t, testNMConnectionManager, *sent.Properties.NetworkManagerID)
		require.Equal(t, "conformance", *sent.Properties.Description)
	})

	t.Run("Create_requires_network_manager_id", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "conn-1"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "networkManagerId is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testNMConnectionNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "conn-1", props["name"])
		require.Equal(t, testNMConnectionManager, props["networkManagerId"])
		require.Equal(t, "conformance", props["description"])
		// The resource is subscription-scoped, so there is no resource group to
		// report and none is invented.
		require.NotContains(t, props, "resourceGroupName")
	})

	// connectionState is the service's verdict on the pairing, not desired
	// state — a Conflict or Pending value must not read as drift.
	t.Run("Read_drops_connection_state", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testNMConnectionNativeID})
		require.NoError(t, err)
		require.NotContains(t, got.Properties, "connectionState")
	})

	t.Run("Update", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testNMConnectionNativeID,
			DesiredProperties: nmConnectionDesired("redescribed"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, "redescribed", *sent.Properties.Description)
	})

	t.Run("Delete", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testNMConnectionNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _ string, _ *armnetwork.SubscriptionNetworkManagerConnectionsClientDeleteOptions) (armnetwork.SubscriptionNetworkManagerConnectionsClientDeleteResponse, error) {
			return armnetwork.SubscriptionNetworkManagerConnectionsClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testNMConnectionNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	// The scope is the client's own subscription, so List needs no
	// AdditionalProperties and the type needs no listParam.
	t.Run("List_needs_no_scope", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Equal(t, []string{testNMConnectionNativeID}, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure_with_message", func(t *testing.T) {
		fake.createOrUpdateFn = func(_ context.Context, _ string, _ armnetwork.ManagerConnection, _ *armnetwork.SubscriptionNetworkManagerConnectionsClientCreateOrUpdateOptions) (armnetwork.SubscriptionNetworkManagerConnectionsClientCreateOrUpdateResponse, error) {
			return armnetwork.SubscriptionNetworkManagerConnectionsClientCreateOrUpdateResponse{}, &azcore.ResponseError{StatusCode: 409}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "conn-1", Properties: nmConnectionDesired("conformance"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.NotEmpty(t, got.ProgressResult.StatusMessage)
	})
}

// The ID has no resource group, so armIDParts cannot parse it — the dedicated
// parser has to accept a subscription-scoped ID and reject anything else.
func TestNetworkManagerSubscriptionConnectionIDParts(t *testing.T) {
	name, err := networkManagerSubscriptionConnectionIDParts(testNMConnectionNativeID)
	require.NoError(t, err)
	require.Equal(t, "conn-1", name)

	_, err = networkManagerSubscriptionConnectionIDParts(
		"/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/networkManagers/nm-1")
	require.Error(t, err)

	_, err = networkManagerSubscriptionConnectionIDParts("")
	require.Error(t, err)
}

func TestNetworkManagerSubscriptionConnection_ReadNotFound(t *testing.T) {
	fake := &fakeNMSubscriptionConnectionsAPI{
		getFn: func(_ context.Context, _ string, _ *armnetwork.SubscriptionNetworkManagerConnectionsClientGetOptions) (armnetwork.SubscriptionNetworkManagerConnectionsClientGetResponse, error) {
			return armnetwork.SubscriptionNetworkManagerConnectionsClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestNetworkManagerSubscriptionConnection(fake).Read(context.Background(),
		&resource.ReadRequest{NativeID: testNMConnectionNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeNMSubscriptionConnectionsAPI struct {
	createOrUpdateFn func(ctx context.Context, name string, params armnetwork.ManagerConnection, options *armnetwork.SubscriptionNetworkManagerConnectionsClientCreateOrUpdateOptions) (armnetwork.SubscriptionNetworkManagerConnectionsClientCreateOrUpdateResponse, error)
	getFn            func(ctx context.Context, name string, options *armnetwork.SubscriptionNetworkManagerConnectionsClientGetOptions) (armnetwork.SubscriptionNetworkManagerConnectionsClientGetResponse, error)
	deleteFn         func(ctx context.Context, name string, options *armnetwork.SubscriptionNetworkManagerConnectionsClientDeleteOptions) (armnetwork.SubscriptionNetworkManagerConnectionsClientDeleteResponse, error)
	newListPagerFn   func(options *armnetwork.SubscriptionNetworkManagerConnectionsClientListOptions) *runtime.Pager[armnetwork.SubscriptionNetworkManagerConnectionsClientListResponse]
}

func (f *fakeNMSubscriptionConnectionsAPI) CreateOrUpdate(ctx context.Context, name string, params armnetwork.ManagerConnection, options *armnetwork.SubscriptionNetworkManagerConnectionsClientCreateOrUpdateOptions) (armnetwork.SubscriptionNetworkManagerConnectionsClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, name, params, options)
}

func (f *fakeNMSubscriptionConnectionsAPI) Get(ctx context.Context, name string, options *armnetwork.SubscriptionNetworkManagerConnectionsClientGetOptions) (armnetwork.SubscriptionNetworkManagerConnectionsClientGetResponse, error) {
	return f.getFn(ctx, name, options)
}

func (f *fakeNMSubscriptionConnectionsAPI) Delete(ctx context.Context, name string, options *armnetwork.SubscriptionNetworkManagerConnectionsClientDeleteOptions) (armnetwork.SubscriptionNetworkManagerConnectionsClientDeleteResponse, error) {
	return f.deleteFn(ctx, name, options)
}

func (f *fakeNMSubscriptionConnectionsAPI) NewListPager(options *armnetwork.SubscriptionNetworkManagerConnectionsClientListOptions) *runtime.Pager[armnetwork.SubscriptionNetworkManagerConnectionsClientListResponse] {
	return f.newListPagerFn(options)
}
