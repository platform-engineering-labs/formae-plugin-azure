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

const testHybridConnectionNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Relay/namespaces/relay1/hybridConnections/hc-1"

func newTestHybridConnection(api relayHybridConnectionsAPI) *RelayHybridConnection {
	return &RelayHybridConnection{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func hybridConnectionDesired(metadata string) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":                        "hc-1",
		"resourceGroupName":           "rg-1",
		"namespaceName":               "relay1",
		"requiresClientAuthorization": true,
		"userMetadata":                metadata,
	})
	return out
}

func TestRelayHybridConnection_CRUD(t *testing.T) {
	hcResult := armrelay.HybridConnection{
		ID:   to.Ptr(testHybridConnectionNativeID),
		Name: to.Ptr("hc-1"),
		Properties: &armrelay.HybridConnectionProperties{
			RequiresClientAuthorization: to.Ptr(true),
			UserMetadata:                to.Ptr("listener on prem"),
			ListenerCount:               to.Ptr(int32(2)),
			CreatedAt:                   to.Ptr(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)),
			UpdatedAt:                   to.Ptr(time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)),
		},
	}

	var sentCreate armrelay.HybridConnection
	var sawNamespace string
	createCalls := 0
	deleteCalls := 0
	fake := &fakeHybridConnectionsAPI{
		createOrUpdateFn: func(_ context.Context, _, namespaceName, name string, params armrelay.HybridConnection, _ *armrelay.HybridConnectionsClientCreateOrUpdateOptions) (armrelay.HybridConnectionsClientCreateOrUpdateResponse, error) {
			require.Equal(t, "hc-1", name)
			sawNamespace = namespaceName
			sentCreate = params
			createCalls++
			return armrelay.HybridConnectionsClientCreateOrUpdateResponse{HybridConnection: hcResult}, nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ *armrelay.HybridConnectionsClientGetOptions) (armrelay.HybridConnectionsClientGetResponse, error) {
			return armrelay.HybridConnectionsClientGetResponse{HybridConnection: hcResult}, nil
		},
		deleteFn: func(_ context.Context, _, _, _ string, _ *armrelay.HybridConnectionsClientDeleteOptions) (armrelay.HybridConnectionsClientDeleteResponse, error) {
			deleteCalls++
			return armrelay.HybridConnectionsClientDeleteResponse{}, nil
		},
		newListByNamespacePagerFn: func(_, _ string, _ *armrelay.HybridConnectionsClientListByNamespaceOptions) *runtime.Pager[armrelay.HybridConnectionsClientListByNamespaceResponse] {
			return runtime.NewPager(runtime.PagingHandler[armrelay.HybridConnectionsClientListByNamespaceResponse]{
				More: func(_ armrelay.HybridConnectionsClientListByNamespaceResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armrelay.HybridConnectionsClientListByNamespaceResponse) (armrelay.HybridConnectionsClientListByNamespaceResponse, error) {
					return armrelay.HybridConnectionsClientListByNamespaceResponse{
						HybridConnectionListResult: armrelay.HybridConnectionListResult{
							Value: []*armrelay.HybridConnection{{ID: to.Ptr(testHybridConnectionNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestHybridConnection(fake)

	// Create is synchronous: success comes back directly, with no resume token.
	t.Run("Create_is_synchronous", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "hc-1",
			Properties: hybridConnectionDesired("listener on prem"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testHybridConnectionNativeID, got.ProgressResult.NativeID)
		require.Empty(t, got.ProgressResult.RequestID)

		require.Equal(t, "relay1", sawNamespace)
		require.True(t, *sentCreate.Properties.RequiresClientAuthorization)
		require.Equal(t, "listener on prem", *sentCreate.Properties.UserMetadata)
	})

	t.Run("Create_requires_namespace", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "hc-1", "resourceGroupName": "rg-1"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "namespaceName is required")
	})

	t.Run("Create_requires_resource_group", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "hc-1", "namespaceName": "relay1"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "resourceGroupName is required")
	})

	// An omitted requiresClientAuthorization must be left out of the body so ARM
	// applies its own default of true, rather than being sent as false.
	t.Run("Create_without_client_auth_sends_none", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "hc-1", "resourceGroupName": "rg-1", "namespaceName": "relay1",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.Nil(t, sentCreate.Properties.RequiresClientAuthorization)
		require.Nil(t, sentCreate.Properties.UserMetadata)
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testHybridConnectionNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "hc-1", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		// Both parents come from the native ID, not the response body.
		require.Equal(t, "relay1", props["namespaceName"])
		require.Equal(t, true, props["requiresClientAuthorization"])
		require.Equal(t, "listener on prem", props["userMetadata"])
	})

	// listenerCount changes whenever a listener connects and the timestamps move on
	// their own: all three would read back as drift on every sync.
	t.Run("Read_drops_service_state", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testHybridConnectionNativeID})
		require.NoError(t, err)
		for _, key := range []string{"listenerCount", "createdAt", "updatedAt"} {
			require.NotContains(t, got.Properties, key)
		}
	})

	// This API has no PATCH verb: an update is another CreateOrUpdate, and it must
	// still report success synchronously.
	t.Run("Update_reissues_create_or_update", func(t *testing.T) {
		before := createCalls
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testHybridConnectionNativeID,
			DesiredProperties: hybridConnectionDesired("listener moved"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Empty(t, got.ProgressResult.RequestID)
		require.Equal(t, before+1, createCalls)
		require.Equal(t, "listener moved", *sentCreate.Properties.UserMetadata)
	})

	t.Run("Delete_is_synchronous", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testHybridConnectionNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Empty(t, got.ProgressResult.RequestID)
		require.Equal(t, before+1, deleteCalls)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _, _ string, _ *armrelay.HybridConnectionsClientDeleteOptions) (armrelay.HybridConnectionsClientDeleteResponse, error) {
			return armrelay.HybridConnectionsClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testHybridConnectionNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_namespace", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "namespaceName": "relay1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testHybridConnectionNativeID}, got.NativeIDs)
	})

	// ARM has no subscription-wide listing here: without both parents there is
	// nothing to page, so List must return empty rather than error.
	t.Run("List_without_parents_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.createOrUpdateFn = func(_ context.Context, _, _, _ string, _ armrelay.HybridConnection, _ *armrelay.HybridConnectionsClientCreateOrUpdateOptions) (armrelay.HybridConnectionsClientCreateOrUpdateResponse, error) {
			return armrelay.HybridConnectionsClientCreateOrUpdateResponse{}, &azcore.ResponseError{StatusCode: 409}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "hc-1", Properties: hybridConnectionDesired("listener on prem"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

func TestRelayHybridConnection_ReadNotFound(t *testing.T) {
	fake := &fakeHybridConnectionsAPI{
		getFn: func(_ context.Context, _, _, _ string, _ *armrelay.HybridConnectionsClientGetOptions) (armrelay.HybridConnectionsClientGetResponse, error) {
			return armrelay.HybridConnectionsClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestHybridConnection(fake).Read(context.Background(), &resource.ReadRequest{NativeID: testHybridConnectionNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeHybridConnectionsAPI struct {
	createOrUpdateFn          func(ctx context.Context, rgName, namespaceName, name string, params armrelay.HybridConnection, options *armrelay.HybridConnectionsClientCreateOrUpdateOptions) (armrelay.HybridConnectionsClientCreateOrUpdateResponse, error)
	getFn                     func(ctx context.Context, rgName, namespaceName, name string, options *armrelay.HybridConnectionsClientGetOptions) (armrelay.HybridConnectionsClientGetResponse, error)
	deleteFn                  func(ctx context.Context, rgName, namespaceName, name string, options *armrelay.HybridConnectionsClientDeleteOptions) (armrelay.HybridConnectionsClientDeleteResponse, error)
	newListByNamespacePagerFn func(rgName, namespaceName string, options *armrelay.HybridConnectionsClientListByNamespaceOptions) *runtime.Pager[armrelay.HybridConnectionsClientListByNamespaceResponse]
}

func (f *fakeHybridConnectionsAPI) CreateOrUpdate(ctx context.Context, rgName, namespaceName, name string, params armrelay.HybridConnection, options *armrelay.HybridConnectionsClientCreateOrUpdateOptions) (armrelay.HybridConnectionsClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, namespaceName, name, params, options)
}

func (f *fakeHybridConnectionsAPI) Get(ctx context.Context, rgName, namespaceName, name string, options *armrelay.HybridConnectionsClientGetOptions) (armrelay.HybridConnectionsClientGetResponse, error) {
	return f.getFn(ctx, rgName, namespaceName, name, options)
}

func (f *fakeHybridConnectionsAPI) Delete(ctx context.Context, rgName, namespaceName, name string, options *armrelay.HybridConnectionsClientDeleteOptions) (armrelay.HybridConnectionsClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, namespaceName, name, options)
}

func (f *fakeHybridConnectionsAPI) NewListByNamespacePager(rgName, namespaceName string, options *armrelay.HybridConnectionsClientListByNamespaceOptions) *runtime.Pager[armrelay.HybridConnectionsClientListByNamespaceResponse] {
	return f.newListByNamespacePagerFn(rgName, namespaceName, options)
}
