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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/notificationhubs/armnotificationhubs"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testNotificationHubNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.NotificationHubs/namespaces/nh1/notificationHubs/hub-1"

func newTestNotificationHub(api notificationHubsAPI) *NotificationHub {
	return &NotificationHub{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func notificationHubDesired(tagValue string) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":              "hub-1",
		"location":          "eastus",
		"resourceGroupName": "rg-1",
		"namespaceName":     "nh1",
		"registrationTtl":   "7.00:00:00",
		"Tags":              []any{map[string]any{"Key": "env", "Value": tagValue}},
	})
	return out
}

func TestNotificationHub_CRUD(t *testing.T) {
	hubResult := armnotificationhubs.NotificationHubResource{
		ID:       to.Ptr(testNotificationHubNativeID),
		Name:     to.Ptr("hub-1"),
		Location: to.Ptr("East US"),
		Properties: &armnotificationhubs.NotificationHubProperties{
			Name:            to.Ptr("hub-1"),
			RegistrationTTL: to.Ptr("7.00:00:00"),
			// ARM does echo credential blocks on some API versions; read must never
			// surface them regardless.
			GCMCredential: &armnotificationhubs.GCMCredential{
				Properties: &armnotificationhubs.GCMCredentialProperties{
					GoogleAPIKey: to.Ptr("super-secret-fcm-key"),
				},
			},
		},
		Tags: map[string]*string{"env": to.Ptr("test")},
	}

	var sentCreate armnotificationhubs.NotificationHubCreateOrUpdateParameters
	var sawNamespace string
	createCalls := 0
	deleteCalls := 0
	fake := &fakeNotificationHubsAPI{
		createOrUpdateFn: func(_ context.Context, _, namespaceName, name string, params armnotificationhubs.NotificationHubCreateOrUpdateParameters, _ *armnotificationhubs.ClientCreateOrUpdateOptions) (armnotificationhubs.ClientCreateOrUpdateResponse, error) {
			require.Equal(t, "hub-1", name)
			sawNamespace = namespaceName
			sentCreate = params
			createCalls++
			return armnotificationhubs.ClientCreateOrUpdateResponse{NotificationHubResource: hubResult}, nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ *armnotificationhubs.ClientGetOptions) (armnotificationhubs.ClientGetResponse, error) {
			return armnotificationhubs.ClientGetResponse{NotificationHubResource: hubResult}, nil
		},
		deleteFn: func(_ context.Context, _, _, _ string, _ *armnotificationhubs.ClientDeleteOptions) (armnotificationhubs.ClientDeleteResponse, error) {
			deleteCalls++
			return armnotificationhubs.ClientDeleteResponse{}, nil
		},
		newListPagerFn: func(_, _ string, _ *armnotificationhubs.ClientListOptions) *runtime.Pager[armnotificationhubs.ClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armnotificationhubs.ClientListResponse]{
				More: func(_ armnotificationhubs.ClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armnotificationhubs.ClientListResponse) (armnotificationhubs.ClientListResponse, error) {
					return armnotificationhubs.ClientListResponse{
						NotificationHubListResult: armnotificationhubs.NotificationHubListResult{
							Value: []*armnotificationhubs.NotificationHubResource{{ID: to.Ptr(testNotificationHubNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestNotificationHub(fake)

	// Create is synchronous: success comes back directly, with no resume token.
	t.Run("Create_is_synchronous", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "hub-1",
			Properties: notificationHubDesired("test"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testNotificationHubNativeID, got.ProgressResult.NativeID)
		require.Empty(t, got.ProgressResult.RequestID)

		require.Equal(t, "nh1", sawNamespace)
		require.Equal(t, "eastus", *sentCreate.Location)
		require.Equal(t, "7.00:00:00", *sentCreate.Properties.RegistrationTTL)
		require.Equal(t, "test", *sentCreate.Tags["env"])
		// Credential blocks are never sent: an out-of-band credential must survive
		// an update, and an empty block would clear it.
		require.Nil(t, sentCreate.Properties.GCMCredential)
		require.Nil(t, sentCreate.Properties.ApnsCredential)
	})

	t.Run("Create_requires_namespace", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "hub-1", "resourceGroupName": "rg-1"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "namespaceName is required")
	})

	t.Run("Create_requires_resource_group", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "hub-1", "namespaceName": "nh1"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "resourceGroupName is required")
	})

	t.Run("Create_requires_location", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "hub-1", "resourceGroupName": "rg-1", "namespaceName": "nh1",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "location is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testNotificationHubNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "hub-1", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		// Both parents come from the native ID, not the response body.
		require.Equal(t, "nh1", props["namespaceName"])
		require.Equal(t, "eastus", props["location"])
		require.Equal(t, "7.00:00:00", props["registrationTtl"])
	})

	// The PNS credentials are live secrets. Even when ARM echoes them back, read
	// must never put them in state.
	t.Run("credentials_never_serialized", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testNotificationHubNativeID})
		require.NoError(t, err)
		require.NotContains(t, got.Properties, "super-secret-fcm-key")
		for _, key := range []string{
			"gcmCredential", "apnsCredential", "wnsCredential",
			"mpnsCredential", "admCredential", "baiduCredential", "googleApiKey",
		} {
			require.NotContains(t, got.Properties, key)
		}
	})

	// This API has no PATCH verb: an update is another CreateOrUpdate, and it must
	// still report success synchronously.
	t.Run("Update_reissues_create_or_update", func(t *testing.T) {
		before := createCalls
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testNotificationHubNativeID,
			DesiredProperties: notificationHubDesired("updated"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Empty(t, got.ProgressResult.RequestID)
		require.Equal(t, before+1, createCalls)
		require.Equal(t, "updated", *sentCreate.Tags["env"])
	})

	t.Run("Delete_is_synchronous", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testNotificationHubNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Empty(t, got.ProgressResult.RequestID)
		require.Equal(t, before+1, deleteCalls)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _, _ string, _ *armnotificationhubs.ClientDeleteOptions) (armnotificationhubs.ClientDeleteResponse, error) {
			return armnotificationhubs.ClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testNotificationHubNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_namespace", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "namespaceName": "nh1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testNotificationHubNativeID}, got.NativeIDs)
	})

	// ARM has no subscription-wide listing here: without both parents there is
	// nothing to page, so List must return empty rather than error.
	t.Run("List_without_parents_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.createOrUpdateFn = func(_ context.Context, _, _, _ string, _ armnotificationhubs.NotificationHubCreateOrUpdateParameters, _ *armnotificationhubs.ClientCreateOrUpdateOptions) (armnotificationhubs.ClientCreateOrUpdateResponse, error) {
			return armnotificationhubs.ClientCreateOrUpdateResponse{}, &azcore.ResponseError{StatusCode: 409}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "hub-1", Properties: notificationHubDesired("test"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

func TestNotificationHub_ReadNotFound(t *testing.T) {
	fake := &fakeNotificationHubsAPI{
		getFn: func(_ context.Context, _, _, _ string, _ *armnotificationhubs.ClientGetOptions) (armnotificationhubs.ClientGetResponse, error) {
			return armnotificationhubs.ClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestNotificationHub(fake).Read(context.Background(), &resource.ReadRequest{NativeID: testNotificationHubNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeNotificationHubsAPI struct {
	createOrUpdateFn func(ctx context.Context, rgName, namespaceName, name string, params armnotificationhubs.NotificationHubCreateOrUpdateParameters, options *armnotificationhubs.ClientCreateOrUpdateOptions) (armnotificationhubs.ClientCreateOrUpdateResponse, error)
	getFn            func(ctx context.Context, rgName, namespaceName, name string, options *armnotificationhubs.ClientGetOptions) (armnotificationhubs.ClientGetResponse, error)
	deleteFn         func(ctx context.Context, rgName, namespaceName, name string, options *armnotificationhubs.ClientDeleteOptions) (armnotificationhubs.ClientDeleteResponse, error)
	newListPagerFn   func(rgName, namespaceName string, options *armnotificationhubs.ClientListOptions) *runtime.Pager[armnotificationhubs.ClientListResponse]
}

func (f *fakeNotificationHubsAPI) CreateOrUpdate(ctx context.Context, rgName, namespaceName, name string, params armnotificationhubs.NotificationHubCreateOrUpdateParameters, options *armnotificationhubs.ClientCreateOrUpdateOptions) (armnotificationhubs.ClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, namespaceName, name, params, options)
}

func (f *fakeNotificationHubsAPI) Get(ctx context.Context, rgName, namespaceName, name string, options *armnotificationhubs.ClientGetOptions) (armnotificationhubs.ClientGetResponse, error) {
	return f.getFn(ctx, rgName, namespaceName, name, options)
}

func (f *fakeNotificationHubsAPI) Delete(ctx context.Context, rgName, namespaceName, name string, options *armnotificationhubs.ClientDeleteOptions) (armnotificationhubs.ClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, namespaceName, name, options)
}

func (f *fakeNotificationHubsAPI) NewListPager(rgName, namespaceName string, options *armnotificationhubs.ClientListOptions) *runtime.Pager[armnotificationhubs.ClientListResponse] {
	return f.newListPagerFn(rgName, namespaceName, options)
}
