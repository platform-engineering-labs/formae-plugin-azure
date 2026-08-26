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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerregistry/armcontainerregistry"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const (
	testACRWebhookNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.ContainerRegistry/registries/reg1/webhooks/hook1"
	testACRWebhookURI      = "https://example.invalid/acr-hook"
)

func newTestACRWebhook(api containerRegistryWebhooksAPI) *ContainerRegistryWebhook {
	return &ContainerRegistryWebhook{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func acrWebhookDesired(status string) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":              "hook1",
		"resourceGroupName": "rg-1",
		"registryName":      "reg1",
		"location":          "eastus",
		"serviceUri":        testACRWebhookURI,
		"actions":           []any{"push", "delete"},
		"status":            status,
		"scope":             "myrepo:latest",
		"Tags":              []any{map[string]any{"Key": "env", "Value": "test"}},
	})
	return out
}

func TestContainerRegistryWebhook_CRUD(t *testing.T) {
	// ARM's Get response has no serviceUri or customHeaders at all — they come only
	// from GetCallbackConfig — so the fake echoes back exactly what the service does.
	hookResult := armcontainerregistry.Webhook{
		ID:       to.Ptr(testACRWebhookNativeID),
		Name:     to.Ptr("hook1"),
		Location: to.Ptr("East US"),
		Properties: &armcontainerregistry.WebhookProperties{
			Status: to.Ptr(armcontainerregistry.WebhookStatusEnabled),
			Scope:  to.Ptr("myrepo:latest"),
			Actions: []*armcontainerregistry.WebhookAction{
				to.Ptr(armcontainerregistry.WebhookActionPush),
				to.Ptr(armcontainerregistry.WebhookActionDelete),
			},
			ProvisioningState: to.Ptr(armcontainerregistry.ProvisioningStateSucceeded),
		},
		Tags: map[string]*string{"env": to.Ptr("test")},
	}

	var sentCreate armcontainerregistry.WebhookCreateParameters
	var sentUpdate armcontainerregistry.WebhookUpdateParameters
	deleteCalls := 0
	fake := &fakeACRWebhooksAPI{
		beginCreateFn: func(_ context.Context, _, registryName, name string, params armcontainerregistry.WebhookCreateParameters, _ *armcontainerregistry.WebhooksClientBeginCreateOptions) (*runtime.Poller[armcontainerregistry.WebhooksClientCreateResponse], error) {
			require.Equal(t, "reg1", registryName)
			require.Equal(t, "hook1", name)
			sentCreate = params
			return newDonePoller(armcontainerregistry.WebhooksClientCreateResponse{Webhook: hookResult}), nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ *armcontainerregistry.WebhooksClientGetOptions) (armcontainerregistry.WebhooksClientGetResponse, error) {
			return armcontainerregistry.WebhooksClientGetResponse{Webhook: hookResult}, nil
		},
		beginUpdateFn: func(_ context.Context, _, _, _ string, params armcontainerregistry.WebhookUpdateParameters, _ *armcontainerregistry.WebhooksClientBeginUpdateOptions) (*runtime.Poller[armcontainerregistry.WebhooksClientUpdateResponse], error) {
			sentUpdate = params
			return newDonePoller(armcontainerregistry.WebhooksClientUpdateResponse{Webhook: hookResult}), nil
		},
		beginDeleteFn: func(_ context.Context, _, _, _ string, _ *armcontainerregistry.WebhooksClientBeginDeleteOptions) (*runtime.Poller[armcontainerregistry.WebhooksClientDeleteResponse], error) {
			deleteCalls++
			return newDonePoller(armcontainerregistry.WebhooksClientDeleteResponse{}), nil
		},
		newListPagerFn: func(_, _ string, _ *armcontainerregistry.WebhooksClientListOptions) *runtime.Pager[armcontainerregistry.WebhooksClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armcontainerregistry.WebhooksClientListResponse]{
				More: func(_ armcontainerregistry.WebhooksClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armcontainerregistry.WebhooksClientListResponse) (armcontainerregistry.WebhooksClientListResponse, error) {
					return armcontainerregistry.WebhooksClientListResponse{
						WebhookListResult: armcontainerregistry.WebhookListResult{
							Value: []*armcontainerregistry.Webhook{{ID: to.Ptr(testACRWebhookNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestACRWebhook(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "hook1", Properties: acrWebhookDesired("enabled"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testACRWebhookNativeID, got.ProgressResult.NativeID)

		// The create body carries location; the update body has no such field.
		require.Equal(t, "eastus", *sentCreate.Location)
		require.Equal(t, testACRWebhookURI, *sentCreate.Properties.ServiceURI)
		require.Equal(t, armcontainerregistry.WebhookStatusEnabled, *sentCreate.Properties.Status)
		require.Equal(t, "myrepo:latest", *sentCreate.Properties.Scope)
		require.Len(t, sentCreate.Properties.Actions, 2)
		require.Equal(t, armcontainerregistry.WebhookActionPush, *sentCreate.Properties.Actions[0])
		require.Equal(t, "test", *sentCreate.Tags["env"])
	})

	t.Run("Create_requires_service_uri", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "hook1", "resourceGroupName": "rg-1", "registryName": "reg1",
			"location": "eastus", "actions": []any{"push"},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "serviceUri is required")
	})

	t.Run("Create_requires_actions", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "hook1", "resourceGroupName": "rg-1", "registryName": "reg1",
			"location": "eastus", "serviceUri": testACRWebhookURI,
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "actions is required")
	})

	t.Run("Create_requires_registry", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "hook1", "resourceGroupName": "rg-1", "location": "eastus",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "registryName is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testACRWebhookNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "hook1", props["name"])
		// ARM returns "East US"; read must normalise or desired state drifts.
		require.Equal(t, "eastus", props["location"])
		// Both parents come from the native ID, not the response body.
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "reg1", props["registryName"])
		require.Equal(t, "enabled", props["status"])
		require.Equal(t, "myrepo:latest", props["scope"])
		// Order is echoed as ARM returns it, not sorted.
		require.Equal(t, []any{"push", "delete"}, props["actions"])
	})

	// serviceUri is write-only by ARM's design: absent from Get, so it can never
	// reach resource state. provisioningState is service state and is dropped too.
	t.Run("service_uri_never_serialized", func(t *testing.T) {
		read, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testACRWebhookNativeID})
		require.NoError(t, err)
		require.NotContains(t, read.Properties, "serviceUri")
		require.NotContains(t, read.Properties, "example.invalid")
		require.NotContains(t, read.Properties, "customHeaders")
		require.NotContains(t, read.Properties, "provisioningState")
	})

	t.Run("Update_sends_update_parameters", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testACRWebhookNativeID,
			DesiredProperties: acrWebhookDesired("disabled"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, armcontainerregistry.WebhookStatusDisabled, *sentUpdate.Properties.Status)
		// serviceUri rides along on the update so a changed endpoint is pushed, even
		// though drift in it cannot be observed.
		require.Equal(t, testACRWebhookURI, *sentUpdate.Properties.ServiceURI)
		require.Equal(t, "test", *sentUpdate.Tags["env"])
	})

	t.Run("Delete", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testACRWebhookNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _, _ string, _ *armcontainerregistry.WebhooksClientBeginDeleteOptions) (*runtime.Poller[armcontainerregistry.WebhooksClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testACRWebhookNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_registry", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "registryName": "reg1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testACRWebhookNativeID}, got.NativeIDs)
	})

	t.Run("List_without_parents_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.beginCreateFn = func(_ context.Context, _, _, _ string, _ armcontainerregistry.WebhookCreateParameters, _ *armcontainerregistry.WebhooksClientBeginCreateOptions) (*runtime.Poller[armcontainerregistry.WebhooksClientCreateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 409}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "hook1", Properties: acrWebhookDesired("enabled"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

func TestContainerRegistryWebhook_ReadNotFound(t *testing.T) {
	fake := &fakeACRWebhooksAPI{
		getFn: func(_ context.Context, _, _, _ string, _ *armcontainerregistry.WebhooksClientGetOptions) (armcontainerregistry.WebhooksClientGetResponse, error) {
			return armcontainerregistry.WebhooksClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestACRWebhook(fake).Read(context.Background(), &resource.ReadRequest{NativeID: testACRWebhookNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeACRWebhooksAPI struct {
	beginCreateFn  func(ctx context.Context, rgName, registryName, name string, params armcontainerregistry.WebhookCreateParameters, options *armcontainerregistry.WebhooksClientBeginCreateOptions) (*runtime.Poller[armcontainerregistry.WebhooksClientCreateResponse], error)
	getFn          func(ctx context.Context, rgName, registryName, name string, options *armcontainerregistry.WebhooksClientGetOptions) (armcontainerregistry.WebhooksClientGetResponse, error)
	beginUpdateFn  func(ctx context.Context, rgName, registryName, name string, params armcontainerregistry.WebhookUpdateParameters, options *armcontainerregistry.WebhooksClientBeginUpdateOptions) (*runtime.Poller[armcontainerregistry.WebhooksClientUpdateResponse], error)
	beginDeleteFn  func(ctx context.Context, rgName, registryName, name string, options *armcontainerregistry.WebhooksClientBeginDeleteOptions) (*runtime.Poller[armcontainerregistry.WebhooksClientDeleteResponse], error)
	newListPagerFn func(rgName, registryName string, options *armcontainerregistry.WebhooksClientListOptions) *runtime.Pager[armcontainerregistry.WebhooksClientListResponse]
}

func (f *fakeACRWebhooksAPI) BeginCreate(ctx context.Context, rgName, registryName, name string, params armcontainerregistry.WebhookCreateParameters, options *armcontainerregistry.WebhooksClientBeginCreateOptions) (*runtime.Poller[armcontainerregistry.WebhooksClientCreateResponse], error) {
	return f.beginCreateFn(ctx, rgName, registryName, name, params, options)
}

func (f *fakeACRWebhooksAPI) Get(ctx context.Context, rgName, registryName, name string, options *armcontainerregistry.WebhooksClientGetOptions) (armcontainerregistry.WebhooksClientGetResponse, error) {
	return f.getFn(ctx, rgName, registryName, name, options)
}

func (f *fakeACRWebhooksAPI) BeginUpdate(ctx context.Context, rgName, registryName, name string, params armcontainerregistry.WebhookUpdateParameters, options *armcontainerregistry.WebhooksClientBeginUpdateOptions) (*runtime.Poller[armcontainerregistry.WebhooksClientUpdateResponse], error) {
	return f.beginUpdateFn(ctx, rgName, registryName, name, params, options)
}

func (f *fakeACRWebhooksAPI) BeginDelete(ctx context.Context, rgName, registryName, name string, options *armcontainerregistry.WebhooksClientBeginDeleteOptions) (*runtime.Poller[armcontainerregistry.WebhooksClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, registryName, name, options)
}

func (f *fakeACRWebhooksAPI) NewListPager(rgName, registryName string, options *armcontainerregistry.WebhooksClientListOptions) *runtime.Pager[armcontainerregistry.WebhooksClientListResponse] {
	return f.newListPagerFn(rgName, registryName, options)
}
