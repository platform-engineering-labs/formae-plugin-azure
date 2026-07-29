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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v5"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const (
	testSSHPublicKeyNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Compute/sshPublicKeys/key-1"
	testSSHPublicKeyMaterial = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC0000000000000000000000 formae@test"
)

func TestSSHPublicKey_CRUD(t *testing.T) {
	model := armcompute.SSHPublicKeyResource{
		ID:       to.Ptr(testSSHPublicKeyNativeID),
		Name:     to.Ptr("key-1"),
		Location: to.Ptr("eastus"),
		Properties: &armcompute.SSHPublicKeyResourceProperties{
			PublicKey: to.Ptr(testSSHPublicKeyMaterial),
		},
		Tags: map[string]*string{"Environment": to.Ptr("test")},
	}
	fake := &fakeSSHPublicKeysAPI{
		createFn: func(_ context.Context, _, _ string, _ armcompute.SSHPublicKeyResource, _ *armcompute.SSHPublicKeysClientCreateOptions) (armcompute.SSHPublicKeysClientCreateResponse, error) {
			return armcompute.SSHPublicKeysClientCreateResponse{SSHPublicKeyResource: model}, nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armcompute.SSHPublicKeysClientGetOptions) (armcompute.SSHPublicKeysClientGetResponse, error) {
			return armcompute.SSHPublicKeysClientGetResponse{SSHPublicKeyResource: model}, nil
		},
		updateFn: func(_ context.Context, _, _ string, _ armcompute.SSHPublicKeyUpdateResource, _ *armcompute.SSHPublicKeysClientUpdateOptions) (armcompute.SSHPublicKeysClientUpdateResponse, error) {
			return armcompute.SSHPublicKeysClientUpdateResponse{SSHPublicKeyResource: model}, nil
		},
		deleteFn: func(_ context.Context, _, _ string, _ *armcompute.SSHPublicKeysClientDeleteOptions) (armcompute.SSHPublicKeysClientDeleteResponse, error) {
			return armcompute.SSHPublicKeysClientDeleteResponse{}, nil
		},
		newListByResourceGroupPagerFn: func(_ string, _ *armcompute.SSHPublicKeysClientListByResourceGroupOptions) *runtime.Pager[armcompute.SSHPublicKeysClientListByResourceGroupResponse] {
			return runtime.NewPager(runtime.PagingHandler[armcompute.SSHPublicKeysClientListByResourceGroupResponse]{
				More: func(_ armcompute.SSHPublicKeysClientListByResourceGroupResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armcompute.SSHPublicKeysClientListByResourceGroupResponse) (armcompute.SSHPublicKeysClientListByResourceGroupResponse, error) {
					return armcompute.SSHPublicKeysClientListByResourceGroupResponse{
						SSHPublicKeysGroupListResult: armcompute.SSHPublicKeysGroupListResult{
							Value: []*armcompute.SSHPublicKeyResource{{ID: to.Ptr(testSSHPublicKeyNativeID)}},
						},
					}, nil
				},
			})
		},
		newListBySubscriptionPagerFn: func(_ *armcompute.SSHPublicKeysClientListBySubscriptionOptions) *runtime.Pager[armcompute.SSHPublicKeysClientListBySubscriptionResponse] {
			return runtime.NewPager(runtime.PagingHandler[armcompute.SSHPublicKeysClientListBySubscriptionResponse]{
				More: func(_ armcompute.SSHPublicKeysClientListBySubscriptionResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armcompute.SSHPublicKeysClientListBySubscriptionResponse) (armcompute.SSHPublicKeysClientListBySubscriptionResponse, error) {
					return armcompute.SSHPublicKeysClientListBySubscriptionResponse{
						SSHPublicKeysGroupListResult: armcompute.SSHPublicKeysGroupListResult{
							Value: []*armcompute.SSHPublicKeyResource{{ID: to.Ptr(testSSHPublicKeyNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestSSHPublicKey(fake)

	mkProps := func() json.RawMessage {
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName": "rg-1",
			"name":              "key-1",
			"location":          "eastus",
			"publicKey":         testSSHPublicKeyMaterial,
			"Tags":              []map[string]string{{"Key": "Environment", "Value": "test"}},
		})
		return props
	}

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testSSHPublicKeyNativeID, got.ProgressResult.NativeID)

		var serialized map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &serialized))
		require.Equal(t, "key-1", serialized["name"])
		require.Equal(t, "rg-1", serialized["resourceGroupName"])
		require.Equal(t, "eastus", serialized["location"])
		require.Equal(t, testSSHPublicKeyMaterial, serialized["publicKey"])
	})

	t.Run("Create_forwards_params_to_ARM", func(t *testing.T) {
		var seen armcompute.SSHPublicKeyResource
		var seenRG, seenName string
		fake.createFn = func(_ context.Context, rg, name string, params armcompute.SSHPublicKeyResource, _ *armcompute.SSHPublicKeysClientCreateOptions) (armcompute.SSHPublicKeysClientCreateResponse, error) {
			seen, seenRG, seenName = params, rg, name
			return armcompute.SSHPublicKeysClientCreateResponse{SSHPublicKeyResource: model}, nil
		}
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, "rg-1", seenRG)
		require.Equal(t, "key-1", seenName)
		require.Equal(t, "eastus", *seen.Location)
		require.Equal(t, testSSHPublicKeyMaterial, *seen.Properties.PublicKey)
		require.Equal(t, "test", *seen.Tags["Environment"])

		fake.createFn = func(_ context.Context, _, _ string, _ armcompute.SSHPublicKeyResource, _ *armcompute.SSHPublicKeysClientCreateOptions) (armcompute.SSHPublicKeysClientCreateResponse, error) {
			return armcompute.SSHPublicKeysClientCreateResponse{SSHPublicKeyResource: model}, nil
		}
	})

	t.Run("Create_requires_location", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"resourceGroupName": "rg-1", "name": "key-1"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "location is required")
	})

	t.Run("Create_requires_resourceGroupName", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "key-1", "location": "eastus"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "resourceGroupName is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testSSHPublicKeyNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
		require.Equal(t, ResourceTypeSSHPublicKey, got.ResourceType)

		var serialized map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &serialized))
		require.Equal(t, testSSHPublicKeyMaterial, serialized["publicKey"])
	})

	t.Run("Read_not_found", func(t *testing.T) {
		fake.getFn = func(_ context.Context, _, _ string, _ *armcompute.SSHPublicKeysClientGetOptions) (armcompute.SSHPublicKeysClientGetResponse, error) {
			return armcompute.SSHPublicKeysClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testSSHPublicKeyNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)

		fake.getFn = func(_ context.Context, _, _ string, _ *armcompute.SSHPublicKeysClientGetOptions) (armcompute.SSHPublicKeysClientGetResponse, error) {
			return armcompute.SSHPublicKeysClientGetResponse{SSHPublicKeyResource: model}, nil
		}
	})

	t.Run("Update_patches_key_and_tags", func(t *testing.T) {
		var seen armcompute.SSHPublicKeyUpdateResource
		fake.updateFn = func(_ context.Context, _, _ string, params armcompute.SSHPublicKeyUpdateResource, _ *armcompute.SSHPublicKeysClientUpdateOptions) (armcompute.SSHPublicKeysClientUpdateResponse, error) {
			seen = params
			return armcompute.SSHPublicKeysClientUpdateResponse{SSHPublicKeyResource: model}, nil
		}
		desired, _ := json.Marshal(map[string]any{
			"resourceGroupName": "rg-1",
			"name":              "key-1",
			"location":          "eastus",
			"publicKey":         testSSHPublicKeyMaterial,
			"Tags":              []map[string]string{{"Key": "Environment", "Value": "updated"}},
		})
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testSSHPublicKeyNativeID,
			DesiredProperties: desired,
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testSSHPublicKeyMaterial, *seen.Properties.PublicKey)
		require.Equal(t, "updated", *seen.Tags["Environment"])
	})

	t.Run("Delete", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testSSHPublicKeyNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _ string, _ *armcompute.SSHPublicKeysClientDeleteOptions) (armcompute.SSHPublicKeysClientDeleteResponse, error) {
			return armcompute.SSHPublicKeysClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testSSHPublicKeyNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Status_is_sync_success", func(t *testing.T) {
		got, err := prov.Status(context.Background(), &resource.StatusRequest{RequestID: "anything"})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_resource_group", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testSSHPublicKeyNativeID}, got.NativeIDs)
	})

	t.Run("List_by_subscription", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Equal(t, []string{testSSHPublicKeyNativeID}, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.createFn = func(_ context.Context, _, _ string, _ armcompute.SSHPublicKeyResource, _ *armcompute.SSHPublicKeysClientCreateOptions) (armcompute.SSHPublicKeysClientCreateResponse, error) {
			return armcompute.SSHPublicKeysClientCreateResponse{}, &azcore.ResponseError{StatusCode: 403}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

func TestSSHPublicKeyIDParts(t *testing.T) {
	rg, name, err := sshPublicKeyIDParts(testSSHPublicKeyNativeID)
	require.NoError(t, err)
	require.Equal(t, "rg-1", rg)
	require.Equal(t, "key-1", name)

	_, _, err = sshPublicKeyIDParts("/subscriptions/sub-1/resourceGroups/rg-1")
	require.Error(t, err)
}

// --- Test helpers ---

func newTestSSHPublicKey(api sshPublicKeysAPI) *SSHPublicKey {
	return &SSHPublicKey{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

type fakeSSHPublicKeysAPI struct {
	createFn                      func(ctx context.Context, rgName, name string, params armcompute.SSHPublicKeyResource, opts *armcompute.SSHPublicKeysClientCreateOptions) (armcompute.SSHPublicKeysClientCreateResponse, error)
	getFn                         func(ctx context.Context, rgName, name string, opts *armcompute.SSHPublicKeysClientGetOptions) (armcompute.SSHPublicKeysClientGetResponse, error)
	updateFn                      func(ctx context.Context, rgName, name string, params armcompute.SSHPublicKeyUpdateResource, opts *armcompute.SSHPublicKeysClientUpdateOptions) (armcompute.SSHPublicKeysClientUpdateResponse, error)
	deleteFn                      func(ctx context.Context, rgName, name string, opts *armcompute.SSHPublicKeysClientDeleteOptions) (armcompute.SSHPublicKeysClientDeleteResponse, error)
	newListByResourceGroupPagerFn func(rgName string, opts *armcompute.SSHPublicKeysClientListByResourceGroupOptions) *runtime.Pager[armcompute.SSHPublicKeysClientListByResourceGroupResponse]
	newListBySubscriptionPagerFn  func(opts *armcompute.SSHPublicKeysClientListBySubscriptionOptions) *runtime.Pager[armcompute.SSHPublicKeysClientListBySubscriptionResponse]
}

func (f *fakeSSHPublicKeysAPI) Create(ctx context.Context, rgName, name string, params armcompute.SSHPublicKeyResource, opts *armcompute.SSHPublicKeysClientCreateOptions) (armcompute.SSHPublicKeysClientCreateResponse, error) {
	return f.createFn(ctx, rgName, name, params, opts)
}

func (f *fakeSSHPublicKeysAPI) Get(ctx context.Context, rgName, name string, opts *armcompute.SSHPublicKeysClientGetOptions) (armcompute.SSHPublicKeysClientGetResponse, error) {
	return f.getFn(ctx, rgName, name, opts)
}

func (f *fakeSSHPublicKeysAPI) Update(ctx context.Context, rgName, name string, params armcompute.SSHPublicKeyUpdateResource, opts *armcompute.SSHPublicKeysClientUpdateOptions) (armcompute.SSHPublicKeysClientUpdateResponse, error) {
	return f.updateFn(ctx, rgName, name, params, opts)
}

func (f *fakeSSHPublicKeysAPI) Delete(ctx context.Context, rgName, name string, opts *armcompute.SSHPublicKeysClientDeleteOptions) (armcompute.SSHPublicKeysClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, name, opts)
}

func (f *fakeSSHPublicKeysAPI) NewListByResourceGroupPager(rgName string, opts *armcompute.SSHPublicKeysClientListByResourceGroupOptions) *runtime.Pager[armcompute.SSHPublicKeysClientListByResourceGroupResponse] {
	return f.newListByResourceGroupPagerFn(rgName, opts)
}

func (f *fakeSSHPublicKeysAPI) NewListBySubscriptionPager(opts *armcompute.SSHPublicKeysClientListBySubscriptionOptions) *runtime.Pager[armcompute.SSHPublicKeysClientListBySubscriptionResponse] {
	return f.newListBySubscriptionPagerFn(opts)
}
