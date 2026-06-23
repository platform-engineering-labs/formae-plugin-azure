// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build integration

package resources

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v5"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testVMExtensionNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Compute/virtualMachines/vm-1/extensions/ext-1"

func TestVirtualMachineExtension_CRUD(t *testing.T) {
	doneExt := armcompute.VirtualMachineExtension{
		ID:       to.Ptr(testVMExtensionNativeID),
		Name:     to.Ptr("ext-1"),
		Location: to.Ptr("eastus"),
		Properties: &armcompute.VirtualMachineExtensionProperties{
			Publisher:               to.Ptr("Microsoft.Azure.Extensions"),
			Type:                    to.Ptr("CustomScript"),
			TypeHandlerVersion:      to.Ptr("2.1"),
			AutoUpgradeMinorVersion: to.Ptr(true),
			Settings:                map[string]any{"commandToExecute": "echo hello"},
		},
	}

	fake := &fakeVMExtensionsAPI{
		beginCreateOrUpdateFn: func(_ context.Context, _, _, _ string, _ armcompute.VirtualMachineExtension, _ *armcompute.VirtualMachineExtensionsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armcompute.VirtualMachineExtensionsClientCreateOrUpdateResponse], error) {
			return newDoneVMExtensionPoller(armcompute.VirtualMachineExtensionsClientCreateOrUpdateResponse{VirtualMachineExtension: doneExt}), nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ *armcompute.VirtualMachineExtensionsClientGetOptions) (armcompute.VirtualMachineExtensionsClientGetResponse, error) {
			return armcompute.VirtualMachineExtensionsClientGetResponse{VirtualMachineExtension: doneExt}, nil
		},
		beginUpdateFn: func(_ context.Context, _, _, _ string, _ armcompute.VirtualMachineExtensionUpdate, _ *armcompute.VirtualMachineExtensionsClientBeginUpdateOptions) (*runtime.Poller[armcompute.VirtualMachineExtensionsClientUpdateResponse], error) {
			updated := doneExt
			return newDoneVMExtensionUpdatePoller(armcompute.VirtualMachineExtensionsClientUpdateResponse{VirtualMachineExtension: updated}), nil
		},
		beginDeleteFn: func(_ context.Context, _, _, _ string, _ *armcompute.VirtualMachineExtensionsClientBeginDeleteOptions) (*runtime.Poller[armcompute.VirtualMachineExtensionsClientDeleteResponse], error) {
			return newPendingDeleteVMExtensionPoller(), nil
		},
		listFn: func(_ context.Context, _, _ string, _ *armcompute.VirtualMachineExtensionsClientListOptions) (armcompute.VirtualMachineExtensionsClientListResponse, error) {
			return armcompute.VirtualMachineExtensionsClientListResponse{
				VirtualMachineExtensionsListResult: armcompute.VirtualMachineExtensionsListResult{
					Value: []*armcompute.VirtualMachineExtension{{ID: to.Ptr(testVMExtensionNativeID)}},
				},
			}, nil
		},
	}
	prov := newTestVMExtension(fake)

	createProps := map[string]any{
		"resourceGroupName":  "rg-1",
		"virtualMachineName": "vm-1",
		"name":               "ext-1",
		"location":           "eastus",
		"publisher":          "Microsoft.Azure.Extensions",
		"type":               "CustomScript",
		"typeHandlerVersion": "2.1",
		"settings":           map[string]any{"commandToExecute": "echo hello"},
		"protectedSettings":  map[string]any{"storageAccountKey": "secret-key"},
	}

	t.Run("Create", func(t *testing.T) {
		props, _ := json.Marshal(createProps)
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testVMExtensionNativeID, got.ProgressResult.NativeID)

		var out map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &out))
		require.Equal(t, "ext-1", out["name"])
		require.NotContains(t, out, "protectedSettings")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testVMExtensionNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "ext-1", props["name"])
		require.Equal(t, "CustomScript", props["type"])
		require.NotContains(t, props, "protectedSettings")
	})

	t.Run("Update_keeps_native_id", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"typeHandlerVersion": "2.1",
			"settings":           map[string]any{"commandToExecute": "echo updated"},
		})
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{NativeID: testVMExtensionNativeID, DesiredProperties: props})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testVMExtensionNativeID, got.ProgressResult.NativeID)
	})

	t.Run("Delete", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testVMExtensionNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusInProgress, got.ProgressResult.OperationStatus)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _, _ string, _ *armcompute.VirtualMachineExtensionsClientBeginDeleteOptions) (*runtime.Poller[armcompute.VirtualMachineExtensionsClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testVMExtensionNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "virtualMachineName": "vm-1"},
		})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 1)
		require.Equal(t, testVMExtensionNativeID, got.NativeIDs[0])
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _, _ string, _ armcompute.VirtualMachineExtension, _ *armcompute.VirtualMachineExtensionsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armcompute.VirtualMachineExtensionsClientCreateOrUpdateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 403}
		}
		props, _ := json.Marshal(createProps)
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

// --- Test helpers ---

func newTestVMExtension(api virtualMachineExtensionsAPI) *VirtualMachineExtension {
	return &VirtualMachineExtension{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

type vmExtensionDoneHandler[T any] struct {
	resp T
}

func (h *vmExtensionDoneHandler[T]) Done() bool                                     { return true }
func (h *vmExtensionDoneHandler[T]) Poll(_ context.Context) (*http.Response, error) { return nil, nil }
func (h *vmExtensionDoneHandler[T]) Result(_ context.Context, out *T) error {
	*out = h.resp
	return nil
}

func newDoneVMExtensionPoller(resp armcompute.VirtualMachineExtensionsClientCreateOrUpdateResponse) *runtime.Poller[armcompute.VirtualMachineExtensionsClientCreateOrUpdateResponse] {
	p, err := runtime.NewPoller[armcompute.VirtualMachineExtensionsClientCreateOrUpdateResponse](nil, runtime.Pipeline{}, &runtime.NewPollerOptions[armcompute.VirtualMachineExtensionsClientCreateOrUpdateResponse]{
		Handler: &vmExtensionDoneHandler[armcompute.VirtualMachineExtensionsClientCreateOrUpdateResponse]{resp: resp},
	})
	if err != nil {
		panic(err)
	}
	return p
}

func newDoneVMExtensionUpdatePoller(resp armcompute.VirtualMachineExtensionsClientUpdateResponse) *runtime.Poller[armcompute.VirtualMachineExtensionsClientUpdateResponse] {
	p, err := runtime.NewPoller[armcompute.VirtualMachineExtensionsClientUpdateResponse](nil, runtime.Pipeline{}, &runtime.NewPollerOptions[armcompute.VirtualMachineExtensionsClientUpdateResponse]{
		Handler: &vmExtensionDoneHandler[armcompute.VirtualMachineExtensionsClientUpdateResponse]{resp: resp},
	})
	if err != nil {
		panic(err)
	}
	return p
}

type vmExtensionPendingHandler[T any] struct{}

func (h *vmExtensionPendingHandler[T]) Done() bool { return false }
func (h *vmExtensionPendingHandler[T]) Poll(_ context.Context) (*http.Response, error) {
	return nil, nil
}
func (h *vmExtensionPendingHandler[T]) Result(_ context.Context, _ *T) error { return nil }

func newPendingDeleteVMExtensionPoller() *runtime.Poller[armcompute.VirtualMachineExtensionsClientDeleteResponse] {
	p, err := runtime.NewPoller[armcompute.VirtualMachineExtensionsClientDeleteResponse](nil, runtime.Pipeline{}, &runtime.NewPollerOptions[armcompute.VirtualMachineExtensionsClientDeleteResponse]{
		Handler: &vmExtensionPendingHandler[armcompute.VirtualMachineExtensionsClientDeleteResponse]{},
	})
	if err != nil {
		panic(err)
	}
	return p
}

type fakeVMExtensionsAPI struct {
	beginCreateOrUpdateFn func(ctx context.Context, rgName, vmName, extName string, params armcompute.VirtualMachineExtension, opts *armcompute.VirtualMachineExtensionsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armcompute.VirtualMachineExtensionsClientCreateOrUpdateResponse], error)
	getFn                 func(ctx context.Context, rgName, vmName, extName string, opts *armcompute.VirtualMachineExtensionsClientGetOptions) (armcompute.VirtualMachineExtensionsClientGetResponse, error)
	beginUpdateFn         func(ctx context.Context, rgName, vmName, extName string, params armcompute.VirtualMachineExtensionUpdate, opts *armcompute.VirtualMachineExtensionsClientBeginUpdateOptions) (*runtime.Poller[armcompute.VirtualMachineExtensionsClientUpdateResponse], error)
	beginDeleteFn         func(ctx context.Context, rgName, vmName, extName string, opts *armcompute.VirtualMachineExtensionsClientBeginDeleteOptions) (*runtime.Poller[armcompute.VirtualMachineExtensionsClientDeleteResponse], error)
	listFn                func(ctx context.Context, rgName, vmName string, opts *armcompute.VirtualMachineExtensionsClientListOptions) (armcompute.VirtualMachineExtensionsClientListResponse, error)
}

func (f *fakeVMExtensionsAPI) BeginCreateOrUpdate(ctx context.Context, rgName, vmName, extName string, params armcompute.VirtualMachineExtension, opts *armcompute.VirtualMachineExtensionsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armcompute.VirtualMachineExtensionsClientCreateOrUpdateResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, rgName, vmName, extName, params, opts)
}

func (f *fakeVMExtensionsAPI) Get(ctx context.Context, rgName, vmName, extName string, opts *armcompute.VirtualMachineExtensionsClientGetOptions) (armcompute.VirtualMachineExtensionsClientGetResponse, error) {
	return f.getFn(ctx, rgName, vmName, extName, opts)
}

func (f *fakeVMExtensionsAPI) BeginUpdate(ctx context.Context, rgName, vmName, extName string, params armcompute.VirtualMachineExtensionUpdate, opts *armcompute.VirtualMachineExtensionsClientBeginUpdateOptions) (*runtime.Poller[armcompute.VirtualMachineExtensionsClientUpdateResponse], error) {
	return f.beginUpdateFn(ctx, rgName, vmName, extName, params, opts)
}

func (f *fakeVMExtensionsAPI) BeginDelete(ctx context.Context, rgName, vmName, extName string, opts *armcompute.VirtualMachineExtensionsClientBeginDeleteOptions) (*runtime.Poller[armcompute.VirtualMachineExtensionsClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, vmName, extName, opts)
}

func (f *fakeVMExtensionsAPI) List(ctx context.Context, rgName, vmName string, opts *armcompute.VirtualMachineExtensionsClientListOptions) (armcompute.VirtualMachineExtensionsClientListResponse, error) {
	return f.listFn(ctx, rgName, vmName, opts)
}
