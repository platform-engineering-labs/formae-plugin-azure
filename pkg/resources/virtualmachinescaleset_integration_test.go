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

const testVMSSNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Compute/virtualMachineScaleSets/vmss-1"

func TestVirtualMachineScaleSet_CRUD(t *testing.T) {
	donePoller := armcompute.VirtualMachineScaleSetsClientCreateOrUpdateResponse{
		VirtualMachineScaleSet: armcompute.VirtualMachineScaleSet{
			ID:       to.Ptr(testVMSSNativeID),
			Name:     to.Ptr("vmss-1"),
			Location: to.Ptr("eastus"),
			SKU: &armcompute.SKU{
				Name:     to.Ptr("Standard_D2s_v4"),
				Capacity: to.Ptr(int64(1)),
				Tier:     to.Ptr("Standard"),
			},
			Properties: &armcompute.VirtualMachineScaleSetProperties{
				OrchestrationMode: to.Ptr(armcompute.OrchestrationModeUniform),
				UpgradePolicy: &armcompute.UpgradePolicy{
					Mode: to.Ptr(armcompute.UpgradeModeManual),
				},
			},
		},
	}
	fake := &fakeVMSSAPI{
		beginCreateOrUpdateFn: func(_ context.Context, _, _ string, _ armcompute.VirtualMachineScaleSet, _ *armcompute.VirtualMachineScaleSetsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armcompute.VirtualMachineScaleSetsClientCreateOrUpdateResponse], error) {
			return newDonePoller(donePoller), nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armcompute.VirtualMachineScaleSetsClientGetOptions) (armcompute.VirtualMachineScaleSetsClientGetResponse, error) {
			return armcompute.VirtualMachineScaleSetsClientGetResponse{VirtualMachineScaleSet: donePoller.VirtualMachineScaleSet}, nil
		},
		beginUpdateFn: func(_ context.Context, _, _ string, _ armcompute.VirtualMachineScaleSetUpdate, _ *armcompute.VirtualMachineScaleSetsClientBeginUpdateOptions) (*runtime.Poller[armcompute.VirtualMachineScaleSetsClientUpdateResponse], error) {
			return newDonePoller(armcompute.VirtualMachineScaleSetsClientUpdateResponse{VirtualMachineScaleSet: donePoller.VirtualMachineScaleSet}), nil
		},
		beginDeleteFn: func(_ context.Context, _, _ string, _ *armcompute.VirtualMachineScaleSetsClientBeginDeleteOptions) (*runtime.Poller[armcompute.VirtualMachineScaleSetsClientDeleteResponse], error) {
			return newInProgressPoller[armcompute.VirtualMachineScaleSetsClientDeleteResponse](), nil
		},
		newListPagerFn: func(_ string, _ *armcompute.VirtualMachineScaleSetsClientListOptions) *runtime.Pager[armcompute.VirtualMachineScaleSetsClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armcompute.VirtualMachineScaleSetsClientListResponse]{
				More: func(_ armcompute.VirtualMachineScaleSetsClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armcompute.VirtualMachineScaleSetsClientListResponse) (armcompute.VirtualMachineScaleSetsClientListResponse, error) {
					return armcompute.VirtualMachineScaleSetsClientListResponse{
						VirtualMachineScaleSetListResult: armcompute.VirtualMachineScaleSetListResult{
							Value: []*armcompute.VirtualMachineScaleSet{{ID: to.Ptr(testVMSSNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestVMSS(fake)

	mkProps := func() json.RawMessage {
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName": "rg-1",
			"name":              "vmss-1",
			"location":          "eastus",
			"sku": map[string]any{
				"name":     "Standard_D2s_v4",
				"capacity": 1,
				"tier":     "Standard",
			},
			"upgradePolicy": map[string]any{
				"mode": "Manual",
			},
			"orchestrationMode": "Uniform",
			"virtualMachineProfile": map[string]any{
				"osProfile": map[string]any{
					"computerNamePrefix": "vmss",
					"adminUsername":      "azureuser",
					"adminPassword":      "TestPassword!42",
				},
				"storageProfile": map[string]any{
					"imageReference": map[string]any{
						"publisher": "Canonical",
						"offer":     "0001-com-ubuntu-server-jammy",
						"sku":       "22_04-lts-gen2",
						"version":   "latest",
					},
					"osDisk": map[string]any{
						"createOption": "FromImage",
						"managedDisk": map[string]any{
							"storageAccountType": "Standard_LRS",
						},
					},
				},
				"networkProfile": map[string]any{
					"networkInterfaceConfigurations": []map[string]any{
						{
							"name":    "vmss-nic",
							"primary": true,
							"ipConfigurations": []map[string]any{
								{
									"name":     "vmss-ipcfg",
									"subnetId": "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/virtualNetworks/vnet-1/subnets/snet-1",
								},
							},
						},
					},
				},
			},
		})
		return props
	}

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testVMSSNativeID, got.ProgressResult.NativeID)
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testVMSSNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _ string, _ *armcompute.VirtualMachineScaleSetsClientBeginDeleteOptions) (*runtime.Poller[armcompute.VirtualMachineScaleSetsClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testVMSSNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 1)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, _ armcompute.VirtualMachineScaleSet, _ *armcompute.VirtualMachineScaleSetsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armcompute.VirtualMachineScaleSetsClientCreateOrUpdateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 403}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

// --- Test helpers ---

func newTestVMSS(api vmssAPI) *VirtualMachineScaleSet {
	return &VirtualMachineScaleSet{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

type fakeVMSSAPI struct {
	beginCreateOrUpdateFn func(ctx context.Context, rgName, vmssName string, params armcompute.VirtualMachineScaleSet, opts *armcompute.VirtualMachineScaleSetsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armcompute.VirtualMachineScaleSetsClientCreateOrUpdateResponse], error)
	getFn                 func(ctx context.Context, rgName, vmssName string, opts *armcompute.VirtualMachineScaleSetsClientGetOptions) (armcompute.VirtualMachineScaleSetsClientGetResponse, error)
	beginUpdateFn         func(ctx context.Context, rgName, vmssName string, params armcompute.VirtualMachineScaleSetUpdate, opts *armcompute.VirtualMachineScaleSetsClientBeginUpdateOptions) (*runtime.Poller[armcompute.VirtualMachineScaleSetsClientUpdateResponse], error)
	beginDeleteFn         func(ctx context.Context, rgName, vmssName string, opts *armcompute.VirtualMachineScaleSetsClientBeginDeleteOptions) (*runtime.Poller[armcompute.VirtualMachineScaleSetsClientDeleteResponse], error)
	newListPagerFn        func(rgName string, opts *armcompute.VirtualMachineScaleSetsClientListOptions) *runtime.Pager[armcompute.VirtualMachineScaleSetsClientListResponse]
}

func (f *fakeVMSSAPI) BeginCreateOrUpdate(ctx context.Context, rgName, vmssName string, params armcompute.VirtualMachineScaleSet, opts *armcompute.VirtualMachineScaleSetsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armcompute.VirtualMachineScaleSetsClientCreateOrUpdateResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, rgName, vmssName, params, opts)
}

func (f *fakeVMSSAPI) Get(ctx context.Context, rgName, vmssName string, opts *armcompute.VirtualMachineScaleSetsClientGetOptions) (armcompute.VirtualMachineScaleSetsClientGetResponse, error) {
	return f.getFn(ctx, rgName, vmssName, opts)
}

func (f *fakeVMSSAPI) BeginUpdate(ctx context.Context, rgName, vmssName string, params armcompute.VirtualMachineScaleSetUpdate, opts *armcompute.VirtualMachineScaleSetsClientBeginUpdateOptions) (*runtime.Poller[armcompute.VirtualMachineScaleSetsClientUpdateResponse], error) {
	return f.beginUpdateFn(ctx, rgName, vmssName, params, opts)
}

func (f *fakeVMSSAPI) BeginDelete(ctx context.Context, rgName, vmssName string, opts *armcompute.VirtualMachineScaleSetsClientBeginDeleteOptions) (*runtime.Poller[armcompute.VirtualMachineScaleSetsClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, vmssName, opts)
}

func (f *fakeVMSSAPI) NewListPager(rgName string, opts *armcompute.VirtualMachineScaleSetsClientListOptions) *runtime.Pager[armcompute.VirtualMachineScaleSetsClientListResponse] {
	return f.newListPagerFn(rgName, opts)
}
