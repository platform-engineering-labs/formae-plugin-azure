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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v5"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testVMNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Compute/virtualMachines/my-vm"

func TestVirtualMachine_CRUD(t *testing.T) {
	vmSize := armcompute.VirtualMachineSizeTypesStandardB1S
	fake := &fakeVirtualMachinesAPI{
		beginCreateOrUpdateFn: func(_ context.Context, _, _ string, _ armcompute.VirtualMachine, _ *armcompute.VirtualMachinesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armcompute.VirtualMachinesClientCreateOrUpdateResponse], error) {
			return newDonePoller(armcompute.VirtualMachinesClientCreateOrUpdateResponse{
				VirtualMachine: armcompute.VirtualMachine{
					ID:       to.Ptr(testVMNativeID),
					Name:     to.Ptr("my-vm"),
					Location: to.Ptr("eastus"),
					Properties: &armcompute.VirtualMachineProperties{
						HardwareProfile: &armcompute.HardwareProfile{VMSize: &vmSize},
						OSProfile: &armcompute.OSProfile{
							AdminUsername: to.Ptr("azureuser"),
							ComputerName: to.Ptr("my-vm"),
						},
						ProvisioningState: to.Ptr("Succeeded"),
					},
				},
			}), nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armcompute.VirtualMachinesClientGetOptions) (armcompute.VirtualMachinesClientGetResponse, error) {
			return armcompute.VirtualMachinesClientGetResponse{
				VirtualMachine: armcompute.VirtualMachine{
					ID:       to.Ptr(testVMNativeID),
					Name:     to.Ptr("my-vm"),
					Location: to.Ptr("eastus"),
					Properties: &armcompute.VirtualMachineProperties{
						HardwareProfile: &armcompute.HardwareProfile{VMSize: &vmSize},
						OSProfile: &armcompute.OSProfile{
							AdminUsername: to.Ptr("azureuser"),
							ComputerName: to.Ptr("my-vm"),
						},
						ProvisioningState: to.Ptr("Succeeded"),
					},
				},
			}, nil
		},
		beginUpdateFn: func(_ context.Context, _, _ string, _ armcompute.VirtualMachineUpdate, _ *armcompute.VirtualMachinesClientBeginUpdateOptions) (*runtime.Poller[armcompute.VirtualMachinesClientUpdateResponse], error) {
			return newDonePoller(armcompute.VirtualMachinesClientUpdateResponse{
				VirtualMachine: armcompute.VirtualMachine{
					ID:       to.Ptr(testVMNativeID),
					Name:     to.Ptr("my-vm"),
					Location: to.Ptr("eastus"),
					Properties: &armcompute.VirtualMachineProperties{
						HardwareProfile: &armcompute.HardwareProfile{VMSize: to.Ptr(armcompute.VirtualMachineSizeTypes("Standard_B2s"))},
						OSProfile: &armcompute.OSProfile{
							AdminUsername: to.Ptr("azureuser"),
							ComputerName: to.Ptr("my-vm"),
						},
						ProvisioningState: to.Ptr("Succeeded"),
					},
				},
			}), nil
		},
		beginDeleteFn: func(_ context.Context, _, _ string, _ *armcompute.VirtualMachinesClientBeginDeleteOptions) (*runtime.Poller[armcompute.VirtualMachinesClientDeleteResponse], error) {
			return newDonePoller(armcompute.VirtualMachinesClientDeleteResponse{}), nil
		},
		newListPagerFn: func(_ string, _ *armcompute.VirtualMachinesClientListOptions) *runtime.Pager[armcompute.VirtualMachinesClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armcompute.VirtualMachinesClientListResponse]{
				More: func(_ armcompute.VirtualMachinesClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armcompute.VirtualMachinesClientListResponse) (armcompute.VirtualMachinesClientListResponse, error) {
					return armcompute.VirtualMachinesClientListResponse{
						VirtualMachineListResult: armcompute.VirtualMachineListResult{
							Value: []*armcompute.VirtualMachine{
								{ID: to.Ptr(testVMNativeID)},
								{ID: to.Ptr("/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Compute/virtualMachines/other-vm")},
							},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestVirtualMachine(fake)

	t.Run("Create", func(t *testing.T) {
		props, _ := json.Marshal(map[string]interface{}{
			"resourceGroupName": "rg-1",
			"location":          "eastus",
			"name":              "my-vm",
			"vmSize":            "Standard_B1s",
			"adminUsername":     "azureuser",
			"networkInterfaces": []map[string]interface{}{
				{"id": "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/networkInterfaces/my-nic"},
			},
			"imageReference": map[string]interface{}{
				"publisher": "Canonical",
				"offer":     "UbuntuServer",
				"sku":       "18.04-LTS",
				"version":   "latest",
			},
			"osDisk": map[string]interface{}{
				"createOption": "FromImage",
			},
		})
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "my-vm", Properties: props})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testVMNativeID, got.ProgressResult.NativeID)
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testVMNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
		var props map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "my-vm", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "eastus", props["location"])
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _ string, _ *armcompute.VirtualMachinesClientBeginDeleteOptions) (*runtime.Poller[armcompute.VirtualMachinesClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testVMNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 2)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, _ armcompute.VirtualMachine, _ *armcompute.VirtualMachinesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armcompute.VirtualMachinesClientCreateOrUpdateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 403}
		}
		props, _ := json.Marshal(map[string]interface{}{
			"resourceGroupName": "rg-1",
			"location":          "eastus",
			"name":              "my-vm",
			"vmSize":            "Standard_B1s",
			"adminUsername":     "azureuser",
			"networkInterfaces": []map[string]interface{}{
				{"id": "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/networkInterfaces/my-nic"},
			},
			"imageReference": map[string]interface{}{
				"publisher": "Canonical",
				"offer":     "UbuntuServer",
				"sku":       "18.04-LTS",
				"version":   "latest",
			},
			"osDisk": map[string]interface{}{
				"createOption": "FromImage",
			},
		})
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "my-vm", Properties: props})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

// --- Test helpers ---

func newTestVirtualMachine(api virtualMachinesAPI) *VirtualMachine {
	return &VirtualMachine{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

type fakeVirtualMachinesAPI struct {
	beginCreateOrUpdateFn func(ctx context.Context, resourceGroupName string, vmName string, parameters armcompute.VirtualMachine, options *armcompute.VirtualMachinesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armcompute.VirtualMachinesClientCreateOrUpdateResponse], error)
	getFn                 func(ctx context.Context, resourceGroupName string, vmName string, options *armcompute.VirtualMachinesClientGetOptions) (armcompute.VirtualMachinesClientGetResponse, error)
	beginUpdateFn         func(ctx context.Context, resourceGroupName string, vmName string, parameters armcompute.VirtualMachineUpdate, options *armcompute.VirtualMachinesClientBeginUpdateOptions) (*runtime.Poller[armcompute.VirtualMachinesClientUpdateResponse], error)
	beginDeleteFn         func(ctx context.Context, resourceGroupName string, vmName string, options *armcompute.VirtualMachinesClientBeginDeleteOptions) (*runtime.Poller[armcompute.VirtualMachinesClientDeleteResponse], error)
	newListPagerFn        func(resourceGroupName string, options *armcompute.VirtualMachinesClientListOptions) *runtime.Pager[armcompute.VirtualMachinesClientListResponse]
	resumeCreateFn        func(token string) (*runtime.Poller[armcompute.VirtualMachinesClientCreateOrUpdateResponse], error)
	resumeUpdateFn        func(token string) (*runtime.Poller[armcompute.VirtualMachinesClientUpdateResponse], error)
	resumeDeleteFn        func(token string) (*runtime.Poller[armcompute.VirtualMachinesClientDeleteResponse], error)
}

func (f *fakeVirtualMachinesAPI) BeginCreateOrUpdate(ctx context.Context, resourceGroupName string, vmName string, parameters armcompute.VirtualMachine, options *armcompute.VirtualMachinesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armcompute.VirtualMachinesClientCreateOrUpdateResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, resourceGroupName, vmName, parameters, options)
}

func (f *fakeVirtualMachinesAPI) Get(ctx context.Context, resourceGroupName string, vmName string, options *armcompute.VirtualMachinesClientGetOptions) (armcompute.VirtualMachinesClientGetResponse, error) {
	return f.getFn(ctx, resourceGroupName, vmName, options)
}

func (f *fakeVirtualMachinesAPI) BeginUpdate(ctx context.Context, resourceGroupName string, vmName string, parameters armcompute.VirtualMachineUpdate, options *armcompute.VirtualMachinesClientBeginUpdateOptions) (*runtime.Poller[armcompute.VirtualMachinesClientUpdateResponse], error) {
	return f.beginUpdateFn(ctx, resourceGroupName, vmName, parameters, options)
}

func (f *fakeVirtualMachinesAPI) BeginDelete(ctx context.Context, resourceGroupName string, vmName string, options *armcompute.VirtualMachinesClientBeginDeleteOptions) (*runtime.Poller[armcompute.VirtualMachinesClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, resourceGroupName, vmName, options)
}

func (f *fakeVirtualMachinesAPI) NewListPager(resourceGroupName string, options *armcompute.VirtualMachinesClientListOptions) *runtime.Pager[armcompute.VirtualMachinesClientListResponse] {
	return f.newListPagerFn(resourceGroupName, options)
}

func (f *fakeVirtualMachinesAPI) ResumeCreatePoller(token string) (*runtime.Poller[armcompute.VirtualMachinesClientCreateOrUpdateResponse], error) {
	return f.resumeCreateFn(token)
}

func (f *fakeVirtualMachinesAPI) ResumeUpdatePoller(token string) (*runtime.Poller[armcompute.VirtualMachinesClientUpdateResponse], error) {
	return f.resumeUpdateFn(token)
}

func (f *fakeVirtualMachinesAPI) ResumeDeletePoller(token string) (*runtime.Poller[armcompute.VirtualMachinesClientDeleteResponse], error) {
	return f.resumeDeleteFn(token)
}
