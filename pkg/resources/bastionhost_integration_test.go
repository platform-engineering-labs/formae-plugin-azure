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
	testBastionHostNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/bastionHosts/bastion1"
	testBastionSubnetID     = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/virtualNetworks/vnet1/subnets/AzureBastionSubnet"
	testBastionPipID        = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/publicIPAddresses/pip1"
)

type fakeBastionHostsAPI struct {
	beginCreateOrUpdateFn         func(ctx context.Context, rgName, name string, params armnetwork.BastionHost, options *armnetwork.BastionHostsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.BastionHostsClientCreateOrUpdateResponse], error)
	getFn                         func(ctx context.Context, rgName, name string, options *armnetwork.BastionHostsClientGetOptions) (armnetwork.BastionHostsClientGetResponse, error)
	beginDeleteFn                 func(ctx context.Context, rgName, name string, options *armnetwork.BastionHostsClientBeginDeleteOptions) (*runtime.Poller[armnetwork.BastionHostsClientDeleteResponse], error)
	newListByResourceGroupPagerFn func(rgName string, options *armnetwork.BastionHostsClientListByResourceGroupOptions) *runtime.Pager[armnetwork.BastionHostsClientListByResourceGroupResponse]
	newListPagerFn                func(options *armnetwork.BastionHostsClientListOptions) *runtime.Pager[armnetwork.BastionHostsClientListResponse]
}

func (f *fakeBastionHostsAPI) BeginCreateOrUpdate(ctx context.Context, rgName, name string, params armnetwork.BastionHost, options *armnetwork.BastionHostsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.BastionHostsClientCreateOrUpdateResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, rgName, name, params, options)
}

func (f *fakeBastionHostsAPI) Get(ctx context.Context, rgName, name string, options *armnetwork.BastionHostsClientGetOptions) (armnetwork.BastionHostsClientGetResponse, error) {
	return f.getFn(ctx, rgName, name, options)
}

func (f *fakeBastionHostsAPI) BeginDelete(ctx context.Context, rgName, name string, options *armnetwork.BastionHostsClientBeginDeleteOptions) (*runtime.Poller[armnetwork.BastionHostsClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, name, options)
}

func (f *fakeBastionHostsAPI) NewListByResourceGroupPager(rgName string, options *armnetwork.BastionHostsClientListByResourceGroupOptions) *runtime.Pager[armnetwork.BastionHostsClientListByResourceGroupResponse] {
	return f.newListByResourceGroupPagerFn(rgName, options)
}

func (f *fakeBastionHostsAPI) NewListPager(options *armnetwork.BastionHostsClientListOptions) *runtime.Pager[armnetwork.BastionHostsClientListResponse] {
	return f.newListPagerFn(options)
}

func newTestBastionHost(api bastionHostsAPI) *BastionHost {
	return &BastionHost{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func bastionHostDesired(scaleUnits int, fileCopy bool) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":              "bastion1",
		"resourceGroupName": "rg-1",
		"location":          "eastus",
		"sku":               map[string]any{"name": "Standard"},
		"scaleUnits":        scaleUnits,
		"ipConfigurations": []any{map[string]any{
			"name":                      "IpConf",
			"subnetId":                  testBastionSubnetID,
			"publicIpAddressId":         testBastionPipID,
			"privateIpAllocationMethod": "Dynamic",
		}},
		"enableTunneling":     true,
		"enableIpConnect":     true,
		"enableFileCopy":      fileCopy,
		"enableShareableLink": false,
		"enableKerberos":      false,
		"disableCopyPaste":    false,
		"Tags":                []any{map[string]any{"Key": "env", "Value": "test"}},
	})
	return out
}

func TestBastionHost_CRUD(t *testing.T) {
	hostResult := armnetwork.BastionHost{
		ID:       to.Ptr(testBastionHostNativeID),
		Name:     to.Ptr("bastion1"),
		Location: to.Ptr("East US"),
		// ARM echoes the SKU name back with its own casing.
		SKU: &armnetwork.SKU{Name: to.Ptr(armnetwork.BastionHostSKUName("standard"))},
		Properties: &armnetwork.BastionHostPropertiesFormat{
			ScaleUnits: to.Ptr(int32(2)),
			IPConfigurations: []*armnetwork.BastionHostIPConfiguration{{
				// ARM assigns the child ID, etag and type; none may reach state.
				ID:   to.Ptr(testBastionHostNativeID + "/bastionHostIpConfigurations/IpConf"),
				Name: to.Ptr("IpConf"),
				Etag: to.Ptr("W/\"ipconf-etag\""),
				Type: to.Ptr("Microsoft.Network/bastionHosts/bastionHostIpConfigurations"),
				Properties: &armnetwork.BastionHostIPConfigurationPropertiesFormat{
					Subnet:                    &armnetwork.SubResource{ID: to.Ptr(testBastionSubnetID)},
					PublicIPAddress:           &armnetwork.SubResource{ID: to.Ptr(testBastionPipID)},
					PrivateIPAllocationMethod: to.Ptr(armnetwork.IPAllocationMethod("dynamic")),
					ProvisioningState:         to.Ptr(armnetwork.ProvisioningStateSucceeded),
				},
			}},
			EnableTunneling:     to.Ptr(true),
			EnableIPConnect:     to.Ptr(true),
			EnableFileCopy:      to.Ptr(false),
			EnableShareableLink: to.Ptr(false),
			EnableKerberos:      to.Ptr(false),
			DisableCopyPaste:    to.Ptr(false),
			// Service state: the FQDN Azure mints and the provisioning state.
			DNSName:           to.Ptr("bst-11112222-3333-4444-5555-666677778888.bastion.azure.com"),
			ProvisioningState: to.Ptr(armnetwork.ProvisioningStateSucceeded),
		},
		Tags: map[string]*string{"env": to.Ptr("test")},
		Etag: to.Ptr("W/\"etag\""),
	}

	var sent armnetwork.BastionHost
	createCalls := 0
	deleteCalls := 0
	fake := &fakeBastionHostsAPI{
		beginCreateOrUpdateFn: func(_ context.Context, rgName, name string, params armnetwork.BastionHost, _ *armnetwork.BastionHostsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.BastionHostsClientCreateOrUpdateResponse], error) {
			require.Equal(t, "rg-1", rgName)
			require.Equal(t, "bastion1", name)
			sent = params
			createCalls++
			return newDonePoller(armnetwork.BastionHostsClientCreateOrUpdateResponse{BastionHost: hostResult}), nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armnetwork.BastionHostsClientGetOptions) (armnetwork.BastionHostsClientGetResponse, error) {
			return armnetwork.BastionHostsClientGetResponse{BastionHost: hostResult}, nil
		},
		beginDeleteFn: func(_ context.Context, _, _ string, _ *armnetwork.BastionHostsClientBeginDeleteOptions) (*runtime.Poller[armnetwork.BastionHostsClientDeleteResponse], error) {
			deleteCalls++
			return newDonePoller(armnetwork.BastionHostsClientDeleteResponse{}), nil
		},
		newListByResourceGroupPagerFn: func(_ string, _ *armnetwork.BastionHostsClientListByResourceGroupOptions) *runtime.Pager[armnetwork.BastionHostsClientListByResourceGroupResponse] {
			return runtime.NewPager(runtime.PagingHandler[armnetwork.BastionHostsClientListByResourceGroupResponse]{
				More: func(_ armnetwork.BastionHostsClientListByResourceGroupResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armnetwork.BastionHostsClientListByResourceGroupResponse) (armnetwork.BastionHostsClientListByResourceGroupResponse, error) {
					return armnetwork.BastionHostsClientListByResourceGroupResponse{
						BastionHostListResult: armnetwork.BastionHostListResult{
							Value: []*armnetwork.BastionHost{{ID: to.Ptr(testBastionHostNativeID)}},
						},
					}, nil
				},
			})
		},
		newListPagerFn: func(_ *armnetwork.BastionHostsClientListOptions) *runtime.Pager[armnetwork.BastionHostsClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armnetwork.BastionHostsClientListResponse]{
				More: func(_ armnetwork.BastionHostsClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armnetwork.BastionHostsClientListResponse) (armnetwork.BastionHostsClientListResponse, error) {
					return armnetwork.BastionHostsClientListResponse{
						BastionHostListResult: armnetwork.BastionHostListResult{
							Value: []*armnetwork.BastionHost{{ID: to.Ptr(testBastionHostNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestBastionHost(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "bastion1", Properties: bastionHostDesired(2, false),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testBastionHostNativeID, got.ProgressResult.NativeID)

		require.Equal(t, "eastus", *sent.Location)
		require.Equal(t, armnetwork.BastionHostSKUNameStandard, *sent.SKU.Name)
		require.Equal(t, int32(2), *sent.Properties.ScaleUnits)
		require.Len(t, sent.Properties.IPConfigurations, 1)
		cfg := sent.Properties.IPConfigurations[0]
		require.Equal(t, "IpConf", *cfg.Name)
		require.Equal(t, testBastionSubnetID, *cfg.Properties.Subnet.ID)
		require.Equal(t, testBastionPipID, *cfg.Properties.PublicIPAddress.ID)
		require.Equal(t, armnetwork.IPAllocationMethodDynamic, *cfg.Properties.PrivateIPAllocationMethod)
		require.True(t, *sent.Properties.EnableTunneling)
		require.True(t, *sent.Properties.EnableIPConnect)
		require.False(t, *sent.Properties.EnableFileCopy)
		require.False(t, *sent.Properties.EnableShareableLink)
		require.False(t, *sent.Properties.DisableCopyPaste)
		require.Equal(t, "test", *sent.Tags["env"])
	})

	t.Run("Create_requires_ip_configurations", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "bastion1", "resourceGroupName": "rg-1", "location": "eastus",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "ipConfigurations is required")
	})

	t.Run("Create_requires_public_ip", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "bastion1", "resourceGroupName": "rg-1", "location": "eastus",
			"ipConfigurations": []any{map[string]any{
				"name": "IpConf", "subnetId": testBastionSubnetID,
			}},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "needs a publicIpAddressId")
	})

	// Azure accepts a Bastion host only in a subnet literally named
	// AzureBastionSubnet, and rejects anything else after minutes of provisioning.
	t.Run("Create_rejects_wrong_subnet_name", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "bastion1", "resourceGroupName": "rg-1", "location": "eastus",
			"ipConfigurations": []any{map[string]any{
				"name":              "IpConf",
				"subnetId":          "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/virtualNetworks/vnet1/subnets/default",
				"publicIpAddressId": testBastionPipID,
			}},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "requires a subnet named exactly AzureBastionSubnet")
	})

	// The native ID reported while the LRO is still running must match the path ARM
	// actually assigns, or a ten-minute create orphans a billed host.
	t.Run("PendingCreateReportsRealNativeID", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, _ armnetwork.BastionHost, _ *armnetwork.BastionHostsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.BastionHostsClientCreateOrUpdateResponse], error) {
			return newPendingPoller[armnetwork.BastionHostsClientCreateOrUpdateResponse](), nil
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "bastion1", Properties: bastionHostDesired(2, false),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusInProgress, got.ProgressResult.OperationStatus)
		require.Equal(t, testBastionHostNativeID, got.ProgressResult.NativeID)
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testBastionHostNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "bastion1", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "eastus", props["location"])
		// ARM returns "standard"; the schema union is "Standard".
		require.Equal(t, "Standard", props["sku"].(map[string]any)["name"])
		require.EqualValues(t, 2, props["scaleUnits"])
		require.Equal(t, true, props["enableTunneling"])
		require.Equal(t, true, props["enableIpConnect"])
		require.Equal(t, false, props["enableFileCopy"])
		require.Equal(t, false, props["enableShareableLink"])
		require.Equal(t, false, props["disableCopyPaste"])

		configs := props["ipConfigurations"].([]any)
		require.Len(t, configs, 1)
		cfg := configs[0].(map[string]any)
		require.Equal(t, "IpConf", cfg["name"])
		require.Equal(t, testBastionSubnetID, cfg["subnetId"])
		require.Equal(t, testBastionPipID, cfg["publicIpAddressId"])
		// ARM returns "dynamic"; the schema union is "Dynamic".
		require.Equal(t, "Dynamic", cfg["privateIpAllocationMethod"])
	})

	// Service state and the ARM-assigned per-config identity would read as drift.
	t.Run("Read_drops_service_state", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testBastionHostNativeID})
		require.NoError(t, err)
		for _, key := range []string{
			"provisioningState", "dnsName", "bastion.azure.com", "etag",
			"bastionHostIpConfigurations", "networkAcls",
		} {
			require.NotContains(t, got.Properties, key)
		}
	})

	t.Run("Update_reissues_create_or_update", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, params armnetwork.BastionHost, _ *armnetwork.BastionHostsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.BastionHostsClientCreateOrUpdateResponse], error) {
			sent = params
			createCalls++
			return newDonePoller(armnetwork.BastionHostsClientCreateOrUpdateResponse{BastionHost: hostResult}), nil
		}
		before := createCalls
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testBastionHostNativeID,
			DesiredProperties: bastionHostDesired(3, true),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, createCalls)
		require.Equal(t, int32(3), *sent.Properties.ScaleUnits)
		require.True(t, *sent.Properties.EnableFileCopy)
		// Location, SKU and the IP configuration must ride along: a PUT without them
		// is rejected.
		require.Equal(t, "eastus", *sent.Location)
		require.Equal(t, armnetwork.BastionHostSKUNameStandard, *sent.SKU.Name)
		require.Len(t, sent.Properties.IPConfigurations, 1)
	})

	t.Run("Delete", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testBastionHostNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _ string, _ *armnetwork.BastionHostsClientBeginDeleteOptions) (*runtime.Poller[armnetwork.BastionHostsClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testBastionHostNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_resource_group", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testBastionHostNativeID}, got.NativeIDs)
	})

	t.Run("List_by_subscription", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Equal(t, []string{testBastionHostNativeID}, got.NativeIDs)
	})

	t.Run("Read_NotFound", func(t *testing.T) {
		fake.getFn = func(_ context.Context, _, _ string, _ *armnetwork.BastionHostsClientGetOptions) (armnetwork.BastionHostsClientGetResponse, error) {
			return armnetwork.BastionHostsClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testBastionHostNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
	})
}
