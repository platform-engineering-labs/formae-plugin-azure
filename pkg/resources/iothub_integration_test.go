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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/iothub/armiothub"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testIotHubNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Devices/IotHubs/hub-1"

func newTestIotHub(api iotHubAPI) *IotHub {
	return &IotHub{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func iotHubDesired(comments string) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":                "hub-1",
		"location":            "eastus",
		"resourceGroupName":   "rg-1",
		"sku":                 map[string]any{"name": "S1", "capacity": 1},
		"publicNetworkAccess": "Enabled",
		"comments":            comments,
	})
	return out
}

func TestIotHub_CRUD(t *testing.T) {
	// ARM returns the SAS keys inline under authorizationPolicies on every read.
	hubResult := armiothub.Description{
		ID:       to.Ptr(testIotHubNativeID),
		Name:     to.Ptr("hub-1"),
		Location: to.Ptr("East US"),
		SKU: &armiothub.SKUInfo{
			Name:     to.Ptr(armiothub.IotHubSKUS1),
			Capacity: to.Ptr(int64(1)),
		},
		Properties: &armiothub.Properties{
			HostName:            to.Ptr("hub-1.azure-devices.net"),
			PublicNetworkAccess: to.Ptr(armiothub.PublicNetworkAccessEnabled),
			Comments:            to.Ptr("managed by formae"),
			AuthorizationPolicies: []*armiothub.SharedAccessSignatureAuthorizationRule{{
				KeyName:      to.Ptr("iothubowner"),
				PrimaryKey:   to.Ptr("SUPER-SECRET-PRIMARY"),
				SecondaryKey: to.Ptr("SUPER-SECRET-SECONDARY"),
			}},
		},
	}

	var sent armiothub.Description
	putCalls := 0
	fake := &fakeIotHubAPI{
		beginCreateOrUpdateFn: func(_ context.Context, _, name string, desc armiothub.Description, _ *armiothub.ResourceClientBeginCreateOrUpdateOptions) (*runtime.Poller[armiothub.ResourceClientCreateOrUpdateResponse], error) {
			require.Equal(t, "hub-1", name)
			putCalls++
			sent = desc
			return newDonePoller(armiothub.ResourceClientCreateOrUpdateResponse{Description: hubResult}), nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armiothub.ResourceClientGetOptions) (armiothub.ResourceClientGetResponse, error) {
			return armiothub.ResourceClientGetResponse{Description: hubResult}, nil
		},
		beginDeleteFn: func(_ context.Context, _, _ string, _ *armiothub.ResourceClientBeginDeleteOptions) (*runtime.Poller[armiothub.ResourceClientDeleteResponse], error) {
			return newDonePoller(armiothub.ResourceClientDeleteResponse{}), nil
		},
		newListBySubscriptionPagerFn: func(_ *armiothub.ResourceClientListBySubscriptionOptions) *runtime.Pager[armiothub.ResourceClientListBySubscriptionResponse] {
			return runtime.NewPager(runtime.PagingHandler[armiothub.ResourceClientListBySubscriptionResponse]{
				More: func(_ armiothub.ResourceClientListBySubscriptionResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armiothub.ResourceClientListBySubscriptionResponse) (armiothub.ResourceClientListBySubscriptionResponse, error) {
					return armiothub.ResourceClientListBySubscriptionResponse{
						DescriptionListResult: armiothub.DescriptionListResult{
							Value: []*armiothub.Description{
								{ID: to.Ptr(testIotHubNativeID)},
								{ID: to.Ptr("/subscriptions/sub-1/resourceGroups/rg-2/providers/Microsoft.Devices/IotHubs/hub-2")},
							},
						},
					}, nil
				},
			})
		},
		newListByResourceGroupPagerFn: func(_ string, _ *armiothub.ResourceClientListByResourceGroupOptions) *runtime.Pager[armiothub.ResourceClientListByResourceGroupResponse] {
			return runtime.NewPager(runtime.PagingHandler[armiothub.ResourceClientListByResourceGroupResponse]{
				More: func(_ armiothub.ResourceClientListByResourceGroupResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armiothub.ResourceClientListByResourceGroupResponse) (armiothub.ResourceClientListByResourceGroupResponse, error) {
					return armiothub.ResourceClientListByResourceGroupResponse{
						DescriptionListResult: armiothub.DescriptionListResult{
							Value: []*armiothub.Description{{ID: to.Ptr(testIotHubNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestIotHub(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "hub-1", Properties: iotHubDesired("managed by formae")})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testIotHubNativeID, got.ProgressResult.NativeID)

		require.Equal(t, armiothub.IotHubSKUS1, *sent.SKU.Name)
		require.EqualValues(t, 1, *sent.SKU.Capacity)
		require.Equal(t, "managed by formae", *sent.Properties.Comments)
	})

	// capacity below 1 is invalid; the handler floors it rather than sending 0.
	t.Run("Create_floors_capacity", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "hub-1", "location": "eastus", "resourceGroupName": "rg-1",
			"sku": map[string]any{"name": "S1"},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "hub-1", Properties: props})
		require.NoError(t, err)
		require.EqualValues(t, 1, *sent.SKU.Capacity)
	})

	t.Run("Create_requires_sku", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "hub-1", "location": "eastus", "resourceGroupName": "rg-1",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "sku.name is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testIotHubNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "hub-1", props["name"])
		require.Equal(t, "eastus", props["location"])
		require.Equal(t, "hub-1.azure-devices.net", props["hostName"])
		require.Equal(t, "Enabled", props["publicNetworkAccess"])
		sku := props["sku"].(map[string]any)
		require.Equal(t, "S1", sku["name"])
	})

	// The SAS keys arrive inline on every read; authorizationPolicies must not be
	// serialized at all.
	t.Run("inline_sas_keys_never_serialized", func(t *testing.T) {
		read, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testIotHubNativeID})
		require.NoError(t, err)
		created, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "hub-1", Properties: iotHubDesired("x")})
		require.NoError(t, err)
		for _, payload := range []string{read.Properties, string(created.ProgressResult.ResourceProperties)} {
			require.NotContains(t, payload, "SUPER-SECRET-PRIMARY")
			require.NotContains(t, payload, "SUPER-SECRET-SECONDARY")
			require.NotContains(t, payload, "authorizationPolicies")
			require.NotContains(t, payload, "primaryKey")
		}
	})

	// ARM's PATCH body is a TagsResource and cannot carry properties, so an update
	// has to be a full CreateOrUpdate PUT.
	t.Run("Update_uses_full_put", func(t *testing.T) {
		before := putCalls
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testIotHubNativeID,
			DesiredProperties: iotHubDesired("updated comment"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testIotHubNativeID, got.ProgressResult.NativeID)
		require.Equal(t, before+1, putCalls, "Update must issue a CreateOrUpdate PUT")
		require.Equal(t, "updated comment", *sent.Properties.Comments)
	})

	t.Run("Delete", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testIotHubNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _ string, _ *armiothub.ResourceClientBeginDeleteOptions) (*runtime.Poller[armiothub.ResourceClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testIotHubNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_resource_group", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testIotHubNativeID}, got.NativeIDs)
	})

	t.Run("List_without_group_is_subscription_wide", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 2)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, _ armiothub.Description, _ *armiothub.ResourceClientBeginCreateOrUpdateOptions) (*runtime.Poller[armiothub.ResourceClientCreateOrUpdateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 409}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "hub-1", Properties: iotHubDesired("x")})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

func TestIotHub_ReadNotFound(t *testing.T) {
	fake := &fakeIotHubAPI{
		getFn: func(_ context.Context, _, _ string, _ *armiothub.ResourceClientGetOptions) (armiothub.ResourceClientGetResponse, error) {
			return armiothub.ResourceClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestIotHub(fake).Read(context.Background(), &resource.ReadRequest{NativeID: testIotHubNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeIotHubAPI struct {
	beginCreateOrUpdateFn         func(ctx context.Context, rgName, name string, desc armiothub.Description, options *armiothub.ResourceClientBeginCreateOrUpdateOptions) (*runtime.Poller[armiothub.ResourceClientCreateOrUpdateResponse], error)
	getFn                         func(ctx context.Context, rgName, name string, options *armiothub.ResourceClientGetOptions) (armiothub.ResourceClientGetResponse, error)
	beginDeleteFn                 func(ctx context.Context, rgName, name string, options *armiothub.ResourceClientBeginDeleteOptions) (*runtime.Poller[armiothub.ResourceClientDeleteResponse], error)
	newListBySubscriptionPagerFn  func(options *armiothub.ResourceClientListBySubscriptionOptions) *runtime.Pager[armiothub.ResourceClientListBySubscriptionResponse]
	newListByResourceGroupPagerFn func(rgName string, options *armiothub.ResourceClientListByResourceGroupOptions) *runtime.Pager[armiothub.ResourceClientListByResourceGroupResponse]
}

func (f *fakeIotHubAPI) BeginCreateOrUpdate(ctx context.Context, rgName, name string, desc armiothub.Description, options *armiothub.ResourceClientBeginCreateOrUpdateOptions) (*runtime.Poller[armiothub.ResourceClientCreateOrUpdateResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, rgName, name, desc, options)
}

func (f *fakeIotHubAPI) Get(ctx context.Context, rgName, name string, options *armiothub.ResourceClientGetOptions) (armiothub.ResourceClientGetResponse, error) {
	return f.getFn(ctx, rgName, name, options)
}

func (f *fakeIotHubAPI) BeginDelete(ctx context.Context, rgName, name string, options *armiothub.ResourceClientBeginDeleteOptions) (*runtime.Poller[armiothub.ResourceClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, name, options)
}

func (f *fakeIotHubAPI) NewListBySubscriptionPager(options *armiothub.ResourceClientListBySubscriptionOptions) *runtime.Pager[armiothub.ResourceClientListBySubscriptionResponse] {
	return f.newListBySubscriptionPagerFn(options)
}

func (f *fakeIotHubAPI) NewListByResourceGroupPager(rgName string, options *armiothub.ResourceClientListByResourceGroupOptions) *runtime.Pager[armiothub.ResourceClientListByResourceGroupResponse] {
	return f.newListByResourceGroupPagerFn(rgName, options)
}
