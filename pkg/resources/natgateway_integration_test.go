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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v4"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const (
	testNatGatewayNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/natGateways/nat-1"
	testNatPipA            = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/publicIPAddresses/pip-a"
	testNatPipB            = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/publicIPAddresses/pip-b"
)

func TestNatGateway_CRUD(t *testing.T) {
	// Azure echoes references back in its own order; the model deliberately lists
	// them reversed to prove serialize sorts.
	model := armnetwork.NatGateway{
		ID:       to.Ptr(testNatGatewayNativeID),
		Name:     to.Ptr("nat-1"),
		Location: to.Ptr("eastus"),
		SKU:      &armnetwork.NatGatewaySKU{Name: to.Ptr(armnetwork.NatGatewaySKUNameStandard)},
		Properties: &armnetwork.NatGatewayPropertiesFormat{
			IdleTimeoutInMinutes: to.Ptr(int32(4)),
			PublicIPAddresses: []*armnetwork.SubResource{
				{ID: to.Ptr(testNatPipB)},
				{ID: to.Ptr(testNatPipA)},
			},
		},
		Tags: map[string]*string{"Environment": to.Ptr("test")},
	}
	fake := &fakeNatGatewaysAPI{
		beginCreateOrUpdateFn: func(_ context.Context, _, _ string, _ armnetwork.NatGateway, _ *armnetwork.NatGatewaysClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.NatGatewaysClientCreateOrUpdateResponse], error) {
			return newDonePoller(armnetwork.NatGatewaysClientCreateOrUpdateResponse{NatGateway: model}), nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armnetwork.NatGatewaysClientGetOptions) (armnetwork.NatGatewaysClientGetResponse, error) {
			return armnetwork.NatGatewaysClientGetResponse{NatGateway: model}, nil
		},
		beginDeleteFn: func(_ context.Context, _, _ string, _ *armnetwork.NatGatewaysClientBeginDeleteOptions) (*runtime.Poller[armnetwork.NatGatewaysClientDeleteResponse], error) {
			return newInProgressPoller[armnetwork.NatGatewaysClientDeleteResponse](), nil
		},
		newListPagerFn: func(_ string, _ *armnetwork.NatGatewaysClientListOptions) *runtime.Pager[armnetwork.NatGatewaysClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armnetwork.NatGatewaysClientListResponse]{
				More: func(_ armnetwork.NatGatewaysClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armnetwork.NatGatewaysClientListResponse) (armnetwork.NatGatewaysClientListResponse, error) {
					return armnetwork.NatGatewaysClientListResponse{
						NatGatewayListResult: armnetwork.NatGatewayListResult{
							Value: []*armnetwork.NatGateway{{ID: to.Ptr(testNatGatewayNativeID)}},
						},
					}, nil
				},
			})
		},
		newListAllPagerFn: func(_ *armnetwork.NatGatewaysClientListAllOptions) *runtime.Pager[armnetwork.NatGatewaysClientListAllResponse] {
			return runtime.NewPager(runtime.PagingHandler[armnetwork.NatGatewaysClientListAllResponse]{
				More: func(_ armnetwork.NatGatewaysClientListAllResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armnetwork.NatGatewaysClientListAllResponse) (armnetwork.NatGatewaysClientListAllResponse, error) {
					return armnetwork.NatGatewaysClientListAllResponse{
						NatGatewayListResult: armnetwork.NatGatewayListResult{
							Value: []*armnetwork.NatGateway{{ID: to.Ptr(testNatGatewayNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestNatGateway(fake)

	mkProps := func() json.RawMessage {
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName":    "rg-1",
			"name":                 "nat-1",
			"location":             "eastus",
			"sku":                  map[string]any{"name": "Standard"},
			"idleTimeoutInMinutes": 4,
			"publicIpAddressIds":   []any{testNatPipA, testNatPipB},
			"Tags":                 []map[string]string{{"Key": "Environment", "Value": "test"}},
		})
		return props
	}

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testNatGatewayNativeID, got.ProgressResult.NativeID)

		var serialized map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &serialized))
		require.Equal(t, "nat-1", serialized["name"])
		require.Equal(t, "rg-1", serialized["resourceGroupName"])
		require.Equal(t, float64(4), serialized["idleTimeoutInMinutes"])
		require.Equal(t, map[string]any{"name": "Standard"}, serialized["sku"])
	})

	// ARM does not promise to echo SubResource references in submitted order, so
	// both directions sort — otherwise Read reports drift against an identical set.
	t.Run("Serialize_sorts_public_ip_references", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testNatGatewayNativeID})
		require.NoError(t, err)
		var serialized map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &serialized))
		require.Equal(t, []any{testNatPipA, testNatPipB}, serialized["publicIpAddressIds"])
	})

	t.Run("Create_forwards_params_to_ARM", func(t *testing.T) {
		var seen armnetwork.NatGateway
		var seenRG, seenName string
		fake.beginCreateOrUpdateFn = func(_ context.Context, rg, name string, params armnetwork.NatGateway, _ *armnetwork.NatGatewaysClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.NatGatewaysClientCreateOrUpdateResponse], error) {
			seen, seenRG, seenName = params, rg, name
			return newDonePoller(armnetwork.NatGatewaysClientCreateOrUpdateResponse{NatGateway: model}), nil
		}
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName":    "rg-1",
			"name":                 "nat-1",
			"location":             "eastus",
			"idleTimeoutInMinutes": 10,
			"publicIpAddressIds":   []any{testNatPipB, testNatPipA},
			"zones":                []any{"1"},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.Equal(t, "rg-1", seenRG)
		require.Equal(t, "nat-1", seenName)
		require.Equal(t, "eastus", *seen.Location)
		// SKU defaults to Standard when omitted — ARM requires it in the body.
		require.Equal(t, armnetwork.NatGatewaySKUNameStandard, *seen.SKU.Name)
		require.Equal(t, int32(10), *seen.Properties.IdleTimeoutInMinutes)
		require.Len(t, seen.Properties.PublicIPAddresses, 2)
		require.Equal(t, testNatPipA, *seen.Properties.PublicIPAddresses[0].ID)
		require.Equal(t, testNatPipB, *seen.Properties.PublicIPAddresses[1].ID)
		require.Len(t, seen.Zones, 1)

		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, _ armnetwork.NatGateway, _ *armnetwork.NatGatewaysClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.NatGatewaysClientCreateOrUpdateResponse], error) {
			return newDonePoller(armnetwork.NatGatewaysClientCreateOrUpdateResponse{NatGateway: model}), nil
		}
	})

	t.Run("Create_requires_location", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"resourceGroupName": "rg-1", "name": "nat-1"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "location is required")
	})

	t.Run("Create_requires_resourceGroupName", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "nat-1", "location": "eastus"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "resourceGroupName is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testNatGatewayNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
		require.Equal(t, ResourceTypeNatGateway, got.ResourceType)
	})

	t.Run("Read_not_found", func(t *testing.T) {
		fake.getFn = func(_ context.Context, _, _ string, _ *armnetwork.NatGatewaysClientGetOptions) (armnetwork.NatGatewaysClientGetResponse, error) {
			return armnetwork.NatGatewaysClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testNatGatewayNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)

		fake.getFn = func(_ context.Context, _, _ string, _ *armnetwork.NatGatewaysClientGetOptions) (armnetwork.NatGatewaysClientGetResponse, error) {
			return armnetwork.NatGatewaysClientGetResponse{NatGateway: model}, nil
		}
	})

	// The NAT gateway PATCH verb (UpdateTags) accepts tags only, so idle timeout and
	// IP association changes must go through the full-body PUT.
	t.Run("Update_sends_full_body_put", func(t *testing.T) {
		var seen armnetwork.NatGateway
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, params armnetwork.NatGateway, _ *armnetwork.NatGatewaysClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.NatGatewaysClientCreateOrUpdateResponse], error) {
			seen = params
			return newDonePoller(armnetwork.NatGatewaysClientCreateOrUpdateResponse{NatGateway: model}), nil
		}
		desired, _ := json.Marshal(map[string]any{
			"resourceGroupName":    "rg-1",
			"name":                 "nat-1",
			"location":             "eastus",
			"sku":                  map[string]any{"name": "Standard"},
			"idleTimeoutInMinutes": 15,
			"publicIpAddressIds":   []any{testNatPipA},
			"Tags":                 []map[string]string{{"Key": "Environment", "Value": "updated"}},
		})
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testNatGatewayNativeID,
			DesiredProperties: desired,
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, int32(15), *seen.Properties.IdleTimeoutInMinutes)
		require.Len(t, seen.Properties.PublicIPAddresses, 1)
		require.Equal(t, "updated", *seen.Tags["Environment"])
	})

	t.Run("Delete_in_progress_returns_lro_request_id", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testNatGatewayNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusInProgress, got.ProgressResult.OperationStatus)
		reqID, err := decodeLROStatus(got.ProgressResult.RequestID)
		require.NoError(t, err)
		require.Equal(t, lroOpDelete, reqID.OperationType)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _ string, _ *armnetwork.NatGatewaysClientBeginDeleteOptions) (*runtime.Poller[armnetwork.NatGatewaysClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testNatGatewayNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Status_rejects_unknown_operation", func(t *testing.T) {
		reqID, err := encodeLROStart("bogus", "token", testNatGatewayNativeID)
		require.NoError(t, err)
		got, err := prov.Status(context.Background(), &resource.StatusRequest{RequestID: reqID})
		require.Error(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_resource_group", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testNatGatewayNativeID}, got.NativeIDs)
	})

	t.Run("List_all", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Equal(t, []string{testNatGatewayNativeID}, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, _ armnetwork.NatGateway, _ *armnetwork.NatGatewaysClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.NatGatewaysClientCreateOrUpdateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 403}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

func TestNatGatewayIDParts(t *testing.T) {
	rg, name, err := natGatewayIDParts(testNatGatewayNativeID)
	require.NoError(t, err)
	require.Equal(t, "rg-1", rg)
	require.Equal(t, "nat-1", name)

	_, _, err = natGatewayIDParts("/subscriptions/sub-1/resourceGroups/rg-1")
	require.Error(t, err)
}

// --- Test helpers ---

func newTestNatGateway(api natGatewaysAPI) *NatGateway {
	return &NatGateway{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

type fakeNatGatewaysAPI struct {
	beginCreateOrUpdateFn func(ctx context.Context, rgName, name string, params armnetwork.NatGateway, opts *armnetwork.NatGatewaysClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.NatGatewaysClientCreateOrUpdateResponse], error)
	getFn                 func(ctx context.Context, rgName, name string, opts *armnetwork.NatGatewaysClientGetOptions) (armnetwork.NatGatewaysClientGetResponse, error)
	beginDeleteFn         func(ctx context.Context, rgName, name string, opts *armnetwork.NatGatewaysClientBeginDeleteOptions) (*runtime.Poller[armnetwork.NatGatewaysClientDeleteResponse], error)
	newListPagerFn        func(rgName string, opts *armnetwork.NatGatewaysClientListOptions) *runtime.Pager[armnetwork.NatGatewaysClientListResponse]
	newListAllPagerFn     func(opts *armnetwork.NatGatewaysClientListAllOptions) *runtime.Pager[armnetwork.NatGatewaysClientListAllResponse]
}

func (f *fakeNatGatewaysAPI) BeginCreateOrUpdate(ctx context.Context, rgName, name string, params armnetwork.NatGateway, opts *armnetwork.NatGatewaysClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.NatGatewaysClientCreateOrUpdateResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, rgName, name, params, opts)
}

func (f *fakeNatGatewaysAPI) Get(ctx context.Context, rgName, name string, opts *armnetwork.NatGatewaysClientGetOptions) (armnetwork.NatGatewaysClientGetResponse, error) {
	return f.getFn(ctx, rgName, name, opts)
}

func (f *fakeNatGatewaysAPI) BeginDelete(ctx context.Context, rgName, name string, opts *armnetwork.NatGatewaysClientBeginDeleteOptions) (*runtime.Poller[armnetwork.NatGatewaysClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, name, opts)
}

func (f *fakeNatGatewaysAPI) NewListPager(rgName string, opts *armnetwork.NatGatewaysClientListOptions) *runtime.Pager[armnetwork.NatGatewaysClientListResponse] {
	return f.newListPagerFn(rgName, opts)
}

func (f *fakeNatGatewaysAPI) NewListAllPager(opts *armnetwork.NatGatewaysClientListAllOptions) *runtime.Pager[armnetwork.NatGatewaysClientListAllResponse] {
	return f.newListAllPagerFn(opts)
}
