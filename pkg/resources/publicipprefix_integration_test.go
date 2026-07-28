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

const testPublicIPPrefixNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/publicIPPrefixes/pipp-1"

func testPublicIPPrefixModel() armnetwork.PublicIPPrefix {
	return armnetwork.PublicIPPrefix{
		ID:       to.Ptr(testPublicIPPrefixNativeID),
		Name:     to.Ptr("pipp-1"),
		Location: to.Ptr("eastus"),
		SKU: &armnetwork.PublicIPPrefixSKU{
			Name: to.Ptr(armnetwork.PublicIPPrefixSKUNameStandard),
			Tier: to.Ptr(armnetwork.PublicIPPrefixSKUTierRegional),
		},
		Properties: &armnetwork.PublicIPPrefixPropertiesFormat{
			PrefixLength:           to.Ptr(int32(30)),
			PublicIPAddressVersion: to.Ptr(armnetwork.IPVersionIPv4),
			IPPrefix:               to.Ptr("20.10.0.0/30"),
		},
		Tags: map[string]*string{"Environment": to.Ptr("test")},
	}
}

func TestPublicIPPrefix_CRUD(t *testing.T) {
	model := testPublicIPPrefixModel()
	fake := &fakePublicIPPrefixesAPI{
		beginCreateOrUpdateFn: func(_ context.Context, _, _ string, _ armnetwork.PublicIPPrefix, _ *armnetwork.PublicIPPrefixesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.PublicIPPrefixesClientCreateOrUpdateResponse], error) {
			return newDonePoller(armnetwork.PublicIPPrefixesClientCreateOrUpdateResponse{PublicIPPrefix: model}), nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armnetwork.PublicIPPrefixesClientGetOptions) (armnetwork.PublicIPPrefixesClientGetResponse, error) {
			return armnetwork.PublicIPPrefixesClientGetResponse{PublicIPPrefix: model}, nil
		},
		beginDeleteFn: func(_ context.Context, _, _ string, _ *armnetwork.PublicIPPrefixesClientBeginDeleteOptions) (*runtime.Poller[armnetwork.PublicIPPrefixesClientDeleteResponse], error) {
			return newInProgressPoller[armnetwork.PublicIPPrefixesClientDeleteResponse](), nil
		},
		newListPagerFn: func(_ string, _ *armnetwork.PublicIPPrefixesClientListOptions) *runtime.Pager[armnetwork.PublicIPPrefixesClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armnetwork.PublicIPPrefixesClientListResponse]{
				More: func(_ armnetwork.PublicIPPrefixesClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armnetwork.PublicIPPrefixesClientListResponse) (armnetwork.PublicIPPrefixesClientListResponse, error) {
					return armnetwork.PublicIPPrefixesClientListResponse{
						PublicIPPrefixListResult: armnetwork.PublicIPPrefixListResult{
							Value: []*armnetwork.PublicIPPrefix{{ID: to.Ptr(testPublicIPPrefixNativeID)}},
						},
					}, nil
				},
			})
		},
		newListAllPagerFn: func(_ *armnetwork.PublicIPPrefixesClientListAllOptions) *runtime.Pager[armnetwork.PublicIPPrefixesClientListAllResponse] {
			return runtime.NewPager(runtime.PagingHandler[armnetwork.PublicIPPrefixesClientListAllResponse]{
				More: func(_ armnetwork.PublicIPPrefixesClientListAllResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armnetwork.PublicIPPrefixesClientListAllResponse) (armnetwork.PublicIPPrefixesClientListAllResponse, error) {
					return armnetwork.PublicIPPrefixesClientListAllResponse{
						PublicIPPrefixListResult: armnetwork.PublicIPPrefixListResult{
							Value: []*armnetwork.PublicIPPrefix{{ID: to.Ptr(testPublicIPPrefixNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestPublicIPPrefix(fake)

	mkProps := func() json.RawMessage {
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName":      "rg-1",
			"name":                   "pipp-1",
			"location":               "eastus",
			"sku":                    map[string]any{"name": "Standard", "tier": "Regional"},
			"prefixLength":           30,
			"publicIPAddressVersion": "IPv4",
			"Tags":                   []map[string]string{{"Key": "Environment", "Value": "test"}},
		})
		return props
	}

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testPublicIPPrefixNativeID, got.ProgressResult.NativeID)

		var serialized map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &serialized))
		require.Equal(t, "pipp-1", serialized["name"])
		require.Equal(t, "rg-1", serialized["resourceGroupName"])
		require.Equal(t, float64(30), serialized["prefixLength"])
		require.Equal(t, "IPv4", serialized["publicIPAddressVersion"])
		require.Equal(t, map[string]any{"name": "Standard", "tier": "Regional"}, serialized["sku"])
		// Azure-allocated CIDR is surfaced read-only.
		require.Equal(t, "20.10.0.0/30", serialized["ipPrefix"])
	})

	t.Run("Create_forwards_params_to_ARM", func(t *testing.T) {
		var seen armnetwork.PublicIPPrefix
		var seenRG, seenName string
		fake.beginCreateOrUpdateFn = func(_ context.Context, rg, name string, params armnetwork.PublicIPPrefix, _ *armnetwork.PublicIPPrefixesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.PublicIPPrefixesClientCreateOrUpdateResponse], error) {
			seen, seenRG, seenName = params, rg, name
			return newDonePoller(armnetwork.PublicIPPrefixesClientCreateOrUpdateResponse{PublicIPPrefix: model}), nil
		}
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, "rg-1", seenRG)
		require.Equal(t, "pipp-1", seenName)
		require.Equal(t, "eastus", *seen.Location)
		require.Equal(t, armnetwork.PublicIPPrefixSKUNameStandard, *seen.SKU.Name)
		require.Equal(t, armnetwork.PublicIPPrefixSKUTierRegional, *seen.SKU.Tier)
		require.Equal(t, int32(30), *seen.Properties.PrefixLength)
		require.Equal(t, armnetwork.IPVersionIPv4, *seen.Properties.PublicIPAddressVersion)
		require.Equal(t, "test", *seen.Tags["Environment"])

		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, _ armnetwork.PublicIPPrefix, _ *armnetwork.PublicIPPrefixesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.PublicIPPrefixesClientCreateOrUpdateResponse], error) {
			return newDonePoller(armnetwork.PublicIPPrefixesClientCreateOrUpdateResponse{PublicIPPrefix: model}), nil
		}
	})

	t.Run("Create_forwards_ipTags_and_zones", func(t *testing.T) {
		var seen armnetwork.PublicIPPrefix
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, params armnetwork.PublicIPPrefix, _ *armnetwork.PublicIPPrefixesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.PublicIPPrefixesClientCreateOrUpdateResponse], error) {
			seen = params
			return newDonePoller(armnetwork.PublicIPPrefixesClientCreateOrUpdateResponse{PublicIPPrefix: model}), nil
		}
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName": "rg-1",
			"name":              "pipp-1",
			"location":          "eastus",
			"sku":               map[string]any{"name": "Standard"},
			"prefixLength":      30,
			"ipTags":            []map[string]any{{"ipTagType": "FirstPartyUsage", "tag": "SQL"}},
			"zones":             []any{"1", "2"},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.Len(t, seen.Properties.IPTags, 1)
		require.Equal(t, "FirstPartyUsage", *seen.Properties.IPTags[0].IPTagType)
		require.Equal(t, "SQL", *seen.Properties.IPTags[0].Tag)
		require.Len(t, seen.Zones, 2)
		require.Equal(t, "1", *seen.Zones[0])

		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, _ armnetwork.PublicIPPrefix, _ *armnetwork.PublicIPPrefixesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.PublicIPPrefixesClientCreateOrUpdateResponse], error) {
			return newDonePoller(armnetwork.PublicIPPrefixesClientCreateOrUpdateResponse{PublicIPPrefix: model}), nil
		}
	})

	t.Run("Create_requires_sku_and_prefixLength", func(t *testing.T) {
		noSKU, _ := json.Marshal(map[string]any{
			"resourceGroupName": "rg-1", "name": "pipp-1", "location": "eastus", "prefixLength": 30,
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: noSKU})
		require.ErrorContains(t, err, "sku is required")

		noLen, _ := json.Marshal(map[string]any{
			"resourceGroupName": "rg-1", "name": "pipp-1", "location": "eastus",
			"sku": map[string]any{"name": "Standard"},
		})
		_, err = prov.Create(context.Background(), &resource.CreateRequest{Properties: noLen})
		require.ErrorContains(t, err, "prefixLength is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testPublicIPPrefixNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
		require.Equal(t, ResourceTypePublicIPPrefix, got.ResourceType)
	})

	t.Run("Read_not_found", func(t *testing.T) {
		fake.getFn = func(_ context.Context, _, _ string, _ *armnetwork.PublicIPPrefixesClientGetOptions) (armnetwork.PublicIPPrefixesClientGetResponse, error) {
			return armnetwork.PublicIPPrefixesClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testPublicIPPrefixNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)

		fake.getFn = func(_ context.Context, _, _ string, _ *armnetwork.PublicIPPrefixesClientGetOptions) (armnetwork.PublicIPPrefixesClientGetResponse, error) {
			return armnetwork.PublicIPPrefixesClientGetResponse{PublicIPPrefix: model}, nil
		}
	})

	// ARM requires the immutable prefixLength/SKU in every PUT, so Update echoes
	// the full body rather than sending a tags-only patch.
	t.Run("Update_sends_full_body", func(t *testing.T) {
		var seen armnetwork.PublicIPPrefix
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, params armnetwork.PublicIPPrefix, _ *armnetwork.PublicIPPrefixesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.PublicIPPrefixesClientCreateOrUpdateResponse], error) {
			seen = params
			return newDonePoller(armnetwork.PublicIPPrefixesClientCreateOrUpdateResponse{PublicIPPrefix: model}), nil
		}
		desired, _ := json.Marshal(map[string]any{
			"resourceGroupName": "rg-1",
			"name":              "pipp-1",
			"location":          "eastus",
			"sku":               map[string]any{"name": "Standard", "tier": "Regional"},
			"prefixLength":      30,
			"Tags":              []map[string]string{{"Key": "Environment", "Value": "updated"}},
		})
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testPublicIPPrefixNativeID,
			DesiredProperties: desired,
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, int32(30), *seen.Properties.PrefixLength)
		require.Equal(t, "updated", *seen.Tags["Environment"])
	})

	t.Run("Delete_in_progress_returns_lro_request_id", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testPublicIPPrefixNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusInProgress, got.ProgressResult.OperationStatus)
		reqID, err := decodeLROStatus(got.ProgressResult.RequestID)
		require.NoError(t, err)
		require.Equal(t, lroOpDelete, reqID.OperationType)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _ string, _ *armnetwork.PublicIPPrefixesClientBeginDeleteOptions) (*runtime.Poller[armnetwork.PublicIPPrefixesClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testPublicIPPrefixNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Status_rejects_unknown_operation", func(t *testing.T) {
		reqID, err := encodeLROStart("bogus", "token", testPublicIPPrefixNativeID)
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
		require.Equal(t, []string{testPublicIPPrefixNativeID}, got.NativeIDs)
	})

	t.Run("List_all", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Equal(t, []string{testPublicIPPrefixNativeID}, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, _ armnetwork.PublicIPPrefix, _ *armnetwork.PublicIPPrefixesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.PublicIPPrefixesClientCreateOrUpdateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 403}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

func TestPublicIPPrefixIDParts(t *testing.T) {
	rg, name, err := publicIPPrefixIDParts(testPublicIPPrefixNativeID)
	require.NoError(t, err)
	require.Equal(t, "rg-1", rg)
	require.Equal(t, "pipp-1", name)

	_, _, err = publicIPPrefixIDParts("/subscriptions/sub-1/resourceGroups/rg-1")
	require.Error(t, err)
}

// --- Test helpers ---

func newTestPublicIPPrefix(api publicIPPrefixesAPI) *PublicIPPrefix {
	return &PublicIPPrefix{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

type fakePublicIPPrefixesAPI struct {
	beginCreateOrUpdateFn func(ctx context.Context, rgName, name string, params armnetwork.PublicIPPrefix, opts *armnetwork.PublicIPPrefixesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.PublicIPPrefixesClientCreateOrUpdateResponse], error)
	getFn                 func(ctx context.Context, rgName, name string, opts *armnetwork.PublicIPPrefixesClientGetOptions) (armnetwork.PublicIPPrefixesClientGetResponse, error)
	beginDeleteFn         func(ctx context.Context, rgName, name string, opts *armnetwork.PublicIPPrefixesClientBeginDeleteOptions) (*runtime.Poller[armnetwork.PublicIPPrefixesClientDeleteResponse], error)
	newListPagerFn        func(rgName string, opts *armnetwork.PublicIPPrefixesClientListOptions) *runtime.Pager[armnetwork.PublicIPPrefixesClientListResponse]
	newListAllPagerFn     func(opts *armnetwork.PublicIPPrefixesClientListAllOptions) *runtime.Pager[armnetwork.PublicIPPrefixesClientListAllResponse]
}

func (f *fakePublicIPPrefixesAPI) BeginCreateOrUpdate(ctx context.Context, rgName, name string, params armnetwork.PublicIPPrefix, opts *armnetwork.PublicIPPrefixesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.PublicIPPrefixesClientCreateOrUpdateResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, rgName, name, params, opts)
}

func (f *fakePublicIPPrefixesAPI) Get(ctx context.Context, rgName, name string, opts *armnetwork.PublicIPPrefixesClientGetOptions) (armnetwork.PublicIPPrefixesClientGetResponse, error) {
	return f.getFn(ctx, rgName, name, opts)
}

func (f *fakePublicIPPrefixesAPI) BeginDelete(ctx context.Context, rgName, name string, opts *armnetwork.PublicIPPrefixesClientBeginDeleteOptions) (*runtime.Poller[armnetwork.PublicIPPrefixesClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, name, opts)
}

func (f *fakePublicIPPrefixesAPI) NewListPager(rgName string, opts *armnetwork.PublicIPPrefixesClientListOptions) *runtime.Pager[armnetwork.PublicIPPrefixesClientListResponse] {
	return f.newListPagerFn(rgName, opts)
}

func (f *fakePublicIPPrefixesAPI) NewListAllPager(opts *armnetwork.PublicIPPrefixesClientListAllOptions) *runtime.Pager[armnetwork.PublicIPPrefixesClientListAllResponse] {
	return f.newListAllPagerFn(opts)
}
