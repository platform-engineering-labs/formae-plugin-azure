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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/cosmos/armcosmos/v3"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testCosmosAccountNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.DocumentDB/databaseAccounts/cosmos-1"

func newTestCosmosDatabaseAccount(api cosmosDatabaseAccountsAPI) *CosmosDatabaseAccount {
	return &CosmosDatabaseAccount{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func cosmosDesired(level string, withStaleness bool) []byte {
	consistency := map[string]any{"defaultConsistencyLevel": level}
	if withStaleness {
		consistency["maxStalenessPrefix"] = 100
		consistency["maxIntervalInSeconds"] = 300
	}
	out, _ := json.Marshal(map[string]any{
		"name":              "cosmos-1",
		"location":          "eastus",
		"resourceGroupName": "rg-1",
		"kind":              "GlobalDocumentDB",
		"geoLocations": []map[string]any{
			{"locationName": "eastus", "failoverPriority": 0, "isZoneRedundant": false},
		},
		"consistencyPolicy":   consistency,
		"publicNetworkAccess": "Enabled",
	})
	return out
}

func TestCosmosDatabaseAccount_CRUD(t *testing.T) {
	acctResult := armcosmos.DatabaseAccountGetResults{
		ID:       to.Ptr(testCosmosAccountNativeID),
		Name:     to.Ptr("cosmos-1"),
		Location: to.Ptr("East US"),
		Kind:     to.Ptr(armcosmos.DatabaseAccountKindGlobalDocumentDB),
		Properties: &armcosmos.DatabaseAccountGetProperties{
			DocumentEndpoint:    to.Ptr("https://cosmos-1.documents.azure.com:443/"),
			PublicNetworkAccess: to.Ptr(armcosmos.PublicNetworkAccessEnabled),
			ConsistencyPolicy: &armcosmos.ConsistencyPolicy{
				DefaultConsistencyLevel: to.Ptr(armcosmos.DefaultConsistencyLevelSession),
			},
			Locations: []*armcosmos.Location{
				{LocationName: to.Ptr("East US"), FailoverPriority: to.Ptr(int32(0)), IsZoneRedundant: to.Ptr(false)},
			},
		},
	}

	var sentCreate armcosmos.DatabaseAccountCreateUpdateParameters
	var sentUpdate armcosmos.DatabaseAccountUpdateParameters
	fake := &fakeCosmosAccountsAPI{
		beginCreateOrUpdateFn: func(_ context.Context, _, name string, params armcosmos.DatabaseAccountCreateUpdateParameters, _ *armcosmos.DatabaseAccountsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armcosmos.DatabaseAccountsClientCreateOrUpdateResponse], error) {
			require.Equal(t, "cosmos-1", name)
			sentCreate = params
			return newDonePoller(armcosmos.DatabaseAccountsClientCreateOrUpdateResponse{DatabaseAccountGetResults: acctResult}), nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armcosmos.DatabaseAccountsClientGetOptions) (armcosmos.DatabaseAccountsClientGetResponse, error) {
			return armcosmos.DatabaseAccountsClientGetResponse{DatabaseAccountGetResults: acctResult}, nil
		},
		beginUpdateFn: func(_ context.Context, _, _ string, params armcosmos.DatabaseAccountUpdateParameters, _ *armcosmos.DatabaseAccountsClientBeginUpdateOptions) (*runtime.Poller[armcosmos.DatabaseAccountsClientUpdateResponse], error) {
			sentUpdate = params
			return newDonePoller(armcosmos.DatabaseAccountsClientUpdateResponse{DatabaseAccountGetResults: acctResult}), nil
		},
		beginDeleteFn: func(_ context.Context, _, _ string, _ *armcosmos.DatabaseAccountsClientBeginDeleteOptions) (*runtime.Poller[armcosmos.DatabaseAccountsClientDeleteResponse], error) {
			return newDonePoller(armcosmos.DatabaseAccountsClientDeleteResponse{}), nil
		},
		newListPagerFn: func(_ *armcosmos.DatabaseAccountsClientListOptions) *runtime.Pager[armcosmos.DatabaseAccountsClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armcosmos.DatabaseAccountsClientListResponse]{
				More: func(_ armcosmos.DatabaseAccountsClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armcosmos.DatabaseAccountsClientListResponse) (armcosmos.DatabaseAccountsClientListResponse, error) {
					return armcosmos.DatabaseAccountsClientListResponse{
						DatabaseAccountsListResult: armcosmos.DatabaseAccountsListResult{
							Value: []*armcosmos.DatabaseAccountGetResults{
								{ID: to.Ptr(testCosmosAccountNativeID)},
								{ID: to.Ptr("/subscriptions/sub-1/resourceGroups/rg-2/providers/Microsoft.DocumentDB/databaseAccounts/cosmos-2")},
							},
						},
					}, nil
				},
			})
		},
		newListByResourceGroupPagerFn: func(_ string, _ *armcosmos.DatabaseAccountsClientListByResourceGroupOptions) *runtime.Pager[armcosmos.DatabaseAccountsClientListByResourceGroupResponse] {
			return runtime.NewPager(runtime.PagingHandler[armcosmos.DatabaseAccountsClientListByResourceGroupResponse]{
				More: func(_ armcosmos.DatabaseAccountsClientListByResourceGroupResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armcosmos.DatabaseAccountsClientListByResourceGroupResponse) (armcosmos.DatabaseAccountsClientListByResourceGroupResponse, error) {
					return armcosmos.DatabaseAccountsClientListByResourceGroupResponse{
						DatabaseAccountsListResult: armcosmos.DatabaseAccountsListResult{
							Value: []*armcosmos.DatabaseAccountGetResults{{ID: to.Ptr(testCosmosAccountNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestCosmosDatabaseAccount(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "cosmos-1", Properties: cosmosDesired("Session", false)})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testCosmosAccountNativeID, got.ProgressResult.NativeID)

		// ARM requires databaseAccountOfferType and rejects anything but Standard.
		require.Equal(t, "Standard", *sentCreate.Properties.DatabaseAccountOfferType)
		require.Len(t, sentCreate.Properties.Locations, 1)
		require.EqualValues(t, 0, *sentCreate.Properties.Locations[0].FailoverPriority)

		var props map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &props))
		require.Equal(t, "https://cosmos-1.documents.azure.com:443/", props["documentEndpoint"])
	})

	// Exactly one region must be the write region; anything else is an ARM error
	// that is cheaper to catch here.
	t.Run("Create_rejects_zero_write_regions", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "cosmos-1", "location": "eastus", "resourceGroupName": "rg-1",
			"geoLocations": []map[string]any{{"locationName": "eastus", "failoverPriority": 1}},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "exactly one geoLocation must have failoverPriority 0")
	})

	t.Run("Create_rejects_two_write_regions", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "cosmos-1", "location": "eastus", "resourceGroupName": "rg-1",
			"geoLocations": []map[string]any{
				{"locationName": "eastus", "failoverPriority": 0},
				{"locationName": "westus", "failoverPriority": 0},
			},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "exactly one geoLocation must have failoverPriority 0")
	})

	t.Run("Create_requires_a_geoLocation", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "cosmos-1", "location": "eastus", "resourceGroupName": "rg-1",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "at least one geoLocation")
	})

	// maxStalenessPrefix / maxIntervalInSeconds are legal only for BoundedStaleness;
	// ARM rejects the whole request if they accompany another level.
	t.Run("Create_drops_staleness_for_non_bounded_level", func(t *testing.T) {
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "cosmos-1", Properties: cosmosDesired("Session", true)})
		require.NoError(t, err)
		require.Nil(t, sentCreate.Properties.ConsistencyPolicy.MaxStalenessPrefix)
		require.Nil(t, sentCreate.Properties.ConsistencyPolicy.MaxIntervalInSeconds)
	})

	t.Run("Create_keeps_staleness_for_bounded_level", func(t *testing.T) {
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "cosmos-1", Properties: cosmosDesired("BoundedStaleness", true)})
		require.NoError(t, err)
		require.EqualValues(t, 100, *sentCreate.Properties.ConsistencyPolicy.MaxStalenessPrefix)
		require.EqualValues(t, 300, *sentCreate.Properties.ConsistencyPolicy.MaxIntervalInSeconds)
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testCosmosAccountNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "cosmos-1", props["name"])
		require.Equal(t, "eastus", props["location"])
		require.Equal(t, "GlobalDocumentDB", props["kind"])
		// ARM returns "East US"; the read must normalise to match desired state.
		geos := props["geoLocations"].([]any)
		require.Len(t, geos, 1)
		require.Equal(t, "eastus", geos[0].(map[string]any)["locationName"])
	})

	// Omitting locations on update asks ARM to drop every replica region.
	t.Run("Update_echoes_locations_back", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testCosmosAccountNativeID,
			DesiredProperties: cosmosDesired("Session", false),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testCosmosAccountNativeID, got.ProgressResult.NativeID)
		require.Len(t, sentUpdate.Properties.Locations, 1)
	})

	t.Run("Delete", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testCosmosAccountNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _ string, _ *armcosmos.DatabaseAccountsClientBeginDeleteOptions) (*runtime.Poller[armcosmos.DatabaseAccountsClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testCosmosAccountNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_resource_group", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testCosmosAccountNativeID}, got.NativeIDs)
	})

	t.Run("List_without_group_is_subscription_wide", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 2)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, _ armcosmos.DatabaseAccountCreateUpdateParameters, _ *armcosmos.DatabaseAccountsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armcosmos.DatabaseAccountsClientCreateOrUpdateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 409}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "cosmos-1", Properties: cosmosDesired("Session", false)})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

func TestCosmosDatabaseAccount_ReadNotFound(t *testing.T) {
	fake := &fakeCosmosAccountsAPI{
		getFn: func(_ context.Context, _, _ string, _ *armcosmos.DatabaseAccountsClientGetOptions) (armcosmos.DatabaseAccountsClientGetResponse, error) {
			return armcosmos.DatabaseAccountsClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestCosmosDatabaseAccount(fake).Read(context.Background(), &resource.ReadRequest{NativeID: testCosmosAccountNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeCosmosAccountsAPI struct {
	beginCreateOrUpdateFn         func(ctx context.Context, rgName, name string, params armcosmos.DatabaseAccountCreateUpdateParameters, options *armcosmos.DatabaseAccountsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armcosmos.DatabaseAccountsClientCreateOrUpdateResponse], error)
	getFn                         func(ctx context.Context, rgName, name string, options *armcosmos.DatabaseAccountsClientGetOptions) (armcosmos.DatabaseAccountsClientGetResponse, error)
	beginUpdateFn                 func(ctx context.Context, rgName, name string, params armcosmos.DatabaseAccountUpdateParameters, options *armcosmos.DatabaseAccountsClientBeginUpdateOptions) (*runtime.Poller[armcosmos.DatabaseAccountsClientUpdateResponse], error)
	beginDeleteFn                 func(ctx context.Context, rgName, name string, options *armcosmos.DatabaseAccountsClientBeginDeleteOptions) (*runtime.Poller[armcosmos.DatabaseAccountsClientDeleteResponse], error)
	newListPagerFn                func(options *armcosmos.DatabaseAccountsClientListOptions) *runtime.Pager[armcosmos.DatabaseAccountsClientListResponse]
	newListByResourceGroupPagerFn func(rgName string, options *armcosmos.DatabaseAccountsClientListByResourceGroupOptions) *runtime.Pager[armcosmos.DatabaseAccountsClientListByResourceGroupResponse]
}

func (f *fakeCosmosAccountsAPI) BeginCreateOrUpdate(ctx context.Context, rgName, name string, params armcosmos.DatabaseAccountCreateUpdateParameters, options *armcosmos.DatabaseAccountsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armcosmos.DatabaseAccountsClientCreateOrUpdateResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, rgName, name, params, options)
}

func (f *fakeCosmosAccountsAPI) Get(ctx context.Context, rgName, name string, options *armcosmos.DatabaseAccountsClientGetOptions) (armcosmos.DatabaseAccountsClientGetResponse, error) {
	return f.getFn(ctx, rgName, name, options)
}

func (f *fakeCosmosAccountsAPI) BeginUpdate(ctx context.Context, rgName, name string, params armcosmos.DatabaseAccountUpdateParameters, options *armcosmos.DatabaseAccountsClientBeginUpdateOptions) (*runtime.Poller[armcosmos.DatabaseAccountsClientUpdateResponse], error) {
	return f.beginUpdateFn(ctx, rgName, name, params, options)
}

func (f *fakeCosmosAccountsAPI) BeginDelete(ctx context.Context, rgName, name string, options *armcosmos.DatabaseAccountsClientBeginDeleteOptions) (*runtime.Poller[armcosmos.DatabaseAccountsClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, name, options)
}

func (f *fakeCosmosAccountsAPI) NewListPager(options *armcosmos.DatabaseAccountsClientListOptions) *runtime.Pager[armcosmos.DatabaseAccountsClientListResponse] {
	return f.newListPagerFn(options)
}

func (f *fakeCosmosAccountsAPI) NewListByResourceGroupPager(rgName string, options *armcosmos.DatabaseAccountsClientListByResourceGroupOptions) *runtime.Pager[armcosmos.DatabaseAccountsClientListByResourceGroupResponse] {
	return f.newListByResourceGroupPagerFn(rgName, options)
}
