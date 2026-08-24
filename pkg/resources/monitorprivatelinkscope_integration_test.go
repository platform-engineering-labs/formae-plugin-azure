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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/monitor/armmonitor"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testPrivateLinkScopeNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Insights/privateLinkScopes/ampls1"

type fakePrivateLinkScopesAPI struct {
	createOrUpdateFn func(ctx context.Context, rgName, name string, payload armmonitor.AzureMonitorPrivateLinkScope, options *armmonitor.PrivateLinkScopesClientCreateOrUpdateOptions) (armmonitor.PrivateLinkScopesClientCreateOrUpdateResponse, error)
	getFn            func(ctx context.Context, rgName, name string, options *armmonitor.PrivateLinkScopesClientGetOptions) (armmonitor.PrivateLinkScopesClientGetResponse, error)
	beginDeleteFn    func(ctx context.Context, rgName, name string, options *armmonitor.PrivateLinkScopesClientBeginDeleteOptions) (*runtime.Poller[armmonitor.PrivateLinkScopesClientDeleteResponse], error)
	listPagerFn      func(options *armmonitor.PrivateLinkScopesClientListOptions) *runtime.Pager[armmonitor.PrivateLinkScopesClientListResponse]
	listByRGPagerFn  func(rgName string, options *armmonitor.PrivateLinkScopesClientListByResourceGroupOptions) *runtime.Pager[armmonitor.PrivateLinkScopesClientListByResourceGroupResponse]
}

func (f *fakePrivateLinkScopesAPI) CreateOrUpdate(ctx context.Context, rgName, name string, payload armmonitor.AzureMonitorPrivateLinkScope, options *armmonitor.PrivateLinkScopesClientCreateOrUpdateOptions) (armmonitor.PrivateLinkScopesClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, name, payload, options)
}

func (f *fakePrivateLinkScopesAPI) Get(ctx context.Context, rgName, name string, options *armmonitor.PrivateLinkScopesClientGetOptions) (armmonitor.PrivateLinkScopesClientGetResponse, error) {
	return f.getFn(ctx, rgName, name, options)
}

func (f *fakePrivateLinkScopesAPI) BeginDelete(ctx context.Context, rgName, name string, options *armmonitor.PrivateLinkScopesClientBeginDeleteOptions) (*runtime.Poller[armmonitor.PrivateLinkScopesClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, name, options)
}

func (f *fakePrivateLinkScopesAPI) NewListPager(options *armmonitor.PrivateLinkScopesClientListOptions) *runtime.Pager[armmonitor.PrivateLinkScopesClientListResponse] {
	return f.listPagerFn(options)
}

func (f *fakePrivateLinkScopesAPI) NewListByResourceGroupPager(rgName string, options *armmonitor.PrivateLinkScopesClientListByResourceGroupOptions) *runtime.Pager[armmonitor.PrivateLinkScopesClientListByResourceGroupResponse] {
	return f.listByRGPagerFn(rgName, options)
}

func newTestPrivateLinkScope(api monitorPrivateLinkScopesAPI) *MonitorPrivateLinkScope {
	return &MonitorPrivateLinkScope{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func privateLinkScopeDesired(ingestion, query string) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":                "ampls1",
		"resourceGroupName":   "rg-1",
		"location":            "global",
		"ingestionAccessMode": ingestion,
		"queryAccessMode":     query,
		"Tags":                []any{map[string]any{"Key": "env", "Value": "test"}},
	})
	return out
}

func TestMonitorPrivateLinkScope_CRUD(t *testing.T) {
	scopeResult := armmonitor.AzureMonitorPrivateLinkScope{
		ID:       to.Ptr(testPrivateLinkScopeNativeID),
		Name:     to.Ptr("ampls1"),
		Location: to.Ptr("global"),
		Properties: &armmonitor.AzureMonitorPrivateLinkScopeProperties{
			AccessModeSettings: &armmonitor.AccessModeSettings{
				IngestionAccessMode: to.Ptr(armmonitor.AccessModeOpen),
				QueryAccessMode:     to.Ptr(armmonitor.AccessModeOpen),
				// Per-connection overrides are not modelled.
				Exclusions: []*armmonitor.AccessModeSettingsExclusion{{
					PrivateEndpointConnectionName: to.Ptr("unmodelled-exclusion"),
					QueryAccessMode:               to.Ptr(armmonitor.AccessModePrivateOnly),
				}},
			},
			// ARM's back-reference to an endpoint that attached itself.
			PrivateEndpointConnections: []*armmonitor.PrivateEndpointConnection{{
				ID: to.Ptr(testPrivateLinkScopeNativeID + "/privateEndpointConnections/pec1"),
			}},
			ProvisioningState: to.Ptr(armmonitor.PrivateLinkScopeProvisioningStateSucceeded),
		},
		Tags: map[string]*string{"env": to.Ptr("test")},
	}

	var sent armmonitor.AzureMonitorPrivateLinkScope
	writeCalls := 0
	deleteCalls := 0
	fake := &fakePrivateLinkScopesAPI{
		createOrUpdateFn: func(_ context.Context, rgName, name string, payload armmonitor.AzureMonitorPrivateLinkScope, _ *armmonitor.PrivateLinkScopesClientCreateOrUpdateOptions) (armmonitor.PrivateLinkScopesClientCreateOrUpdateResponse, error) {
			require.Equal(t, "rg-1", rgName)
			require.Equal(t, "ampls1", name)
			sent = payload
			writeCalls++
			return armmonitor.PrivateLinkScopesClientCreateOrUpdateResponse{AzureMonitorPrivateLinkScope: scopeResult}, nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armmonitor.PrivateLinkScopesClientGetOptions) (armmonitor.PrivateLinkScopesClientGetResponse, error) {
			return armmonitor.PrivateLinkScopesClientGetResponse{AzureMonitorPrivateLinkScope: scopeResult}, nil
		},
		beginDeleteFn: func(_ context.Context, _, _ string, _ *armmonitor.PrivateLinkScopesClientBeginDeleteOptions) (*runtime.Poller[armmonitor.PrivateLinkScopesClientDeleteResponse], error) {
			deleteCalls++
			return newDonePoller(armmonitor.PrivateLinkScopesClientDeleteResponse{}), nil
		},
		listPagerFn: func(_ *armmonitor.PrivateLinkScopesClientListOptions) *runtime.Pager[armmonitor.PrivateLinkScopesClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armmonitor.PrivateLinkScopesClientListResponse]{
				More: func(_ armmonitor.PrivateLinkScopesClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armmonitor.PrivateLinkScopesClientListResponse) (armmonitor.PrivateLinkScopesClientListResponse, error) {
					return armmonitor.PrivateLinkScopesClientListResponse{
						AzureMonitorPrivateLinkScopeListResult: armmonitor.AzureMonitorPrivateLinkScopeListResult{
							Value: []*armmonitor.AzureMonitorPrivateLinkScope{
								{ID: to.Ptr(testPrivateLinkScopeNativeID)},
								{ID: to.Ptr("/subscriptions/sub-1/resourceGroups/rg-2/providers/Microsoft.Insights/privateLinkScopes/ampls2")},
							},
						},
					}, nil
				},
			})
		},
		listByRGPagerFn: func(_ string, _ *armmonitor.PrivateLinkScopesClientListByResourceGroupOptions) *runtime.Pager[armmonitor.PrivateLinkScopesClientListByResourceGroupResponse] {
			return runtime.NewPager(runtime.PagingHandler[armmonitor.PrivateLinkScopesClientListByResourceGroupResponse]{
				More: func(_ armmonitor.PrivateLinkScopesClientListByResourceGroupResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armmonitor.PrivateLinkScopesClientListByResourceGroupResponse) (armmonitor.PrivateLinkScopesClientListByResourceGroupResponse, error) {
					return armmonitor.PrivateLinkScopesClientListByResourceGroupResponse{
						AzureMonitorPrivateLinkScopeListResult: armmonitor.AzureMonitorPrivateLinkScopeListResult{
							Value: []*armmonitor.AzureMonitorPrivateLinkScope{
								{ID: to.Ptr(testPrivateLinkScopeNativeID)},
								// A nil entry must not panic the walk.
								nil,
							},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestPrivateLinkScope(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "ampls1", Properties: privateLinkScopeDesired("Open", "Open"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testPrivateLinkScopeNativeID, got.ProgressResult.NativeID)

		require.Equal(t, "global", *sent.Location)
		require.Equal(t, armmonitor.AccessModeOpen, *sent.Properties.AccessModeSettings.IngestionAccessMode)
		require.Equal(t, armmonitor.AccessModeOpen, *sent.Properties.AccessModeSettings.QueryAccessMode)
		require.Equal(t, "test", *sent.Tags["env"])
		// Unmodelled configuration must never be invented on the way out.
		require.Nil(t, sent.Properties.AccessModeSettings.Exclusions)
		require.Nil(t, sent.Properties.PrivateEndpointConnections)
	})

	t.Run("Create_requires_access_modes", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "ampls1", "resourceGroupName": "rg-1", "location": "global",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "ingestionAccessMode is required")
	})

	t.Run("Create_requires_location", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "ampls1", "resourceGroupName": "rg-1"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "location is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testPrivateLinkScopeNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "ampls1", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		// "global" is the literal ARM expects for this type, not a region to
		// normalise.
		require.Equal(t, "global", props["location"])
		require.Equal(t, "Open", props["ingestionAccessMode"])
		require.Equal(t, "Open", props["queryAccessMode"])
	})

	t.Run("Read_drops_unmodelled_and_backrefs", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testPrivateLinkScopeNativeID})
		require.NoError(t, err)
		for _, key := range []string{
			"exclusions", "unmodelled-exclusion", "privateEndpointConnections",
			"pec1", "provisioningState", "systemData",
		} {
			require.NotContains(t, got.Properties, key)
		}
	})

	// UpdateTags exists but reaches only the tags, so an access-mode change is
	// another CreateOrUpdate.
	t.Run("Update_reissues_create_or_update", func(t *testing.T) {
		before := writeCalls
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testPrivateLinkScopeNativeID,
			DesiredProperties: privateLinkScopeDesired("PrivateOnly", "Open"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, writeCalls)
		require.Equal(t, armmonitor.AccessModePrivateOnly, *sent.Properties.AccessModeSettings.IngestionAccessMode)
		// Location must ride along: a PUT without it is rejected.
		require.Equal(t, "global", *sent.Location)
	})

	// The delete is an LRO even though the writes are synchronous.
	t.Run("Delete", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testPrivateLinkScopeNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
	})

	t.Run("PendingDeleteReportsInProgress", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _ string, _ *armmonitor.PrivateLinkScopesClientBeginDeleteOptions) (*runtime.Poller[armmonitor.PrivateLinkScopesClientDeleteResponse], error) {
			return newPendingPoller[armmonitor.PrivateLinkScopesClientDeleteResponse](), nil
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testPrivateLinkScopeNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusInProgress, got.ProgressResult.OperationStatus)

		reqID, err := decodeLROStatus(got.ProgressResult.RequestID)
		require.NoError(t, err)
		require.Equal(t, lroOpDelete, reqID.OperationType)
		require.Equal(t, testPrivateLinkScopeNativeID, reqID.NativeID)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _ string, _ *armmonitor.PrivateLinkScopesClientBeginDeleteOptions) (*runtime.Poller[armmonitor.PrivateLinkScopesClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testPrivateLinkScopeNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_resource_group", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testPrivateLinkScopeNativeID}, got.NativeIDs)
	})

	t.Run("List_without_group_is_subscription_wide", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 2)
	})

	t.Run("Read_NotFound", func(t *testing.T) {
		fake.getFn = func(_ context.Context, _, _ string, _ *armmonitor.PrivateLinkScopesClientGetOptions) (armmonitor.PrivateLinkScopesClientGetResponse, error) {
			return armmonitor.PrivateLinkScopesClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testPrivateLinkScopeNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
	})
}
