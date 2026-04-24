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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/postgresql/armpostgresqlflexibleservers/v4"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testConfigNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.DBforPostgreSQL/flexibleServers/pg-1/configurations/azure.extensions"

func TestConfiguration_CRUD(t *testing.T) {
	fake := &fakeConfigurationsAPI{
		beginUpdateFn: func(_ context.Context, _, _, _ string, _ armpostgresqlflexibleservers.ConfigurationForUpdate, _ *armpostgresqlflexibleservers.ConfigurationsClientBeginUpdateOptions) (*runtime.Poller[armpostgresqlflexibleservers.ConfigurationsClientUpdateResponse], error) {
			return newDonePoller(armpostgresqlflexibleservers.ConfigurationsClientUpdateResponse{
				Configuration: armpostgresqlflexibleservers.Configuration{
					ID:   to.Ptr(testConfigNativeID),
					Name: to.Ptr("azure.extensions"),
					Properties: &armpostgresqlflexibleservers.ConfigurationProperties{
						Value:  to.Ptr("uuid-ossp"),
						Source: to.Ptr("user-override"),
					},
				},
			}), nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ *armpostgresqlflexibleservers.ConfigurationsClientGetOptions) (armpostgresqlflexibleservers.ConfigurationsClientGetResponse, error) {
			return armpostgresqlflexibleservers.ConfigurationsClientGetResponse{
				Configuration: armpostgresqlflexibleservers.Configuration{
					ID:   to.Ptr(testConfigNativeID),
					Name: to.Ptr("azure.extensions"),
					Properties: &armpostgresqlflexibleservers.ConfigurationProperties{
						Value:  to.Ptr("uuid-ossp"),
						Source: to.Ptr("user-override"),
					},
				},
			}, nil
		},
		newListByServerPagerFn: func(_, _ string, _ *armpostgresqlflexibleservers.ConfigurationsClientListByServerOptions) *runtime.Pager[armpostgresqlflexibleservers.ConfigurationsClientListByServerResponse] {
			return runtime.NewPager(runtime.PagingHandler[armpostgresqlflexibleservers.ConfigurationsClientListByServerResponse]{
				More: func(_ armpostgresqlflexibleservers.ConfigurationsClientListByServerResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armpostgresqlflexibleservers.ConfigurationsClientListByServerResponse) (armpostgresqlflexibleservers.ConfigurationsClientListByServerResponse, error) {
					return armpostgresqlflexibleservers.ConfigurationsClientListByServerResponse{
						ConfigurationListResult: armpostgresqlflexibleservers.ConfigurationListResult{
							Value: []*armpostgresqlflexibleservers.Configuration{
								{
									ID: to.Ptr(testConfigNativeID),
									Properties: &armpostgresqlflexibleservers.ConfigurationProperties{
										Source: to.Ptr("user-override"),
									},
								},
							},
						},
					}, nil
				},
			})
		},
		newListFlexibleServersPagerFn: func(_ *armpostgresqlflexibleservers.ServersClientListOptions) *runtime.Pager[armpostgresqlflexibleservers.ServersClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armpostgresqlflexibleservers.ServersClientListResponse]{
				More: func(_ armpostgresqlflexibleservers.ServersClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armpostgresqlflexibleservers.ServersClientListResponse) (armpostgresqlflexibleservers.ServersClientListResponse, error) {
					return armpostgresqlflexibleservers.ServersClientListResponse{
						ServerListResult: armpostgresqlflexibleservers.ServerListResult{
							Value: []*armpostgresqlflexibleservers.Server{
								{ID: to.Ptr("/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.DBforPostgreSQL/flexibleServers/pg-1")},
							},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestConfiguration(fake)

	t.Run("Create", func(t *testing.T) {
		props, _ := json.Marshal(map[string]interface{}{
			"resourceGroupName": "rg-1",
			"serverName":        "pg-1",
			"name":              "azure.extensions",
			"value":             "uuid-ossp",
		})
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testConfigNativeID, got.ProgressResult.NativeID)
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testConfigNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "azure.extensions", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "pg-1", props["serverName"])
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.getFn = func(_ context.Context, _, _, _ string, _ *armpostgresqlflexibleservers.ConfigurationsClientGetOptions) (armpostgresqlflexibleservers.ConfigurationsClientGetResponse, error) {
			return armpostgresqlflexibleservers.ConfigurationsClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testConfigNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{
				"resourceGroupName": "rg-1",
				"serverName":        "pg-1",
			},
		})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 1)
		require.Equal(t, testConfigNativeID, got.NativeIDs[0])
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.beginUpdateFn = func(_ context.Context, _, _, _ string, _ armpostgresqlflexibleservers.ConfigurationForUpdate, _ *armpostgresqlflexibleservers.ConfigurationsClientBeginUpdateOptions) (*runtime.Poller[armpostgresqlflexibleservers.ConfigurationsClientUpdateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 403}
		}
		props, _ := json.Marshal(map[string]interface{}{
			"resourceGroupName": "rg-1",
			"serverName":        "pg-1",
			"name":              "azure.extensions",
			"value":             "uuid-ossp",
		})
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

// --- Test helpers ---

func newTestConfiguration(api configurationsAPI) *Configuration {
	return &Configuration{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

type fakeConfigurationsAPI struct {
	beginUpdateFn                func(ctx context.Context, resourceGroupName string, serverName string, configurationName string, parameters armpostgresqlflexibleservers.ConfigurationForUpdate, options *armpostgresqlflexibleservers.ConfigurationsClientBeginUpdateOptions) (*runtime.Poller[armpostgresqlflexibleservers.ConfigurationsClientUpdateResponse], error)
	getFn                        func(ctx context.Context, resourceGroupName string, serverName string, configurationName string, options *armpostgresqlflexibleservers.ConfigurationsClientGetOptions) (armpostgresqlflexibleservers.ConfigurationsClientGetResponse, error)
	newListByServerPagerFn       func(resourceGroupName string, serverName string, options *armpostgresqlflexibleservers.ConfigurationsClientListByServerOptions) *runtime.Pager[armpostgresqlflexibleservers.ConfigurationsClientListByServerResponse]
	newListFlexibleServersPagerFn func(options *armpostgresqlflexibleservers.ServersClientListOptions) *runtime.Pager[armpostgresqlflexibleservers.ServersClientListResponse]
	resumeUpdatePollerFn         func(token string) (*runtime.Poller[armpostgresqlflexibleservers.ConfigurationsClientUpdateResponse], error)
}

func (f *fakeConfigurationsAPI) BeginUpdate(ctx context.Context, resourceGroupName string, serverName string, configurationName string, parameters armpostgresqlflexibleservers.ConfigurationForUpdate, options *armpostgresqlflexibleservers.ConfigurationsClientBeginUpdateOptions) (*runtime.Poller[armpostgresqlflexibleservers.ConfigurationsClientUpdateResponse], error) {
	return f.beginUpdateFn(ctx, resourceGroupName, serverName, configurationName, parameters, options)
}

func (f *fakeConfigurationsAPI) Get(ctx context.Context, resourceGroupName string, serverName string, configurationName string, options *armpostgresqlflexibleservers.ConfigurationsClientGetOptions) (armpostgresqlflexibleservers.ConfigurationsClientGetResponse, error) {
	return f.getFn(ctx, resourceGroupName, serverName, configurationName, options)
}

func (f *fakeConfigurationsAPI) NewListByServerPager(resourceGroupName string, serverName string, options *armpostgresqlflexibleservers.ConfigurationsClientListByServerOptions) *runtime.Pager[armpostgresqlflexibleservers.ConfigurationsClientListByServerResponse] {
	return f.newListByServerPagerFn(resourceGroupName, serverName, options)
}

func (f *fakeConfigurationsAPI) NewListFlexibleServersPager(options *armpostgresqlflexibleservers.ServersClientListOptions) *runtime.Pager[armpostgresqlflexibleservers.ServersClientListResponse] {
	return f.newListFlexibleServersPagerFn(options)
}

func (f *fakeConfigurationsAPI) ResumeUpdatePoller(token string) (*runtime.Poller[armpostgresqlflexibleservers.ConfigurationsClientUpdateResponse], error) {
	return f.resumeUpdatePollerFn(token)
}
