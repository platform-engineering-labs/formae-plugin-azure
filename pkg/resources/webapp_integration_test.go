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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appservice/armappservice/v5"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const (
	testWebAppNativeID      = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Web/sites/app-1"
	testFunctionAppNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Web/sites/fn-1"
	testServerFarmID        = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Web/serverfarms/plan-1"
	testSubnetID            = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/virtualNetworks/vnet-1/subnets/apps"
	testUserAssignedID      = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.ManagedIdentity/userAssignedIdentities/uai-1"
)

func newTestWebApp(api webSitesAPI) *WebApp {
	return &WebApp{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func webAppDesired(http20Enabled bool, greeting string) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":                   "app-1",
		"resourceGroupName":      "rg-1",
		"location":               "eastus",
		"serverFarmId":           testServerFarmID,
		"kind":                   "app,linux",
		"httpsOnly":              true,
		"clientAffinityEnabled":  false,
		"publicNetworkAccess":    "Enabled",
		"virtualNetworkSubnetId": testSubnetID,
		"siteConfig": map[string]any{
			"linuxFxVersion":      "PYTHON|3.12",
			"netFrameworkVersion": "v4.0",
			"alwaysOn":            true,
			"ftpsState":           "FtpsOnly",
			"minTlsVersion":       "1.2",
			"http20Enabled":       http20Enabled,
			"healthCheckPath":     "/healthz",
		},
		"appSettings": []any{
			map[string]any{"name": "GREETING", "value": greeting},
		},
		"identity": map[string]any{
			"type":                    "SystemAssigned, UserAssigned",
			"userAssignedIdentityIds": []any{testUserAssignedID},
		},
		"Tags": []any{map[string]any{"Key": "env", "Value": "test"}},
	})
	return out
}

func webAppSiteResult(nativeID, name, kind string) armappservice.Site {
	return armappservice.Site{
		ID:       to.Ptr(nativeID),
		Name:     to.Ptr(name),
		Location: to.Ptr("East US"),
		Kind:     to.Ptr(kind),
		Identity: &armappservice.ManagedServiceIdentity{
			Type:        to.Ptr(armappservice.ManagedServiceIdentityTypeSystemAssignedUserAssigned),
			PrincipalID: to.Ptr("principal-1"),
			UserAssignedIdentities: map[string]*armappservice.UserAssignedIdentity{
				testUserAssignedID: {ClientID: to.Ptr("client-1")},
			},
		},
		Properties: &armappservice.SiteProperties{
			ServerFarmID:           to.Ptr(testServerFarmID),
			HTTPSOnly:              to.Ptr(true),
			ClientAffinityEnabled:  to.Ptr(false),
			PublicNetworkAccess:    to.Ptr("Enabled"),
			VirtualNetworkSubnetID: to.Ptr(testSubnetID),
			DefaultHostName:        to.Ptr(name + ".azurewebsites.net"),
			// ARM deliberately blanks siteConfig on the site GET.
			SiteConfig: &armappservice.SiteConfig{},
		},
		Tags: map[string]*string{"env": to.Ptr("test")},
	}
}

func webAppConfigResult() armappservice.SiteConfigResource {
	return armappservice.SiteConfigResource{
		Properties: &armappservice.SiteConfig{
			LinuxFxVersion:        to.Ptr("PYTHON|3.12"),
			WindowsFxVersion:      to.Ptr(""),
			NetFrameworkVersion:   to.Ptr("v4.0"),
			AlwaysOn:              to.Ptr(true),
			FtpsState:             to.Ptr(armappservice.FtpsStateFtpsOnly),
			MinTLSVersion:         to.Ptr(armappservice.SupportedTLSVersionsOne2),
			Http20Enabled:         to.Ptr(true),
			HealthCheckPath:       to.Ptr("/healthz"),
			FunctionAppScaleLimit: to.Ptr(int32(0)),
			// App settings are never read back — see webapp.go.
			AppSettings: []*armappservice.NameValuePair{
				{Name: to.Ptr("WEBSITE_INJECTED_BY_AZURE"), Value: to.Ptr("1")},
			},
		},
	}
}

func newWebSitesFake(t *testing.T, nativeID, name, kind string, sent *armappservice.Site) *fakeWebSitesAPI {
	t.Helper()
	site := webAppSiteResult(nativeID, name, kind)
	return &fakeWebSitesAPI{
		beginCreateOrUpdateFn: func(_ context.Context, rgName, siteName string, params armappservice.Site, _ *armappservice.WebAppsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armappservice.WebAppsClientCreateOrUpdateResponse], error) {
			require.Equal(t, "rg-1", rgName)
			require.Equal(t, name, siteName)
			*sent = params
			return newDonePoller(armappservice.WebAppsClientCreateOrUpdateResponse{Site: site}), nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armappservice.WebAppsClientGetOptions) (armappservice.WebAppsClientGetResponse, error) {
			return armappservice.WebAppsClientGetResponse{Site: site}, nil
		},
		deleteFn: func(_ context.Context, _, _ string, _ *armappservice.WebAppsClientDeleteOptions) (armappservice.WebAppsClientDeleteResponse, error) {
			return armappservice.WebAppsClientDeleteResponse{}, nil
		},
		getConfigurationFn: func(_ context.Context, _, _ string, _ *armappservice.WebAppsClientGetConfigurationOptions) (armappservice.WebAppsClientGetConfigurationResponse, error) {
			return armappservice.WebAppsClientGetConfigurationResponse{SiteConfigResource: webAppConfigResult()}, nil
		},
		newListByResourceGroupPagerFn: func(_ string, _ *armappservice.WebAppsClientListByResourceGroupOptions) *runtime.Pager[armappservice.WebAppsClientListByResourceGroupResponse] {
			return runtime.NewPager(runtime.PagingHandler[armappservice.WebAppsClientListByResourceGroupResponse]{
				More: func(_ armappservice.WebAppsClientListByResourceGroupResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armappservice.WebAppsClientListByResourceGroupResponse) (armappservice.WebAppsClientListByResourceGroupResponse, error) {
					return armappservice.WebAppsClientListByResourceGroupResponse{
						WebAppCollection: armappservice.WebAppCollection{Value: webAppMixedListing()},
					}, nil
				},
			})
		},
		newListPagerFn: func(_ *armappservice.WebAppsClientListOptions) *runtime.Pager[armappservice.WebAppsClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armappservice.WebAppsClientListResponse]{
				More: func(_ armappservice.WebAppsClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armappservice.WebAppsClientListResponse) (armappservice.WebAppsClientListResponse, error) {
					return armappservice.WebAppsClientListResponse{
						WebAppCollection: armappservice.WebAppCollection{Value: webAppMixedListing()},
					}, nil
				},
			})
		},
	}
}

// webAppMixedListing is what ARM returns for /sites: web apps and function apps in
// one listing, told apart only by kind.
func webAppMixedListing() []*armappservice.Site {
	return []*armappservice.Site{
		{ID: to.Ptr(testWebAppNativeID), Kind: to.Ptr("app,linux")},
		{ID: to.Ptr(testFunctionAppNativeID), Kind: to.Ptr("functionapp,linux")},
		{ID: to.Ptr("/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Web/sites/app-nokind")},
	}
}

func TestWebApp_CRUD(t *testing.T) {
	var sent armappservice.Site
	fake := newWebSitesFake(t, testWebAppNativeID, "app-1", "app,linux", &sent)
	prov := newTestWebApp(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "app-1",
			Properties: webAppDesired(true, "hello"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testWebAppNativeID, got.ProgressResult.NativeID)

		require.Equal(t, "eastus", *sent.Location)
		require.Equal(t, "app,linux", *sent.Kind)
		require.Equal(t, testServerFarmID, *sent.Properties.ServerFarmID)
		require.True(t, *sent.Properties.HTTPSOnly)
		require.Equal(t, "Enabled", *sent.Properties.PublicNetworkAccess)
		require.Equal(t, testSubnetID, *sent.Properties.VirtualNetworkSubnetID)

		// siteConfig and the write-only app settings both ride in the site body.
		require.Equal(t, "PYTHON|3.12", *sent.Properties.SiteConfig.LinuxFxVersion)
		require.Equal(t, armappservice.FtpsStateFtpsOnly, *sent.Properties.SiteConfig.FtpsState)
		require.Equal(t, armappservice.SupportedTLSVersionsOne2, *sent.Properties.SiteConfig.MinTLSVersion)
		require.True(t, *sent.Properties.SiteConfig.Http20Enabled)
		require.Equal(t, "/healthz", *sent.Properties.SiteConfig.HealthCheckPath)
		require.Len(t, sent.Properties.SiteConfig.AppSettings, 1)
		require.Equal(t, "GREETING", *sent.Properties.SiteConfig.AppSettings[0].Name)
		require.Equal(t, "hello", *sent.Properties.SiteConfig.AppSettings[0].Value)

		require.Equal(t, armappservice.ManagedServiceIdentityTypeSystemAssignedUserAssigned, *sent.Identity.Type)
		require.Contains(t, sent.Identity.UserAssignedIdentities, testUserAssignedID)
		require.Equal(t, "test", *sent.Tags["env"])
	})

	t.Run("Create_requires_serverFarmId", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "app-1", "resourceGroupName": "rg-1", "location": "eastus",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "serverFarmId is required")
	})

	t.Run("Read_merges_site_and_config", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testWebAppNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "app-1", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "eastus", props["location"])
		require.Equal(t, "app,linux", props["kind"])
		require.Equal(t, testServerFarmID, props["serverFarmId"])
		require.Equal(t, true, props["httpsOnly"])
		require.Equal(t, false, props["clientAffinityEnabled"])
		require.Equal(t, "Enabled", props["publicNetworkAccess"])
		require.Equal(t, testSubnetID, props["virtualNetworkSubnetId"])
		require.Equal(t, "app-1.azurewebsites.net", props["defaultHostName"])

		// siteConfig comes from the second call, not from the (blank) site GET.
		cfg := props["siteConfig"].(map[string]any)
		require.Equal(t, "PYTHON|3.12", cfg["linuxFxVersion"])
		require.Equal(t, "v4.0", cfg["netFrameworkVersion"])
		require.Equal(t, true, cfg["alwaysOn"])
		require.Equal(t, "FtpsOnly", cfg["ftpsState"])
		require.Equal(t, "1.2", cfg["minTlsVersion"])
		require.Equal(t, true, cfg["http20Enabled"])
		require.Equal(t, "/healthz", cfg["healthCheckPath"])
		// An empty windowsFxVersion is dropped rather than read back as "".
		require.NotContains(t, cfg, "windowsFxVersion")
		// functionAppScaleLimit belongs to AZURE::Web::FunctionApp only.
		require.NotContains(t, cfg, "functionAppScaleLimit")

		// App settings are write-only: the platform-injected setting the fake
		// returns must NOT surface, or it would read as permanent drift.
		require.NotContains(t, props, "appSettings")

		identity := props["identity"].(map[string]any)
		require.Equal(t, "SystemAssigned, UserAssigned", identity["type"])
		require.Equal(t, []any{testUserAssignedID}, identity["userAssignedIdentityIds"])
		require.NotContains(t, identity, "principalId")
	})

	t.Run("Update_keeps_native_id", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testWebAppNativeID,
			DesiredProperties: webAppDesired(false, "bonjour"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testWebAppNativeID, got.ProgressResult.NativeID)
		require.False(t, *sent.Properties.SiteConfig.Http20Enabled)
		require.Equal(t, "bonjour", *sent.Properties.SiteConfig.AppSettings[0].Value)
	})

	t.Run("Delete", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testWebAppNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _ string, _ *armappservice.WebAppsClientDeleteOptions) (armappservice.WebAppsClientDeleteResponse, error) {
			return armappservice.WebAppsClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testWebAppNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	// The whole point of the kind split: a mixed /sites listing must partition
	// cleanly between AZURE::Web::WebApp and AZURE::Web::FunctionApp.
	t.Run("List_excludes_function_apps", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{
			testWebAppNativeID,
			"/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Web/sites/app-nokind",
		}, got.NativeIDs)
	})

	t.Run("List_without_group_is_subscription_wide", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 2)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, _ armappservice.Site, _ *armappservice.WebAppsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armappservice.WebAppsClientCreateOrUpdateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 409}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "app-1",
			Properties: webAppDesired(true, "hello"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

func TestWebApp_CreateInProgressPinsNativeID(t *testing.T) {
	fake := &fakeWebSitesAPI{
		beginCreateOrUpdateFn: func(_ context.Context, _, _ string, _ armappservice.Site, _ *armappservice.WebAppsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armappservice.WebAppsClientCreateOrUpdateResponse], error) {
			return newInProgressPoller[armappservice.WebAppsClientCreateOrUpdateResponse](), nil
		},
	}
	got, err := newTestWebApp(fake).Create(context.Background(), &resource.CreateRequest{
		Label:      "app-1",
		Properties: webAppDesired(true, "hello"),
	})
	require.NoError(t, err)
	require.Equal(t, resource.OperationStatusInProgress, got.ProgressResult.OperationStatus)
	require.Equal(t, testWebAppNativeID, got.ProgressResult.NativeID)
	require.NotEmpty(t, got.ProgressResult.RequestID)
}

func TestWebApp_ReadNotFound(t *testing.T) {
	fake := &fakeWebSitesAPI{
		getFn: func(_ context.Context, _, _ string, _ *armappservice.WebAppsClientGetOptions) (armappservice.WebAppsClientGetResponse, error) {
			return armappservice.WebAppsClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestWebApp(fake).Read(context.Background(), &resource.ReadRequest{NativeID: testWebAppNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// A site that exists but has no config resource yet must still read, just without
// the siteConfig block.
func TestWebApp_ReadToleratesMissingSiteConfig(t *testing.T) {
	var sent armappservice.Site
	fake := newWebSitesFake(t, testWebAppNativeID, "app-1", "app,linux", &sent)
	fake.getConfigurationFn = func(_ context.Context, _, _ string, _ *armappservice.WebAppsClientGetConfigurationOptions) (armappservice.WebAppsClientGetConfigurationResponse, error) {
		return armappservice.WebAppsClientGetConfigurationResponse{}, &azcore.ResponseError{StatusCode: 404}
	}
	got, err := newTestWebApp(fake).Read(context.Background(), &resource.ReadRequest{NativeID: testWebAppNativeID})
	require.NoError(t, err)
	require.Empty(t, got.ErrorCode)

	var props map[string]any
	require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
	require.Equal(t, "app-1", props["name"])
	require.NotContains(t, props, "siteConfig")
}

func TestWebApp_IDParts(t *testing.T) {
	rgName, siteName, err := webAppIDParts(testWebAppNativeID)
	require.NoError(t, err)
	require.Equal(t, "rg-1", rgName)
	require.Equal(t, "app-1", siteName)

	_, _, err = webAppIDParts("/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Web/serverfarms/plan-1")
	require.Error(t, err)
}

func TestWebSiteIsFunctionApp(t *testing.T) {
	require.False(t, webSiteIsFunctionApp(nil))
	require.False(t, webSiteIsFunctionApp(to.Ptr("app,linux")))
	require.True(t, webSiteIsFunctionApp(to.Ptr("functionapp")))
	require.True(t, webSiteIsFunctionApp(to.Ptr("FunctionApp,Linux")))
	require.True(t, webSiteIsFunctionApp(to.Ptr("functionapp,workflowapp")))
}

// --- Test helpers ---

type fakeWebSitesAPI struct {
	beginCreateOrUpdateFn         func(ctx context.Context, rgName, name string, params armappservice.Site, options *armappservice.WebAppsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armappservice.WebAppsClientCreateOrUpdateResponse], error)
	getFn                         func(ctx context.Context, rgName, name string, options *armappservice.WebAppsClientGetOptions) (armappservice.WebAppsClientGetResponse, error)
	deleteFn                      func(ctx context.Context, rgName, name string, options *armappservice.WebAppsClientDeleteOptions) (armappservice.WebAppsClientDeleteResponse, error)
	getConfigurationFn            func(ctx context.Context, rgName, name string, options *armappservice.WebAppsClientGetConfigurationOptions) (armappservice.WebAppsClientGetConfigurationResponse, error)
	newListByResourceGroupPagerFn func(rgName string, options *armappservice.WebAppsClientListByResourceGroupOptions) *runtime.Pager[armappservice.WebAppsClientListByResourceGroupResponse]
	newListPagerFn                func(options *armappservice.WebAppsClientListOptions) *runtime.Pager[armappservice.WebAppsClientListResponse]
}

func (f *fakeWebSitesAPI) BeginCreateOrUpdate(ctx context.Context, rgName string, name string, params armappservice.Site, options *armappservice.WebAppsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armappservice.WebAppsClientCreateOrUpdateResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, rgName, name, params, options)
}

func (f *fakeWebSitesAPI) Get(ctx context.Context, rgName string, name string, options *armappservice.WebAppsClientGetOptions) (armappservice.WebAppsClientGetResponse, error) {
	return f.getFn(ctx, rgName, name, options)
}

func (f *fakeWebSitesAPI) Delete(ctx context.Context, rgName string, name string, options *armappservice.WebAppsClientDeleteOptions) (armappservice.WebAppsClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, name, options)
}

func (f *fakeWebSitesAPI) GetConfiguration(ctx context.Context, rgName string, name string, options *armappservice.WebAppsClientGetConfigurationOptions) (armappservice.WebAppsClientGetConfigurationResponse, error) {
	return f.getConfigurationFn(ctx, rgName, name, options)
}

func (f *fakeWebSitesAPI) NewListByResourceGroupPager(rgName string, options *armappservice.WebAppsClientListByResourceGroupOptions) *runtime.Pager[armappservice.WebAppsClientListByResourceGroupResponse] {
	return f.newListByResourceGroupPagerFn(rgName, options)
}

func (f *fakeWebSitesAPI) NewListPager(options *armappservice.WebAppsClientListOptions) *runtime.Pager[armappservice.WebAppsClientListResponse] {
	return f.newListPagerFn(options)
}
