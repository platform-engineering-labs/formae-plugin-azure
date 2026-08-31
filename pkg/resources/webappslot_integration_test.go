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

const testWebAppSlotNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Web/sites/app-1/slots/staging"

func newTestWebAppSlot(api webAppSlotsAPI) *WebAppSlot {
	return &WebAppSlot{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func webAppSlotDesired(http20Enabled bool, slotEnv string) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":              "staging",
		"siteName":          "app-1",
		"resourceGroupName": "rg-1",
		"location":          "eastus",
		"serverFarmId":      testServerFarmID,
		"kind":              "app,linux",
		"httpsOnly":         true,
		"siteConfig": map[string]any{
			"linuxFxVersion":      "PYTHON|3.12",
			"netFrameworkVersion": "v4.0",
			"alwaysOn":            true,
			"ftpsState":           "FtpsOnly",
			"minTlsVersion":       "1.2",
			"http20Enabled":       http20Enabled,
		},
		"appSettings": []any{
			map[string]any{"name": "SLOT_ENV", "value": slotEnv},
		},
	})
	return out
}

func webAppSlotResult() armappservice.Site {
	return armappservice.Site{
		ID: to.Ptr(testWebAppSlotNativeID),
		// ARM reports a slot's Name as "<site>/<slot>", which is not the formae name.
		Name:     to.Ptr("app-1/staging"),
		Location: to.Ptr("East US"),
		Kind:     to.Ptr("app,linux"),
		// A slot can carry an identity ARM assigns; the slot schema does not model
		// one, so it must not surface as a property.
		Identity: &armappservice.ManagedServiceIdentity{
			Type: to.Ptr(armappservice.ManagedServiceIdentityTypeSystemAssigned),
		},
		Properties: &armappservice.SiteProperties{
			ServerFarmID:           to.Ptr(testServerFarmID),
			HTTPSOnly:              to.Ptr(true),
			DefaultHostName:        to.Ptr("app-1-staging.azurewebsites.net"),
			PublicNetworkAccess:    to.Ptr("Enabled"),
			VirtualNetworkSubnetID: to.Ptr(testSubnetID),
			SiteConfig:             &armappservice.SiteConfig{},
		},
	}
}

func TestWebAppSlot_CRUD(t *testing.T) {
	slot := webAppSlotResult()

	var sent armappservice.Site
	fake := &fakeWebAppSlotsAPI{
		beginCreateOrUpdateSlotFn: func(_ context.Context, rgName, siteName, slotName string, params armappservice.Site, _ *armappservice.WebAppsClientBeginCreateOrUpdateSlotOptions) (*runtime.Poller[armappservice.WebAppsClientCreateOrUpdateSlotResponse], error) {
			require.Equal(t, "rg-1", rgName)
			require.Equal(t, "app-1", siteName)
			require.Equal(t, "staging", slotName)
			sent = params
			return newDonePoller(armappservice.WebAppsClientCreateOrUpdateSlotResponse{Site: slot}), nil
		},
		getSlotFn: func(_ context.Context, _, _, _ string, _ *armappservice.WebAppsClientGetSlotOptions) (armappservice.WebAppsClientGetSlotResponse, error) {
			return armappservice.WebAppsClientGetSlotResponse{Site: slot}, nil
		},
		deleteSlotFn: func(_ context.Context, _, _, _ string, _ *armappservice.WebAppsClientDeleteSlotOptions) (armappservice.WebAppsClientDeleteSlotResponse, error) {
			return armappservice.WebAppsClientDeleteSlotResponse{}, nil
		},
		getConfigurationSlotFn: func(_ context.Context, _, _, _ string, _ *armappservice.WebAppsClientGetConfigurationSlotOptions) (armappservice.WebAppsClientGetConfigurationSlotResponse, error) {
			return armappservice.WebAppsClientGetConfigurationSlotResponse{SiteConfigResource: webAppConfigResult()}, nil
		},
		newListSlotsPagerFn: func(_, _ string, _ *armappservice.WebAppsClientListSlotsOptions) *runtime.Pager[armappservice.WebAppsClientListSlotsResponse] {
			return runtime.NewPager(runtime.PagingHandler[armappservice.WebAppsClientListSlotsResponse]{
				More: func(_ armappservice.WebAppsClientListSlotsResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armappservice.WebAppsClientListSlotsResponse) (armappservice.WebAppsClientListSlotsResponse, error) {
					return armappservice.WebAppsClientListSlotsResponse{
						WebAppCollection: armappservice.WebAppCollection{
							Value: []*armappservice.Site{{ID: to.Ptr(testWebAppSlotNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestWebAppSlot(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "staging",
			Properties: webAppSlotDesired(true, "staging"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testWebAppSlotNativeID, got.ProgressResult.NativeID)

		require.Equal(t, "eastus", *sent.Location)
		require.Equal(t, testServerFarmID, *sent.Properties.ServerFarmID)
		require.True(t, *sent.Properties.HTTPSOnly)
		require.Equal(t, "PYTHON|3.12", *sent.Properties.SiteConfig.LinuxFxVersion)
		require.Len(t, sent.Properties.SiteConfig.AppSettings, 1)
		require.Equal(t, "staging", *sent.Properties.SiteConfig.AppSettings[0].Value)
	})

	t.Run("Create_requires_siteName", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "staging", "resourceGroupName": "rg-1", "location": "eastus",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "siteName is required")
	})

	// The slot's serverFarmId is optional: ARM inherits the parent app's plan.
	t.Run("Create_without_serverFarmId", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "staging", "siteName": "app-1", "resourceGroupName": "rg-1", "location": "eastus",
		})
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Nil(t, sent.Properties.ServerFarmID)
	})

	t.Run("Read_uses_slot_name_from_arm_id", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testWebAppSlotNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		// Not "app-1/staging", which is what the ARM body carries.
		require.Equal(t, "staging", props["name"])
		require.Equal(t, "app-1", props["siteName"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "eastus", props["location"])
		require.Equal(t, "app,linux", props["kind"])
		require.Equal(t, testServerFarmID, props["serverFarmId"])
		require.Equal(t, true, props["httpsOnly"])
		require.Equal(t, "app-1-staging.azurewebsites.net", props["defaultHostName"])

		cfg := props["siteConfig"].(map[string]any)
		require.Equal(t, "PYTHON|3.12", cfg["linuxFxVersion"])
		require.Equal(t, "FtpsOnly", cfg["ftpsState"])
		// functionAppScaleLimit is not part of the slot schema.
		require.NotContains(t, cfg, "functionAppScaleLimit")

		// The slot schema models none of these, so a forma could not express them.
		require.NotContains(t, props, "appSettings")
		require.NotContains(t, props, "identity")
		require.NotContains(t, props, "publicNetworkAccess")
		require.NotContains(t, props, "virtualNetworkSubnetId")
	})

	t.Run("Update_keeps_native_id", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testWebAppSlotNativeID,
			DesiredProperties: webAppSlotDesired(false, "preprod"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testWebAppSlotNativeID, got.ProgressResult.NativeID)
		require.False(t, *sent.Properties.SiteConfig.Http20Enabled)
		require.Equal(t, "preprod", *sent.Properties.SiteConfig.AppSettings[0].Value)
	})

	t.Run("Delete", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testWebAppSlotNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteSlotFn = func(_ context.Context, _, _, _ string, _ *armappservice.WebAppsClientDeleteSlotOptions) (armappservice.WebAppsClientDeleteSlotResponse, error) {
			return armappservice.WebAppsClientDeleteSlotResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testWebAppSlotNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_parent_site", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "siteName": "app-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testWebAppSlotNativeID}, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.beginCreateOrUpdateSlotFn = func(_ context.Context, _, _, _ string, _ armappservice.Site, _ *armappservice.WebAppsClientBeginCreateOrUpdateSlotOptions) (*runtime.Poller[armappservice.WebAppsClientCreateOrUpdateSlotResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 400}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "staging",
			Properties: webAppSlotDesired(true, "staging"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

func TestWebAppSlot_CreateInProgressPinsNativeID(t *testing.T) {
	fake := &fakeWebAppSlotsAPI{
		beginCreateOrUpdateSlotFn: func(_ context.Context, _, _, _ string, _ armappservice.Site, _ *armappservice.WebAppsClientBeginCreateOrUpdateSlotOptions) (*runtime.Poller[armappservice.WebAppsClientCreateOrUpdateSlotResponse], error) {
			return newInProgressPoller[armappservice.WebAppsClientCreateOrUpdateSlotResponse](), nil
		},
	}
	got, err := newTestWebAppSlot(fake).Create(context.Background(), &resource.CreateRequest{
		Label:      "staging",
		Properties: webAppSlotDesired(true, "staging"),
	})
	require.NoError(t, err)
	require.Equal(t, resource.OperationStatusInProgress, got.ProgressResult.OperationStatus)
	require.Equal(t, testWebAppSlotNativeID, got.ProgressResult.NativeID)
	require.NotEmpty(t, got.ProgressResult.RequestID)
}

func TestWebAppSlot_ReadNotFound(t *testing.T) {
	fake := &fakeWebAppSlotsAPI{
		getSlotFn: func(_ context.Context, _, _, _ string, _ *armappservice.WebAppsClientGetSlotOptions) (armappservice.WebAppsClientGetSlotResponse, error) {
			return armappservice.WebAppsClientGetSlotResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestWebAppSlot(fake).Read(context.Background(), &resource.ReadRequest{NativeID: testWebAppSlotNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

func TestWebAppSlot_IDParts(t *testing.T) {
	rgName, siteName, slotName, err := webAppSlotIDParts(testWebAppSlotNativeID)
	require.NoError(t, err)
	require.Equal(t, "rg-1", rgName)
	require.Equal(t, "app-1", siteName)
	require.Equal(t, "staging", slotName)

	// The parent site's own ARM ID names no slot.
	_, _, _, err = webAppSlotIDParts(testWebAppNativeID)
	require.Error(t, err)
}

// --- Test helpers ---

type fakeWebAppSlotsAPI struct {
	beginCreateOrUpdateSlotFn func(ctx context.Context, rgName, name, slot string, params armappservice.Site, options *armappservice.WebAppsClientBeginCreateOrUpdateSlotOptions) (*runtime.Poller[armappservice.WebAppsClientCreateOrUpdateSlotResponse], error)
	getSlotFn                 func(ctx context.Context, rgName, name, slot string, options *armappservice.WebAppsClientGetSlotOptions) (armappservice.WebAppsClientGetSlotResponse, error)
	deleteSlotFn              func(ctx context.Context, rgName, name, slot string, options *armappservice.WebAppsClientDeleteSlotOptions) (armappservice.WebAppsClientDeleteSlotResponse, error)
	getConfigurationSlotFn    func(ctx context.Context, rgName, name, slot string, options *armappservice.WebAppsClientGetConfigurationSlotOptions) (armappservice.WebAppsClientGetConfigurationSlotResponse, error)
	newListSlotsPagerFn       func(rgName, name string, options *armappservice.WebAppsClientListSlotsOptions) *runtime.Pager[armappservice.WebAppsClientListSlotsResponse]
}

func (f *fakeWebAppSlotsAPI) BeginCreateOrUpdateSlot(ctx context.Context, rgName string, name string, slot string, params armappservice.Site, options *armappservice.WebAppsClientBeginCreateOrUpdateSlotOptions) (*runtime.Poller[armappservice.WebAppsClientCreateOrUpdateSlotResponse], error) {
	return f.beginCreateOrUpdateSlotFn(ctx, rgName, name, slot, params, options)
}

func (f *fakeWebAppSlotsAPI) GetSlot(ctx context.Context, rgName string, name string, slot string, options *armappservice.WebAppsClientGetSlotOptions) (armappservice.WebAppsClientGetSlotResponse, error) {
	return f.getSlotFn(ctx, rgName, name, slot, options)
}

func (f *fakeWebAppSlotsAPI) DeleteSlot(ctx context.Context, rgName string, name string, slot string, options *armappservice.WebAppsClientDeleteSlotOptions) (armappservice.WebAppsClientDeleteSlotResponse, error) {
	return f.deleteSlotFn(ctx, rgName, name, slot, options)
}

func (f *fakeWebAppSlotsAPI) GetConfigurationSlot(ctx context.Context, rgName string, name string, slot string, options *armappservice.WebAppsClientGetConfigurationSlotOptions) (armappservice.WebAppsClientGetConfigurationSlotResponse, error) {
	return f.getConfigurationSlotFn(ctx, rgName, name, slot, options)
}

func (f *fakeWebAppSlotsAPI) NewListSlotsPager(rgName string, name string, options *armappservice.WebAppsClientListSlotsOptions) *runtime.Pager[armappservice.WebAppsClientListSlotsResponse] {
	return f.newListSlotsPagerFn(rgName, name, options)
}
