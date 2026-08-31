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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appservice/armappservice/v5"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

func newTestFunctionApp(api webSitesAPI) *FunctionApp {
	return &FunctionApp{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func functionAppDesired(kind string, scaleLimit int) []byte {
	props := map[string]any{
		"name":              "fn-1",
		"resourceGroupName": "rg-1",
		"location":          "eastus",
		"serverFarmId":      testServerFarmID,
		"httpsOnly":         true,
		"siteConfig": map[string]any{
			"linuxFxVersion":        "PYTHON|3.12",
			"netFrameworkVersion":   "v4.0",
			"alwaysOn":              true,
			"ftpsState":             "FtpsOnly",
			"minTlsVersion":         "1.2",
			"http20Enabled":         true,
			"functionAppScaleLimit": scaleLimit,
		},
		"appSettings": []any{
			map[string]any{"name": "FUNCTIONS_EXTENSION_VERSION", "value": "~4"},
			map[string]any{"name": "FUNCTIONS_WORKER_RUNTIME", "value": "python"},
			map[string]any{"name": "AzureWebJobsStorage__accountName", "value": "sa1"},
		},
	}
	if kind != "" {
		props["kind"] = kind
	}
	out, _ := json.Marshal(props)
	return out
}

func TestFunctionApp_CRUD(t *testing.T) {
	var sent armappservice.Site
	fake := newWebSitesFake(t, testFunctionAppNativeID, "fn-1", "functionapp,linux", &sent)
	prov := newTestFunctionApp(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "fn-1",
			Properties: functionAppDesired("functionapp,linux", 0),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testFunctionAppNativeID, got.ProgressResult.NativeID)

		require.Equal(t, "functionapp,linux", *sent.Kind)
		require.Equal(t, testServerFarmID, *sent.Properties.ServerFarmID)
		require.EqualValues(t, 0, *sent.Properties.SiteConfig.FunctionAppScaleLimit)
		require.Len(t, sent.Properties.SiteConfig.AppSettings, 3)
		require.Equal(t, "FUNCTIONS_EXTENSION_VERSION", *sent.Properties.SiteConfig.AppSettings[0].Name)
		require.Equal(t, "~4", *sent.Properties.SiteConfig.AppSettings[0].Value)
	})

	// A function app is only a function app because of its kind, so an undeclared
	// kind has to become one rather than defaulting to a plain web app.
	t.Run("Create_defaults_kind_to_functionapp", func(t *testing.T) {
		_, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "fn-1",
			Properties: functionAppDesired("", 0),
		})
		require.NoError(t, err)
		require.Equal(t, defaultFunctionAppKind, *sent.Kind)
	})

	t.Run("Create_rejects_non_function_kind", func(t *testing.T) {
		_, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "fn-1",
			Properties: functionAppDesired("app,linux", 0),
		})
		require.ErrorContains(t, err, "is not a function app kind")
	})

	t.Run("Create_requires_serverFarmId", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "fn-1", "resourceGroupName": "rg-1", "location": "eastus",
			"kind": "functionapp",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "serverFarmId is required")
	})

	// Unlike WebApp, the function app surfaces functionAppScaleLimit.
	t.Run("Read_includes_functionAppScaleLimit", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testFunctionAppNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "fn-1", props["name"])
		require.Equal(t, "functionapp,linux", props["kind"])
		cfg := props["siteConfig"].(map[string]any)
		require.EqualValues(t, 0, cfg["functionAppScaleLimit"])
		require.Equal(t, "PYTHON|3.12", cfg["linuxFxVersion"])
		// App settings stay write-only here too.
		require.NotContains(t, props, "appSettings")
	})

	t.Run("Update_keeps_native_id", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testFunctionAppNativeID,
			DesiredProperties: functionAppDesired("functionapp,linux", 10),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testFunctionAppNativeID, got.ProgressResult.NativeID)
		require.EqualValues(t, 10, *sent.Properties.SiteConfig.FunctionAppScaleLimit)
	})

	t.Run("Delete", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testFunctionAppNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _ string, _ *armappservice.WebAppsClientDeleteOptions) (armappservice.WebAppsClientDeleteResponse, error) {
			return armappservice.WebAppsClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testFunctionAppNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	// The complement of TestWebApp_CRUD/List_excludes_function_apps.
	t.Run("List_only_function_apps", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testFunctionAppNativeID}, got.NativeIDs)
	})

	t.Run("List_without_group_is_subscription_wide", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Equal(t, []string{testFunctionAppNativeID}, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, _ armappservice.Site, _ *armappservice.WebAppsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armappservice.WebAppsClientCreateOrUpdateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 409}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "fn-1",
			Properties: functionAppDesired("functionapp,linux", 0),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

func TestFunctionApp_CreateInProgressPinsNativeID(t *testing.T) {
	fake := &fakeWebSitesAPI{
		beginCreateOrUpdateFn: func(_ context.Context, _, _ string, _ armappservice.Site, _ *armappservice.WebAppsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armappservice.WebAppsClientCreateOrUpdateResponse], error) {
			return newInProgressPoller[armappservice.WebAppsClientCreateOrUpdateResponse](), nil
		},
	}
	got, err := newTestFunctionApp(fake).Create(context.Background(), &resource.CreateRequest{
		Label:      "fn-1",
		Properties: functionAppDesired("functionapp,linux", 0),
	})
	require.NoError(t, err)
	require.Equal(t, resource.OperationStatusInProgress, got.ProgressResult.OperationStatus)
	require.Equal(t, testFunctionAppNativeID, got.ProgressResult.NativeID)
	require.NotEmpty(t, got.ProgressResult.RequestID)
}

func TestFunctionApp_ReadNotFound(t *testing.T) {
	fake := &fakeWebSitesAPI{
		getFn: func(_ context.Context, _, _ string, _ *armappservice.WebAppsClientGetOptions) (armappservice.WebAppsClientGetResponse, error) {
			return armappservice.WebAppsClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestFunctionApp(fake).Read(context.Background(), &resource.ReadRequest{NativeID: testFunctionAppNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}
