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

const testHostnameBindingNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Web/sites/app-1/hostNameBindings/www.example.com"

func newTestCustomHostnameBinding(api webHostNameBindingsAPI) *CustomHostnameBinding {
	return &CustomHostnameBinding{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func hostnameBindingDesired(sslState string) []byte {
	props := map[string]any{
		"name":                        "www.example.com",
		"siteName":                    "app-1",
		"resourceGroupName":           "rg-1",
		"hostNameType":                "Verified",
		"customHostNameDnsRecordType": "CName",
		"azureResourceType":           "Website",
	}
	if sslState != "" {
		props["sslState"] = sslState
	}
	out, _ := json.Marshal(props)
	return out
}

func hostnameBindingResult() armappservice.HostNameBinding {
	return armappservice.HostNameBinding{
		ID: to.Ptr(testHostnameBindingNativeID),
		// ARM reports the binding's Name as "<site>/<hostname>".
		Name: to.Ptr("app-1/www.example.com"),
		Properties: &armappservice.HostNameBindingProperties{
			SiteName: to.Ptr("app-1"),
			// Lower-cased on the way back out, as ARM sometimes does with enums.
			SSLState:                    to.Ptr(armappservice.SSLState("disabled")),
			HostNameType:                to.Ptr(armappservice.HostNameTypeVerified),
			CustomHostNameDNSRecordType: to.Ptr(armappservice.CustomHostNameDNSRecordTypeCName),
			AzureResourceType:           to.Ptr(armappservice.AzureResourceTypeWebsite),
		},
	}
}

func TestCustomHostnameBinding_CRUD(t *testing.T) {
	result := hostnameBindingResult()

	var sent armappservice.HostNameBinding
	fake := &fakeWebHostNameBindingsAPI{
		createOrUpdateFn: func(_ context.Context, rgName, siteName, hostName string, params armappservice.HostNameBinding, _ *armappservice.WebAppsClientCreateOrUpdateHostNameBindingOptions) (armappservice.WebAppsClientCreateOrUpdateHostNameBindingResponse, error) {
			require.Equal(t, "rg-1", rgName)
			require.Equal(t, "app-1", siteName)
			require.Equal(t, "www.example.com", hostName)
			sent = params
			return armappservice.WebAppsClientCreateOrUpdateHostNameBindingResponse{HostNameBinding: result}, nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ *armappservice.WebAppsClientGetHostNameBindingOptions) (armappservice.WebAppsClientGetHostNameBindingResponse, error) {
			return armappservice.WebAppsClientGetHostNameBindingResponse{HostNameBinding: result}, nil
		},
		deleteFn: func(_ context.Context, _, _, _ string, _ *armappservice.WebAppsClientDeleteHostNameBindingOptions) (armappservice.WebAppsClientDeleteHostNameBindingResponse, error) {
			return armappservice.WebAppsClientDeleteHostNameBindingResponse{}, nil
		},
		newListPagerFn: func(_, _ string, _ *armappservice.WebAppsClientListHostNameBindingsOptions) *runtime.Pager[armappservice.WebAppsClientListHostNameBindingsResponse] {
			return runtime.NewPager(runtime.PagingHandler[armappservice.WebAppsClientListHostNameBindingsResponse]{
				More: func(_ armappservice.WebAppsClientListHostNameBindingsResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armappservice.WebAppsClientListHostNameBindingsResponse) (armappservice.WebAppsClientListHostNameBindingsResponse, error) {
					return armappservice.WebAppsClientListHostNameBindingsResponse{
						HostNameBindingCollection: armappservice.HostNameBindingCollection{
							Value: []*armappservice.HostNameBinding{{ID: to.Ptr(testHostnameBindingNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestCustomHostnameBinding(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "www.example.com",
			Properties: hostnameBindingDesired(""),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testHostnameBindingNativeID, got.ProgressResult.NativeID)

		// The parent site name has to go in the body as well as the path.
		require.Equal(t, "app-1", *sent.Properties.SiteName)
		require.Equal(t, armappservice.HostNameTypeVerified, *sent.Properties.HostNameType)
		require.Equal(t, armappservice.CustomHostNameDNSRecordTypeCName, *sent.Properties.CustomHostNameDNSRecordType)
		require.Equal(t, armappservice.AzureResourceTypeWebsite, *sent.Properties.AzureResourceType)
		require.Nil(t, sent.Properties.SSLState)
	})

	t.Run("Create_requires_siteName", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "www.example.com", "resourceGroupName": "rg-1",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "siteName is required")
	})

	t.Run("Read_canonicalizes_enums_and_uses_arm_id", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testHostnameBindingNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		// Not "app-1/www.example.com", which is what the ARM body carries.
		require.Equal(t, "www.example.com", props["name"])
		require.Equal(t, "app-1", props["siteName"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		// ARM handed back "disabled"; desired state and the PKL union use "Disabled".
		require.Equal(t, "Disabled", props["sslState"])
		require.Equal(t, "Verified", props["hostNameType"])
		require.Equal(t, "CName", props["customHostNameDnsRecordType"])
		require.Equal(t, "Website", props["azureResourceType"])
	})

	t.Run("Update_sets_ssl_state", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testHostnameBindingNativeID,
			DesiredProperties: hostnameBindingDesired("Disabled"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testHostnameBindingNativeID, got.ProgressResult.NativeID)
		require.Equal(t, armappservice.SSLStateDisabled, *sent.Properties.SSLState)
	})

	t.Run("Delete", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testHostnameBindingNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _, _ string, _ *armappservice.WebAppsClientDeleteHostNameBindingOptions) (armappservice.WebAppsClientDeleteHostNameBindingResponse, error) {
			return armappservice.WebAppsClientDeleteHostNameBindingResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testHostnameBindingNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Status_rereads", func(t *testing.T) {
		got, err := prov.Status(context.Background(), &resource.StatusRequest{NativeID: testHostnameBindingNativeID, RequestID: "n/a"})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_parent_site", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "siteName": "app-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testHostnameBindingNativeID}, got.NativeIDs)
	})

	// The real-world failure mode: Azure refuses a hostname it cannot verify.
	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.createOrUpdateFn = func(_ context.Context, _, _, _ string, _ armappservice.HostNameBinding, _ *armappservice.WebAppsClientCreateOrUpdateHostNameBindingOptions) (armappservice.WebAppsClientCreateOrUpdateHostNameBindingResponse, error) {
			return armappservice.WebAppsClientCreateOrUpdateHostNameBindingResponse{}, &azcore.ResponseError{StatusCode: 400, ErrorCode: "CustomDomainVerificationFailed"}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "www.example.com",
			Properties: hostnameBindingDesired(""),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

func TestCustomHostnameBinding_ReadNotFound(t *testing.T) {
	fake := &fakeWebHostNameBindingsAPI{
		getFn: func(_ context.Context, _, _, _ string, _ *armappservice.WebAppsClientGetHostNameBindingOptions) (armappservice.WebAppsClientGetHostNameBindingResponse, error) {
			return armappservice.WebAppsClientGetHostNameBindingResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestCustomHostnameBinding(fake).Read(context.Background(), &resource.ReadRequest{NativeID: testHostnameBindingNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

func TestCustomHostnameBinding_IDParts(t *testing.T) {
	rgName, siteName, hostName, err := customHostnameBindingIDParts(testHostnameBindingNativeID)
	require.NoError(t, err)
	require.Equal(t, "rg-1", rgName)
	require.Equal(t, "app-1", siteName)
	require.Equal(t, "www.example.com", hostName)

	// The parent site's own ARM ID names no binding.
	_, _, _, err = customHostnameBindingIDParts(testWebAppNativeID)
	require.Error(t, err)
}

// --- Test helpers ---

type fakeWebHostNameBindingsAPI struct {
	createOrUpdateFn func(ctx context.Context, rgName, name, hostName string, params armappservice.HostNameBinding, options *armappservice.WebAppsClientCreateOrUpdateHostNameBindingOptions) (armappservice.WebAppsClientCreateOrUpdateHostNameBindingResponse, error)
	getFn            func(ctx context.Context, rgName, name, hostName string, options *armappservice.WebAppsClientGetHostNameBindingOptions) (armappservice.WebAppsClientGetHostNameBindingResponse, error)
	deleteFn         func(ctx context.Context, rgName, name, hostName string, options *armappservice.WebAppsClientDeleteHostNameBindingOptions) (armappservice.WebAppsClientDeleteHostNameBindingResponse, error)
	newListPagerFn   func(rgName, name string, options *armappservice.WebAppsClientListHostNameBindingsOptions) *runtime.Pager[armappservice.WebAppsClientListHostNameBindingsResponse]
}

func (f *fakeWebHostNameBindingsAPI) CreateOrUpdateHostNameBinding(ctx context.Context, rgName string, name string, hostName string, params armappservice.HostNameBinding, options *armappservice.WebAppsClientCreateOrUpdateHostNameBindingOptions) (armappservice.WebAppsClientCreateOrUpdateHostNameBindingResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, name, hostName, params, options)
}

func (f *fakeWebHostNameBindingsAPI) GetHostNameBinding(ctx context.Context, rgName string, name string, hostName string, options *armappservice.WebAppsClientGetHostNameBindingOptions) (armappservice.WebAppsClientGetHostNameBindingResponse, error) {
	return f.getFn(ctx, rgName, name, hostName, options)
}

func (f *fakeWebHostNameBindingsAPI) DeleteHostNameBinding(ctx context.Context, rgName string, name string, hostName string, options *armappservice.WebAppsClientDeleteHostNameBindingOptions) (armappservice.WebAppsClientDeleteHostNameBindingResponse, error) {
	return f.deleteFn(ctx, rgName, name, hostName, options)
}

func (f *fakeWebHostNameBindingsAPI) NewListHostNameBindingsPager(rgName string, name string, options *armappservice.WebAppsClientListHostNameBindingsOptions) *runtime.Pager[armappservice.WebAppsClientListHostNameBindingsResponse] {
	return f.newListPagerFn(rgName, name, options)
}
