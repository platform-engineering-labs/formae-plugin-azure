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
	testWebCertNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Web/certificates/cert-1"
	// "placeholder-pfx" in base-64.
	testPfxBase64 = "cGxhY2Vob2xkZXItcGZ4"
)

func newTestWebCertificate(api webCertificatesAPI) *WebCertificate {
	return &WebCertificate{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func webCertDesired(password string) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":              "cert-1",
		"resourceGroupName": "rg-1",
		"location":          "eastus",
		"serverFarmId":      testServerFarmID,
		"pfxBlob":           map[string]any{"$value": testPfxBase64},
		"password":          map[string]any{"$value": password},
		"Tags":              []any{map[string]any{"Key": "env", "Value": "test"}},
	})
	return out
}

func webCertResult() armappservice.AppCertificate {
	return armappservice.AppCertificate{
		ID:       to.Ptr(testWebCertNativeID),
		Name:     to.Ptr("cert-1"),
		Location: to.Ptr("East US"),
		Properties: &armappservice.AppCertificateProperties{
			ServerFarmID: to.Ptr(testServerFarmID),
			HostNames:    []*string{to.Ptr("www.example.com")},
			Thumbprint:   to.Ptr("ABCDEF0123456789"),
			SubjectName:  to.Ptr("www.example.com"),
			Issuer:       to.Ptr("Example CA"),
			// Azure never returns the key material, but assert the plugin would not
			// leak it even if a response carried it.
			PfxBlob: []byte("should-not-surface"),
		},
		Tags: map[string]*string{"env": to.Ptr("test")},
	}
}

func TestWebCertificate_CRUD(t *testing.T) {
	result := webCertResult()

	var sent armappservice.AppCertificate
	fake := &fakeWebCertificatesAPI{
		createOrUpdateFn: func(_ context.Context, rgName, name string, params armappservice.AppCertificate, _ *armappservice.CertificatesClientCreateOrUpdateOptions) (armappservice.CertificatesClientCreateOrUpdateResponse, error) {
			require.Equal(t, "rg-1", rgName)
			require.Equal(t, "cert-1", name)
			sent = params
			return armappservice.CertificatesClientCreateOrUpdateResponse{AppCertificate: result}, nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armappservice.CertificatesClientGetOptions) (armappservice.CertificatesClientGetResponse, error) {
			return armappservice.CertificatesClientGetResponse{AppCertificate: result}, nil
		},
		deleteFn: func(_ context.Context, _, _ string, _ *armappservice.CertificatesClientDeleteOptions) (armappservice.CertificatesClientDeleteResponse, error) {
			return armappservice.CertificatesClientDeleteResponse{}, nil
		},
		newListByResourceGroupPagerFn: func(_ string, _ *armappservice.CertificatesClientListByResourceGroupOptions) *runtime.Pager[armappservice.CertificatesClientListByResourceGroupResponse] {
			return runtime.NewPager(runtime.PagingHandler[armappservice.CertificatesClientListByResourceGroupResponse]{
				More: func(_ armappservice.CertificatesClientListByResourceGroupResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armappservice.CertificatesClientListByResourceGroupResponse) (armappservice.CertificatesClientListByResourceGroupResponse, error) {
					return armappservice.CertificatesClientListByResourceGroupResponse{
						AppCertificateCollection: armappservice.AppCertificateCollection{
							Value: []*armappservice.AppCertificate{{ID: to.Ptr(testWebCertNativeID)}},
						},
					}, nil
				},
			})
		},
		newListPagerFn: func(_ *armappservice.CertificatesClientListOptions) *runtime.Pager[armappservice.CertificatesClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armappservice.CertificatesClientListResponse]{
				More: func(_ armappservice.CertificatesClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armappservice.CertificatesClientListResponse) (armappservice.CertificatesClientListResponse, error) {
					return armappservice.CertificatesClientListResponse{
						AppCertificateCollection: armappservice.AppCertificateCollection{
							Value: []*armappservice.AppCertificate{
								{ID: to.Ptr(testWebCertNativeID)},
								{ID: to.Ptr("/subscriptions/sub-1/resourceGroups/rg-2/providers/Microsoft.Web/certificates/cert-2")},
							},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestWebCertificate(fake)

	t.Run("Create_decodes_pfx_blob", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "cert-1",
			Properties: webCertDesired("secret"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testWebCertNativeID, got.ProgressResult.NativeID)

		require.Equal(t, "eastus", *sent.Location)
		require.Equal(t, testServerFarmID, *sent.Properties.ServerFarmID)
		// The PKL field carries base-64 text; the SDK model is raw bytes it
		// re-encodes on the wire, so the plugin has to decode on the way in.
		require.Equal(t, []byte("placeholder-pfx"), sent.Properties.PfxBlob)
		require.Equal(t, "secret", *sent.Properties.Password)
		require.Equal(t, "test", *sent.Tags["env"])
	})

	t.Run("Create_rejects_invalid_base64", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "cert-1", "resourceGroupName": "rg-1", "location": "eastus",
			"pfxBlob": "not!valid!base64",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "pfxBlob is not valid base-64")
	})

	t.Run("Create_requires_certificate_material", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "cert-1", "resourceGroupName": "rg-1", "location": "eastus",
			"serverFarmId": testServerFarmID,
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "one of pfxBlob, keyVaultId or canonicalName is required")
	})

	t.Run("Create_accepts_key_vault_reference", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "cert-1", "resourceGroupName": "rg-1", "location": "eastus",
			"keyVaultId":         "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.KeyVault/vaults/kv-1",
			"keyVaultSecretName": "wildcard",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.Equal(t, "wildcard", *sent.Properties.KeyVaultSecretName)
		require.Nil(t, sent.Properties.PfxBlob)
	})

	t.Run("Read_never_returns_key_material", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testWebCertNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "cert-1", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "eastus", props["location"])
		require.Equal(t, testServerFarmID, props["serverFarmId"])
		require.Equal(t, []any{"www.example.com"}, props["hostNames"])
		require.Equal(t, "ABCDEF0123456789", props["thumbprint"])
		require.Equal(t, "www.example.com", props["subjectName"])
		require.Equal(t, "Example CA", props["issuer"])
		require.NotContains(t, props, "pfxBlob")
		require.NotContains(t, props, "password")
	})

	t.Run("Update_keeps_native_id", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testWebCertNativeID,
			DesiredProperties: webCertDesired("rotated"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testWebCertNativeID, got.ProgressResult.NativeID)
		require.Equal(t, "rotated", *sent.Properties.Password)
	})

	t.Run("Delete", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testWebCertNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _ string, _ *armappservice.CertificatesClientDeleteOptions) (armappservice.CertificatesClientDeleteResponse, error) {
			return armappservice.CertificatesClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testWebCertNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Status_rereads", func(t *testing.T) {
		got, err := prov.Status(context.Background(), &resource.StatusRequest{NativeID: testWebCertNativeID, RequestID: "n/a"})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testWebCertNativeID, got.ProgressResult.NativeID)
	})

	t.Run("List_by_resource_group", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testWebCertNativeID}, got.NativeIDs)
	})

	t.Run("List_without_group_is_subscription_wide", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 2)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.createOrUpdateFn = func(_ context.Context, _, _ string, _ armappservice.AppCertificate, _ *armappservice.CertificatesClientCreateOrUpdateOptions) (armappservice.CertificatesClientCreateOrUpdateResponse, error) {
			return armappservice.CertificatesClientCreateOrUpdateResponse{}, &azcore.ResponseError{StatusCode: 400}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "cert-1",
			Properties: webCertDesired("secret"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

func TestWebCertificate_ReadNotFound(t *testing.T) {
	fake := &fakeWebCertificatesAPI{
		getFn: func(_ context.Context, _, _ string, _ *armappservice.CertificatesClientGetOptions) (armappservice.CertificatesClientGetResponse, error) {
			return armappservice.CertificatesClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestWebCertificate(fake).Read(context.Background(), &resource.ReadRequest{NativeID: testWebCertNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

func TestWebCertificate_IDParts(t *testing.T) {
	rgName, certName, err := webCertificateIDParts(testWebCertNativeID)
	require.NoError(t, err)
	require.Equal(t, "rg-1", rgName)
	require.Equal(t, "cert-1", certName)

	_, _, err = webCertificateIDParts(testWebAppNativeID)
	require.Error(t, err)
}

// --- Test helpers ---

type fakeWebCertificatesAPI struct {
	createOrUpdateFn              func(ctx context.Context, rgName, name string, params armappservice.AppCertificate, options *armappservice.CertificatesClientCreateOrUpdateOptions) (armappservice.CertificatesClientCreateOrUpdateResponse, error)
	getFn                         func(ctx context.Context, rgName, name string, options *armappservice.CertificatesClientGetOptions) (armappservice.CertificatesClientGetResponse, error)
	deleteFn                      func(ctx context.Context, rgName, name string, options *armappservice.CertificatesClientDeleteOptions) (armappservice.CertificatesClientDeleteResponse, error)
	newListByResourceGroupPagerFn func(rgName string, options *armappservice.CertificatesClientListByResourceGroupOptions) *runtime.Pager[armappservice.CertificatesClientListByResourceGroupResponse]
	newListPagerFn                func(options *armappservice.CertificatesClientListOptions) *runtime.Pager[armappservice.CertificatesClientListResponse]
}

func (f *fakeWebCertificatesAPI) CreateOrUpdate(ctx context.Context, rgName string, name string, params armappservice.AppCertificate, options *armappservice.CertificatesClientCreateOrUpdateOptions) (armappservice.CertificatesClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, name, params, options)
}

func (f *fakeWebCertificatesAPI) Get(ctx context.Context, rgName string, name string, options *armappservice.CertificatesClientGetOptions) (armappservice.CertificatesClientGetResponse, error) {
	return f.getFn(ctx, rgName, name, options)
}

func (f *fakeWebCertificatesAPI) Delete(ctx context.Context, rgName string, name string, options *armappservice.CertificatesClientDeleteOptions) (armappservice.CertificatesClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, name, options)
}

func (f *fakeWebCertificatesAPI) NewListByResourceGroupPager(rgName string, options *armappservice.CertificatesClientListByResourceGroupOptions) *runtime.Pager[armappservice.CertificatesClientListByResourceGroupResponse] {
	return f.newListByResourceGroupPagerFn(rgName, options)
}

func (f *fakeWebCertificatesAPI) NewListPager(options *armappservice.CertificatesClientListOptions) *runtime.Pager[armappservice.CertificatesClientListResponse] {
	return f.newListPagerFn(options)
}
