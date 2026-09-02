// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/logic/armlogic"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testLogicIntegrationAccountCertificateNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Logic/integrationAccounts/ia-1/certificates/cert-1"

func newTestLogicIntegrationAccountCertificate(api logicIntegrationAccountCertificatesAPI) *LogicIntegrationAccountCertificate {
	return &LogicIntegrationAccountCertificate{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

const testLogicPublicCertificate = "MIIDIzCCAgugAwIBAgIUHoaq4IO1Gcn2inqN8Cb5CAQ"

func logicCertificateDesired(publicCertificate string) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":                   "cert-1",
		"resourceGroupName":      "rg-1",
		"integrationAccountName": "ia-1",
		"publicCertificate":      publicCertificate,
	})
	return out
}

func TestLogicIntegrationAccountCertificate_CRUD(t *testing.T) {
	// Unlike every other artifact body in this namespace, ARM echoes the
	// certificate blob rather than replacing it with a contentLink.
	result := armlogic.IntegrationAccountCertificate{
		ID:   to.Ptr(testLogicIntegrationAccountCertificateNativeID),
		Name: to.Ptr("cert-1"),
		Properties: &armlogic.IntegrationAccountCertificateProperties{
			PublicCertificate: to.Ptr(testLogicPublicCertificate),
			CreatedTime:       to.Ptr(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)),
			ChangedTime:       to.Ptr(time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)),
		},
	}

	var sentCreate armlogic.IntegrationAccountCertificate
	createCalls := 0
	deleteCalls := 0
	fake := &fakeLogicIntegrationAccountCertificatesAPI{
		createOrUpdateFn: func(_ context.Context, rgName, accountName, name string, params armlogic.IntegrationAccountCertificate, _ *armlogic.IntegrationAccountCertificatesClientCreateOrUpdateOptions) (armlogic.IntegrationAccountCertificatesClientCreateOrUpdateResponse, error) {
			require.Equal(t, "rg-1", rgName)
			require.Equal(t, "ia-1", accountName)
			require.Equal(t, "cert-1", name)
			sentCreate = params
			createCalls++
			return armlogic.IntegrationAccountCertificatesClientCreateOrUpdateResponse{IntegrationAccountCertificate: result}, nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ *armlogic.IntegrationAccountCertificatesClientGetOptions) (armlogic.IntegrationAccountCertificatesClientGetResponse, error) {
			return armlogic.IntegrationAccountCertificatesClientGetResponse{IntegrationAccountCertificate: result}, nil
		},
		deleteFn: func(_ context.Context, _, _, _ string, _ *armlogic.IntegrationAccountCertificatesClientDeleteOptions) (armlogic.IntegrationAccountCertificatesClientDeleteResponse, error) {
			deleteCalls++
			return armlogic.IntegrationAccountCertificatesClientDeleteResponse{}, nil
		},
		newListPagerFn: func(_, _ string, _ *armlogic.IntegrationAccountCertificatesClientListOptions) *runtime.Pager[armlogic.IntegrationAccountCertificatesClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armlogic.IntegrationAccountCertificatesClientListResponse]{
				More: func(_ armlogic.IntegrationAccountCertificatesClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armlogic.IntegrationAccountCertificatesClientListResponse) (armlogic.IntegrationAccountCertificatesClientListResponse, error) {
					return armlogic.IntegrationAccountCertificatesClientListResponse{
						IntegrationAccountCertificateListResult: armlogic.IntegrationAccountCertificateListResult{
							Value: []*armlogic.IntegrationAccountCertificate{{ID: to.Ptr(testLogicIntegrationAccountCertificateNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestLogicIntegrationAccountCertificate(fake)

	// Create is synchronous: IntegrationAccountCertificatesClient has no BeginX at all, so no
	// resume token is ever produced.
	t.Run("Create_is_synchronous", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "cert-1",
			Properties: logicCertificateDesired(testLogicPublicCertificate),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testLogicIntegrationAccountCertificateNativeID, got.ProgressResult.NativeID)
		require.Empty(t, got.ProgressResult.RequestID)

		require.Equal(t, testLogicPublicCertificate, *sentCreate.Properties.PublicCertificate)
		// The public form only: the Key Vault form needs a data-plane grant this
		// resource type cannot express, so the key member is never set.
		require.Nil(t, sentCreate.Properties.Key)
	})

	t.Run("Create_requires_resource_group", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "cert-1", "integrationAccountName": "ia-1"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "resourceGroupName is required")
	})

	t.Run("Create_requires_integration_account", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "cert-1", "resourceGroupName": "rg-1"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "integrationAccountName is required")
	})

	t.Run("Create_requires_public_certificate", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "cert-1", "resourceGroupName": "rg-1", "integrationAccountName": "ia-1",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "publicCertificate is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testLogicIntegrationAccountCertificateNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "cert-1", props["name"])
		// Both parents come from the native ID, not the response body: ARM echoes
		// neither on a child.
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "ia-1", props["integrationAccountName"])
		require.Equal(t, testLogicPublicCertificate, props["publicCertificate"])
	})

	t.Run("Read_drops_key_vault_reference_and_service_state", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testLogicIntegrationAccountCertificateNativeID})
		require.NoError(t, err)
		for _, key := range []string{"key", "keyVault", "metadata", "createdTime", "changedTime"} {
			require.NotContains(t, got.Properties, key)
		}
	})

	// armExactIDParts, not armIDParts: an ID naming a different child kind of the
	// same account must be rejected here rather than 404ing against the wrong
	// client.
	t.Run("Read_rejects_another_child_kind", func(t *testing.T) {
		_, err := prov.Read(context.Background(), &resource.ReadRequest{
			NativeID: "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Logic/integrationAccounts/ia-1/sessions/s-1",
		})
		require.Error(t, err)
	})

	// Update reissues CreateOrUpdate: this API has no PATCH verb for certificates.
	t.Run("Update_reissues_create_or_update", func(t *testing.T) {
		before := createCalls
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testLogicIntegrationAccountCertificateNativeID,
			DesiredProperties: logicCertificateDesired(testLogicPublicCertificate + "ROTATED"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Empty(t, got.ProgressResult.RequestID)
		require.Equal(t, before+1, createCalls)
		require.Equal(t, testLogicPublicCertificate+"ROTATED", *sentCreate.Properties.PublicCertificate)
	})

	t.Run("Delete_is_synchronous", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testLogicIntegrationAccountCertificateNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Empty(t, got.ProgressResult.RequestID)
		require.Equal(t, before+1, deleteCalls)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _, _ string, _ *armlogic.IntegrationAccountCertificatesClientDeleteOptions) (armlogic.IntegrationAccountCertificatesClientDeleteResponse, error) {
			return armlogic.IntegrationAccountCertificatesClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testLogicIntegrationAccountCertificateNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_account", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "integrationAccountName": "ia-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testLogicIntegrationAccountCertificateNativeID}, got.NativeIDs)
	})

	// ARM has no subscription-wide listing here: without both parents there is
	// nothing to page, so List must return empty rather than error. Both keys ARE
	// supplied by the hint's listParam, so no subscriptionWideList entry is
	// needed.
	t.Run("List_without_parents_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure_with_a_cause", func(t *testing.T) {
		fake.createOrUpdateFn = func(_ context.Context, _, _, _ string, _ armlogic.IntegrationAccountCertificate, _ *armlogic.IntegrationAccountCertificatesClientCreateOrUpdateOptions) (armlogic.IntegrationAccountCertificatesClientCreateOrUpdateResponse, error) {
			return armlogic.IntegrationAccountCertificatesClientCreateOrUpdateResponse{}, &azcore.ResponseError{StatusCode: 409}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "cert-1", Properties: logicCertificateDesired(testLogicPublicCertificate),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.NotEmpty(t, got.ProgressResult.StatusMessage)
	})
}

func TestLogicIntegrationAccountCertificate_ReadNotFound(t *testing.T) {
	fake := &fakeLogicIntegrationAccountCertificatesAPI{
		getFn: func(_ context.Context, _, _, _ string, _ *armlogic.IntegrationAccountCertificatesClientGetOptions) (armlogic.IntegrationAccountCertificatesClientGetResponse, error) {
			return armlogic.IntegrationAccountCertificatesClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestLogicIntegrationAccountCertificate(fake).Read(context.Background(),
		&resource.ReadRequest{NativeID: testLogicIntegrationAccountCertificateNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// A certificate ARM answers without a public half - which is what a Key Vault
// backed certificate created outside this provider looks like - must read
// without the property rather than reporting an empty string as its value.
func TestLogicIntegrationAccountCertificate_ReadWithoutPublicHalf(t *testing.T) {
	fake := &fakeLogicIntegrationAccountCertificatesAPI{
		getFn: func(_ context.Context, _, _, _ string, _ *armlogic.IntegrationAccountCertificatesClientGetOptions) (armlogic.IntegrationAccountCertificatesClientGetResponse, error) {
			return armlogic.IntegrationAccountCertificatesClientGetResponse{
				IntegrationAccountCertificate: armlogic.IntegrationAccountCertificate{
					ID:   to.Ptr(testLogicIntegrationAccountCertificateNativeID),
					Name: to.Ptr("cert-1"),
					Properties: &armlogic.IntegrationAccountCertificateProperties{
						Key: &armlogic.KeyVaultKeyReference{KeyName: to.Ptr("signing")},
					},
				},
			}, nil
		},
	}
	got, err := newTestLogicIntegrationAccountCertificate(fake).Read(context.Background(),
		&resource.ReadRequest{NativeID: testLogicIntegrationAccountCertificateNativeID})
	require.NoError(t, err)
	require.NotContains(t, got.Properties, "publicCertificate")
}

// --- Test helpers ---

type fakeLogicIntegrationAccountCertificatesAPI struct {
	createOrUpdateFn func(ctx context.Context, rgName, accountName, name string, params armlogic.IntegrationAccountCertificate, options *armlogic.IntegrationAccountCertificatesClientCreateOrUpdateOptions) (armlogic.IntegrationAccountCertificatesClientCreateOrUpdateResponse, error)
	getFn            func(ctx context.Context, rgName, accountName, name string, options *armlogic.IntegrationAccountCertificatesClientGetOptions) (armlogic.IntegrationAccountCertificatesClientGetResponse, error)
	deleteFn         func(ctx context.Context, rgName, accountName, name string, options *armlogic.IntegrationAccountCertificatesClientDeleteOptions) (armlogic.IntegrationAccountCertificatesClientDeleteResponse, error)
	newListPagerFn   func(rgName, accountName string, options *armlogic.IntegrationAccountCertificatesClientListOptions) *runtime.Pager[armlogic.IntegrationAccountCertificatesClientListResponse]
}

func (f *fakeLogicIntegrationAccountCertificatesAPI) CreateOrUpdate(ctx context.Context, rgName, accountName, name string, params armlogic.IntegrationAccountCertificate, options *armlogic.IntegrationAccountCertificatesClientCreateOrUpdateOptions) (armlogic.IntegrationAccountCertificatesClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, accountName, name, params, options)
}

func (f *fakeLogicIntegrationAccountCertificatesAPI) Get(ctx context.Context, rgName, accountName, name string, options *armlogic.IntegrationAccountCertificatesClientGetOptions) (armlogic.IntegrationAccountCertificatesClientGetResponse, error) {
	return f.getFn(ctx, rgName, accountName, name, options)
}

func (f *fakeLogicIntegrationAccountCertificatesAPI) Delete(ctx context.Context, rgName, accountName, name string, options *armlogic.IntegrationAccountCertificatesClientDeleteOptions) (armlogic.IntegrationAccountCertificatesClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, accountName, name, options)
}

func (f *fakeLogicIntegrationAccountCertificatesAPI) NewListPager(rgName, accountName string, options *armlogic.IntegrationAccountCertificatesClientListOptions) *runtime.Pager[armlogic.IntegrationAccountCertificatesClientListResponse] {
	return f.newListPagerFn(rgName, accountName, options)
}
