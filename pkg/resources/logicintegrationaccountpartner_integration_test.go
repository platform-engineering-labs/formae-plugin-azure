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

const testLogicIntegrationAccountPartnerNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Logic/integrationAccounts/ia-1/partners/ptn-1"

func newTestLogicIntegrationAccountPartner(api logicIntegrationAccountPartnersAPI) *LogicIntegrationAccountPartner {
	return &LogicIntegrationAccountPartner{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func logicPartnerDesired(identities ...map[string]string) []byte {
	entries := make([]map[string]string, 0, len(identities))
	entries = append(entries, identities...)
	out, _ := json.Marshal(map[string]any{
		"name":                   "ptn-1",
		"resourceGroupName":      "rg-1",
		"integrationAccountName": "ia-1",
		"partnerType":            "B2B",
		"businessIdentities":     entries,
	})
	return out
}

func logicAS2Identity(value string) map[string]string {
	return map[string]string{"qualifier": "AS2Identity", "value": value}
}

func TestLogicIntegrationAccountPartner_CRUD(t *testing.T) {
	result := armlogic.IntegrationAccountPartner{
		ID:   to.Ptr(testLogicIntegrationAccountPartnerNativeID),
		Name: to.Ptr("ptn-1"),
		Properties: &armlogic.IntegrationAccountPartnerProperties{
			PartnerType: to.Ptr(armlogic.PartnerTypeB2B),
			Content: &armlogic.PartnerContent{
				B2B: &armlogic.B2BPartnerContent{
					BusinessIdentities: []*armlogic.BusinessIdentity{
						{Qualifier: to.Ptr("AS2Identity"), Value: to.Ptr("FORMAE-HOST")},
					},
				},
			},
			CreatedTime: to.Ptr(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)),
			ChangedTime: to.Ptr(time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)),
		},
	}

	var sentCreate armlogic.IntegrationAccountPartner
	createCalls := 0
	deleteCalls := 0
	fake := &fakeLogicIntegrationAccountPartnersAPI{
		createOrUpdateFn: func(_ context.Context, rgName, accountName, name string, params armlogic.IntegrationAccountPartner, _ *armlogic.IntegrationAccountPartnersClientCreateOrUpdateOptions) (armlogic.IntegrationAccountPartnersClientCreateOrUpdateResponse, error) {
			require.Equal(t, "rg-1", rgName)
			require.Equal(t, "ia-1", accountName)
			require.Equal(t, "ptn-1", name)
			sentCreate = params
			createCalls++
			return armlogic.IntegrationAccountPartnersClientCreateOrUpdateResponse{IntegrationAccountPartner: result}, nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ *armlogic.IntegrationAccountPartnersClientGetOptions) (armlogic.IntegrationAccountPartnersClientGetResponse, error) {
			return armlogic.IntegrationAccountPartnersClientGetResponse{IntegrationAccountPartner: result}, nil
		},
		deleteFn: func(_ context.Context, _, _, _ string, _ *armlogic.IntegrationAccountPartnersClientDeleteOptions) (armlogic.IntegrationAccountPartnersClientDeleteResponse, error) {
			deleteCalls++
			return armlogic.IntegrationAccountPartnersClientDeleteResponse{}, nil
		},
		newListPagerFn: func(_, _ string, _ *armlogic.IntegrationAccountPartnersClientListOptions) *runtime.Pager[armlogic.IntegrationAccountPartnersClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armlogic.IntegrationAccountPartnersClientListResponse]{
				More: func(_ armlogic.IntegrationAccountPartnersClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armlogic.IntegrationAccountPartnersClientListResponse) (armlogic.IntegrationAccountPartnersClientListResponse, error) {
					return armlogic.IntegrationAccountPartnersClientListResponse{
						IntegrationAccountPartnerListResult: armlogic.IntegrationAccountPartnerListResult{
							Value: []*armlogic.IntegrationAccountPartner{{ID: to.Ptr(testLogicIntegrationAccountPartnerNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestLogicIntegrationAccountPartner(fake)

	// Create is synchronous: IntegrationAccountPartnersClient has no BeginX at all, so no
	// resume token is ever produced.
	t.Run("Create_is_synchronous", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "ptn-1",
			Properties: logicPartnerDesired(logicAS2Identity("FORMAE-HOST")),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testLogicIntegrationAccountPartnerNativeID, got.ProgressResult.NativeID)
		require.Empty(t, got.ProgressResult.RequestID)

		require.Equal(t, armlogic.PartnerTypeB2B, *sentCreate.Properties.PartnerType)
		// The schema flattens ARM's content.b2b.businessIdentities wrapper, so the
		// provider has to rebuild both intermediate objects.
		require.NotNil(t, sentCreate.Properties.Content.B2B)
		require.Len(t, sentCreate.Properties.Content.B2B.BusinessIdentities, 1)
		require.Equal(t, "AS2Identity", *sentCreate.Properties.Content.B2B.BusinessIdentities[0].Qualifier)
		require.Equal(t, "FORMAE-HOST", *sentCreate.Properties.Content.B2B.BusinessIdentities[0].Value)
	})

	t.Run("Create_requires_resource_group", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "ptn-1", "integrationAccountName": "ia-1"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "resourceGroupName is required")
	})

	t.Run("Create_requires_integration_account", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "ptn-1", "resourceGroupName": "rg-1"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "integrationAccountName is required")
	})

	t.Run("Create_requires_partner_type", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "ptn-1", "resourceGroupName": "rg-1", "integrationAccountName": "ia-1",
			"businessIdentities": []map[string]string{logicAS2Identity("FORMAE-HOST")},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "partnerType is required")
	})

	t.Run("Create_requires_at_least_one_identity", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "ptn-1", "resourceGroupName": "rg-1", "integrationAccountName": "ia-1",
			"partnerType": "B2B",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "businessIdentities is required")
	})

	// An agreement matches a partner on BOTH qualifier and value, so a half-filled
	// identity has to fail here rather than produce a partner no agreement can
	// name.
	t.Run("Create_rejects_a_half_filled_identity", func(t *testing.T) {
		_, err := prov.Create(context.Background(), &resource.CreateRequest{
			Properties: logicPartnerDesired(map[string]string{"qualifier": "AS2Identity"}),
		})
		require.ErrorContains(t, err, "businessIdentities[0].value is required")

		_, err = prov.Create(context.Background(), &resource.CreateRequest{
			Properties: logicPartnerDesired(map[string]string{"value": "FORMAE-HOST"}),
		})
		require.ErrorContains(t, err, "businessIdentities[0].qualifier is required")
	})


	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testLogicIntegrationAccountPartnerNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "ptn-1", props["name"])
		// Both parents come from the native ID, not the response body: ARM echoes
		// neither on a child.
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "ia-1", props["integrationAccountName"])
		require.Equal(t, "B2B", props["partnerType"])
		identities, ok := props["businessIdentities"].([]any)
		require.True(t, ok)
		require.Len(t, identities, 1)
		require.Equal(t, map[string]any{"qualifier": "AS2Identity", "value": "FORMAE-HOST"}, identities[0])
	})

	t.Run("Read_drops_service_state", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testLogicIntegrationAccountPartnerNativeID})
		require.NoError(t, err)
		for _, key := range []string{"metadata", "createdTime", "changedTime"} {
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

	// Update reissues CreateOrUpdate: this API has no PATCH verb for partners.
	t.Run("Update_reissues_create_or_update", func(t *testing.T) {
		before := createCalls
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testLogicIntegrationAccountPartnerNativeID,
			DesiredProperties: logicPartnerDesired(logicAS2Identity("FORMAE-HOST"), map[string]string{"qualifier": "ZZ", "value": "FORMAEHOST"}),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Empty(t, got.ProgressResult.RequestID)
		require.Equal(t, before+1, createCalls)
		// Order is preserved: ARM stores the identity list as given.
		require.Len(t, sentCreate.Properties.Content.B2B.BusinessIdentities, 2)
		require.Equal(t, "FORMAE-HOST", *sentCreate.Properties.Content.B2B.BusinessIdentities[0].Value)
		require.Equal(t, "ZZ", *sentCreate.Properties.Content.B2B.BusinessIdentities[1].Qualifier)
	})

	t.Run("Delete_is_synchronous", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testLogicIntegrationAccountPartnerNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Empty(t, got.ProgressResult.RequestID)
		require.Equal(t, before+1, deleteCalls)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _, _ string, _ *armlogic.IntegrationAccountPartnersClientDeleteOptions) (armlogic.IntegrationAccountPartnersClientDeleteResponse, error) {
			return armlogic.IntegrationAccountPartnersClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testLogicIntegrationAccountPartnerNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_account", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "integrationAccountName": "ia-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testLogicIntegrationAccountPartnerNativeID}, got.NativeIDs)
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
		fake.createOrUpdateFn = func(_ context.Context, _, _, _ string, _ armlogic.IntegrationAccountPartner, _ *armlogic.IntegrationAccountPartnersClientCreateOrUpdateOptions) (armlogic.IntegrationAccountPartnersClientCreateOrUpdateResponse, error) {
			return armlogic.IntegrationAccountPartnersClientCreateOrUpdateResponse{}, &azcore.ResponseError{StatusCode: 409}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "ptn-1", Properties: logicPartnerDesired(logicAS2Identity("FORMAE-HOST")),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.NotEmpty(t, got.ProgressResult.StatusMessage)
	})
}

func TestLogicIntegrationAccountPartner_ReadNotFound(t *testing.T) {
	fake := &fakeLogicIntegrationAccountPartnersAPI{
		getFn: func(_ context.Context, _, _, _ string, _ *armlogic.IntegrationAccountPartnersClientGetOptions) (armlogic.IntegrationAccountPartnersClientGetResponse, error) {
			return armlogic.IntegrationAccountPartnersClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestLogicIntegrationAccountPartner(fake).Read(context.Background(),
		&resource.ReadRequest{NativeID: testLogicIntegrationAccountPartnerNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeLogicIntegrationAccountPartnersAPI struct {
	createOrUpdateFn func(ctx context.Context, rgName, accountName, name string, params armlogic.IntegrationAccountPartner, options *armlogic.IntegrationAccountPartnersClientCreateOrUpdateOptions) (armlogic.IntegrationAccountPartnersClientCreateOrUpdateResponse, error)
	getFn            func(ctx context.Context, rgName, accountName, name string, options *armlogic.IntegrationAccountPartnersClientGetOptions) (armlogic.IntegrationAccountPartnersClientGetResponse, error)
	deleteFn         func(ctx context.Context, rgName, accountName, name string, options *armlogic.IntegrationAccountPartnersClientDeleteOptions) (armlogic.IntegrationAccountPartnersClientDeleteResponse, error)
	newListPagerFn   func(rgName, accountName string, options *armlogic.IntegrationAccountPartnersClientListOptions) *runtime.Pager[armlogic.IntegrationAccountPartnersClientListResponse]
}

func (f *fakeLogicIntegrationAccountPartnersAPI) CreateOrUpdate(ctx context.Context, rgName, accountName, name string, params armlogic.IntegrationAccountPartner, options *armlogic.IntegrationAccountPartnersClientCreateOrUpdateOptions) (armlogic.IntegrationAccountPartnersClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, accountName, name, params, options)
}

func (f *fakeLogicIntegrationAccountPartnersAPI) Get(ctx context.Context, rgName, accountName, name string, options *armlogic.IntegrationAccountPartnersClientGetOptions) (armlogic.IntegrationAccountPartnersClientGetResponse, error) {
	return f.getFn(ctx, rgName, accountName, name, options)
}

func (f *fakeLogicIntegrationAccountPartnersAPI) Delete(ctx context.Context, rgName, accountName, name string, options *armlogic.IntegrationAccountPartnersClientDeleteOptions) (armlogic.IntegrationAccountPartnersClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, accountName, name, options)
}

func (f *fakeLogicIntegrationAccountPartnersAPI) NewListPager(rgName, accountName string, options *armlogic.IntegrationAccountPartnersClientListOptions) *runtime.Pager[armlogic.IntegrationAccountPartnersClientListResponse] {
	return f.newListPagerFn(rgName, accountName, options)
}
