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

const testLogicIntegrationAccountAgreementNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Logic/integrationAccounts/ia-1/agreements/agr-1"

func newTestLogicIntegrationAccountAgreement(api logicIntegrationAccountAgreementsAPI) *LogicIntegrationAccountAgreement {
	return &LogicIntegrationAccountAgreement{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

// The AS2 settings block, as the schema carries it: the INNER document with
// receiveAgreement and sendAgreement, not ARM's one-member AgreementContent
// wrapper. A real fixture fills in every one of the ~70 required leaves; the
// provider only has to route the document to the right member and reject one
// that is the wrong shape, so this abbreviated block is enough here.
const testLogicAgreementAS2Content = `{"receiveAgreement":{"protocolSettings":{"mdnSettings":{"micHashingAlgorithm":"NotSpecified","needMDN":false}},"receiverBusinessIdentity":{"qualifier":"AS2Identity","value":"FORMAE-HOST"},"senderBusinessIdentity":{"qualifier":"AS2Identity","value":"FORMAE-GUEST"}},"sendAgreement":{"protocolSettings":{"mdnSettings":{"micHashingAlgorithm":"NotSpecified","needMDN":false}},"receiverBusinessIdentity":{"qualifier":"AS2Identity","value":"FORMAE-GUEST"},"senderBusinessIdentity":{"qualifier":"AS2Identity","value":"FORMAE-HOST"}}}`

const testLogicAgreementAS2ContentUpdated = `{"receiveAgreement":{"protocolSettings":{"mdnSettings":{"micHashingAlgorithm":"SHA2256","needMDN":false}},"receiverBusinessIdentity":{"qualifier":"AS2Identity","value":"FORMAE-HOST"},"senderBusinessIdentity":{"qualifier":"AS2Identity","value":"FORMAE-GUEST"}},"sendAgreement":{"protocolSettings":{"mdnSettings":{"micHashingAlgorithm":"SHA2256","needMDN":false}},"receiverBusinessIdentity":{"qualifier":"AS2Identity","value":"FORMAE-GUEST"},"senderBusinessIdentity":{"qualifier":"AS2Identity","value":"FORMAE-HOST"}}}`

func logicAgreementDesired(agreementType, content string) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":                   "agr-1",
		"resourceGroupName":      "rg-1",
		"integrationAccountName": "ia-1",
		"agreementType":          agreementType,
		"hostPartner":            "conformance-host",
		"guestPartner":           "conformance-guest",
		"hostIdentity":           map[string]string{"qualifier": "AS2Identity", "value": "FORMAE-HOST"},
		"guestIdentity":          map[string]string{"qualifier": "AS2Identity", "value": "FORMAE-GUEST"},
		"content":                content,
	})
	return out
}

func TestLogicIntegrationAccountAgreement_CRUD(t *testing.T) {
	// ARM fills in every optional leaf of the protocol settings tree it did not
	// receive and reorders the object, which is why content is writeOnly and is
	// never read back.
	result := armlogic.IntegrationAccountAgreement{
		ID:   to.Ptr(testLogicIntegrationAccountAgreementNativeID),
		Name: to.Ptr("agr-1"),
		Properties: &armlogic.IntegrationAccountAgreementProperties{
			AgreementType: to.Ptr(armlogic.AgreementTypeAS2),
			HostPartner:   to.Ptr("conformance-host"),
			GuestPartner:  to.Ptr("conformance-guest"),
			HostIdentity:  &armlogic.BusinessIdentity{Qualifier: to.Ptr("AS2Identity"), Value: to.Ptr("FORMAE-HOST")},
			GuestIdentity: &armlogic.BusinessIdentity{Qualifier: to.Ptr("AS2Identity"), Value: to.Ptr("FORMAE-GUEST")},
			Content: &armlogic.AgreementContent{
				AS2: &armlogic.AS2AgreementContent{
					ReceiveAgreement: &armlogic.AS2OneWayAgreement{
						ProtocolSettings: &armlogic.AS2ProtocolSettings{
							MdnSettings: &armlogic.AS2MdnSettings{
								MicHashingAlgorithm: to.Ptr(armlogic.HashingAlgorithmNotSpecified),
								NeedMDN:             to.Ptr(false),
								MdnText:             to.Ptr("filled in by ARM"),
							},
						},
					},
				},
			},
			CreatedTime: to.Ptr(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)),
			ChangedTime: to.Ptr(time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)),
		},
	}

	var sentCreate armlogic.IntegrationAccountAgreement
	createCalls := 0
	deleteCalls := 0
	fake := &fakeLogicIntegrationAccountAgreementsAPI{
		createOrUpdateFn: func(_ context.Context, rgName, accountName, name string, params armlogic.IntegrationAccountAgreement, _ *armlogic.IntegrationAccountAgreementsClientCreateOrUpdateOptions) (armlogic.IntegrationAccountAgreementsClientCreateOrUpdateResponse, error) {
			require.Equal(t, "rg-1", rgName)
			require.Equal(t, "ia-1", accountName)
			require.Equal(t, "agr-1", name)
			sentCreate = params
			createCalls++
			return armlogic.IntegrationAccountAgreementsClientCreateOrUpdateResponse{IntegrationAccountAgreement: result}, nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ *armlogic.IntegrationAccountAgreementsClientGetOptions) (armlogic.IntegrationAccountAgreementsClientGetResponse, error) {
			return armlogic.IntegrationAccountAgreementsClientGetResponse{IntegrationAccountAgreement: result}, nil
		},
		deleteFn: func(_ context.Context, _, _, _ string, _ *armlogic.IntegrationAccountAgreementsClientDeleteOptions) (armlogic.IntegrationAccountAgreementsClientDeleteResponse, error) {
			deleteCalls++
			return armlogic.IntegrationAccountAgreementsClientDeleteResponse{}, nil
		},
		newListPagerFn: func(_, _ string, _ *armlogic.IntegrationAccountAgreementsClientListOptions) *runtime.Pager[armlogic.IntegrationAccountAgreementsClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armlogic.IntegrationAccountAgreementsClientListResponse]{
				More: func(_ armlogic.IntegrationAccountAgreementsClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armlogic.IntegrationAccountAgreementsClientListResponse) (armlogic.IntegrationAccountAgreementsClientListResponse, error) {
					return armlogic.IntegrationAccountAgreementsClientListResponse{
						IntegrationAccountAgreementListResult: armlogic.IntegrationAccountAgreementListResult{
							Value: []*armlogic.IntegrationAccountAgreement{{ID: to.Ptr(testLogicIntegrationAccountAgreementNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestLogicIntegrationAccountAgreement(fake)

	// Create is synchronous: IntegrationAccountAgreementsClient has no BeginX at all, so no
	// resume token is ever produced.
	t.Run("Create_is_synchronous", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "agr-1",
			Properties: logicAgreementDesired("AS2", testLogicAgreementAS2Content),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testLogicIntegrationAccountAgreementNativeID, got.ProgressResult.NativeID)
		require.Empty(t, got.ProgressResult.RequestID)

		require.Equal(t, armlogic.AgreementTypeAS2, *sentCreate.Properties.AgreementType)
		require.Equal(t, "conformance-host", *sentCreate.Properties.HostPartner)
		require.Equal(t, "conformance-guest", *sentCreate.Properties.GuestPartner)
		require.Equal(t, "FORMAE-HOST", *sentCreate.Properties.HostIdentity.Value)
		require.Equal(t, "FORMAE-GUEST", *sentCreate.Properties.GuestIdentity.Value)

		// The schema carries only the inner AS2 block; the provider routes it to
		// the member named by agreementType. The other two protocol members must
		// stay nil, or ARM sees a contradictory body.
		require.NotNil(t, sentCreate.Properties.Content.AS2)
		require.Nil(t, sentCreate.Properties.Content.X12)
		require.Nil(t, sentCreate.Properties.Content.Edifact)
		require.Equal(t, "FORMAE-GUEST",
			*sentCreate.Properties.Content.AS2.ReceiveAgreement.SenderBusinessIdentity.Value)
		require.Equal(t, "FORMAE-HOST",
			*sentCreate.Properties.Content.AS2.SendAgreement.SenderBusinessIdentity.Value)
	})

	t.Run("Create_requires_resource_group", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "agr-1", "integrationAccountName": "ia-1"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "resourceGroupName is required")
	})

	t.Run("Create_requires_integration_account", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "agr-1", "resourceGroupName": "rg-1"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "integrationAccountName is required")
	})

	t.Run("Create_requires_agreement_type", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "agr-1", "resourceGroupName": "rg-1", "integrationAccountName": "ia-1",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "agreementType is required")
	})

	// ARM rejects an agreement whose host or guest partner does not already
	// exist, with a message that names neither, so both are mandatory here.
	t.Run("Create_requires_both_partners", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "agr-1", "resourceGroupName": "rg-1", "integrationAccountName": "ia-1",
			"agreementType": "AS2",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "hostPartner is required")

		props, _ = json.Marshal(map[string]any{
			"name": "agr-1", "resourceGroupName": "rg-1", "integrationAccountName": "ia-1",
			"agreementType": "AS2", "hostPartner": "conformance-host",
		})
		_, err = prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "guestPartner is required")
	})

	// ARM matches each partner on BOTH qualifier and value; a half-filled
	// identity produces an opaque 400, so it is rejected here instead.
	t.Run("Create_requires_both_halves_of_each_identity", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "agr-1", "resourceGroupName": "rg-1", "integrationAccountName": "ia-1",
			"agreementType": "AS2", "hostPartner": "conformance-host", "guestPartner": "conformance-guest",
			"hostIdentity": map[string]string{"qualifier": "AS2Identity"},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "hostIdentity.qualifier and hostIdentity.value are required")

		props, _ = json.Marshal(map[string]any{
			"name": "agr-1", "resourceGroupName": "rg-1", "integrationAccountName": "ia-1",
			"agreementType": "AS2", "hostPartner": "conformance-host", "guestPartner": "conformance-guest",
			"hostIdentity":  map[string]string{"qualifier": "AS2Identity", "value": "FORMAE-HOST"},
			"guestIdentity": map[string]string{"value": "FORMAE-GUEST"},
		})
		_, err = prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "guestIdentity.qualifier and guestIdentity.value are required")
	})

	t.Run("Create_requires_content", func(t *testing.T) {
		_, err := prov.Create(context.Background(), &resource.CreateRequest{
			Properties: logicAgreementDesired("AS2", ""),
		})
		require.ErrorContains(t, err, "content is required")
	})

	// Decoding into the SDK's own typed model means a document that is valid JSON
	// but the wrong shape fails before any ARM call rather than as an opaque 400.
	t.Run("Create_rejects_invalid_content_json", func(t *testing.T) {
		_, err := prov.Create(context.Background(), &resource.CreateRequest{
			Properties: logicAgreementDesired("AS2", "{not json"),
		})
		require.ErrorContains(t, err, "content is not valid JSON")
	})

	t.Run("Create_rejects_a_one_directional_content_block", func(t *testing.T) {
		_, err := prov.Create(context.Background(), &resource.CreateRequest{
			Properties: logicAgreementDesired("AS2", `{"receiveAgreement":{}}`),
		})
		require.ErrorContains(t, err, "must carry both receiveAgreement and sendAgreement")
	})

	// An AS2 block handed to an X12 agreement decodes into the wrong model and
	// leaves both directions nil, which is caught rather than sent.
	t.Run("Create_rejects_content_that_does_not_match_the_type", func(t *testing.T) {
		_, err := prov.Create(context.Background(), &resource.CreateRequest{
			Properties: logicAgreementDesired("X12", `{"somethingElse":{}}`),
		})
		require.ErrorContains(t, err, "must carry both receiveAgreement and sendAgreement")
	})

	t.Run("Create_rejects_an_unknown_agreement_type", func(t *testing.T) {
		_, err := prov.Create(context.Background(), &resource.CreateRequest{
			Properties: logicAgreementDesired("RosettaNet", testLogicAgreementAS2Content),
		})
		require.ErrorContains(t, err, "unsupported agreementType")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testLogicIntegrationAccountAgreementNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "agr-1", props["name"])
		// Both parents come from the native ID, not the response body: ARM echoes
		// neither on a child.
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "ia-1", props["integrationAccountName"])
		require.Equal(t, "AS2", props["agreementType"])
		require.Equal(t, "conformance-host", props["hostPartner"])
		require.Equal(t, "conformance-guest", props["guestPartner"])
		require.Equal(t, map[string]any{"qualifier": "AS2Identity", "value": "FORMAE-HOST"}, props["hostIdentity"])
		require.Equal(t, map[string]any{"qualifier": "AS2Identity", "value": "FORMAE-GUEST"}, props["guestIdentity"])
	})

	t.Run("Read_drops_write_only_content_and_service_state", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testLogicIntegrationAccountAgreementNativeID})
		require.NoError(t, err)
		for _, key := range []string{"content", "protocolSettings", "mdnSettings", "filled in by ARM", "metadata", "createdTime", "changedTime"} {
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

	// Update reissues CreateOrUpdate: this API has no PATCH verb for agreements.
	t.Run("Update_reissues_create_or_update", func(t *testing.T) {
		before := createCalls
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testLogicIntegrationAccountAgreementNativeID,
			DesiredProperties: logicAgreementDesired("AS2", testLogicAgreementAS2ContentUpdated),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Empty(t, got.ProgressResult.RequestID)
		require.Equal(t, before+1, createCalls)
		require.Equal(t, armlogic.HashingAlgorithmSHA2256,
			*sentCreate.Properties.Content.AS2.SendAgreement.ProtocolSettings.MdnSettings.MicHashingAlgorithm)
	})

	t.Run("Delete_is_synchronous", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testLogicIntegrationAccountAgreementNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Empty(t, got.ProgressResult.RequestID)
		require.Equal(t, before+1, deleteCalls)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _, _ string, _ *armlogic.IntegrationAccountAgreementsClientDeleteOptions) (armlogic.IntegrationAccountAgreementsClientDeleteResponse, error) {
			return armlogic.IntegrationAccountAgreementsClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testLogicIntegrationAccountAgreementNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_account", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "integrationAccountName": "ia-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testLogicIntegrationAccountAgreementNativeID}, got.NativeIDs)
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
		fake.createOrUpdateFn = func(_ context.Context, _, _, _ string, _ armlogic.IntegrationAccountAgreement, _ *armlogic.IntegrationAccountAgreementsClientCreateOrUpdateOptions) (armlogic.IntegrationAccountAgreementsClientCreateOrUpdateResponse, error) {
			return armlogic.IntegrationAccountAgreementsClientCreateOrUpdateResponse{}, &azcore.ResponseError{StatusCode: 409}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "agr-1", Properties: logicAgreementDesired("AS2", testLogicAgreementAS2Content),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.NotEmpty(t, got.ProgressResult.StatusMessage)
	})
}

func TestLogicIntegrationAccountAgreement_ReadNotFound(t *testing.T) {
	fake := &fakeLogicIntegrationAccountAgreementsAPI{
		getFn: func(_ context.Context, _, _, _ string, _ *armlogic.IntegrationAccountAgreementsClientGetOptions) (armlogic.IntegrationAccountAgreementsClientGetResponse, error) {
			return armlogic.IntegrationAccountAgreementsClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestLogicIntegrationAccountAgreement(fake).Read(context.Background(),
		&resource.ReadRequest{NativeID: testLogicIntegrationAccountAgreementNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeLogicIntegrationAccountAgreementsAPI struct {
	createOrUpdateFn func(ctx context.Context, rgName, accountName, name string, params armlogic.IntegrationAccountAgreement, options *armlogic.IntegrationAccountAgreementsClientCreateOrUpdateOptions) (armlogic.IntegrationAccountAgreementsClientCreateOrUpdateResponse, error)
	getFn            func(ctx context.Context, rgName, accountName, name string, options *armlogic.IntegrationAccountAgreementsClientGetOptions) (armlogic.IntegrationAccountAgreementsClientGetResponse, error)
	deleteFn         func(ctx context.Context, rgName, accountName, name string, options *armlogic.IntegrationAccountAgreementsClientDeleteOptions) (armlogic.IntegrationAccountAgreementsClientDeleteResponse, error)
	newListPagerFn   func(rgName, accountName string, options *armlogic.IntegrationAccountAgreementsClientListOptions) *runtime.Pager[armlogic.IntegrationAccountAgreementsClientListResponse]
}

func (f *fakeLogicIntegrationAccountAgreementsAPI) CreateOrUpdate(ctx context.Context, rgName, accountName, name string, params armlogic.IntegrationAccountAgreement, options *armlogic.IntegrationAccountAgreementsClientCreateOrUpdateOptions) (armlogic.IntegrationAccountAgreementsClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, accountName, name, params, options)
}

func (f *fakeLogicIntegrationAccountAgreementsAPI) Get(ctx context.Context, rgName, accountName, name string, options *armlogic.IntegrationAccountAgreementsClientGetOptions) (armlogic.IntegrationAccountAgreementsClientGetResponse, error) {
	return f.getFn(ctx, rgName, accountName, name, options)
}

func (f *fakeLogicIntegrationAccountAgreementsAPI) Delete(ctx context.Context, rgName, accountName, name string, options *armlogic.IntegrationAccountAgreementsClientDeleteOptions) (armlogic.IntegrationAccountAgreementsClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, accountName, name, options)
}

func (f *fakeLogicIntegrationAccountAgreementsAPI) NewListPager(rgName, accountName string, options *armlogic.IntegrationAccountAgreementsClientListOptions) *runtime.Pager[armlogic.IntegrationAccountAgreementsClientListResponse] {
	return f.newListPagerFn(rgName, accountName, options)
}
