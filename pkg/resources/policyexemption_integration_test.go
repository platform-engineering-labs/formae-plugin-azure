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
	armpolicyv2 "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy/v2"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const (
	testPolicyExemptionScope    = "/subscriptions/sub-1/resourceGroups/rg-1"
	testPolicyExemptionNativeID = testPolicyExemptionScope + "/providers/Microsoft.Authorization/policyExemptions/pe1"
	testExemptedAssignmentID    = testPolicyExemptionScope + "/providers/Microsoft.Authorization/policyAssignments/pa1"
)

type fakePolicyExemptionsAPI struct {
	createFn     func(ctx context.Context, scope, name string, parameters armpolicyv2.Exemption, options *armpolicyv2.ExemptionsClientCreateOrUpdateOptions) (armpolicyv2.ExemptionsClientCreateOrUpdateResponse, error)
	getFn        func(ctx context.Context, scope, name string, options *armpolicyv2.ExemptionsClientGetOptions) (armpolicyv2.ExemptionsClientGetResponse, error)
	deleteFn     func(ctx context.Context, scope, name string, options *armpolicyv2.ExemptionsClientDeleteOptions) (armpolicyv2.ExemptionsClientDeleteResponse, error)
	listPagerFn  func(options *armpolicyv2.ExemptionsClientListOptions) *runtime.Pager[armpolicyv2.ExemptionsClientListResponse]
	listForRGPFn func(rgName string, options *armpolicyv2.ExemptionsClientListForResourceGroupOptions) *runtime.Pager[armpolicyv2.ExemptionsClientListForResourceGroupResponse]
}

func (f *fakePolicyExemptionsAPI) CreateOrUpdate(ctx context.Context, scope, name string, parameters armpolicyv2.Exemption, options *armpolicyv2.ExemptionsClientCreateOrUpdateOptions) (armpolicyv2.ExemptionsClientCreateOrUpdateResponse, error) {
	return f.createFn(ctx, scope, name, parameters, options)
}

func (f *fakePolicyExemptionsAPI) Get(ctx context.Context, scope, name string, options *armpolicyv2.ExemptionsClientGetOptions) (armpolicyv2.ExemptionsClientGetResponse, error) {
	return f.getFn(ctx, scope, name, options)
}

func (f *fakePolicyExemptionsAPI) Delete(ctx context.Context, scope, name string, options *armpolicyv2.ExemptionsClientDeleteOptions) (armpolicyv2.ExemptionsClientDeleteResponse, error) {
	return f.deleteFn(ctx, scope, name, options)
}

func (f *fakePolicyExemptionsAPI) NewListPager(options *armpolicyv2.ExemptionsClientListOptions) *runtime.Pager[armpolicyv2.ExemptionsClientListResponse] {
	return f.listPagerFn(options)
}

func (f *fakePolicyExemptionsAPI) NewListForResourceGroupPager(rgName string, options *armpolicyv2.ExemptionsClientListForResourceGroupOptions) *runtime.Pager[armpolicyv2.ExemptionsClientListForResourceGroupResponse] {
	return f.listForRGPFn(rgName, options)
}

func newTestPolicyExemption(api policyExemptionsAPI) *PolicyExemption {
	return &PolicyExemption{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

func policyExemptionDesired(description, category string, expiresOn any) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":               "pe1",
		"scope":              testPolicyExemptionScope,
		"policyAssignmentId": testExemptedAssignmentID,
		"exemptionCategory":  category,
		"displayName":        "exempt the test group",
		"description":        description,
		"expiresOn":          expiresOn,
	})
	return out
}

func TestPolicyExemption_CRUD(t *testing.T) {
	expiresOn := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	exemptionResult := armpolicyv2.Exemption{
		ID:   to.Ptr(testPolicyExemptionNativeID),
		Name: to.Ptr("pe1"),
		Properties: &armpolicyv2.ExemptionProperties{
			PolicyAssignmentID: to.Ptr(testExemptedAssignmentID),
			ExemptionCategory:  to.Ptr(armpolicyv2.ExemptionCategoryWaiver),
			DisplayName:        to.Ptr("exempt the test group"),
			Description:        to.Ptr("conformance test exemption"),
			ExpiresOn:          to.Ptr(expiresOn),
			// Unmodelled configuration plus the service's own view.
			Metadata: map[string]any{"createdBy": "unmodelled-metadata"},
			ResourceSelectors: []*armpolicyv2.ResourceSelector{{
				Name: to.Ptr("unmodelled-selector"),
			}},
		},
		SystemData: &armpolicyv2.SystemData{CreatedBy: to.Ptr("someone")},
	}

	var sentScope, sentName string
	var sent armpolicyv2.Exemption
	writeCalls := 0
	deleteCalls := 0
	fake := &fakePolicyExemptionsAPI{
		createFn: func(_ context.Context, scope, name string, parameters armpolicyv2.Exemption, _ *armpolicyv2.ExemptionsClientCreateOrUpdateOptions) (armpolicyv2.ExemptionsClientCreateOrUpdateResponse, error) {
			sentScope, sentName, sent = scope, name, parameters
			writeCalls++
			return armpolicyv2.ExemptionsClientCreateOrUpdateResponse{Exemption: exemptionResult}, nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armpolicyv2.ExemptionsClientGetOptions) (armpolicyv2.ExemptionsClientGetResponse, error) {
			return armpolicyv2.ExemptionsClientGetResponse{Exemption: exemptionResult}, nil
		},
		deleteFn: func(_ context.Context, scope, name string, _ *armpolicyv2.ExemptionsClientDeleteOptions) (armpolicyv2.ExemptionsClientDeleteResponse, error) {
			sentScope, sentName = scope, name
			deleteCalls++
			return armpolicyv2.ExemptionsClientDeleteResponse{}, nil
		},
		listPagerFn: func(_ *armpolicyv2.ExemptionsClientListOptions) *runtime.Pager[armpolicyv2.ExemptionsClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armpolicyv2.ExemptionsClientListResponse]{
				More: func(_ armpolicyv2.ExemptionsClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armpolicyv2.ExemptionsClientListResponse) (armpolicyv2.ExemptionsClientListResponse, error) {
					return armpolicyv2.ExemptionsClientListResponse{
						ExemptionListResult: armpolicyv2.ExemptionListResult{
							Value: []*armpolicyv2.Exemption{
								{ID: to.Ptr(testPolicyExemptionNativeID)},
								{ID: to.Ptr("/subscriptions/sub-1/providers/Microsoft.Authorization/policyExemptions/pe2")},
								// A nil entry must not panic the walk.
								nil,
							},
						},
					}, nil
				},
			})
		},
		listForRGPFn: func(rgName string, _ *armpolicyv2.ExemptionsClientListForResourceGroupOptions) *runtime.Pager[armpolicyv2.ExemptionsClientListForResourceGroupResponse] {
			require.Equal(t, "rg-1", rgName)
			return runtime.NewPager(runtime.PagingHandler[armpolicyv2.ExemptionsClientListForResourceGroupResponse]{
				More: func(_ armpolicyv2.ExemptionsClientListForResourceGroupResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armpolicyv2.ExemptionsClientListForResourceGroupResponse) (armpolicyv2.ExemptionsClientListForResourceGroupResponse, error) {
					return armpolicyv2.ExemptionsClientListForResourceGroupResponse{
						ExemptionListResult: armpolicyv2.ExemptionListResult{
							Value: []*armpolicyv2.Exemption{{ID: to.Ptr(testPolicyExemptionNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestPolicyExemption(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "pe1", Properties: policyExemptionDesired("conformance test exemption", "Waiver", "2030-01-01T00:00:00Z"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testPolicyExemptionNativeID, got.ProgressResult.NativeID)

		// The scope addresses the resource; it is not part of the body.
		require.Equal(t, testPolicyExemptionScope, sentScope)
		require.Equal(t, "pe1", sentName)
		require.Equal(t, testExemptedAssignmentID, *sent.Properties.PolicyAssignmentID)
		require.Equal(t, armpolicyv2.ExemptionCategoryWaiver, *sent.Properties.ExemptionCategory)
		require.Equal(t, expiresOn, *sent.Properties.ExpiresOn)
	})

	t.Run("Create_requires_assignment_scope_and_category", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "pe1", "exemptionCategory": "Waiver"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "scope is required")

		props, _ = json.Marshal(map[string]any{"name": "pe1", "scope": testPolicyExemptionScope, "exemptionCategory": "Waiver"})
		_, err = prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "policyAssignmentId is required")

		props, _ = json.Marshal(map[string]any{"name": "pe1", "scope": testPolicyExemptionScope, "policyAssignmentId": testExemptedAssignmentID})
		_, err = prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "exemptionCategory is required")
	})

	t.Run("Create_rejects_an_unparsable_expiry", func(t *testing.T) {
		_, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "pe1", Properties: policyExemptionDesired("x", "Waiver", "not-a-timestamp"),
		})
		require.ErrorContains(t, err, "expiresOn is not a valid ISO 8601 timestamp")
	})

	// An exemption that declares no expiry or reference ids must not carry empties.
	t.Run("Create_omits_unset_optionals", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "pe1", "scope": testPolicyExemptionScope,
			"policyAssignmentId": testExemptedAssignmentID,
			"exemptionCategory":  "Mitigated",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.Nil(t, sent.Properties.ExpiresOn)
		require.Nil(t, sent.Properties.PolicyDefinitionReferenceIDs)
		require.Nil(t, sent.Properties.AssignmentScopeValidation)
		require.Nil(t, sent.Properties.DisplayName)
	})

	t.Run("Create_surfaces_the_provider_error", func(t *testing.T) {
		fake.createFn = func(_ context.Context, _, _ string, _ armpolicyv2.Exemption, _ *armpolicyv2.ExemptionsClientCreateOrUpdateOptions) (armpolicyv2.ExemptionsClientCreateOrUpdateResponse, error) {
			return armpolicyv2.ExemptionsClientCreateOrUpdateResponse{}, &azcore.ResponseError{StatusCode: 400, ErrorCode: "PolicyExemptionScopeInvalid"}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "pe1", Properties: policyExemptionDesired("x", "Waiver", nil),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.Equal(t, resource.OperationErrorCodeInvalidRequest, got.ProgressResult.ErrorCode)
		require.Contains(t, got.ProgressResult.StatusMessage, "PolicyExemptionScopeInvalid")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testPolicyExemptionNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "pe1", props["name"])
		// The scope comes off the native ID, not from the body's own echo.
		require.Equal(t, testPolicyExemptionScope, props["scope"])
		require.Equal(t, testExemptedAssignmentID, props["policyAssignmentId"])
		require.Equal(t, "Waiver", props["exemptionCategory"])
		require.Equal(t, "conformance test exemption", props["description"])
		// UTC RFC 3339, so an offset ARM chooses does not read as drift.
		require.Equal(t, "2030-01-01T00:00:00Z", props["expiresOn"])
	})

	t.Run("Read_drops_unmodelled_and_service_state", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testPolicyExemptionNativeID})
		require.NoError(t, err)
		for _, key := range []string{
			"metadata", "unmodelled-metadata", "resourceSelectors", "unmodelled-selector", "systemData",
		} {
			require.NotContains(t, got.Properties, key)
		}
	})

	t.Run("IDParts_handles_any_scope_and_casing", func(t *testing.T) {
		scope, name, err := policyExemptionIDParts(testPolicyExemptionNativeID)
		require.NoError(t, err)
		require.Equal(t, testPolicyExemptionScope, scope)
		require.Equal(t, "pe1", name)

		scope, name, err = policyExemptionIDParts("/providers/Microsoft.Management/managementGroups/mg-1/providers/microsoft.authorization/policyexemptions/pe3")
		require.NoError(t, err)
		require.Equal(t, "/providers/Microsoft.Management/managementGroups/mg-1", scope)
		require.Equal(t, "pe3", name)

		_, _, err = policyExemptionIDParts(testPolicyExemptionScope)
		require.ErrorContains(t, err, "not a policy exemption resource ID")
	})

	// The PATCH verb reaches only two fields, so a full PUT is the update path.
	t.Run("Update_reissues_create_or_update", func(t *testing.T) {
		fake.createFn = func(_ context.Context, scope, name string, parameters armpolicyv2.Exemption, _ *armpolicyv2.ExemptionsClientCreateOrUpdateOptions) (armpolicyv2.ExemptionsClientCreateOrUpdateResponse, error) {
			sentScope, sentName, sent = scope, name, parameters
			writeCalls++
			return armpolicyv2.ExemptionsClientCreateOrUpdateResponse{Exemption: exemptionResult}, nil
		}
		before := writeCalls
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testPolicyExemptionNativeID,
			DesiredProperties: policyExemptionDesired("conformance test exemption, revised", "Mitigated", "2031-06-30T12:00:00Z"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, writeCalls)
		require.Equal(t, testPolicyExemptionScope, sentScope)
		require.Equal(t, "pe1", sentName)
		require.Equal(t, armpolicyv2.ExemptionCategoryMitigated, *sent.Properties.ExemptionCategory)
		require.Equal(t, "conformance test exemption, revised", *sent.Properties.Description)
	})

	t.Run("Delete", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testPolicyExemptionNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
		require.Equal(t, testPolicyExemptionScope, sentScope)
		require.Equal(t, "pe1", sentName)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _ string, _ *armpolicyv2.ExemptionsClientDeleteOptions) (armpolicyv2.ExemptionsClientDeleteResponse, error) {
			return armpolicyv2.ExemptionsClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testPolicyExemptionNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Status_is_always_success", func(t *testing.T) {
		got, err := prov.Status(context.Background(), &resource.StatusRequest{RequestID: "whatever"})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_uses_resource_group_pager_for_group_scope", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"scope": testPolicyExemptionScope},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testPolicyExemptionNativeID}, got.NativeIDs)
	})

	t.Run("List_without_scope_is_subscription_wide", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 2)
	})

	t.Run("Read_NotFound", func(t *testing.T) {
		fake.getFn = func(_ context.Context, _, _ string, _ *armpolicyv2.ExemptionsClientGetOptions) (armpolicyv2.ExemptionsClientGetResponse, error) {
			return armpolicyv2.ExemptionsClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testPolicyExemptionNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
	})
}
