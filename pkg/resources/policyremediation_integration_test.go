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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/policyinsights/armpolicyinsights"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const (
	testRemediationScope     = "/subscriptions/sub-1/resourceGroups/rg-1"
	testRemediationNativeID  = testRemediationScope + "/providers/Microsoft.PolicyInsights/remediations/rem1"
	testRemediatedAssignment = testRemediationScope + "/providers/Microsoft.Authorization/policyAssignments/pa1"
)

type fakePolicyRemediationsAPI struct {
	createFn func(ctx context.Context, resourceID, name string, parameters armpolicyinsights.Remediation, options *armpolicyinsights.RemediationsClientCreateOrUpdateAtResourceOptions) (armpolicyinsights.RemediationsClientCreateOrUpdateAtResourceResponse, error)
	getFn    func(ctx context.Context, resourceID, name string, options *armpolicyinsights.RemediationsClientGetAtResourceOptions) (armpolicyinsights.RemediationsClientGetAtResourceResponse, error)
	deleteFn func(ctx context.Context, resourceID, name string, options *armpolicyinsights.RemediationsClientDeleteAtResourceOptions) (armpolicyinsights.RemediationsClientDeleteAtResourceResponse, error)
	cancelFn func(ctx context.Context, resourceID, name string, options *armpolicyinsights.RemediationsClientCancelAtResourceOptions) (armpolicyinsights.RemediationsClientCancelAtResourceResponse, error)

	cancelCalls int
	deleteCalls int
}

func (f *fakePolicyRemediationsAPI) CreateOrUpdateAtResource(ctx context.Context, resourceID, name string, parameters armpolicyinsights.Remediation, options *armpolicyinsights.RemediationsClientCreateOrUpdateAtResourceOptions) (armpolicyinsights.RemediationsClientCreateOrUpdateAtResourceResponse, error) {
	return f.createFn(ctx, resourceID, name, parameters, options)
}

func (f *fakePolicyRemediationsAPI) GetAtResource(ctx context.Context, resourceID, name string, options *armpolicyinsights.RemediationsClientGetAtResourceOptions) (armpolicyinsights.RemediationsClientGetAtResourceResponse, error) {
	return f.getFn(ctx, resourceID, name, options)
}

func (f *fakePolicyRemediationsAPI) DeleteAtResource(ctx context.Context, resourceID, name string, options *armpolicyinsights.RemediationsClientDeleteAtResourceOptions) (armpolicyinsights.RemediationsClientDeleteAtResourceResponse, error) {
	f.deleteCalls++
	return f.deleteFn(ctx, resourceID, name, options)
}

func (f *fakePolicyRemediationsAPI) CancelAtResource(ctx context.Context, resourceID, name string, options *armpolicyinsights.RemediationsClientCancelAtResourceOptions) (armpolicyinsights.RemediationsClientCancelAtResourceResponse, error) {
	f.cancelCalls++
	if f.cancelFn != nil {
		return f.cancelFn(ctx, resourceID, name, options)
	}
	return armpolicyinsights.RemediationsClientCancelAtResourceResponse{}, nil
}

func (f *fakePolicyRemediationsAPI) NewListForResourcePager(resourceID string, _ *armpolicyinsights.RemediationsClientListForResourceOptions) *runtime.Pager[armpolicyinsights.RemediationsClientListForResourceResponse] {
	return runtime.NewPager(runtime.PagingHandler[armpolicyinsights.RemediationsClientListForResourceResponse]{
		More: func(_ armpolicyinsights.RemediationsClientListForResourceResponse) bool { return false },
		Fetcher: func(_ context.Context, _ *armpolicyinsights.RemediationsClientListForResourceResponse) (armpolicyinsights.RemediationsClientListForResourceResponse, error) {
			return armpolicyinsights.RemediationsClientListForResourceResponse{
				RemediationListResult: armpolicyinsights.RemediationListResult{
					Value: []*armpolicyinsights.Remediation{{ID: to.Ptr(testRemediationNativeID)}},
				},
			}, nil
		},
	})
}

func (f *fakePolicyRemediationsAPI) NewListForSubscriptionPager(_ *armpolicyinsights.RemediationsClientListForSubscriptionOptions) *runtime.Pager[armpolicyinsights.RemediationsClientListForSubscriptionResponse] {
	return runtime.NewPager(runtime.PagingHandler[armpolicyinsights.RemediationsClientListForSubscriptionResponse]{
		More: func(_ armpolicyinsights.RemediationsClientListForSubscriptionResponse) bool { return false },
		Fetcher: func(_ context.Context, _ *armpolicyinsights.RemediationsClientListForSubscriptionResponse) (armpolicyinsights.RemediationsClientListForSubscriptionResponse, error) {
			return armpolicyinsights.RemediationsClientListForSubscriptionResponse{
				RemediationListResult: armpolicyinsights.RemediationListResult{
					Value: []*armpolicyinsights.Remediation{
						{ID: to.Ptr(testRemediationNativeID)},
						{ID: to.Ptr("/subscriptions/sub-1/providers/Microsoft.PolicyInsights/remediations/rem2")},
						// A nil entry must not panic the walk.
						nil,
					},
				},
			}, nil
		},
	})
}

func newTestPolicyRemediation(api policyRemediationsAPI) *PolicyRemediation {
	return &PolicyRemediation{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

func remediationDesired(mode any, locations []any, resourceIDs []any) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":                       "rem1",
		"scope":                      testRemediationScope,
		"policyAssignmentId":         testRemediatedAssignment,
		"resourceDiscoveryMode":      mode,
		"parallelDeployments":        10,
		"resourceCount":              100,
		"failureThresholdPercentage": 0.5,
		"filterLocations":            locations,
		"filterResourceIds":          resourceIDs,
	})
	return out
}

func remediationResult(provisioningState string) armpolicyinsights.Remediation {
	return armpolicyinsights.Remediation{
		ID:   to.Ptr(testRemediationNativeID),
		Name: to.Ptr("rem1"),
		Properties: &armpolicyinsights.RemediationProperties{
			PolicyAssignmentID:    to.Ptr(testRemediatedAssignment),
			ResourceDiscoveryMode: to.Ptr(armpolicyinsights.ResourceDiscoveryModeExistingNonCompliant),
			ParallelDeployments:   to.Ptr(int32(10)),
			ResourceCount:         to.Ptr(int32(100)),
			FailureThreshold:      &armpolicyinsights.RemediationPropertiesFailureThreshold{Percentage: to.Ptr(float32(0.5))},
			Filters:               &armpolicyinsights.RemediationFilters{Locations: []*string{to.Ptr("eastus")}},
			// The running task's own state, which changes without anyone asking.
			ProvisioningState: to.Ptr(provisioningState),
			CorrelationID:     to.Ptr("correlation-1"),
			CreatedOn:         to.Ptr(time.Now()),
			DeploymentStatus:  &armpolicyinsights.RemediationDeploymentSummary{TotalDeployments: to.Ptr(int32(3))},
			StatusMessage:     to.Ptr("in flight"),
		},
	}
}

func newRemediationFake(provisioningState string) *fakePolicyRemediationsAPI {
	result := remediationResult(provisioningState)
	return &fakePolicyRemediationsAPI{
		createFn: func(_ context.Context, _, _ string, _ armpolicyinsights.Remediation, _ *armpolicyinsights.RemediationsClientCreateOrUpdateAtResourceOptions) (armpolicyinsights.RemediationsClientCreateOrUpdateAtResourceResponse, error) {
			return armpolicyinsights.RemediationsClientCreateOrUpdateAtResourceResponse{Remediation: result}, nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armpolicyinsights.RemediationsClientGetAtResourceOptions) (armpolicyinsights.RemediationsClientGetAtResourceResponse, error) {
			return armpolicyinsights.RemediationsClientGetAtResourceResponse{Remediation: result}, nil
		},
		deleteFn: func(_ context.Context, _, _ string, _ *armpolicyinsights.RemediationsClientDeleteAtResourceOptions) (armpolicyinsights.RemediationsClientDeleteAtResourceResponse, error) {
			return armpolicyinsights.RemediationsClientDeleteAtResourceResponse{Remediation: result}, nil
		},
	}
}

func TestPolicyRemediation_CRUD(t *testing.T) {
	fake := newRemediationFake("Succeeded")
	var sentScope, sentName string
	var sent armpolicyinsights.Remediation
	writeCalls := 0
	result := remediationResult("Succeeded")
	fake.createFn = func(_ context.Context, resourceID, name string, parameters armpolicyinsights.Remediation, _ *armpolicyinsights.RemediationsClientCreateOrUpdateAtResourceOptions) (armpolicyinsights.RemediationsClientCreateOrUpdateAtResourceResponse, error) {
		sentScope, sentName, sent = resourceID, name, parameters
		writeCalls++
		return armpolicyinsights.RemediationsClientCreateOrUpdateAtResourceResponse{Remediation: result}, nil
	}
	prov := newTestPolicyRemediation(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "rem1", Properties: remediationDesired("ExistingNonCompliant", []any{"eastus"}, nil),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testRemediationNativeID, got.ProgressResult.NativeID)

		// The scope addresses the resource; the AtResource verb takes it whole.
		require.Equal(t, testRemediationScope, sentScope)
		require.Equal(t, "rem1", sentName)
		require.Equal(t, testRemediatedAssignment, *sent.Properties.PolicyAssignmentID)
		require.Equal(t, armpolicyinsights.ResourceDiscoveryModeExistingNonCompliant, *sent.Properties.ResourceDiscoveryMode)
		require.Equal(t, int32(10), *sent.Properties.ParallelDeployments)
		require.Equal(t, int32(100), *sent.Properties.ResourceCount)
		// The flat schema fields are re-nested into ARM's own objects.
		require.Equal(t, float32(0.5), *sent.Properties.FailureThreshold.Percentage)
		require.Equal(t, "eastus", *sent.Properties.Filters.Locations[0])
	})

	t.Run("Create_requires_scope_and_assignment", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "rem1", "policyAssignmentId": testRemediatedAssignment})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "scope is required")

		props, _ = json.Marshal(map[string]any{"name": "rem1", "scope": testRemediationScope})
		_, err = prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "policyAssignmentId is required")
	})

	// ARM reports this at PUT time with a message that never names the mode.
	t.Run("Create_rejects_resource_id_filter_with_re_evaluate", func(t *testing.T) {
		_, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "rem1", Properties: remediationDesired("ReEvaluateCompliance", nil, []any{"/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Storage/storageAccounts/sa1"}),
		})
		require.ErrorContains(t, err, "filterResourceIds cannot be used with resourceDiscoveryMode ReEvaluateCompliance")
	})

	t.Run("Create_omits_unset_optionals", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "rem1", "scope": testRemediationScope, "policyAssignmentId": testRemediatedAssignment,
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.Nil(t, sent.Properties.ResourceDiscoveryMode)
		require.Nil(t, sent.Properties.Filters)
		require.Nil(t, sent.Properties.FailureThreshold)
		require.Nil(t, sent.Properties.ParallelDeployments)
	})

	t.Run("Create_surfaces_the_provider_error", func(t *testing.T) {
		failing := newRemediationFake("Succeeded")
		failing.createFn = func(_ context.Context, _, _ string, _ armpolicyinsights.Remediation, _ *armpolicyinsights.RemediationsClientCreateOrUpdateAtResourceOptions) (armpolicyinsights.RemediationsClientCreateOrUpdateAtResourceResponse, error) {
			return armpolicyinsights.RemediationsClientCreateOrUpdateAtResourceResponse{}, &azcore.ResponseError{StatusCode: 400, ErrorCode: "InvalidCreateRemediationRequest"}
		}
		got, err := newTestPolicyRemediation(failing).Create(context.Background(), &resource.CreateRequest{
			Label: "rem1", Properties: remediationDesired(nil, nil, nil),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.Equal(t, resource.OperationErrorCodeInvalidRequest, got.ProgressResult.ErrorCode)
		require.Contains(t, got.ProgressResult.StatusMessage, "InvalidCreateRemediationRequest")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testRemediationNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "rem1", props["name"])
		require.Equal(t, testRemediationScope, props["scope"])
		require.Equal(t, testRemediatedAssignment, props["policyAssignmentId"])
		require.Equal(t, "ExistingNonCompliant", props["resourceDiscoveryMode"])
		require.Equal(t, float64(10), props["parallelDeployments"])
		require.Equal(t, float64(100), props["resourceCount"])
		require.Equal(t, 0.5, props["failureThresholdPercentage"])
		require.Equal(t, []any{"eastus"}, props["filterLocations"])
		// Not set on the way in, so it must not come back as an empty list.
		require.NotContains(t, props, "filterResourceIds")
	})

	// The task's own progress changes under the resource; reading it back as
	// desired state would make every sync report drift.
	t.Run("Read_drops_task_state", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testRemediationNativeID})
		require.NoError(t, err)
		for _, key := range []string{
			"provisioningState", "correlationId", "createdOn", "lastUpdatedOn",
			"deploymentStatus", "statusMessage",
		} {
			require.NotContains(t, got.Properties, key)
		}
	})

	t.Run("IDParts_handles_any_scope_and_casing", func(t *testing.T) {
		scope, name, err := policyRemediationIDParts(testRemediationNativeID)
		require.NoError(t, err)
		require.Equal(t, testRemediationScope, scope)
		require.Equal(t, "rem1", name)

		scope, name, err = policyRemediationIDParts("/providers/Microsoft.Management/managementGroups/mg-1/providers/microsoft.policyinsights/remediations/rem3")
		require.NoError(t, err)
		require.Equal(t, "/providers/Microsoft.Management/managementGroups/mg-1", scope)
		require.Equal(t, "rem3", name)

		_, _, err = policyRemediationIDParts(testRemediationScope)
		require.ErrorContains(t, err, "not a policy remediation resource ID")
	})

	t.Run("Update_reissues_create_or_update", func(t *testing.T) {
		before := writeCalls
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testRemediationNativeID,
			DesiredProperties: remediationDesired("ExistingNonCompliant", []any{"eastus", "westus"}, nil),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, writeCalls)
		require.Len(t, sent.Properties.Filters.Locations, 2)
	})

	t.Run("Status_is_always_success", func(t *testing.T) {
		got, err := prov.Status(context.Background(), &resource.StatusRequest{RequestID: "whatever"})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_at_scope", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"scope": testRemediationScope},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testRemediationNativeID}, got.NativeIDs)
	})

	t.Run("List_without_scope_is_subscription_wide", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 2)
	})

	t.Run("Read_NotFound", func(t *testing.T) {
		fake.getFn = func(_ context.Context, _, _ string, _ *armpolicyinsights.RemediationsClientGetAtResourceOptions) (armpolicyinsights.RemediationsClientGetAtResourceResponse, error) {
			return armpolicyinsights.RemediationsClientGetAtResourceResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testRemediationNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
	})
}

// ARM refuses to delete a remediation that is still evaluating, so a running task
// is cancelled first.
func TestPolicyRemediation_Delete(t *testing.T) {
	t.Run("terminal_task_is_deleted_without_a_cancel", func(t *testing.T) {
		fake := newRemediationFake("Succeeded")
		got, err := newTestPolicyRemediation(fake).Delete(context.Background(), &resource.DeleteRequest{NativeID: testRemediationNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Zero(t, fake.cancelCalls)
		require.Equal(t, 1, fake.deleteCalls)
	})

	t.Run("running_task_is_cancelled_first", func(t *testing.T) {
		fake := newRemediationFake("Evaluating")
		got, err := newTestPolicyRemediation(fake).Delete(context.Background(), &resource.DeleteRequest{NativeID: testRemediationNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, 1, fake.cancelCalls)
	})

	t.Run("already_gone_is_success", func(t *testing.T) {
		fake := newRemediationFake("Succeeded")
		fake.getFn = func(_ context.Context, _, _ string, _ *armpolicyinsights.RemediationsClientGetAtResourceOptions) (armpolicyinsights.RemediationsClientGetAtResourceResponse, error) {
			return armpolicyinsights.RemediationsClientGetAtResourceResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := newTestPolicyRemediation(fake).Delete(context.Background(), &resource.DeleteRequest{NativeID: testRemediationNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Zero(t, fake.deleteCalls)
	})

	t.Run("a_non_retryable_delete_error_fails_at_once", func(t *testing.T) {
		fake := newRemediationFake("Succeeded")
		fake.deleteFn = func(_ context.Context, _, _ string, _ *armpolicyinsights.RemediationsClientDeleteAtResourceOptions) (armpolicyinsights.RemediationsClientDeleteAtResourceResponse, error) {
			return armpolicyinsights.RemediationsClientDeleteAtResourceResponse{}, &azcore.ResponseError{StatusCode: 403, ErrorCode: "AuthorizationFailed"}
		}
		got, err := newTestPolicyRemediation(fake).Delete(context.Background(), &resource.DeleteRequest{NativeID: testRemediationNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.Equal(t, resource.OperationErrorCodeAccessDenied, got.ProgressResult.ErrorCode)
		require.Contains(t, got.ProgressResult.StatusMessage, "AuthorizationFailed")
		require.Equal(t, 1, fake.deleteCalls)
	})

	t.Run("a_conflict_is_retried_until_the_context_gives_up", func(t *testing.T) {
		fake := newRemediationFake("Succeeded")
		fake.deleteFn = func(_ context.Context, _, _ string, _ *armpolicyinsights.RemediationsClientDeleteAtResourceOptions) (armpolicyinsights.RemediationsClientDeleteAtResourceResponse, error) {
			return armpolicyinsights.RemediationsClientDeleteAtResourceResponse{}, &azcore.ResponseError{StatusCode: 409, ErrorCode: "RemediationInProgress"}
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		got, err := newTestPolicyRemediation(fake).Delete(ctx, &resource.DeleteRequest{NativeID: testRemediationNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.Equal(t, 1, fake.deleteCalls)
	})
}
