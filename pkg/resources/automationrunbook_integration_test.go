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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/automation/armautomation"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testAutomationRunbookNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Automation/automationAccounts/aa-1/runbooks/rb-1"

func newTestAutomationRunbook(api automationRunbookAPI) *AutomationRunbook {
	return &AutomationRunbook{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func automationRunbookDesired(description string, logVerbose bool, extra map[string]any) []byte {
	props := map[string]any{
		"name":                  "rb-1",
		"resourceGroupName":     "rg-1",
		"automationAccountName": "aa-1",
		"location":              "eastus",
		"runbookType":           "PowerShell",
		"logVerbose":            logVerbose,
		"logProgress":           false,
		"description":           description,
	}
	for k, v := range extra {
		props[k] = v
	}
	out, _ := json.Marshal(props)
	return out
}

func TestAutomationRunbook_CRUD(t *testing.T) {
	rbResult := armautomation.Runbook{
		ID:       to.Ptr(testAutomationRunbookNativeID),
		Name:     to.Ptr("rb-1"),
		Location: to.Ptr("East US"),
		Properties: &armautomation.RunbookProperties{
			RunbookType:       to.Ptr(armautomation.RunbookTypeEnumPowerShell),
			LogVerbose:        to.Ptr(false),
			LogProgress:       to.Ptr(false),
			LogActivityTrace:  to.Ptr(int32(1)),
			Description:       to.Ptr("Conformance runbook"),
			State:             to.Ptr(armautomation.RunbookStatePublished),
			ProvisioningState: to.Ptr("Succeeded"),
			JobCount:          to.Ptr(int32(3)),
			LastModifiedBy:    to.Ptr("someone@example.com"),
			CreationTime:      to.Ptr(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)),
			LastModifiedTime:  to.Ptr(time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)),
		},
		Tags: map[string]*string{"env": to.Ptr("conformance")},
	}

	var sentCreate armautomation.RunbookCreateOrUpdateParameters
	var sentUpdate armautomation.RunbookUpdateParameters
	deleteCalls := 0
	fake := &fakeAutomationRunbookAPI{
		createOrUpdateFn: func(_ context.Context, rgName, accountName, name string, params armautomation.RunbookCreateOrUpdateParameters, _ *armautomation.RunbookClientCreateOrUpdateOptions) (armautomation.RunbookClientCreateOrUpdateResponse, error) {
			require.Equal(t, "rg-1", rgName)
			require.Equal(t, "aa-1", accountName)
			require.Equal(t, "rb-1", name)
			sentCreate = params
			return armautomation.RunbookClientCreateOrUpdateResponse{Runbook: rbResult}, nil
		},
		getFn: func(context.Context, string, string, string, *armautomation.RunbookClientGetOptions) (armautomation.RunbookClientGetResponse, error) {
			return armautomation.RunbookClientGetResponse{Runbook: rbResult}, nil
		},
		updateFn: func(_ context.Context, _, _, _ string, params armautomation.RunbookUpdateParameters, _ *armautomation.RunbookClientUpdateOptions) (armautomation.RunbookClientUpdateResponse, error) {
			sentUpdate = params
			return armautomation.RunbookClientUpdateResponse{Runbook: rbResult}, nil
		},
		deleteFn: func(context.Context, string, string, string, *armautomation.RunbookClientDeleteOptions) (armautomation.RunbookClientDeleteResponse, error) {
			deleteCalls++
			return armautomation.RunbookClientDeleteResponse{}, nil
		},
		newListByAutomationAccountPagerFn: func(rgName, accountName string, _ *armautomation.RunbookClientListByAutomationAccountOptions) *runtime.Pager[armautomation.RunbookClientListByAutomationAccountResponse] {
			require.Equal(t, "rg-1", rgName)
			require.Equal(t, "aa-1", accountName)
			return runtime.NewPager(runtime.PagingHandler[armautomation.RunbookClientListByAutomationAccountResponse]{
				More: func(armautomation.RunbookClientListByAutomationAccountResponse) bool { return false },
				Fetcher: func(context.Context, *armautomation.RunbookClientListByAutomationAccountResponse) (armautomation.RunbookClientListByAutomationAccountResponse, error) {
					return armautomation.RunbookClientListByAutomationAccountResponse{
						RunbookListResult: armautomation.RunbookListResult{
							Value: []*armautomation.Runbook{{ID: to.Ptr(testAutomationRunbookNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestAutomationRunbook(fake)

	// ARM rejects a runbook that carries neither a publishContentLink nor a
	// draft, so an omitted content link must become an empty draft rather than
	// nothing at all.
	t.Run("Create_without_content_link_sends_empty_draft", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "rb-1",
			Properties: automationRunbookDesired("Conformance runbook", false, nil),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testAutomationRunbookNativeID, got.ProgressResult.NativeID)
		require.Empty(t, got.ProgressResult.RequestID)

		require.NotNil(t, sentCreate.Properties.Draft)
		require.Nil(t, sentCreate.Properties.PublishContentLink)
		require.Equal(t, armautomation.RunbookTypeEnumPowerShell, *sentCreate.Properties.RunbookType)
		require.False(t, *sentCreate.Properties.LogVerbose)
	})

	t.Run("Create_with_content_link_publishes_and_sends_no_draft", func(t *testing.T) {
		_, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "rb-1",
			Properties: automationRunbookDesired("Conformance runbook", false, map[string]any{
				"publishContentLinkUri":     "https://example.invalid/runbook.ps1",
				"publishContentLinkVersion": "1.0.0",
			}),
		})
		require.NoError(t, err)
		require.Nil(t, sentCreate.Properties.Draft)
		require.Equal(t, "https://example.invalid/runbook.ps1", *sentCreate.Properties.PublishContentLink.URI)
		require.Equal(t, "1.0.0", *sentCreate.Properties.PublishContentLink.Version)
		// The hash is deliberately not modelled: ARM only verifies it.
		require.Nil(t, sentCreate.Properties.PublishContentLink.ContentHash)
	})

	// An opaque write-only property that reaches the plugin as the wrapper object
	// rather than as unwrapped plaintext must still yield the URI, not fail the
	// whole unmarshal.
	t.Run("Create_accepts_a_wrapped_content_link", func(t *testing.T) {
		_, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "rb-1",
			Properties: automationRunbookDesired("Conformance runbook", false, map[string]any{
				"publishContentLinkUri": map[string]any{"$value": "https://example.invalid/wrapped.ps1"},
			}),
		})
		require.NoError(t, err)
		require.Equal(t, "https://example.invalid/wrapped.ps1", *sentCreate.Properties.PublishContentLink.URI)
	})

	t.Run("Create_requires_parents_and_type", func(t *testing.T) {
		for _, tc := range []struct {
			drop string
			want string
		}{
			{"resourceGroupName", "resourceGroupName is required"},
			{"automationAccountName", "automationAccountName is required"},
			{"location", "location is required"},
			{"runbookType", "runbookType is required"},
		} {
			var props map[string]any
			require.NoError(t, json.Unmarshal(automationRunbookDesired("d", false, nil), &props))
			delete(props, tc.drop)
			raw, _ := json.Marshal(props)
			_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: raw})
			require.ErrorContains(t, err, tc.want)
		}
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testAutomationRunbookNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "rb-1", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		// Both parents come from the native ID, not the response body.
		require.Equal(t, "aa-1", props["automationAccountName"])
		require.Equal(t, "eastus", props["location"])
		require.Equal(t, "PowerShell", props["runbookType"])
		require.Equal(t, false, props["logVerbose"])
		require.Equal(t, false, props["logProgress"])
		require.Equal(t, "Conformance runbook", props["description"])
	})

	// jobCount climbs with every run, state and provisioningState are service
	// state, logActivityTrace is not modelled, and the content link is
	// write-only: all of them would read back as drift.
	t.Run("Read_drops_service_state", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testAutomationRunbookNativeID})
		require.NoError(t, err)
		for _, key := range []string{"state", "provisioningState", "jobCount", "logActivityTrace",
			"publishContentLink", "lastModifiedBy", "creationTime", "lastModifiedTime"} {
			require.NotContains(t, got.Properties, key)
		}
	})

	// An empty description must be left out of the body rather than sent as "",
	// which is also why the read path drops an empty one.
	t.Run("Read_drops_empty_description", func(t *testing.T) {
		fake.getFn = func(context.Context, string, string, string, *armautomation.RunbookClientGetOptions) (armautomation.RunbookClientGetResponse, error) {
			empty := rbResult
			propsCopy := *rbResult.Properties
			propsCopy.Description = to.Ptr("")
			empty.Properties = &propsCopy
			return armautomation.RunbookClientGetResponse{Runbook: empty}, nil
		}
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testAutomationRunbookNativeID})
		require.NoError(t, err)
		require.NotContains(t, got.Properties, "description")
		fake.getFn = func(context.Context, string, string, string, *armautomation.RunbookClientGetOptions) (armautomation.RunbookClientGetResponse, error) {
			return armautomation.RunbookClientGetResponse{Runbook: rbResult}, nil
		}
	})

	// RunbookUpdateParameters reaches only the description, the log flags and the
	// tags: the type and the content link are createOnly.
	t.Run("Update_patches_logs_and_description", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testAutomationRunbookNativeID,
			DesiredProperties: automationRunbookDesired("Conformance runbook updated", true, nil),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.True(t, *sentUpdate.Properties.LogVerbose)
		require.Equal(t, "Conformance runbook updated", *sentUpdate.Properties.Description)
	})

	t.Run("Delete_is_synchronous", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testAutomationRunbookNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(context.Context, string, string, string, *armautomation.RunbookClientDeleteOptions) (armautomation.RunbookClientDeleteResponse, error) {
			return armautomation.RunbookClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testAutomationRunbookNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_automation_account", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "automationAccountName": "aa-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testAutomationRunbookNativeID}, got.NativeIDs)
	})

	// ARM has no subscription-wide listing here, so List must return empty
	// rather than build a pager with a blank scope.
	t.Run("List_without_parents_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure_with_cause", func(t *testing.T) {
		fake.createOrUpdateFn = func(context.Context, string, string, string, armautomation.RunbookCreateOrUpdateParameters, *armautomation.RunbookClientCreateOrUpdateOptions) (armautomation.RunbookClientCreateOrUpdateResponse, error) {
			return armautomation.RunbookClientCreateOrUpdateResponse{}, &azcore.ResponseError{StatusCode: 400, ErrorCode: "BadRequest"}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "rb-1", Properties: automationRunbookDesired("d", false, nil),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.Contains(t, got.ProgressResult.StatusMessage, "BadRequest")
	})
}

func TestAutomationRunbook_ReadNotFound(t *testing.T) {
	fake := &fakeAutomationRunbookAPI{
		getFn: func(context.Context, string, string, string, *armautomation.RunbookClientGetOptions) (armautomation.RunbookClientGetResponse, error) {
			return armautomation.RunbookClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestAutomationRunbook(fake).Read(context.Background(),
		&resource.ReadRequest{NativeID: testAutomationRunbookNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeAutomationRunbookAPI struct {
	createOrUpdateFn                  func(ctx context.Context, rgName, accountName, name string, params armautomation.RunbookCreateOrUpdateParameters, options *armautomation.RunbookClientCreateOrUpdateOptions) (armautomation.RunbookClientCreateOrUpdateResponse, error)
	getFn                             func(ctx context.Context, rgName, accountName, name string, options *armautomation.RunbookClientGetOptions) (armautomation.RunbookClientGetResponse, error)
	updateFn                          func(ctx context.Context, rgName, accountName, name string, params armautomation.RunbookUpdateParameters, options *armautomation.RunbookClientUpdateOptions) (armautomation.RunbookClientUpdateResponse, error)
	deleteFn                          func(ctx context.Context, rgName, accountName, name string, options *armautomation.RunbookClientDeleteOptions) (armautomation.RunbookClientDeleteResponse, error)
	newListByAutomationAccountPagerFn func(rgName, accountName string, options *armautomation.RunbookClientListByAutomationAccountOptions) *runtime.Pager[armautomation.RunbookClientListByAutomationAccountResponse]
}

func (f *fakeAutomationRunbookAPI) CreateOrUpdate(ctx context.Context, rgName, accountName, name string, params armautomation.RunbookCreateOrUpdateParameters, options *armautomation.RunbookClientCreateOrUpdateOptions) (armautomation.RunbookClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, accountName, name, params, options)
}

func (f *fakeAutomationRunbookAPI) Get(ctx context.Context, rgName, accountName, name string, options *armautomation.RunbookClientGetOptions) (armautomation.RunbookClientGetResponse, error) {
	return f.getFn(ctx, rgName, accountName, name, options)
}

func (f *fakeAutomationRunbookAPI) Update(ctx context.Context, rgName, accountName, name string, params armautomation.RunbookUpdateParameters, options *armautomation.RunbookClientUpdateOptions) (armautomation.RunbookClientUpdateResponse, error) {
	return f.updateFn(ctx, rgName, accountName, name, params, options)
}

func (f *fakeAutomationRunbookAPI) Delete(ctx context.Context, rgName, accountName, name string, options *armautomation.RunbookClientDeleteOptions) (armautomation.RunbookClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, accountName, name, options)
}

func (f *fakeAutomationRunbookAPI) NewListByAutomationAccountPager(rgName, accountName string, options *armautomation.RunbookClientListByAutomationAccountOptions) *runtime.Pager[armautomation.RunbookClientListByAutomationAccountResponse] {
	return f.newListByAutomationAccountPagerFn(rgName, accountName, options)
}
