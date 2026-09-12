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

const testAutomationVariableNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Automation/automationAccounts/aa-1/variables/var-1"

func newTestAutomationVariable(api automationVariableAPI) *AutomationVariable {
	return &AutomationVariable{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func automationVariableDesired(value any, description string, isEncrypted bool) []byte {
	props := map[string]any{
		"name":                  "var-1",
		"resourceGroupName":     "rg-1",
		"automationAccountName": "aa-1",
		"isEncrypted":           isEncrypted,
		"description":           description,
	}
	if value != nil {
		props["value"] = value
	}
	out, _ := json.Marshal(props)
	return out
}

func TestAutomationVariable_CRUD(t *testing.T) {
	// A plain (unencrypted) variable: ARM DOES echo the value back here, which is
	// exactly the case the read path must still refuse to emit, because a runbook
	// can assign to the variable at runtime.
	varResult := armautomation.Variable{
		ID:   to.Ptr(testAutomationVariableNativeID),
		Name: to.Ptr("var-1"),
		Properties: &armautomation.VariableProperties{
			IsEncrypted:      to.Ptr(false),
			Value:            to.Ptr(`"conformance"`),
			Description:      to.Ptr("Conformance variable"),
			CreationTime:     to.Ptr(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)),
			LastModifiedTime: to.Ptr(time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)),
		},
	}

	var sentCreate armautomation.VariableCreateOrUpdateParameters
	var sentUpdate armautomation.VariableUpdateParameters
	deleteCalls := 0
	fake := &fakeAutomationVariableAPI{
		createOrUpdateFn: func(_ context.Context, rgName, accountName, name string, params armautomation.VariableCreateOrUpdateParameters, _ *armautomation.VariableClientCreateOrUpdateOptions) (armautomation.VariableClientCreateOrUpdateResponse, error) {
			require.Equal(t, "rg-1", rgName)
			require.Equal(t, "aa-1", accountName)
			require.Equal(t, "var-1", name)
			sentCreate = params
			return armautomation.VariableClientCreateOrUpdateResponse{Variable: varResult}, nil
		},
		getFn: func(context.Context, string, string, string, *armautomation.VariableClientGetOptions) (armautomation.VariableClientGetResponse, error) {
			return armautomation.VariableClientGetResponse{Variable: varResult}, nil
		},
		updateFn: func(_ context.Context, _, _, _ string, params armautomation.VariableUpdateParameters, _ *armautomation.VariableClientUpdateOptions) (armautomation.VariableClientUpdateResponse, error) {
			sentUpdate = params
			return armautomation.VariableClientUpdateResponse{Variable: varResult}, nil
		},
		deleteFn: func(context.Context, string, string, string, *armautomation.VariableClientDeleteOptions) (armautomation.VariableClientDeleteResponse, error) {
			deleteCalls++
			return armautomation.VariableClientDeleteResponse{}, nil
		},
		newListByAutomationAccountPagerFn: func(rgName, accountName string, _ *armautomation.VariableClientListByAutomationAccountOptions) *runtime.Pager[armautomation.VariableClientListByAutomationAccountResponse] {
			require.Equal(t, "rg-1", rgName)
			require.Equal(t, "aa-1", accountName)
			return runtime.NewPager(runtime.PagingHandler[armautomation.VariableClientListByAutomationAccountResponse]{
				More: func(armautomation.VariableClientListByAutomationAccountResponse) bool { return false },
				Fetcher: func(context.Context, *armautomation.VariableClientListByAutomationAccountResponse) (armautomation.VariableClientListByAutomationAccountResponse, error) {
					return armautomation.VariableClientListByAutomationAccountResponse{
						VariableListResult: armautomation.VariableListResult{
							Value: []*armautomation.Variable{{ID: to.Ptr(testAutomationVariableNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestAutomationVariable(fake)

	t.Run("Create_is_synchronous", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "var-1",
			Properties: automationVariableDesired(`"conformance"`, "Conformance variable", false),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testAutomationVariableNativeID, got.ProgressResult.NativeID)
		require.Empty(t, got.ProgressResult.RequestID)

		require.False(t, *sentCreate.Properties.IsEncrypted)
		require.Equal(t, `"conformance"`, *sentCreate.Properties.Value)
		require.Equal(t, "Conformance variable", *sentCreate.Properties.Description)
	})

	// isEncrypted is a *bool precisely so an omitted flag is distinguishable from
	// a declared false; the schema makes it required, so a create without it must
	// still not send a spurious false.
	t.Run("Create_omits_an_undeclared_encryption_flag", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "var-1", "resourceGroupName": "rg-1", "automationAccountName": "aa-1",
			"value": `"x"`,
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.Nil(t, sentCreate.Properties.IsEncrypted)
	})

	// An opaque write-only value can reach the plugin as the wrapper object
	// rather than as unwrapped plaintext; it must still be sent, and must not
	// fail the whole unmarshal.
	t.Run("Create_accepts_a_wrapped_value", func(t *testing.T) {
		_, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "var-1",
			Properties: automationVariableDesired(map[string]any{"$value": `"wrapped"`}, "d", true),
		})
		require.NoError(t, err)
		require.Equal(t, `"wrapped"`, *sentCreate.Properties.Value)
		require.True(t, *sentCreate.Properties.IsEncrypted)
	})

	// A value core cannot recover the plaintext of must leave the field out of
	// the body — "keep what the provider already holds" — rather than clearing it.
	t.Run("Create_without_a_usable_value_sends_none", func(t *testing.T) {
		_, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "var-1",
			Properties: automationVariableDesired(nil, "d", false),
		})
		require.NoError(t, err)
		require.Nil(t, sentCreate.Properties.Value)
	})

	t.Run("Create_requires_parents", func(t *testing.T) {
		for _, tc := range []struct {
			drop string
			want string
		}{
			{"resourceGroupName", "resourceGroupName is required"},
			{"automationAccountName", "automationAccountName is required"},
		} {
			var props map[string]any
			require.NoError(t, json.Unmarshal(automationVariableDesired(`"x"`, "d", false), &props))
			delete(props, tc.drop)
			raw, _ := json.Marshal(props)
			_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: raw})
			require.ErrorContains(t, err, tc.want)
		}
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testAutomationVariableNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "var-1", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "aa-1", props["automationAccountName"])
		require.Equal(t, false, props["isEncrypted"])
		require.Equal(t, "Conformance variable", props["description"])
	})

	// The load-bearing assertion for this type. ARM returned the value here
	// (isEncrypted is false), and the read must STILL not emit it: an encrypted
	// variable never returns one, and a runbook is a legitimate co-writer of an
	// unencrypted one, so comparing it would report drift the plugin cannot own.
	t.Run("Read_never_emits_the_value", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testAutomationVariableNativeID})
		require.NoError(t, err)
		require.NotContains(t, got.Properties, "value")
		require.NotContains(t, got.Properties, "conformance")
	})

	// The same must hold when ARM returns no value at all, which is what an
	// encrypted variable does.
	t.Run("Read_of_an_encrypted_variable_omits_the_value", func(t *testing.T) {
		fake.getFn = func(context.Context, string, string, string, *armautomation.VariableClientGetOptions) (armautomation.VariableClientGetResponse, error) {
			encrypted := varResult
			propsCopy := *varResult.Properties
			propsCopy.IsEncrypted = to.Ptr(true)
			propsCopy.Value = nil
			encrypted.Properties = &propsCopy
			return armautomation.VariableClientGetResponse{Variable: encrypted}, nil
		}
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testAutomationVariableNativeID})
		require.NoError(t, err)
		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, true, props["isEncrypted"])
		require.NotContains(t, props, "value")
		fake.getFn = func(context.Context, string, string, string, *armautomation.VariableClientGetOptions) (armautomation.VariableClientGetResponse, error) {
			return armautomation.VariableClientGetResponse{Variable: varResult}, nil
		}
	})

	t.Run("Read_drops_moving_timestamps", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testAutomationVariableNativeID})
		require.NoError(t, err)
		for _, key := range []string{"creationTime", "lastModifiedTime"} {
			require.NotContains(t, got.Properties, key)
		}
	})

	// VariableUpdateProperties reaches the value and the description;
	// isEncrypted is createOnly and must not appear in the PATCH shape at all.
	t.Run("Update_patches_value_and_description", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testAutomationVariableNativeID,
			DesiredProperties: automationVariableDesired(`"conformance-updated"`, "Conformance variable updated", false),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, `"conformance-updated"`, *sentUpdate.Properties.Value)
		require.Equal(t, "Conformance variable updated", *sentUpdate.Properties.Description)
	})

	// A rotation whose plaintext core no longer holds must not clear the stored
	// value.
	t.Run("Update_without_a_usable_value_leaves_it_alone", func(t *testing.T) {
		_, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testAutomationVariableNativeID,
			DesiredProperties: automationVariableDesired(nil, "still here", false),
		})
		require.NoError(t, err)
		require.Nil(t, sentUpdate.Properties.Value)
		require.Equal(t, "still here", *sentUpdate.Properties.Description)
	})

	t.Run("Delete_is_synchronous", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testAutomationVariableNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(context.Context, string, string, string, *armautomation.VariableClientDeleteOptions) (armautomation.VariableClientDeleteResponse, error) {
			return armautomation.VariableClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testAutomationVariableNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_automation_account", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "automationAccountName": "aa-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testAutomationVariableNativeID}, got.NativeIDs)
	})

	t.Run("List_without_parents_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure_with_cause", func(t *testing.T) {
		fake.createOrUpdateFn = func(context.Context, string, string, string, armautomation.VariableCreateOrUpdateParameters, *armautomation.VariableClientCreateOrUpdateOptions) (armautomation.VariableClientCreateOrUpdateResponse, error) {
			return armautomation.VariableClientCreateOrUpdateResponse{}, &azcore.ResponseError{StatusCode: 409, ErrorCode: "Conflict"}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "var-1", Properties: automationVariableDesired(`"x"`, "d", false),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.Contains(t, got.ProgressResult.StatusMessage, "Conflict")
	})
}

func TestAutomationVariable_ReadNotFound(t *testing.T) {
	fake := &fakeAutomationVariableAPI{
		getFn: func(context.Context, string, string, string, *armautomation.VariableClientGetOptions) (armautomation.VariableClientGetResponse, error) {
			return armautomation.VariableClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestAutomationVariable(fake).Read(context.Background(),
		&resource.ReadRequest{NativeID: testAutomationVariableNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeAutomationVariableAPI struct {
	createOrUpdateFn                  func(ctx context.Context, rgName, accountName, name string, params armautomation.VariableCreateOrUpdateParameters, options *armautomation.VariableClientCreateOrUpdateOptions) (armautomation.VariableClientCreateOrUpdateResponse, error)
	getFn                             func(ctx context.Context, rgName, accountName, name string, options *armautomation.VariableClientGetOptions) (armautomation.VariableClientGetResponse, error)
	updateFn                          func(ctx context.Context, rgName, accountName, name string, params armautomation.VariableUpdateParameters, options *armautomation.VariableClientUpdateOptions) (armautomation.VariableClientUpdateResponse, error)
	deleteFn                          func(ctx context.Context, rgName, accountName, name string, options *armautomation.VariableClientDeleteOptions) (armautomation.VariableClientDeleteResponse, error)
	newListByAutomationAccountPagerFn func(rgName, accountName string, options *armautomation.VariableClientListByAutomationAccountOptions) *runtime.Pager[armautomation.VariableClientListByAutomationAccountResponse]
}

func (f *fakeAutomationVariableAPI) CreateOrUpdate(ctx context.Context, rgName, accountName, name string, params armautomation.VariableCreateOrUpdateParameters, options *armautomation.VariableClientCreateOrUpdateOptions) (armautomation.VariableClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, accountName, name, params, options)
}

func (f *fakeAutomationVariableAPI) Get(ctx context.Context, rgName, accountName, name string, options *armautomation.VariableClientGetOptions) (armautomation.VariableClientGetResponse, error) {
	return f.getFn(ctx, rgName, accountName, name, options)
}

func (f *fakeAutomationVariableAPI) Update(ctx context.Context, rgName, accountName, name string, params armautomation.VariableUpdateParameters, options *armautomation.VariableClientUpdateOptions) (armautomation.VariableClientUpdateResponse, error) {
	return f.updateFn(ctx, rgName, accountName, name, params, options)
}

func (f *fakeAutomationVariableAPI) Delete(ctx context.Context, rgName, accountName, name string, options *armautomation.VariableClientDeleteOptions) (armautomation.VariableClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, accountName, name, options)
}

func (f *fakeAutomationVariableAPI) NewListByAutomationAccountPager(rgName, accountName string, options *armautomation.VariableClientListByAutomationAccountOptions) *runtime.Pager[armautomation.VariableClientListByAutomationAccountResponse] {
	return f.newListByAutomationAccountPagerFn(rgName, accountName, options)
}
