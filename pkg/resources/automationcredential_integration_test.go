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

const testAutomationCredentialNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Automation/automationAccounts/aa-1/credentials/cred-1"

func newTestAutomationCredential(api automationCredentialAPI) *AutomationCredential {
	return &AutomationCredential{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func automationCredentialDesired(userName string, password any, description string) []byte {
	props := map[string]any{
		"name":                  "cred-1",
		"resourceGroupName":     "rg-1",
		"automationAccountName": "aa-1",
		"userName":              userName,
		"description":           description,
	}
	if password != nil {
		props["password"] = password
	}
	out, _ := json.Marshal(props)
	return out
}

func TestAutomationCredential_CRUD(t *testing.T) {
	// Note what is NOT in this response: CredentialProperties has no password
	// field at all, so there is nothing for a read to leak even by accident.
	credResult := armautomation.Credential{
		ID:   to.Ptr(testAutomationCredentialNativeID),
		Name: to.Ptr("cred-1"),
		Properties: &armautomation.CredentialProperties{
			UserName:         to.Ptr("conformance-user"),
			Description:      to.Ptr("Conformance credential"),
			CreationTime:     to.Ptr(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)),
			LastModifiedTime: to.Ptr(time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)),
		},
	}

	var sentCreate armautomation.CredentialCreateOrUpdateParameters
	var sentUpdate armautomation.CredentialUpdateParameters
	deleteCalls := 0
	fake := &fakeAutomationCredentialAPI{
		createOrUpdateFn: func(_ context.Context, rgName, accountName, name string, params armautomation.CredentialCreateOrUpdateParameters, _ *armautomation.CredentialClientCreateOrUpdateOptions) (armautomation.CredentialClientCreateOrUpdateResponse, error) {
			require.Equal(t, "rg-1", rgName)
			require.Equal(t, "aa-1", accountName)
			require.Equal(t, "cred-1", name)
			sentCreate = params
			return armautomation.CredentialClientCreateOrUpdateResponse{Credential: credResult}, nil
		},
		getFn: func(context.Context, string, string, string, *armautomation.CredentialClientGetOptions) (armautomation.CredentialClientGetResponse, error) {
			return armautomation.CredentialClientGetResponse{Credential: credResult}, nil
		},
		updateFn: func(_ context.Context, _, _, _ string, params armautomation.CredentialUpdateParameters, _ *armautomation.CredentialClientUpdateOptions) (armautomation.CredentialClientUpdateResponse, error) {
			sentUpdate = params
			return armautomation.CredentialClientUpdateResponse{Credential: credResult}, nil
		},
		deleteFn: func(context.Context, string, string, string, *armautomation.CredentialClientDeleteOptions) (armautomation.CredentialClientDeleteResponse, error) {
			deleteCalls++
			return armautomation.CredentialClientDeleteResponse{}, nil
		},
		newListByAutomationAccountPagerFn: func(rgName, accountName string, _ *armautomation.CredentialClientListByAutomationAccountOptions) *runtime.Pager[armautomation.CredentialClientListByAutomationAccountResponse] {
			require.Equal(t, "rg-1", rgName)
			require.Equal(t, "aa-1", accountName)
			return runtime.NewPager(runtime.PagingHandler[armautomation.CredentialClientListByAutomationAccountResponse]{
				More: func(armautomation.CredentialClientListByAutomationAccountResponse) bool { return false },
				Fetcher: func(context.Context, *armautomation.CredentialClientListByAutomationAccountResponse) (armautomation.CredentialClientListByAutomationAccountResponse, error) {
					return armautomation.CredentialClientListByAutomationAccountResponse{
						CredentialListResult: armautomation.CredentialListResult{
							Value: []*armautomation.Credential{{ID: to.Ptr(testAutomationCredentialNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestAutomationCredential(fake)

	t.Run("Create_is_synchronous", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "cred-1",
			Properties: automationCredentialDesired("conformance-user", "placeholder-1", "Conformance credential"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testAutomationCredentialNativeID, got.ProgressResult.NativeID)
		require.Empty(t, got.ProgressResult.RequestID)

		require.Equal(t, "conformance-user", *sentCreate.Properties.UserName)
		require.Equal(t, "placeholder-1", *sentCreate.Properties.Password)
		require.Equal(t, "Conformance credential", *sentCreate.Properties.Description)
	})

	// An opaque password can reach the plugin as the wrapper object rather than
	// as unwrapped plaintext. It must still be sent, and must not fail the whole
	// json.Unmarshal and take the rest of the properties down with it.
	t.Run("Create_accepts_a_wrapped_password", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "cred-1",
			Properties: automationCredentialDesired("conformance-user",
				map[string]any{"$value": "wrapped-secret"}, "d"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, "wrapped-secret", *sentCreate.Properties.Password)
		require.Equal(t, "conformance-user", *sentCreate.Properties.UserName)
	})

	// ARM requires both halves of the pair on create, so an absent password has
	// to be refused at the handler rather than PUT as an empty string.
	t.Run("Create_requires_a_password_and_a_username", func(t *testing.T) {
		_, err := prov.Create(context.Background(), &resource.CreateRequest{
			Properties: automationCredentialDesired("conformance-user", nil, "d"),
		})
		require.ErrorContains(t, err, "password is required")

		_, err = prov.Create(context.Background(), &resource.CreateRequest{
			Properties: automationCredentialDesired("", "placeholder-1", "d"),
		})
		require.ErrorContains(t, err, "userName is required")
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
			require.NoError(t, json.Unmarshal(automationCredentialDesired("u", "p", "d"), &props))
			delete(props, tc.drop)
			raw, _ := json.Marshal(props)
			_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: raw})
			require.ErrorContains(t, err, tc.want)
		}
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testAutomationCredentialNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "cred-1", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "aa-1", props["automationAccountName"])
		// The username IS returned by ARM and is fully comparable.
		require.Equal(t, "conformance-user", props["userName"])
		require.Equal(t, "Conformance credential", props["description"])
	})

	// The load-bearing assertion for this type: the password is write-only by
	// ARM's own design, so it must never appear in a read. If it did, every
	// conformance phase would compare a value the service can never report.
	t.Run("Read_never_emits_the_password", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testAutomationCredentialNativeID})
		require.NoError(t, err)
		require.NotContains(t, got.Properties, "password")
	})

	t.Run("Read_drops_moving_timestamps", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testAutomationCredentialNativeID})
		require.NoError(t, err)
		for _, key := range []string{"creationTime", "lastModifiedTime"} {
			require.NotContains(t, got.Properties, key)
		}
	})

	t.Run("Update_patches_username_password_and_description", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID: testAutomationCredentialNativeID,
			DesiredProperties: automationCredentialDesired("conformance-user-updated",
				"placeholder-2", "Conformance credential updated"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, "conformance-user-updated", *sentUpdate.Properties.UserName)
		require.Equal(t, "placeholder-2", *sentUpdate.Properties.Password)
		require.Equal(t, "Conformance credential updated", *sentUpdate.Properties.Description)
	})

	// An update whose password core cannot recover the plaintext of must leave
	// the field out of the body — "keep the one the service already holds" —
	// rather than clearing the credential.
	t.Run("Update_without_a_usable_password_leaves_it_alone", func(t *testing.T) {
		_, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testAutomationCredentialNativeID,
			DesiredProperties: automationCredentialDesired("conformance-user", nil, "only the description moved"),
		})
		require.NoError(t, err)
		require.Nil(t, sentUpdate.Properties.Password)
		require.Equal(t, "conformance-user", *sentUpdate.Properties.UserName)
		require.Equal(t, "only the description moved", *sentUpdate.Properties.Description)
	})

	t.Run("Delete_is_synchronous", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testAutomationCredentialNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(context.Context, string, string, string, *armautomation.CredentialClientDeleteOptions) (armautomation.CredentialClientDeleteResponse, error) {
			return armautomation.CredentialClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testAutomationCredentialNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_automation_account", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "automationAccountName": "aa-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testAutomationCredentialNativeID}, got.NativeIDs)
	})

	t.Run("List_without_parents_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure_with_cause", func(t *testing.T) {
		fake.createOrUpdateFn = func(context.Context, string, string, string, armautomation.CredentialCreateOrUpdateParameters, *armautomation.CredentialClientCreateOrUpdateOptions) (armautomation.CredentialClientCreateOrUpdateResponse, error) {
			return armautomation.CredentialClientCreateOrUpdateResponse{}, &azcore.ResponseError{StatusCode: 409, ErrorCode: "Conflict"}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "cred-1", Properties: automationCredentialDesired("u", "p", "d"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.Contains(t, got.ProgressResult.StatusMessage, "Conflict")
	})
}

func TestAutomationCredential_ReadNotFound(t *testing.T) {
	fake := &fakeAutomationCredentialAPI{
		getFn: func(context.Context, string, string, string, *armautomation.CredentialClientGetOptions) (armautomation.CredentialClientGetResponse, error) {
			return armautomation.CredentialClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestAutomationCredential(fake).Read(context.Background(),
		&resource.ReadRequest{NativeID: testAutomationCredentialNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeAutomationCredentialAPI struct {
	createOrUpdateFn                  func(ctx context.Context, rgName, accountName, name string, params armautomation.CredentialCreateOrUpdateParameters, options *armautomation.CredentialClientCreateOrUpdateOptions) (armautomation.CredentialClientCreateOrUpdateResponse, error)
	getFn                             func(ctx context.Context, rgName, accountName, name string, options *armautomation.CredentialClientGetOptions) (armautomation.CredentialClientGetResponse, error)
	updateFn                          func(ctx context.Context, rgName, accountName, name string, params armautomation.CredentialUpdateParameters, options *armautomation.CredentialClientUpdateOptions) (armautomation.CredentialClientUpdateResponse, error)
	deleteFn                          func(ctx context.Context, rgName, accountName, name string, options *armautomation.CredentialClientDeleteOptions) (armautomation.CredentialClientDeleteResponse, error)
	newListByAutomationAccountPagerFn func(rgName, accountName string, options *armautomation.CredentialClientListByAutomationAccountOptions) *runtime.Pager[armautomation.CredentialClientListByAutomationAccountResponse]
}

func (f *fakeAutomationCredentialAPI) CreateOrUpdate(ctx context.Context, rgName, accountName, name string, params armautomation.CredentialCreateOrUpdateParameters, options *armautomation.CredentialClientCreateOrUpdateOptions) (armautomation.CredentialClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, accountName, name, params, options)
}

func (f *fakeAutomationCredentialAPI) Get(ctx context.Context, rgName, accountName, name string, options *armautomation.CredentialClientGetOptions) (armautomation.CredentialClientGetResponse, error) {
	return f.getFn(ctx, rgName, accountName, name, options)
}

func (f *fakeAutomationCredentialAPI) Update(ctx context.Context, rgName, accountName, name string, params armautomation.CredentialUpdateParameters, options *armautomation.CredentialClientUpdateOptions) (armautomation.CredentialClientUpdateResponse, error) {
	return f.updateFn(ctx, rgName, accountName, name, params, options)
}

func (f *fakeAutomationCredentialAPI) Delete(ctx context.Context, rgName, accountName, name string, options *armautomation.CredentialClientDeleteOptions) (armautomation.CredentialClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, accountName, name, options)
}

func (f *fakeAutomationCredentialAPI) NewListByAutomationAccountPager(rgName, accountName string, options *armautomation.CredentialClientListByAutomationAccountOptions) *runtime.Pager[armautomation.CredentialClientListByAutomationAccountResponse] {
	return f.newListByAutomationAccountPagerFn(rgName, accountName, options)
}
