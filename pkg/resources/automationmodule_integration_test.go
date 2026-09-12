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

const testAutomationModuleNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Automation/automationAccounts/aa-1/modules/xActiveDirectory"

const testAutomationModuleURI = "https://www.powershellgallery.com/api/v2/package/xActiveDirectory/2.19.0"

func newTestAutomationModule(api automationModuleAPI) *AutomationModule {
	return &AutomationModule{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func automationModuleDesired(uri any, version string) []byte {
	props := map[string]any{
		"name":                  "xActiveDirectory",
		"resourceGroupName":     "rg-1",
		"automationAccountName": "aa-1",
		"contentLinkVersion":    version,
		"Tags":                  []map[string]string{{"Key": "env", "Value": "conformance"}},
	}
	if uri != nil {
		props["contentLinkUri"] = uri
	}
	out, _ := json.Marshal(props)
	return out
}

func TestAutomationModule_CRUD(t *testing.T) {
	// A response mid-import: provisioningState is still Creating and every other
	// property is derived from the package ARM is in the middle of downloading.
	// None of it may reach the read.
	modResult := armautomation.Module{
		ID:       to.Ptr(testAutomationModuleNativeID),
		Name:     to.Ptr("xActiveDirectory"),
		Location: to.Ptr("East US"),
		Properties: &armautomation.ModuleProperties{
			ProvisioningState: to.Ptr(armautomation.ModuleProvisioningStateCreating),
			Version:           to.Ptr("2.19.0"),
			SizeInBytes:       to.Ptr(int64(101851)),
			ActivityCount:     to.Ptr(int32(0)),
			IsComposite:       to.Ptr(false),
			IsGlobal:          to.Ptr(false),
			Error:             &armautomation.ModuleErrorInfo{Message: to.Ptr("")},
			CreationTime:      to.Ptr(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)),
			LastModifiedTime:  to.Ptr(time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)),
		},
		Tags: map[string]*string{"env": to.Ptr("conformance")},
	}

	var sentCreate armautomation.ModuleCreateOrUpdateParameters
	var sentUpdate armautomation.ModuleUpdateParameters
	deleteCalls := 0
	fake := &fakeAutomationModuleAPI{
		createOrUpdateFn: func(_ context.Context, rgName, accountName, name string, params armautomation.ModuleCreateOrUpdateParameters, _ *armautomation.ModuleClientCreateOrUpdateOptions) (armautomation.ModuleClientCreateOrUpdateResponse, error) {
			require.Equal(t, "rg-1", rgName)
			require.Equal(t, "aa-1", accountName)
			require.Equal(t, "xActiveDirectory", name)
			sentCreate = params
			return armautomation.ModuleClientCreateOrUpdateResponse{Module: modResult}, nil
		},
		getFn: func(context.Context, string, string, string, *armautomation.ModuleClientGetOptions) (armautomation.ModuleClientGetResponse, error) {
			return armautomation.ModuleClientGetResponse{Module: modResult}, nil
		},
		updateFn: func(_ context.Context, _, _, _ string, params armautomation.ModuleUpdateParameters, _ *armautomation.ModuleClientUpdateOptions) (armautomation.ModuleClientUpdateResponse, error) {
			sentUpdate = params
			return armautomation.ModuleClientUpdateResponse{Module: modResult}, nil
		},
		deleteFn: func(context.Context, string, string, string, *armautomation.ModuleClientDeleteOptions) (armautomation.ModuleClientDeleteResponse, error) {
			deleteCalls++
			return armautomation.ModuleClientDeleteResponse{}, nil
		},
		newListByAutomationAccountPagerFn: func(rgName, accountName string, _ *armautomation.ModuleClientListByAutomationAccountOptions) *runtime.Pager[armautomation.ModuleClientListByAutomationAccountResponse] {
			require.Equal(t, "rg-1", rgName)
			require.Equal(t, "aa-1", accountName)
			return runtime.NewPager(runtime.PagingHandler[armautomation.ModuleClientListByAutomationAccountResponse]{
				More: func(armautomation.ModuleClientListByAutomationAccountResponse) bool { return false },
				Fetcher: func(context.Context, *armautomation.ModuleClientListByAutomationAccountResponse) (armautomation.ModuleClientListByAutomationAccountResponse, error) {
					return armautomation.ModuleClientListByAutomationAccountResponse{
						ModuleListResult: armautomation.ModuleListResult{
							Value: []*armautomation.Module{{ID: to.Ptr(testAutomationModuleNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestAutomationModule(fake)

	// The PUT is synchronous even though the import it starts is not: there is no
	// poller to resume, so no resume token may be minted.
	t.Run("Create_is_synchronous_despite_the_async_import", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "xActiveDirectory",
			Properties: automationModuleDesired(testAutomationModuleURI, "2.19.0"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testAutomationModuleNativeID, got.ProgressResult.NativeID)
		require.Empty(t, got.ProgressResult.RequestID)

		require.Equal(t, testAutomationModuleURI, *sentCreate.Properties.ContentLink.URI)
		require.Equal(t, "2.19.0", *sentCreate.Properties.ContentLink.Version)
		// The hash is deliberately not modelled: ARM only verifies it, and
		// carrying it would make every content change a two-field edit.
		require.Nil(t, sentCreate.Properties.ContentLink.ContentHash)
		require.Equal(t, "conformance", *sentCreate.Tags["env"])
	})

	t.Run("Create_omits_an_undeclared_version", func(t *testing.T) {
		_, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "xActiveDirectory",
			Properties: automationModuleDesired(testAutomationModuleURI, ""),
		})
		require.NoError(t, err)
		require.Equal(t, testAutomationModuleURI, *sentCreate.Properties.ContentLink.URI)
		require.Nil(t, sentCreate.Properties.ContentLink.Version)
	})

	t.Run("Create_accepts_a_wrapped_content_link", func(t *testing.T) {
		_, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "xActiveDirectory",
			Properties: automationModuleDesired(
				map[string]any{"$value": testAutomationModuleURI}, "2.19.0"),
		})
		require.NoError(t, err)
		require.Equal(t, testAutomationModuleURI, *sentCreate.Properties.ContentLink.URI)
	})

	// There is nothing to import without a URI, so it has to be refused at the
	// handler rather than PUT as an empty contentLink.
	t.Run("Create_requires_a_content_link", func(t *testing.T) {
		_, err := prov.Create(context.Background(), &resource.CreateRequest{
			Properties: automationModuleDesired(nil, "2.19.0"),
		})
		require.ErrorContains(t, err, "contentLinkUri is required")
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
			require.NoError(t, json.Unmarshal(automationModuleDesired(testAutomationModuleURI, "2.19.0"), &props))
			delete(props, tc.drop)
			raw, _ := json.Marshal(props)
			_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: raw})
			require.ErrorContains(t, err, tc.want)
		}
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testAutomationModuleNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "xActiveDirectory", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "aa-1", props["automationAccountName"])
		require.Equal(t, []any{map[string]any{"Key": "env", "Value": "conformance"}}, props["Tags"])
	})

	// The load-bearing assertion for this type. provisioningState walks
	// Creating -> ... -> Succeeded out of band, and version / sizeInBytes /
	// activityCount are all derived from the package: emitting any of them would
	// report drift on every sync of an import still in flight. contentLink is
	// write-only and ARM does not return it anyway.
	t.Run("Read_drops_everything_the_import_derives", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testAutomationModuleNativeID})
		require.NoError(t, err)
		for _, key := range []string{"provisioningState", "version", "sizeInBytes", "activityCount",
			"isComposite", "isGlobal", "error", "creationTime", "lastModifiedTime",
			"contentLink", "contentLinkUri", "contentLinkVersion", "location"} {
			require.NotContains(t, got.Properties, key)
		}
	})

	t.Run("Update_reimports_from_a_new_content_link", func(t *testing.T) {
		const nextURI = "https://www.powershellgallery.com/api/v2/package/xActiveDirectory/2.20.0"
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testAutomationModuleNativeID,
			DesiredProperties: automationModuleDesired(nextURI, "2.20.0"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, nextURI, *sentUpdate.Properties.ContentLink.URI)
		require.Equal(t, "2.20.0", *sentUpdate.Properties.ContentLink.Version)
		require.Equal(t, "conformance", *sentUpdate.Tags["env"])
	})

	// A PATCH that carries no usable URI must not send an empty contentLink,
	// which would ask ARM to re-import from nothing.
	t.Run("Update_without_a_usable_content_link_sends_none", func(t *testing.T) {
		_, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testAutomationModuleNativeID,
			DesiredProperties: automationModuleDesired(nil, ""),
		})
		require.NoError(t, err)
		require.Nil(t, sentUpdate.Properties.ContentLink)
	})

	t.Run("Delete_is_synchronous", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testAutomationModuleNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(context.Context, string, string, string, *armautomation.ModuleClientDeleteOptions) (armautomation.ModuleClientDeleteResponse, error) {
			return armautomation.ModuleClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testAutomationModuleNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_automation_account", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "automationAccountName": "aa-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testAutomationModuleNativeID}, got.NativeIDs)
	})

	t.Run("List_without_parents_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure_with_cause", func(t *testing.T) {
		fake.createOrUpdateFn = func(context.Context, string, string, string, armautomation.ModuleCreateOrUpdateParameters, *armautomation.ModuleClientCreateOrUpdateOptions) (armautomation.ModuleClientCreateOrUpdateResponse, error) {
			return armautomation.ModuleClientCreateOrUpdateResponse{}, &azcore.ResponseError{StatusCode: 400, ErrorCode: "ModuleNameMismatch"}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "xActiveDirectory", Properties: automationModuleDesired(testAutomationModuleURI, "2.19.0"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.Contains(t, got.ProgressResult.StatusMessage, "ModuleNameMismatch")
	})
}

func TestAutomationModule_ReadNotFound(t *testing.T) {
	fake := &fakeAutomationModuleAPI{
		getFn: func(context.Context, string, string, string, *armautomation.ModuleClientGetOptions) (armautomation.ModuleClientGetResponse, error) {
			return armautomation.ModuleClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestAutomationModule(fake).Read(context.Background(),
		&resource.ReadRequest{NativeID: testAutomationModuleNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeAutomationModuleAPI struct {
	createOrUpdateFn                  func(ctx context.Context, rgName, accountName, name string, params armautomation.ModuleCreateOrUpdateParameters, options *armautomation.ModuleClientCreateOrUpdateOptions) (armautomation.ModuleClientCreateOrUpdateResponse, error)
	getFn                             func(ctx context.Context, rgName, accountName, name string, options *armautomation.ModuleClientGetOptions) (armautomation.ModuleClientGetResponse, error)
	updateFn                          func(ctx context.Context, rgName, accountName, name string, params armautomation.ModuleUpdateParameters, options *armautomation.ModuleClientUpdateOptions) (armautomation.ModuleClientUpdateResponse, error)
	deleteFn                          func(ctx context.Context, rgName, accountName, name string, options *armautomation.ModuleClientDeleteOptions) (armautomation.ModuleClientDeleteResponse, error)
	newListByAutomationAccountPagerFn func(rgName, accountName string, options *armautomation.ModuleClientListByAutomationAccountOptions) *runtime.Pager[armautomation.ModuleClientListByAutomationAccountResponse]
}

func (f *fakeAutomationModuleAPI) CreateOrUpdate(ctx context.Context, rgName, accountName, name string, params armautomation.ModuleCreateOrUpdateParameters, options *armautomation.ModuleClientCreateOrUpdateOptions) (armautomation.ModuleClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, accountName, name, params, options)
}

func (f *fakeAutomationModuleAPI) Get(ctx context.Context, rgName, accountName, name string, options *armautomation.ModuleClientGetOptions) (armautomation.ModuleClientGetResponse, error) {
	return f.getFn(ctx, rgName, accountName, name, options)
}

func (f *fakeAutomationModuleAPI) Update(ctx context.Context, rgName, accountName, name string, params armautomation.ModuleUpdateParameters, options *armautomation.ModuleClientUpdateOptions) (armautomation.ModuleClientUpdateResponse, error) {
	return f.updateFn(ctx, rgName, accountName, name, params, options)
}

func (f *fakeAutomationModuleAPI) Delete(ctx context.Context, rgName, accountName, name string, options *armautomation.ModuleClientDeleteOptions) (armautomation.ModuleClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, accountName, name, options)
}

func (f *fakeAutomationModuleAPI) NewListByAutomationAccountPager(rgName, accountName string, options *armautomation.ModuleClientListByAutomationAccountOptions) *runtime.Pager[armautomation.ModuleClientListByAutomationAccountResponse] {
	return f.newListByAutomationAccountPagerFn(rgName, accountName, options)
}
