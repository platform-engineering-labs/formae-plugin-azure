// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/desktopvirtualization/armdesktopvirtualization"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testAvdApplicationNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.DesktopVirtualization/applicationGroups/ag-1/applications/app-1"

func newTestAvdApplication(api avdApplicationsAPI) *AvdApplication {
	return &AvdApplication{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func avdApplicationDesired(friendlyName string) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":                 "app-1",
		"resourceGroupName":    "rg-1",
		"applicationGroupName": "ag-1",
		"commandLineSetting":   "DoNotAllow",
		"filePath":             `C:\Windows\System32\mspaint.exe`,
		"description":          "conformance application",
		"friendlyName":         friendlyName,
		"showInPortal":         true,
	})
	return out
}

func TestAvdApplication_CRUD(t *testing.T) {
	// ARM answers a nested proxy resource's Name qualified by its parent
	// ("ag-1/app-1") and fills in the service-computed icon fields; both have to
	// be normalised or dropped or every sync reports drift.
	appResult := armdesktopvirtualization.Application{
		ID:   to.Ptr(testAvdApplicationNativeID),
		Name: to.Ptr("ag-1/app-1"),
		Properties: &armdesktopvirtualization.ApplicationProperties{
			CommandLineSetting: to.Ptr(armdesktopvirtualization.CommandLineSettingDoNotAllow),
			FilePath:           to.Ptr(`C:\Windows\System32\mspaint.exe`),
			Description:        to.Ptr("conformance application"),
			FriendlyName:       to.Ptr("Paint"),
			ShowInPortal:       to.Ptr(true),
			IconIndex:          to.Ptr(int32(0)),
			IconHash:           to.Ptr("a-service-computed-hash"),
			IconContent:        []byte{0x01, 0x02},
			ObjectID:           to.Ptr("00000000-0000-0000-0000-000000000003"),
		},
	}

	var sentCreate armdesktopvirtualization.Application
	var sentUpdate *armdesktopvirtualization.ApplicationPatch
	deleteCalls := 0
	fake := &fakeAvdApplicationsAPI{
		createOrUpdateFn: func(_ context.Context, rgName, groupName, name string, params armdesktopvirtualization.Application, _ *armdesktopvirtualization.ApplicationsClientCreateOrUpdateOptions) (armdesktopvirtualization.ApplicationsClientCreateOrUpdateResponse, error) {
			require.Equal(t, "rg-1", rgName)
			require.Equal(t, "ag-1", groupName)
			require.Equal(t, "app-1", name)
			sentCreate = params
			return armdesktopvirtualization.ApplicationsClientCreateOrUpdateResponse{Application: appResult}, nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ *armdesktopvirtualization.ApplicationsClientGetOptions) (armdesktopvirtualization.ApplicationsClientGetResponse, error) {
			return armdesktopvirtualization.ApplicationsClientGetResponse{Application: appResult}, nil
		},
		updateFn: func(_ context.Context, _, _, _ string, options *armdesktopvirtualization.ApplicationsClientUpdateOptions) (armdesktopvirtualization.ApplicationsClientUpdateResponse, error) {
			sentUpdate = options.Application
			return armdesktopvirtualization.ApplicationsClientUpdateResponse{Application: appResult}, nil
		},
		deleteFn: func(_ context.Context, _, _, _ string, _ *armdesktopvirtualization.ApplicationsClientDeleteOptions) (armdesktopvirtualization.ApplicationsClientDeleteResponse, error) {
			deleteCalls++
			return armdesktopvirtualization.ApplicationsClientDeleteResponse{}, nil
		},
		newListPagerFn: func(rgName, groupName string, _ *armdesktopvirtualization.ApplicationsClientListOptions) *runtime.Pager[armdesktopvirtualization.ApplicationsClientListResponse] {
			require.Equal(t, "rg-1", rgName)
			require.Equal(t, "ag-1", groupName)
			return runtime.NewPager(runtime.PagingHandler[armdesktopvirtualization.ApplicationsClientListResponse]{
				More: func(armdesktopvirtualization.ApplicationsClientListResponse) bool { return false },
				Fetcher: func(context.Context, *armdesktopvirtualization.ApplicationsClientListResponse) (armdesktopvirtualization.ApplicationsClientListResponse, error) {
					return armdesktopvirtualization.ApplicationsClientListResponse{
						ApplicationList: armdesktopvirtualization.ApplicationList{
							Value: []*armdesktopvirtualization.Application{{ID: to.Ptr(testAvdApplicationNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestAvdApplication(fake)

	t.Run("Create_is_synchronous", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "app-1",
			Properties: avdApplicationDesired("Paint"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testAvdApplicationNativeID, got.ProgressResult.NativeID)
		require.Empty(t, got.ProgressResult.RequestID)

		require.Equal(t, armdesktopvirtualization.CommandLineSettingDoNotAllow,
			*sentCreate.Properties.CommandLineSetting)
		require.Equal(t, `C:\Windows\System32\mspaint.exe`, *sentCreate.Properties.FilePath)
		require.True(t, *sentCreate.Properties.ShowInPortal)
		// applicationType is deliberately never sent: leaving it unset gets the
		// InBuilt behaviour a filePath application wants, and MSIX app attach is
		// not modelled.
		require.Nil(t, sentCreate.Properties.ApplicationType)
		require.Nil(t, sentCreate.Properties.MsixPackageFamilyName)
	})

	t.Run("Create_requires_application_group", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "app-1", "resourceGroupName": "rg-1",
			"commandLineSetting": "DoNotAllow", "filePath": "C:\\x.exe",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "applicationGroupName is required")
	})

	t.Run("Create_requires_command_line_setting", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "app-1", "resourceGroupName": "rg-1",
			"applicationGroupName": "ag-1", "filePath": "C:\\x.exe",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "commandLineSetting is required")
	})

	t.Run("Create_requires_file_path", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "app-1", "resourceGroupName": "rg-1",
			"applicationGroupName": "ag-1", "commandLineSetting": "DoNotAllow",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "filePath is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testAvdApplicationNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		// The parent qualifier ARM prefixes onto the name is stripped: desired
		// state and the ARM ID both carry the bare leaf.
		require.Equal(t, "app-1", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "ag-1", props["applicationGroupName"])
		require.Equal(t, "DoNotAllow", props["commandLineSetting"])
		require.Equal(t, `C:\Windows\System32\mspaint.exe`, props["filePath"])
		require.Equal(t, true, props["showInPortal"])
		// The Application model has no location and no tags at all.
		require.NotContains(t, props, "location")
		require.NotContains(t, props, "Tags")
	})

	// The icon fields are service-computed and objectId is internal bookkeeping;
	// all of them would read back as drift.
	t.Run("Read_drops_service_state", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testAvdApplicationNativeID})
		require.NoError(t, err)
		for _, key := range []string{"iconIndex", "iconHash", "iconContent", "objectId", "applicationType"} {
			require.NotContains(t, got.Properties, key)
		}
	})

	t.Run("Read_drops_empty_free_text", func(t *testing.T) {
		fake.getFn = func(context.Context, string, string, string, *armdesktopvirtualization.ApplicationsClientGetOptions) (armdesktopvirtualization.ApplicationsClientGetResponse, error) {
			return armdesktopvirtualization.ApplicationsClientGetResponse{Application: armdesktopvirtualization.Application{
				ID:   to.Ptr(testAvdApplicationNativeID),
				Name: to.Ptr("ag-1/app-1"),
				Properties: &armdesktopvirtualization.ApplicationProperties{
					CommandLineSetting:   to.Ptr(armdesktopvirtualization.CommandLineSettingDoNotAllow),
					CommandLineArguments: to.Ptr(""),
					Description:          to.Ptr(""),
					FriendlyName:         to.Ptr(""),
				},
			}}, nil
		}
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testAvdApplicationNativeID})
		require.NoError(t, err)
		for _, key := range []string{"commandLineArguments", "description", "friendlyName"} {
			require.NotContains(t, got.Properties, key)
		}
		fake.getFn = func(context.Context, string, string, string, *armdesktopvirtualization.ApplicationsClientGetOptions) (armdesktopvirtualization.ApplicationsClientGetResponse, error) {
			return armdesktopvirtualization.ApplicationsClientGetResponse{Application: appResult}, nil
		}
	})

	// Every mutable field is present in ApplicationPatchProperties, so nothing
	// about an application needs a replace.
	t.Run("Update_patches_in_place", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testAvdApplicationNativeID,
			DesiredProperties: avdApplicationDesired("Paint renamed"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, "Paint renamed", *sentUpdate.Properties.FriendlyName)
		require.Equal(t, `C:\Windows\System32\mspaint.exe`, *sentUpdate.Properties.FilePath)
		require.True(t, *sentUpdate.Properties.ShowInPortal)
	})

	t.Run("Delete_is_synchronous", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testAvdApplicationNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Empty(t, got.ProgressResult.RequestID)
		require.Equal(t, before+1, deleteCalls)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(context.Context, string, string, string, *armdesktopvirtualization.ApplicationsClientDeleteOptions) (armdesktopvirtualization.ApplicationsClientDeleteResponse, error) {
			return armdesktopvirtualization.ApplicationsClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testAvdApplicationNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	// Both scope keys come from the schema's two-level listParam block; ARM has
	// no subscription-wide pager for applications, so an unscoped List has
	// nothing it could enumerate and must not build a blank-scoped pager.
	t.Run("List_by_application_group", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{
				"resourceGroupName":    "rg-1",
				"applicationGroupName": "ag-1",
			},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testAvdApplicationNativeID}, got.NativeIDs)
	})

	t.Run("List_without_scope_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure_with_cause", func(t *testing.T) {
		fake.createOrUpdateFn = func(context.Context, string, string, string, armdesktopvirtualization.Application, *armdesktopvirtualization.ApplicationsClientCreateOrUpdateOptions) (armdesktopvirtualization.ApplicationsClientCreateOrUpdateResponse, error) {
			return armdesktopvirtualization.ApplicationsClientCreateOrUpdateResponse{},
				&azcore.ResponseError{StatusCode: 400, ErrorCode: "DesktopApplicationGroupCannotHoldApplications"}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "app-1", Properties: avdApplicationDesired("Paint"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.Contains(t, got.ProgressResult.StatusMessage, "DesktopApplicationGroupCannotHoldApplications")
	})
}

func TestAvdApplication_ReadNotFound(t *testing.T) {
	fake := &fakeAvdApplicationsAPI{
		getFn: func(context.Context, string, string, string, *armdesktopvirtualization.ApplicationsClientGetOptions) (armdesktopvirtualization.ApplicationsClientGetResponse, error) {
			return armdesktopvirtualization.ApplicationsClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestAvdApplication(fake).Read(context.Background(),
		&resource.ReadRequest{NativeID: testAvdApplicationNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeAvdApplicationsAPI struct {
	createOrUpdateFn func(ctx context.Context, rgName, groupName, name string, params armdesktopvirtualization.Application, options *armdesktopvirtualization.ApplicationsClientCreateOrUpdateOptions) (armdesktopvirtualization.ApplicationsClientCreateOrUpdateResponse, error)
	getFn            func(ctx context.Context, rgName, groupName, name string, options *armdesktopvirtualization.ApplicationsClientGetOptions) (armdesktopvirtualization.ApplicationsClientGetResponse, error)
	updateFn         func(ctx context.Context, rgName, groupName, name string, options *armdesktopvirtualization.ApplicationsClientUpdateOptions) (armdesktopvirtualization.ApplicationsClientUpdateResponse, error)
	deleteFn         func(ctx context.Context, rgName, groupName, name string, options *armdesktopvirtualization.ApplicationsClientDeleteOptions) (armdesktopvirtualization.ApplicationsClientDeleteResponse, error)
	newListPagerFn   func(rgName, groupName string, options *armdesktopvirtualization.ApplicationsClientListOptions) *runtime.Pager[armdesktopvirtualization.ApplicationsClientListResponse]
}

func (f *fakeAvdApplicationsAPI) CreateOrUpdate(ctx context.Context, rgName, groupName, name string, params armdesktopvirtualization.Application, options *armdesktopvirtualization.ApplicationsClientCreateOrUpdateOptions) (armdesktopvirtualization.ApplicationsClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, groupName, name, params, options)
}

func (f *fakeAvdApplicationsAPI) Get(ctx context.Context, rgName, groupName, name string, options *armdesktopvirtualization.ApplicationsClientGetOptions) (armdesktopvirtualization.ApplicationsClientGetResponse, error) {
	return f.getFn(ctx, rgName, groupName, name, options)
}

func (f *fakeAvdApplicationsAPI) Update(ctx context.Context, rgName, groupName, name string, options *armdesktopvirtualization.ApplicationsClientUpdateOptions) (armdesktopvirtualization.ApplicationsClientUpdateResponse, error) {
	return f.updateFn(ctx, rgName, groupName, name, options)
}

func (f *fakeAvdApplicationsAPI) Delete(ctx context.Context, rgName, groupName, name string, options *armdesktopvirtualization.ApplicationsClientDeleteOptions) (armdesktopvirtualization.ApplicationsClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, groupName, name, options)
}

func (f *fakeAvdApplicationsAPI) NewListPager(rgName, groupName string, options *armdesktopvirtualization.ApplicationsClientListOptions) *runtime.Pager[armdesktopvirtualization.ApplicationsClientListResponse] {
	return f.newListPagerFn(rgName, groupName, options)
}
