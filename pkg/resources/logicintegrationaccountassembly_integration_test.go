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

const testLogicIntegrationAccountAssemblyNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Logic/integrationAccounts/ia-1/assemblies/asm-1"

func newTestLogicIntegrationAccountAssembly(api logicIntegrationAccountAssembliesAPI) *LogicIntegrationAccountAssembly {
	return &LogicIntegrationAccountAssembly{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

const testLogicAssemblyContent = "TVqQAAMAAAAEAAAA"

func logicAssemblyDesired(assemblyVersion any) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":                   "asm-1",
		"resourceGroupName":      "rg-1",
		"integrationAccountName": "ia-1",
		"assemblyName":           "Formae.Conformance.Transforms",
		"content":                testLogicAssemblyContent,
		"assemblyVersion":        assemblyVersion,
	})
	return out
}

func TestLogicIntegrationAccountAssembly_CRUD(t *testing.T) {
	// ARM's answer replaces content with a contentLink SAS URL and fills in the
	// strong-name triple it derived from the blob.
	result := armlogic.AssemblyDefinition{
		ID:   to.Ptr(testLogicIntegrationAccountAssemblyNativeID),
		Name: to.Ptr("asm-1"),
		Properties: &armlogic.AssemblyProperties{
			AssemblyName:    to.Ptr("Formae.Conformance.Transforms"),
			AssemblyVersion: to.Ptr("1.0.0.0"),
			AssemblyCulture: to.Ptr("neutral"),
			ContentLink: &armlogic.ContentLink{
				URI:         to.Ptr("https://prod.blob.core.windows.net/assemblies/asm-1?sig=REDACTED"),
				ContentSize: to.Ptr[int64](3056),
			},
			CreatedTime: to.Ptr(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)),
			ChangedTime: to.Ptr(time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)),
		},
	}

	var sentCreate armlogic.AssemblyDefinition
	createCalls := 0
	deleteCalls := 0
	fake := &fakeLogicIntegrationAccountAssembliesAPI{
		createOrUpdateFn: func(_ context.Context, rgName, accountName, name string, params armlogic.AssemblyDefinition, _ *armlogic.IntegrationAccountAssembliesClientCreateOrUpdateOptions) (armlogic.IntegrationAccountAssembliesClientCreateOrUpdateResponse, error) {
			require.Equal(t, "rg-1", rgName)
			require.Equal(t, "ia-1", accountName)
			require.Equal(t, "asm-1", name)
			sentCreate = params
			createCalls++
			return armlogic.IntegrationAccountAssembliesClientCreateOrUpdateResponse{AssemblyDefinition: result}, nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ *armlogic.IntegrationAccountAssembliesClientGetOptions) (armlogic.IntegrationAccountAssembliesClientGetResponse, error) {
			return armlogic.IntegrationAccountAssembliesClientGetResponse{AssemblyDefinition: result}, nil
		},
		deleteFn: func(_ context.Context, _, _, _ string, _ *armlogic.IntegrationAccountAssembliesClientDeleteOptions) (armlogic.IntegrationAccountAssembliesClientDeleteResponse, error) {
			deleteCalls++
			return armlogic.IntegrationAccountAssembliesClientDeleteResponse{}, nil
		},
		newListPagerFn: func(_, _ string, _ *armlogic.IntegrationAccountAssembliesClientListOptions) *runtime.Pager[armlogic.IntegrationAccountAssembliesClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armlogic.IntegrationAccountAssembliesClientListResponse]{
				More: func(_ armlogic.IntegrationAccountAssembliesClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armlogic.IntegrationAccountAssembliesClientListResponse) (armlogic.IntegrationAccountAssembliesClientListResponse, error) {
					return armlogic.IntegrationAccountAssembliesClientListResponse{
						AssemblyCollection: armlogic.AssemblyCollection{
							Value: []*armlogic.AssemblyDefinition{{ID: to.Ptr(testLogicIntegrationAccountAssemblyNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestLogicIntegrationAccountAssembly(fake)

	// Create is synchronous: IntegrationAccountAssembliesClient has no BeginX at all, so no
	// resume token is ever produced.
	t.Run("Create_is_synchronous", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "asm-1",
			Properties: logicAssemblyDesired("1.0.0.0"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testLogicIntegrationAccountAssemblyNativeID, got.ProgressResult.NativeID)
		require.Empty(t, got.ProgressResult.RequestID)

		// name is the ARM child resource name; assemblyName is the .NET identity
		// recorded inside it. ARM requires both and they are independent.
		require.Equal(t, "Formae.Conformance.Transforms", *sentCreate.Properties.AssemblyName)
		require.Equal(t, testLogicAssemblyContent, sentCreate.Properties.Content)
		require.Equal(t, "1.0.0.0", *sentCreate.Properties.AssemblyVersion)
	})

	t.Run("Create_requires_resource_group", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "asm-1", "integrationAccountName": "ia-1"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "resourceGroupName is required")
	})

	t.Run("Create_requires_integration_account", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "asm-1", "resourceGroupName": "rg-1"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "integrationAccountName is required")
	})

	t.Run("Create_requires_assembly_name", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "asm-1", "resourceGroupName": "rg-1", "integrationAccountName": "ia-1",
			"content": testLogicAssemblyContent,
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "assemblyName is required")
	})

	t.Run("Create_requires_content", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "asm-1", "resourceGroupName": "rg-1", "integrationAccountName": "ia-1",
			"assemblyName": "Formae.Conformance.Transforms",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "content is required")
	})

	// An omitted strong-name field must be left out of the body so ARM derives it
	// from the blob rather than receiving an empty string.
	t.Run("Create_without_strong_name_fields_sends_none", func(t *testing.T) {
		_, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "asm-1", Properties: logicAssemblyDesired(nil),
		})
		require.NoError(t, err)
		require.Nil(t, sentCreate.Properties.AssemblyVersion)
		require.Nil(t, sentCreate.Properties.AssemblyCulture)
		require.Nil(t, sentCreate.Properties.AssemblyPublicKeyToken)
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testLogicIntegrationAccountAssemblyNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "asm-1", props["name"])
		// Both parents come from the native ID, not the response body: ARM echoes
		// neither on a child.
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "ia-1", props["integrationAccountName"])
		require.Equal(t, "Formae.Conformance.Transforms", props["assemblyName"])
		// ARM derives the strong-name triple from the blob, which is why each of
		// the three carries hasProviderDefault in the schema.
		require.Equal(t, "1.0.0.0", props["assemblyVersion"])
		require.Equal(t, "neutral", props["assemblyCulture"])
		require.NotContains(t, props, "assemblyPublicKeyToken")
	})

	t.Run("Read_drops_write_only_content", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testLogicIntegrationAccountAssemblyNativeID})
		require.NoError(t, err)
		for _, key := range []string{"content", "contentLink", "sig=REDACTED", "metadata", "createdTime", "changedTime"} {
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

	// Update reissues CreateOrUpdate: this API has no PATCH verb for assemblies.
	t.Run("Update_reissues_create_or_update", func(t *testing.T) {
		before := createCalls
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testLogicIntegrationAccountAssemblyNativeID,
			DesiredProperties: logicAssemblyDesired("1.1.0.0"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Empty(t, got.ProgressResult.RequestID)
		require.Equal(t, before+1, createCalls)
		require.Equal(t, "1.1.0.0", *sentCreate.Properties.AssemblyVersion)
	})

	t.Run("Delete_is_synchronous", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testLogicIntegrationAccountAssemblyNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Empty(t, got.ProgressResult.RequestID)
		require.Equal(t, before+1, deleteCalls)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _, _ string, _ *armlogic.IntegrationAccountAssembliesClientDeleteOptions) (armlogic.IntegrationAccountAssembliesClientDeleteResponse, error) {
			return armlogic.IntegrationAccountAssembliesClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testLogicIntegrationAccountAssemblyNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_account", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "integrationAccountName": "ia-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testLogicIntegrationAccountAssemblyNativeID}, got.NativeIDs)
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
		fake.createOrUpdateFn = func(_ context.Context, _, _, _ string, _ armlogic.AssemblyDefinition, _ *armlogic.IntegrationAccountAssembliesClientCreateOrUpdateOptions) (armlogic.IntegrationAccountAssembliesClientCreateOrUpdateResponse, error) {
			return armlogic.IntegrationAccountAssembliesClientCreateOrUpdateResponse{}, &azcore.ResponseError{StatusCode: 409}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "asm-1", Properties: logicAssemblyDesired("1.0.0.0"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.NotEmpty(t, got.ProgressResult.StatusMessage)
	})
}

func TestLogicIntegrationAccountAssembly_ReadNotFound(t *testing.T) {
	fake := &fakeLogicIntegrationAccountAssembliesAPI{
		getFn: func(_ context.Context, _, _, _ string, _ *armlogic.IntegrationAccountAssembliesClientGetOptions) (armlogic.IntegrationAccountAssembliesClientGetResponse, error) {
			return armlogic.IntegrationAccountAssembliesClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestLogicIntegrationAccountAssembly(fake).Read(context.Background(),
		&resource.ReadRequest{NativeID: testLogicIntegrationAccountAssemblyNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeLogicIntegrationAccountAssembliesAPI struct {
	createOrUpdateFn func(ctx context.Context, rgName, accountName, name string, params armlogic.AssemblyDefinition, options *armlogic.IntegrationAccountAssembliesClientCreateOrUpdateOptions) (armlogic.IntegrationAccountAssembliesClientCreateOrUpdateResponse, error)
	getFn            func(ctx context.Context, rgName, accountName, name string, options *armlogic.IntegrationAccountAssembliesClientGetOptions) (armlogic.IntegrationAccountAssembliesClientGetResponse, error)
	deleteFn         func(ctx context.Context, rgName, accountName, name string, options *armlogic.IntegrationAccountAssembliesClientDeleteOptions) (armlogic.IntegrationAccountAssembliesClientDeleteResponse, error)
	newListPagerFn   func(rgName, accountName string, options *armlogic.IntegrationAccountAssembliesClientListOptions) *runtime.Pager[armlogic.IntegrationAccountAssembliesClientListResponse]
}

func (f *fakeLogicIntegrationAccountAssembliesAPI) CreateOrUpdate(ctx context.Context, rgName, accountName, name string, params armlogic.AssemblyDefinition, options *armlogic.IntegrationAccountAssembliesClientCreateOrUpdateOptions) (armlogic.IntegrationAccountAssembliesClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, accountName, name, params, options)
}

func (f *fakeLogicIntegrationAccountAssembliesAPI) Get(ctx context.Context, rgName, accountName, name string, options *armlogic.IntegrationAccountAssembliesClientGetOptions) (armlogic.IntegrationAccountAssembliesClientGetResponse, error) {
	return f.getFn(ctx, rgName, accountName, name, options)
}

func (f *fakeLogicIntegrationAccountAssembliesAPI) Delete(ctx context.Context, rgName, accountName, name string, options *armlogic.IntegrationAccountAssembliesClientDeleteOptions) (armlogic.IntegrationAccountAssembliesClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, accountName, name, options)
}

func (f *fakeLogicIntegrationAccountAssembliesAPI) NewListPager(rgName, accountName string, options *armlogic.IntegrationAccountAssembliesClientListOptions) *runtime.Pager[armlogic.IntegrationAccountAssembliesClientListResponse] {
	return f.newListPagerFn(rgName, accountName, options)
}
