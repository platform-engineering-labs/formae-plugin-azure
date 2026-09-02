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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/datafactory/armdatafactory"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testSelfHostedIRNativeID = testDataFactoryNativeID + "/integrationRuntimes/shir-1"

const testAzureIRNativeID = testDataFactoryNativeID + "/integrationRuntimes/azir-1"

func newTestSelfHostedIR(api dataFactoryIntegrationRuntimesAPI) *DataFactoryIntegrationRuntimeSelfHosted {
	return &DataFactoryIntegrationRuntimeSelfHosted{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func selfHostedIRDesired(description string) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":              "shir-1",
		"resourceGroupName": "rg-1",
		"factoryName":       "adf-1",
		"description":       description,
	})
	return out
}

func TestDataFactoryIntegrationRuntimeSelfHosted_CRUD(t *testing.T) {
	irResult := armdatafactory.IntegrationRuntimeResource{
		ID:   to.Ptr(testSelfHostedIRNativeID),
		Name: to.Ptr("shir-1"),
		Etag: to.Ptr("W/\"datetime\""),
		Properties: &armdatafactory.SelfHostedIntegrationRuntime{
			Type:        to.Ptr(armdatafactory.IntegrationRuntimeTypeSelfHosted),
			Description: to.Ptr("on-prem copy runtime"),
		},
	}

	var sent armdatafactory.IntegrationRuntimeResource
	var sawRG, sawFactory, sawName string
	createCalls := 0
	deleteCalls := 0
	fake := newFakeIntegrationRuntimesAPI(irResult, &sent, &sawRG, &sawFactory, &sawName, &createCalls, &deleteCalls)
	prov := newTestSelfHostedIR(fake)

	// CreateOrUpdate on IntegrationRuntimesClient is synchronous: the only pollers
	// on that client are BeginStart and BeginStop, which apply to Azure-SSIS
	// runtimes this provider does not manage.
	t.Run("Create_is_synchronous", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "shir-1",
			Properties: selfHostedIRDesired("on-prem copy runtime"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testSelfHostedIRNativeID, got.ProgressResult.NativeID)
		require.Empty(t, got.ProgressResult.RequestID)

		require.Equal(t, "rg-1", sawRG)
		require.Equal(t, "adf-1", sawFactory)
		require.Equal(t, "shir-1", sawName)

		shir, ok := sent.Properties.(*armdatafactory.SelfHostedIntegrationRuntime)
		require.True(t, ok)
		require.Equal(t, armdatafactory.IntegrationRuntimeTypeSelfHosted, *shir.Type)
		require.Equal(t, "on-prem copy runtime", *shir.Description)
		// linkedInfo is not modelled: a linked runtime is created through a
		// different verb and keyed by a sharing credential ARM never returns.
		require.Nil(t, shir.TypeProperties)
	})

	t.Run("Create_requires_factory", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "shir-1", "resourceGroupName": "rg-1"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "factoryName is required")
	})

	t.Run("Create_requires_resource_group", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "shir-1", "factoryName": "adf-1"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "resourceGroupName is required")
	})

	t.Run("Create_falls_back_to_label_for_name", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"resourceGroupName": "rg-1", "factoryName": "adf-1"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "shir-1", Properties: props})
		require.NoError(t, err)
		require.Equal(t, "shir-1", sawName)
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testSelfHostedIRNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "shir-1", props["name"])
		// Both parents come from the native ID, not the response body.
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "adf-1", props["factoryName"])
		require.Equal(t, "on-prem copy runtime", props["description"])
	})

	// The auth keys must never reach resource state: ARM hands them out only from
	// a separate ListAuthKeys call, so storing them would persist live credentials.
	t.Run("Read_never_surfaces_auth_keys_or_etag", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testSelfHostedIRNativeID})
		require.NoError(t, err)
		for _, key := range []string{"authKey", "etag", "Etag"} {
			require.NotContains(t, got.Properties, key)
		}
	})

	t.Run("Update_reissues_create_or_update", func(t *testing.T) {
		before := createCalls
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testSelfHostedIRNativeID,
			DesiredProperties: selfHostedIRDesired("moved to the new datacentre"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Empty(t, got.ProgressResult.RequestID)
		require.Equal(t, before+1, createCalls)
		shir, ok := sent.Properties.(*armdatafactory.SelfHostedIntegrationRuntime)
		require.True(t, ok)
		require.Equal(t, "moved to the new datacentre", *shir.Description)
	})

	t.Run("Delete_is_synchronous", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testSelfHostedIRNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _, _ string, _ *armdatafactory.IntegrationRuntimesClientDeleteOptions) (armdatafactory.IntegrationRuntimesClientDeleteResponse, error) {
			return armdatafactory.IntegrationRuntimesClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testSelfHostedIRNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	// ARM returns both runtime kinds from one pager, so the results must be
	// filtered: handing a managed runtime's ID to this provisioner would read it
	// with the wrong shape.
	t.Run("List_keeps_only_self_hosted", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "factoryName": "adf-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testSelfHostedIRNativeID}, got.NativeIDs)
	})

	// ARM has no subscription-wide listing here: without both parents there is
	// nothing to page, so List must return empty rather than error.
	t.Run("List_without_parents_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)

		got, err = prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure_with_reason", func(t *testing.T) {
		fake.createOrUpdateFn = func(_ context.Context, _, _, _ string, _ armdatafactory.IntegrationRuntimeResource, _ *armdatafactory.IntegrationRuntimesClientCreateOrUpdateOptions) (armdatafactory.IntegrationRuntimesClientCreateOrUpdateResponse, error) {
			return armdatafactory.IntegrationRuntimesClientCreateOrUpdateResponse{},
				&azcore.ResponseError{StatusCode: 400, ErrorCode: "InvalidIntegrationRuntimeName"}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "shir-1", Properties: selfHostedIRDesired("x"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.Equal(t, resource.OperationErrorCodeInvalidRequest, got.ProgressResult.ErrorCode)
		require.Contains(t, got.ProgressResult.StatusMessage, "InvalidIntegrationRuntimeName")
	})
}

func TestDataFactoryIntegrationRuntimeSelfHosted_ReadNotFound(t *testing.T) {
	fake := &fakeIntegrationRuntimesAPI{
		getFn: func(_ context.Context, _, _, _ string, _ *armdatafactory.IntegrationRuntimesClientGetOptions) (armdatafactory.IntegrationRuntimesClientGetResponse, error) {
			return armdatafactory.IntegrationRuntimesClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestSelfHostedIR(fake).Read(context.Background(), &resource.ReadRequest{NativeID: testSelfHostedIRNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

func TestDataFactoryIntegrationRuntimeSelfHosted_StatusIsAlwaysDone(t *testing.T) {
	got, err := newTestSelfHostedIR(&fakeIntegrationRuntimesAPI{}).
		Status(context.Background(), &resource.StatusRequest{RequestID: "anything"})
	require.NoError(t, err)
	require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
}

// --- Test helpers, shared with the Azure (managed) runtime test ---

type fakeIntegrationRuntimesAPI struct {
	createOrUpdateFn        func(ctx context.Context, rgName, factoryName, name string, params armdatafactory.IntegrationRuntimeResource, options *armdatafactory.IntegrationRuntimesClientCreateOrUpdateOptions) (armdatafactory.IntegrationRuntimesClientCreateOrUpdateResponse, error)
	getFn                   func(ctx context.Context, rgName, factoryName, name string, options *armdatafactory.IntegrationRuntimesClientGetOptions) (armdatafactory.IntegrationRuntimesClientGetResponse, error)
	deleteFn                func(ctx context.Context, rgName, factoryName, name string, options *armdatafactory.IntegrationRuntimesClientDeleteOptions) (armdatafactory.IntegrationRuntimesClientDeleteResponse, error)
	newListByFactoryPagerFn func(rgName, factoryName string, options *armdatafactory.IntegrationRuntimesClientListByFactoryOptions) *runtime.Pager[armdatafactory.IntegrationRuntimesClientListByFactoryResponse]
}

func (f *fakeIntegrationRuntimesAPI) CreateOrUpdate(ctx context.Context, rgName, factoryName, name string, params armdatafactory.IntegrationRuntimeResource, options *armdatafactory.IntegrationRuntimesClientCreateOrUpdateOptions) (armdatafactory.IntegrationRuntimesClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, factoryName, name, params, options)
}

func (f *fakeIntegrationRuntimesAPI) Get(ctx context.Context, rgName, factoryName, name string, options *armdatafactory.IntegrationRuntimesClientGetOptions) (armdatafactory.IntegrationRuntimesClientGetResponse, error) {
	return f.getFn(ctx, rgName, factoryName, name, options)
}

func (f *fakeIntegrationRuntimesAPI) Delete(ctx context.Context, rgName, factoryName, name string, options *armdatafactory.IntegrationRuntimesClientDeleteOptions) (armdatafactory.IntegrationRuntimesClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, factoryName, name, options)
}

func (f *fakeIntegrationRuntimesAPI) NewListByFactoryPager(rgName, factoryName string, options *armdatafactory.IntegrationRuntimesClientListByFactoryOptions) *runtime.Pager[armdatafactory.IntegrationRuntimesClientListByFactoryResponse] {
	return f.newListByFactoryPagerFn(rgName, factoryName, options)
}

// newFakeIntegrationRuntimesAPI wires a fake whose pager always returns one
// self-hosted and one managed runtime, so both provisioners' List filters are
// exercised against a mixed factory.
func newFakeIntegrationRuntimesAPI(
	result armdatafactory.IntegrationRuntimeResource,
	sent *armdatafactory.IntegrationRuntimeResource,
	sawRG, sawFactory, sawName *string,
	createCalls, deleteCalls *int,
) *fakeIntegrationRuntimesAPI {
	mixedPage := []*armdatafactory.IntegrationRuntimeResource{
		{
			ID: to.Ptr(testSelfHostedIRNativeID),
			Properties: &armdatafactory.SelfHostedIntegrationRuntime{
				Type: to.Ptr(armdatafactory.IntegrationRuntimeTypeSelfHosted),
			},
		},
		{
			ID: to.Ptr(testAzureIRNativeID),
			Properties: &armdatafactory.ManagedIntegrationRuntime{
				Type: to.Ptr(armdatafactory.IntegrationRuntimeTypeManaged),
			},
		},
		// No ID and no properties: both must be skipped rather than panicking.
		{},
	}

	return &fakeIntegrationRuntimesAPI{
		createOrUpdateFn: func(_ context.Context, rgName, factoryName, name string, params armdatafactory.IntegrationRuntimeResource, _ *armdatafactory.IntegrationRuntimesClientCreateOrUpdateOptions) (armdatafactory.IntegrationRuntimesClientCreateOrUpdateResponse, error) {
			*sawRG, *sawFactory, *sawName, *sent = rgName, factoryName, name, params
			*createCalls++
			return armdatafactory.IntegrationRuntimesClientCreateOrUpdateResponse{IntegrationRuntimeResource: result}, nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ *armdatafactory.IntegrationRuntimesClientGetOptions) (armdatafactory.IntegrationRuntimesClientGetResponse, error) {
			return armdatafactory.IntegrationRuntimesClientGetResponse{IntegrationRuntimeResource: result}, nil
		},
		deleteFn: func(_ context.Context, _, _, _ string, _ *armdatafactory.IntegrationRuntimesClientDeleteOptions) (armdatafactory.IntegrationRuntimesClientDeleteResponse, error) {
			*deleteCalls++
			return armdatafactory.IntegrationRuntimesClientDeleteResponse{}, nil
		},
		newListByFactoryPagerFn: func(_, _ string, _ *armdatafactory.IntegrationRuntimesClientListByFactoryOptions) *runtime.Pager[armdatafactory.IntegrationRuntimesClientListByFactoryResponse] {
			return runtime.NewPager(runtime.PagingHandler[armdatafactory.IntegrationRuntimesClientListByFactoryResponse]{
				More: func(_ armdatafactory.IntegrationRuntimesClientListByFactoryResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armdatafactory.IntegrationRuntimesClientListByFactoryResponse) (armdatafactory.IntegrationRuntimesClientListByFactoryResponse, error) {
					return armdatafactory.IntegrationRuntimesClientListByFactoryResponse{
						IntegrationRuntimeListResponse: armdatafactory.IntegrationRuntimeListResponse{Value: mixedPage},
					}, nil
				},
			})
		},
	}
}
