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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/apimanagement/armapimanagement"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testApimApiVersionSetNativeID = testApimServiceNativeID + "/apiVersionSets/vs1"

func newTestApiManagementApiVersionSet(api apiManagementAPIVersionSetsAPI) *ApiManagementApiVersionSet {
	return &ApiManagementApiVersionSet{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func apimApiVersionSetDesired(displayName string) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":              "vs1",
		"resourceGroupName": "rg-1",
		"serviceName":       "apim1",
		"displayName":       displayName,
		"versioningScheme":  "Segment",
	})
	return out
}

func TestApiManagementApiVersionSet_CRUD(t *testing.T) {
	setResult := armapimanagement.APIVersionSetContract{
		ID:   to.Ptr(testApimApiVersionSetNativeID),
		Name: to.Ptr("vs1"),
		Properties: &armapimanagement.APIVersionSetContractProperties{
			DisplayName:      to.Ptr("Orders versions"),
			VersioningScheme: to.Ptr(armapimanagement.VersioningSchemeSegment),
			Description:      to.Ptr("Versioned orders API"),
		},
	}

	var sentCreate armapimanagement.APIVersionSetContract
	var sentUpdate armapimanagement.APIVersionSetUpdateParameters
	var sawIfMatch string
	createCalls := 0
	deleteCalls := 0
	fake := &fakeApiManagementAPIVersionSetsAPI{
		createOrUpdateFn: func(_ context.Context, _, serviceName, versionSetID string, params armapimanagement.APIVersionSetContract, _ *armapimanagement.APIVersionSetClientCreateOrUpdateOptions) (armapimanagement.APIVersionSetClientCreateOrUpdateResponse, error) {
			require.Equal(t, "apim1", serviceName)
			require.Equal(t, "vs1", versionSetID)
			sentCreate = params
			createCalls++
			return armapimanagement.APIVersionSetClientCreateOrUpdateResponse{APIVersionSetContract: setResult}, nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ *armapimanagement.APIVersionSetClientGetOptions) (armapimanagement.APIVersionSetClientGetResponse, error) {
			return armapimanagement.APIVersionSetClientGetResponse{APIVersionSetContract: setResult}, nil
		},
		updateFn: func(_ context.Context, _, _, _, ifMatch string, params armapimanagement.APIVersionSetUpdateParameters, _ *armapimanagement.APIVersionSetClientUpdateOptions) (armapimanagement.APIVersionSetClientUpdateResponse, error) {
			sawIfMatch = ifMatch
			sentUpdate = params
			return armapimanagement.APIVersionSetClientUpdateResponse{APIVersionSetContract: setResult}, nil
		},
		deleteFn: func(_ context.Context, _, _, _, ifMatch string, _ *armapimanagement.APIVersionSetClientDeleteOptions) (armapimanagement.APIVersionSetClientDeleteResponse, error) {
			sawIfMatch = ifMatch
			deleteCalls++
			return armapimanagement.APIVersionSetClientDeleteResponse{}, nil
		},
		newListByServicePagerFn: func(_, _ string, _ *armapimanagement.APIVersionSetClientListByServiceOptions) *runtime.Pager[armapimanagement.APIVersionSetClientListByServiceResponse] {
			return runtime.NewPager(runtime.PagingHandler[armapimanagement.APIVersionSetClientListByServiceResponse]{
				More: func(_ armapimanagement.APIVersionSetClientListByServiceResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armapimanagement.APIVersionSetClientListByServiceResponse) (armapimanagement.APIVersionSetClientListByServiceResponse, error) {
					return armapimanagement.APIVersionSetClientListByServiceResponse{
						APIVersionSetCollection: armapimanagement.APIVersionSetCollection{
							Value: []*armapimanagement.APIVersionSetContract{{ID: to.Ptr(testApimApiVersionSetNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestApiManagementApiVersionSet(fake)

	t.Run("Create_is_synchronous", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "vs1",
			Properties: apimApiVersionSetDesired("Orders versions"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testApimApiVersionSetNativeID, got.ProgressResult.NativeID)
		require.Empty(t, got.ProgressResult.RequestID)
		require.Equal(t, armapimanagement.VersioningSchemeSegment, *sentCreate.Properties.VersioningScheme)
		// Segment versioning carries neither name, and ARM rejects a name that
		// does not match the scheme, so both must stay absent.
		require.Nil(t, sentCreate.Properties.VersionHeaderName)
		require.Nil(t, sentCreate.Properties.VersionQueryName)
	})

	t.Run("Create_sends_a_header_name_for_header_versioning", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "vs1", "resourceGroupName": "rg-1", "serviceName": "apim1",
			"displayName": "Orders versions", "versioningScheme": "Header",
			"versionHeaderName": "Api-Version",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.Equal(t, "Api-Version", *sentCreate.Properties.VersionHeaderName)
	})

	t.Run("Create_requires_versioning_scheme", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "vs1", "resourceGroupName": "rg-1", "serviceName": "apim1", "displayName": "Orders",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "versioningScheme is required")
	})

	t.Run("Create_requires_display_name", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "vs1", "resourceGroupName": "rg-1", "serviceName": "apim1",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "displayName is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testApimApiVersionSetNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "vs1", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "apim1", props["serviceName"])
		require.Equal(t, "Segment", props["versioningScheme"])
		require.Equal(t, "Versioned orders API", props["description"])
	})

	t.Run("Update_uses_patch_with_wildcard_if_match", func(t *testing.T) {
		before := createCalls
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testApimApiVersionSetNativeID,
			DesiredProperties: apimApiVersionSetDesired("Orders versions v2"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, "*", sawIfMatch)
		require.Equal(t, "Orders versions v2", *sentUpdate.Properties.DisplayName)
		require.Equal(t, before, createCalls)
	})

	t.Run("Delete_is_synchronous", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testApimApiVersionSetNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
		require.Equal(t, "*", sawIfMatch)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _, _, _ string, _ *armapimanagement.APIVersionSetClientDeleteOptions) (armapimanagement.APIVersionSetClientDeleteResponse, error) {
			return armapimanagement.APIVersionSetClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testApimApiVersionSetNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_service", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "serviceName": "apim1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testApimApiVersionSetNativeID}, got.NativeIDs)
	})

	t.Run("List_without_parents_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure_with_a_reason", func(t *testing.T) {
		fake.createOrUpdateFn = func(_ context.Context, _, _, _ string, _ armapimanagement.APIVersionSetContract, _ *armapimanagement.APIVersionSetClientCreateOrUpdateOptions) (armapimanagement.APIVersionSetClientCreateOrUpdateResponse, error) {
			return armapimanagement.APIVersionSetClientCreateOrUpdateResponse{}, &azcore.ResponseError{StatusCode: 400}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "vs1", Properties: apimApiVersionSetDesired("Orders versions"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.NotEmpty(t, got.ProgressResult.StatusMessage)
	})
}

func TestApiManagementApiVersionSet_ReadNotFound(t *testing.T) {
	fake := &fakeApiManagementAPIVersionSetsAPI{
		getFn: func(_ context.Context, _, _, _ string, _ *armapimanagement.APIVersionSetClientGetOptions) (armapimanagement.APIVersionSetClientGetResponse, error) {
			return armapimanagement.APIVersionSetClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestApiManagementApiVersionSet(fake).Read(context.Background(),
		&resource.ReadRequest{NativeID: testApimApiVersionSetNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeApiManagementAPIVersionSetsAPI struct {
	createOrUpdateFn        func(ctx context.Context, rgName, serviceName, versionSetID string, params armapimanagement.APIVersionSetContract, options *armapimanagement.APIVersionSetClientCreateOrUpdateOptions) (armapimanagement.APIVersionSetClientCreateOrUpdateResponse, error)
	getFn                   func(ctx context.Context, rgName, serviceName, versionSetID string, options *armapimanagement.APIVersionSetClientGetOptions) (armapimanagement.APIVersionSetClientGetResponse, error)
	updateFn                func(ctx context.Context, rgName, serviceName, versionSetID, ifMatch string, params armapimanagement.APIVersionSetUpdateParameters, options *armapimanagement.APIVersionSetClientUpdateOptions) (armapimanagement.APIVersionSetClientUpdateResponse, error)
	deleteFn                func(ctx context.Context, rgName, serviceName, versionSetID, ifMatch string, options *armapimanagement.APIVersionSetClientDeleteOptions) (armapimanagement.APIVersionSetClientDeleteResponse, error)
	newListByServicePagerFn func(rgName, serviceName string, options *armapimanagement.APIVersionSetClientListByServiceOptions) *runtime.Pager[armapimanagement.APIVersionSetClientListByServiceResponse]
}

func (f *fakeApiManagementAPIVersionSetsAPI) CreateOrUpdate(ctx context.Context, rgName, serviceName, versionSetID string, params armapimanagement.APIVersionSetContract, options *armapimanagement.APIVersionSetClientCreateOrUpdateOptions) (armapimanagement.APIVersionSetClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, serviceName, versionSetID, params, options)
}

func (f *fakeApiManagementAPIVersionSetsAPI) Get(ctx context.Context, rgName, serviceName, versionSetID string, options *armapimanagement.APIVersionSetClientGetOptions) (armapimanagement.APIVersionSetClientGetResponse, error) {
	return f.getFn(ctx, rgName, serviceName, versionSetID, options)
}

func (f *fakeApiManagementAPIVersionSetsAPI) Update(ctx context.Context, rgName, serviceName, versionSetID, ifMatch string, params armapimanagement.APIVersionSetUpdateParameters, options *armapimanagement.APIVersionSetClientUpdateOptions) (armapimanagement.APIVersionSetClientUpdateResponse, error) {
	return f.updateFn(ctx, rgName, serviceName, versionSetID, ifMatch, params, options)
}

func (f *fakeApiManagementAPIVersionSetsAPI) Delete(ctx context.Context, rgName, serviceName, versionSetID, ifMatch string, options *armapimanagement.APIVersionSetClientDeleteOptions) (armapimanagement.APIVersionSetClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, serviceName, versionSetID, ifMatch, options)
}

func (f *fakeApiManagementAPIVersionSetsAPI) NewListByServicePager(rgName, serviceName string, options *armapimanagement.APIVersionSetClientListByServiceOptions) *runtime.Pager[armapimanagement.APIVersionSetClientListByServiceResponse] {
	return f.newListByServicePagerFn(rgName, serviceName, options)
}
