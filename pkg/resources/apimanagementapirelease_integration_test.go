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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/apimanagement/armapimanagement"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testApimApiReleaseNativeID = testApimApiNativeID + "/releases/rel1"

func newTestApiManagementApiRelease(api apiManagementAPIReleasesAPI) *ApiManagementApiRelease {
	return &ApiManagementApiRelease{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func apimApiReleaseDesired(notes string) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":              "rel1",
		"resourceGroupName": "rg-1",
		"serviceName":       "apim1",
		"apiName":           "api1",
		"apiId":             testApimApiNativeID,
		"notes":             notes,
	})
	return out
}

func TestApiManagementApiRelease_CRUD(t *testing.T) {
	releaseResult := armapimanagement.APIReleaseContract{
		ID:   to.Ptr(testApimApiReleaseNativeID),
		Name: to.Ptr("rel1"),
		Properties: &armapimanagement.APIReleaseContractProperties{
			APIID:           to.Ptr(testApimApiNativeID),
			Notes:           to.Ptr("initial release"),
			CreatedDateTime: to.Ptr(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)),
			UpdatedDateTime: to.Ptr(time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)),
		},
	}

	var sentCreate armapimanagement.APIReleaseContract
	var sentUpdate armapimanagement.APIReleaseContract
	var sawIfMatch string
	createCalls := 0
	deleteCalls := 0
	fake := &fakeApiManagementAPIReleasesAPI{
		createOrUpdateFn: func(_ context.Context, _, _, apiID, releaseID string, params armapimanagement.APIReleaseContract, _ *armapimanagement.APIReleaseClientCreateOrUpdateOptions) (armapimanagement.APIReleaseClientCreateOrUpdateResponse, error) {
			require.Equal(t, "api1", apiID)
			require.Equal(t, "rel1", releaseID)
			sentCreate = params
			createCalls++
			return armapimanagement.APIReleaseClientCreateOrUpdateResponse{APIReleaseContract: releaseResult}, nil
		},
		getFn: func(_ context.Context, _, _, _, _ string, _ *armapimanagement.APIReleaseClientGetOptions) (armapimanagement.APIReleaseClientGetResponse, error) {
			return armapimanagement.APIReleaseClientGetResponse{APIReleaseContract: releaseResult}, nil
		},
		updateFn: func(_ context.Context, _, _, _, _, ifMatch string, params armapimanagement.APIReleaseContract, _ *armapimanagement.APIReleaseClientUpdateOptions) (armapimanagement.APIReleaseClientUpdateResponse, error) {
			sawIfMatch = ifMatch
			sentUpdate = params
			return armapimanagement.APIReleaseClientUpdateResponse{APIReleaseContract: releaseResult}, nil
		},
		deleteFn: func(_ context.Context, _, _, _, _, ifMatch string, _ *armapimanagement.APIReleaseClientDeleteOptions) (armapimanagement.APIReleaseClientDeleteResponse, error) {
			sawIfMatch = ifMatch
			deleteCalls++
			return armapimanagement.APIReleaseClientDeleteResponse{}, nil
		},
		newListByServicePagerFn: func(_, _, _ string, _ *armapimanagement.APIReleaseClientListByServiceOptions) *runtime.Pager[armapimanagement.APIReleaseClientListByServiceResponse] {
			return runtime.NewPager(runtime.PagingHandler[armapimanagement.APIReleaseClientListByServiceResponse]{
				More: func(_ armapimanagement.APIReleaseClientListByServiceResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armapimanagement.APIReleaseClientListByServiceResponse) (armapimanagement.APIReleaseClientListByServiceResponse, error) {
					return armapimanagement.APIReleaseClientListByServiceResponse{
						APIReleaseCollection: armapimanagement.APIReleaseCollection{
							Value: []*armapimanagement.APIReleaseContract{{ID: to.Ptr(testApimApiReleaseNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestApiManagementApiRelease(fake)

	t.Run("Create_is_synchronous", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "rel1",
			Properties: apimApiReleaseDesired("initial release"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testApimApiReleaseNativeID, got.ProgressResult.NativeID)
		require.Empty(t, got.ProgressResult.RequestID)
		// The body carries the full ARM id of the API, not its short name.
		require.Equal(t, testApimApiNativeID, *sentCreate.Properties.APIID)
	})

	t.Run("Create_accepts_a_revision_suffixed_api_id", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "rel1", "resourceGroupName": "rg-1", "serviceName": "apim1",
			"apiName": "api1", "apiId": testApimApiNativeID + ";rev=2",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.Equal(t, testApimApiNativeID+";rev=2", *sentCreate.Properties.APIID)
	})

	t.Run("Create_requires_api_id", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "rel1", "resourceGroupName": "rg-1", "serviceName": "apim1", "apiName": "api1",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "apiId is required")
	})

	t.Run("Create_requires_api_name", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "rel1", "resourceGroupName": "rg-1", "serviceName": "apim1",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "apiName is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testApimApiReleaseNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "rel1", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "apim1", props["serviceName"])
		require.Equal(t, "api1", props["apiName"])
		require.Equal(t, testApimApiNativeID, props["apiId"])
		require.Equal(t, "initial release", props["notes"])
	})

	// Both timestamps move on their own and would read back as drift.
	t.Run("Read_drops_timestamps", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testApimApiReleaseNativeID})
		require.NoError(t, err)
		require.NotContains(t, got.Properties, "createdDateTime")
		require.NotContains(t, got.Properties, "updatedDateTime")
	})

	t.Run("Update_uses_patch_with_wildcard_if_match", func(t *testing.T) {
		before := createCalls
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testApimApiReleaseNativeID,
			DesiredProperties: apimApiReleaseDesired("second release"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, "*", sawIfMatch)
		require.Equal(t, "second release", *sentUpdate.Properties.Notes)
		require.Equal(t, before, createCalls)
	})

	t.Run("Delete_is_synchronous", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testApimApiReleaseNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
		require.Equal(t, "*", sawIfMatch)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _, _, _, _ string, _ *armapimanagement.APIReleaseClientDeleteOptions) (armapimanagement.APIReleaseClientDeleteResponse, error) {
			return armapimanagement.APIReleaseClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testApimApiReleaseNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	// The SDK calls the pager ListByService but it is scoped to one API, so all
	// three scope values are needed.
	t.Run("List_by_api", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{
				"resourceGroupName": "rg-1", "serviceName": "apim1", "apiName": "api1",
			},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testApimApiReleaseNativeID}, got.NativeIDs)
	})

	t.Run("List_without_the_api_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "serviceName": "apim1"},
		})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure_with_a_reason", func(t *testing.T) {
		fake.createOrUpdateFn = func(_ context.Context, _, _, _, _ string, _ armapimanagement.APIReleaseContract, _ *armapimanagement.APIReleaseClientCreateOrUpdateOptions) (armapimanagement.APIReleaseClientCreateOrUpdateResponse, error) {
			return armapimanagement.APIReleaseClientCreateOrUpdateResponse{}, &azcore.ResponseError{StatusCode: 400}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "rel1", Properties: apimApiReleaseDesired("initial release"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.NotEmpty(t, got.ProgressResult.StatusMessage)
	})
}

func TestApiManagementApiRelease_ReadNotFound(t *testing.T) {
	fake := &fakeApiManagementAPIReleasesAPI{
		getFn: func(_ context.Context, _, _, _, _ string, _ *armapimanagement.APIReleaseClientGetOptions) (armapimanagement.APIReleaseClientGetResponse, error) {
			return armapimanagement.APIReleaseClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestApiManagementApiRelease(fake).Read(context.Background(),
		&resource.ReadRequest{NativeID: testApimApiReleaseNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeApiManagementAPIReleasesAPI struct {
	createOrUpdateFn        func(ctx context.Context, rgName, serviceName, apiID, releaseID string, params armapimanagement.APIReleaseContract, options *armapimanagement.APIReleaseClientCreateOrUpdateOptions) (armapimanagement.APIReleaseClientCreateOrUpdateResponse, error)
	getFn                   func(ctx context.Context, rgName, serviceName, apiID, releaseID string, options *armapimanagement.APIReleaseClientGetOptions) (armapimanagement.APIReleaseClientGetResponse, error)
	updateFn                func(ctx context.Context, rgName, serviceName, apiID, releaseID, ifMatch string, params armapimanagement.APIReleaseContract, options *armapimanagement.APIReleaseClientUpdateOptions) (armapimanagement.APIReleaseClientUpdateResponse, error)
	deleteFn                func(ctx context.Context, rgName, serviceName, apiID, releaseID, ifMatch string, options *armapimanagement.APIReleaseClientDeleteOptions) (armapimanagement.APIReleaseClientDeleteResponse, error)
	newListByServicePagerFn func(rgName, serviceName, apiID string, options *armapimanagement.APIReleaseClientListByServiceOptions) *runtime.Pager[armapimanagement.APIReleaseClientListByServiceResponse]
}

func (f *fakeApiManagementAPIReleasesAPI) CreateOrUpdate(ctx context.Context, rgName, serviceName, apiID, releaseID string, params armapimanagement.APIReleaseContract, options *armapimanagement.APIReleaseClientCreateOrUpdateOptions) (armapimanagement.APIReleaseClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, serviceName, apiID, releaseID, params, options)
}

func (f *fakeApiManagementAPIReleasesAPI) Get(ctx context.Context, rgName, serviceName, apiID, releaseID string, options *armapimanagement.APIReleaseClientGetOptions) (armapimanagement.APIReleaseClientGetResponse, error) {
	return f.getFn(ctx, rgName, serviceName, apiID, releaseID, options)
}

func (f *fakeApiManagementAPIReleasesAPI) Update(ctx context.Context, rgName, serviceName, apiID, releaseID, ifMatch string, params armapimanagement.APIReleaseContract, options *armapimanagement.APIReleaseClientUpdateOptions) (armapimanagement.APIReleaseClientUpdateResponse, error) {
	return f.updateFn(ctx, rgName, serviceName, apiID, releaseID, ifMatch, params, options)
}

func (f *fakeApiManagementAPIReleasesAPI) Delete(ctx context.Context, rgName, serviceName, apiID, releaseID, ifMatch string, options *armapimanagement.APIReleaseClientDeleteOptions) (armapimanagement.APIReleaseClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, serviceName, apiID, releaseID, ifMatch, options)
}

func (f *fakeApiManagementAPIReleasesAPI) NewListByServicePager(rgName, serviceName, apiID string, options *armapimanagement.APIReleaseClientListByServiceOptions) *runtime.Pager[armapimanagement.APIReleaseClientListByServiceResponse] {
	return f.newListByServicePagerFn(rgName, serviceName, apiID, options)
}
