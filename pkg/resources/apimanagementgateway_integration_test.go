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

const testApimGatewayNativeID = testApimServiceNativeID + "/gateways/gw1"

func newTestApiManagementGateway(api apiManagementGatewaysAPI) *ApiManagementGateway {
	return &ApiManagementGateway{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func apimGatewayDesired(description string) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":              "gw1",
		"resourceGroupName": "rg-1",
		"serviceName":       "apim1",
		"locationDataName":  "on-prem-dc",
		"locationDataCity":  "Karlsruhe",
		"description":       description,
	})
	return out
}

func TestApiManagementGateway_CRUD(t *testing.T) {
	gatewayResult := armapimanagement.GatewayContract{
		ID:   to.Ptr(testApimGatewayNativeID),
		Name: to.Ptr("gw1"),
		Properties: &armapimanagement.GatewayContractProperties{
			Description: to.Ptr("On-prem gateway"),
			LocationData: &armapimanagement.ResourceLocationDataContract{
				Name: to.Ptr("on-prem-dc"),
				City: to.Ptr("Karlsruhe"),
			},
		},
	}

	var sentCreate armapimanagement.GatewayContract
	var sentUpdate armapimanagement.GatewayContract
	var sawIfMatch string
	createCalls := 0
	deleteCalls := 0
	fake := &fakeApiManagementGatewaysAPI{
		createOrUpdateFn: func(_ context.Context, _, serviceName, gatewayID string, params armapimanagement.GatewayContract, _ *armapimanagement.GatewayClientCreateOrUpdateOptions) (armapimanagement.GatewayClientCreateOrUpdateResponse, error) {
			require.Equal(t, "apim1", serviceName)
			require.Equal(t, "gw1", gatewayID)
			sentCreate = params
			createCalls++
			return armapimanagement.GatewayClientCreateOrUpdateResponse{GatewayContract: gatewayResult}, nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ *armapimanagement.GatewayClientGetOptions) (armapimanagement.GatewayClientGetResponse, error) {
			return armapimanagement.GatewayClientGetResponse{GatewayContract: gatewayResult}, nil
		},
		updateFn: func(_ context.Context, _, _, _, ifMatch string, params armapimanagement.GatewayContract, _ *armapimanagement.GatewayClientUpdateOptions) (armapimanagement.GatewayClientUpdateResponse, error) {
			sawIfMatch = ifMatch
			sentUpdate = params
			return armapimanagement.GatewayClientUpdateResponse{}, nil
		},
		deleteFn: func(_ context.Context, _, _, _, ifMatch string, _ *armapimanagement.GatewayClientDeleteOptions) (armapimanagement.GatewayClientDeleteResponse, error) {
			sawIfMatch = ifMatch
			deleteCalls++
			return armapimanagement.GatewayClientDeleteResponse{}, nil
		},
		newListByServicePagerFn: func(_, _ string, _ *armapimanagement.GatewayClientListByServiceOptions) *runtime.Pager[armapimanagement.GatewayClientListByServiceResponse] {
			return runtime.NewPager(runtime.PagingHandler[armapimanagement.GatewayClientListByServiceResponse]{
				More: func(_ armapimanagement.GatewayClientListByServiceResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armapimanagement.GatewayClientListByServiceResponse) (armapimanagement.GatewayClientListByServiceResponse, error) {
					return armapimanagement.GatewayClientListByServiceResponse{
						GatewayCollection: armapimanagement.GatewayCollection{
							Value: []*armapimanagement.GatewayContract{{ID: to.Ptr(testApimGatewayNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestApiManagementGateway(fake)

	t.Run("Create_is_synchronous", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "gw1",
			Properties: apimGatewayDesired("On-prem gateway"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testApimGatewayNativeID, got.ProgressResult.NativeID)
		require.Empty(t, got.ProgressResult.RequestID)
		// The four flat locationData* properties are reassembled into ARM's
		// nested block.
		require.Equal(t, "on-prem-dc", *sentCreate.Properties.LocationData.Name)
		require.Equal(t, "Karlsruhe", *sentCreate.Properties.LocationData.City)
		require.Nil(t, sentCreate.Properties.LocationData.District)
	})

	t.Run("Create_requires_location_data_name", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "gw1", "resourceGroupName": "rg-1", "serviceName": "apim1",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "locationDataName is required")
	})

	t.Run("Create_requires_service", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "gw1", "resourceGroupName": "rg-1", "locationDataName": "dc",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "serviceName is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testApimGatewayNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "gw1", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "apim1", props["serviceName"])
		// ARM's nested block is flattened back out.
		require.Equal(t, "on-prem-dc", props["locationDataName"])
		require.Equal(t, "Karlsruhe", props["locationDataCity"])
		require.NotContains(t, props, "locationDataDistrict")
		require.Equal(t, "On-prem gateway", props["description"])
	})

	// The gateway PATCH answers 204 with no body, so the handler has to re-read
	// to report the current state rather than echoing an empty response.
	t.Run("Update_rereads_after_the_empty_patch", func(t *testing.T) {
		before := createCalls
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testApimGatewayNativeID,
			DesiredProperties: apimGatewayDesired("On-prem gateway v2"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, "*", sawIfMatch)
		require.Equal(t, "On-prem gateway v2", *sentUpdate.Properties.Description)
		require.Equal(t, before, createCalls)

		var props map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &props))
		require.Equal(t, "gw1", props["name"])
	})

	t.Run("Update_requires_location_data_name", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"resourceGroupName": "rg-1", "serviceName": "apim1"})
		_, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID: testApimGatewayNativeID, DesiredProperties: props,
		})
		require.ErrorContains(t, err, "locationDataName is required")
	})

	t.Run("Delete_is_synchronous", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testApimGatewayNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
		require.Equal(t, "*", sawIfMatch)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _, _, _ string, _ *armapimanagement.GatewayClientDeleteOptions) (armapimanagement.GatewayClientDeleteResponse, error) {
			return armapimanagement.GatewayClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testApimGatewayNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_service", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "serviceName": "apim1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testApimGatewayNativeID}, got.NativeIDs)
	})

	t.Run("List_without_parents_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})

	// This is what a Consumption-tier service answers: self-hosted gateways
	// need Developer or Premium, and the reason has to survive into the status
	// message or the failure is undiagnosable.
	t.Run("Unsupported_tier_maps_to_failure_with_a_reason", func(t *testing.T) {
		fake.createOrUpdateFn = func(_ context.Context, _, _, _ string, _ armapimanagement.GatewayContract, _ *armapimanagement.GatewayClientCreateOrUpdateOptions) (armapimanagement.GatewayClientCreateOrUpdateResponse, error) {
			return armapimanagement.GatewayClientCreateOrUpdateResponse{}, &azcore.ResponseError{StatusCode: 400}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "gw1", Properties: apimGatewayDesired("On-prem gateway"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.Equal(t, resource.OperationErrorCodeInvalidRequest, got.ProgressResult.ErrorCode)
		require.NotEmpty(t, got.ProgressResult.StatusMessage)
	})
}

func TestApiManagementGateway_ReadNotFound(t *testing.T) {
	fake := &fakeApiManagementGatewaysAPI{
		getFn: func(_ context.Context, _, _, _ string, _ *armapimanagement.GatewayClientGetOptions) (armapimanagement.GatewayClientGetResponse, error) {
			return armapimanagement.GatewayClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestApiManagementGateway(fake).Read(context.Background(),
		&resource.ReadRequest{NativeID: testApimGatewayNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeApiManagementGatewaysAPI struct {
	createOrUpdateFn        func(ctx context.Context, rgName, serviceName, gatewayID string, params armapimanagement.GatewayContract, options *armapimanagement.GatewayClientCreateOrUpdateOptions) (armapimanagement.GatewayClientCreateOrUpdateResponse, error)
	getFn                   func(ctx context.Context, rgName, serviceName, gatewayID string, options *armapimanagement.GatewayClientGetOptions) (armapimanagement.GatewayClientGetResponse, error)
	updateFn                func(ctx context.Context, rgName, serviceName, gatewayID, ifMatch string, params armapimanagement.GatewayContract, options *armapimanagement.GatewayClientUpdateOptions) (armapimanagement.GatewayClientUpdateResponse, error)
	deleteFn                func(ctx context.Context, rgName, serviceName, gatewayID, ifMatch string, options *armapimanagement.GatewayClientDeleteOptions) (armapimanagement.GatewayClientDeleteResponse, error)
	newListByServicePagerFn func(rgName, serviceName string, options *armapimanagement.GatewayClientListByServiceOptions) *runtime.Pager[armapimanagement.GatewayClientListByServiceResponse]
}

func (f *fakeApiManagementGatewaysAPI) CreateOrUpdate(ctx context.Context, rgName, serviceName, gatewayID string, params armapimanagement.GatewayContract, options *armapimanagement.GatewayClientCreateOrUpdateOptions) (armapimanagement.GatewayClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, serviceName, gatewayID, params, options)
}

func (f *fakeApiManagementGatewaysAPI) Get(ctx context.Context, rgName, serviceName, gatewayID string, options *armapimanagement.GatewayClientGetOptions) (armapimanagement.GatewayClientGetResponse, error) {
	return f.getFn(ctx, rgName, serviceName, gatewayID, options)
}

func (f *fakeApiManagementGatewaysAPI) Update(ctx context.Context, rgName, serviceName, gatewayID, ifMatch string, params armapimanagement.GatewayContract, options *armapimanagement.GatewayClientUpdateOptions) (armapimanagement.GatewayClientUpdateResponse, error) {
	return f.updateFn(ctx, rgName, serviceName, gatewayID, ifMatch, params, options)
}

func (f *fakeApiManagementGatewaysAPI) Delete(ctx context.Context, rgName, serviceName, gatewayID, ifMatch string, options *armapimanagement.GatewayClientDeleteOptions) (armapimanagement.GatewayClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, serviceName, gatewayID, ifMatch, options)
}

func (f *fakeApiManagementGatewaysAPI) NewListByServicePager(rgName, serviceName string, options *armapimanagement.GatewayClientListByServiceOptions) *runtime.Pager[armapimanagement.GatewayClientListByServiceResponse] {
	return f.newListByServicePagerFn(rgName, serviceName, options)
}
