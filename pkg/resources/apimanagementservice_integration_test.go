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

const testApimServiceNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.ApiManagement/service/apim1"

func newTestApiManagementService(api apiManagementServicesAPI) *ApiManagementService {
	return &ApiManagementService{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func apimServiceDesired(publisherName string) []byte {
	out, _ := json.Marshal(map[string]any{
		"Tags":              []any{map[string]any{"Key": "env", "Value": "conformance"}},
		"name":              "apim1",
		"location":          "eastus",
		"resourceGroupName": "rg-1",
		"publisherEmail":    "conformance@platform.engineering",
		"publisherName":     publisherName,
		"skuName":           "Consumption",
		"skuCapacity":       0,
	})
	return out
}

func TestApiManagementService_CRUD(t *testing.T) {
	svcResult := armapimanagement.ServiceResource{
		ID:       to.Ptr(testApimServiceNativeID),
		Name:     to.Ptr("apim1"),
		Location: to.Ptr("East US"),
		SKU: &armapimanagement.ServiceSKUProperties{
			Name:     to.Ptr(armapimanagement.SKUTypeConsumption),
			Capacity: to.Ptr(int32(0)),
		},
		Properties: &armapimanagement.ServiceProperties{
			PublisherEmail:          to.Ptr("conformance@platform.engineering"),
			PublisherName:           to.Ptr("Platform Engineering Labs"),
			NotificationSenderEmail: to.Ptr("apimgmt-noreply@mail.windowsazure.com"),
			PublicNetworkAccess:     to.Ptr(armapimanagement.PublicNetworkAccessEnabled),
			VirtualNetworkType:      to.Ptr(armapimanagement.VirtualNetworkTypeNone),
			GatewayURL:              to.Ptr("https://apim1.azure-api.net"),
			ManagementAPIURL:        to.Ptr("https://apim1.management.azure-api.net"),
			ProvisioningState:       to.Ptr("Succeeded"),
			TargetProvisioningState: to.Ptr(""),
			PlatformVersion:         to.Ptr(armapimanagement.PlatformVersionStv2),
			CreatedAtUTC:            to.Ptr(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)),
			PublicIPAddresses:       []*string{to.Ptr("20.0.0.1")},
		},
		Tags: map[string]*string{"env": to.Ptr("conformance")},
	}

	var sentCreate armapimanagement.ServiceResource
	var sentUpdate armapimanagement.ServiceUpdateParameters
	deleteCalls := 0
	fake := &fakeApiManagementServicesAPI{
		beginCreateOrUpdateFn: func(_ context.Context, _, name string, params armapimanagement.ServiceResource, _ *armapimanagement.ServiceClientBeginCreateOrUpdateOptions) (*runtime.Poller[armapimanagement.ServiceClientCreateOrUpdateResponse], error) {
			require.Equal(t, "apim1", name)
			sentCreate = params
			return newDonePoller(armapimanagement.ServiceClientCreateOrUpdateResponse{ServiceResource: svcResult}), nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armapimanagement.ServiceClientGetOptions) (armapimanagement.ServiceClientGetResponse, error) {
			return armapimanagement.ServiceClientGetResponse{ServiceResource: svcResult}, nil
		},
		beginUpdateFn: func(_ context.Context, _, _ string, params armapimanagement.ServiceUpdateParameters, _ *armapimanagement.ServiceClientBeginUpdateOptions) (*runtime.Poller[armapimanagement.ServiceClientUpdateResponse], error) {
			sentUpdate = params
			return newDonePoller(armapimanagement.ServiceClientUpdateResponse{ServiceResource: svcResult}), nil
		},
		beginDeleteFn: func(_ context.Context, _, _ string, _ *armapimanagement.ServiceClientBeginDeleteOptions) (*runtime.Poller[armapimanagement.ServiceClientDeleteResponse], error) {
			deleteCalls++
			return newDonePoller(armapimanagement.ServiceClientDeleteResponse{}), nil
		},
		newListPagerFn: func(_ *armapimanagement.ServiceClientListOptions) *runtime.Pager[armapimanagement.ServiceClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armapimanagement.ServiceClientListResponse]{
				More: func(_ armapimanagement.ServiceClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armapimanagement.ServiceClientListResponse) (armapimanagement.ServiceClientListResponse, error) {
					return armapimanagement.ServiceClientListResponse{
						ServiceListResult: armapimanagement.ServiceListResult{
							Value: []*armapimanagement.ServiceResource{
								{ID: to.Ptr(testApimServiceNativeID)},
								{ID: to.Ptr("/subscriptions/sub-1/resourceGroups/rg-2/providers/Microsoft.ApiManagement/service/apim2")},
							},
						},
					}, nil
				},
			})
		},
		newListByResourceGroupPagerFn: func(_ string, _ *armapimanagement.ServiceClientListByResourceGroupOptions) *runtime.Pager[armapimanagement.ServiceClientListByResourceGroupResponse] {
			return runtime.NewPager(runtime.PagingHandler[armapimanagement.ServiceClientListByResourceGroupResponse]{
				More: func(_ armapimanagement.ServiceClientListByResourceGroupResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armapimanagement.ServiceClientListByResourceGroupResponse) (armapimanagement.ServiceClientListByResourceGroupResponse, error) {
					return armapimanagement.ServiceClientListByResourceGroupResponse{
						ServiceListResult: armapimanagement.ServiceListResult{
							Value: []*armapimanagement.ServiceResource{{ID: to.Ptr(testApimServiceNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestApiManagementService(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "apim1",
			Properties: apimServiceDesired("Platform Engineering Labs"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testApimServiceNativeID, got.ProgressResult.NativeID)

		require.Equal(t, armapimanagement.SKUTypeConsumption, *sentCreate.SKU.Name)
		require.Equal(t, int32(0), *sentCreate.SKU.Capacity)
		require.Equal(t, "conformance@platform.engineering", *sentCreate.Properties.PublisherEmail)
		require.Equal(t, "eastus", *sentCreate.Location)
		require.Equal(t, "conformance", *sentCreate.Tags["env"])
		// No identity was declared, so none is sent: ARM must not be told to
		// remove one that is not there.
		require.Nil(t, sentCreate.Identity)
	})

	// Consumption has no scale units, so an omitted capacity has to become 0
	// rather than being left out or sent as 1: ARM rejects both.
	t.Run("Create_floors_consumption_capacity", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "apim1", "location": "eastus", "resourceGroupName": "rg-1",
			"publisherEmail": "a@b.c", "publisherName": "n", "skuName": "Consumption",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.Equal(t, int32(0), *sentCreate.SKU.Capacity)
	})

	// Every dedicated tier needs at least one unit, so an omitted capacity
	// defaults to 1 there instead.
	t.Run("Create_defaults_dedicated_capacity_to_one", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "apim1", "location": "eastus", "resourceGroupName": "rg-1",
			"publisherEmail": "a@b.c", "publisherName": "n", "skuName": "Developer",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.Equal(t, int32(1), *sentCreate.SKU.Capacity)
	})

	t.Run("Create_sends_system_assigned_identity", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "apim1", "location": "eastus", "resourceGroupName": "rg-1",
			"publisherEmail": "a@b.c", "publisherName": "n", "skuName": "Consumption",
			"skuCapacity": 0, "identityType": "SystemAssigned",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.Equal(t, armapimanagement.ApimIdentityTypeSystemAssigned, *sentCreate.Identity.Type)
	})

	t.Run("Create_requires_publisher", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "apim1", "location": "eastus", "resourceGroupName": "rg-1", "skuName": "Consumption",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "publisherEmail is required")
	})

	t.Run("Create_requires_sku", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "apim1", "location": "eastus", "resourceGroupName": "rg-1",
			"publisherEmail": "a@b.c", "publisherName": "n",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "skuName is required")
	})

	t.Run("Create_requires_resource_group", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "apim1", "location": "eastus"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "resourceGroupName is required")
	})

	t.Run("Create_in_progress_yields_resume_token", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, _ armapimanagement.ServiceResource, _ *armapimanagement.ServiceClientBeginCreateOrUpdateOptions) (*runtime.Poller[armapimanagement.ServiceClientCreateOrUpdateResponse], error) {
			return newInProgressPoller[armapimanagement.ServiceClientCreateOrUpdateResponse](), nil
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "apim1",
			Properties: apimServiceDesired("Platform Engineering Labs"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusInProgress, got.ProgressResult.OperationStatus)
		require.NotEmpty(t, got.ProgressResult.RequestID)
		// The native ID has to be predicted: the LRO has no body yet.
		require.Equal(t, testApimServiceNativeID, got.ProgressResult.NativeID)

		var reqID lroRequestID
		require.NoError(t, json.Unmarshal([]byte(got.ProgressResult.RequestID), &reqID))
		require.Equal(t, lroOpCreate, reqID.OperationType)
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testApimServiceNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "apim1", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		// ARM answers with the display form of the region; it has to be
		// normalized or every read is drift.
		require.Equal(t, "eastus", props["location"])
		require.Equal(t, "Consumption", props["skuName"])
		require.EqualValues(t, 0, props["skuCapacity"])
		require.Equal(t, "https://apim1.azure-api.net", props["gatewayUrl"])
		require.Equal(t, "None", props["virtualNetworkType"])
	})

	// None of these is desired state, and the timestamp and platform version
	// move on their own: all would read back as drift.
	t.Run("Read_drops_service_state", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testApimServiceNativeID})
		require.NoError(t, err)
		for _, key := range []string{"provisioningState", "targetProvisioningState",
			"createdAtUtc", "platformVersion", "publicIPAddresses", "customProperties"} {
			require.NotContains(t, got.Properties, key)
		}
	})

	// A PATCH on an API Management instance is an LRO too, so the update has to
	// carry an update-flavoured resume token rather than reporting success.
	t.Run("Update_is_an_lro", func(t *testing.T) {
		fake.beginUpdateFn = func(_ context.Context, _, _ string, params armapimanagement.ServiceUpdateParameters, _ *armapimanagement.ServiceClientBeginUpdateOptions) (*runtime.Poller[armapimanagement.ServiceClientUpdateResponse], error) {
			sentUpdate = params
			return newInProgressPoller[armapimanagement.ServiceClientUpdateResponse](), nil
		}
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testApimServiceNativeID,
			DesiredProperties: apimServiceDesired("Renamed Publisher"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusInProgress, got.ProgressResult.OperationStatus)
		require.Equal(t, "Renamed Publisher", *sentUpdate.Properties.PublisherName)

		var reqID lroRequestID
		require.NoError(t, json.Unmarshal([]byte(got.ProgressResult.RequestID), &reqID))
		require.Equal(t, lroOpUpdate, reqID.OperationType)
	})

	t.Run("Update_completes_synchronously_when_poller_is_done", func(t *testing.T) {
		fake.beginUpdateFn = func(_ context.Context, _, _ string, params armapimanagement.ServiceUpdateParameters, _ *armapimanagement.ServiceClientBeginUpdateOptions) (*runtime.Poller[armapimanagement.ServiceClientUpdateResponse], error) {
			sentUpdate = params
			return newDonePoller(armapimanagement.ServiceClientUpdateResponse{ServiceResource: svcResult}), nil
		}
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testApimServiceNativeID,
			DesiredProperties: apimServiceDesired("Platform Engineering Labs"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Empty(t, got.ProgressResult.RequestID)
	})

	t.Run("Delete", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testApimServiceNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _ string, _ *armapimanagement.ServiceClientBeginDeleteOptions) (*runtime.Poller[armapimanagement.ServiceClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testApimServiceNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_resource_group", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testApimServiceNativeID}, got.NativeIDs)
	})

	t.Run("List_without_group_is_subscription_wide", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 2)
	})

	t.Run("Azure_error_maps_to_failure_with_a_reason", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, _ armapimanagement.ServiceResource, _ *armapimanagement.ServiceClientBeginCreateOrUpdateOptions) (*runtime.Poller[armapimanagement.ServiceClientCreateOrUpdateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 409}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "apim1", Properties: apimServiceDesired("Platform Engineering Labs"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.Equal(t, resource.OperationErrorCodeResourceConflict, got.ProgressResult.ErrorCode)
		// The provider's own message must survive: a failed create that logs
		// only "Failed" is undiagnosable.
		require.NotEmpty(t, got.ProgressResult.StatusMessage)
	})
}

func TestApiManagementService_ReadNotFound(t *testing.T) {
	fake := &fakeApiManagementServicesAPI{
		getFn: func(_ context.Context, _, _ string, _ *armapimanagement.ServiceClientGetOptions) (armapimanagement.ServiceClientGetResponse, error) {
			return armapimanagement.ServiceClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestApiManagementService(fake).Read(context.Background(), &resource.ReadRequest{NativeID: testApimServiceNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// A child ARM ID must not parse as a service: the type chain has to match
// exactly, or a policy's ID would be read as its parent's.
func TestApiManagementService_RejectsChildID(t *testing.T) {
	_, _, err := apiManagementServiceIDParts(testApimServiceNativeID + "/apis/api1")
	require.Error(t, err)
}

// --- Test helpers ---

type fakeApiManagementServicesAPI struct {
	beginCreateOrUpdateFn         func(ctx context.Context, rgName, name string, params armapimanagement.ServiceResource, options *armapimanagement.ServiceClientBeginCreateOrUpdateOptions) (*runtime.Poller[armapimanagement.ServiceClientCreateOrUpdateResponse], error)
	getFn                         func(ctx context.Context, rgName, name string, options *armapimanagement.ServiceClientGetOptions) (armapimanagement.ServiceClientGetResponse, error)
	beginUpdateFn                 func(ctx context.Context, rgName, name string, params armapimanagement.ServiceUpdateParameters, options *armapimanagement.ServiceClientBeginUpdateOptions) (*runtime.Poller[armapimanagement.ServiceClientUpdateResponse], error)
	beginDeleteFn                 func(ctx context.Context, rgName, name string, options *armapimanagement.ServiceClientBeginDeleteOptions) (*runtime.Poller[armapimanagement.ServiceClientDeleteResponse], error)
	newListPagerFn                func(options *armapimanagement.ServiceClientListOptions) *runtime.Pager[armapimanagement.ServiceClientListResponse]
	newListByResourceGroupPagerFn func(rgName string, options *armapimanagement.ServiceClientListByResourceGroupOptions) *runtime.Pager[armapimanagement.ServiceClientListByResourceGroupResponse]
}

func (f *fakeApiManagementServicesAPI) BeginCreateOrUpdate(ctx context.Context, rgName, name string, params armapimanagement.ServiceResource, options *armapimanagement.ServiceClientBeginCreateOrUpdateOptions) (*runtime.Poller[armapimanagement.ServiceClientCreateOrUpdateResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, rgName, name, params, options)
}

func (f *fakeApiManagementServicesAPI) Get(ctx context.Context, rgName, name string, options *armapimanagement.ServiceClientGetOptions) (armapimanagement.ServiceClientGetResponse, error) {
	return f.getFn(ctx, rgName, name, options)
}

func (f *fakeApiManagementServicesAPI) BeginUpdate(ctx context.Context, rgName, name string, params armapimanagement.ServiceUpdateParameters, options *armapimanagement.ServiceClientBeginUpdateOptions) (*runtime.Poller[armapimanagement.ServiceClientUpdateResponse], error) {
	return f.beginUpdateFn(ctx, rgName, name, params, options)
}

func (f *fakeApiManagementServicesAPI) BeginDelete(ctx context.Context, rgName, name string, options *armapimanagement.ServiceClientBeginDeleteOptions) (*runtime.Poller[armapimanagement.ServiceClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, name, options)
}

func (f *fakeApiManagementServicesAPI) NewListPager(options *armapimanagement.ServiceClientListOptions) *runtime.Pager[armapimanagement.ServiceClientListResponse] {
	return f.newListPagerFn(options)
}

func (f *fakeApiManagementServicesAPI) NewListByResourceGroupPager(rgName string, options *armapimanagement.ServiceClientListByResourceGroupOptions) *runtime.Pager[armapimanagement.ServiceClientListByResourceGroupResponse] {
	return f.newListByResourceGroupPagerFn(rgName, options)
}
