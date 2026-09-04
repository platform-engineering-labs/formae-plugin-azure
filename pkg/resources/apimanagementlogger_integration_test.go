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

const testApimLoggerNativeID = testApimServiceNativeID + "/loggers/appinsights"

func newTestApiManagementLogger(api apiManagementLoggersAPI) *ApiManagementLogger {
	return &ApiManagementLogger{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func apimLoggerDesired(description string) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":              "appinsights",
		"resourceGroupName": "rg-1",
		"serviceName":       "apim1",
		"loggerType":        "applicationInsights",
		"description":       description,
		"credentials": map[string]string{
			"instrumentationKey": "00000000-1111-2222-3333-444444444444",
		},
		"resourceId": "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Insights/components/ai1",
		"isBuffered": true,
	})
	return out
}

func TestApiManagementLogger_CRUD(t *testing.T) {
	// Note the credentials ARM answers with: not the key that was sent, but a
	// reference to the hidden secret named value ARM moved it into.
	loggerResult := armapimanagement.LoggerContract{
		ID:   to.Ptr(testApimLoggerNativeID),
		Name: to.Ptr("appinsights"),
		Properties: &armapimanagement.LoggerContractProperties{
			LoggerType:  to.Ptr(armapimanagement.LoggerTypeApplicationInsights),
			Description: to.Ptr("Conformance logger"),
			Credentials: map[string]*string{
				"instrumentationKey": to.Ptr("{{Logger-Credentials-5f0d1a}}"),
			},
			ResourceID: to.Ptr("/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Insights/components/ai1"),
			IsBuffered: to.Ptr(true),
		},
	}

	var sentCreate armapimanagement.LoggerContract
	var sentUpdate armapimanagement.LoggerUpdateContract
	var sawIfMatch string
	deleteCalls := 0
	fake := &fakeApiManagementLoggersAPI{
		createOrUpdateFn: func(_ context.Context, _, serviceName, loggerID string, params armapimanagement.LoggerContract, _ *armapimanagement.LoggerClientCreateOrUpdateOptions) (armapimanagement.LoggerClientCreateOrUpdateResponse, error) {
			require.Equal(t, "apim1", serviceName)
			require.NotEmpty(t, loggerID)
			sentCreate = params
			return armapimanagement.LoggerClientCreateOrUpdateResponse{LoggerContract: loggerResult}, nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ *armapimanagement.LoggerClientGetOptions) (armapimanagement.LoggerClientGetResponse, error) {
			return armapimanagement.LoggerClientGetResponse{LoggerContract: loggerResult}, nil
		},
		updateFn: func(_ context.Context, _, _, _, ifMatch string, params armapimanagement.LoggerUpdateContract, _ *armapimanagement.LoggerClientUpdateOptions) (armapimanagement.LoggerClientUpdateResponse, error) {
			sawIfMatch = ifMatch
			sentUpdate = params
			return armapimanagement.LoggerClientUpdateResponse{LoggerContract: loggerResult}, nil
		},
		deleteFn: func(_ context.Context, _, _, _, ifMatch string, _ *armapimanagement.LoggerClientDeleteOptions) (armapimanagement.LoggerClientDeleteResponse, error) {
			sawIfMatch = ifMatch
			deleteCalls++
			return armapimanagement.LoggerClientDeleteResponse{}, nil
		},
		newListByServicePagerFn: func(_, _ string, _ *armapimanagement.LoggerClientListByServiceOptions) *runtime.Pager[armapimanagement.LoggerClientListByServiceResponse] {
			return runtime.NewPager(runtime.PagingHandler[armapimanagement.LoggerClientListByServiceResponse]{
				More: func(_ armapimanagement.LoggerClientListByServiceResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armapimanagement.LoggerClientListByServiceResponse) (armapimanagement.LoggerClientListByServiceResponse, error) {
					return armapimanagement.LoggerClientListByServiceResponse{
						LoggerCollection: armapimanagement.LoggerCollection{
							Value: []*armapimanagement.LoggerContract{{ID: to.Ptr(testApimLoggerNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestApiManagementLogger(fake)

	t.Run("Create_is_synchronous", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "appinsights",
			Properties: apimLoggerDesired("Conformance logger"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testApimLoggerNativeID, got.ProgressResult.NativeID)
		require.Empty(t, got.ProgressResult.RequestID)
		require.Equal(t, armapimanagement.LoggerTypeApplicationInsights, *sentCreate.Properties.LoggerType)
		require.Equal(t, "00000000-1111-2222-3333-444444444444",
			*sentCreate.Properties.Credentials["instrumentationKey"])
	})

	t.Run("Create_sends_no_credentials_block_for_azure_monitor", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "azmon", "resourceGroupName": "rg-1", "serviceName": "apim1",
			"loggerType": "azureMonitor",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.Nil(t, sentCreate.Properties.Credentials)
	})

	t.Run("Create_requires_logger_type", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "l", "resourceGroupName": "rg-1", "serviceName": "apim1",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "loggerType is required")
	})

	// The whole reason credentials is write-only: what ARM hands back is a
	// reference to a hidden secret named value, not the key that was declared.
	t.Run("Read_never_reports_the_credentials_ARM_rewrote", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testApimLoggerNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "appinsights", props["name"])
		require.Equal(t, "applicationInsights", props["loggerType"])
		require.Equal(t, true, props["isBuffered"])
		require.NotContains(t, props, "credentials")
	})

	t.Run("Update_uses_patch_with_wildcard_if_match", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testApimLoggerNativeID,
			DesiredProperties: apimLoggerDesired("Conformance logger v2"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, "*", sawIfMatch)
		// LoggerUpdateContract wraps LoggerUpdateParameters, which IS the
		// properties bag rather than a second envelope.
		require.Equal(t, "Conformance logger v2", *sentUpdate.Properties.Description)
	})

	t.Run("Delete_is_synchronous", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testApimLoggerNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
		require.Equal(t, "*", sawIfMatch)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _, _, _ string, _ *armapimanagement.LoggerClientDeleteOptions) (armapimanagement.LoggerClientDeleteResponse, error) {
			return armapimanagement.LoggerClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testApimLoggerNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_service", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "serviceName": "apim1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testApimLoggerNativeID}, got.NativeIDs)
	})

	t.Run("List_without_parents_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure_with_a_reason", func(t *testing.T) {
		fake.createOrUpdateFn = func(_ context.Context, _, _, _ string, _ armapimanagement.LoggerContract, _ *armapimanagement.LoggerClientCreateOrUpdateOptions) (armapimanagement.LoggerClientCreateOrUpdateResponse, error) {
			return armapimanagement.LoggerClientCreateOrUpdateResponse{}, &azcore.ResponseError{StatusCode: 400}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "appinsights", Properties: apimLoggerDesired("Conformance logger"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.NotEmpty(t, got.ProgressResult.StatusMessage)
	})
}

func TestApiManagementLogger_ReadNotFound(t *testing.T) {
	fake := &fakeApiManagementLoggersAPI{
		getFn: func(_ context.Context, _, _, _ string, _ *armapimanagement.LoggerClientGetOptions) (armapimanagement.LoggerClientGetResponse, error) {
			return armapimanagement.LoggerClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestApiManagementLogger(fake).Read(context.Background(),
		&resource.ReadRequest{NativeID: testApimLoggerNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeApiManagementLoggersAPI struct {
	createOrUpdateFn        func(ctx context.Context, rgName, serviceName, loggerID string, params armapimanagement.LoggerContract, options *armapimanagement.LoggerClientCreateOrUpdateOptions) (armapimanagement.LoggerClientCreateOrUpdateResponse, error)
	getFn                   func(ctx context.Context, rgName, serviceName, loggerID string, options *armapimanagement.LoggerClientGetOptions) (armapimanagement.LoggerClientGetResponse, error)
	updateFn                func(ctx context.Context, rgName, serviceName, loggerID, ifMatch string, params armapimanagement.LoggerUpdateContract, options *armapimanagement.LoggerClientUpdateOptions) (armapimanagement.LoggerClientUpdateResponse, error)
	deleteFn                func(ctx context.Context, rgName, serviceName, loggerID, ifMatch string, options *armapimanagement.LoggerClientDeleteOptions) (armapimanagement.LoggerClientDeleteResponse, error)
	newListByServicePagerFn func(rgName, serviceName string, options *armapimanagement.LoggerClientListByServiceOptions) *runtime.Pager[armapimanagement.LoggerClientListByServiceResponse]
}

func (f *fakeApiManagementLoggersAPI) CreateOrUpdate(ctx context.Context, rgName, serviceName, loggerID string, params armapimanagement.LoggerContract, options *armapimanagement.LoggerClientCreateOrUpdateOptions) (armapimanagement.LoggerClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, serviceName, loggerID, params, options)
}

func (f *fakeApiManagementLoggersAPI) Get(ctx context.Context, rgName, serviceName, loggerID string, options *armapimanagement.LoggerClientGetOptions) (armapimanagement.LoggerClientGetResponse, error) {
	return f.getFn(ctx, rgName, serviceName, loggerID, options)
}

func (f *fakeApiManagementLoggersAPI) Update(ctx context.Context, rgName, serviceName, loggerID, ifMatch string, params armapimanagement.LoggerUpdateContract, options *armapimanagement.LoggerClientUpdateOptions) (armapimanagement.LoggerClientUpdateResponse, error) {
	return f.updateFn(ctx, rgName, serviceName, loggerID, ifMatch, params, options)
}

func (f *fakeApiManagementLoggersAPI) Delete(ctx context.Context, rgName, serviceName, loggerID, ifMatch string, options *armapimanagement.LoggerClientDeleteOptions) (armapimanagement.LoggerClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, serviceName, loggerID, ifMatch, options)
}

func (f *fakeApiManagementLoggersAPI) NewListByServicePager(rgName, serviceName string, options *armapimanagement.LoggerClientListByServiceOptions) *runtime.Pager[armapimanagement.LoggerClientListByServiceResponse] {
	return f.newListByServicePagerFn(rgName, serviceName, options)
}
