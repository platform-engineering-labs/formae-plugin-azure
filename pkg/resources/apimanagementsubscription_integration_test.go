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

const testApimSubscriptionNativeID = testApimServiceNativeID + "/subscriptions/conformance-sub"

// The relative form ARM accepts on the way in, and the absolute id it always
// answers with. The two name the same product.
const (
	testApimSubRelativeScope = "/products/starter"
	testApimSubAbsoluteScope = testApimServiceNativeID + "/products/starter"
)

func newTestApiManagementSubscription(api apiManagementSubscriptionsAPI) *ApiManagementSubscription {
	return &ApiManagementSubscription{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func apimSubscriptionDesired(displayName, scope string) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":              "conformance-sub",
		"resourceGroupName": "rg-1",
		"serviceName":       "apim1",
		"displayName":       displayName,
		"scope":             scope,
		"state":             "active",
		"allowTracing":      false,
	})
	return out
}

func TestApiManagementSubscription_CRUD(t *testing.T) {
	subResult := armapimanagement.SubscriptionContract{
		ID:   to.Ptr(testApimSubscriptionNativeID),
		Name: to.Ptr("conformance-sub"),
		Properties: &armapimanagement.SubscriptionContractProperties{
			DisplayName:  to.Ptr("Conformance Subscription"),
			Scope:        to.Ptr(testApimSubAbsoluteScope),
			State:        to.Ptr(armapimanagement.SubscriptionStateActive),
			AllowTracing: to.Ptr(false),
			CreatedDate:  to.Ptr(time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)),
		},
	}

	var sentCreate armapimanagement.SubscriptionCreateParameters
	var sentCreateOpts *armapimanagement.SubscriptionClientCreateOrUpdateOptions
	var sentUpdate armapimanagement.SubscriptionUpdateParameters
	var sawIfMatch string
	deleteCalls := 0
	fake := &fakeApiManagementSubscriptionsAPI{
		createOrUpdateFn: func(_ context.Context, _, serviceName, sid string, params armapimanagement.SubscriptionCreateParameters, options *armapimanagement.SubscriptionClientCreateOrUpdateOptions) (armapimanagement.SubscriptionClientCreateOrUpdateResponse, error) {
			require.Equal(t, "apim1", serviceName)
			require.Equal(t, "conformance-sub", sid)
			sentCreate = params
			sentCreateOpts = options
			return armapimanagement.SubscriptionClientCreateOrUpdateResponse{SubscriptionContract: subResult}, nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ *armapimanagement.SubscriptionClientGetOptions) (armapimanagement.SubscriptionClientGetResponse, error) {
			return armapimanagement.SubscriptionClientGetResponse{SubscriptionContract: subResult}, nil
		},
		updateFn: func(_ context.Context, _, _, _, ifMatch string, params armapimanagement.SubscriptionUpdateParameters, _ *armapimanagement.SubscriptionClientUpdateOptions) (armapimanagement.SubscriptionClientUpdateResponse, error) {
			sawIfMatch = ifMatch
			sentUpdate = params
			return armapimanagement.SubscriptionClientUpdateResponse{SubscriptionContract: subResult}, nil
		},
		deleteFn: func(_ context.Context, _, _, _, ifMatch string, _ *armapimanagement.SubscriptionClientDeleteOptions) (armapimanagement.SubscriptionClientDeleteResponse, error) {
			sawIfMatch = ifMatch
			deleteCalls++
			return armapimanagement.SubscriptionClientDeleteResponse{}, nil
		},
		newListPagerFn: func(_, _ string, _ *armapimanagement.SubscriptionClientListOptions) *runtime.Pager[armapimanagement.SubscriptionClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armapimanagement.SubscriptionClientListResponse]{
				More: func(_ armapimanagement.SubscriptionClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armapimanagement.SubscriptionClientListResponse) (armapimanagement.SubscriptionClientListResponse, error) {
					return armapimanagement.SubscriptionClientListResponse{
						SubscriptionCollection: armapimanagement.SubscriptionCollection{
							Value: []*armapimanagement.SubscriptionContract{{ID: to.Ptr(testApimSubscriptionNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestApiManagementSubscription(fake)

	t.Run("Create_is_synchronous_and_notifies_nobody", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "conformance-sub",
			Properties: apimSubscriptionDesired("Conformance Subscription", testApimSubRelativeScope),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testApimSubscriptionNativeID, got.ProgressResult.NativeID)
		require.Empty(t, got.ProgressResult.RequestID)
		require.Equal(t, testApimSubRelativeScope, *sentCreate.Properties.Scope)
		require.Equal(t, armapimanagement.SubscriptionStateActive, *sentCreate.Properties.State)
		require.NotNil(t, sentCreateOpts)
		require.False(t, *sentCreateOpts.Notify)
		// No keys declared, so ARM generates a random pair.
		require.Nil(t, sentCreate.Properties.PrimaryKey)
		require.Nil(t, sentCreate.Properties.SecondaryKey)
	})

	t.Run("Create_write_back_reports_the_declared_scope", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Properties: apimSubscriptionDesired("Conformance Subscription", testApimSubRelativeScope),
		})
		require.NoError(t, err)
		var props map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &props))
		require.Equal(t, testApimSubRelativeScope, props["scope"])
	})

	t.Run("Create_pins_the_keys_when_declared", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "conformance-sub", "resourceGroupName": "rg-1", "serviceName": "apim1",
			"displayName": "Conformance Subscription", "scope": testApimSubRelativeScope,
			"primaryKey": "0123456789abcdef", "secondaryKey": "fedcba9876543210",
			"ownerId": "/users/conformance-user",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.Equal(t, "0123456789abcdef", *sentCreate.Properties.PrimaryKey)
		require.Equal(t, "fedcba9876543210", *sentCreate.Properties.SecondaryKey)
		require.Equal(t, "/users/conformance-user", *sentCreate.Properties.OwnerID)
	})

	t.Run("Create_requires_display_name_and_scope", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "s", "resourceGroupName": "rg-1", "serviceName": "apim1",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "displayName is required")

		props, _ = json.Marshal(map[string]any{
			"name": "s", "resourceGroupName": "rg-1", "serviceName": "apim1", "displayName": "S",
		})
		_, err = prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "scope is required")
	})

	// ARM always answers with the absolute id of the scope target. Echoing that
	// back against a forma that declared the relative form would report drift on
	// every single sync.
	t.Run("Read_echoes_a_relative_scope_that_names_the_same_product", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{
			NativeID:        testApimSubscriptionNativeID,
			PriorProperties: apimSubscriptionDesired("Conformance Subscription", testApimSubRelativeScope),
		})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, testApimSubRelativeScope, props["scope"])
		require.Equal(t, "conformance-sub", props["name"])
		require.Equal(t, "active", props["state"])
		// Never echoed: ARM does not fill either on a Get, and the audit dates
		// are the service's own bookkeeping.
		require.NotContains(t, props, "primaryKey")
		require.NotContains(t, props, "secondaryKey")
		require.NotContains(t, props, "createdDate")
	})

	t.Run("Read_reports_ARMs_scope_when_the_target_genuinely_moved", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{
			NativeID:        testApimSubscriptionNativeID,
			PriorProperties: apimSubscriptionDesired("Conformance Subscription", "/products/premium"),
		})
		require.NoError(t, err)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, testApimSubAbsoluteScope, props["scope"])
	})

	t.Run("Read_without_prior_state_reports_ARMs_absolute_scope", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testApimSubscriptionNativeID})
		require.NoError(t, err)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, testApimSubAbsoluteScope, props["scope"])
	})

	t.Run("Update_uses_patch_with_wildcard_if_match", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testApimSubscriptionNativeID,
			DesiredProperties: apimSubscriptionDesired("Conformance Subscription v2", testApimSubRelativeScope),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, "*", sawIfMatch)
		require.Equal(t, "Conformance Subscription v2", *sentUpdate.Properties.DisplayName)
	})

	t.Run("Delete_is_synchronous", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testApimSubscriptionNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
		require.Equal(t, "*", sawIfMatch)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _, _, _ string, _ *armapimanagement.SubscriptionClientDeleteOptions) (armapimanagement.SubscriptionClientDeleteResponse, error) {
			return armapimanagement.SubscriptionClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testApimSubscriptionNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_service", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "serviceName": "apim1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testApimSubscriptionNativeID}, got.NativeIDs)
	})

	t.Run("List_without_parents_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure_with_a_reason", func(t *testing.T) {
		fake.createOrUpdateFn = func(_ context.Context, _, _, _ string, _ armapimanagement.SubscriptionCreateParameters, _ *armapimanagement.SubscriptionClientCreateOrUpdateOptions) (armapimanagement.SubscriptionClientCreateOrUpdateResponse, error) {
			return armapimanagement.SubscriptionClientCreateOrUpdateResponse{}, &azcore.ResponseError{StatusCode: 400}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "conformance-sub",
			Properties: apimSubscriptionDesired("Conformance Subscription", testApimSubRelativeScope),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.NotEmpty(t, got.ProgressResult.StatusMessage)
	})
}

func TestApiManagementSubscription_ReadNotFound(t *testing.T) {
	fake := &fakeApiManagementSubscriptionsAPI{
		getFn: func(_ context.Context, _, _, _ string, _ *armapimanagement.SubscriptionClientGetOptions) (armapimanagement.SubscriptionClientGetResponse, error) {
			return armapimanagement.SubscriptionClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestApiManagementSubscription(fake).Read(context.Background(),
		&resource.ReadRequest{NativeID: testApimSubscriptionNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

func TestApiManagementSubscriptionScope(t *testing.T) {
	require.Equal(t, testApimSubRelativeScope,
		apiManagementSubscriptionScope(testApimSubRelativeScope, testApimSubAbsoluteScope))
	require.Equal(t, testApimSubAbsoluteScope,
		apiManagementSubscriptionScope(testApimSubAbsoluteScope, testApimSubAbsoluteScope))
	require.Equal(t, testApimSubAbsoluteScope,
		apiManagementSubscriptionScope("/products/premium", testApimSubAbsoluteScope))
	require.Equal(t, testApimSubAbsoluteScope,
		apiManagementSubscriptionScope("", testApimSubAbsoluteScope))
	// "/apis" must not be reported for a subscription ARM says covers only
	// "/apis/orders": a suffix match is only right the other way round.
	require.Equal(t, "/apis", apiManagementSubscriptionScope("/apis", "/apis"))
}

// --- Test helpers ---

type fakeApiManagementSubscriptionsAPI struct {
	createOrUpdateFn func(ctx context.Context, rgName, serviceName, sid string, params armapimanagement.SubscriptionCreateParameters, options *armapimanagement.SubscriptionClientCreateOrUpdateOptions) (armapimanagement.SubscriptionClientCreateOrUpdateResponse, error)
	getFn            func(ctx context.Context, rgName, serviceName, sid string, options *armapimanagement.SubscriptionClientGetOptions) (armapimanagement.SubscriptionClientGetResponse, error)
	updateFn         func(ctx context.Context, rgName, serviceName, sid, ifMatch string, params armapimanagement.SubscriptionUpdateParameters, options *armapimanagement.SubscriptionClientUpdateOptions) (armapimanagement.SubscriptionClientUpdateResponse, error)
	deleteFn         func(ctx context.Context, rgName, serviceName, sid, ifMatch string, options *armapimanagement.SubscriptionClientDeleteOptions) (armapimanagement.SubscriptionClientDeleteResponse, error)
	newListPagerFn   func(rgName, serviceName string, options *armapimanagement.SubscriptionClientListOptions) *runtime.Pager[armapimanagement.SubscriptionClientListResponse]
}

func (f *fakeApiManagementSubscriptionsAPI) CreateOrUpdate(ctx context.Context, rgName, serviceName, sid string, params armapimanagement.SubscriptionCreateParameters, options *armapimanagement.SubscriptionClientCreateOrUpdateOptions) (armapimanagement.SubscriptionClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, serviceName, sid, params, options)
}

func (f *fakeApiManagementSubscriptionsAPI) Get(ctx context.Context, rgName, serviceName, sid string, options *armapimanagement.SubscriptionClientGetOptions) (armapimanagement.SubscriptionClientGetResponse, error) {
	return f.getFn(ctx, rgName, serviceName, sid, options)
}

func (f *fakeApiManagementSubscriptionsAPI) Update(ctx context.Context, rgName, serviceName, sid, ifMatch string, params armapimanagement.SubscriptionUpdateParameters, options *armapimanagement.SubscriptionClientUpdateOptions) (armapimanagement.SubscriptionClientUpdateResponse, error) {
	return f.updateFn(ctx, rgName, serviceName, sid, ifMatch, params, options)
}

func (f *fakeApiManagementSubscriptionsAPI) Delete(ctx context.Context, rgName, serviceName, sid, ifMatch string, options *armapimanagement.SubscriptionClientDeleteOptions) (armapimanagement.SubscriptionClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, serviceName, sid, ifMatch, options)
}

func (f *fakeApiManagementSubscriptionsAPI) NewListPager(rgName, serviceName string, options *armapimanagement.SubscriptionClientListOptions) *runtime.Pager[armapimanagement.SubscriptionClientListResponse] {
	return f.newListPagerFn(rgName, serviceName, options)
}
