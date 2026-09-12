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

const testApimGroupNativeID = testApimServiceNativeID + "/groups/partners"

func newTestApiManagementGroup(api apiManagementGroupsAPI) *ApiManagementGroup {
	return &ApiManagementGroup{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func apimGroupDesired(displayName string) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":              "partners",
		"resourceGroupName": "rg-1",
		"serviceName":       "apim1",
		"displayName":       displayName,
		"description":       "Partner developers",
		"groupType":         "custom",
	})
	return out
}

func TestApiManagementGroup_CRUD(t *testing.T) {
	groupResult := armapimanagement.GroupContract{
		ID:   to.Ptr(testApimGroupNativeID),
		Name: to.Ptr("partners"),
		Properties: &armapimanagement.GroupContractProperties{
			DisplayName: to.Ptr("Partners"),
			Description: to.Ptr("Partner developers"),
			Type:        to.Ptr(armapimanagement.GroupTypeCustom),
			BuiltIn:     to.Ptr(false),
		},
	}

	var sentCreate armapimanagement.GroupCreateParameters
	var sentUpdate armapimanagement.GroupUpdateParameters
	var sawIfMatch string
	deleteCalls := 0
	fake := &fakeApiManagementGroupsAPI{
		createOrUpdateFn: func(_ context.Context, _, serviceName, groupID string, params armapimanagement.GroupCreateParameters, _ *armapimanagement.GroupClientCreateOrUpdateOptions) (armapimanagement.GroupClientCreateOrUpdateResponse, error) {
			require.Equal(t, "apim1", serviceName)
			require.Equal(t, "partners", groupID)
			sentCreate = params
			return armapimanagement.GroupClientCreateOrUpdateResponse{GroupContract: groupResult}, nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ *armapimanagement.GroupClientGetOptions) (armapimanagement.GroupClientGetResponse, error) {
			return armapimanagement.GroupClientGetResponse{GroupContract: groupResult}, nil
		},
		updateFn: func(_ context.Context, _, _, _, ifMatch string, params armapimanagement.GroupUpdateParameters, _ *armapimanagement.GroupClientUpdateOptions) (armapimanagement.GroupClientUpdateResponse, error) {
			sawIfMatch = ifMatch
			sentUpdate = params
			return armapimanagement.GroupClientUpdateResponse{GroupContract: groupResult}, nil
		},
		deleteFn: func(_ context.Context, _, _, _, ifMatch string, _ *armapimanagement.GroupClientDeleteOptions) (armapimanagement.GroupClientDeleteResponse, error) {
			sawIfMatch = ifMatch
			deleteCalls++
			return armapimanagement.GroupClientDeleteResponse{}, nil
		},
		newListByServicePagerFn: func(_, _ string, _ *armapimanagement.GroupClientListByServiceOptions) *runtime.Pager[armapimanagement.GroupClientListByServiceResponse] {
			return runtime.NewPager(runtime.PagingHandler[armapimanagement.GroupClientListByServiceResponse]{
				More: func(_ armapimanagement.GroupClientListByServiceResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armapimanagement.GroupClientListByServiceResponse) (armapimanagement.GroupClientListByServiceResponse, error) {
					return armapimanagement.GroupClientListByServiceResponse{
						GroupCollection: armapimanagement.GroupCollection{
							Value: []*armapimanagement.GroupContract{{ID: to.Ptr(testApimGroupNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestApiManagementGroup(fake)

	t.Run("Create_is_synchronous", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "partners",
			Properties: apimGroupDesired("Partners"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testApimGroupNativeID, got.ProgressResult.NativeID)
		require.Empty(t, got.ProgressResult.RequestID)
		require.Equal(t, "Partners", *sentCreate.Properties.DisplayName)
		require.Equal(t, armapimanagement.GroupTypeCustom, *sentCreate.Properties.Type)
		// A custom group has no directory to mirror.
		require.Nil(t, sentCreate.Properties.ExternalID)
	})

	t.Run("Create_omits_group_type_when_unset_so_ARM_defaults_it", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "partners", "resourceGroupName": "rg-1", "serviceName": "apim1",
			"displayName": "Partners",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.Nil(t, sentCreate.Properties.Type)
	})

	t.Run("Create_sends_an_external_id_for_an_external_group", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "partners", "resourceGroupName": "rg-1", "serviceName": "apim1",
			"displayName": "Partners", "groupType": "external",
			"externalId": "aad://contoso.onmicrosoft.com/groups/00000000-0000-0000-0000-000000000000",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.Equal(t, armapimanagement.GroupTypeExternal, *sentCreate.Properties.Type)
		require.Equal(t, "aad://contoso.onmicrosoft.com/groups/00000000-0000-0000-0000-000000000000",
			*sentCreate.Properties.ExternalID)
	})

	t.Run("Create_requires_display_name", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "partners", "resourceGroupName": "rg-1", "serviceName": "apim1",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "displayName is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testApimGroupNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "partners", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "apim1", props["serviceName"])
		require.Equal(t, "Partners", props["displayName"])
		require.Equal(t, "custom", props["groupType"])
		// builtIn is ARM's own read-only flag and is not part of the schema.
		require.NotContains(t, props, "builtIn")
	})

	t.Run("Update_uses_patch_with_wildcard_if_match", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testApimGroupNativeID,
			DesiredProperties: apimGroupDesired("Partners v2"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, "*", sawIfMatch)
		require.Equal(t, "Partners v2", *sentUpdate.Properties.DisplayName)
	})

	t.Run("Delete_is_synchronous", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testApimGroupNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
		require.Equal(t, "*", sawIfMatch)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _, _, _ string, _ *armapimanagement.GroupClientDeleteOptions) (armapimanagement.GroupClientDeleteResponse, error) {
			return armapimanagement.GroupClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testApimGroupNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_service", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "serviceName": "apim1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testApimGroupNativeID}, got.NativeIDs)
	})

	t.Run("List_without_parents_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})

	// A Consumption instance has no group store, so this is the shape of the
	// failure the fixture hits there: ARM refuses the create and the reason has
	// to reach StatusMessage rather than being dropped.
	t.Run("Azure_error_maps_to_failure_with_a_reason", func(t *testing.T) {
		fake.createOrUpdateFn = func(_ context.Context, _, _, _ string, _ armapimanagement.GroupCreateParameters, _ *armapimanagement.GroupClientCreateOrUpdateOptions) (armapimanagement.GroupClientCreateOrUpdateResponse, error) {
			return armapimanagement.GroupClientCreateOrUpdateResponse{}, &azcore.ResponseError{StatusCode: 400}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "partners", Properties: apimGroupDesired("Partners"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.NotEmpty(t, got.ProgressResult.StatusMessage)
	})
}

func TestApiManagementGroup_ReadNotFound(t *testing.T) {
	fake := &fakeApiManagementGroupsAPI{
		getFn: func(_ context.Context, _, _, _ string, _ *armapimanagement.GroupClientGetOptions) (armapimanagement.GroupClientGetResponse, error) {
			return armapimanagement.GroupClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestApiManagementGroup(fake).Read(context.Background(),
		&resource.ReadRequest{NativeID: testApimGroupNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeApiManagementGroupsAPI struct {
	createOrUpdateFn        func(ctx context.Context, rgName, serviceName, groupID string, params armapimanagement.GroupCreateParameters, options *armapimanagement.GroupClientCreateOrUpdateOptions) (armapimanagement.GroupClientCreateOrUpdateResponse, error)
	getFn                   func(ctx context.Context, rgName, serviceName, groupID string, options *armapimanagement.GroupClientGetOptions) (armapimanagement.GroupClientGetResponse, error)
	updateFn                func(ctx context.Context, rgName, serviceName, groupID, ifMatch string, params armapimanagement.GroupUpdateParameters, options *armapimanagement.GroupClientUpdateOptions) (armapimanagement.GroupClientUpdateResponse, error)
	deleteFn                func(ctx context.Context, rgName, serviceName, groupID, ifMatch string, options *armapimanagement.GroupClientDeleteOptions) (armapimanagement.GroupClientDeleteResponse, error)
	newListByServicePagerFn func(rgName, serviceName string, options *armapimanagement.GroupClientListByServiceOptions) *runtime.Pager[armapimanagement.GroupClientListByServiceResponse]
}

func (f *fakeApiManagementGroupsAPI) CreateOrUpdate(ctx context.Context, rgName, serviceName, groupID string, params armapimanagement.GroupCreateParameters, options *armapimanagement.GroupClientCreateOrUpdateOptions) (armapimanagement.GroupClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, serviceName, groupID, params, options)
}

func (f *fakeApiManagementGroupsAPI) Get(ctx context.Context, rgName, serviceName, groupID string, options *armapimanagement.GroupClientGetOptions) (armapimanagement.GroupClientGetResponse, error) {
	return f.getFn(ctx, rgName, serviceName, groupID, options)
}

func (f *fakeApiManagementGroupsAPI) Update(ctx context.Context, rgName, serviceName, groupID, ifMatch string, params armapimanagement.GroupUpdateParameters, options *armapimanagement.GroupClientUpdateOptions) (armapimanagement.GroupClientUpdateResponse, error) {
	return f.updateFn(ctx, rgName, serviceName, groupID, ifMatch, params, options)
}

func (f *fakeApiManagementGroupsAPI) Delete(ctx context.Context, rgName, serviceName, groupID, ifMatch string, options *armapimanagement.GroupClientDeleteOptions) (armapimanagement.GroupClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, serviceName, groupID, ifMatch, options)
}

func (f *fakeApiManagementGroupsAPI) NewListByServicePager(rgName, serviceName string, options *armapimanagement.GroupClientListByServiceOptions) *runtime.Pager[armapimanagement.GroupClientListByServiceResponse] {
	return f.newListByServicePagerFn(rgName, serviceName, options)
}
