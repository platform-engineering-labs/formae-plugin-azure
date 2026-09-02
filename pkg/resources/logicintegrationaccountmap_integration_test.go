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

const testLogicIntegrationAccountMapNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Logic/integrationAccounts/ia-1/maps/map-1"

func newTestLogicIntegrationAccountMap(api logicIntegrationAccountMapsAPI) *LogicIntegrationAccountMap {
	return &LogicIntegrationAccountMap{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

const testLogicMapContent = `<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><Receipt /></xsl:template></xsl:stylesheet>`

func logicMapDesired(mapType string, parametersSchemaRef any) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":                   "map-1",
		"resourceGroupName":      "rg-1",
		"integrationAccountName": "ia-1",
		"mapType":                mapType,
		"content":                testLogicMapContent,
		"parametersSchemaRef":    parametersSchemaRef,
	})
	return out
}

func TestLogicIntegrationAccountMap_CRUD(t *testing.T) {
	// ARM's answer replaces content with a contentLink SAS URL.
	result := armlogic.IntegrationAccountMap{
		ID:   to.Ptr(testLogicIntegrationAccountMapNativeID),
		Name: to.Ptr("map-1"),
		Properties: &armlogic.IntegrationAccountMapProperties{
			MapType:     to.Ptr(armlogic.MapTypeXslt),
			ContentType: to.Ptr("application/xml"),
			ParametersSchema: &armlogic.IntegrationAccountMapPropertiesParametersSchema{
				Ref: to.Ptr("order-params"),
			},
			ContentLink: &armlogic.ContentLink{
				URI: to.Ptr("https://prod.blob.core.windows.net/maps/map-1?sig=REDACTED"),
			},
			CreatedTime: to.Ptr(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)),
			ChangedTime: to.Ptr(time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)),
		},
	}

	var sentCreate armlogic.IntegrationAccountMap
	createCalls := 0
	deleteCalls := 0
	fake := &fakeLogicIntegrationAccountMapsAPI{
		createOrUpdateFn: func(_ context.Context, rgName, accountName, name string, params armlogic.IntegrationAccountMap, _ *armlogic.IntegrationAccountMapsClientCreateOrUpdateOptions) (armlogic.IntegrationAccountMapsClientCreateOrUpdateResponse, error) {
			require.Equal(t, "rg-1", rgName)
			require.Equal(t, "ia-1", accountName)
			require.Equal(t, "map-1", name)
			sentCreate = params
			createCalls++
			return armlogic.IntegrationAccountMapsClientCreateOrUpdateResponse{IntegrationAccountMap: result}, nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ *armlogic.IntegrationAccountMapsClientGetOptions) (armlogic.IntegrationAccountMapsClientGetResponse, error) {
			return armlogic.IntegrationAccountMapsClientGetResponse{IntegrationAccountMap: result}, nil
		},
		deleteFn: func(_ context.Context, _, _, _ string, _ *armlogic.IntegrationAccountMapsClientDeleteOptions) (armlogic.IntegrationAccountMapsClientDeleteResponse, error) {
			deleteCalls++
			return armlogic.IntegrationAccountMapsClientDeleteResponse{}, nil
		},
		newListPagerFn: func(_, _ string, _ *armlogic.IntegrationAccountMapsClientListOptions) *runtime.Pager[armlogic.IntegrationAccountMapsClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armlogic.IntegrationAccountMapsClientListResponse]{
				More: func(_ armlogic.IntegrationAccountMapsClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armlogic.IntegrationAccountMapsClientListResponse) (armlogic.IntegrationAccountMapsClientListResponse, error) {
					return armlogic.IntegrationAccountMapsClientListResponse{
						IntegrationAccountMapListResult: armlogic.IntegrationAccountMapListResult{
							Value: []*armlogic.IntegrationAccountMap{{ID: to.Ptr(testLogicIntegrationAccountMapNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestLogicIntegrationAccountMap(fake)

	// Create is synchronous: IntegrationAccountMapsClient has no BeginX at all, so no
	// resume token is ever produced.
	t.Run("Create_is_synchronous", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "map-1",
			Properties: logicMapDesired("Xslt", "order-params"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testLogicIntegrationAccountMapNativeID, got.ProgressResult.NativeID)
		require.Empty(t, got.ProgressResult.RequestID)

		require.Equal(t, armlogic.MapTypeXslt, *sentCreate.Properties.MapType)
		require.Equal(t, testLogicMapContent, *sentCreate.Properties.Content)
		require.Equal(t, "order-params", *sentCreate.Properties.ParametersSchema.Ref)
		// ARM rejects a map whose contentType is absent and will not infer one, so
		// the provider derives the media type from mapType rather than making the
		// caller repeat it.
		require.Equal(t, "application/xml", *sentCreate.Properties.ContentType)
	})

	t.Run("Create_requires_resource_group", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "map-1", "integrationAccountName": "ia-1"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "resourceGroupName is required")
	})

	t.Run("Create_requires_integration_account", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "map-1", "resourceGroupName": "rg-1"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "integrationAccountName is required")
	})

	t.Run("Create_requires_map_type", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "map-1", "resourceGroupName": "rg-1", "integrationAccountName": "ia-1",
			"content": testLogicMapContent,
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "mapType is required")
	})

	t.Run("Create_requires_content", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "map-1", "resourceGroupName": "rg-1", "integrationAccountName": "ia-1",
			"mapType": "Xslt",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "content is required")
	})

	// A Liquid template is plain text; every XSLT flavour is XML.
	t.Run("Create_liquid_sends_text_content_type", func(t *testing.T) {
		_, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "map-1", Properties: logicMapDesired("Liquid", nil),
		})
		require.NoError(t, err)
		require.Equal(t, "text/plain", *sentCreate.Properties.ContentType)
		require.Nil(t, sentCreate.Properties.ParametersSchema)
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testLogicIntegrationAccountMapNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "map-1", props["name"])
		// Both parents come from the native ID, not the response body: ARM echoes
		// neither on a child.
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "ia-1", props["integrationAccountName"])
		require.Equal(t, "Xslt", props["mapType"])
		require.Equal(t, "order-params", props["parametersSchemaRef"])
	})

	t.Run("Read_drops_write_only_content_and_derived_fields", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testLogicIntegrationAccountMapNativeID})
		require.NoError(t, err)
		for _, key := range []string{"content", "contentLink", "sig=REDACTED", "contentType", "createdTime", "changedTime"} {
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

	// Update reissues CreateOrUpdate: this API has no PATCH verb for maps.
	t.Run("Update_reissues_create_or_update", func(t *testing.T) {
		before := createCalls
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testLogicIntegrationAccountMapNativeID,
			DesiredProperties: logicMapDesired("Xslt", nil),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Empty(t, got.ProgressResult.RequestID)
		require.Equal(t, before+1, createCalls)
		require.Equal(t, armlogic.MapTypeXslt, *sentCreate.Properties.MapType)
		// An omitted parametersSchemaRef must be left out of the body rather than
		// sent as an empty ref object.
		require.Nil(t, sentCreate.Properties.ParametersSchema)
	})

	t.Run("Delete_is_synchronous", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testLogicIntegrationAccountMapNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Empty(t, got.ProgressResult.RequestID)
		require.Equal(t, before+1, deleteCalls)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _, _ string, _ *armlogic.IntegrationAccountMapsClientDeleteOptions) (armlogic.IntegrationAccountMapsClientDeleteResponse, error) {
			return armlogic.IntegrationAccountMapsClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testLogicIntegrationAccountMapNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_account", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "integrationAccountName": "ia-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testLogicIntegrationAccountMapNativeID}, got.NativeIDs)
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
		fake.createOrUpdateFn = func(_ context.Context, _, _, _ string, _ armlogic.IntegrationAccountMap, _ *armlogic.IntegrationAccountMapsClientCreateOrUpdateOptions) (armlogic.IntegrationAccountMapsClientCreateOrUpdateResponse, error) {
			return armlogic.IntegrationAccountMapsClientCreateOrUpdateResponse{}, &azcore.ResponseError{StatusCode: 409}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "map-1", Properties: logicMapDesired("Xslt", "order-params"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.NotEmpty(t, got.ProgressResult.StatusMessage)
	})
}

func TestLogicIntegrationAccountMap_ReadNotFound(t *testing.T) {
	fake := &fakeLogicIntegrationAccountMapsAPI{
		getFn: func(_ context.Context, _, _, _ string, _ *armlogic.IntegrationAccountMapsClientGetOptions) (armlogic.IntegrationAccountMapsClientGetResponse, error) {
			return armlogic.IntegrationAccountMapsClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestLogicIntegrationAccountMap(fake).Read(context.Background(),
		&resource.ReadRequest{NativeID: testLogicIntegrationAccountMapNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeLogicIntegrationAccountMapsAPI struct {
	createOrUpdateFn func(ctx context.Context, rgName, accountName, name string, params armlogic.IntegrationAccountMap, options *armlogic.IntegrationAccountMapsClientCreateOrUpdateOptions) (armlogic.IntegrationAccountMapsClientCreateOrUpdateResponse, error)
	getFn            func(ctx context.Context, rgName, accountName, name string, options *armlogic.IntegrationAccountMapsClientGetOptions) (armlogic.IntegrationAccountMapsClientGetResponse, error)
	deleteFn         func(ctx context.Context, rgName, accountName, name string, options *armlogic.IntegrationAccountMapsClientDeleteOptions) (armlogic.IntegrationAccountMapsClientDeleteResponse, error)
	newListPagerFn   func(rgName, accountName string, options *armlogic.IntegrationAccountMapsClientListOptions) *runtime.Pager[armlogic.IntegrationAccountMapsClientListResponse]
}

func (f *fakeLogicIntegrationAccountMapsAPI) CreateOrUpdate(ctx context.Context, rgName, accountName, name string, params armlogic.IntegrationAccountMap, options *armlogic.IntegrationAccountMapsClientCreateOrUpdateOptions) (armlogic.IntegrationAccountMapsClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, accountName, name, params, options)
}

func (f *fakeLogicIntegrationAccountMapsAPI) Get(ctx context.Context, rgName, accountName, name string, options *armlogic.IntegrationAccountMapsClientGetOptions) (armlogic.IntegrationAccountMapsClientGetResponse, error) {
	return f.getFn(ctx, rgName, accountName, name, options)
}

func (f *fakeLogicIntegrationAccountMapsAPI) Delete(ctx context.Context, rgName, accountName, name string, options *armlogic.IntegrationAccountMapsClientDeleteOptions) (armlogic.IntegrationAccountMapsClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, accountName, name, options)
}

func (f *fakeLogicIntegrationAccountMapsAPI) NewListPager(rgName, accountName string, options *armlogic.IntegrationAccountMapsClientListOptions) *runtime.Pager[armlogic.IntegrationAccountMapsClientListResponse] {
	return f.newListPagerFn(rgName, accountName, options)
}
