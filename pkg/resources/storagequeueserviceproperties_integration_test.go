// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build integration

package resources

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testQueueServiceNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Storage/storageAccounts/acct1/queueServices/default"

func queueServiceDesired(maxAge int, methods ...string) json.RawMessage {
	props, _ := json.Marshal(map[string]any{
		"resourceGroupName":  "rg-1",
		"storageAccountName": "acct1",
		"corsRules": []map[string]any{{
			"allowedOrigins":  []string{"https://example.com"},
			"allowedMethods":  methods,
			"allowedHeaders":  []string{"x-ms-meta-purpose"},
			"exposedHeaders":  []string{"x-ms-meta-purpose"},
			"maxAgeInSeconds": maxAge,
		}},
	})
	return props
}

func echoQueueService(sent armstorage.QueueServiceProperties) armstorage.QueueServiceProperties {
	sent.ID = to.Ptr(testQueueServiceNativeID)
	sent.Name = to.Ptr("default")
	return sent
}

func TestStorageQueueServiceProperties_CRUD(t *testing.T) {
	var current armstorage.QueueServiceProperties
	var lastSent armstorage.QueueServiceProperties
	fake := &fakeQueueServicesAPI{
		setFn: func(_ context.Context, _, _ string, params armstorage.QueueServiceProperties, _ *armstorage.QueueServicesClientSetServicePropertiesOptions) (armstorage.QueueServicesClientSetServicePropertiesResponse, error) {
			lastSent = params
			current = echoQueueService(params)
			return armstorage.QueueServicesClientSetServicePropertiesResponse{QueueServiceProperties: current}, nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armstorage.QueueServicesClientGetServicePropertiesOptions) (armstorage.QueueServicesClientGetServicePropertiesResponse, error) {
			return armstorage.QueueServicesClientGetServicePropertiesResponse{QueueServiceProperties: current}, nil
		},
	}
	prov := newTestStorageQueueServiceProperties(fake)

	t.Run("Create_maps_onto_setServiceProperties", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: queueServiceDesired(300, "GET", "PUT")})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testQueueServiceNativeID, got.ProgressResult.NativeID)

		require.Len(t, lastSent.QueueServiceProperties.Cors.CorsRules, 1)
		rule := lastSent.QueueServiceProperties.Cors.CorsRules[0]
		require.Equal(t, "https://example.com", *rule.AllowedOrigins[0])
		require.Equal(t, armstorage.CorsRuleAllowedMethodsItemGET, *rule.AllowedMethods[0])
		require.Equal(t, armstorage.CorsRuleAllowedMethodsItemPUT, *rule.AllowedMethods[1])
		require.EqualValues(t, 300, *rule.MaxAgeInSeconds)

		var serialized map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &serialized))
		require.Equal(t, "rg-1", serialized["resourceGroupName"])
		require.Equal(t, "acct1", serialized["storageAccountName"])
		// The singleton ARM name is never surfaced as a property.
		require.NotContains(t, serialized, "name")
		rules := serialized["corsRules"].([]any)
		require.Len(t, rules, 1)
		readRule := rules[0].(map[string]any)
		require.Equal(t, []any{"https://example.com"}, readRule["allowedOrigins"])
		require.Equal(t, []any{"GET", "PUT"}, readRule["allowedMethods"])
		require.Equal(t, []any{"x-ms-meta-purpose"}, readRule["allowedHeaders"])
		require.Equal(t, []any{"x-ms-meta-purpose"}, readRule["exposedHeaders"])
		require.EqualValues(t, 300, readRule["maxAgeInSeconds"])
	})

	t.Run("Create_requires_storageAccountName", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"resourceGroupName": "rg-1"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "storageAccountName is required")
	})

	t.Run("Create_rejects_more_than_five_cors_rules", func(t *testing.T) {
		rule := map[string]any{
			"allowedOrigins":  []string{"*"},
			"allowedMethods":  []string{"GET"},
			"allowedHeaders":  []string{"*"},
			"exposedHeaders":  []string{"*"},
			"maxAgeInSeconds": 1,
		}
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName":  "rg-1",
			"storageAccountName": "acct1",
			"corsRules":          []map[string]any{rule, rule, rule, rule, rule, rule},
		})
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.Contains(t, got.ProgressResult.StatusMessage, "at most 5 CORS rules")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testQueueServiceNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
		require.Equal(t, ResourceTypeStorageQueueServiceProperties, got.ResourceType)
	})

	t.Run("Update_derives_the_account_from_the_native_id", func(t *testing.T) {
		var seenRG, seenAcct string
		fake.setFn = func(_ context.Context, rg, acct string, params armstorage.QueueServiceProperties, _ *armstorage.QueueServicesClientSetServicePropertiesOptions) (armstorage.QueueServicesClientSetServicePropertiesResponse, error) {
			seenRG, seenAcct, lastSent = rg, acct, params
			current = echoQueueService(params)
			return armstorage.QueueServicesClientSetServicePropertiesResponse{QueueServiceProperties: current}, nil
		}
		desired, _ := json.Marshal(map[string]any{
			"corsRules": []map[string]any{{
				"allowedOrigins":  []string{"https://example.com"},
				"allowedMethods":  []string{"GET"},
				"allowedHeaders":  []string{"*"},
				"exposedHeaders":  []string{"*"},
				"maxAgeInSeconds": 600,
			}},
		})
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testQueueServiceNativeID,
			DesiredProperties: desired,
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testQueueServiceNativeID, got.ProgressResult.NativeID)
		require.Equal(t, "rg-1", seenRG)
		require.Equal(t, "acct1", seenAcct)
		require.EqualValues(t, 600, *lastSent.QueueServiceProperties.Cors.CorsRules[0].MaxAgeInSeconds)
	})

	t.Run("Delete_resets_the_properties_to_empty", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testQueueServiceNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		// ARM cannot remove the queue service, so "deleted" is an empty CORS set.
		require.NotNil(t, lastSent.QueueServiceProperties.Cors)
		require.Empty(t, lastSent.QueueServiceProperties.Cors.CorsRules)
	})

	t.Run("an_empty_cors_set_reads_back_as_absence", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testQueueServiceNativeID})
		require.NoError(t, err)
		var serialized map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &serialized))
		// corsRules has no schema default, so an empty list must not be reported as
		// an empty listing the caller never declared.
		require.NotContains(t, serialized, "corsRules")
	})

	t.Run("Status_rereads", func(t *testing.T) {
		got, err := prov.Status(context.Background(), &resource.StatusRequest{
			RequestID: "req-1",
			NativeID:  testQueueServiceNativeID,
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testQueueServiceNativeID, got.ProgressResult.NativeID)
	})

	t.Run("List_probes_the_singleton", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "storageAccountName": "acct1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testQueueServiceNativeID}, got.NativeIDs)
	})

	t.Run("List_without_parent_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})
}

func TestStorageQueueServiceProperties_Failures(t *testing.T) {
	fake := &fakeQueueServicesAPI{
		setFn: func(_ context.Context, _, _ string, _ armstorage.QueueServiceProperties, _ *armstorage.QueueServicesClientSetServicePropertiesOptions) (armstorage.QueueServicesClientSetServicePropertiesResponse, error) {
			return armstorage.QueueServicesClientSetServicePropertiesResponse{},
				&azcore.ResponseError{StatusCode: 400, ErrorCode: "InvalidCorsRule"}
		},
		getFn: func(_ context.Context, _, _ string, _ *armstorage.QueueServicesClientGetServicePropertiesOptions) (armstorage.QueueServicesClientGetServicePropertiesResponse, error) {
			return armstorage.QueueServicesClientGetServicePropertiesResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	prov := newTestStorageQueueServiceProperties(fake)

	t.Run("Create_failure_reports_the_provider_error", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: queueServiceDesired(300, "GET")})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.Equal(t, resource.OperationErrorCodeInvalidRequest, got.ProgressResult.ErrorCode)
		require.Contains(t, got.ProgressResult.StatusMessage, "InvalidCorsRule")
	})

	t.Run("Read_maps_404", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testQueueServiceNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
	})

	// An account whose queue service cannot be read must list as empty rather than
	// fail the whole discovery pass.
	t.Run("List_maps_404_to_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "storageAccountName": "acct1"},
		})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})
}

// --- Test helpers ---

func newTestStorageQueueServiceProperties(api storageQueueServicesAPI) *StorageQueueServiceProperties {
	return &StorageQueueServiceProperties{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

type fakeQueueServicesAPI struct {
	getFn func(ctx context.Context, rgName, accountName string, opts *armstorage.QueueServicesClientGetServicePropertiesOptions) (armstorage.QueueServicesClientGetServicePropertiesResponse, error)
	setFn func(ctx context.Context, rgName, accountName string, params armstorage.QueueServiceProperties, opts *armstorage.QueueServicesClientSetServicePropertiesOptions) (armstorage.QueueServicesClientSetServicePropertiesResponse, error)
}

func (f *fakeQueueServicesAPI) GetServiceProperties(ctx context.Context, rgName, accountName string, opts *armstorage.QueueServicesClientGetServicePropertiesOptions) (armstorage.QueueServicesClientGetServicePropertiesResponse, error) {
	return f.getFn(ctx, rgName, accountName, opts)
}

func (f *fakeQueueServicesAPI) SetServiceProperties(ctx context.Context, rgName, accountName string, params armstorage.QueueServiceProperties, opts *armstorage.QueueServicesClientSetServicePropertiesOptions) (armstorage.QueueServicesClientSetServicePropertiesResponse, error) {
	return f.setFn(ctx, rgName, accountName, params, opts)
}
