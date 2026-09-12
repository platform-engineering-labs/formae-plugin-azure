// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/streamanalytics/armstreamanalytics"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testSAServiceBusPolicyKey = "c2Jwb2xpY3lrZXk="

func testSAOutputServiceBusQueueDesired(propertyColumns []any) map[string]any {
	return map[string]any{
		"name":                   "asaoutput",
		"resourceGroupName":      testSAJobResourceGroup,
		"jobName":                testSAJobName,
		"serviceBusNamespace":    "sb-ns-1",
		"queueName":              "queue-1",
		"sharedAccessPolicyName": "RootManageSharedAccessKey",
		"sharedAccessPolicyKey":  testSAServiceBusPolicyKey,
		"propertyColumns":        propertyColumns,
		"serialization": map[string]any{
			"type": "Json", "encoding": "UTF8", "format": "LineSeparated",
		},
	}
}

func newTestSAOutputServiceBusQueue(api streamAnalyticsOutputsAPI) *StreamAnalyticsOutput {
	return &StreamAnalyticsOutput{api: api, kind: streamAnalyticsOutputServiceBusQueueKind}
}

func TestStreamAnalyticsOutputServiceBusQueue_CRUD(t *testing.T) {
	service := newSAOutputService()
	prov := newTestSAOutputServiceBusQueue(service)

	t.Run("Create", func(t *testing.T) {
		progress, props := saCreate(t, prov, testSAOutputServiceBusQueueDesired([]any{"deviceId"}), "asaoutput")
		require.Equal(t, testSAOutputNativeID("asaoutput"), progress.NativeID)

		sent := service.lastSent()
		queue, ok := sent.Properties.Datasource.(*armstreamanalytics.ServiceBusQueueOutputDataSource)
		require.True(t, ok)
		require.Equal(t, "Microsoft.ServiceBus/Queue", *queue.Type)
		require.Equal(t, "sb-ns-1", *queue.Properties.ServiceBusNamespace)
		require.Equal(t, "queue-1", *queue.Properties.QueueName)
		require.Equal(t, testSAServiceBusPolicyKey, *queue.Properties.SharedAccessPolicyKey)
		// systemPropertyColumns is not modelled, so it must never be sent: the
		// API types it as a free-form object with no stable shape.
		require.Nil(t, queue.Properties.SystemPropertyColumns)

		saRequireNoSecrets(t, props)
	})

	t.Run("Read", func(t *testing.T) {
		props := saRead(t, prov, testSAOutputNativeID("asaoutput"))
		require.Equal(t, "sb-ns-1", props["serviceBusNamespace"])
		require.Equal(t, "queue-1", props["queueName"])
		require.Equal(t, "RootManageSharedAccessKey", props["sharedAccessPolicyName"])
		require.Equal(t, []any{"deviceId"}, props["propertyColumns"])
		require.NotContains(t, props, "systemPropertyColumns")
		saRequireNoSecrets(t, props)
	})

	t.Run("Update_adds_property_column", func(t *testing.T) {
		raw, err := json.Marshal(testSAOutputServiceBusQueueDesired([]any{"deviceId", "sensorId"}))
		require.NoError(t, err)
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testSAOutputNativeID("asaoutput"),
			DesiredProperties: raw,
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)

		var props map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &props))
		require.Equal(t, []any{"deviceId", "sensorId"}, props["propertyColumns"])
		saRequireNoSecrets(t, props)
	})

	t.Run("Delete", func(t *testing.T) {
		before := service.deletes
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testSAOutputNativeID("asaoutput")})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, service.deletes)
	})
}

func TestStreamAnalyticsOutputServiceBusQueue_CreateRequiresDatasourceFields(t *testing.T) {
	prov := newTestSAOutputServiceBusQueue(newSAOutputService())

	for _, missing := range []string{"serviceBusNamespace", "queueName", "sharedAccessPolicyName", "sharedAccessPolicyKey"} {
		t.Run(missing, func(t *testing.T) {
			desired := testSAOutputServiceBusQueueDesired([]any{"deviceId"})
			delete(desired, missing)
			raw, err := json.Marshal(desired)
			require.NoError(t, err)
			_, err = prov.Create(context.Background(), &resource.CreateRequest{Label: "asaoutput", Properties: raw})
			require.ErrorContains(t, err, missing+" is required")
		})
	}
}
