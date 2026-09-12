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

const testSAIotHubPolicyKey = "aW90cG9saWN5a2V5"

func testSAInputIotHubDesired(partitionKey string) map[string]any {
	return map[string]any{
		"name":                   "asainput",
		"resourceGroupName":      testSAJobResourceGroup,
		"jobName":                testSAJobName,
		"iotHubNamespace":        "iot-1",
		"sharedAccessPolicyName": "iothubowner",
		"sharedAccessPolicyKey":  testSAIotHubPolicyKey,
		"endpoint":               "messages/events",
		"partitionKey":           partitionKey,
		"serialization":          map[string]any{"type": "Json", "encoding": "UTF8"},
	}
}

func newTestSAInputIotHub(api streamAnalyticsInputsAPI) *StreamAnalyticsInput {
	return &StreamAnalyticsInput{api: api, kind: streamAnalyticsInputIotHubKind}
}

func TestStreamAnalyticsInputIotHub_CRUD(t *testing.T) {
	service := newSAInputService()
	prov := newTestSAInputIotHub(service)

	t.Run("Create", func(t *testing.T) {
		progress, props := saCreate(t, prov, testSAInputIotHubDesired("deviceId"), "asainput")
		require.Equal(t, testSAInputNativeID("asainput"), progress.NativeID)

		sent := service.lastSent()
		stream := sent.Properties.(*armstreamanalytics.StreamInputProperties)
		hub, ok := stream.Datasource.(*armstreamanalytics.IoTHubStreamInputDataSource)
		require.True(t, ok)
		require.Equal(t, "Microsoft.Devices/IotHubs", *hub.Type)
		// iotHubNamespace is ARM's field name for the hub itself.
		require.Equal(t, "iot-1", *hub.Properties.IotHubNamespace)
		require.Equal(t, "iothubowner", *hub.Properties.SharedAccessPolicyName)
		require.Equal(t, testSAIotHubPolicyKey, *hub.Properties.SharedAccessPolicyKey)
		require.Equal(t, "messages/events", *hub.Properties.Endpoint)
		require.Nil(t, hub.Properties.ConsumerGroupName)

		saRequireNoSecrets(t, props)
	})

	t.Run("Read", func(t *testing.T) {
		props := saRead(t, prov, testSAInputNativeID("asainput"))
		require.Equal(t, "iot-1", props["iotHubNamespace"])
		require.Equal(t, "iothubowner", props["sharedAccessPolicyName"])
		require.Equal(t, "messages/events", props["endpoint"])
		require.Equal(t, "deviceId", props["partitionKey"])
		require.NotContains(t, props, "consumerGroupName")
		saRequireNoSecrets(t, props)
	})

	t.Run("Update_repartitions_in_place", func(t *testing.T) {
		raw, err := json.Marshal(testSAInputIotHubDesired("sensorId"))
		require.NoError(t, err)
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testSAInputNativeID("asainput"),
			DesiredProperties: raw,
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)

		var props map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &props))
		require.Equal(t, "sensorId", props["partitionKey"])
		saRequireNoSecrets(t, props)
	})

	t.Run("Delete", func(t *testing.T) {
		before := service.deletes
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testSAInputNativeID("asainput")})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, service.deletes)
	})
}

func TestStreamAnalyticsInputIotHub_CreateRequiresDatasourceFields(t *testing.T) {
	prov := newTestSAInputIotHub(newSAInputService())

	for _, missing := range []string{"iotHubNamespace", "sharedAccessPolicyName", "sharedAccessPolicyKey"} {
		t.Run(missing, func(t *testing.T) {
			desired := testSAInputIotHubDesired("deviceId")
			delete(desired, missing)
			raw, err := json.Marshal(desired)
			require.NoError(t, err)
			_, err = prov.Create(context.Background(), &resource.CreateRequest{Label: "asainput", Properties: raw})
			require.ErrorContains(t, err, missing+" is required")
		})
	}
}
