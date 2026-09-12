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

const testSAEventHubPolicyKey = "cG9saWN5a2V5"

func testSAInputEventHubDesired(partitionKey string) map[string]any {
	return map[string]any{
		"name":                   "asainput",
		"resourceGroupName":      testSAJobResourceGroup,
		"jobName":                testSAJobName,
		"serviceBusNamespace":    "eh-ns-1",
		"eventHubName":           "hub-1",
		"sharedAccessPolicyName": "RootManageSharedAccessKey",
		"sharedAccessPolicyKey":  testSAEventHubPolicyKey,
		"partitionKey":           partitionKey,
		"serialization":          map[string]any{"type": "Json", "encoding": "UTF8"},
	}
}

func newTestSAInputEventHub(api streamAnalyticsInputsAPI) *StreamAnalyticsInput {
	return &StreamAnalyticsInput{api: api, kind: streamAnalyticsInputEventHubKind}
}

func TestStreamAnalyticsInputEventHub_CRUD(t *testing.T) {
	service := newSAInputService()
	prov := newTestSAInputEventHub(service)

	t.Run("Create", func(t *testing.T) {
		progress, props := saCreate(t, prov, testSAInputEventHubDesired("deviceId"), "asainput")
		require.Equal(t, testSAInputNativeID("asainput"), progress.NativeID)

		sent := service.lastSent()
		stream := sent.Properties.(*armstreamanalytics.StreamInputProperties)
		hub, ok := stream.Datasource.(*armstreamanalytics.EventHubStreamInputDataSource)
		require.True(t, ok)
		// The ServiceBus namespace, not Microsoft.EventHub/EventHub: that is the
		// managed-identity EventHubV2 datasource, which takes no policy key.
		require.Equal(t, "Microsoft.ServiceBus/EventHub", *hub.Type)
		require.Equal(t, "eh-ns-1", *hub.Properties.ServiceBusNamespace)
		require.Equal(t, "hub-1", *hub.Properties.EventHubName)
		require.Equal(t, "RootManageSharedAccessKey", *hub.Properties.SharedAccessPolicyName)
		require.Equal(t, testSAEventHubPolicyKey, *hub.Properties.SharedAccessPolicyKey)
		// Not declared, so not sent: ARM would otherwise store an empty string.
		require.Nil(t, hub.Properties.ConsumerGroupName)

		saRequireNoSecrets(t, props)
	})

	t.Run("Read", func(t *testing.T) {
		props := saRead(t, prov, testSAInputNativeID("asainput"))
		require.Equal(t, "eh-ns-1", props["serviceBusNamespace"])
		require.Equal(t, "hub-1", props["eventHubName"])
		require.Equal(t, "RootManageSharedAccessKey", props["sharedAccessPolicyName"])
		require.Equal(t, "deviceId", props["partitionKey"])
		require.NotContains(t, props, "consumerGroupName")
		saRequireNoSecrets(t, props)
	})

	t.Run("Update_repartitions_in_place", func(t *testing.T) {
		raw, err := json.Marshal(testSAInputEventHubDesired("sensorId"))
		require.NoError(t, err)
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testSAInputNativeID("asainput"),
			DesiredProperties: raw,
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Empty(t, got.ProgressResult.RequestID)

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

func TestStreamAnalyticsInputEventHub_ConsumerGroupRoundTrips(t *testing.T) {
	service := newSAInputService()
	desired := testSAInputEventHubDesired("deviceId")
	desired["consumerGroupName"] = "asa-cg"
	_, props := saCreate(t, newTestSAInputEventHub(service), desired, "asainput")
	require.Equal(t, "asa-cg", props["consumerGroupName"])
}

func TestStreamAnalyticsInputEventHub_CreateRequiresDatasourceFields(t *testing.T) {
	prov := newTestSAInputEventHub(newSAInputService())

	for _, missing := range []string{"serviceBusNamespace", "eventHubName", "sharedAccessPolicyName", "sharedAccessPolicyKey"} {
		t.Run(missing, func(t *testing.T) {
			desired := testSAInputEventHubDesired("deviceId")
			delete(desired, missing)
			raw, err := json.Marshal(desired)
			require.NoError(t, err)
			_, err = prov.Create(context.Background(), &resource.CreateRequest{Label: "asainput", Properties: raw})
			require.ErrorContains(t, err, missing+" is required")
		})
	}
}
