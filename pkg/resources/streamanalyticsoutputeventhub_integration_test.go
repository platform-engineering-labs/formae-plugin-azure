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

func testSAOutputEventHubDesired(partitionKey string, propertyColumns []any) map[string]any {
	return map[string]any{
		"name":                   "asaoutput",
		"resourceGroupName":      testSAJobResourceGroup,
		"jobName":                testSAJobName,
		"serviceBusNamespace":    "eh-ns-1",
		"eventHubName":           "hub-1",
		"sharedAccessPolicyName": "RootManageSharedAccessKey",
		"sharedAccessPolicyKey":  testSAEventHubPolicyKey,
		"partitionKey":           partitionKey,
		"propertyColumns":        propertyColumns,
		"serialization": map[string]any{
			"type": "Json", "encoding": "UTF8", "format": "LineSeparated",
		},
	}
}

func newTestSAOutputEventHub(api streamAnalyticsOutputsAPI) *StreamAnalyticsOutput {
	return &StreamAnalyticsOutput{api: api, kind: streamAnalyticsOutputEventHubKind}
}

func TestStreamAnalyticsOutputEventHub_CRUD(t *testing.T) {
	service := newSAOutputService()
	prov := newTestSAOutputEventHub(service)

	t.Run("Create", func(t *testing.T) {
		progress, props := saCreate(t, prov, testSAOutputEventHubDesired("deviceId", []any{"deviceId"}), "asaoutput")
		require.Equal(t, testSAOutputNativeID("asaoutput"), progress.NativeID)

		sent := service.lastSent()
		hub, ok := sent.Properties.Datasource.(*armstreamanalytics.EventHubOutputDataSource)
		require.True(t, ok)
		require.Equal(t, "Microsoft.ServiceBus/EventHub", *hub.Type)
		require.Equal(t, "eh-ns-1", *hub.Properties.ServiceBusNamespace)
		require.Equal(t, "hub-1", *hub.Properties.EventHubName)
		require.Equal(t, testSAEventHubPolicyKey, *hub.Properties.SharedAccessPolicyKey)
		require.Len(t, hub.Properties.PropertyColumns, 1)
		require.Equal(t, "deviceId", *hub.Properties.PropertyColumns[0])

		saRequireNoSecrets(t, props)
	})

	t.Run("Read", func(t *testing.T) {
		props := saRead(t, prov, testSAOutputNativeID("asaoutput"))
		require.Equal(t, "eh-ns-1", props["serviceBusNamespace"])
		require.Equal(t, "hub-1", props["eventHubName"])
		require.Equal(t, "deviceId", props["partitionKey"])
		require.Equal(t, []any{"deviceId"}, props["propertyColumns"])
		saRequireNoSecrets(t, props)
	})

	t.Run("Update_adds_property_column", func(t *testing.T) {
		raw, err := json.Marshal(testSAOutputEventHubDesired("sensorId", []any{"deviceId", "sensorId"}))
		require.NoError(t, err)
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testSAOutputNativeID("asaoutput"),
			DesiredProperties: raw,
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)

		var props map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &props))
		require.Equal(t, "sensorId", props["partitionKey"])
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

// An undeclared propertyColumns must stay absent from both the request and
// state, not become an empty array ARM would echo back as drift.
func TestStreamAnalyticsOutputEventHub_UnsetListsAreOmitted(t *testing.T) {
	service := newSAOutputService()
	desired := testSAOutputEventHubDesired("deviceId", nil)
	delete(desired, "propertyColumns")

	_, props := saCreate(t, newTestSAOutputEventHub(service), desired, "asaoutput")
	require.NotContains(t, props, "propertyColumns")

	sent := service.lastSent()
	hub := sent.Properties.Datasource.(*armstreamanalytics.EventHubOutputDataSource)
	require.Nil(t, hub.Properties.PropertyColumns)
}

func TestStreamAnalyticsOutputEventHub_CreateRequiresDatasourceFields(t *testing.T) {
	prov := newTestSAOutputEventHub(newSAOutputService())

	for _, missing := range []string{"serviceBusNamespace", "eventHubName", "sharedAccessPolicyName", "sharedAccessPolicyKey"} {
		t.Run(missing, func(t *testing.T) {
			desired := testSAOutputEventHubDesired("deviceId", []any{"deviceId"})
			delete(desired, missing)
			raw, err := json.Marshal(desired)
			require.NoError(t, err)
			_, err = prov.Create(context.Background(), &resource.CreateRequest{Label: "asaoutput", Properties: raw})
			require.ErrorContains(t, err, missing+" is required")
		})
	}
}
