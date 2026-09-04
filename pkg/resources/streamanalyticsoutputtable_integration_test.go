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

const testSAOutputTableKey = "dGFibGVrZXk="

func testSAOutputTableDesired(batchSize int) map[string]any {
	return map[string]any{
		"name":               "asaoutput",
		"resourceGroupName":  testSAJobResourceGroup,
		"jobName":            testSAJobName,
		"storageAccountName": "sa1",
		"storageAccountKey":  testSAOutputTableKey,
		"table":              "events",
		"partitionKey":       "deviceId",
		"rowKey":             "eventId",
		"batchSize":          batchSize,
		"columnsToRemove":    []any{"internalSeq"},
	}
}

func newTestSAOutputTable(api streamAnalyticsOutputsAPI) *StreamAnalyticsOutput {
	return &StreamAnalyticsOutput{api: api, kind: streamAnalyticsOutputTableKind}
}

func TestStreamAnalyticsOutputTable_CRUD(t *testing.T) {
	service := newSAOutputService()
	prov := newTestSAOutputTable(service)

	t.Run("Create", func(t *testing.T) {
		progress, props := saCreate(t, prov, testSAOutputTableDesired(25), "asaoutput")
		require.Equal(t, testSAOutputNativeID("asaoutput"), progress.NativeID)

		sent := service.lastSent()
		table, ok := sent.Properties.Datasource.(*armstreamanalytics.AzureTableOutputDataSource)
		require.True(t, ok)
		// Table storage, not SQL.
		require.Equal(t, "Microsoft.Storage/Table", *table.Type)
		require.Equal(t, "sa1", *table.Properties.AccountName)
		require.Equal(t, testSAOutputTableKey, *table.Properties.AccountKey)
		require.Equal(t, "events", *table.Properties.Table)
		require.Equal(t, "deviceId", *table.Properties.PartitionKey)
		require.Equal(t, "eventId", *table.Properties.RowKey)
		require.EqualValues(t, 25, *table.Properties.BatchSize)

		// The Azure Table output is the only one ARM takes no serialization block
		// for. Sending one is rejected, and emitting one on read would report
		// drift against a fixture that cannot declare it.
		require.Nil(t, sent.Properties.Serialization)
		require.NotContains(t, props, "serialization")

		saRequireNoSecrets(t, props)
	})

	t.Run("Read", func(t *testing.T) {
		props := saRead(t, prov, testSAOutputNativeID("asaoutput"))
		require.Equal(t, "sa1", props["storageAccountName"])
		require.Equal(t, "events", props["table"])
		require.Equal(t, "deviceId", props["partitionKey"])
		require.Equal(t, "eventId", props["rowKey"])
		require.EqualValues(t, 25, props["batchSize"])
		require.Equal(t, []any{"internalSeq"}, props["columnsToRemove"])
		require.NotContains(t, props, "serialization")
		saRequireNoSecrets(t, props)
	})

	t.Run("Update_resizes_batch", func(t *testing.T) {
		raw, err := json.Marshal(testSAOutputTableDesired(50))
		require.NoError(t, err)
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testSAOutputNativeID("asaoutput"),
			DesiredProperties: raw,
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Empty(t, got.ProgressResult.RequestID)

		var props map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &props))
		require.EqualValues(t, 50, props["batchSize"])
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

func TestStreamAnalyticsOutputTable_CreateRequiresDatasourceFields(t *testing.T) {
	prov := newTestSAOutputTable(newSAOutputService())

	for _, missing := range []string{"storageAccountName", "storageAccountKey", "table", "partitionKey", "rowKey"} {
		t.Run(missing, func(t *testing.T) {
			desired := testSAOutputTableDesired(25)
			delete(desired, missing)
			raw, err := json.Marshal(desired)
			require.NoError(t, err)
			_, err = prov.Create(context.Background(), &resource.CreateRequest{Label: "asaoutput", Properties: raw})
			require.ErrorContains(t, err, missing+" is required")
		})
	}
}

// batchSize and columnsToRemove are optional; ARM echoes them only when sent, so
// leaving them out must leave them out of state too.
func TestStreamAnalyticsOutputTable_OptionalFieldsOmitted(t *testing.T) {
	service := newSAOutputService()
	desired := testSAOutputTableDesired(25)
	delete(desired, "batchSize")
	delete(desired, "columnsToRemove")

	_, props := saCreate(t, newTestSAOutputTable(service), desired, "asaoutput")
	require.NotContains(t, props, "batchSize")
	require.NotContains(t, props, "columnsToRemove")

	sent := service.lastSent()
	table := sent.Properties.Datasource.(*armstreamanalytics.AzureTableOutputDataSource)
	require.Nil(t, table.Properties.BatchSize)
	require.Nil(t, table.Properties.ColumnsToRemove)
}
