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

const testSAOutputBlobKey = "b3V0YmxvYmtleQ=="

func testSAOutputBlobDesired(pathPattern string) map[string]any {
	return map[string]any{
		"name":               "asaoutput",
		"resourceGroupName":  testSAJobResourceGroup,
		"jobName":            testSAJobName,
		"storageAccountName": "sa1",
		"storageAccountKey":  testSAOutputBlobKey,
		"container":          "results",
		"pathPattern":        pathPattern,
		"dateFormat":         "yyyy/MM/dd",
		"timeFormat":         "HH",
		"serialization": map[string]any{
			"type": "Json", "encoding": "UTF8", "format": "LineSeparated",
		},
	}
}

func newTestSAOutputBlob(api streamAnalyticsOutputsAPI) *StreamAnalyticsOutput {
	return &StreamAnalyticsOutput{api: api, kind: streamAnalyticsOutputBlobKind}
}

func TestStreamAnalyticsOutputBlob_CRUD(t *testing.T) {
	service := newSAOutputService()
	prov := newTestSAOutputBlob(service)

	t.Run("Create", func(t *testing.T) {
		progress, props := saCreate(t, prov, testSAOutputBlobDesired("{date}/{time}"), "asaoutput")
		require.Equal(t, testSAOutputNativeID("asaoutput"), progress.NativeID)

		sent := service.lastSent()
		blob, ok := sent.Properties.Datasource.(*armstreamanalytics.BlobOutputDataSource)
		require.True(t, ok)
		require.Equal(t, streamAnalyticsBlobDatasourceType, *blob.Type)
		require.Len(t, blob.Properties.StorageAccounts, 1)
		require.Equal(t, "sa1", *blob.Properties.StorageAccounts[0].AccountName)
		require.Equal(t, testSAOutputBlobKey, *blob.Properties.StorageAccounts[0].AccountKey)
		require.Equal(t, "results", *blob.Properties.Container)
		// Unlike the Azure Table output, a blob output does carry serialization.
		require.NotNil(t, sent.Properties.Serialization)

		saRequireNoSecrets(t, props)
	})

	t.Run("Read", func(t *testing.T) {
		props := saRead(t, prov, testSAOutputNativeID("asaoutput"))
		require.Equal(t, "asaoutput", props["name"])
		require.Equal(t, "sa1", props["storageAccountName"])
		require.Equal(t, "results", props["container"])
		require.Equal(t, "{date}/{time}", props["pathPattern"])
		require.Equal(t, map[string]any{
			"type": "Json", "encoding": "UTF8", "format": "LineSeparated",
		}, props["serialization"])
		saRequireNoSecrets(t, props)
	})

	t.Run("Update_is_synchronous", func(t *testing.T) {
		raw, err := json.Marshal(testSAOutputBlobDesired("out/{date}/{time}"))
		require.NoError(t, err)
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testSAOutputNativeID("asaoutput"),
			DesiredProperties: raw,
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Empty(t, got.ProgressResult.RequestID)

		// The credential is re-sent on a PATCH; ARM keeps no copy to merge with.
		sent := service.lastSent()
		blob := sent.Properties.Datasource.(*armstreamanalytics.BlobOutputDataSource)
		require.Equal(t, testSAOutputBlobKey, *blob.Properties.StorageAccounts[0].AccountKey)

		var props map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &props))
		require.Equal(t, "out/{date}/{time}", props["pathPattern"])
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

func TestStreamAnalyticsOutputBlob_CreateRequiresDatasourceFields(t *testing.T) {
	prov := newTestSAOutputBlob(newSAOutputService())

	for _, missing := range []string{"storageAccountName", "storageAccountKey", "container", "pathPattern"} {
		t.Run(missing, func(t *testing.T) {
			desired := testSAOutputBlobDesired("{date}/{time}")
			delete(desired, missing)
			raw, err := json.Marshal(desired)
			require.NoError(t, err)
			_, err = prov.Create(context.Background(), &resource.CreateRequest{Label: "asaoutput", Properties: raw})
			require.ErrorContains(t, err, missing+" is required")
		})
	}
}

func TestStreamAnalyticsOutputBlob_ReadNotFound(t *testing.T) {
	service := newSAOutputService()
	service.getErr = testSANotFound()
	got, err := newTestSAOutputBlob(service).Read(context.Background(), &resource.ReadRequest{
		NativeID: testSAOutputNativeID("asaoutput"),
	})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}
