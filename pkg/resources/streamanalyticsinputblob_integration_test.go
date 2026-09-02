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

// testSAInputBlobKey is a placeholder, matching what the conformance fixture
// sends. ARM accepts any string and never returns it.
const testSAInputBlobKey = "cGxhY2VobGRlcg=="

func testSAInputBlobDesired(pathPattern string) map[string]any {
	return map[string]any{
		"name":               "asainput",
		"resourceGroupName":  testSAJobResourceGroup,
		"jobName":            testSAJobName,
		"storageAccountName": "sa1",
		"storageAccountKey":  testSAInputBlobKey,
		"container":          "landing",
		"pathPattern":        pathPattern,
		"dateFormat":         "yyyy/MM/dd",
		"timeFormat":         "HH",
		"serialization":      map[string]any{"type": "Json", "encoding": "UTF8"},
	}
}

func newTestSAInputBlob(api streamAnalyticsInputsAPI) *StreamAnalyticsInput {
	return &StreamAnalyticsInput{api: api, kind: streamAnalyticsInputBlobKind}
}

func TestStreamAnalyticsInputBlob_CRUD(t *testing.T) {
	service := newSAInputService()
	prov := newTestSAInputBlob(service)

	t.Run("Create", func(t *testing.T) {
		progress, props := saCreate(t, prov, testSAInputBlobDesired("{date}/{time}"), "asainput")
		require.Equal(t, testSAInputNativeID("asainput"), progress.NativeID)

		// The PUT body must carry the flattened account name AND the key, inside
		// ARM's single-element storageAccounts array.
		sent := service.lastSent()
		stream, ok := sent.Properties.(*armstreamanalytics.StreamInputProperties)
		require.True(t, ok)
		require.Equal(t, "Stream", *stream.Type)
		blob, ok := stream.Datasource.(*armstreamanalytics.BlobStreamInputDataSource)
		require.True(t, ok)
		require.Equal(t, streamAnalyticsBlobDatasourceType, *blob.Type)
		require.Len(t, blob.Properties.StorageAccounts, 1)
		require.Equal(t, "sa1", *blob.Properties.StorageAccounts[0].AccountName)
		require.Equal(t, testSAInputBlobKey, *blob.Properties.StorageAccounts[0].AccountKey)
		require.Equal(t, "landing", *blob.Properties.Container)
		require.Equal(t, "{date}/{time}", *blob.Properties.PathPattern)

		require.Equal(t, "sa1", props["storageAccountName"])
		require.Equal(t, "landing", props["container"])
		saRequireNoSecrets(t, props)
	})

	t.Run("Read", func(t *testing.T) {
		props := saRead(t, prov, testSAInputNativeID("asainput"))
		require.Equal(t, "asainput", props["name"])
		require.Equal(t, testSAJobName, props["jobName"])
		require.Equal(t, testSAJobResourceGroup, props["resourceGroupName"])
		require.Equal(t, "{date}/{time}", props["pathPattern"])
		require.Equal(t, "yyyy/MM/dd", props["dateFormat"])
		require.Equal(t, "HH", props["timeFormat"])
		require.Equal(t, map[string]any{"type": "Json", "encoding": "UTF8"}, props["serialization"])
		// sourcePartitionCount was never declared, so it must not appear: an
		// invented value reads as drift in every conformance phase.
		require.NotContains(t, props, "sourcePartitionCount")
		saRequireNoSecrets(t, props)
	})

	t.Run("Update_is_synchronous", func(t *testing.T) {
		raw, err := json.Marshal(testSAInputBlobDesired("in/{date}/{time}"))
		require.NoError(t, err)
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testSAInputNativeID("asainput"),
			DesiredProperties: raw,
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Empty(t, got.ProgressResult.RequestID)

		// The credential has to be re-sent on a PATCH; ARM has no other copy of
		// it to merge against.
		sent := service.lastSent()
		stream := sent.Properties.(*armstreamanalytics.StreamInputProperties)
		blob := stream.Datasource.(*armstreamanalytics.BlobStreamInputDataSource)
		require.Equal(t, "in/{date}/{time}", *blob.Properties.PathPattern)
		require.Equal(t, testSAInputBlobKey, *blob.Properties.StorageAccounts[0].AccountKey)

		var props map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &props))
		require.Equal(t, "in/{date}/{time}", props["pathPattern"])
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

func TestStreamAnalyticsInputBlob_CreateRequiresDatasourceFields(t *testing.T) {
	prov := newTestSAInputBlob(newSAInputService())

	for _, missing := range []string{"storageAccountName", "storageAccountKey", "container", "pathPattern", "resourceGroupName", "jobName"} {
		t.Run(missing, func(t *testing.T) {
			desired := testSAInputBlobDesired("{date}/{time}")
			delete(desired, missing)
			raw, err := json.Marshal(desired)
			require.NoError(t, err)
			_, err = prov.Create(context.Background(), &resource.CreateRequest{Label: "asainput", Properties: raw})
			require.ErrorContains(t, err, missing+" is required")
		})
	}
}

func TestStreamAnalyticsInputBlob_ReadNotFound(t *testing.T) {
	service := newSAInputService()
	service.getErr = testSANotFound()
	got, err := newTestSAInputBlob(service).Read(context.Background(), &resource.ReadRequest{
		NativeID: testSAInputNativeID("asainput"),
	})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// A caller who does declare sourcePartitionCount must see it round-trip.
func TestStreamAnalyticsInputBlob_SourcePartitionCountRoundTrips(t *testing.T) {
	service := newSAInputService()
	prov := newTestSAInputBlob(service)

	desired := testSAInputBlobDesired("{partition}/{date}/{time}")
	desired["sourcePartitionCount"] = 4
	_, props := saCreate(t, prov, desired, "asainput")
	require.EqualValues(t, 4, props["sourcePartitionCount"])
}
