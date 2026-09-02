// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/streamanalytics/armstreamanalytics"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
)

const ResourceTypeStreamAnalyticsOutputTable = "AZURE::StreamAnalytics::OutputTable"

// streamAnalyticsTableDatasourceType is the ARM discriminator for the Azure Table
// storage output datasource. Table storage, not SQL: "Microsoft.Sql/Server/Database"
// is a different output type entirely.
const streamAnalyticsTableDatasourceType = "Microsoft.Storage/Table"

func init() {
	registry.Register(ResourceTypeStreamAnalyticsOutputTable, func(c *client.Client, _ *config.Config) prov.Provisioner {
		return &StreamAnalyticsOutput{
			api:  c.StreamAnalyticsOutputsClient,
			kind: streamAnalyticsOutputTableKind,
		}
	})
}

// streamAnalyticsOutputTableKind is the Azure Table half of
// AZURE::StreamAnalytics::OutputTable. The envelope lives in streamanalyticsio.go.
//
// This is the one output whose ARM body carries no `properties.serialization`
// block at all — the row shape comes from partitionKey/rowKey and the query's
// SELECT list — hence serialization: false.
var streamAnalyticsOutputTableKind = streamAnalyticsOutputKind{
	resourceType:   ResourceTypeStreamAnalyticsOutputTable,
	datasourceType: streamAnalyticsTableDatasourceType,
	serialization:  false,

	build: func(props map[string]any) (armstreamanalytics.OutputDataSourceClassification, error) {
		accountName, err := saRequiredString(props, "storageAccountName")
		if err != nil {
			return nil, err
		}
		accountKey, err := saRequiredString(props, "storageAccountKey")
		if err != nil {
			return nil, err
		}
		table, err := saRequiredString(props, "table")
		if err != nil {
			return nil, err
		}
		partitionKey, err := saRequiredString(props, "partitionKey")
		if err != nil {
			return nil, err
		}
		rowKey, err := saRequiredString(props, "rowKey")
		if err != nil {
			return nil, err
		}

		return &armstreamanalytics.AzureTableOutputDataSource{
			Type: to.Ptr(streamAnalyticsTableDatasourceType),
			Properties: &armstreamanalytics.AzureTableOutputDataSourceProperties{
				AccountName:     to.Ptr(accountName),
				AccountKey:      to.Ptr(accountKey),
				Table:           to.Ptr(table),
				PartitionKey:    to.Ptr(partitionKey),
				RowKey:          to.Ptr(rowKey),
				BatchSize:       saInt32Ptr(props, "batchSize"),
				ColumnsToRemove: stringPointers(saStringList(props, "columnsToRemove")),
			},
		}, nil
	},

	serialize: func(ds armstreamanalytics.OutputDataSourceClassification, props map[string]any) {
		table, ok := ds.(*armstreamanalytics.AzureTableOutputDataSource)
		if !ok || table == nil || table.Properties == nil {
			return
		}
		body := table.Properties
		if body.AccountName != nil {
			props["storageAccountName"] = *body.AccountName
		}
		if body.Table != nil {
			props["table"] = *body.Table
		}
		if body.PartitionKey != nil {
			props["partitionKey"] = *body.PartitionKey
		}
		if body.RowKey != nil {
			props["rowKey"] = *body.RowKey
		}
		if body.BatchSize != nil {
			props["batchSize"] = *body.BatchSize
		}
		if columns := stringsFromPointers(body.ColumnsToRemove); columns != nil {
			props["columnsToRemove"] = columns
		}
		// storageAccountKey is never echoed: ARM strips AccountKey from responses.
	},
}
