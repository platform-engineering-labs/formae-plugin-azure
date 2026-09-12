// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/datafactory/armdatafactory"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
)

const ResourceTypeDataFactoryDatasetAzureSQLTable = "AZURE::DataFactory::DatasetAzureSqlTable"

// dataFactoryDatasetAzureSQLTableProps mirrors the format-specific half of
// schema/pkl/datafactory/datafactorydatasetazuresqltable.pkl. The shared half lives
// in dataFactoryDatasetCommon.
//
// schemaName and tableName are named for what they are rather than for ARM's own
// `schema` and `table`: `schema` on a dataset already means the column schema
// inherited from the Dataset base class, and reusing the word for a SQL schema in
// the same property set would be unreadable.
type dataFactoryDatasetAzureSQLTableProps struct {
	SchemaName *string `json:"schemaName"`
	TableName  *string `json:"tableName"`
}

// dataFactoryDatasetAzureSQLTableKind is the "AzureSqlTable" dataset — one table or
// view in the database its linked service points at.
//
// Both members are optional in ARM: a dataset with neither is a placeholder whose
// table is supplied by the copy activity that uses it. That is legal and is left
// expressible rather than rejected here.
var dataFactoryDatasetAzureSQLTableKind = datasetKind{
	resourceType: ResourceTypeDataFactoryDatasetAzureSQLTable,
	armType:      "AzureSqlTable",

	build: func(common *dataFactoryDatasetCommon, payload json.RawMessage) (armdatafactory.DatasetClassification, error) {
		var props dataFactoryDatasetAzureSQLTableProps
		if err := json.Unmarshal(payload, &props); err != nil {
			return nil, fmt.Errorf("failed to parse resource properties: %w", err)
		}

		typeProps := &armdatafactory.AzureSQLTableDatasetTypeProperties{}
		if props.SchemaName != nil && *props.SchemaName != "" {
			typeProps.Schema = *props.SchemaName
		}
		if props.TableName != nil && *props.TableName != "" {
			typeProps.Table = *props.TableName
		}

		return &armdatafactory.AzureSQLTableDataset{
			Type:              to.Ptr("AzureSqlTable"),
			LinkedServiceName: common.linkedServiceRef(),
			Description:       common.Description,
			Folder:            common.folder(),
			Annotations:       common.annotationList(),
			TypeProperties:    typeProps,
		}, nil
	},

	readTypeProperties: func(properties armdatafactory.DatasetClassification, props map[string]any) {
		ds, ok := properties.(*armdatafactory.AzureSQLTableDataset)
		if !ok || ds.TypeProperties == nil {
			return
		}
		if v, ok := dataFactoryExpressionString(ds.TypeProperties.Schema); ok {
			props["schemaName"] = v
		}
		if v, ok := dataFactoryExpressionString(ds.TypeProperties.Table); ok {
			props["tableName"] = v
		}
		// typeProperties.tableName — ARM's own retired member, distinct from the
		// tableName above, which maps to typeProperties.table — is neither sent
		// nor read: the service documents it as superseded by schema + table.
	},
}

func init() {
	registry.Register(ResourceTypeDataFactoryDatasetAzureSQLTable, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &DataFactoryDataset{
			api:    c.DataFactoryDatasetsClient,
			kind:   &dataFactoryDatasetAzureSQLTableKind,
			config: cfg,
		}
	})
}
