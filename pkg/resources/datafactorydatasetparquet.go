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

const ResourceTypeDataFactoryDatasetParquet = "AZURE::DataFactory::DatasetParquet"

// dataFactoryDatasetParquetProps mirrors the format-specific half of
// schema/pkl/datafactory/datafactorydatasetparquet.pkl. The shared half lives in
// dataFactoryDatasetCommon, and the location half in dataFactoryBlobLocationProps.
type dataFactoryDatasetParquetProps struct {
	dataFactoryBlobLocationProps
	CompressionCodec *string `json:"compressionCodec"`
}

// dataFactoryDatasetParquetKind is the "Parquet" dataset.
//
// Parquet carries its own schema in the file footer, so there is nothing to declare
// beyond the location and the codec pages are compressed with.
var dataFactoryDatasetParquetKind = datasetKind{
	resourceType: ResourceTypeDataFactoryDatasetParquet,
	armType:      "Parquet",

	build: func(common *dataFactoryDatasetCommon, payload json.RawMessage) (armdatafactory.DatasetClassification, error) {
		var props dataFactoryDatasetParquetProps
		if err := json.Unmarshal(payload, &props); err != nil {
			return nil, fmt.Errorf("failed to parse resource properties: %w", err)
		}
		location, err := props.blobLocation()
		if err != nil {
			return nil, err
		}

		typeProps := &armdatafactory.ParquetDatasetTypeProperties{Location: location}
		if props.CompressionCodec != nil && *props.CompressionCodec != "" {
			typeProps.CompressionCodec = *props.CompressionCodec
		}

		return &armdatafactory.ParquetDataset{
			Type:              to.Ptr("Parquet"),
			LinkedServiceName: common.linkedServiceRef(),
			Description:       common.Description,
			Folder:            common.folder(),
			Annotations:       common.annotationList(),
			TypeProperties:    typeProps,
		}, nil
	},

	readTypeProperties: func(properties armdatafactory.DatasetClassification, props map[string]any) {
		ds, ok := properties.(*armdatafactory.ParquetDataset)
		if !ok || ds.TypeProperties == nil {
			return
		}
		dataFactoryReadBlobLocation(ds.TypeProperties.Location, props)
		if v, ok := dataFactoryExpressionString(ds.TypeProperties.CompressionCodec); ok {
			props["compressionCodec"] = v
		}
	},
}

func init() {
	registry.Register(ResourceTypeDataFactoryDatasetParquet, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &DataFactoryDataset{
			api:    c.DataFactoryDatasetsClient,
			kind:   &dataFactoryDatasetParquetKind,
			config: cfg,
		}
	})
}
