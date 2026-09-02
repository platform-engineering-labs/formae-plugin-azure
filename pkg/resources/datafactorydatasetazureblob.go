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

const ResourceTypeDataFactoryDatasetAzureBlob = "AZURE::DataFactory::DatasetAzureBlob"

// dataFactoryDatasetAzureBlobProps mirrors the format-specific half of
// schema/pkl/datafactory/datafactorydatasetazureblob.pkl. The shared half lives in
// dataFactoryDatasetCommon.
type dataFactoryDatasetAzureBlobProps struct {
	FolderPath        *string `json:"folderPath"`
	FileName          *string `json:"fileName"`
	TableRootLocation *string `json:"tableRootLocation"`
}

// dataFactoryDatasetAzureBlobKind is the legacy "AzureBlob" dataset.
//
// It predates the DatasetLocation union: the blob path is carried as a flat
// folderPath / fileName pair on typeProperties rather than in a location block,
// which is why this type looks different from DelimitedText, Json and Parquet even
// though it points at the same storage.
var dataFactoryDatasetAzureBlobKind = datasetKind{
	resourceType: ResourceTypeDataFactoryDatasetAzureBlob,
	armType:      "AzureBlob",

	build: func(common *dataFactoryDatasetCommon, payload json.RawMessage) (armdatafactory.DatasetClassification, error) {
		var props dataFactoryDatasetAzureBlobProps
		if err := json.Unmarshal(payload, &props); err != nil {
			return nil, fmt.Errorf("failed to parse resource properties: %w", err)
		}

		typeProps := &armdatafactory.AzureBlobDatasetTypeProperties{}
		if props.FolderPath != nil && *props.FolderPath != "" {
			typeProps.FolderPath = *props.FolderPath
		}
		if props.FileName != nil && *props.FileName != "" {
			typeProps.FileName = *props.FileName
		}
		if props.TableRootLocation != nil && *props.TableRootLocation != "" {
			typeProps.TableRootLocation = *props.TableRootLocation
		}

		return &armdatafactory.AzureBlobDataset{
			Type:              to.Ptr("AzureBlob"),
			LinkedServiceName: common.linkedServiceRef(),
			Description:       common.Description,
			Folder:            common.folder(),
			Annotations:       common.annotationList(),
			TypeProperties:    typeProps,
		}, nil
	},

	readTypeProperties: func(properties armdatafactory.DatasetClassification, props map[string]any) {
		ds, ok := properties.(*armdatafactory.AzureBlobDataset)
		if !ok || ds.TypeProperties == nil {
			return
		}
		if v, ok := dataFactoryExpressionString(ds.TypeProperties.FolderPath); ok {
			props["folderPath"] = v
		}
		if v, ok := dataFactoryExpressionString(ds.TypeProperties.FileName); ok {
			props["fileName"] = v
		}
		if v, ok := dataFactoryExpressionString(ds.TypeProperties.TableRootLocation); ok {
			props["tableRootLocation"] = v
		}
		// format, compression, modifiedDatetimeStart and modifiedDatetimeEnd are
		// not modelled at all: format is a second discriminated union nested
		// inside this one, and the two datetimes are read filters rather than a
		// description of the data.
	},
}

func init() {
	registry.Register(ResourceTypeDataFactoryDatasetAzureBlob, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &DataFactoryDataset{
			api:    c.DataFactoryDatasetsClient,
			kind:   &dataFactoryDatasetAzureBlobKind,
			config: cfg,
		}
	})
}
