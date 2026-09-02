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

const ResourceTypeDataFactoryDatasetJSON = "AZURE::DataFactory::DatasetJson"

// dataFactoryDatasetJSONProps mirrors the format-specific half of
// schema/pkl/datafactory/datafactorydatasetjson.pkl. The shared half lives in
// dataFactoryDatasetCommon, and the location half in dataFactoryBlobLocationProps.
type dataFactoryDatasetJSONProps struct {
	dataFactoryBlobLocationProps
	EncodingName *string `json:"encodingName"`
}

// dataFactoryDatasetJSONKind is the "Json" dataset.
//
// The thinnest of the four file-based formats: a location and, optionally, the code
// page the file is written in. Whether the file holds one JSON document, an array or
// newline-delimited records is decided by the activity that reads it, not by the
// dataset.
var dataFactoryDatasetJSONKind = datasetKind{
	resourceType: ResourceTypeDataFactoryDatasetJSON,
	armType:      "Json",

	build: func(common *dataFactoryDatasetCommon, payload json.RawMessage) (armdatafactory.DatasetClassification, error) {
		var props dataFactoryDatasetJSONProps
		if err := json.Unmarshal(payload, &props); err != nil {
			return nil, fmt.Errorf("failed to parse resource properties: %w", err)
		}
		location, err := props.blobLocation()
		if err != nil {
			return nil, err
		}

		typeProps := &armdatafactory.JSONDatasetTypeProperties{Location: location}
		if props.EncodingName != nil && *props.EncodingName != "" {
			typeProps.EncodingName = *props.EncodingName
		}

		return &armdatafactory.JSONDataset{
			Type:              to.Ptr("Json"),
			LinkedServiceName: common.linkedServiceRef(),
			Description:       common.Description,
			Folder:            common.folder(),
			Annotations:       common.annotationList(),
			TypeProperties:    typeProps,
		}, nil
	},

	readTypeProperties: func(properties armdatafactory.DatasetClassification, props map[string]any) {
		ds, ok := properties.(*armdatafactory.JSONDataset)
		if !ok || ds.TypeProperties == nil {
			return
		}
		dataFactoryReadBlobLocation(ds.TypeProperties.Location, props)
		if v, ok := dataFactoryExpressionString(ds.TypeProperties.EncodingName); ok {
			props["encodingName"] = v
		}
		// compression is not modelled: it is a nested object whose only member
		// this schema would express is a codec name, and the Json format carries
		// no compression in the fixtures this plugin ships.
	},
}

func init() {
	registry.Register(ResourceTypeDataFactoryDatasetJSON, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &DataFactoryDataset{
			api:    c.DataFactoryDatasetsClient,
			kind:   &dataFactoryDatasetJSONKind,
			config: cfg,
		}
	})
}
