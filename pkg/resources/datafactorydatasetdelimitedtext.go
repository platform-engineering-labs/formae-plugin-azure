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

const ResourceTypeDataFactoryDatasetDelimitedText = "AZURE::DataFactory::DatasetDelimitedText"

// dataFactoryDatasetDelimitedTextProps mirrors the format-specific half of
// schema/pkl/datafactory/datafactorydatasetdelimitedtext.pkl. The shared half lives
// in dataFactoryDatasetCommon, and the location half in
// dataFactoryBlobLocationProps.
type dataFactoryDatasetDelimitedTextProps struct {
	dataFactoryBlobLocationProps
	ColumnDelimiter  *string `json:"columnDelimiter"`
	RowDelimiter     *string `json:"rowDelimiter"`
	QuoteChar        *string `json:"quoteChar"`
	EscapeChar       *string `json:"escapeChar"`
	NullValue        *string `json:"nullValue"`
	EncodingName     *string `json:"encodingName"`
	CompressionCodec *string `json:"compressionCodec"`
	FirstRowAsHeader *bool   `json:"firstRowAsHeader"`
}

// dataFactoryExpressionBool narrows one of ARM's `interface{}`-typed dataset fields
// back to a plain bool, the same way dataFactoryExpressionString does for strings.
//
// A factory expression comes back as an object, which no PKL boolean could match,
// so it is reported as absent rather than coerced.
func dataFactoryExpressionBool(value any) (bool, bool) {
	b, ok := value.(bool)
	return b, ok
}

// dataFactoryDatasetDelimitedTextKind is the "DelimitedText" dataset — CSV and its
// relatives.
//
// Every dialect field (columnDelimiter, quoteChar, ...) has a documented service
// default, but the service does not write those defaults into the stored
// definition: an omitted field reads back absent, not filled in. They are therefore
// plain optionals rather than hasProviderDefault, and the conformance fixture sets
// each one explicitly so that a future change of that behaviour cannot be mistaken
// for drift the provider caused.
var dataFactoryDatasetDelimitedTextKind = datasetKind{
	resourceType: ResourceTypeDataFactoryDatasetDelimitedText,
	armType:      "DelimitedText",

	build: func(common *dataFactoryDatasetCommon, payload json.RawMessage) (armdatafactory.DatasetClassification, error) {
		var props dataFactoryDatasetDelimitedTextProps
		if err := json.Unmarshal(payload, &props); err != nil {
			return nil, fmt.Errorf("failed to parse resource properties: %w", err)
		}
		location, err := props.blobLocation()
		if err != nil {
			return nil, err
		}

		typeProps := &armdatafactory.DelimitedTextDatasetTypeProperties{Location: location}
		if props.ColumnDelimiter != nil && *props.ColumnDelimiter != "" {
			typeProps.ColumnDelimiter = *props.ColumnDelimiter
		}
		if props.RowDelimiter != nil && *props.RowDelimiter != "" {
			typeProps.RowDelimiter = *props.RowDelimiter
		}
		if props.QuoteChar != nil && *props.QuoteChar != "" {
			typeProps.QuoteChar = *props.QuoteChar
		}
		if props.EscapeChar != nil && *props.EscapeChar != "" {
			typeProps.EscapeChar = *props.EscapeChar
		}
		if props.NullValue != nil && *props.NullValue != "" {
			typeProps.NullValue = *props.NullValue
		}
		if props.EncodingName != nil && *props.EncodingName != "" {
			typeProps.EncodingName = *props.EncodingName
		}
		if props.CompressionCodec != nil && *props.CompressionCodec != "" {
			typeProps.CompressionCodec = *props.CompressionCodec
		}
		if props.FirstRowAsHeader != nil {
			typeProps.FirstRowAsHeader = *props.FirstRowAsHeader
		}

		return &armdatafactory.DelimitedTextDataset{
			Type:              to.Ptr("DelimitedText"),
			LinkedServiceName: common.linkedServiceRef(),
			Description:       common.Description,
			Folder:            common.folder(),
			Annotations:       common.annotationList(),
			TypeProperties:    typeProps,
		}, nil
	},

	readTypeProperties: func(properties armdatafactory.DatasetClassification, props map[string]any) {
		ds, ok := properties.(*armdatafactory.DelimitedTextDataset)
		if !ok || ds.TypeProperties == nil {
			return
		}
		dataFactoryReadBlobLocation(ds.TypeProperties.Location, props)
		if v, ok := dataFactoryExpressionString(ds.TypeProperties.ColumnDelimiter); ok {
			props["columnDelimiter"] = v
		}
		if v, ok := dataFactoryExpressionString(ds.TypeProperties.RowDelimiter); ok {
			props["rowDelimiter"] = v
		}
		if v, ok := dataFactoryExpressionString(ds.TypeProperties.QuoteChar); ok {
			props["quoteChar"] = v
		}
		if v, ok := dataFactoryExpressionString(ds.TypeProperties.EscapeChar); ok {
			props["escapeChar"] = v
		}
		if v, ok := dataFactoryExpressionString(ds.TypeProperties.NullValue); ok {
			props["nullValue"] = v
		}
		if v, ok := dataFactoryExpressionString(ds.TypeProperties.EncodingName); ok {
			props["encodingName"] = v
		}
		if v, ok := dataFactoryExpressionString(ds.TypeProperties.CompressionCodec); ok {
			props["compressionCodec"] = v
		}
		if v, ok := dataFactoryExpressionBool(ds.TypeProperties.FirstRowAsHeader); ok {
			props["firstRowAsHeader"] = v
		}
		// compressionLevel is not modelled: it is meaningful only alongside a
		// compressionCodec and ARM types it as free-form JSON.
	},
}

func init() {
	registry.Register(ResourceTypeDataFactoryDatasetDelimitedText, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &DataFactoryDataset{
			api:    c.DataFactoryDatasetsClient,
			kind:   &dataFactoryDatasetDelimitedTextKind,
			config: cfg,
		}
	})
}
