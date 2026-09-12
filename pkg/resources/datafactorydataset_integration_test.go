// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/datafactory/armdatafactory"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

// All five AZURE::DataFactory::Dataset* types run through the one
// DataFactoryDataset provisioner, so the shared CRUD is exercised once against the
// AzureSqlTable format — the one with no location block — and each of the other
// four gets its own build/read round trip. Same layout as
// datafactorylinkedservice_integration_test.go.

const testDatasetNativeID = testDataFactoryNativeID + "/datasets/ds-1"

func newTestDataset(api dataFactoryDatasetsAPI, kind *datasetKind) *DataFactoryDataset {
	return &DataFactoryDataset{
		api:    api,
		kind:   kind,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func datasetDesired(overrides map[string]any) []byte {
	props := map[string]any{
		"name":              "ds-1",
		"resourceGroupName": "rg-1",
		"factoryName":       "adf-1",
		"linkedServiceName": "ls-1",
	}
	for k, v := range overrides {
		if v == nil {
			delete(props, k)
			continue
		}
		props[k] = v
	}
	out, _ := json.Marshal(props)
	return out
}

// datasetRoundTrip builds a payload through a kind and hands the result straight
// back to that kind's reader, which is what an ARM echo of an unchanged dataset
// amounts to.
func datasetRoundTrip(t *testing.T, kind *datasetKind, payload []byte) (armdatafactory.DatasetClassification, map[string]any) {
	t.Helper()
	var common dataFactoryDatasetCommon
	require.NoError(t, common.parse(payload, "ds-1"))
	built, err := kind.build(&common, payload)
	require.NoError(t, err)

	prov := newTestDataset(nil, kind)
	props := prov.buildPropertiesFromResult(&armdatafactory.DatasetResource{
		ID:         to.Ptr(testDatasetNativeID),
		Name:       to.Ptr("ds-1"),
		Etag:       to.Ptr("W/\"datetime\""),
		Properties: built,
	}, "rg-1", "adf-1")
	return built, props
}

func TestDataFactoryDataset_SharedCRUD(t *testing.T) {
	sqlTableResult := armdatafactory.DatasetResource{
		ID:   to.Ptr(testDatasetNativeID),
		Name: to.Ptr("ds-1"),
		Properties: &armdatafactory.AzureSQLTableDataset{
			Type:        to.Ptr("AzureSqlTable"),
			Description: to.Ptr("orders table"),
			Annotations: []any{"conformance"},
			Folder:      &armdatafactory.DatasetFolder{Name: to.Ptr("conformance")},
			LinkedServiceName: &armdatafactory.LinkedServiceReference{
				Type:          to.Ptr(armdatafactory.LinkedServiceReferenceTypeLinkedServiceReference),
				ReferenceName: to.Ptr("ls-1"),
			},
			TypeProperties: &armdatafactory.AzureSQLTableDatasetTypeProperties{
				Schema: "dbo",
				Table:  "orders",
			},
		},
	}

	var sent armdatafactory.DatasetResource
	var sawRG, sawFactory, sawName string
	createCalls := 0
	deleteCalls := 0
	fake := &fakeDatasetsAPI{
		createOrUpdateFn: func(_ context.Context, rgName, factoryName, name string, params armdatafactory.DatasetResource, _ *armdatafactory.DatasetsClientCreateOrUpdateOptions) (armdatafactory.DatasetsClientCreateOrUpdateResponse, error) {
			sawRG, sawFactory, sawName, sent = rgName, factoryName, name, params
			createCalls++
			return armdatafactory.DatasetsClientCreateOrUpdateResponse{DatasetResource: sqlTableResult}, nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ *armdatafactory.DatasetsClientGetOptions) (armdatafactory.DatasetsClientGetResponse, error) {
			return armdatafactory.DatasetsClientGetResponse{DatasetResource: sqlTableResult}, nil
		},
		deleteFn: func(_ context.Context, _, _, _ string, _ *armdatafactory.DatasetsClientDeleteOptions) (armdatafactory.DatasetsClientDeleteResponse, error) {
			deleteCalls++
			return armdatafactory.DatasetsClientDeleteResponse{}, nil
		},
		newListByFactoryPagerFn: func(_, _ string, _ *armdatafactory.DatasetsClientListByFactoryOptions) *runtime.Pager[armdatafactory.DatasetsClientListByFactoryResponse] {
			return runtime.NewPager(runtime.PagingHandler[armdatafactory.DatasetsClientListByFactoryResponse]{
				More: func(_ armdatafactory.DatasetsClientListByFactoryResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armdatafactory.DatasetsClientListByFactoryResponse) (armdatafactory.DatasetsClientListByFactoryResponse, error) {
					return armdatafactory.DatasetsClientListByFactoryResponse{
						DatasetListResponse: armdatafactory.DatasetListResponse{
							Value: []*armdatafactory.DatasetResource{
								{
									ID: to.Ptr(testDatasetNativeID),
									Properties: &armdatafactory.AzureSQLTableDataset{
										Type: to.Ptr("AzureSqlTable"),
									},
								},
								{
									// A different format in the same factory: it
									// must not be claimed by this type.
									ID: to.Ptr(testDataFactoryNativeID + "/datasets/parquet-1"),
									Properties: &armdatafactory.ParquetDataset{
										Type: to.Ptr("Parquet"),
									},
								},
								// No ID and no properties: skipped, not a panic.
								{},
							},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestDataset(fake, &dataFactoryDatasetAzureSQLTableKind)

	sqlTableProps := map[string]any{
		"schemaName":  "dbo",
		"tableName":   "orders",
		"description": "orders table",
		"folderName":  "conformance",
		"annotations": []string{"conformance"},
	}

	// DatasetsClient has no BeginX: a create reports success directly and never
	// hands back a resume token.
	t.Run("Create_is_synchronous", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "ds-1",
			Properties: datasetDesired(sqlTableProps),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testDatasetNativeID, got.ProgressResult.NativeID)
		require.Empty(t, got.ProgressResult.RequestID)

		require.Equal(t, "rg-1", sawRG)
		require.Equal(t, "adf-1", sawFactory)
		require.Equal(t, "ds-1", sawName)

		ds, ok := sent.Properties.(*armdatafactory.AzureSQLTableDataset)
		require.True(t, ok)
		require.Equal(t, "dbo", ds.TypeProperties.Schema)
		require.Equal(t, "orders", ds.TypeProperties.Table)
		require.Equal(t, "orders table", *ds.Description)
		require.Equal(t, "conformance", *ds.Folder.Name)
		require.Equal(t, []any{"conformance"}, ds.Annotations)
		// The linked-service reference is not optional: ARM rejects a dataset
		// without one, and it always carries the discriminator.
		require.Equal(t, "ls-1", *ds.LinkedServiceName.ReferenceName)
		require.Equal(t, armdatafactory.LinkedServiceReferenceTypeLinkedServiceReference,
			*ds.LinkedServiceName.Type)
	})

	// An undeclared folder must leave the block out so the dataset appears at the
	// root of the authoring UI.
	t.Run("Create_without_folder_sends_none", func(t *testing.T) {
		_, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "ds-1",
			Properties: datasetDesired(nil),
		})
		require.NoError(t, err)
		ds, ok := sent.Properties.(*armdatafactory.AzureSQLTableDataset)
		require.True(t, ok)
		require.Nil(t, ds.Folder)
		require.Nil(t, ds.Annotations)
		require.Nil(t, ds.Description)
	})

	t.Run("Create_requires_factory", func(t *testing.T) {
		_, err := prov.Create(context.Background(), &resource.CreateRequest{
			Properties: datasetDesired(map[string]any{"factoryName": nil}),
		})
		require.ErrorContains(t, err, "factoryName is required")
	})

	t.Run("Create_requires_resource_group", func(t *testing.T) {
		_, err := prov.Create(context.Background(), &resource.CreateRequest{
			Properties: datasetDesired(map[string]any{"resourceGroupName": nil}),
		})
		require.ErrorContains(t, err, "resourceGroupName is required")
	})

	// ARM rejects a dataset with no linked service, so the mistake is caught
	// before any ARM call rather than as an opaque 400.
	t.Run("Create_requires_linked_service", func(t *testing.T) {
		_, err := prov.Create(context.Background(), &resource.CreateRequest{
			Properties: datasetDesired(map[string]any{"linkedServiceName": nil}),
		})
		require.ErrorContains(t, err, "linkedServiceName is required")
	})

	t.Run("Create_falls_back_to_label_for_name", func(t *testing.T) {
		_, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "ds-1",
			Properties: datasetDesired(map[string]any{"name": nil}),
		})
		require.NoError(t, err)
		require.Equal(t, "ds-1", sawName)
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testDatasetNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
		require.Equal(t, ResourceTypeDataFactoryDatasetAzureSQLTable, got.ResourceType)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "ds-1", props["name"])
		// Both parents come from the native ID, not the response body.
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "adf-1", props["factoryName"])
		require.Equal(t, "ls-1", props["linkedServiceName"])
		require.Equal(t, "dbo", props["schemaName"])
		require.Equal(t, "orders", props["tableName"])
		require.Equal(t, "orders table", props["description"])
		require.Equal(t, "conformance", props["folderName"])
		require.Equal(t, []any{"conformance"}, props["annotations"])
	})

	t.Run("Update_reissues_create_or_update", func(t *testing.T) {
		before := createCalls
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID: testDatasetNativeID,
			DesiredProperties: datasetDesired(map[string]any{
				"schemaName": "sales",
				"tableName":  "invoices",
			}),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Empty(t, got.ProgressResult.RequestID)
		require.Equal(t, before+1, createCalls)
		ds, ok := sent.Properties.(*armdatafactory.AzureSQLTableDataset)
		require.True(t, ok)
		require.Equal(t, "sales", ds.TypeProperties.Schema)
		require.Equal(t, "invoices", ds.TypeProperties.Table)
	})

	t.Run("Delete_is_synchronous", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testDatasetNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _, _ string, _ *armdatafactory.DatasetsClientDeleteOptions) (armdatafactory.DatasetsClientDeleteResponse, error) {
			return armdatafactory.DatasetsClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testDatasetNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	// A dataset still referenced by a pipeline activity or a data flow cannot be
	// deleted; that arrives as a 400 and must surface with the provider's own
	// reason.
	t.Run("Delete_in_use_maps_to_failure_with_reason", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _, _ string, _ *armdatafactory.DatasetsClientDeleteOptions) (armdatafactory.DatasetsClientDeleteResponse, error) {
			return armdatafactory.DatasetsClientDeleteResponse{},
				&azcore.ResponseError{StatusCode: 400, ErrorCode: "DatasetIsInUse"}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testDatasetNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.Equal(t, resource.OperationErrorCodeInvalidRequest, got.ProgressResult.ErrorCode)
		require.Contains(t, got.ProgressResult.StatusMessage, "DatasetIsInUse")
	})

	// One factory pager returns every format, so the results must be filtered by
	// discriminator: reading a Parquet dataset through the AzureSqlTable
	// provisioner would surface the wrong shape.
	t.Run("List_keeps_only_this_format", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "factoryName": "adf-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testDatasetNativeID}, got.NativeIDs)
	})

	// ARM has no subscription-wide listing here: without both parents there is
	// nothing to page, so List must return empty rather than error.
	t.Run("List_without_parents_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)

		got, err = prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"factoryName": "adf-1"},
		})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure_with_reason", func(t *testing.T) {
		fake.createOrUpdateFn = func(_ context.Context, _, _, _ string, _ armdatafactory.DatasetResource, _ *armdatafactory.DatasetsClientCreateOrUpdateOptions) (armdatafactory.DatasetsClientCreateOrUpdateResponse, error) {
			return armdatafactory.DatasetsClientCreateOrUpdateResponse{},
				&azcore.ResponseError{StatusCode: 404, ErrorCode: "LinkedServiceNotFound"}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "ds-1", Properties: datasetDesired(sqlTableProps),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.Equal(t, resource.OperationErrorCodeNotFound, got.ProgressResult.ErrorCode)
		require.Contains(t, got.ProgressResult.StatusMessage, "LinkedServiceNotFound")
	})
}

func TestDataFactoryDatasetAzureSqlTable(t *testing.T) {
	kind := &dataFactoryDatasetAzureSQLTableKind
	require.Equal(t, "AzureSqlTable", kind.armType)

	// Both members are optional in ARM: a dataset with neither is a placeholder
	// whose table the copy activity supplies, which is legal and must stay
	// expressible.
	t.Run("both_members_are_optional", func(t *testing.T) {
		built, props := datasetRoundTrip(t, kind, datasetDesired(nil))
		ds, ok := built.(*armdatafactory.AzureSQLTableDataset)
		require.True(t, ok)
		require.Nil(t, ds.TypeProperties.Schema)
		require.Nil(t, ds.TypeProperties.Table)
		require.NotContains(t, props, "schemaName")
		require.NotContains(t, props, "tableName")
	})

	t.Run("round_trip", func(t *testing.T) {
		_, props := datasetRoundTrip(t, kind, datasetDesired(map[string]any{
			"schemaName": "dbo", "tableName": "orders",
		}))
		require.Equal(t, "dbo", props["schemaName"])
		require.Equal(t, "orders", props["tableName"])
	})

	// Data Factory types most dataset fields as "string, or Expression with
	// resultType string". Only the literal form is expressible in the schema, so
	// an expression object must be reported as absent rather than rendered in
	// Go's map formatting, which no PKL union could match.
	t.Run("an_expression_object_is_not_reported", func(t *testing.T) {
		props := map[string]any{}
		kind.readTypeProperties(&armdatafactory.AzureSQLTableDataset{
			TypeProperties: &armdatafactory.AzureSQLTableDatasetTypeProperties{
				Table: map[string]any{"type": "Expression", "value": "@dataset().table"},
			},
		}, props)
		require.NotContains(t, props, "tableName")
	})
}

func TestDataFactoryDatasetAzureBlob(t *testing.T) {
	kind := &dataFactoryDatasetAzureBlobKind
	require.Equal(t, "AzureBlob", kind.armType)

	// The legacy blob dataset predates the DatasetLocation union: the path is a
	// flat folderPath / fileName pair on typeProperties, with no container of its
	// own.
	t.Run("round_trip", func(t *testing.T) {
		built, props := datasetRoundTrip(t, kind, datasetDesired(map[string]any{
			"folderPath":        "landing/incoming",
			"fileName":          "orders.csv",
			"tableRootLocation": "landing",
		}))
		ds, ok := built.(*armdatafactory.AzureBlobDataset)
		require.True(t, ok)
		require.Equal(t, "landing/incoming", ds.TypeProperties.FolderPath)
		require.Equal(t, "orders.csv", ds.TypeProperties.FileName)

		require.Equal(t, "landing/incoming", props["folderPath"])
		require.Equal(t, "orders.csv", props["fileName"])
		require.Equal(t, "landing", props["tableRootLocation"])
	})

	t.Run("empty_path_sends_nothing", func(t *testing.T) {
		built, props := datasetRoundTrip(t, kind, datasetDesired(nil))
		ds, ok := built.(*armdatafactory.AzureBlobDataset)
		require.True(t, ok)
		require.Nil(t, ds.TypeProperties.FolderPath)
		require.Nil(t, ds.TypeProperties.FileName)
		require.NotContains(t, props, "folderPath")
	})
}

func TestDataFactoryDatasetDelimitedText(t *testing.T) {
	kind := &dataFactoryDatasetDelimitedTextKind
	require.Equal(t, "DelimitedText", kind.armType)

	build := func(t *testing.T, overrides map[string]any) (armdatafactory.DatasetClassification, error) {
		t.Helper()
		var common dataFactoryDatasetCommon
		payload := datasetDesired(overrides)
		require.NoError(t, common.parse(payload, "ds-1"))
		return kind.build(&common, payload)
	}

	// ARM rejects a DelimitedText dataset without a location, and a location
	// without a container addresses nothing.
	t.Run("requires_container", func(t *testing.T) {
		_, err := build(t, nil)
		require.ErrorContains(t, err, "container is required")
	})

	t.Run("round_trip", func(t *testing.T) {
		built, props := datasetRoundTrip(t, kind, datasetDesired(map[string]any{
			"container":        "landing",
			"folderPath":       "incoming",
			"fileName":         "orders.csv",
			"columnDelimiter":  ";",
			"rowDelimiter":     "\n",
			"quoteChar":        "\"",
			"escapeChar":       "\\",
			"nullValue":        "\\N",
			"encodingName":     "UTF-8",
			"compressionCodec": "gzip",
			"firstRowAsHeader": true,
		}))
		ds, ok := built.(*armdatafactory.DelimitedTextDataset)
		require.True(t, ok)
		location, ok := ds.TypeProperties.Location.(*armdatafactory.AzureBlobStorageLocation)
		require.True(t, ok)
		require.Equal(t, "AzureBlobStorageLocation", *location.Type)
		require.Equal(t, "landing", location.Container)
		require.Equal(t, "incoming", location.FolderPath)
		require.Equal(t, "orders.csv", location.FileName)

		require.Equal(t, "landing", props["container"])
		require.Equal(t, "incoming", props["folderPath"])
		require.Equal(t, "orders.csv", props["fileName"])
		require.Equal(t, ";", props["columnDelimiter"])
		require.Equal(t, "\n", props["rowDelimiter"])
		require.Equal(t, "\"", props["quoteChar"])
		require.Equal(t, "\\", props["escapeChar"])
		require.Equal(t, "\\N", props["nullValue"])
		require.Equal(t, "UTF-8", props["encodingName"])
		require.Equal(t, "gzip", props["compressionCodec"])
		require.Equal(t, true, props["firstRowAsHeader"])
	})

	// firstRowAsHeader = false must still cross the wire: dropping it would make
	// "explicitly not a header row" indistinguishable from "unset".
	t.Run("false_first_row_as_header_is_sent", func(t *testing.T) {
		built, props := datasetRoundTrip(t, kind, datasetDesired(map[string]any{
			"container": "landing", "firstRowAsHeader": false,
		}))
		ds, ok := built.(*armdatafactory.DelimitedTextDataset)
		require.True(t, ok)
		require.Equal(t, false, ds.TypeProperties.FirstRowAsHeader)
		require.Equal(t, false, props["firstRowAsHeader"])
	})

	// A dialect field the caller omitted must not be invented on the way out:
	// the service does not write its documented defaults into the stored
	// definition, so an invented value would be drift the provider caused.
	t.Run("omitted_dialect_fields_stay_absent", func(t *testing.T) {
		_, props := datasetRoundTrip(t, kind, datasetDesired(map[string]any{"container": "landing"}))
		require.NotContains(t, props, "columnDelimiter")
		require.NotContains(t, props, "quoteChar")
		require.NotContains(t, props, "encodingName")
		require.NotContains(t, props, "firstRowAsHeader")
	})

	// A location of any other kind is skipped rather than half-read: surfacing
	// something the schema cannot express would show as drift forever.
	t.Run("a_non_blob_location_is_not_reported", func(t *testing.T) {
		props := map[string]any{}
		kind.readTypeProperties(&armdatafactory.DelimitedTextDataset{
			TypeProperties: &armdatafactory.DelimitedTextDatasetTypeProperties{
				Location: &armdatafactory.AmazonS3Location{
					Type:       to.Ptr("AmazonS3Location"),
					BucketName: "some-bucket",
				},
			},
		}, props)
		require.NotContains(t, props, "container")
		require.NotContains(t, props, "folderPath")
	})
}

func TestDataFactoryDatasetJson(t *testing.T) {
	kind := &dataFactoryDatasetJSONKind
	require.Equal(t, "Json", kind.armType)

	t.Run("requires_container", func(t *testing.T) {
		var common dataFactoryDatasetCommon
		payload := datasetDesired(nil)
		require.NoError(t, common.parse(payload, "ds-1"))
		_, err := kind.build(&common, payload)
		require.ErrorContains(t, err, "container is required")
	})

	t.Run("round_trip", func(t *testing.T) {
		built, props := datasetRoundTrip(t, kind, datasetDesired(map[string]any{
			"container":    "landing",
			"folderPath":   "events",
			"fileName":     "events.json",
			"encodingName": "UTF-8",
		}))
		ds, ok := built.(*armdatafactory.JSONDataset)
		require.True(t, ok)
		location, ok := ds.TypeProperties.Location.(*armdatafactory.AzureBlobStorageLocation)
		require.True(t, ok)
		require.Equal(t, "landing", location.Container)

		require.Equal(t, "landing", props["container"])
		require.Equal(t, "events", props["folderPath"])
		require.Equal(t, "events.json", props["fileName"])
		require.Equal(t, "UTF-8", props["encodingName"])
	})
}

func TestDataFactoryDatasetParquet(t *testing.T) {
	kind := &dataFactoryDatasetParquetKind
	require.Equal(t, "Parquet", kind.armType)

	t.Run("requires_container", func(t *testing.T) {
		var common dataFactoryDatasetCommon
		payload := datasetDesired(nil)
		require.NoError(t, common.parse(payload, "ds-1"))
		_, err := kind.build(&common, payload)
		require.ErrorContains(t, err, "container is required")
	})

	t.Run("round_trip", func(t *testing.T) {
		built, props := datasetRoundTrip(t, kind, datasetDesired(map[string]any{
			"container":        "curated",
			"folderPath":       "orders",
			"compressionCodec": "snappy",
		}))
		ds, ok := built.(*armdatafactory.ParquetDataset)
		require.True(t, ok)
		location, ok := ds.TypeProperties.Location.(*armdatafactory.AzureBlobStorageLocation)
		require.True(t, ok)
		require.Equal(t, "curated", location.Container)
		require.Nil(t, location.FileName)

		require.Equal(t, "curated", props["container"])
		require.Equal(t, "orders", props["folderPath"])
		require.Equal(t, "snappy", props["compressionCodec"])
		require.NotContains(t, props, "fileName")
	})
}

// Every one of the five must be reachable by its own AZURE:: type name, and each
// must claim a distinct ARM discriminator — two kinds sharing one would make List
// hand the same IDs to two provisioners.
func TestDataFactoryDatasetKindsAreDistinct(t *testing.T) {
	kinds := []*datasetKind{
		&dataFactoryDatasetAzureBlobKind,
		&dataFactoryDatasetDelimitedTextKind,
		&dataFactoryDatasetJSONKind,
		&dataFactoryDatasetParquetKind,
		&dataFactoryDatasetAzureSQLTableKind,
	}
	seenType := map[string]bool{}
	seenARM := map[string]bool{}
	for _, kind := range kinds {
		require.NotEmpty(t, kind.resourceType)
		require.NotEmpty(t, kind.armType)
		require.False(t, seenType[kind.resourceType], "duplicate resource type %s", kind.resourceType)
		require.False(t, seenARM[kind.armType], "duplicate ARM discriminator %s", kind.armType)
		seenType[kind.resourceType] = true
		seenARM[kind.armType] = true
	}
	require.Len(t, seenType, 5)
}

func TestDataFactoryDataset_ReadNotFound(t *testing.T) {
	fake := &fakeDatasetsAPI{
		getFn: func(_ context.Context, _, _, _ string, _ *armdatafactory.DatasetsClientGetOptions) (armdatafactory.DatasetsClientGetResponse, error) {
			return armdatafactory.DatasetsClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestDataset(fake, &dataFactoryDatasetParquetKind).
		Read(context.Background(), &resource.ReadRequest{NativeID: testDatasetNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// Reading a dataset of another format must degrade to the shared fields rather than
// panicking on the type assertion.
func TestDataFactoryDataset_ReadOfWrongKindIsSafe(t *testing.T) {
	fake := &fakeDatasetsAPI{
		getFn: func(_ context.Context, _, _, _ string, _ *armdatafactory.DatasetsClientGetOptions) (armdatafactory.DatasetsClientGetResponse, error) {
			return armdatafactory.DatasetsClientGetResponse{
				DatasetResource: armdatafactory.DatasetResource{
					ID:   to.Ptr(testDatasetNativeID),
					Name: to.Ptr("ds-1"),
					Properties: &armdatafactory.ParquetDataset{
						Type: to.Ptr("Parquet"),
						LinkedServiceName: &armdatafactory.LinkedServiceReference{
							ReferenceName: to.Ptr("ls-1"),
						},
					},
				},
			}, nil
		},
	}
	got, err := newTestDataset(fake, &dataFactoryDatasetJSONKind).
		Read(context.Background(), &resource.ReadRequest{NativeID: testDatasetNativeID})
	require.NoError(t, err)
	require.Contains(t, got.Properties, "ls-1")
	require.NotContains(t, got.Properties, "encodingName")
}

func TestDataFactoryDataset_StatusIsAlwaysDone(t *testing.T) {
	got, err := newTestDataset(&fakeDatasetsAPI{}, &dataFactoryDatasetParquetKind).
		Status(context.Background(), &resource.StatusRequest{RequestID: "anything"})
	require.NoError(t, err)
	require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
}

// --- Test helpers ---

type fakeDatasetsAPI struct {
	createOrUpdateFn        func(ctx context.Context, rgName, factoryName, name string, params armdatafactory.DatasetResource, options *armdatafactory.DatasetsClientCreateOrUpdateOptions) (armdatafactory.DatasetsClientCreateOrUpdateResponse, error)
	getFn                   func(ctx context.Context, rgName, factoryName, name string, options *armdatafactory.DatasetsClientGetOptions) (armdatafactory.DatasetsClientGetResponse, error)
	deleteFn                func(ctx context.Context, rgName, factoryName, name string, options *armdatafactory.DatasetsClientDeleteOptions) (armdatafactory.DatasetsClientDeleteResponse, error)
	newListByFactoryPagerFn func(rgName, factoryName string, options *armdatafactory.DatasetsClientListByFactoryOptions) *runtime.Pager[armdatafactory.DatasetsClientListByFactoryResponse]
}

func (f *fakeDatasetsAPI) CreateOrUpdate(ctx context.Context, rgName, factoryName, name string, params armdatafactory.DatasetResource, options *armdatafactory.DatasetsClientCreateOrUpdateOptions) (armdatafactory.DatasetsClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, factoryName, name, params, options)
}

func (f *fakeDatasetsAPI) Get(ctx context.Context, rgName, factoryName, name string, options *armdatafactory.DatasetsClientGetOptions) (armdatafactory.DatasetsClientGetResponse, error) {
	return f.getFn(ctx, rgName, factoryName, name, options)
}

func (f *fakeDatasetsAPI) Delete(ctx context.Context, rgName, factoryName, name string, options *armdatafactory.DatasetsClientDeleteOptions) (armdatafactory.DatasetsClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, factoryName, name, options)
}

func (f *fakeDatasetsAPI) NewListByFactoryPager(rgName, factoryName string, options *armdatafactory.DatasetsClientListByFactoryOptions) *runtime.Pager[armdatafactory.DatasetsClientListByFactoryResponse] {
	return f.newListByFactoryPagerFn(rgName, factoryName, options)
}
