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

const testDataFlowNativeID = testDataFactoryNativeID + "/dataflows/df-1"

const testDataFlowScript = "source(allowSchemaDrift: true) ~> src\nsrc sink(allowSchemaDrift: true) ~> dst"

func newTestDataFlow(api dataFactoryDataFlowsAPI) *DataFactoryDataFlow {
	return &DataFactoryDataFlow{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func dataFlowDesired(overrides map[string]any) []byte {
	props := map[string]any{
		"name":              "df-1",
		"resourceGroupName": "rg-1",
		"factoryName":       "adf-1",
		"script":            testDataFlowScript,
		"sources": []map[string]any{
			{"name": "src", "datasetName": "ds-in"},
		},
		"sinks": []map[string]any{
			{"name": "dst", "datasetName": "ds-out"},
		},
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

func TestDataFactoryDataFlow_CRUD(t *testing.T) {
	result := armdatafactory.DataFlowResource{
		ID:   to.Ptr(testDataFlowNativeID),
		Name: to.Ptr("df-1"),
		Properties: &armdatafactory.MappingDataFlow{
			Type:        to.Ptr("MappingDataFlow"),
			Description: to.Ptr("copy with drift"),
			Annotations: []any{"conformance"},
			Folder:      &armdatafactory.DataFlowFolder{Name: to.Ptr("conformance")},
			TypeProperties: &armdatafactory.MappingDataFlowTypeProperties{
				// The service reparses the DSL and hands it back as scriptLines,
				// which is exactly why script is write-only.
				ScriptLines: []*string{
					to.Ptr("source(allowSchemaDrift: true) ~> src"),
					to.Ptr("src sink(allowSchemaDrift: true) ~> dst"),
				},
				Sources: []*armdatafactory.DataFlowSource{
					{
						Name: to.Ptr("src"),
						Dataset: &armdatafactory.DatasetReference{
							Type:          to.Ptr(armdatafactory.DatasetReferenceTypeDatasetReference),
							ReferenceName: to.Ptr("ds-in"),
						},
					},
				},
				Sinks: []*armdatafactory.DataFlowSink{
					{
						Name: to.Ptr("dst"),
						Dataset: &armdatafactory.DatasetReference{
							Type:          to.Ptr(armdatafactory.DatasetReferenceTypeDatasetReference),
							ReferenceName: to.Ptr("ds-out"),
						},
					},
				},
			},
		},
	}

	var sent armdatafactory.DataFlowResource
	var sawRG, sawFactory, sawName string
	createCalls := 0
	deleteCalls := 0
	fake := &fakeDataFlowsAPI{
		createOrUpdateFn: func(_ context.Context, rgName, factoryName, name string, params armdatafactory.DataFlowResource, _ *armdatafactory.DataFlowsClientCreateOrUpdateOptions) (armdatafactory.DataFlowsClientCreateOrUpdateResponse, error) {
			sawRG, sawFactory, sawName, sent = rgName, factoryName, name, params
			createCalls++
			return armdatafactory.DataFlowsClientCreateOrUpdateResponse{DataFlowResource: result}, nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ *armdatafactory.DataFlowsClientGetOptions) (armdatafactory.DataFlowsClientGetResponse, error) {
			return armdatafactory.DataFlowsClientGetResponse{DataFlowResource: result}, nil
		},
		deleteFn: func(_ context.Context, _, _, _ string, _ *armdatafactory.DataFlowsClientDeleteOptions) (armdatafactory.DataFlowsClientDeleteResponse, error) {
			deleteCalls++
			return armdatafactory.DataFlowsClientDeleteResponse{}, nil
		},
		newListByFactoryPagerFn: func(_, _ string, _ *armdatafactory.DataFlowsClientListByFactoryOptions) *runtime.Pager[armdatafactory.DataFlowsClientListByFactoryResponse] {
			return runtime.NewPager(runtime.PagingHandler[armdatafactory.DataFlowsClientListByFactoryResponse]{
				More: func(_ armdatafactory.DataFlowsClientListByFactoryResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armdatafactory.DataFlowsClientListByFactoryResponse) (armdatafactory.DataFlowsClientListByFactoryResponse, error) {
					return armdatafactory.DataFlowsClientListByFactoryResponse{
						DataFlowListResponse: armdatafactory.DataFlowListResponse{
							Value: []*armdatafactory.DataFlowResource{
								{
									ID:         to.Ptr(testDataFlowNativeID),
									Properties: &armdatafactory.MappingDataFlow{Type: to.Ptr("MappingDataFlow")},
								},
								{
									// A flowlet in the same factory: a separate
									// DataFlow member this type does not claim.
									ID:         to.Ptr(testDataFactoryNativeID + "/dataflows/flowlet-1"),
									Properties: &armdatafactory.Flowlet{Type: to.Ptr("Flowlet")},
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
	prov := newTestDataFlow(fake)

	// DataFlowsClient has no BeginX: a create reports success directly and never
	// hands back a resume token.
	t.Run("Create_is_synchronous", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "df-1",
			Properties: dataFlowDesired(map[string]any{
				"description": "copy with drift",
				"folderName":  "conformance",
				"annotations": []string{"conformance"},
			}),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testDataFlowNativeID, got.ProgressResult.NativeID)
		require.Empty(t, got.ProgressResult.RequestID)

		require.Equal(t, "rg-1", sawRG)
		require.Equal(t, "adf-1", sawFactory)
		require.Equal(t, "df-1", sawName)

		flow, ok := sent.Properties.(*armdatafactory.MappingDataFlow)
		require.True(t, ok)
		require.Equal(t, "copy with drift", *flow.Description)
		require.Equal(t, "conformance", *flow.Folder.Name)
		require.Equal(t, []any{"conformance"}, flow.Annotations)

		// The script is sent as one string; the service is what splits it into
		// scriptLines.
		require.Equal(t, testDataFlowScript, *flow.TypeProperties.Script)
		require.Nil(t, flow.TypeProperties.ScriptLines)

		require.Len(t, flow.TypeProperties.Sources, 1)
		require.Equal(t, "src", *flow.TypeProperties.Sources[0].Name)
		require.Equal(t, "ds-in", *flow.TypeProperties.Sources[0].Dataset.ReferenceName)
		require.Equal(t, armdatafactory.DatasetReferenceTypeDatasetReference,
			*flow.TypeProperties.Sources[0].Dataset.Type)
		require.Nil(t, flow.TypeProperties.Sources[0].LinkedService)

		require.Len(t, flow.TypeProperties.Sinks, 1)
		require.Equal(t, "dst", *flow.TypeProperties.Sinks[0].Name)
		require.Equal(t, "ds-out", *flow.TypeProperties.Sinks[0].Dataset.ReferenceName)
	})

	t.Run("Create_requires_script", func(t *testing.T) {
		_, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "df-1",
			Properties: dataFlowDesired(map[string]any{"script": nil}),
		})
		require.ErrorContains(t, err, "script is required")
	})

	// A nameless endpoint is meaningless: the script refers to sources and sinks
	// by name, so the mistake must fail before any ARM call.
	t.Run("Create_requires_a_name_on_every_endpoint", func(t *testing.T) {
		_, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "df-1",
			Properties: dataFlowDesired(map[string]any{
				"sinks": []map[string]any{{"datasetName": "ds-out"}},
			}),
		})
		require.ErrorContains(t, err, "every source and sink needs a name")
	})

	t.Run("Create_requires_parents", func(t *testing.T) {
		_, err := prov.Create(context.Background(), &resource.CreateRequest{
			Properties: dataFlowDesired(map[string]any{"factoryName": nil}),
		})
		require.ErrorContains(t, err, "factoryName is required")

		_, err = prov.Create(context.Background(), &resource.CreateRequest{
			Properties: dataFlowDesired(map[string]any{"resourceGroupName": nil}),
		})
		require.ErrorContains(t, err, "resourceGroupName is required")
	})

	t.Run("Create_falls_back_to_label_for_name", func(t *testing.T) {
		_, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "df-1",
			Properties: dataFlowDesired(map[string]any{"name": nil}),
		})
		require.NoError(t, err)
		require.Equal(t, "df-1", sawName)
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testDataFlowNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
		require.Equal(t, ResourceTypeDataFactoryDataFlow, got.ResourceType)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "df-1", props["name"])
		// Both parents come from the native ID, not the response body.
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "adf-1", props["factoryName"])
		require.Equal(t, "copy with drift", props["description"])
		require.Equal(t, "conformance", props["folderName"])
		require.Equal(t, []any{"conformance"}, props["annotations"])

		// script is write-only: the service hands back a re-serialisation as
		// scriptLines, so comparing it would report drift on a data flow nobody
		// touched.
		require.NotContains(t, props, "script")
		require.NotContains(t, props, "scriptLines")

		require.Equal(t, []any{map[string]any{"name": "src", "datasetName": "ds-in"}}, props["sources"])
		require.Equal(t, []any{map[string]any{"name": "dst", "datasetName": "ds-out"}}, props["sinks"])
	})

	t.Run("Update_reissues_create_or_update", func(t *testing.T) {
		before := createCalls
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID: testDataFlowNativeID,
			DesiredProperties: dataFlowDesired(map[string]any{
				"description": "copy with drift, updated",
				"script":      "source(allowSchemaDrift: false) ~> src\nsrc sink(allowSchemaDrift: false) ~> dst",
			}),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Empty(t, got.ProgressResult.RequestID)
		require.Equal(t, before+1, createCalls)
		flow, ok := sent.Properties.(*armdatafactory.MappingDataFlow)
		require.True(t, ok)
		require.Contains(t, *flow.TypeProperties.Script, "allowSchemaDrift: false")
	})

	t.Run("Delete_is_synchronous", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testDataFlowNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _, _ string, _ *armdatafactory.DataFlowsClientDeleteOptions) (armdatafactory.DataFlowsClientDeleteResponse, error) {
			return armdatafactory.DataFlowsClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testDataFlowNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	// A data flow still referenced by an Execute Data Flow activity cannot be
	// deleted; that arrives as a 400 and must surface with the provider's reason.
	t.Run("Delete_in_use_maps_to_failure_with_reason", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _, _ string, _ *armdatafactory.DataFlowsClientDeleteOptions) (armdatafactory.DataFlowsClientDeleteResponse, error) {
			return armdatafactory.DataFlowsClientDeleteResponse{},
				&azcore.ResponseError{StatusCode: 400, ErrorCode: "DataFlowIsInUse"}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testDataFlowNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.Equal(t, resource.OperationErrorCodeInvalidRequest, got.ProgressResult.ErrorCode)
		require.Contains(t, got.ProgressResult.StatusMessage, "DataFlowIsInUse")
	})

	// The pager returns flowlets alongside mapping data flows, so the results must
	// be filtered by discriminator.
	t.Run("List_keeps_only_mapping_data_flows", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "factoryName": "adf-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testDataFlowNativeID}, got.NativeIDs)
	})

	// ARM has no subscription-wide listing here: without both parents there is
	// nothing to page, so List must return empty rather than error.
	t.Run("List_without_parents_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure_with_reason", func(t *testing.T) {
		fake.createOrUpdateFn = func(_ context.Context, _, _, _ string, _ armdatafactory.DataFlowResource, _ *armdatafactory.DataFlowsClientCreateOrUpdateOptions) (armdatafactory.DataFlowsClientCreateOrUpdateResponse, error) {
			return armdatafactory.DataFlowsClientCreateOrUpdateResponse{},
				&azcore.ResponseError{StatusCode: 404, ErrorCode: "DatasetNotFound"}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "df-1", Properties: dataFlowDesired(nil),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.Equal(t, resource.OperationErrorCodeNotFound, got.ProgressResult.ErrorCode)
		require.Contains(t, got.ProgressResult.StatusMessage, "DatasetNotFound")
	})
}

// An endpoint names EITHER a dataset or, for an inline dataset, the linked service
// its format is read through. ARM accepts one with neither, which is how a data flow
// is staged before its datasets exist.
func TestDataFactoryDataFlow_EndpointReferences(t *testing.T) {
	var props dataFactoryDataFlowProps
	require.NoError(t, props.parse(dataFlowDesired(map[string]any{
		"sources": []map[string]any{
			{"name": "inline", "linkedServiceName": "ls-1", "description": "inline dataset"},
			{"name": "bare"},
		},
		"sinks": []map[string]any{{"name": "dst", "datasetName": "ds-out"}},
	}), "df-1"))

	flow, ok := props.params().Properties.(*armdatafactory.MappingDataFlow)
	require.True(t, ok)
	require.Len(t, flow.TypeProperties.Sources, 2)

	inline := flow.TypeProperties.Sources[0]
	require.Nil(t, inline.Dataset)
	require.Equal(t, "ls-1", *inline.LinkedService.ReferenceName)
	require.Equal(t, armdatafactory.LinkedServiceReferenceTypeLinkedServiceReference, *inline.LinkedService.Type)
	require.Equal(t, "inline dataset", *inline.Description)

	bare := flow.TypeProperties.Sources[1]
	require.Nil(t, bare.Dataset)
	require.Nil(t, bare.LinkedService)
	require.Nil(t, bare.Description)

	read := newTestDataFlow(nil).buildPropertiesFromResult(&armdatafactory.DataFlowResource{
		ID:         to.Ptr(testDataFlowNativeID),
		Name:       to.Ptr("df-1"),
		Properties: flow,
	}, "rg-1", "adf-1")
	require.Equal(t, []map[string]any{
		{"name": "inline", "linkedServiceName": "ls-1", "description": "inline dataset"},
		{"name": "bare"},
	}, read["sources"])
}

// A data flow with no endpoints at all must send no empty lists and read back
// without the keys, so an absent listing is not confused with an empty one.
func TestDataFactoryDataFlow_NoEndpoints(t *testing.T) {
	var props dataFactoryDataFlowProps
	require.NoError(t, props.parse(dataFlowDesired(map[string]any{
		"sources": nil, "sinks": nil,
	}), "df-1"))

	flow, ok := props.params().Properties.(*armdatafactory.MappingDataFlow)
	require.True(t, ok)
	require.Nil(t, flow.TypeProperties.Sources)
	require.Nil(t, flow.TypeProperties.Sinks)

	read := newTestDataFlow(nil).buildPropertiesFromResult(&armdatafactory.DataFlowResource{
		ID:         to.Ptr(testDataFlowNativeID),
		Name:       to.Ptr("df-1"),
		Properties: flow,
	}, "rg-1", "adf-1")
	require.NotContains(t, read, "sources")
	require.NotContains(t, read, "sinks")
}

func TestDataFactoryDataFlow_ReadNotFound(t *testing.T) {
	fake := &fakeDataFlowsAPI{
		getFn: func(_ context.Context, _, _, _ string, _ *armdatafactory.DataFlowsClientGetOptions) (armdatafactory.DataFlowsClientGetResponse, error) {
			return armdatafactory.DataFlowsClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestDataFlow(fake).
		Read(context.Background(), &resource.ReadRequest{NativeID: testDataFlowNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// Reading a flowlet must degrade to the parents rather than panicking on the type
// assertion.
func TestDataFactoryDataFlow_ReadOfWrongKindIsSafe(t *testing.T) {
	fake := &fakeDataFlowsAPI{
		getFn: func(_ context.Context, _, _, _ string, _ *armdatafactory.DataFlowsClientGetOptions) (armdatafactory.DataFlowsClientGetResponse, error) {
			return armdatafactory.DataFlowsClientGetResponse{
				DataFlowResource: armdatafactory.DataFlowResource{
					ID:         to.Ptr(testDataFlowNativeID),
					Name:       to.Ptr("df-1"),
					Properties: &armdatafactory.Flowlet{Type: to.Ptr("Flowlet")},
				},
			}, nil
		},
	}
	got, err := newTestDataFlow(fake).
		Read(context.Background(), &resource.ReadRequest{NativeID: testDataFlowNativeID})
	require.NoError(t, err)
	require.NotContains(t, got.Properties, "sources")
}

func TestDataFactoryDataFlow_StatusIsAlwaysDone(t *testing.T) {
	got, err := newTestDataFlow(&fakeDataFlowsAPI{}).
		Status(context.Background(), &resource.StatusRequest{RequestID: "anything"})
	require.NoError(t, err)
	require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
}

// --- Test helpers ---

type fakeDataFlowsAPI struct {
	createOrUpdateFn        func(ctx context.Context, rgName, factoryName, name string, params armdatafactory.DataFlowResource, options *armdatafactory.DataFlowsClientCreateOrUpdateOptions) (armdatafactory.DataFlowsClientCreateOrUpdateResponse, error)
	getFn                   func(ctx context.Context, rgName, factoryName, name string, options *armdatafactory.DataFlowsClientGetOptions) (armdatafactory.DataFlowsClientGetResponse, error)
	deleteFn                func(ctx context.Context, rgName, factoryName, name string, options *armdatafactory.DataFlowsClientDeleteOptions) (armdatafactory.DataFlowsClientDeleteResponse, error)
	newListByFactoryPagerFn func(rgName, factoryName string, options *armdatafactory.DataFlowsClientListByFactoryOptions) *runtime.Pager[armdatafactory.DataFlowsClientListByFactoryResponse]
}

func (f *fakeDataFlowsAPI) CreateOrUpdate(ctx context.Context, rgName, factoryName, name string, params armdatafactory.DataFlowResource, options *armdatafactory.DataFlowsClientCreateOrUpdateOptions) (armdatafactory.DataFlowsClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, factoryName, name, params, options)
}

func (f *fakeDataFlowsAPI) Get(ctx context.Context, rgName, factoryName, name string, options *armdatafactory.DataFlowsClientGetOptions) (armdatafactory.DataFlowsClientGetResponse, error) {
	return f.getFn(ctx, rgName, factoryName, name, options)
}

func (f *fakeDataFlowsAPI) Delete(ctx context.Context, rgName, factoryName, name string, options *armdatafactory.DataFlowsClientDeleteOptions) (armdatafactory.DataFlowsClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, factoryName, name, options)
}

func (f *fakeDataFlowsAPI) NewListByFactoryPager(rgName, factoryName string, options *armdatafactory.DataFlowsClientListByFactoryOptions) *runtime.Pager[armdatafactory.DataFlowsClientListByFactoryResponse] {
	return f.newListByFactoryPagerFn(rgName, factoryName, options)
}
