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

const testDataFactoryPipelineNativeID = testDataFactoryNativeID + "/pipelines/pl-1"

const testWaitActivityJSON = `[{"name":"pause","type":"Wait","typeProperties":{"waitTimeInSeconds":1}}]`

func newTestDataFactoryPipeline(api dataFactoryPipelinesAPI) *DataFactoryPipeline {
	return &DataFactoryPipeline{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func dataFactoryPipelineDesired(overrides map[string]any) []byte {
	props := map[string]any{
		"name":              "pl-1",
		"resourceGroupName": "rg-1",
		"factoryName":       "adf-1",
		"description":       "conformance pipeline",
		"activities":        testWaitActivityJSON,
		"concurrency":       1,
		"folderName":        "conformance",
		"annotations":       []string{"conformance"},
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

func TestDataFactoryPipeline_CRUD(t *testing.T) {
	pipelineResult := armdatafactory.PipelineResource{
		ID:   to.Ptr(testDataFactoryPipelineNativeID),
		Name: to.Ptr("pl-1"),
		Etag: to.Ptr("W/\"datetime\""),
		Properties: &armdatafactory.Pipeline{
			Description: to.Ptr("conformance pipeline"),
			Concurrency: to.Ptr(int32(1)),
			Folder:      &armdatafactory.PipelineFolder{Name: to.Ptr("conformance")},
			Annotations: []any{"conformance", 42},
			Activities: []armdatafactory.ActivityClassification{
				&armdatafactory.WaitActivity{
					Name: to.Ptr("pause"),
					Type: to.Ptr("Wait"),
				},
			},
		},
	}

	var sent armdatafactory.PipelineResource
	var sawRG, sawFactory, sawName string
	createCalls := 0
	deleteCalls := 0
	fake := &fakeDataFactoryPipelinesAPI{
		createOrUpdateFn: func(_ context.Context, rgName, factoryName, name string, params armdatafactory.PipelineResource, _ *armdatafactory.PipelinesClientCreateOrUpdateOptions) (armdatafactory.PipelinesClientCreateOrUpdateResponse, error) {
			sawRG, sawFactory, sawName, sent = rgName, factoryName, name, params
			createCalls++
			return armdatafactory.PipelinesClientCreateOrUpdateResponse{PipelineResource: pipelineResult}, nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ *armdatafactory.PipelinesClientGetOptions) (armdatafactory.PipelinesClientGetResponse, error) {
			return armdatafactory.PipelinesClientGetResponse{PipelineResource: pipelineResult}, nil
		},
		deleteFn: func(_ context.Context, _, _, _ string, _ *armdatafactory.PipelinesClientDeleteOptions) (armdatafactory.PipelinesClientDeleteResponse, error) {
			deleteCalls++
			return armdatafactory.PipelinesClientDeleteResponse{}, nil
		},
		newListByFactoryPagerFn: func(_, _ string, _ *armdatafactory.PipelinesClientListByFactoryOptions) *runtime.Pager[armdatafactory.PipelinesClientListByFactoryResponse] {
			return runtime.NewPager(runtime.PagingHandler[armdatafactory.PipelinesClientListByFactoryResponse]{
				More: func(_ armdatafactory.PipelinesClientListByFactoryResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armdatafactory.PipelinesClientListByFactoryResponse) (armdatafactory.PipelinesClientListByFactoryResponse, error) {
					return armdatafactory.PipelinesClientListByFactoryResponse{
						PipelineListResponse: armdatafactory.PipelineListResponse{
							Value: []*armdatafactory.PipelineResource{
								{ID: to.Ptr(testDataFactoryPipelineNativeID)},
								{},
							},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestDataFactoryPipeline(fake)

	t.Run("Create_is_synchronous", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "pl-1",
			Properties: dataFactoryPipelineDesired(nil),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testDataFactoryPipelineNativeID, got.ProgressResult.NativeID)
		require.Empty(t, got.ProgressResult.RequestID)

		require.Equal(t, "rg-1", sawRG)
		require.Equal(t, "adf-1", sawFactory)
		require.Equal(t, "pl-1", sawName)
		require.Equal(t, "conformance pipeline", *sent.Properties.Description)
		require.Equal(t, int32(1), *sent.Properties.Concurrency)
		require.Equal(t, "conformance", *sent.Properties.Folder.Name)
		require.Equal(t, []any{"conformance"}, sent.Properties.Annotations)
	})

	// The activity list arrives as a JSON string and has to reach ARM as a real
	// typed activity, so a Wait activity must come out as *WaitActivity rather
	// than a bag of maps.
	t.Run("Create_decodes_activities_into_typed_activities", func(t *testing.T) {
		_, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "pl-1", Properties: dataFactoryPipelineDesired(nil),
		})
		require.NoError(t, err)
		require.Len(t, sent.Properties.Activities, 1)
		wait, ok := sent.Properties.Activities[0].(*armdatafactory.WaitActivity)
		require.True(t, ok)
		require.Equal(t, "pause", *wait.Name)
	})

	// An empty pipeline is valid in Data Factory and is the cheapest thing this
	// type can express, so an omitted activity list must not become an empty array
	// in the request body.
	t.Run("Create_without_activities_sends_none", func(t *testing.T) {
		_, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "pl-1",
			Properties: dataFactoryPipelineDesired(map[string]any{"activities": nil, "folderName": nil, "annotations": nil}),
		})
		require.NoError(t, err)
		require.Nil(t, sent.Properties.Activities)
		require.Nil(t, sent.Properties.Folder)
		require.Nil(t, sent.Properties.Annotations)
	})

	// A malformed body must fail before any ARM call, not as an opaque 400.
	t.Run("Create_rejects_malformed_activities", func(t *testing.T) {
		_, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "pl-1",
			Properties: dataFactoryPipelineDesired(map[string]any{"activities": "{not json"}),
		})
		require.ErrorContains(t, err, "activities is not valid JSON")
	})

	t.Run("Create_rejects_a_non_array_activity_body", func(t *testing.T) {
		_, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "pl-1",
			Properties: dataFactoryPipelineDesired(map[string]any{"activities": `{"name":"pause"}`}),
		})
		require.ErrorContains(t, err, "activities must be a JSON array")
	})

	t.Run("Create_requires_factory", func(t *testing.T) {
		_, err := prov.Create(context.Background(), &resource.CreateRequest{
			Properties: dataFactoryPipelineDesired(map[string]any{"factoryName": nil}),
		})
		require.ErrorContains(t, err, "factoryName is required")
	})

	t.Run("Create_requires_resource_group", func(t *testing.T) {
		_, err := prov.Create(context.Background(), &resource.CreateRequest{
			Properties: dataFactoryPipelineDesired(map[string]any{"resourceGroupName": nil}),
		})
		require.ErrorContains(t, err, "resourceGroupName is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testDataFactoryPipelineNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "pl-1", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "adf-1", props["factoryName"])
		require.Equal(t, "conformance pipeline", props["description"])
		require.Equal(t, float64(1), props["concurrency"])
		require.Equal(t, "conformance", props["folderName"])
		// The non-string annotation ARM allows is skipped rather than rendered
		// in Go's formatting, which no PKL union could match.
		require.Equal(t, []any{"conformance"}, props["annotations"])
	})

	// activities is writeOnly: the service re-serialises the list through its own
	// activity model, so the echo is not byte-stable and comparing it would report
	// drift on a pipeline nobody touched.
	t.Run("Read_never_surfaces_activities", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testDataFactoryPipelineNativeID})
		require.NoError(t, err)
		for _, key := range []string{"activities", "parameters", "variables", "policy", "runDimensions", "etag"} {
			require.NotContains(t, got.Properties, key)
		}
	})

	t.Run("Update_reissues_create_or_update", func(t *testing.T) {
		before := createCalls
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testDataFactoryPipelineNativeID,
			DesiredProperties: dataFactoryPipelineDesired(map[string]any{"concurrency": 4}),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Empty(t, got.ProgressResult.RequestID)
		require.Equal(t, before+1, createCalls)
		require.Equal(t, int32(4), *sent.Properties.Concurrency)
	})

	t.Run("Delete_is_synchronous", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testDataFactoryPipelineNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _, _ string, _ *armdatafactory.PipelinesClientDeleteOptions) (armdatafactory.PipelinesClientDeleteResponse, error) {
			return armdatafactory.PipelinesClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testDataFactoryPipelineNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_factory", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "factoryName": "adf-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testDataFactoryPipelineNativeID}, got.NativeIDs)
	})

	// ARM has no subscription-wide listing here: without both parents there is
	// nothing to page, so List must return empty rather than error.
	t.Run("List_without_parents_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure_with_reason", func(t *testing.T) {
		fake.createOrUpdateFn = func(_ context.Context, _, _, _ string, _ armdatafactory.PipelineResource, _ *armdatafactory.PipelinesClientCreateOrUpdateOptions) (armdatafactory.PipelinesClientCreateOrUpdateResponse, error) {
			return armdatafactory.PipelinesClientCreateOrUpdateResponse{},
				&azcore.ResponseError{StatusCode: 400, ErrorCode: "BadRequest"}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "pl-1", Properties: dataFactoryPipelineDesired(nil),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.Equal(t, resource.OperationErrorCodeInvalidRequest, got.ProgressResult.ErrorCode)
		require.Contains(t, got.ProgressResult.StatusMessage, "BadRequest")
	})
}

func TestDataFactoryPipeline_ReadNotFound(t *testing.T) {
	fake := &fakeDataFactoryPipelinesAPI{
		getFn: func(_ context.Context, _, _, _ string, _ *armdatafactory.PipelinesClientGetOptions) (armdatafactory.PipelinesClientGetResponse, error) {
			return armdatafactory.PipelinesClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestDataFactoryPipeline(fake).Read(context.Background(), &resource.ReadRequest{NativeID: testDataFactoryPipelineNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

func TestDataFactoryPipeline_StatusIsAlwaysDone(t *testing.T) {
	got, err := newTestDataFactoryPipeline(&fakeDataFactoryPipelinesAPI{}).
		Status(context.Background(), &resource.StatusRequest{RequestID: "anything"})
	require.NoError(t, err)
	require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
}

// --- Test helpers ---

type fakeDataFactoryPipelinesAPI struct {
	createOrUpdateFn        func(ctx context.Context, rgName, factoryName, name string, params armdatafactory.PipelineResource, options *armdatafactory.PipelinesClientCreateOrUpdateOptions) (armdatafactory.PipelinesClientCreateOrUpdateResponse, error)
	getFn                   func(ctx context.Context, rgName, factoryName, name string, options *armdatafactory.PipelinesClientGetOptions) (armdatafactory.PipelinesClientGetResponse, error)
	deleteFn                func(ctx context.Context, rgName, factoryName, name string, options *armdatafactory.PipelinesClientDeleteOptions) (armdatafactory.PipelinesClientDeleteResponse, error)
	newListByFactoryPagerFn func(rgName, factoryName string, options *armdatafactory.PipelinesClientListByFactoryOptions) *runtime.Pager[armdatafactory.PipelinesClientListByFactoryResponse]
}

func (f *fakeDataFactoryPipelinesAPI) CreateOrUpdate(ctx context.Context, rgName, factoryName, name string, params armdatafactory.PipelineResource, options *armdatafactory.PipelinesClientCreateOrUpdateOptions) (armdatafactory.PipelinesClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, factoryName, name, params, options)
}

func (f *fakeDataFactoryPipelinesAPI) Get(ctx context.Context, rgName, factoryName, name string, options *armdatafactory.PipelinesClientGetOptions) (armdatafactory.PipelinesClientGetResponse, error) {
	return f.getFn(ctx, rgName, factoryName, name, options)
}

func (f *fakeDataFactoryPipelinesAPI) Delete(ctx context.Context, rgName, factoryName, name string, options *armdatafactory.PipelinesClientDeleteOptions) (armdatafactory.PipelinesClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, factoryName, name, options)
}

func (f *fakeDataFactoryPipelinesAPI) NewListByFactoryPager(rgName, factoryName string, options *armdatafactory.PipelinesClientListByFactoryOptions) *runtime.Pager[armdatafactory.PipelinesClientListByFactoryResponse] {
	return f.newListByFactoryPagerFn(rgName, factoryName, options)
}
