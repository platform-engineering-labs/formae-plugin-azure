// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"sort"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/streamanalytics/armstreamanalytics"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

// --- function service simulator ---------------------------------------------

type saFunctionService struct {
	stored  map[string]armstreamanalytics.Function
	sent    []armstreamanalytics.Function
	deletes int

	createErr error
	getErr    error
	updateErr error
	deleteErr error
}

func newSAFunctionService() *saFunctionService {
	return &saFunctionService{stored: map[string]armstreamanalytics.Function{}}
}

func (s *saFunctionService) seed(name string, fn armstreamanalytics.Function) {
	stored := fn
	stored.Name = to.Ptr(name)
	stored.ID = to.Ptr(testSAFunctionNativeID(name))
	s.stored[name] = stored
}

func (s *saFunctionService) put(name string, fn armstreamanalytics.Function) armstreamanalytics.Function {
	s.sent = append(s.sent, fn)
	s.seed(name, fn)
	return s.stored[name]
}

func (s *saFunctionService) lastSent() armstreamanalytics.Function {
	return s.sent[len(s.sent)-1]
}

func (s *saFunctionService) CreateOrReplace(_ context.Context, _, _, functionName string, function armstreamanalytics.Function, _ *armstreamanalytics.FunctionsClientCreateOrReplaceOptions) (armstreamanalytics.FunctionsClientCreateOrReplaceResponse, error) {
	if s.createErr != nil {
		return armstreamanalytics.FunctionsClientCreateOrReplaceResponse{}, s.createErr
	}
	return armstreamanalytics.FunctionsClientCreateOrReplaceResponse{Function: s.put(functionName, function)}, nil
}

func (s *saFunctionService) Get(_ context.Context, _, _, functionName string, _ *armstreamanalytics.FunctionsClientGetOptions) (armstreamanalytics.FunctionsClientGetResponse, error) {
	if s.getErr != nil {
		return armstreamanalytics.FunctionsClientGetResponse{}, s.getErr
	}
	stored, ok := s.stored[functionName]
	if !ok {
		return armstreamanalytics.FunctionsClientGetResponse{}, testSANotFound()
	}
	return armstreamanalytics.FunctionsClientGetResponse{Function: stored}, nil
}

func (s *saFunctionService) Update(_ context.Context, _, _, functionName string, function armstreamanalytics.Function, _ *armstreamanalytics.FunctionsClientUpdateOptions) (armstreamanalytics.FunctionsClientUpdateResponse, error) {
	if s.updateErr != nil {
		return armstreamanalytics.FunctionsClientUpdateResponse{}, s.updateErr
	}
	return armstreamanalytics.FunctionsClientUpdateResponse{Function: s.put(functionName, function)}, nil
}

func (s *saFunctionService) Delete(_ context.Context, _, _, functionName string, _ *armstreamanalytics.FunctionsClientDeleteOptions) (armstreamanalytics.FunctionsClientDeleteResponse, error) {
	if s.deleteErr != nil {
		return armstreamanalytics.FunctionsClientDeleteResponse{}, s.deleteErr
	}
	s.deletes++
	delete(s.stored, functionName)
	return armstreamanalytics.FunctionsClientDeleteResponse{}, nil
}

func (s *saFunctionService) NewListByStreamingJobPager(_, _ string, _ *armstreamanalytics.FunctionsClientListByStreamingJobOptions) *runtime.Pager[armstreamanalytics.FunctionsClientListByStreamingJobResponse] {
	return runtime.NewPager(runtime.PagingHandler[armstreamanalytics.FunctionsClientListByStreamingJobResponse]{
		More: func(_ armstreamanalytics.FunctionsClientListByStreamingJobResponse) bool { return false },
		Fetcher: func(_ context.Context, _ *armstreamanalytics.FunctionsClientListByStreamingJobResponse) (armstreamanalytics.FunctionsClientListByStreamingJobResponse, error) {
			names := make([]string, 0, len(s.stored))
			for name := range s.stored {
				names = append(names, name)
			}
			sort.Strings(names)
			values := make([]*armstreamanalytics.Function, 0, len(names))
			for _, name := range names {
				stored := s.stored[name]
				values = append(values, &stored)
			}
			return armstreamanalytics.FunctionsClientListByStreamingJobResponse{
				FunctionListResult: armstreamanalytics.FunctionListResult{Value: values},
			}, nil
		},
	})
}

// --- tests ------------------------------------------------------------------

func testSAFunctionDesired(script string) map[string]any {
	return map[string]any{
		"name":              "fpsdtudf",
		"resourceGroupName": testSAJobResourceGroup,
		"jobName":           testSAJobName,
		"script":            script,
		"inputs": []any{
			map[string]any{"dataType": "any"},
			map[string]any{"dataType": "any"},
		},
		"outputDataType": "any",
	}
}

func TestStreamAnalyticsFunctionJavaScriptUdf_CRUD(t *testing.T) {
	service := newSAFunctionService()
	prov := &StreamAnalyticsFunctionJavaScriptUdf{api: service}

	t.Run("Create", func(t *testing.T) {
		progress, props := saCreate(t, prov, testSAFunctionDesired("function (x, y) { return x + y; }"), "fpsdtudf")
		require.Equal(t, testSAFunctionNativeID("fpsdtudf"), progress.NativeID)

		// Both ARM discriminators must be filled in even though neither is a
		// settable schema field.
		sent := service.lastSent()
		scalar, ok := sent.Properties.(*armstreamanalytics.ScalarFunctionProperties)
		require.True(t, ok)
		require.Equal(t, "Scalar", *scalar.Type)
		binding, ok := scalar.Properties.Binding.(*armstreamanalytics.JavaScriptFunctionBinding)
		require.True(t, ok)
		require.Equal(t, "Microsoft.StreamAnalytics/JavascriptUdf", *binding.Type)
		require.Equal(t, "function (x, y) { return x + y; }", *binding.Properties.Script)
		require.Len(t, scalar.Properties.Inputs, 2)
		require.Equal(t, "any", *scalar.Properties.Inputs[0].DataType)
		// Not declared, so not sent: ARM echoes only what it was given.
		require.Nil(t, scalar.Properties.Inputs[0].IsConfigurationParameter)
		require.Equal(t, "any", *scalar.Properties.Output.DataType)

		require.Equal(t, "function (x, y) { return x + y; }", props["script"])
		require.Equal(t, "any", props["outputDataType"])
	})

	t.Run("Read", func(t *testing.T) {
		props := saRead(t, prov, testSAFunctionNativeID("fpsdtudf"))
		require.Equal(t, "fpsdtudf", props["name"])
		require.Equal(t, testSAJobName, props["jobName"])
		require.Equal(t, testSAJobResourceGroup, props["resourceGroupName"])
		require.Equal(t, []any{
			map[string]any{"dataType": "any"},
			map[string]any{"dataType": "any"},
		}, props["inputs"])
	})

	t.Run("Update_replaces_body", func(t *testing.T) {
		raw, err := json.Marshal(testSAFunctionDesired("function (x, y) { return x * y; }"))
		require.NoError(t, err)
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testSAFunctionNativeID("fpsdtudf"),
			DesiredProperties: raw,
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Empty(t, got.ProgressResult.RequestID)

		var props map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &props))
		require.Equal(t, "function (x, y) { return x * y; }", props["script"])
	})

	t.Run("Delete", func(t *testing.T) {
		before := service.deletes
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testSAFunctionNativeID("fpsdtudf")})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, service.deletes)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		service.deleteErr = testSANotFound()
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testSAFunctionNativeID("fpsdtudf")})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		service.deleteErr = nil
	})
}

func TestStreamAnalyticsFunctionJavaScriptUdf_ConfigurationParameterRoundTrips(t *testing.T) {
	service := newSAFunctionService()
	prov := &StreamAnalyticsFunctionJavaScriptUdf{api: service}

	desired := testSAFunctionDesired("function (x, factor) { return x * factor; }")
	desired["inputs"] = []any{
		map[string]any{"dataType": "float"},
		map[string]any{"dataType": "float", "isConfigurationParameter": true},
	}
	_, props := saCreate(t, prov, desired, "fpsdtudf")
	require.Equal(t, []any{
		map[string]any{"dataType": "float"},
		map[string]any{"dataType": "float", "isConfigurationParameter": true},
	}, props["inputs"])
}

// ARM's own examples return "Any" where the documented type name is "any".
// Echoing the response casing back fails conformance [Verify] and stops
// `formae extract` rendering the PKL union.
func TestStreamAnalyticsFunctionJavaScriptUdf_ReadCanonicalizesDataTypeCasing(t *testing.T) {
	service := newSAFunctionService()
	service.seed("fpsdtudf", armstreamanalytics.Function{
		Properties: &armstreamanalytics.ScalarFunctionProperties{
			Type: to.Ptr("Scalar"),
			Properties: &armstreamanalytics.FunctionConfiguration{
				Binding: &armstreamanalytics.JavaScriptFunctionBinding{
					Type: to.Ptr(streamAnalyticsJavaScriptUdfBinding),
					Properties: &armstreamanalytics.JavaScriptFunctionBindingProperties{
						Script: to.Ptr("function (x) { return x; }"),
					},
				},
				Inputs: []*armstreamanalytics.FunctionInput{{DataType: to.Ptr("Any")}},
				Output: &armstreamanalytics.FunctionOutput{DataType: to.Ptr("NVARCHAR(MAX)")},
			},
		},
	})

	props := saRead(t, &StreamAnalyticsFunctionJavaScriptUdf{api: service}, testSAFunctionNativeID("fpsdtudf"))
	require.Equal(t, []any{map[string]any{"dataType": "any"}}, props["inputs"])
	require.Equal(t, "nvarchar(max)", props["outputDataType"])
}

// The functions collection also holds aggregate functions and Azure Machine
// Learning web-service bindings; neither belongs to this type.
func TestStreamAnalyticsFunctionJavaScriptUdf_IgnoresOtherBindings(t *testing.T) {
	service := newSAFunctionService()
	service.seed("jsudf", armstreamanalytics.Function{
		Properties: &armstreamanalytics.ScalarFunctionProperties{
			Type: to.Ptr("Scalar"),
			Properties: &armstreamanalytics.FunctionConfiguration{
				Binding: &armstreamanalytics.JavaScriptFunctionBinding{
					Type: to.Ptr(streamAnalyticsJavaScriptUdfBinding),
					Properties: &armstreamanalytics.JavaScriptFunctionBindingProperties{
						Script: to.Ptr("function (x) { return x; }"),
					},
				},
				Output: &armstreamanalytics.FunctionOutput{DataType: to.Ptr("any")},
			},
		},
	})
	service.seed("mludf", armstreamanalytics.Function{
		Properties: &armstreamanalytics.ScalarFunctionProperties{
			Type: to.Ptr("Scalar"),
			Properties: &armstreamanalytics.FunctionConfiguration{
				Binding: &armstreamanalytics.AzureMachineLearningWebServiceFunctionBinding{
					Type: to.Ptr("Microsoft.MachineLearning/WebService"),
				},
				Output: &armstreamanalytics.FunctionOutput{DataType: to.Ptr("any")},
			},
		},
	})

	prov := &StreamAnalyticsFunctionJavaScriptUdf{api: service}

	got, err := prov.List(context.Background(), &resource.ListRequest{
		AdditionalProperties: map[string]string{
			"resourceGroupName": testSAJobResourceGroup,
			"jobName":           testSAJobName,
		},
	})
	require.NoError(t, err)
	require.Equal(t, []string{testSAFunctionNativeID("jsudf")}, got.NativeIDs)

	read, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testSAFunctionNativeID("mludf")})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, read.ErrorCode)
}

func TestStreamAnalyticsFunctionJavaScriptUdf_CreateRequiresFields(t *testing.T) {
	prov := &StreamAnalyticsFunctionJavaScriptUdf{api: newSAFunctionService()}

	for _, tc := range []struct {
		missing string
		wantErr string
	}{
		{"script", "script is required"},
		{"outputDataType", "outputDataType is required"},
		{"inputs", "inputs is required and must declare at least one argument"},
		{"jobName", "jobName is required"},
	} {
		t.Run(tc.missing, func(t *testing.T) {
			desired := testSAFunctionDesired("function (x, y) { return x + y; }")
			delete(desired, tc.missing)
			raw, err := json.Marshal(desired)
			require.NoError(t, err)
			_, err = prov.Create(context.Background(), &resource.CreateRequest{Label: "fpsdtudf", Properties: raw})
			require.ErrorContains(t, err, tc.wantErr)
		})
	}
}

func TestStreamAnalyticsFunctionJavaScriptUdf_FailureCarriesStatusMessage(t *testing.T) {
	service := newSAFunctionService()
	service.createErr = testSAConflict()
	prov := &StreamAnalyticsFunctionJavaScriptUdf{api: service}

	raw, err := json.Marshal(testSAFunctionDesired("function (x, y) { return x + y; }"))
	require.NoError(t, err)
	got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: raw})
	require.NoError(t, err)
	require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	require.NotEmpty(t, got.ProgressResult.ErrorCode)
	require.NotEmpty(t, got.ProgressResult.StatusMessage)
}

// Function operations are synchronous, so Status is only ever a passthrough.
func TestStreamAnalyticsFunctionJavaScriptUdf_StatusIsPassthrough(t *testing.T) {
	prov := &StreamAnalyticsFunctionJavaScriptUdf{api: newSAFunctionService()}
	got, err := prov.Status(context.Background(), &resource.StatusRequest{RequestID: "req-1"})
	require.NoError(t, err)
	require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	require.Equal(t, "req-1", got.ProgressResult.RequestID)
}
