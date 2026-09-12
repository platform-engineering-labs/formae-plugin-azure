// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/streamanalytics/armstreamanalytics"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeStreamAnalyticsFunctionJavaScriptUdf = "AZURE::StreamAnalytics::FunctionJavaScriptUdf"

// ARM discriminators for a JavaScript UDF. `functionType` is the outer
// `properties.type`; `bindingType` is the inner `properties.properties.binding.type`.
const (
	streamAnalyticsScalarFunctionType   = "Scalar"
	streamAnalyticsJavaScriptUdfBinding = "Microsoft.StreamAnalytics/JavascriptUdf"
)

// streamAnalyticsFunctionDataTypes is the canonical casing of the Stream Analytics
// data types a UDF argument or return value can take, matching the PKL union.
//
// The service is inconsistent about casing here — ARM's own examples show "Any"
// where the documented type name is "any" — so the read path folds whatever comes
// back onto this set. Echoing the response verbatim would fail conformance
// [Verify] ("expected any, got Any") and break `formae extract`, which could not
// render the union.
var streamAnalyticsFunctionDataTypes = []string{
	"any", "bigint", "datetime", "float", "nvarchar(max)", "bit", "record", "array",
}

// streamAnalyticsFunctionsAPI is the armstreamanalytics.FunctionsClient surface
// used here. Every CRUD verb is synchronous — the only poller on this client is
// BeginTest, which exercises the function against live data and is not part of
// provisioning.
type streamAnalyticsFunctionsAPI interface {
	CreateOrReplace(ctx context.Context, resourceGroupName string, jobName string, functionName string, function armstreamanalytics.Function, options *armstreamanalytics.FunctionsClientCreateOrReplaceOptions) (armstreamanalytics.FunctionsClientCreateOrReplaceResponse, error)
	Get(ctx context.Context, resourceGroupName string, jobName string, functionName string, options *armstreamanalytics.FunctionsClientGetOptions) (armstreamanalytics.FunctionsClientGetResponse, error)
	Update(ctx context.Context, resourceGroupName string, jobName string, functionName string, function armstreamanalytics.Function, options *armstreamanalytics.FunctionsClientUpdateOptions) (armstreamanalytics.FunctionsClientUpdateResponse, error)
	Delete(ctx context.Context, resourceGroupName string, jobName string, functionName string, options *armstreamanalytics.FunctionsClientDeleteOptions) (armstreamanalytics.FunctionsClientDeleteResponse, error)
	NewListByStreamingJobPager(resourceGroupName string, jobName string, options *armstreamanalytics.FunctionsClientListByStreamingJobOptions) *runtime.Pager[armstreamanalytics.FunctionsClientListByStreamingJobResponse]
}

func init() {
	registry.Register(ResourceTypeStreamAnalyticsFunctionJavaScriptUdf, func(c *client.Client, _ *config.Config) prov.Provisioner {
		return &StreamAnalyticsFunctionJavaScriptUdf{api: c.StreamAnalyticsFunctionsClient}
	})
}

// StreamAnalyticsFunctionJavaScriptUdf is the provisioner for a JavaScript
// user-defined function on a streaming job
// (`Microsoft.StreamAnalytics/streamingjobs/<job>/functions/<name>`).
//
// ARM nests the interesting parts two levels deep behind two discriminators —
// `properties.type = "Scalar"` and
// `properties.properties.binding.type = "Microsoft.StreamAnalytics/JavascriptUdf"`.
// The schema flattens both away: this type only ever writes a scalar JavaScript
// UDF, so neither discriminator is a settable field, and `script` sits at the top
// level rather than under a binding object.
//
// Machine-learning-web-service bindings and aggregate functions share the same ARM
// resource but are separate formae types; List filters on the binding type so this
// one does not claim them.
//
// All operations are synchronous, so Status is a passthrough.
type StreamAnalyticsFunctionJavaScriptUdf struct {
	api streamAnalyticsFunctionsAPI
}

func streamAnalyticsFunctionIDParts(resourceID string) (rgName, jobName, functionName string, err error) {
	rgName, names, err := armIDParts(resourceID, "streamingjobs", "functions")
	if err != nil {
		return "", "", "", err
	}
	return rgName, names["streamingjobs"], names["functions"], nil
}

// streamAnalyticsJavaScriptBinding pulls the JavaScript binding out of a function
// ARM returned, or nil when the function is some other kind.
func streamAnalyticsJavaScriptBinding(fn *armstreamanalytics.Function) (*armstreamanalytics.JavaScriptFunctionBinding, *armstreamanalytics.FunctionConfiguration) {
	if fn == nil || fn.Properties == nil {
		return nil, nil
	}
	base := fn.Properties.GetFunctionProperties()
	if base == nil || base.Properties == nil || base.Properties.Binding == nil {
		return nil, nil
	}
	binding, ok := base.Properties.Binding.(*armstreamanalytics.JavaScriptFunctionBinding)
	if !ok {
		return nil, nil
	}
	return binding, base.Properties
}

func streamAnalyticsFunctionParamsFromProperties(props map[string]any) (armstreamanalytics.Function, error) {
	script, err := saRequiredString(props, "script")
	if err != nil {
		return armstreamanalytics.Function{}, err
	}
	outputDataType, err := saRequiredString(props, "outputDataType")
	if err != nil {
		return armstreamanalytics.Function{}, err
	}

	rawInputs, ok := props["inputs"].([]any)
	if !ok || len(rawInputs) == 0 {
		return armstreamanalytics.Function{}, fmt.Errorf("inputs is required and must declare at least one argument")
	}
	inputs := make([]*armstreamanalytics.FunctionInput, 0, len(rawInputs))
	for i, raw := range rawInputs {
		entry, ok := raw.(map[string]any)
		if !ok {
			return armstreamanalytics.Function{}, fmt.Errorf("inputs[%d] is not an object", i)
		}
		dataType, err := saRequiredString(entry, "dataType")
		if err != nil {
			return armstreamanalytics.Function{}, fmt.Errorf("inputs[%d].dataType is required", i)
		}
		arg := &armstreamanalytics.FunctionInput{DataType: to.Ptr(dataType)}
		if v, ok := entry["isConfigurationParameter"].(bool); ok {
			arg.IsConfigurationParameter = to.Ptr(v)
		}
		inputs = append(inputs, arg)
	}

	return armstreamanalytics.Function{
		Properties: &armstreamanalytics.ScalarFunctionProperties{
			Type: to.Ptr(streamAnalyticsScalarFunctionType),
			Properties: &armstreamanalytics.FunctionConfiguration{
				Binding: &armstreamanalytics.JavaScriptFunctionBinding{
					Type: to.Ptr(streamAnalyticsJavaScriptUdfBinding),
					Properties: &armstreamanalytics.JavaScriptFunctionBindingProperties{
						Script: to.Ptr(script),
					},
				},
				Inputs: inputs,
				Output: &armstreamanalytics.FunctionOutput{DataType: to.Ptr(outputDataType)},
			},
		},
	}, nil
}

func serializeStreamAnalyticsFunctionProperties(fn armstreamanalytics.Function, rgName, jobName, functionName string) (json.RawMessage, error) {
	props := make(map[string]any)
	props["resourceGroupName"] = rgName
	props["jobName"] = jobName
	if fn.Name != nil {
		props["name"] = *fn.Name
	} else {
		props["name"] = functionName
	}
	if fn.ID != nil {
		props["id"] = *fn.ID
	}

	binding, configuration := streamAnalyticsJavaScriptBinding(&fn)
	if binding != nil && binding.Properties != nil && binding.Properties.Script != nil {
		props["script"] = *binding.Properties.Script
	}
	if configuration != nil {
		if configuration.Output != nil && configuration.Output.DataType != nil {
			props["outputDataType"] = canonicalizeEnum(*configuration.Output.DataType, streamAnalyticsFunctionDataTypes...)
		}
		if len(configuration.Inputs) > 0 {
			inputs := make([]map[string]any, 0, len(configuration.Inputs))
			for _, arg := range configuration.Inputs {
				if arg == nil {
					continue
				}
				entry := make(map[string]any)
				if arg.DataType != nil {
					entry["dataType"] = canonicalizeEnum(*arg.DataType, streamAnalyticsFunctionDataTypes...)
				}
				if arg.IsConfigurationParameter != nil {
					entry["isConfigurationParameter"] = *arg.IsConfigurationParameter
				}
				inputs = append(inputs, entry)
			}
			if len(inputs) > 0 {
				props["inputs"] = inputs
			}
		}
	}

	return json.Marshal(props)
}

func (f *StreamAnalyticsFunctionJavaScriptUdf) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props map[string]any
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	rgName, err := saRequiredString(props, "resourceGroupName")
	if err != nil {
		return nil, err
	}
	jobName, err := saRequiredString(props, "jobName")
	if err != nil {
		return nil, err
	}
	functionName := saString(props, "name")
	if functionName == "" {
		functionName = request.Label
	}
	if functionName == "" {
		return nil, fmt.Errorf("name is required")
	}

	params, err := streamAnalyticsFunctionParamsFromProperties(props)
	if err != nil {
		return nil, err
	}

	result, err := f.api.CreateOrReplace(ctx, rgName, jobName, functionName, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
				StatusMessage:   err.Error(),
			},
		}, nil
	}

	propsJSON, err := serializeStreamAnalyticsFunctionProperties(result.Function, rgName, jobName, functionName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize Function properties: %w", err)
	}
	nativeID := ""
	if result.ID != nil {
		nativeID = *result.ID
	}

	return &resource.CreateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:          resource.OperationCreate,
			OperationStatus:    resource.OperationStatusSuccess,
			NativeID:           nativeID,
			ResourceProperties: propsJSON,
		},
	}, nil
}

func (f *StreamAnalyticsFunctionJavaScriptUdf) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, jobName, functionName, err := streamAnalyticsFunctionIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := f.api.Get(ctx, rgName, jobName, functionName, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	// Some other binding kind at this path is a different formae type, not drift.
	if binding, _ := streamAnalyticsJavaScriptBinding(&result.Function); binding == nil {
		return &resource.ReadResult{ErrorCode: resource.OperationErrorCodeNotFound}, nil
	}

	propsJSON, err := serializeStreamAnalyticsFunctionProperties(result.Function, rgName, jobName, functionName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize Function properties: %w", err)
	}

	return &resource.ReadResult{
		ResourceType: ResourceTypeStreamAnalyticsFunctionJavaScriptUdf,
		Properties:   string(propsJSON),
	}, nil
}

func (f *StreamAnalyticsFunctionJavaScriptUdf) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, jobName, functionName, err := streamAnalyticsFunctionIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props map[string]any
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	params, err := streamAnalyticsFunctionParamsFromProperties(props)
	if err != nil {
		return nil, err
	}

	result, err := f.api.Update(ctx, rgName, jobName, functionName, params, nil)
	if err != nil {
		return &resource.UpdateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationUpdate,
				OperationStatus: resource.OperationStatusFailure,
				NativeID:        request.NativeID,
				ErrorCode:       operationErrorCode(err),
				StatusMessage:   err.Error(),
			},
		}, nil
	}

	propsJSON, err := serializeStreamAnalyticsFunctionProperties(result.Function, rgName, jobName, functionName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize Function properties: %w", err)
	}

	return &resource.UpdateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:          resource.OperationUpdate,
			OperationStatus:    resource.OperationStatusSuccess,
			NativeID:           request.NativeID,
			ResourceProperties: propsJSON,
		},
	}, nil
}

func (f *StreamAnalyticsFunctionJavaScriptUdf) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, jobName, functionName, err := streamAnalyticsFunctionIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	if _, err := f.api.Delete(ctx, rgName, jobName, functionName, nil); err != nil && !isDeleteSuccessError(err) {
		return &resource.DeleteResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationDelete,
				OperationStatus: resource.OperationStatusFailure,
				NativeID:        request.NativeID,
				ErrorCode:       operationErrorCode(err),
				StatusMessage:   err.Error(),
			},
		}, nil
	}

	return &resource.DeleteResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationDelete,
			OperationStatus: resource.OperationStatusSuccess,
			NativeID:        request.NativeID,
		},
	}, nil
}

// Status is a success passthrough: function operations are synchronous.
func (f *StreamAnalyticsFunctionJavaScriptUdf) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

func (f *StreamAnalyticsFunctionJavaScriptUdf) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	jobName := request.AdditionalProperties["jobName"]

	var nativeIDs []string
	pager := f.api.NewListByStreamingJobPager(rgName, jobName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list stream analytics functions for job %s: %w", jobName, err)
		}
		for _, fn := range page.Value {
			if fn == nil || fn.ID == nil {
				continue
			}
			// The functions collection also holds ML-web-service bindings and
			// aggregate functions; only JavaScript UDFs belong to this type.
			if binding, _ := streamAnalyticsJavaScriptBinding(fn); binding == nil {
				continue
			}
			nativeIDs = append(nativeIDs, *fn.ID)
		}
	}

	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
