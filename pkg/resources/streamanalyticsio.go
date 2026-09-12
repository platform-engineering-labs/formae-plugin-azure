// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/streamanalytics/armstreamanalytics"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

// Shared envelope for the Stream Analytics input and output resources.
//
// ARM models every input as one `streamingjobs/{job}/inputs/{name}` resource and
// every output as one `streamingjobs/{job}/outputs/{name}` resource, with the
// interesting part behind a `properties.datasource.type` discriminator. Formae
// splits those into one resource type per datasource — InputBlob, InputEventHub,
// InputIotHub, OutputBlob, OutputEventHub, OutputServiceBusQueue, OutputTable —
// because a single polymorphic type would need a PKL union that core cannot plan
// against.
//
// That leaves seven resources with an identical envelope (name/job/CRUD/List) and
// seven different datasource bodies, so the envelope lives here once and each
// resource file contributes only its datasource: a builder for the PUT body and a
// serializer for the read path. This is the same split as cosmoschild.go and
// servicebusprops.go.
//
// Two rules the datasource contributions must respect:
//
//  1. Secrets are write-only. Every datasource carries a credential — a storage
//     account key, an Event Hubs/Service Bus shared access policy key, an IoT Hub
//     shared access policy key — and ARM accepts it on PUT but never returns it
//     from GET (see the SDK's own example response bodies, which drop AccountKey
//     and SharedAccessPolicyKey). A serializer that echoed a key back would emit a
//     field with no ARM value behind it, so every conformance phase would report
//     drift on it. Serializers here never write a key.
//
//  2. List must filter on the discriminator. NewListByStreamingJobPager returns
//     every input (or output) of the job whatever its datasource, so discovery for
//     InputBlob would otherwise claim the job's Event Hub inputs as well.

// --- property helpers -------------------------------------------------------

// saString reads an optional string property. Missing, null and non-string all
// read as "".
func saString(props map[string]any, key string) string {
	v, _ := props[key].(string)
	return v
}

// saRequiredString reads a property the ARM PUT body cannot omit.
func saRequiredString(props map[string]any, key string) (string, error) {
	v := saString(props, key)
	if v == "" {
		return "", fmt.Errorf("%s is required", key)
	}
	return v, nil
}

// saStringPtr returns nil for an absent or empty property so it is omitted from
// the request body rather than sent as "".
func saStringPtr(props map[string]any, key string) *string {
	if v := saString(props, key); v != "" {
		return to.Ptr(v)
	}
	return nil
}

// saInt32Ptr reads a numeric property. JSON numbers arrive as float64.
func saInt32Ptr(props map[string]any, key string) *int32 {
	switch v := props[key].(type) {
	case float64:
		return to.Ptr(int32(v))
	case int:
		return to.Ptr(int32(v))
	case int32:
		return to.Ptr(v)
	case int64:
		return to.Ptr(int32(v))
	}
	return nil
}

// saStringList reads a Listing<String> property.
func saStringList(props map[string]any, key string) []string {
	raw, ok := props[key].([]any)
	if !ok || len(raw) == 0 {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, entry := range raw {
		if s, ok := entry.(string); ok {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// --- serialization (Json / Csv / Avro) --------------------------------------

const (
	saSerializationJSON = "Json"
	saSerializationCSV  = "Csv"
	saSerializationAvro = "Avro"
)

// saSerializationFromProps builds the polymorphic `properties.serialization`
// block from the flat nested `serialization` object in the schema.
func saSerializationFromProps(props map[string]any) (armstreamanalytics.SerializationClassification, error) {
	raw, ok := props["serialization"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("serialization is required")
	}
	kind, err := saRequiredString(raw, "type")
	if err != nil {
		return nil, fmt.Errorf("serialization.type is required")
	}
	switch canonicalizeEnum(kind, saSerializationJSON, saSerializationCSV, saSerializationAvro) {
	case saSerializationJSON:
		body := &armstreamanalytics.JSONSerializationProperties{}
		if v := saString(raw, "encoding"); v != "" {
			body.Encoding = to.Ptr(armstreamanalytics.Encoding(v))
		}
		if v := saString(raw, "format"); v != "" {
			body.Format = to.Ptr(armstreamanalytics.JSONOutputSerializationFormat(v))
		}
		return &armstreamanalytics.JSONSerialization{
			Type:       to.Ptr(armstreamanalytics.EventSerializationTypeJSON),
			Properties: body,
		}, nil
	case saSerializationCSV:
		body := &armstreamanalytics.CSVSerializationProperties{}
		if v := saString(raw, "encoding"); v != "" {
			body.Encoding = to.Ptr(armstreamanalytics.Encoding(v))
		}
		if v := saString(raw, "fieldDelimiter"); v != "" {
			body.FieldDelimiter = to.Ptr(v)
		}
		return &armstreamanalytics.CSVSerialization{
			Type:       to.Ptr(armstreamanalytics.EventSerializationTypeCSV),
			Properties: body,
		}, nil
	case saSerializationAvro:
		// Avro takes no typed properties; ARM echoes an empty object back.
		return &armstreamanalytics.AvroSerialization{
			Type: to.Ptr(armstreamanalytics.EventSerializationTypeAvro),
		}, nil
	default:
		return nil, fmt.Errorf("unsupported serialization.type %q", kind)
	}
}

// saSerializeSerialization is the read-path inverse. Only fields ARM actually
// returned are emitted, so a caller who left `format` unset does not see drift
// against an invented value.
func saSerializeSerialization(s armstreamanalytics.SerializationClassification, props map[string]any) {
	if s == nil {
		return
	}
	out := make(map[string]any)
	switch typed := s.(type) {
	case *armstreamanalytics.JSONSerialization:
		out["type"] = saSerializationJSON
		if typed.Properties != nil {
			if typed.Properties.Encoding != nil {
				out["encoding"] = string(*typed.Properties.Encoding)
			}
			if typed.Properties.Format != nil {
				out["format"] = string(*typed.Properties.Format)
			}
		}
	case *armstreamanalytics.CSVSerialization:
		out["type"] = saSerializationCSV
		if typed.Properties != nil {
			if typed.Properties.Encoding != nil {
				out["encoding"] = string(*typed.Properties.Encoding)
			}
			if typed.Properties.FieldDelimiter != nil {
				out["fieldDelimiter"] = *typed.Properties.FieldDelimiter
			}
		}
	case *armstreamanalytics.AvroSerialization:
		out["type"] = saSerializationAvro
	default:
		base := s.GetSerialization()
		if base == nil || base.Type == nil {
			return
		}
		out["type"] = string(*base.Type)
	}
	props["serialization"] = out
}

// --- input envelope ---------------------------------------------------------

// streamAnalyticsInputsAPI is the armstreamanalytics.InputsClient surface used
// here. Every operation is synchronous: there is no BeginX verb on inputs, so
// Status is never reached.
type streamAnalyticsInputsAPI interface {
	CreateOrReplace(ctx context.Context, resourceGroupName string, jobName string, inputName string, input armstreamanalytics.Input, options *armstreamanalytics.InputsClientCreateOrReplaceOptions) (armstreamanalytics.InputsClientCreateOrReplaceResponse, error)
	Get(ctx context.Context, resourceGroupName string, jobName string, inputName string, options *armstreamanalytics.InputsClientGetOptions) (armstreamanalytics.InputsClientGetResponse, error)
	Update(ctx context.Context, resourceGroupName string, jobName string, inputName string, input armstreamanalytics.Input, options *armstreamanalytics.InputsClientUpdateOptions) (armstreamanalytics.InputsClientUpdateResponse, error)
	Delete(ctx context.Context, resourceGroupName string, jobName string, inputName string, options *armstreamanalytics.InputsClientDeleteOptions) (armstreamanalytics.InputsClientDeleteResponse, error)
	NewListByStreamingJobPager(resourceGroupName string, jobName string, options *armstreamanalytics.InputsClientListByStreamingJobOptions) *runtime.Pager[armstreamanalytics.InputsClientListByStreamingJobResponse]
}

// streamAnalyticsInputKind is everything that differs between the three input
// resource types.
type streamAnalyticsInputKind struct {
	// resourceType is the AZURE::StreamAnalytics::Input* type name.
	resourceType string
	// datasourceType is the ARM `properties.datasource.type` discriminator, used
	// both to build the PUT body and to filter List.
	datasourceType string
	// build turns desired properties into the datasource for a PUT body,
	// including the write-only credential.
	build func(props map[string]any) (armstreamanalytics.StreamInputDataSourceClassification, error)
	// serialize writes the datasource fields ARM returned back into props. It must
	// never emit a credential.
	serialize func(ds armstreamanalytics.StreamInputDataSourceClassification, props map[string]any)
}

// StreamAnalyticsInput provisions one `streamingjobs/<job>/inputs/<name>` ARM
// resource on behalf of whichever Input* formae type its kind names.
type StreamAnalyticsInput struct {
	api  streamAnalyticsInputsAPI
	kind streamAnalyticsInputKind
}

func streamAnalyticsInputIDParts(resourceID string) (rgName, jobName, inputName string, err error) {
	rgName, names, err := armIDParts(resourceID, "streamingjobs", "inputs")
	if err != nil {
		return "", "", "", err
	}
	return rgName, names["streamingjobs"], names["inputs"], nil
}

// saStreamInputDatasourceType pulls the discriminator out of an input returned by
// ARM, so List can tell a blob input from an Event Hub one.
func saStreamInputDatasourceType(in *armstreamanalytics.Input) string {
	if in == nil || in.Properties == nil {
		return ""
	}
	stream, ok := in.Properties.(*armstreamanalytics.StreamInputProperties)
	if !ok || stream.Datasource == nil {
		return ""
	}
	base := stream.Datasource.GetStreamInputDataSource()
	if base == nil || base.Type == nil {
		return ""
	}
	return *base.Type
}

func (i *StreamAnalyticsInput) params(props map[string]any) (armstreamanalytics.Input, error) {
	serialization, err := saSerializationFromProps(props)
	if err != nil {
		return armstreamanalytics.Input{}, err
	}
	datasource, err := i.kind.build(props)
	if err != nil {
		return armstreamanalytics.Input{}, err
	}
	stream := &armstreamanalytics.StreamInputProperties{
		Type:          to.Ptr("Stream"),
		Serialization: serialization,
		Datasource:    datasource,
	}
	if v := saStringPtr(props, "partitionKey"); v != nil {
		stream.PartitionKey = v
	}
	return armstreamanalytics.Input{Properties: stream}, nil
}

func (i *StreamAnalyticsInput) serialize(in armstreamanalytics.Input, rgName, jobName, inputName string) (json.RawMessage, error) {
	props := make(map[string]any)
	props["resourceGroupName"] = rgName
	props["jobName"] = jobName
	if in.Name != nil {
		props["name"] = *in.Name
	} else {
		props["name"] = inputName
	}
	if in.ID != nil {
		props["id"] = *in.ID
	}

	if stream, ok := in.Properties.(*armstreamanalytics.StreamInputProperties); ok && stream != nil {
		saSerializeSerialization(stream.Serialization, props)
		if stream.PartitionKey != nil {
			props["partitionKey"] = *stream.PartitionKey
		}
		if stream.Datasource != nil {
			i.kind.serialize(stream.Datasource, props)
		}
	}

	return json.Marshal(props)
}

func (i *StreamAnalyticsInput) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
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
	inputName := saString(props, "name")
	if inputName == "" {
		inputName = request.Label
	}
	if inputName == "" {
		return nil, fmt.Errorf("name is required")
	}

	params, err := i.params(props)
	if err != nil {
		return nil, err
	}

	result, err := i.api.CreateOrReplace(ctx, rgName, jobName, inputName, params, nil)
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

	propsJSON, err := i.serialize(result.Input, rgName, jobName, inputName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize %s properties: %w", i.kind.resourceType, err)
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

func (i *StreamAnalyticsInput) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, jobName, inputName, err := streamAnalyticsInputIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := i.api.Get(ctx, rgName, jobName, inputName, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	// A blob input read through the InputBlob type is a different resource from an
	// Event Hub input with the same ARM path shape; refuse the mismatch rather
	// than reporting drift on every datasource field.
	if got := saStreamInputDatasourceType(&result.Input); got != "" && !strings.EqualFold(got, i.kind.datasourceType) {
		return &resource.ReadResult{ErrorCode: resource.OperationErrorCodeNotFound}, nil
	}

	propsJSON, err := i.serialize(result.Input, rgName, jobName, inputName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize %s properties: %w", i.kind.resourceType, err)
	}

	return &resource.ReadResult{
		ResourceType: i.kind.resourceType,
		Properties:   string(propsJSON),
	}, nil
}

func (i *StreamAnalyticsInput) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, jobName, inputName, err := streamAnalyticsInputIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props map[string]any
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	params, err := i.params(props)
	if err != nil {
		return nil, err
	}

	result, err := i.api.Update(ctx, rgName, jobName, inputName, params, nil)
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

	propsJSON, err := i.serialize(result.Input, rgName, jobName, inputName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize %s properties: %w", i.kind.resourceType, err)
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

func (i *StreamAnalyticsInput) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, jobName, inputName, err := streamAnalyticsInputIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	if _, err := i.api.Delete(ctx, rgName, jobName, inputName, nil); err != nil && !isDeleteSuccessError(err) {
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

// Status is a success passthrough: input operations are synchronous, so
// Create/Update/Delete never report InProgress.
func (i *StreamAnalyticsInput) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

func (i *StreamAnalyticsInput) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	jobName := request.AdditionalProperties["jobName"]

	var nativeIDs []string
	pager := i.api.NewListByStreamingJobPager(rgName, jobName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list stream analytics inputs for job %s: %w", jobName, err)
		}
		for _, in := range page.Value {
			if in == nil || in.ID == nil {
				continue
			}
			// One ARM collection holds every datasource kind; only the matching
			// ones belong to this formae type.
			if !strings.EqualFold(saStreamInputDatasourceType(in), i.kind.datasourceType) {
				continue
			}
			nativeIDs = append(nativeIDs, *in.ID)
		}
	}

	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}

// --- output envelope --------------------------------------------------------

// streamAnalyticsOutputsAPI is the armstreamanalytics.OutputsClient surface used
// here. Synchronous throughout, like inputs.
type streamAnalyticsOutputsAPI interface {
	CreateOrReplace(ctx context.Context, resourceGroupName string, jobName string, outputName string, output armstreamanalytics.Output, options *armstreamanalytics.OutputsClientCreateOrReplaceOptions) (armstreamanalytics.OutputsClientCreateOrReplaceResponse, error)
	Get(ctx context.Context, resourceGroupName string, jobName string, outputName string, options *armstreamanalytics.OutputsClientGetOptions) (armstreamanalytics.OutputsClientGetResponse, error)
	Update(ctx context.Context, resourceGroupName string, jobName string, outputName string, output armstreamanalytics.Output, options *armstreamanalytics.OutputsClientUpdateOptions) (armstreamanalytics.OutputsClientUpdateResponse, error)
	Delete(ctx context.Context, resourceGroupName string, jobName string, outputName string, options *armstreamanalytics.OutputsClientDeleteOptions) (armstreamanalytics.OutputsClientDeleteResponse, error)
	NewListByStreamingJobPager(resourceGroupName string, jobName string, options *armstreamanalytics.OutputsClientListByStreamingJobOptions) *runtime.Pager[armstreamanalytics.OutputsClientListByStreamingJobResponse]
}

// streamAnalyticsOutputKind is everything that differs between the four output
// resource types.
type streamAnalyticsOutputKind struct {
	resourceType   string
	datasourceType string
	build          func(props map[string]any) (armstreamanalytics.OutputDataSourceClassification, error)
	serialize      func(ds armstreamanalytics.OutputDataSourceClassification, props map[string]any)
	// serialization is false for Azure Table, the one output whose ARM body takes
	// no `properties.serialization` block at all.
	serialization bool
}

// StreamAnalyticsOutput provisions one `streamingjobs/<job>/outputs/<name>` ARM
// resource on behalf of whichever Output* formae type its kind names.
type StreamAnalyticsOutput struct {
	api  streamAnalyticsOutputsAPI
	kind streamAnalyticsOutputKind
}

func streamAnalyticsOutputIDParts(resourceID string) (rgName, jobName, outputName string, err error) {
	rgName, names, err := armIDParts(resourceID, "streamingjobs", "outputs")
	if err != nil {
		return "", "", "", err
	}
	return rgName, names["streamingjobs"], names["outputs"], nil
}

func saOutputDatasourceType(out *armstreamanalytics.Output) string {
	if out == nil || out.Properties == nil || out.Properties.Datasource == nil {
		return ""
	}
	base := out.Properties.Datasource.GetOutputDataSource()
	if base == nil || base.Type == nil {
		return ""
	}
	return *base.Type
}

func (o *StreamAnalyticsOutput) params(props map[string]any) (armstreamanalytics.Output, error) {
	datasource, err := o.kind.build(props)
	if err != nil {
		return armstreamanalytics.Output{}, err
	}
	body := &armstreamanalytics.OutputProperties{Datasource: datasource}
	if o.kind.serialization {
		serialization, err := saSerializationFromProps(props)
		if err != nil {
			return armstreamanalytics.Output{}, err
		}
		body.Serialization = serialization
	}
	return armstreamanalytics.Output{Properties: body}, nil
}

func (o *StreamAnalyticsOutput) serialize(out armstreamanalytics.Output, rgName, jobName, outputName string) (json.RawMessage, error) {
	props := make(map[string]any)
	props["resourceGroupName"] = rgName
	props["jobName"] = jobName
	if out.Name != nil {
		props["name"] = *out.Name
	} else {
		props["name"] = outputName
	}
	if out.ID != nil {
		props["id"] = *out.ID
	}

	if body := out.Properties; body != nil {
		if o.kind.serialization {
			saSerializeSerialization(body.Serialization, props)
		}
		if body.Datasource != nil {
			o.kind.serialize(body.Datasource, props)
		}
	}

	return json.Marshal(props)
}

func (o *StreamAnalyticsOutput) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
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
	outputName := saString(props, "name")
	if outputName == "" {
		outputName = request.Label
	}
	if outputName == "" {
		return nil, fmt.Errorf("name is required")
	}

	params, err := o.params(props)
	if err != nil {
		return nil, err
	}

	result, err := o.api.CreateOrReplace(ctx, rgName, jobName, outputName, params, nil)
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

	propsJSON, err := o.serialize(result.Output, rgName, jobName, outputName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize %s properties: %w", o.kind.resourceType, err)
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

func (o *StreamAnalyticsOutput) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, jobName, outputName, err := streamAnalyticsOutputIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := o.api.Get(ctx, rgName, jobName, outputName, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	if got := saOutputDatasourceType(&result.Output); got != "" && !strings.EqualFold(got, o.kind.datasourceType) {
		return &resource.ReadResult{ErrorCode: resource.OperationErrorCodeNotFound}, nil
	}

	propsJSON, err := o.serialize(result.Output, rgName, jobName, outputName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize %s properties: %w", o.kind.resourceType, err)
	}

	return &resource.ReadResult{
		ResourceType: o.kind.resourceType,
		Properties:   string(propsJSON),
	}, nil
}

func (o *StreamAnalyticsOutput) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, jobName, outputName, err := streamAnalyticsOutputIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props map[string]any
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	params, err := o.params(props)
	if err != nil {
		return nil, err
	}

	result, err := o.api.Update(ctx, rgName, jobName, outputName, params, nil)
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

	propsJSON, err := o.serialize(result.Output, rgName, jobName, outputName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize %s properties: %w", o.kind.resourceType, err)
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

func (o *StreamAnalyticsOutput) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, jobName, outputName, err := streamAnalyticsOutputIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	if _, err := o.api.Delete(ctx, rgName, jobName, outputName, nil); err != nil && !isDeleteSuccessError(err) {
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

// Status is a success passthrough: output operations are synchronous.
func (o *StreamAnalyticsOutput) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

func (o *StreamAnalyticsOutput) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	jobName := request.AdditionalProperties["jobName"]

	var nativeIDs []string
	pager := o.api.NewListByStreamingJobPager(rgName, jobName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list stream analytics outputs for job %s: %w", jobName, err)
		}
		for _, out := range page.Value {
			if out == nil || out.ID == nil {
				continue
			}
			if !strings.EqualFold(saOutputDatasourceType(out), o.kind.datasourceType) {
				continue
			}
			nativeIDs = append(nativeIDs, *out.ID)
		}
	}

	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
