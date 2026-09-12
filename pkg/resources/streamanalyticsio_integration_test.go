// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/streamanalytics/armstreamanalytics"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

// Shared fakes for the Stream Analytics input and output envelopes.
//
// These are service simulators rather than closure-per-method stubs: they store
// what was PUT and echo it back with the credential stripped, because that is the
// one behaviour of the real service the plugin has to get right. Every per-
// datasource test then gets "the key never reaches state" checked for free
// against a fake that behaves like ARM instead of one that behaves however the
// test wanted.

const (
	testSAJobResourceGroup = "rg-1"
	testSAJobName          = "job-1"
	testSAJobNativeID      = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.StreamAnalytics/streamingjobs/job-1"
)

func testSAInputNativeID(name string) string {
	return fmt.Sprintf("%s/inputs/%s", testSAJobNativeID, name)
}

func testSAOutputNativeID(name string) string {
	return fmt.Sprintf("%s/outputs/%s", testSAJobNativeID, name)
}

func testSAFunctionNativeID(name string) string {
	return fmt.Sprintf("%s/functions/%s", testSAJobNativeID, name)
}

func testSANotFound() error {
	return &azcore.ResponseError{StatusCode: http.StatusNotFound}
}

func testSAConflict() error {
	return &azcore.ResponseError{StatusCode: http.StatusConflict}
}

// --- input service simulator ------------------------------------------------

type saInputService struct {
	stored  map[string]armstreamanalytics.Input
	sent    []armstreamanalytics.Input
	deletes int

	createErr error
	getErr    error
	updateErr error
	deleteErr error
	listErr   error
}

func newSAInputService() *saInputService {
	return &saInputService{stored: map[string]armstreamanalytics.Input{}}
}

// seed puts an input into the collection without recording it as a write, for
// tests that need a pre-existing input of some other datasource kind.
func (s *saInputService) seed(name string, in armstreamanalytics.Input) {
	stored := saStripInputSecrets(in)
	stored.Name = to.Ptr(name)
	stored.ID = to.Ptr(testSAInputNativeID(name))
	s.stored[name] = stored
}

func (s *saInputService) put(name string, in armstreamanalytics.Input) armstreamanalytics.Input {
	s.sent = append(s.sent, in)
	s.seed(name, in)
	return s.stored[name]
}

func (s *saInputService) lastSent() armstreamanalytics.Input {
	return s.sent[len(s.sent)-1]
}

func (s *saInputService) CreateOrReplace(_ context.Context, _, _, inputName string, input armstreamanalytics.Input, _ *armstreamanalytics.InputsClientCreateOrReplaceOptions) (armstreamanalytics.InputsClientCreateOrReplaceResponse, error) {
	if s.createErr != nil {
		return armstreamanalytics.InputsClientCreateOrReplaceResponse{}, s.createErr
	}
	return armstreamanalytics.InputsClientCreateOrReplaceResponse{Input: s.put(inputName, input)}, nil
}

func (s *saInputService) Get(_ context.Context, _, _, inputName string, _ *armstreamanalytics.InputsClientGetOptions) (armstreamanalytics.InputsClientGetResponse, error) {
	if s.getErr != nil {
		return armstreamanalytics.InputsClientGetResponse{}, s.getErr
	}
	stored, ok := s.stored[inputName]
	if !ok {
		return armstreamanalytics.InputsClientGetResponse{}, testSANotFound()
	}
	return armstreamanalytics.InputsClientGetResponse{Input: stored}, nil
}

func (s *saInputService) Update(_ context.Context, _, _, inputName string, input armstreamanalytics.Input, _ *armstreamanalytics.InputsClientUpdateOptions) (armstreamanalytics.InputsClientUpdateResponse, error) {
	if s.updateErr != nil {
		return armstreamanalytics.InputsClientUpdateResponse{}, s.updateErr
	}
	return armstreamanalytics.InputsClientUpdateResponse{Input: s.put(inputName, input)}, nil
}

func (s *saInputService) Delete(_ context.Context, _, _, inputName string, _ *armstreamanalytics.InputsClientDeleteOptions) (armstreamanalytics.InputsClientDeleteResponse, error) {
	if s.deleteErr != nil {
		return armstreamanalytics.InputsClientDeleteResponse{}, s.deleteErr
	}
	s.deletes++
	delete(s.stored, inputName)
	return armstreamanalytics.InputsClientDeleteResponse{}, nil
}

func (s *saInputService) NewListByStreamingJobPager(_, _ string, _ *armstreamanalytics.InputsClientListByStreamingJobOptions) *runtime.Pager[armstreamanalytics.InputsClientListByStreamingJobResponse] {
	return runtime.NewPager(runtime.PagingHandler[armstreamanalytics.InputsClientListByStreamingJobResponse]{
		More: func(_ armstreamanalytics.InputsClientListByStreamingJobResponse) bool { return false },
		Fetcher: func(_ context.Context, _ *armstreamanalytics.InputsClientListByStreamingJobResponse) (armstreamanalytics.InputsClientListByStreamingJobResponse, error) {
			if s.listErr != nil {
				return armstreamanalytics.InputsClientListByStreamingJobResponse{}, s.listErr
			}
			names := make([]string, 0, len(s.stored))
			for name := range s.stored {
				names = append(names, name)
			}
			sort.Strings(names)
			values := make([]*armstreamanalytics.Input, 0, len(names))
			for _, name := range names {
				stored := s.stored[name]
				values = append(values, &stored)
			}
			return armstreamanalytics.InputsClientListByStreamingJobResponse{
				InputListResult: armstreamanalytics.InputListResult{Value: values},
			}, nil
		},
	})
}

// saStripInputSecrets reproduces what ARM does to an input on the way out: the
// datasource credential is dropped from every response.
func saStripInputSecrets(in armstreamanalytics.Input) armstreamanalytics.Input {
	stream, ok := in.Properties.(*armstreamanalytics.StreamInputProperties)
	if !ok || stream == nil || stream.Datasource == nil {
		return in
	}
	stripped := *stream
	switch ds := stream.Datasource.(type) {
	case *armstreamanalytics.BlobStreamInputDataSource:
		if ds.Properties != nil {
			body := *ds.Properties
			accounts := make([]*armstreamanalytics.StorageAccount, 0, len(body.StorageAccounts))
			for _, account := range body.StorageAccounts {
				if account == nil {
					continue
				}
				accounts = append(accounts, &armstreamanalytics.StorageAccount{AccountName: account.AccountName})
			}
			body.StorageAccounts = accounts
			stripped.Datasource = &armstreamanalytics.BlobStreamInputDataSource{Type: ds.Type, Properties: &body}
		}
	case *armstreamanalytics.EventHubStreamInputDataSource:
		if ds.Properties != nil {
			body := *ds.Properties
			body.SharedAccessPolicyKey = nil
			stripped.Datasource = &armstreamanalytics.EventHubStreamInputDataSource{Type: ds.Type, Properties: &body}
		}
	case *armstreamanalytics.IoTHubStreamInputDataSource:
		if ds.Properties != nil {
			body := *ds.Properties
			body.SharedAccessPolicyKey = nil
			stripped.Datasource = &armstreamanalytics.IoTHubStreamInputDataSource{Type: ds.Type, Properties: &body}
		}
	}
	out := in
	out.Properties = &stripped
	return out
}

// --- output service simulator -----------------------------------------------

type saOutputService struct {
	stored  map[string]armstreamanalytics.Output
	sent    []armstreamanalytics.Output
	deletes int

	createErr error
	getErr    error
	updateErr error
	deleteErr error
	listErr   error
}

func newSAOutputService() *saOutputService {
	return &saOutputService{stored: map[string]armstreamanalytics.Output{}}
}

func (s *saOutputService) seed(name string, out armstreamanalytics.Output) {
	stored := saStripOutputSecrets(out)
	stored.Name = to.Ptr(name)
	stored.ID = to.Ptr(testSAOutputNativeID(name))
	s.stored[name] = stored
}

func (s *saOutputService) put(name string, out armstreamanalytics.Output) armstreamanalytics.Output {
	s.sent = append(s.sent, out)
	s.seed(name, out)
	return s.stored[name]
}

func (s *saOutputService) lastSent() armstreamanalytics.Output {
	return s.sent[len(s.sent)-1]
}

func (s *saOutputService) CreateOrReplace(_ context.Context, _, _, outputName string, output armstreamanalytics.Output, _ *armstreamanalytics.OutputsClientCreateOrReplaceOptions) (armstreamanalytics.OutputsClientCreateOrReplaceResponse, error) {
	if s.createErr != nil {
		return armstreamanalytics.OutputsClientCreateOrReplaceResponse{}, s.createErr
	}
	return armstreamanalytics.OutputsClientCreateOrReplaceResponse{Output: s.put(outputName, output)}, nil
}

func (s *saOutputService) Get(_ context.Context, _, _, outputName string, _ *armstreamanalytics.OutputsClientGetOptions) (armstreamanalytics.OutputsClientGetResponse, error) {
	if s.getErr != nil {
		return armstreamanalytics.OutputsClientGetResponse{}, s.getErr
	}
	stored, ok := s.stored[outputName]
	if !ok {
		return armstreamanalytics.OutputsClientGetResponse{}, testSANotFound()
	}
	return armstreamanalytics.OutputsClientGetResponse{Output: stored}, nil
}

func (s *saOutputService) Update(_ context.Context, _, _, outputName string, output armstreamanalytics.Output, _ *armstreamanalytics.OutputsClientUpdateOptions) (armstreamanalytics.OutputsClientUpdateResponse, error) {
	if s.updateErr != nil {
		return armstreamanalytics.OutputsClientUpdateResponse{}, s.updateErr
	}
	return armstreamanalytics.OutputsClientUpdateResponse{Output: s.put(outputName, output)}, nil
}

func (s *saOutputService) Delete(_ context.Context, _, _, outputName string, _ *armstreamanalytics.OutputsClientDeleteOptions) (armstreamanalytics.OutputsClientDeleteResponse, error) {
	if s.deleteErr != nil {
		return armstreamanalytics.OutputsClientDeleteResponse{}, s.deleteErr
	}
	s.deletes++
	delete(s.stored, outputName)
	return armstreamanalytics.OutputsClientDeleteResponse{}, nil
}

func (s *saOutputService) NewListByStreamingJobPager(_, _ string, _ *armstreamanalytics.OutputsClientListByStreamingJobOptions) *runtime.Pager[armstreamanalytics.OutputsClientListByStreamingJobResponse] {
	return runtime.NewPager(runtime.PagingHandler[armstreamanalytics.OutputsClientListByStreamingJobResponse]{
		More: func(_ armstreamanalytics.OutputsClientListByStreamingJobResponse) bool { return false },
		Fetcher: func(_ context.Context, _ *armstreamanalytics.OutputsClientListByStreamingJobResponse) (armstreamanalytics.OutputsClientListByStreamingJobResponse, error) {
			if s.listErr != nil {
				return armstreamanalytics.OutputsClientListByStreamingJobResponse{}, s.listErr
			}
			names := make([]string, 0, len(s.stored))
			for name := range s.stored {
				names = append(names, name)
			}
			sort.Strings(names)
			values := make([]*armstreamanalytics.Output, 0, len(names))
			for _, name := range names {
				stored := s.stored[name]
				values = append(values, &stored)
			}
			return armstreamanalytics.OutputsClientListByStreamingJobResponse{
				OutputListResult: armstreamanalytics.OutputListResult{Value: values},
			}, nil
		},
	})
}

// saStripOutputSecrets reproduces what ARM does to an output on the way out.
func saStripOutputSecrets(out armstreamanalytics.Output) armstreamanalytics.Output {
	if out.Properties == nil || out.Properties.Datasource == nil {
		return out
	}
	stripped := *out.Properties
	switch ds := out.Properties.Datasource.(type) {
	case *armstreamanalytics.BlobOutputDataSource:
		if ds.Properties != nil {
			body := *ds.Properties
			accounts := make([]*armstreamanalytics.StorageAccount, 0, len(body.StorageAccounts))
			for _, account := range body.StorageAccounts {
				if account == nil {
					continue
				}
				accounts = append(accounts, &armstreamanalytics.StorageAccount{AccountName: account.AccountName})
			}
			body.StorageAccounts = accounts
			stripped.Datasource = &armstreamanalytics.BlobOutputDataSource{Type: ds.Type, Properties: &body}
		}
	case *armstreamanalytics.EventHubOutputDataSource:
		if ds.Properties != nil {
			body := *ds.Properties
			body.SharedAccessPolicyKey = nil
			stripped.Datasource = &armstreamanalytics.EventHubOutputDataSource{Type: ds.Type, Properties: &body}
		}
	case *armstreamanalytics.ServiceBusQueueOutputDataSource:
		if ds.Properties != nil {
			body := *ds.Properties
			body.SharedAccessPolicyKey = nil
			stripped.Datasource = &armstreamanalytics.ServiceBusQueueOutputDataSource{Type: ds.Type, Properties: &body}
		}
	case *armstreamanalytics.AzureTableOutputDataSource:
		if ds.Properties != nil {
			body := *ds.Properties
			body.AccountKey = nil
			stripped.Datasource = &armstreamanalytics.AzureTableOutputDataSource{Type: ds.Type, Properties: &body}
		}
	}
	result := out
	result.Properties = &stripped
	return result
}

// --- shared assertions used by every per-datasource test --------------------

// saCreate runs Create and unwraps the serialized properties.
func saCreate(t *testing.T, prov interface {
	Create(context.Context, *resource.CreateRequest) (*resource.CreateResult, error)
}, desired map[string]any, label string) (*resource.ProgressResult, map[string]any) {
	t.Helper()
	raw, err := json.Marshal(desired)
	require.NoError(t, err)
	got, err := prov.Create(context.Background(), &resource.CreateRequest{Label: label, Properties: raw})
	require.NoError(t, err)
	require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	var props map[string]any
	require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &props))
	return got.ProgressResult, props
}

// saRead runs Read and unwraps the serialized properties.
func saRead(t *testing.T, prov interface {
	Read(context.Context, *resource.ReadRequest) (*resource.ReadResult, error)
}, nativeID string) map[string]any {
	t.Helper()
	got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: nativeID})
	require.NoError(t, err)
	require.Empty(t, got.ErrorCode)
	var props map[string]any
	require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
	return props
}

// saRequireNoSecrets fails if any credential-shaped key made it into state.
// ARM never returns these, so a serializer that emitted one would report drift
// in all four conformance phases.
func saRequireNoSecrets(t *testing.T, props map[string]any) {
	t.Helper()
	for _, key := range []string{"storageAccountKey", "sharedAccessPolicyKey", "accountKey", "accessKey"} {
		require.NotContains(t, props, key, "credential must never reach resource state")
	}
}

// --- envelope tests ---------------------------------------------------------

// One ARM collection holds every datasource kind, so each formae type's List
// must filter on the discriminator or discovery claims its siblings' resources.
func TestStreamAnalyticsInput_ListFiltersByDatasource(t *testing.T) {
	service := newSAInputService()
	service.seed("blobbie", armstreamanalytics.Input{Properties: &armstreamanalytics.StreamInputProperties{
		Type: to.Ptr("Stream"),
		Datasource: &armstreamanalytics.BlobStreamInputDataSource{
			Type:       to.Ptr(streamAnalyticsBlobDatasourceType),
			Properties: &armstreamanalytics.BlobStreamInputDataSourceProperties{Container: to.Ptr("c")},
		},
	}})
	service.seed("hubbie", armstreamanalytics.Input{Properties: &armstreamanalytics.StreamInputProperties{
		Type: to.Ptr("Stream"),
		Datasource: &armstreamanalytics.EventHubStreamInputDataSource{
			Type:       to.Ptr(streamAnalyticsEventHubDatasourceType),
			Properties: &armstreamanalytics.EventHubStreamInputDataSourceProperties{EventHubName: to.Ptr("h")},
		},
	}})
	service.seed("iottie", armstreamanalytics.Input{Properties: &armstreamanalytics.StreamInputProperties{
		Type: to.Ptr("Stream"),
		Datasource: &armstreamanalytics.IoTHubStreamInputDataSource{
			Type:       to.Ptr(streamAnalyticsIotHubDatasourceType),
			Properties: &armstreamanalytics.IoTHubStreamInputDataSourceProperties{IotHubNamespace: to.Ptr("i")},
		},
	}})

	for _, tc := range []struct {
		kind streamAnalyticsInputKind
		want string
	}{
		{streamAnalyticsInputBlobKind, "blobbie"},
		{streamAnalyticsInputEventHubKind, "hubbie"},
		{streamAnalyticsInputIotHubKind, "iottie"},
	} {
		t.Run(tc.kind.resourceType, func(t *testing.T) {
			prov := &StreamAnalyticsInput{api: service, kind: tc.kind}
			got, err := prov.List(context.Background(), &resource.ListRequest{
				AdditionalProperties: map[string]string{
					"resourceGroupName": testSAJobResourceGroup,
					"jobName":           testSAJobName,
				},
			})
			require.NoError(t, err)
			require.Equal(t, []string{testSAInputNativeID(tc.want)}, got.NativeIDs)
		})
	}
}

// Reading an Event Hub input through the InputBlob type must not report drift on
// every datasource field; it is a different resource, so NotFound is the answer.
func TestStreamAnalyticsInput_ReadRejectsForeignDatasource(t *testing.T) {
	service := newSAInputService()
	service.seed("hubbie", armstreamanalytics.Input{Properties: &armstreamanalytics.StreamInputProperties{
		Type: to.Ptr("Stream"),
		Datasource: &armstreamanalytics.EventHubStreamInputDataSource{
			Type:       to.Ptr(streamAnalyticsEventHubDatasourceType),
			Properties: &armstreamanalytics.EventHubStreamInputDataSourceProperties{EventHubName: to.Ptr("h")},
		},
	}})

	prov := &StreamAnalyticsInput{api: service, kind: streamAnalyticsInputBlobKind}
	got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testSAInputNativeID("hubbie")})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

func TestStreamAnalyticsOutput_ListFiltersByDatasource(t *testing.T) {
	service := newSAOutputService()
	service.seed("blobbie", armstreamanalytics.Output{Properties: &armstreamanalytics.OutputProperties{
		Datasource: &armstreamanalytics.BlobOutputDataSource{
			Type:       to.Ptr(streamAnalyticsBlobDatasourceType),
			Properties: &armstreamanalytics.BlobOutputDataSourceProperties{Container: to.Ptr("c")},
		},
	}})
	service.seed("hubbie", armstreamanalytics.Output{Properties: &armstreamanalytics.OutputProperties{
		Datasource: &armstreamanalytics.EventHubOutputDataSource{
			Type:       to.Ptr(streamAnalyticsEventHubDatasourceType),
			Properties: &armstreamanalytics.EventHubOutputDataSourceProperties{EventHubName: to.Ptr("h")},
		},
	}})
	service.seed("queuey", armstreamanalytics.Output{Properties: &armstreamanalytics.OutputProperties{
		Datasource: &armstreamanalytics.ServiceBusQueueOutputDataSource{
			Type:       to.Ptr(streamAnalyticsServiceBusQueueDatasourceType),
			Properties: &armstreamanalytics.ServiceBusQueueOutputDataSourceProperties{QueueName: to.Ptr("q")},
		},
	}})
	service.seed("tabley", armstreamanalytics.Output{Properties: &armstreamanalytics.OutputProperties{
		Datasource: &armstreamanalytics.AzureTableOutputDataSource{
			Type:       to.Ptr(streamAnalyticsTableDatasourceType),
			Properties: &armstreamanalytics.AzureTableOutputDataSourceProperties{Table: to.Ptr("t")},
		},
	}})

	for _, tc := range []struct {
		kind streamAnalyticsOutputKind
		want string
	}{
		{streamAnalyticsOutputBlobKind, "blobbie"},
		{streamAnalyticsOutputEventHubKind, "hubbie"},
		{streamAnalyticsOutputServiceBusQueueKind, "queuey"},
		{streamAnalyticsOutputTableKind, "tabley"},
	} {
		t.Run(tc.kind.resourceType, func(t *testing.T) {
			prov := &StreamAnalyticsOutput{api: service, kind: tc.kind}
			got, err := prov.List(context.Background(), &resource.ListRequest{
				AdditionalProperties: map[string]string{
					"resourceGroupName": testSAJobResourceGroup,
					"jobName":           testSAJobName,
				},
			})
			require.NoError(t, err)
			require.Equal(t, []string{testSAOutputNativeID(tc.want)}, got.NativeIDs)
		})
	}
}

// Serialization is the one nested block shared by six of the seven input/output
// types, so it is round-tripped here rather than in each of them.
func TestStreamAnalyticsSerialization_RoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name    string
		desired map[string]any
		want    map[string]any
	}{
		{
			name:    "json",
			desired: map[string]any{"type": "Json", "encoding": "UTF8"},
			want:    map[string]any{"type": "Json", "encoding": "UTF8"},
		},
		{
			name:    "json_with_output_format",
			desired: map[string]any{"type": "Json", "encoding": "UTF8", "format": "LineSeparated"},
			want:    map[string]any{"type": "Json", "encoding": "UTF8", "format": "LineSeparated"},
		},
		{
			name:    "csv",
			desired: map[string]any{"type": "Csv", "encoding": "UTF8", "fieldDelimiter": ","},
			want:    map[string]any{"type": "Csv", "encoding": "UTF8", "fieldDelimiter": ","},
		},
		{
			// Avro takes no properties at all; emitting an invented encoding
			// would read as drift against a fixture that declared only the type.
			name:    "avro_has_no_properties",
			desired: map[string]any{"type": "Avro"},
			want:    map[string]any{"type": "Avro"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			built, err := saSerializationFromProps(map[string]any{"serialization": tc.desired})
			require.NoError(t, err)

			props := map[string]any{}
			saSerializeSerialization(built, props)

			got, err := json.Marshal(props["serialization"])
			require.NoError(t, err)
			want, err := json.Marshal(tc.want)
			require.NoError(t, err)
			require.JSONEq(t, string(want), string(got))
		})
	}
}

func TestStreamAnalyticsSerialization_Errors(t *testing.T) {
	_, err := saSerializationFromProps(map[string]any{})
	require.ErrorContains(t, err, "serialization is required")

	_, err = saSerializationFromProps(map[string]any{"serialization": map[string]any{}})
	require.ErrorContains(t, err, "serialization.type is required")

	_, err = saSerializationFromProps(map[string]any{"serialization": map[string]any{"type": "Protobuf"}})
	require.ErrorContains(t, err, "unsupported serialization.type")
}

// Delete is idempotent: a 404 means the goal is already achieved.
func TestStreamAnalyticsInput_DeleteNotFoundIsSuccess(t *testing.T) {
	service := newSAInputService()
	service.deleteErr = testSANotFound()
	prov := &StreamAnalyticsInput{api: service, kind: streamAnalyticsInputBlobKind}

	got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testSAInputNativeID("asainput")})
	require.NoError(t, err)
	require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
}

func TestStreamAnalyticsOutput_DeleteNotFoundIsSuccess(t *testing.T) {
	service := newSAOutputService()
	service.deleteErr = testSANotFound()
	prov := &StreamAnalyticsOutput{api: service, kind: streamAnalyticsOutputBlobKind}

	got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testSAOutputNativeID("asaoutput")})
	require.NoError(t, err)
	require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
}

// A provider error must carry its own text into StatusMessage, not just an
// opaque error code: 51 of this plugin's resources drop it and a failed create
// then logs a transition to Failed with no cause.
func TestStreamAnalyticsInput_FailureCarriesStatusMessage(t *testing.T) {
	service := newSAInputService()
	service.createErr = testSAConflict()
	prov := &StreamAnalyticsInput{api: service, kind: streamAnalyticsInputBlobKind}

	raw, err := json.Marshal(testSAInputBlobDesired("{date}/{time}"))
	require.NoError(t, err)
	got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: raw})
	require.NoError(t, err)
	require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	require.NotEmpty(t, got.ProgressResult.ErrorCode)
	require.NotEmpty(t, got.ProgressResult.StatusMessage)
}

func TestStreamAnalyticsOutput_FailureCarriesStatusMessage(t *testing.T) {
	service := newSAOutputService()
	service.createErr = testSAConflict()
	prov := &StreamAnalyticsOutput{api: service, kind: streamAnalyticsOutputTableKind}

	raw, err := json.Marshal(testSAOutputTableDesired(25))
	require.NoError(t, err)
	got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: raw})
	require.NoError(t, err)
	require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	require.NotEmpty(t, got.ProgressResult.ErrorCode)
	require.NotEmpty(t, got.ProgressResult.StatusMessage)
}

// Input and output operations are synchronous, so Status is only ever the
// passthrough that satisfies the Provisioner interface.
func TestStreamAnalyticsIO_StatusIsPassthrough(t *testing.T) {
	in := &StreamAnalyticsInput{api: newSAInputService(), kind: streamAnalyticsInputBlobKind}
	got, err := in.Status(context.Background(), &resource.StatusRequest{RequestID: "req-1"})
	require.NoError(t, err)
	require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	require.Equal(t, "req-1", got.ProgressResult.RequestID)

	out := &StreamAnalyticsOutput{api: newSAOutputService(), kind: streamAnalyticsOutputBlobKind}
	got, err = out.Status(context.Background(), &resource.StatusRequest{RequestID: "req-2"})
	require.NoError(t, err)
	require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	require.Equal(t, "req-2", got.ProgressResult.RequestID)
}
