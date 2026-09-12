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
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

// --- streaming job service simulator ----------------------------------------
//
// Unlike inputs and outputs, this one has to model ARM's default GET
// projection: a job's transformation comes back only when the caller asks for
// $expand=transformation. The plugin depends on that, so the fake enforces it.

type saJobService struct {
	stored     map[string]armstreamanalytics.StreamingJob
	sentCreate []armstreamanalytics.StreamingJob
	sentUpdate []armstreamanalytics.StreamingJob
	getExpands []string

	createErr error
	getErr    error
	updateErr error
	deleteErr error
}

func newSAJobService() *saJobService {
	return &saJobService{stored: map[string]armstreamanalytics.StreamingJob{}}
}

func (s *saJobService) seed(name string, job armstreamanalytics.StreamingJob) {
	stored := job
	stored.Name = to.Ptr(name)
	stored.ID = to.Ptr(testSAJobNativeID)
	s.stored[name] = stored
}

func (s *saJobService) BeginCreateOrReplace(_ context.Context, _, jobName string, job armstreamanalytics.StreamingJob, _ *armstreamanalytics.StreamingJobsClientBeginCreateOrReplaceOptions) (*runtime.Poller[armstreamanalytics.StreamingJobsClientCreateOrReplaceResponse], error) {
	if s.createErr != nil {
		return nil, s.createErr
	}
	s.sentCreate = append(s.sentCreate, job)
	s.seed(jobName, job)
	// ARM echoes the transformation it was given on a PUT.
	return newDonePoller(armstreamanalytics.StreamingJobsClientCreateOrReplaceResponse{
		StreamingJob: s.stored[jobName],
	}), nil
}

// Get honours $expand: without it the transformation is withheld, exactly as
// ARM's default projection does.
func (s *saJobService) Get(_ context.Context, _, jobName string, options *armstreamanalytics.StreamingJobsClientGetOptions) (armstreamanalytics.StreamingJobsClientGetResponse, error) {
	expand := ""
	if options != nil && options.Expand != nil {
		expand = *options.Expand
	}
	s.getExpands = append(s.getExpands, expand)

	if s.getErr != nil {
		return armstreamanalytics.StreamingJobsClientGetResponse{}, s.getErr
	}
	stored, ok := s.stored[jobName]
	if !ok {
		return armstreamanalytics.StreamingJobsClientGetResponse{}, testSANotFound()
	}
	if expand != streamAnalyticsJobExpandTransformation && stored.Properties != nil {
		withheld := *stored.Properties
		withheld.Transformation = nil
		stored.Properties = &withheld
	}
	return armstreamanalytics.StreamingJobsClientGetResponse{StreamingJob: stored}, nil
}

// Update is a PATCH: it merges the body it is given and, like ARM, never
// returns a transformation.
func (s *saJobService) Update(_ context.Context, _, jobName string, job armstreamanalytics.StreamingJob, _ *armstreamanalytics.StreamingJobsClientUpdateOptions) (armstreamanalytics.StreamingJobsClientUpdateResponse, error) {
	if s.updateErr != nil {
		return armstreamanalytics.StreamingJobsClientUpdateResponse{}, s.updateErr
	}
	s.sentUpdate = append(s.sentUpdate, job)

	stored := s.stored[jobName]
	merged := *stored.Properties
	if patch := job.Properties; patch != nil {
		if patch.EventsLateArrivalMaxDelayInSeconds != nil {
			merged.EventsLateArrivalMaxDelayInSeconds = patch.EventsLateArrivalMaxDelayInSeconds
		}
		if patch.DataLocale != nil {
			merged.DataLocale = patch.DataLocale
		}
		if patch.OutputErrorPolicy != nil {
			merged.OutputErrorPolicy = patch.OutputErrorPolicy
		}
	}
	stored.Properties = &merged
	if job.Tags != nil {
		stored.Tags = job.Tags
	}
	s.stored[jobName] = stored

	response := stored
	withheld := merged
	withheld.Transformation = nil
	response.Properties = &withheld
	return armstreamanalytics.StreamingJobsClientUpdateResponse{StreamingJob: response}, nil
}

func (s *saJobService) BeginDelete(_ context.Context, _, jobName string, _ *armstreamanalytics.StreamingJobsClientBeginDeleteOptions) (*runtime.Poller[armstreamanalytics.StreamingJobsClientDeleteResponse], error) {
	if s.deleteErr != nil {
		return nil, s.deleteErr
	}
	delete(s.stored, jobName)
	return newDonePoller(armstreamanalytics.StreamingJobsClientDeleteResponse{}), nil
}

func (s *saJobService) NewListPager(_ *armstreamanalytics.StreamingJobsClientListOptions) *runtime.Pager[armstreamanalytics.StreamingJobsClientListResponse] {
	return runtime.NewPager(runtime.PagingHandler[armstreamanalytics.StreamingJobsClientListResponse]{
		More: func(_ armstreamanalytics.StreamingJobsClientListResponse) bool { return false },
		Fetcher: func(_ context.Context, _ *armstreamanalytics.StreamingJobsClientListResponse) (armstreamanalytics.StreamingJobsClientListResponse, error) {
			return armstreamanalytics.StreamingJobsClientListResponse{
				StreamingJobListResult: armstreamanalytics.StreamingJobListResult{Value: s.list()},
			}, nil
		},
	})
}

func (s *saJobService) NewListByResourceGroupPager(_ string, _ *armstreamanalytics.StreamingJobsClientListByResourceGroupOptions) *runtime.Pager[armstreamanalytics.StreamingJobsClientListByResourceGroupResponse] {
	return runtime.NewPager(runtime.PagingHandler[armstreamanalytics.StreamingJobsClientListByResourceGroupResponse]{
		More: func(_ armstreamanalytics.StreamingJobsClientListByResourceGroupResponse) bool { return false },
		Fetcher: func(_ context.Context, _ *armstreamanalytics.StreamingJobsClientListByResourceGroupResponse) (armstreamanalytics.StreamingJobsClientListByResourceGroupResponse, error) {
			return armstreamanalytics.StreamingJobsClientListByResourceGroupResponse{
				StreamingJobListResult: armstreamanalytics.StreamingJobListResult{Value: s.list()},
			}, nil
		},
	})
}

func (s *saJobService) list() []*armstreamanalytics.StreamingJob {
	names := make([]string, 0, len(s.stored))
	for name := range s.stored {
		names = append(names, name)
	}
	sort.Strings(names)
	values := make([]*armstreamanalytics.StreamingJob, 0, len(names))
	for _, name := range names {
		stored := s.stored[name]
		values = append(values, &stored)
	}
	return values
}

// --- tests ------------------------------------------------------------------

func newTestSAJob(api streamAnalyticsJobsAPI) *StreamAnalyticsStreamingJob {
	return &StreamAnalyticsStreamingJob{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func testSAJobDesired(lateArrival int) map[string]any {
	return map[string]any{
		"name":                               testSAJobName,
		"resourceGroupName":                  testSAJobResourceGroup,
		"location":                           "eastus",
		"sku":                                map[string]any{"name": "Standard"},
		"jobType":                            "Cloud",
		"compatibilityLevel":                 "1.2",
		"dataLocale":                         "en-US",
		"eventsLateArrivalMaxDelayInSeconds": lateArrival,
		"eventsOutOfOrderMaxDelayInSeconds":  0,
		"eventsOutOfOrderPolicy":             "Adjust",
		"outputErrorPolicy":                  "Stop",
		"transformation": map[string]any{
			"name":           "Transformation",
			"query":          "SELECT * INTO [asaoutput] FROM [asainput]",
			"streamingUnits": 3,
		},
	}
}

func TestStreamAnalyticsStreamingJob_CRUD(t *testing.T) {
	service := newSAJobService()
	prov := newTestSAJob(service)

	t.Run("Create", func(t *testing.T) {
		progress, props := saCreate(t, prov, testSAJobDesired(5), testSAJobName)
		require.Equal(t, testSAJobNativeID, progress.NativeID)

		sent := service.sentCreate[len(service.sentCreate)-1]
		require.Equal(t, "eastus", *sent.Location)
		require.Equal(t, armstreamanalytics.SKUNameStandard, *sent.Properties.SKU.Name)
		require.Equal(t, armstreamanalytics.JobTypeCloud, *sent.Properties.JobType)
		require.Equal(t, armstreamanalytics.CompatibilityLevelOne2, *sent.Properties.CompatibilityLevel)
		require.EqualValues(t, 5, *sent.Properties.EventsLateArrivalMaxDelayInSeconds)
		// The transformation is only settable through the job's own PUT body.
		require.NotNil(t, sent.Properties.Transformation)
		require.Equal(t, "Transformation", *sent.Properties.Transformation.Name)
		require.Equal(t, "SELECT * INTO [asaoutput] FROM [asainput]", *sent.Properties.Transformation.Properties.Query)
		require.EqualValues(t, 3, *sent.Properties.Transformation.Properties.StreamingUnits)

		// No execution state is ever sent: Start/Stop is a separate verb pair and
		// the job must be left stopped.
		require.Nil(t, sent.Properties.OutputStartMode)
		require.Nil(t, sent.Properties.OutputStartTime)

		require.Equal(t, map[string]any{"name": "Standard"}, props["sku"])
		require.Equal(t, map[string]any{
			"name":           "Transformation",
			"query":          "SELECT * INTO [asaoutput] FROM [asainput]",
			"streamingUnits": float64(3),
		}, props["transformation"])
	})

	t.Run("Read_expands_transformation", func(t *testing.T) {
		before := len(service.getExpands)
		props := saRead(t, prov, testSAJobNativeID)
		// Without $expand ARM withholds the transformation and the query would
		// read as absent against a declared value.
		require.Equal(t, streamAnalyticsJobExpandTransformation, service.getExpands[before])

		require.Equal(t, testSAJobName, props["name"])
		require.Equal(t, testSAJobResourceGroup, props["resourceGroupName"])
		require.Equal(t, "eastus", props["location"])
		require.Equal(t, "Cloud", props["jobType"])
		require.Equal(t, "1.2", props["compatibilityLevel"])
		require.Equal(t, "en-US", props["dataLocale"])
		require.Equal(t, "Adjust", props["eventsOutOfOrderPolicy"])
		require.Equal(t, "Stop", props["outputErrorPolicy"])
		transformation := props["transformation"].(map[string]any)
		require.Equal(t, "SELECT * INTO [asaoutput] FROM [asainput]", transformation["query"])
	})

	// ARM's read-only status fields are never declarable, so serializing them
	// would report properties with no declared counterpart on every sync.
	t.Run("read_only_status_fields_never_serialized", func(t *testing.T) {
		service.seed(testSAJobName, armstreamanalytics.StreamingJob{
			Location: to.Ptr("East US"),
			Properties: &armstreamanalytics.StreamingJobProperties{
				SKU:               &armstreamanalytics.SKU{Name: to.Ptr(armstreamanalytics.SKUNameStandard)},
				JobID:             to.Ptr("11111111-2222-3333-4444-555555555555"),
				JobState:          to.Ptr("Created"),
				ProvisioningState: to.Ptr("Succeeded"),
				Etag:              to.Ptr("etag-1"),
				Transformation: &armstreamanalytics.Transformation{
					Name:       to.Ptr("Transformation"),
					Properties: &armstreamanalytics.TransformationProperties{Query: to.Ptr("SELECT 1")},
				},
			},
		})
		props := saRead(t, prov, testSAJobNativeID)
		for _, key := range []string{"jobId", "jobState", "provisioningState", "etag", "createdDate", "lastOutputEventTime"} {
			require.NotContains(t, props, key)
		}
		// ARM hands back "East US"; read must fold it or desired state drifts.
		require.Equal(t, "eastus", props["location"])
	})

	t.Run("Update_is_synchronous_and_omits_transformation", func(t *testing.T) {
		// Re-seed the full job so the PATCH has something to merge into.
		_, _ = saCreate(t, prov, testSAJobDesired(5), testSAJobName)

		raw, err := json.Marshal(testSAJobDesired(10))
		require.NoError(t, err)
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testSAJobNativeID,
			DesiredProperties: raw,
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Empty(t, got.ProgressResult.RequestID)

		// ARM rejects a PATCH carrying a transformation, so it must not be sent
		// even though desired state has one.
		patch := service.sentUpdate[len(service.sentUpdate)-1]
		require.Nil(t, patch.Properties.Transformation)
		require.Nil(t, patch.Location)
		require.EqualValues(t, 10, *patch.Properties.EventsLateArrivalMaxDelayInSeconds)

		// The PATCH response carries no transformation, so the update path has to
		// re-Get with $expand or the query would vanish from state.
		var props map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &props))
		require.EqualValues(t, 10, props["eventsLateArrivalMaxDelayInSeconds"])
		transformation, ok := props["transformation"].(map[string]any)
		require.True(t, ok, "update must not drop the transformation from state")
		require.Equal(t, "SELECT * INTO [asaoutput] FROM [asainput]", transformation["query"])
	})

	t.Run("Delete", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testSAJobNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		service.deleteErr = testSANotFound()
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testSAJobNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		service.deleteErr = nil
	})
}

func TestStreamAnalyticsStreamingJob_CreateRequiresFields(t *testing.T) {
	prov := newTestSAJob(newSAJobService())

	for _, tc := range []struct {
		missing string
		wantErr string
	}{
		{"resourceGroupName", "resourceGroupName is required"},
		{"location", "location is required"},
		{"sku", "sku.name is required"},
		{"transformation", "transformation.query is required"},
	} {
		t.Run(tc.missing, func(t *testing.T) {
			desired := testSAJobDesired(5)
			delete(desired, tc.missing)
			raw, err := json.Marshal(desired)
			require.NoError(t, err)
			_, err = prov.Create(context.Background(), &resource.CreateRequest{Label: testSAJobName, Properties: raw})
			require.ErrorContains(t, err, tc.wantErr)
		})
	}
}

func TestStreamAnalyticsStreamingJob_ReadNotFound(t *testing.T) {
	service := newSAJobService()
	service.getErr = testSANotFound()
	got, err := newTestSAJob(service).Read(context.Background(), &resource.ReadRequest{NativeID: testSAJobNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

func TestStreamAnalyticsStreamingJob_FailureCarriesStatusMessage(t *testing.T) {
	service := newSAJobService()
	service.createErr = testSAConflict()
	prov := newTestSAJob(service)

	raw, err := json.Marshal(testSAJobDesired(5))
	require.NoError(t, err)
	got, err := prov.Create(context.Background(), &resource.CreateRequest{Label: testSAJobName, Properties: raw})
	require.NoError(t, err)
	require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	require.NotEmpty(t, got.ProgressResult.ErrorCode)
	require.NotEmpty(t, got.ProgressResult.StatusMessage)
}

func TestStreamAnalyticsStreamingJob_Tags(t *testing.T) {
	service := newSAJobService()
	prov := newTestSAJob(service)

	desired := testSAJobDesired(5)
	desired["Tags"] = []any{map[string]any{"Key": "owner", "Value": "conformance"}}
	_, props := saCreate(t, prov, desired, testSAJobName)

	sent := service.sentCreate[len(service.sentCreate)-1]
	require.Equal(t, "conformance", *sent.Tags["owner"])
	require.Equal(t, []any{map[string]any{"Key": "owner", "Value": "conformance"}}, props["Tags"])
}

func TestStreamAnalyticsStreamingJob_List(t *testing.T) {
	service := newSAJobService()
	prov := newTestSAJob(service)
	_, _ = saCreate(t, prov, testSAJobDesired(5), testSAJobName)

	t.Run("by_resource_group", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": testSAJobResourceGroup},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testSAJobNativeID}, got.NativeIDs)
	})

	// Discovery supplies resourceGroupName from the parent resource group, but an
	// empty scope must still enumerate rather than build a blank-scope pager.
	t.Run("without_group_is_subscription_wide", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Equal(t, []string{testSAJobNativeID}, got.NativeIDs)
	})
}
