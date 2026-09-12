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

const ResourceTypeStreamAnalyticsStreamingJob = "AZURE::StreamAnalytics::StreamingJob"

// streamAnalyticsJobExpandTransformation is the $expand value that makes GET
// return the job's transformation.
//
// ARM's default GET projection excludes `inputs`, `transformation`, `outputs` and
// `functions`. The first three of those are separate formae resource types and are
// deliberately left out, but the transformation is not: ARM requires a streaming
// job to carry one, there is no wired TransformationsClient to manage it as its own
// resource, and it can only be written through the job's own PUT body. So it is a
// field of the job here — and every read has to ask for it, or the query would come
// back absent and read as drift against the declared value.
const streamAnalyticsJobExpandTransformation = "transformation"

// streamAnalyticsJobsAPI is the armstreamanalytics.StreamingJobsClient surface
// used here. Mixed shape: create and delete are LROs, update is a synchronous
// PATCH.
//
// Start/Stop/Scale are deliberately absent. A job's execution state is a separate
// verb pair rather than a property — a running job cannot be reconciled into a
// stopped one by a PATCH — and a running job bills streaming units per hour, so
// this type provisions jobs and leaves them stopped.
type streamAnalyticsJobsAPI interface {
	BeginCreateOrReplace(ctx context.Context, resourceGroupName string, jobName string, streamingJob armstreamanalytics.StreamingJob, options *armstreamanalytics.StreamingJobsClientBeginCreateOrReplaceOptions) (*runtime.Poller[armstreamanalytics.StreamingJobsClientCreateOrReplaceResponse], error)
	Get(ctx context.Context, resourceGroupName string, jobName string, options *armstreamanalytics.StreamingJobsClientGetOptions) (armstreamanalytics.StreamingJobsClientGetResponse, error)
	Update(ctx context.Context, resourceGroupName string, jobName string, streamingJob armstreamanalytics.StreamingJob, options *armstreamanalytics.StreamingJobsClientUpdateOptions) (armstreamanalytics.StreamingJobsClientUpdateResponse, error)
	BeginDelete(ctx context.Context, resourceGroupName string, jobName string, options *armstreamanalytics.StreamingJobsClientBeginDeleteOptions) (*runtime.Poller[armstreamanalytics.StreamingJobsClientDeleteResponse], error)
	NewListPager(options *armstreamanalytics.StreamingJobsClientListOptions) *runtime.Pager[armstreamanalytics.StreamingJobsClientListResponse]
	NewListByResourceGroupPager(resourceGroupName string, options *armstreamanalytics.StreamingJobsClientListByResourceGroupOptions) *runtime.Pager[armstreamanalytics.StreamingJobsClientListByResourceGroupResponse]
}

func init() {
	registry.Register(ResourceTypeStreamAnalyticsStreamingJob, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &StreamAnalyticsStreamingJob{
			api:      c.StreamAnalyticsStreamingJobsClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// StreamAnalyticsStreamingJob is the provisioner for Azure Stream Analytics jobs
// (`Microsoft.StreamAnalytics/streamingjobs`).
//
// The read-only status fields ARM returns — jobId, jobState, provisioningState,
// createdDate, lastOutputEventTime, etag — are intentionally not serialized. None
// is declarable, and emitting them would make every sync report properties with no
// declared counterpart.
type StreamAnalyticsStreamingJob struct {
	api      streamAnalyticsJobsAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

// streamAnalyticsJobSKUProps mirrors the `sku` block in
// schema/pkl/streamanalytics/streamanalyticsjob.pkl.
type streamAnalyticsJobSKUProps struct {
	Name string `json:"name"`
}

// streamAnalyticsTransformationProps mirrors the `transformation` block. All three
// fields are required in the schema because ARM always returns all three, so an
// omitted one would come back populated and read as drift.
type streamAnalyticsTransformationProps struct {
	Name           string `json:"name"`
	Query          string `json:"query"`
	StreamingUnits *int32 `json:"streamingUnits"`
}

// streamAnalyticsJobProps mirrors schema/pkl/streamanalytics/streamanalyticsjob.pkl.
type streamAnalyticsJobProps struct {
	Name                               string                              `json:"name"`
	ResourceGroupName                  string                              `json:"resourceGroupName"`
	Location                           string                              `json:"location"`
	SKU                                *streamAnalyticsJobSKUProps         `json:"sku"`
	JobType                            string                              `json:"jobType"`
	Transformation                     *streamAnalyticsTransformationProps `json:"transformation"`
	CompatibilityLevel                 string                              `json:"compatibilityLevel"`
	DataLocale                         string                              `json:"dataLocale"`
	EventsLateArrivalMaxDelayInSeconds *int32                              `json:"eventsLateArrivalMaxDelayInSeconds"`
	EventsOutOfOrderMaxDelayInSeconds  *int32                              `json:"eventsOutOfOrderMaxDelayInSeconds"`
	EventsOutOfOrderPolicy             string                              `json:"eventsOutOfOrderPolicy"`
	OutputErrorPolicy                  string                              `json:"outputErrorPolicy"`
}

func streamAnalyticsJobIDParts(resourceID string) (rgName, jobName string, err error) {
	rgName, names, err := armIDParts(resourceID, "streamingjobs")
	if err != nil {
		return "", "", err
	}
	return rgName, names["streamingjobs"], nil
}

// streamAnalyticsJobPropertiesFromProps builds the ARM properties block. The
// transformation is included only when includeTransformation is set: PATCH cannot
// modify it (ARM rejects the attempt), so the update path leaves it out.
func streamAnalyticsJobPropertiesFromProps(props streamAnalyticsJobProps, includeTransformation bool) *armstreamanalytics.StreamingJobProperties {
	body := &armstreamanalytics.StreamingJobProperties{}
	if props.SKU != nil && props.SKU.Name != "" {
		body.SKU = &armstreamanalytics.SKU{Name: to.Ptr(armstreamanalytics.SKUName(props.SKU.Name))}
	}
	if props.JobType != "" {
		body.JobType = to.Ptr(armstreamanalytics.JobType(props.JobType))
	}
	if props.CompatibilityLevel != "" {
		body.CompatibilityLevel = to.Ptr(armstreamanalytics.CompatibilityLevel(props.CompatibilityLevel))
	}
	if props.DataLocale != "" {
		body.DataLocale = to.Ptr(props.DataLocale)
	}
	if props.EventsLateArrivalMaxDelayInSeconds != nil {
		body.EventsLateArrivalMaxDelayInSeconds = props.EventsLateArrivalMaxDelayInSeconds
	}
	if props.EventsOutOfOrderMaxDelayInSeconds != nil {
		body.EventsOutOfOrderMaxDelayInSeconds = props.EventsOutOfOrderMaxDelayInSeconds
	}
	if props.EventsOutOfOrderPolicy != "" {
		body.EventsOutOfOrderPolicy = to.Ptr(armstreamanalytics.EventsOutOfOrderPolicy(props.EventsOutOfOrderPolicy))
	}
	if props.OutputErrorPolicy != "" {
		body.OutputErrorPolicy = to.Ptr(armstreamanalytics.OutputErrorPolicy(props.OutputErrorPolicy))
	}
	if includeTransformation && props.Transformation != nil {
		transformation := &armstreamanalytics.Transformation{
			Properties: &armstreamanalytics.TransformationProperties{
				Query:          to.Ptr(props.Transformation.Query),
				StreamingUnits: props.Transformation.StreamingUnits,
			},
		}
		if props.Transformation.Name != "" {
			transformation.Name = to.Ptr(props.Transformation.Name)
		}
		body.Transformation = transformation
	}
	return body
}

// buildPropertiesFromResult serializes an ARM streaming job into formae resource
// properties. Inputs, outputs and functions are never emitted even when ARM
// includes them: each is its own formae resource type.
func (s *StreamAnalyticsStreamingJob) buildPropertiesFromResult(job *armstreamanalytics.StreamingJob, rgName string) map[string]any {
	props := make(map[string]any)
	props["resourceGroupName"] = rgName

	if job.ID != nil {
		props["id"] = *job.ID
	}
	if job.Name != nil {
		props["name"] = *job.Name
	}
	if job.Location != nil {
		props["location"] = normalizeAzureLocation(*job.Location)
	}

	if body := job.Properties; body != nil {
		if body.SKU != nil && body.SKU.Name != nil {
			props["sku"] = map[string]any{"name": canonicalizeEnum(string(*body.SKU.Name), "Standard")}
		}
		if body.JobType != nil {
			props["jobType"] = canonicalizeEnum(string(*body.JobType), "Cloud", "Edge")
		}
		if body.CompatibilityLevel != nil {
			props["compatibilityLevel"] = string(*body.CompatibilityLevel)
		}
		if body.DataLocale != nil {
			props["dataLocale"] = *body.DataLocale
		}
		if body.EventsLateArrivalMaxDelayInSeconds != nil {
			props["eventsLateArrivalMaxDelayInSeconds"] = *body.EventsLateArrivalMaxDelayInSeconds
		}
		if body.EventsOutOfOrderMaxDelayInSeconds != nil {
			props["eventsOutOfOrderMaxDelayInSeconds"] = *body.EventsOutOfOrderMaxDelayInSeconds
		}
		if body.EventsOutOfOrderPolicy != nil {
			props["eventsOutOfOrderPolicy"] = canonicalizeEnum(string(*body.EventsOutOfOrderPolicy), "Adjust", "Drop")
		}
		if body.OutputErrorPolicy != nil {
			props["outputErrorPolicy"] = canonicalizeEnum(string(*body.OutputErrorPolicy), "Drop", "Stop")
		}
		if t := body.Transformation; t != nil {
			transformation := make(map[string]any)
			if t.Name != nil {
				transformation["name"] = *t.Name
			}
			if t.Properties != nil {
				if t.Properties.Query != nil {
					transformation["query"] = *t.Properties.Query
				}
				if t.Properties.StreamingUnits != nil {
					transformation["streamingUnits"] = *t.Properties.StreamingUnits
				}
			}
			if len(transformation) > 0 {
				props["transformation"] = transformation
			}
		}
	}

	if tags := azureTagsToFormaeTags(job.Tags); tags != nil {
		props["Tags"] = tags
	}

	return props
}

// serializeWithTransformation serializes a job, falling back to a GET with
// $expand=transformation when the response in hand carries none.
//
// A PUT echoes the transformation it was given, but a PATCH response and the
// default GET projection do not, and a job whose transformation is missing from
// state reads as drift against the declared query. Asking ARM once is cheaper than
// getting that wrong.
func (s *StreamAnalyticsStreamingJob) serializeWithTransformation(ctx context.Context, job *armstreamanalytics.StreamingJob, rgName, jobName string) (json.RawMessage, error) {
	if job.Properties == nil || job.Properties.Transformation == nil {
		expanded, err := s.api.Get(ctx, rgName, jobName, &armstreamanalytics.StreamingJobsClientGetOptions{
			Expand: to.Ptr(streamAnalyticsJobExpandTransformation),
		})
		if err == nil {
			job = &expanded.StreamingJob
		}
	}
	propsJSON, err := json.Marshal(s.buildPropertiesFromResult(job, rgName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return propsJSON, nil
}

func (s *StreamAnalyticsStreamingJob) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props streamAnalyticsJobProps
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	if props.Location == "" {
		return nil, fmt.Errorf("location is required")
	}
	if props.SKU == nil || props.SKU.Name == "" {
		return nil, fmt.Errorf("sku.name is required")
	}
	if props.Transformation == nil || props.Transformation.Query == "" {
		return nil, fmt.Errorf("transformation.query is required")
	}
	name := props.Name
	if name == "" {
		name = request.Label
	}
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}

	params := armstreamanalytics.StreamingJob{
		Location:   to.Ptr(props.Location),
		Properties: streamAnalyticsJobPropertiesFromProps(props, true),
	}
	if azureTags := formaeTagsToAzureTags(request.Properties); azureTags != nil {
		params.Tags = azureTags
	}

	poller, err := s.api.BeginCreateOrReplace(ctx, props.ResourceGroupName, name, params, nil)
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

	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.StreamAnalytics/streamingjobs/%s",
		s.config.SubscriptionId, props.ResourceGroupName, name)

	if poller.Done() {
		result, err := poller.Result(ctx)
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
		nativeID, propsJSON, err := s.completeFromJob(ctx, &result.StreamingJob, expectedNativeID)
		if err != nil {
			return nil, err
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

	resumeToken, err := poller.ResumeToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get resume token: %w", err)
	}
	reqIDJSON, err := encodeLROStart(lroOpCreate, resumeToken, expectedNativeID)
	if err != nil {
		return nil, err
	}

	return &resource.CreateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationCreate,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       reqIDJSON,
			NativeID:        expectedNativeID,
		},
	}, nil
}

func (s *StreamAnalyticsStreamingJob) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, jobName, err := streamAnalyticsJobIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := s.api.Get(ctx, rgName, jobName, &armstreamanalytics.StreamingJobsClientGetOptions{
		Expand: to.Ptr(streamAnalyticsJobExpandTransformation),
	})
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(s.buildPropertiesFromResult(&result.StreamingJob, rgName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}

	return &resource.ReadResult{
		ResourceType: ResourceTypeStreamAnalyticsStreamingJob,
		Properties:   string(propsJSON),
	}, nil
}

// Update is a synchronous PATCH, so it never returns InProgress. sku, location and
// transformation are createOnly in the schema: ARM rejects a PATCH that carries a
// transformation, and there is no wired TransformationsClient to patch it through.
func (s *StreamAnalyticsStreamingJob) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, jobName, err := streamAnalyticsJobIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props streamAnalyticsJobProps
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	params := armstreamanalytics.StreamingJob{
		Properties: streamAnalyticsJobPropertiesFromProps(props, false),
	}
	if azureTags := formaeTagsToAzureTags(request.DesiredProperties); azureTags != nil {
		params.Tags = azureTags
	}

	result, err := s.api.Update(ctx, rgName, jobName, params, nil)
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

	propsJSON, err := s.serializeWithTransformation(ctx, &result.StreamingJob, rgName, jobName)
	if err != nil {
		return nil, err
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

func (s *StreamAnalyticsStreamingJob) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, jobName, err := streamAnalyticsJobIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, err := s.api.BeginDelete(ctx, rgName, jobName, nil)
	if err != nil {
		if isDeleteSuccessError(err) {
			return &resource.DeleteResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationDelete,
					OperationStatus: resource.OperationStatusSuccess,
					NativeID:        request.NativeID,
				},
			}, nil
		}
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

	if poller.Done() {
		if _, err := poller.Result(ctx); err != nil && !isDeleteSuccessError(err) {
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

	resumeToken, err := poller.ResumeToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get resume token: %w", err)
	}
	reqIDJSON, err := encodeLROStart(lroOpDelete, resumeToken, request.NativeID)
	if err != nil {
		return nil, err
	}

	return &resource.DeleteResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationDelete,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       reqIDJSON,
			NativeID:        request.NativeID,
		},
	}, nil
}

// Status resumes the create or delete LRO. Update is synchronous and never lands
// here.
func (s *StreamAnalyticsStreamingJob) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	reqID, err := decodeLROStatus(request.RequestID)
	if err != nil {
		return nil, err
	}

	switch reqID.OperationType {
	case lroOpCreate:
		return statusLRO(ctx, request, &reqID, resource.OperationCreate,
			func(token string) (*runtime.Poller[armstreamanalytics.StreamingJobsClientCreateOrReplaceResponse], error) {
				return resumePoller[armstreamanalytics.StreamingJobsClientCreateOrReplaceResponse](s.pipeline, token)
			},
			func(ctx context.Context, result armstreamanalytics.StreamingJobsClientCreateOrReplaceResponse, _ resource.Operation) (string, json.RawMessage, error) {
				return s.completeFromJob(ctx, &result.StreamingJob, reqID.NativeID)
			})
	case lroOpDelete:
		return statusDeleteLRO(ctx, request, &reqID,
			func(token string) (*runtime.Poller[armstreamanalytics.StreamingJobsClientDeleteResponse], error) {
				return resumePoller[armstreamanalytics.StreamingJobsClientDeleteResponse](s.pipeline, token)
			}, nil)
	default:
		return nil, fmt.Errorf("unknown operation type: %s", reqID.OperationType)
	}
}

// completeFromJob turns a finished create into a native ID plus properties.
// fallbackNativeID covers the case where ARM's response body omits the ID.
func (s *StreamAnalyticsStreamingJob) completeFromJob(ctx context.Context, job *armstreamanalytics.StreamingJob, fallbackNativeID string) (string, json.RawMessage, error) {
	nativeID := fallbackNativeID
	if job.ID != nil {
		nativeID = *job.ID
	}
	rgName, jobName, err := streamAnalyticsJobIDParts(nativeID)
	if err != nil {
		return "", nil, err
	}
	propsJSON, err := s.serializeWithTransformation(ctx, job, rgName, jobName)
	if err != nil {
		return "", nil, err
	}
	return nativeID, propsJSON, nil
}

func (s *StreamAnalyticsStreamingJob) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]

	var nativeIDs []string

	if rgName != "" {
		pager := s.api.NewListByResourceGroupPager(rgName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list stream analytics jobs: %w", err)
			}
			for _, job := range page.Value {
				if job != nil && job.ID != nil {
					nativeIDs = append(nativeIDs, *job.ID)
				}
			}
		}
		return &resource.ListResult{NativeIDs: nativeIDs}, nil
	}

	pager := s.api.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list stream analytics jobs: %w", err)
		}
		for _, job := range page.Value {
			if job != nil && job.ID != nil {
				nativeIDs = append(nativeIDs, *job.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
