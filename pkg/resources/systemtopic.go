// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/eventgrid/armeventgrid"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeSystemTopic = "AZURE::EventGrid::SystemTopic"

type systemTopicsAPI interface {
	BeginCreateOrUpdate(ctx context.Context, resourceGroupName string, systemTopicName string, systemTopicInfo armeventgrid.SystemTopic, options *armeventgrid.SystemTopicsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armeventgrid.SystemTopicsClientCreateOrUpdateResponse], error)
	Get(ctx context.Context, resourceGroupName string, systemTopicName string, options *armeventgrid.SystemTopicsClientGetOptions) (armeventgrid.SystemTopicsClientGetResponse, error)
	BeginUpdate(ctx context.Context, resourceGroupName string, systemTopicName string, systemTopicUpdateParameters armeventgrid.SystemTopicUpdateParameters, options *armeventgrid.SystemTopicsClientBeginUpdateOptions) (*runtime.Poller[armeventgrid.SystemTopicsClientUpdateResponse], error)
	BeginDelete(ctx context.Context, resourceGroupName string, systemTopicName string, options *armeventgrid.SystemTopicsClientBeginDeleteOptions) (*runtime.Poller[armeventgrid.SystemTopicsClientDeleteResponse], error)
	NewListByResourceGroupPager(resourceGroupName string, options *armeventgrid.SystemTopicsClientListByResourceGroupOptions) *runtime.Pager[armeventgrid.SystemTopicsClientListByResourceGroupResponse]
}

func init() {
	registry.Register(ResourceTypeSystemTopic, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &SystemTopic{
			api:      c.EventGridSystemTopicsClient,
			config:   cfg,
			pipeline: c.Pipeline(),
		}
	})
}

// SystemTopic is the provisioner for Azure Event Grid System Topics.
type SystemTopic struct {
	api      systemTopicsAPI
	config   *config.Config
	pipeline runtime.Pipeline
}

func systemTopicIDParts(resourceID string) (rgName, topicName string, err error) {
	rgName, names, err := armIDParts(resourceID, "systemtopics")
	if err != nil {
		return "", "", err
	}
	return rgName, names["systemtopics"], nil
}

func serializeSystemTopicProperties(result armeventgrid.SystemTopic, rgName, topicName string) (json.RawMessage, error) {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	if result.Name != nil {
		props["name"] = *result.Name
	} else {
		props["name"] = topicName
	}

	if result.Location != nil {
		props["location"] = *result.Location
	}

	if result.Properties != nil {
		if result.Properties.Source != nil {
			props["source"] = *result.Properties.Source
		}
		if result.Properties.TopicType != nil {
			props["topicType"] = *result.Properties.TopicType
		}
	}

	if tags := azureTagsToFormaeTags(result.Tags); tags != nil {
		props["Tags"] = tags
	}

	if result.ID != nil {
		props["id"] = *result.ID
	}

	return json.Marshal(props)
}

func (st *SystemTopic) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props map[string]any
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	rgName, ok := props["resourceGroupName"].(string)
	if !ok || rgName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}

	location, ok := props["location"].(string)
	if !ok || location == "" {
		return nil, fmt.Errorf("location is required")
	}

	topicName, ok := props["name"].(string)
	if !ok || topicName == "" {
		topicName = request.Label
	}

	source, ok := props["source"].(string)
	if !ok || source == "" {
		return nil, fmt.Errorf("source is required")
	}

	topicType, ok := props["topicType"].(string)
	if !ok || topicType == "" {
		return nil, fmt.Errorf("topicType is required")
	}

	params := armeventgrid.SystemTopic{
		Location: stringPtr(location),
		Properties: &armeventgrid.SystemTopicProperties{
			Source:    stringPtr(source),
			TopicType: stringPtr(topicType),
		},
	}

	if azureTags := formaeTagsToAzureTags(request.Properties); azureTags != nil {
		params.Tags = azureTags
	}

	poller, err := st.api.BeginCreateOrUpdate(ctx, rgName, topicName, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.EventGrid/systemTopics/%s",
		st.config.SubscriptionId, rgName, topicName)

	if poller.Done() {
		result, err := poller.Result(ctx)
		if err != nil {
			return &resource.CreateResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationCreate,
					OperationStatus: resource.OperationStatusFailure,
					ErrorCode:       operationErrorCode(err),
				},
			}, nil
		}

		propsJSON, err := serializeSystemTopicProperties(result.SystemTopic, rgName, topicName)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize System Topic properties: %w", err)
		}

		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:          resource.OperationCreate,
				OperationStatus:    resource.OperationStatusSuccess,
				NativeID:           *result.ID,
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

func (st *SystemTopic) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, topicName, err := systemTopicIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := st.api.Get(ctx, rgName, topicName, nil)
	if err != nil {
		return &resource.ReadResult{
			ErrorCode: operationErrorCode(err),
		}, nil
	}

	propsJSON, err := serializeSystemTopicProperties(result.SystemTopic, rgName, topicName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize System Topic properties: %w", err)
	}

	return &resource.ReadResult{
		ResourceType: ResourceTypeSystemTopic,
		Properties:   string(propsJSON),
	}, nil
}

func (st *SystemTopic) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, topicName, err := systemTopicIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	params := armeventgrid.SystemTopicUpdateParameters{}
	if azureTags := formaeTagsToAzureTags(request.DesiredProperties); azureTags != nil {
		params.Tags = azureTags
	}

	poller, err := st.api.BeginUpdate(ctx, rgName, topicName, params, nil)
	if err != nil {
		return &resource.UpdateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationUpdate,
				OperationStatus: resource.OperationStatusFailure,
				NativeID:        request.NativeID,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	if poller.Done() {
		result, err := poller.Result(ctx)
		if err != nil {
			return &resource.UpdateResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationUpdate,
					OperationStatus: resource.OperationStatusFailure,
					NativeID:        request.NativeID,
					ErrorCode:       operationErrorCode(err),
				},
			}, nil
		}

		propsJSON, err := serializeSystemTopicProperties(result.SystemTopic, rgName, topicName)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize System Topic properties: %w", err)
		}

		return &resource.UpdateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:          resource.OperationUpdate,
				OperationStatus:    resource.OperationStatusSuccess,
				NativeID:           *result.ID,
				ResourceProperties: propsJSON,
			},
		}, nil
	}

	resumeToken, err := poller.ResumeToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get resume token: %w", err)
	}

	reqIDJSON, err := encodeLROStart(lroOpUpdate, resumeToken, request.NativeID)
	if err != nil {
		return nil, err
	}

	return &resource.UpdateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationUpdate,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       reqIDJSON,
			NativeID:        request.NativeID,
		},
	}, nil
}

func (st *SystemTopic) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, topicName, err := systemTopicIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, err := st.api.BeginDelete(ctx, rgName, topicName, nil)
	if err != nil {
		if operationErrorCode(err) == resource.OperationErrorCodeNotFound {
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
			},
		}, fmt.Errorf("failed to start System Topic deletion: %w", err)
	}

	if poller.Done() {
		if _, err := poller.Result(ctx); err != nil && !isDeleteSuccessError(err) {
			return &resource.DeleteResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationDelete,
					OperationStatus: resource.OperationStatusFailure,
					NativeID:        request.NativeID,
					ErrorCode:       operationErrorCode(err),
				},
			}, fmt.Errorf("failed to get System Topic delete result: %w", err)
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

func (st *SystemTopic) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	reqID, err := decodeLROStatus(request.RequestID)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
			},
		}, err
	}

	switch reqID.OperationType {
	case lroOpCreate:
		return st.statusCreate(ctx, request, &reqID)
	case lroOpUpdate:
		return st.statusUpdate(ctx, request, &reqID)
	case lroOpDelete:
		return st.statusDelete(ctx, request, &reqID)
	default:
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
			},
		}, fmt.Errorf("unexpected operation type: %s", reqID.OperationType)
	}
}

func (st *SystemTopic) statusCreate(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	return statusLRO(ctx, request, reqID, resource.OperationCreate,
		func(token string) (*runtime.Poller[armeventgrid.SystemTopicsClientCreateOrUpdateResponse], error) {
			return resumePoller[armeventgrid.SystemTopicsClientCreateOrUpdateResponse](st.pipeline, token)
		},
		func(_ context.Context, result armeventgrid.SystemTopicsClientCreateOrUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
			rgName, topicName, err := systemTopicIDParts(*result.ID)
			if err != nil {
				return "", nil, err
			}
			propsJSON, err := serializeSystemTopicProperties(result.SystemTopic, rgName, topicName)
			if err != nil {
				return "", nil, fmt.Errorf("failed to serialize System Topic properties: %w", err)
			}
			return *result.ID, propsJSON, nil
		})
}

func (st *SystemTopic) statusUpdate(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	return statusLRO(ctx, request, reqID, resource.OperationUpdate,
		func(token string) (*runtime.Poller[armeventgrid.SystemTopicsClientUpdateResponse], error) {
			return resumePoller[armeventgrid.SystemTopicsClientUpdateResponse](st.pipeline, token)
		},
		func(_ context.Context, result armeventgrid.SystemTopicsClientUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
			rgName, topicName, err := systemTopicIDParts(*result.ID)
			if err != nil {
				return "", nil, err
			}
			propsJSON, err := serializeSystemTopicProperties(result.SystemTopic, rgName, topicName)
			if err != nil {
				return "", nil, fmt.Errorf("failed to serialize System Topic properties: %w", err)
			}
			return *result.ID, propsJSON, nil
		})
}

func (st *SystemTopic) statusDelete(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	return statusDeleteLRO(ctx, request, reqID,
		func(token string) (*runtime.Poller[armeventgrid.SystemTopicsClientDeleteResponse], error) {
			return resumePoller[armeventgrid.SystemTopicsClientDeleteResponse](st.pipeline, token)
		}, nil)
}

func (st *SystemTopic) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	if rgName == "" {
		return nil, fmt.Errorf("resourceGroupName is required to list System Topics")
	}

	var nativeIDs []string

	pager := st.api.NewListByResourceGroupPager(rgName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list System Topics: %w", err)
		}
		for _, topic := range page.Value {
			if topic.ID != nil {
				nativeIDs = append(nativeIDs, *topic.ID)
			}
		}
	}

	return &resource.ListResult{
		NativeIDs: nativeIDs,
	}, nil
}
