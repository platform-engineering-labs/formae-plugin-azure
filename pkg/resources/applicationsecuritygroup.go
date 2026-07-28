// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v4"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeApplicationSecurityGroup = "AZURE::Network::ApplicationSecurityGroup"

// applicationSecurityGroupsAPI is the subset of
// *armnetwork.ApplicationSecurityGroupsClient used here. Create/update/delete
// are LROs.
type applicationSecurityGroupsAPI interface {
	BeginCreateOrUpdate(ctx context.Context, resourceGroupName string, applicationSecurityGroupName string, parameters armnetwork.ApplicationSecurityGroup, options *armnetwork.ApplicationSecurityGroupsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.ApplicationSecurityGroupsClientCreateOrUpdateResponse], error)
	Get(ctx context.Context, resourceGroupName string, applicationSecurityGroupName string, options *armnetwork.ApplicationSecurityGroupsClientGetOptions) (armnetwork.ApplicationSecurityGroupsClientGetResponse, error)
	BeginDelete(ctx context.Context, resourceGroupName string, applicationSecurityGroupName string, options *armnetwork.ApplicationSecurityGroupsClientBeginDeleteOptions) (*runtime.Poller[armnetwork.ApplicationSecurityGroupsClientDeleteResponse], error)
	NewListPager(resourceGroupName string, options *armnetwork.ApplicationSecurityGroupsClientListOptions) *runtime.Pager[armnetwork.ApplicationSecurityGroupsClientListResponse]
	NewListAllPager(options *armnetwork.ApplicationSecurityGroupsClientListAllOptions) *runtime.Pager[armnetwork.ApplicationSecurityGroupsClientListAllResponse]
}

func init() {
	registry.Register(ResourceTypeApplicationSecurityGroup, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &ApplicationSecurityGroup{
			api:      c.ApplicationSecurityGroupsClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// ApplicationSecurityGroup is the provisioner for Azure application security
// groups (`Microsoft.Network/applicationSecurityGroups/<name>`). The ARM body
// carries no writable properties beyond location and tags — an ASG is a named
// handle that NSG rules reference — so Update is a plain CreateOrUpdate upsert.
type ApplicationSecurityGroup struct {
	api      applicationSecurityGroupsAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

func serializeApplicationSecurityGroupProperties(result armnetwork.ApplicationSecurityGroup, rgName, name string) (json.RawMessage, error) {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	if result.Name != nil {
		props["name"] = *result.Name
	} else {
		props["name"] = name
	}
	if result.Location != nil {
		props["location"] = *result.Location
	}
	if result.ID != nil {
		props["id"] = *result.ID
	}
	if tags := azureTagsToFormaeTags(result.Tags); tags != nil {
		props["Tags"] = tags
	}

	return json.Marshal(props)
}

func applicationSecurityGroupParamsFromProperties(props map[string]any, rawProps json.RawMessage) (armnetwork.ApplicationSecurityGroup, error) {
	location, _ := props["location"].(string)
	if location == "" {
		return armnetwork.ApplicationSecurityGroup{}, fmt.Errorf("location is required")
	}
	asg := armnetwork.ApplicationSecurityGroup{Location: stringPtr(location)}
	if azureTags := formaeTagsToAzureTags(rawProps); azureTags != nil {
		asg.Tags = azureTags
	}
	return asg, nil
}

func applicationSecurityGroupIDParts(resourceID string) (rgName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "applicationsecuritygroups")
	if err != nil {
		return "", "", err
	}
	return rgName, names["applicationsecuritygroups"], nil
}

func (a *ApplicationSecurityGroup) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props map[string]any
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	rgName, _ := props["resourceGroupName"].(string)
	if rgName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	name, _ := props["name"].(string)
	if name == "" {
		name = request.Label
	}
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}

	params, err := applicationSecurityGroupParamsFromProperties(props, request.Properties)
	if err != nil {
		return nil, err
	}

	poller, err := a.api.BeginCreateOrUpdate(ctx, rgName, name, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	expectedID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/applicationSecurityGroups/%s",
		a.config.SubscriptionId, rgName, name)

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
		propsJSON, err := serializeApplicationSecurityGroupProperties(result.ApplicationSecurityGroup, rgName, name)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize ApplicationSecurityGroup properties: %w", err)
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

	token, err := poller.ResumeToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get resume token: %w", err)
	}
	reqID, err := encodeLROStart(lroOpCreate, token, expectedID)
	if err != nil {
		return nil, err
	}

	return &resource.CreateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationCreate,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       reqID,
			NativeID:        expectedID,
		},
	}, nil
}

func (a *ApplicationSecurityGroup) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, name, err := applicationSecurityGroupIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := a.api.Get(ctx, rgName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := serializeApplicationSecurityGroupProperties(result.ApplicationSecurityGroup, rgName, name)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize ApplicationSecurityGroup properties: %w", err)
	}

	return &resource.ReadResult{
		ResourceType: ResourceTypeApplicationSecurityGroup,
		Properties:   string(propsJSON),
	}, nil
}

func (a *ApplicationSecurityGroup) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, name, err := applicationSecurityGroupIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props map[string]any
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse desired properties: %w", err)
	}

	params, err := applicationSecurityGroupParamsFromProperties(props, request.DesiredProperties)
	if err != nil {
		return nil, err
	}

	poller, err := a.api.BeginCreateOrUpdate(ctx, rgName, name, params, nil)
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
		propsJSON, err := serializeApplicationSecurityGroupProperties(result.ApplicationSecurityGroup, rgName, name)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize ApplicationSecurityGroup properties: %w", err)
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

	token, err := poller.ResumeToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get resume token: %w", err)
	}
	reqID, err := encodeLROStart(lroOpUpdate, token, request.NativeID)
	if err != nil {
		return nil, err
	}

	return &resource.UpdateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationUpdate,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       reqID,
			NativeID:        request.NativeID,
		},
	}, nil
}

func (a *ApplicationSecurityGroup) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, name, err := applicationSecurityGroupIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, err := a.api.BeginDelete(ctx, rgName, name, nil)
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
			},
		}, fmt.Errorf("failed to delete ApplicationSecurityGroup: %w", err)
	}

	if poller.Done() {
		return &resource.DeleteResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationDelete,
				OperationStatus: resource.OperationStatusSuccess,
				NativeID:        request.NativeID,
			},
		}, nil
	}

	token, err := poller.ResumeToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get resume token: %w", err)
	}
	reqID, err := encodeLROStart(lroOpDelete, token, request.NativeID)
	if err != nil {
		return nil, err
	}

	return &resource.DeleteResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationDelete,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       reqID,
			NativeID:        request.NativeID,
		},
	}, nil
}

func (a *ApplicationSecurityGroup) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
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
	case lroOpCreate, lroOpUpdate:
		return a.statusCreateOrUpdate(ctx, request, &reqID)
	case lroOpDelete:
		return a.statusDelete(ctx, request, &reqID)
	default:
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
			},
		}, fmt.Errorf("unknown LRO operation type: %s", reqID.OperationType)
	}
}

func (a *ApplicationSecurityGroup) statusCreateOrUpdate(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	operation := resource.OperationCreate
	if reqID.OperationType == lroOpUpdate {
		operation = resource.OperationUpdate
	}

	return statusLRO(ctx, request, reqID, operation,
		func(token string) (*runtime.Poller[armnetwork.ApplicationSecurityGroupsClientCreateOrUpdateResponse], error) {
			return resumePoller[armnetwork.ApplicationSecurityGroupsClientCreateOrUpdateResponse](a.pipeline, token)
		},
		func(_ context.Context, result armnetwork.ApplicationSecurityGroupsClientCreateOrUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
			rgName, name, err := applicationSecurityGroupIDParts(*result.ID)
			if err != nil {
				return "", nil, err
			}
			propsJSON, err := serializeApplicationSecurityGroupProperties(result.ApplicationSecurityGroup, rgName, name)
			if err != nil {
				return "", nil, fmt.Errorf("failed to serialize ApplicationSecurityGroup properties: %w", err)
			}
			return *result.ID, propsJSON, nil
		})
}

func (a *ApplicationSecurityGroup) statusDelete(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	return statusDeleteLRO(ctx, request, reqID,
		func(token string) (*runtime.Poller[armnetwork.ApplicationSecurityGroupsClientDeleteResponse], error) {
			return resumePoller[armnetwork.ApplicationSecurityGroupsClientDeleteResponse](a.pipeline, token)
		}, nil)
}

func (a *ApplicationSecurityGroup) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]

	var nativeIDs []string
	if rgName != "" {
		pager := a.api.NewListPager(rgName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list application security groups in resource group %s: %w", rgName, err)
			}
			for _, asg := range page.Value {
				if asg.ID != nil {
					nativeIDs = append(nativeIDs, *asg.ID)
				}
			}
		}
		return &resource.ListResult{NativeIDs: nativeIDs}, nil
	}

	pager := a.api.NewListAllPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list application security groups: %w", err)
		}
		for _, asg := range page.Value {
			if asg.ID != nil {
				nativeIDs = append(nativeIDs, *asg.ID)
			}
		}
	}

	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
