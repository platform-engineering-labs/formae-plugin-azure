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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/operationalinsights/armoperationalinsights"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeLogAnalyticsLinkedService = "AZURE::OperationalInsights::LinkedService"

// logAnalyticsLinkedServicesAPI is the subset of
// *armoperationalinsights.LinkedServicesClient used here. Create and delete are
// both LROs, and BeginCreateOrUpdate is also the update verb — there is no PATCH.
type logAnalyticsLinkedServicesAPI interface {
	BeginCreateOrUpdate(ctx context.Context, resourceGroupName, workspaceName, linkedServiceName string, parameters armoperationalinsights.LinkedService, options *armoperationalinsights.LinkedServicesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armoperationalinsights.LinkedServicesClientCreateOrUpdateResponse], error)
	Get(ctx context.Context, resourceGroupName, workspaceName, linkedServiceName string, options *armoperationalinsights.LinkedServicesClientGetOptions) (armoperationalinsights.LinkedServicesClientGetResponse, error)
	BeginDelete(ctx context.Context, resourceGroupName, workspaceName, linkedServiceName string, options *armoperationalinsights.LinkedServicesClientBeginDeleteOptions) (*runtime.Poller[armoperationalinsights.LinkedServicesClientDeleteResponse], error)
	NewListByWorkspacePager(resourceGroupName, workspaceName string, options *armoperationalinsights.LinkedServicesClientListByWorkspaceOptions) *runtime.Pager[armoperationalinsights.LinkedServicesClientListByWorkspaceResponse]
}

// logAnalyticsLinkedServiceNames is the set ARM accepts as the resource's path
// segment. Like a linked storage account, the name is the link's kind, not a
// free-form name.
var logAnalyticsLinkedServiceNames = []string{"Automation", "Cluster"}

func init() {
	registry.Register(ResourceTypeLogAnalyticsLinkedService, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &LogAnalyticsLinkedService{
			api:      c.LogAnalyticsLinkedServicesClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// LogAnalyticsLinkedService is the provisioner for workspace links
// (`Microsoft.OperationalInsights/workspaces/<ws>/linkedServices/<name>`). It is a
// child of AZURE::OperationalInsights::Workspace, and binds the workspace to an
// Automation account (`Automation`) or to a dedicated Log Analytics cluster
// (`Cluster`).
type LogAnalyticsLinkedService struct {
	api      logAnalyticsLinkedServicesAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

// logAnalyticsLinkedServiceProps mirrors
// schema/pkl/operationalinsights/loganalyticslinkedservice.pkl.
type logAnalyticsLinkedServiceProps struct {
	Name                  string  `json:"name"`
	ResourceGroupName     string  `json:"resourceGroupName"`
	WorkspaceName         string  `json:"workspaceName"`
	ResourceID            *string `json:"resourceId"`
	WriteAccessResourceID *string `json:"writeAccessResourceId"`
}

func logAnalyticsLinkedServiceIDParts(resourceID string) (rgName, workspaceName, serviceName string, err error) {
	rgName, names, err := armIDParts(resourceID, "workspaces", "linkedservices")
	if err != nil {
		return "", "", "", err
	}
	// ARM answers with the link kind lower-cased in the ID; desired state carries
	// the enum's own casing, so canonicalize or every sync drifts.
	return rgName, names["workspaces"], canonicalizeEnum(names["linkedservices"], logAnalyticsLinkedServiceNames...), nil
}

func (l *LogAnalyticsLinkedService) buildPropertiesFromResult(link *armoperationalinsights.LinkedService, rgName, workspaceName, serviceName string) map[string]any {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	props["workspaceName"] = workspaceName
	// ARM returns Name workspace-qualified ("TestLinkWS/Cluster"), which is not
	// what the schema declares, so the name comes from the ID's leaf instead.
	props["name"] = serviceName

	if link.ID != nil {
		props["id"] = *link.ID
	}

	if p := link.Properties; p != nil {
		if p.ResourceID != nil && *p.ResourceID != "" {
			props["resourceId"] = *p.ResourceID
		}
		if p.WriteAccessResourceID != nil && *p.WriteAccessResourceID != "" {
			props["writeAccessResourceId"] = *p.WriteAccessResourceID
		}
		// provisioningState is service state and is deliberately not surfaced.
	}

	return props
}

func (l *LogAnalyticsLinkedService) parseProps(payload json.RawMessage, label string) (logAnalyticsLinkedServiceProps, string, error) {
	var props logAnalyticsLinkedServiceProps
	if err := json.Unmarshal(payload, &props); err != nil {
		return props, "", fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return props, "", fmt.Errorf("resourceGroupName is required")
	}
	if props.WorkspaceName == "" {
		return props, "", fmt.Errorf("workspaceName is required")
	}
	// ARM rejects a link that points nowhere, and the two fields are the read-
	// access and write-access halves of the same choice.
	if (props.ResourceID == nil || *props.ResourceID == "") &&
		(props.WriteAccessResourceID == nil || *props.WriteAccessResourceID == "") {
		return props, "", fmt.Errorf("one of resourceId or writeAccessResourceId is required")
	}
	name := props.Name
	if name == "" {
		name = label
	}
	if name == "" {
		return props, "", fmt.Errorf("name is required")
	}
	return props, name, nil
}

func logAnalyticsLinkedServiceParams(props logAnalyticsLinkedServiceProps) armoperationalinsights.LinkedService {
	serviceProps := &armoperationalinsights.LinkedServiceProperties{}
	if props.ResourceID != nil && *props.ResourceID != "" {
		serviceProps.ResourceID = to.Ptr(*props.ResourceID)
	}
	if props.WriteAccessResourceID != nil && *props.WriteAccessResourceID != "" {
		serviceProps.WriteAccessResourceID = to.Ptr(*props.WriteAccessResourceID)
	}
	return armoperationalinsights.LinkedService{Properties: serviceProps}
}

func (l *LogAnalyticsLinkedService) completeFromLinkedService(link *armoperationalinsights.LinkedService, rgName, workspaceName, serviceName string) (string, json.RawMessage, error) {
	nativeID := ""
	if link.ID != nil {
		nativeID = *link.ID
		if rg, ws, name, err := logAnalyticsLinkedServiceIDParts(*link.ID); err == nil {
			rgName, workspaceName, serviceName = rg, ws, name
		}
	}
	propsJSON, err := json.Marshal(l.buildPropertiesFromResult(link, rgName, workspaceName, serviceName))
	if err != nil {
		return "", nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return nativeID, propsJSON, nil
}

func (l *LogAnalyticsLinkedService) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	props, name, err := l.parseProps(request.Properties, request.Label)
	if err != nil {
		return nil, err
	}

	poller, err := l.api.BeginCreateOrUpdate(ctx, props.ResourceGroupName, props.WorkspaceName, name,
		logAnalyticsLinkedServiceParams(props), nil)
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

	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.OperationalInsights/workspaces/%s/linkedServices/%s",
		l.config.SubscriptionId, props.ResourceGroupName, props.WorkspaceName, name)

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
		nativeID, propsJSON, err := l.completeFromLinkedService(&result.LinkedService,
			props.ResourceGroupName, props.WorkspaceName, name)
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

func (l *LogAnalyticsLinkedService) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, workspaceName, serviceName, err := logAnalyticsLinkedServiceIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := l.api.Get(ctx, rgName, workspaceName, serviceName, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(l.buildPropertiesFromResult(&result.LinkedService, rgName, workspaceName, serviceName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeLogAnalyticsLinkedService,
		Properties:   string(propsJSON),
	}, nil
}

// Update reissues BeginCreateOrUpdate: it is the API's only write verb. Only the
// link target can change — the kind is the resource's own address.
func (l *LogAnalyticsLinkedService) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, workspaceName, serviceName, err := logAnalyticsLinkedServiceIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	props, _, err := l.parseProps(request.DesiredProperties, serviceName)
	if err != nil {
		return nil, err
	}

	poller, err := l.api.BeginCreateOrUpdate(ctx, rgName, workspaceName, serviceName,
		logAnalyticsLinkedServiceParams(props), nil)
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

	if poller.Done() {
		result, err := poller.Result(ctx)
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
		propsJSON, err := json.Marshal(l.buildPropertiesFromResult(&result.LinkedService, rgName, workspaceName, serviceName))
		if err != nil {
			return nil, fmt.Errorf("failed to marshal response properties: %w", err)
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

func (l *LogAnalyticsLinkedService) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, workspaceName, serviceName, err := logAnalyticsLinkedServiceIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, err := l.api.BeginDelete(ctx, rgName, workspaceName, serviceName, nil)
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

func (l *LogAnalyticsLinkedService) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	reqID, err := decodeLROStatus(request.RequestID)
	if err != nil {
		return nil, err
	}

	switch reqID.OperationType {
	case lroOpCreate, lroOpUpdate:
		operation := resource.OperationCreate
		if reqID.OperationType == lroOpUpdate {
			operation = resource.OperationUpdate
		}
		return statusLRO(ctx, request, &reqID, operation,
			func(token string) (*runtime.Poller[armoperationalinsights.LinkedServicesClientCreateOrUpdateResponse], error) {
				return resumePoller[armoperationalinsights.LinkedServicesClientCreateOrUpdateResponse](l.pipeline, token)
			},
			func(_ context.Context, result armoperationalinsights.LinkedServicesClientCreateOrUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				rgName, workspaceName, serviceName, err := logAnalyticsLinkedServiceIDParts(reqID.NativeID)
				if err != nil {
					return "", nil, err
				}
				return l.completeFromLinkedService(&result.LinkedService, rgName, workspaceName, serviceName)
			})
	case lroOpDelete:
		return statusDeleteLRO(ctx, request, &reqID,
			func(token string) (*runtime.Poller[armoperationalinsights.LinkedServicesClientDeleteResponse], error) {
				return resumePoller[armoperationalinsights.LinkedServicesClientDeleteResponse](l.pipeline, token)
			}, nil)
	default:
		return nil, fmt.Errorf("unknown operation type: %s", reqID.OperationType)
	}
}

// List requires both the resource group and the workspace: links only exist inside
// one.
func (l *LogAnalyticsLinkedService) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	workspaceName := request.AdditionalProperties["workspaceName"]
	if rgName == "" || workspaceName == "" {
		return &resource.ListResult{}, nil
	}

	var nativeIDs []string
	pager := l.api.NewListByWorkspacePager(rgName, workspaceName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list linked services: %w", err)
		}
		for _, link := range page.Value {
			if link != nil && link.ID != nil {
				nativeIDs = append(nativeIDs, *link.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
