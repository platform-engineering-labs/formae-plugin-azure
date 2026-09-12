// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/apimanagement/armapimanagement"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeApiManagementGroupUser = "AZURE::ApiManagement::GroupUser"

// apiManagementGroupUsersAPI is the armapimanagement surface used here.
//
// The write verb is Create rather than CreateOrUpdate, and like the other APIM
// links it takes no request body. There is no Get: CheckEntityExists is a HEAD
// answering with a bare bool. NewListPager hands back user contracts, whose ids
// are the users' own rather than the membership's, so the link id is composed.
type apiManagementGroupUsersAPI interface {
	Create(ctx context.Context, resourceGroupName string, serviceName string, groupID string, userID string, options *armapimanagement.GroupUserClientCreateOptions) (armapimanagement.GroupUserClientCreateResponse, error)
	CheckEntityExists(ctx context.Context, resourceGroupName string, serviceName string, groupID string, userID string, options *armapimanagement.GroupUserClientCheckEntityExistsOptions) (armapimanagement.GroupUserClientCheckEntityExistsResponse, error)
	Delete(ctx context.Context, resourceGroupName string, serviceName string, groupID string, userID string, options *armapimanagement.GroupUserClientDeleteOptions) (armapimanagement.GroupUserClientDeleteResponse, error)
	NewListPager(resourceGroupName string, serviceName string, groupID string, options *armapimanagement.GroupUserClientListOptions) *runtime.Pager[armapimanagement.GroupUserClientListResponse]
}

func init() {
	registry.Register(ResourceTypeApiManagementGroupUser, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &ApiManagementGroupUser{
			api:    c.ApiManagementGroupUserClient,
			config: cfg,
		}
	})
}

// ApiManagementGroupUser provisions the membership of one user in one group
// (Microsoft.ApiManagement/service/groups/users). It is a pure link: no
// properties beyond the names of the two ends.
//
// Neither end exists on the Consumption tier, so neither does this. See the
// schema for the doc reference.
type ApiManagementGroupUser struct {
	api    apiManagementGroupUsersAPI
	config *config.Config
}

// apiManagementGroupUserProps mirrors
// schema/pkl/apimanagement/apimanagementgroupuser.pkl.
type apiManagementGroupUserProps struct {
	ResourceGroupName string `json:"resourceGroupName"`
	ServiceName       string `json:"serviceName"`
	GroupName         string `json:"groupName"`
	UserName          string `json:"userName"`
}

func apiManagementGroupUserIDParts(resourceID string) (rgName, serviceName, groupID, userID string, err error) {
	rgName, names, err := armExactIDParts(resourceID, "service", "groups", "users")
	if err != nil {
		return "", "", "", "", err
	}
	return rgName, names[0], names[1], names[2], nil
}

func (l *ApiManagementGroupUser) nativeID(rgName, serviceName, groupID, userID string) string {
	return fmt.Sprintf(
		"/subscriptions/%s/resourceGroups/%s/providers/Microsoft.ApiManagement/service/%s/groups/%s/users/%s",
		l.config.SubscriptionId, rgName, serviceName, groupID, userID)
}

func apiManagementGroupUserProperties(rgName, serviceName, groupID, userID, nativeID string) map[string]any {
	props := map[string]any{
		"resourceGroupName": rgName,
		"serviceName":       serviceName,
		"groupName":         groupID,
		"userName":          userID,
	}
	if nativeID != "" {
		props["id"] = nativeID
	}
	return props
}

func (l *ApiManagementGroupUser) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props apiManagementGroupUserProps
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	if props.ServiceName == "" {
		return nil, fmt.Errorf("serviceName is required")
	}
	if props.GroupName == "" {
		return nil, fmt.Errorf("groupName is required")
	}
	if props.UserName == "" {
		return nil, fmt.Errorf("userName is required")
	}

	if _, err := l.api.Create(ctx, props.ResourceGroupName, props.ServiceName,
		props.GroupName, props.UserName, nil); err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
				StatusMessage:   err.Error(),
			},
		}, nil
	}

	nativeID := l.nativeID(props.ResourceGroupName, props.ServiceName, props.GroupName, props.UserName)
	propsJSON, err := json.Marshal(apiManagementGroupUserProperties(props.ResourceGroupName,
		props.ServiceName, props.GroupName, props.UserName, nativeID))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
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

// Read reports the membership's existence. A false answer from CheckEntityExists
// is a NotFound as far as formae is concerned, so an out-of-band removal from
// the group is seen as a deletion.
func (l *ApiManagementGroupUser) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, serviceName, groupID, userID, err := apiManagementGroupUserIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := l.api.CheckEntityExists(ctx, rgName, serviceName, groupID, userID, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}
	if !result.Success {
		return &resource.ReadResult{ErrorCode: resource.OperationErrorCodeNotFound}, nil
	}

	propsJSON, err := json.Marshal(apiManagementGroupUserProperties(rgName, serviceName,
		groupID, userID, request.NativeID))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeApiManagementGroupUser,
		Properties:   string(propsJSON),
	}, nil
}

// Update re-issues Create, which ARM treats as idempotent. Every field is
// createOnly, so formae replaces rather than updates when one changes; this
// exists so a reconcile of an unchanged membership is a no-op.
func (l *ApiManagementGroupUser) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, serviceName, groupID, userID, err := apiManagementGroupUserIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	if _, err := l.api.Create(ctx, rgName, serviceName, groupID, userID, nil); err != nil {
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

	propsJSON, err := json.Marshal(apiManagementGroupUserProperties(rgName, serviceName,
		groupID, userID, request.NativeID))
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

func (l *ApiManagementGroupUser) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, serviceName, groupID, userID, err := apiManagementGroupUserIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	if _, err := l.api.Delete(ctx, rgName, serviceName, groupID, userID, nil); err != nil &&
		!isDeleteSuccessError(err) {
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

// Status is never reached with real work to do: link writes are synchronous.
func (l *ApiManagementGroupUser) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

// List needs the resource group, the service and the group. The pager hands back
// user contracts, so each link id is composed from the user's name.
func (l *ApiManagementGroupUser) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	serviceName := request.AdditionalProperties["serviceName"]
	groupName := request.AdditionalProperties["groupName"]
	if rgName == "" || serviceName == "" || groupName == "" {
		return &resource.ListResult{}, nil
	}

	var nativeIDs []string
	pager := l.api.NewListPager(rgName, serviceName, groupName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list api management group users: %w", err)
		}
		for _, user := range page.Value {
			if user.Name == nil {
				continue
			}
			nativeIDs = append(nativeIDs, l.nativeID(rgName, serviceName, groupName, *user.Name))
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
