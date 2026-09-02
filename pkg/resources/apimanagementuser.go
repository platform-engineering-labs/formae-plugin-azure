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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/apimanagement/armapimanagement"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeApiManagementUser = "AZURE::ApiManagement::User"

// apiManagementUsersAPI is the armapimanagement surface used here. All
// synchronous, with ifMatch passed positionally on the PATCH and the delete.
type apiManagementUsersAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName string, serviceName string, userID string, parameters armapimanagement.UserCreateParameters, options *armapimanagement.UserClientCreateOrUpdateOptions) (armapimanagement.UserClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName string, serviceName string, userID string, options *armapimanagement.UserClientGetOptions) (armapimanagement.UserClientGetResponse, error)
	Update(ctx context.Context, resourceGroupName string, serviceName string, userID string, ifMatch string, parameters armapimanagement.UserUpdateParameters, options *armapimanagement.UserClientUpdateOptions) (armapimanagement.UserClientUpdateResponse, error)
	Delete(ctx context.Context, resourceGroupName string, serviceName string, userID string, ifMatch string, options *armapimanagement.UserClientDeleteOptions) (armapimanagement.UserClientDeleteResponse, error)
	NewListByServicePager(resourceGroupName string, serviceName string, options *armapimanagement.UserClientListByServiceOptions) *runtime.Pager[armapimanagement.UserClientListByServiceResponse]
}

func init() {
	registry.Register(ResourceTypeApiManagementUser, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &ApiManagementUser{
			api:    c.ApiManagementUserClient,
			config: cfg,
		}
	})
}

// ApiManagementUser is the provisioner for developer accounts
// (Microsoft.ApiManagement/service/users).
//
// The Consumption tier has no user store, so this resource is only usable on a
// dedicated tier. See the schema for the doc reference.
type ApiManagementUser struct {
	api    apiManagementUsersAPI
	config *config.Config
}

// apiManagementUserProps mirrors
// schema/pkl/apimanagement/apimanagementuser.pkl.
type apiManagementUserProps struct {
	Name              string  `json:"name"`
	ResourceGroupName string  `json:"resourceGroupName"`
	ServiceName       string  `json:"serviceName"`
	Email             string  `json:"email"`
	FirstName         string  `json:"firstName"`
	LastName          string  `json:"lastName"`
	Note              *string `json:"note"`
	Password          string  `json:"password"`
	Confirmation      string  `json:"confirmation"`
	State             string  `json:"state"`
}

func apiManagementUserIDParts(resourceID string) (rgName, serviceName, userID string, err error) {
	rgName, names, err := armExactIDParts(resourceID, "service", "users")
	if err != nil {
		return "", "", "", err
	}
	return rgName, names[0], names[1], nil
}

func apiManagementUserState(state string) *armapimanagement.UserState {
	if state == "" {
		return nil
	}
	return to.Ptr(armapimanagement.UserState(state))
}

// buildPropertiesFromResult reports only the fields the schema declares.
//
// Two ARM-returned fields are deliberately dropped: `registrationDate`, which
// is the moment the account was created and changes on every recreate, and
// `groups`, which is the read-only mirror of every
// AZURE::ApiManagement::GroupUser pointing at this account and belongs to that
// resource rather than this one.
func (u *ApiManagementUser) buildPropertiesFromResult(user *armapimanagement.UserContract, rgName, serviceName string) map[string]any {
	props := map[string]any{
		"resourceGroupName": rgName,
		"serviceName":       serviceName,
	}
	if user.ID != nil {
		props["id"] = *user.ID
	}
	if user.Name != nil {
		props["name"] = *user.Name
	}
	if up := user.Properties; up != nil {
		if up.Email != nil {
			props["email"] = *up.Email
		}
		if up.FirstName != nil {
			props["firstName"] = *up.FirstName
		}
		if up.LastName != nil {
			props["lastName"] = *up.LastName
		}
		if up.Note != nil {
			props["note"] = *up.Note
		}
		if up.State != nil {
			props["state"] = canonicalizeEnum(string(*up.State), "active", "blocked", "deleted", "pending")
		}
	}
	return props
}

func (u *ApiManagementUser) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props apiManagementUserProps
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	if props.ServiceName == "" {
		return nil, fmt.Errorf("serviceName is required")
	}
	if props.Email == "" {
		return nil, fmt.Errorf("email is required")
	}
	if props.FirstName == "" {
		return nil, fmt.Errorf("firstName is required")
	}
	if props.LastName == "" {
		return nil, fmt.Errorf("lastName is required")
	}
	name := props.Name
	if name == "" {
		name = request.Label
	}
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}

	createProps := &armapimanagement.UserCreateParameterProperties{
		Email:     to.Ptr(props.Email),
		FirstName: to.Ptr(props.FirstName),
		LastName:  to.Ptr(props.LastName),
		Note:      props.Note,
		State:     apiManagementUserState(props.State),
	}
	if props.Password != "" {
		createProps.Password = to.Ptr(props.Password)
	}
	// Left nil when unset so ARM sends no mail at all. Sending one is opt-in:
	// an automated declaration should not email a stranger.
	if props.Confirmation != "" {
		createProps.Confirmation = to.Ptr(armapimanagement.Confirmation(props.Confirmation))
	}

	result, err := u.api.CreateOrUpdate(ctx, props.ResourceGroupName, props.ServiceName, name,
		armapimanagement.UserCreateParameters{Properties: createProps}, nil)
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

	nativeID := ""
	if result.ID != nil {
		nativeID = *result.ID
	}
	propsJSON, err := json.Marshal(u.buildPropertiesFromResult(&result.UserContract,
		props.ResourceGroupName, props.ServiceName))
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

func (u *ApiManagementUser) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, serviceName, userID, err := apiManagementUserIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := u.api.Get(ctx, rgName, serviceName, userID, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(u.buildPropertiesFromResult(&result.UserContract, rgName, serviceName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeApiManagementUser,
		Properties:   string(propsJSON),
	}, nil
}

// Update PATCHes. `confirmation` is createOnly and never sent here: there is no
// second account to confirm.
func (u *ApiManagementUser) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, serviceName, userID, err := apiManagementUserIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props apiManagementUserProps
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	updateProps := &armapimanagement.UserUpdateParametersProperties{
		Note:  props.Note,
		State: apiManagementUserState(props.State),
	}
	if props.Email != "" {
		updateProps.Email = to.Ptr(props.Email)
	}
	if props.FirstName != "" {
		updateProps.FirstName = to.Ptr(props.FirstName)
	}
	if props.LastName != "" {
		updateProps.LastName = to.Ptr(props.LastName)
	}
	if props.Password != "" {
		updateProps.Password = to.Ptr(props.Password)
	}

	result, err := u.api.Update(ctx, rgName, serviceName, userID, apimIfMatchAny,
		armapimanagement.UserUpdateParameters{Properties: updateProps}, nil)
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

	propsJSON, err := json.Marshal(u.buildPropertiesFromResult(&result.UserContract, rgName, serviceName))
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

// Delete drops the account's subscriptions with it and sends no closure email.
// Without deleteSubscriptions ARM refuses to delete an account that still owns
// one, and notify would mail a person about an automated teardown.
func (u *ApiManagementUser) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, serviceName, userID, err := apiManagementUserIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	opts := &armapimanagement.UserClientDeleteOptions{
		DeleteSubscriptions: to.Ptr(true),
		Notify:              to.Ptr(false),
	}
	if _, err := u.api.Delete(ctx, rgName, serviceName, userID, apimIfMatchAny, opts); err != nil &&
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

// Status is never reached with real work to do: user writes are synchronous.
func (u *ApiManagementUser) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

// List needs both the resource group and the service name: ARM has no
// subscription-wide listing of users.
func (u *ApiManagementUser) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	serviceName := request.AdditionalProperties["serviceName"]
	if rgName == "" || serviceName == "" {
		return &resource.ListResult{}, nil
	}

	var nativeIDs []string
	pager := u.api.NewListByServicePager(rgName, serviceName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list api management users: %w", err)
		}
		for _, user := range page.Value {
			if user.ID != nil {
				nativeIDs = append(nativeIDs, *user.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
