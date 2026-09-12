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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/apimanagement/armapimanagement"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeApiManagementSubscription = "AZURE::ApiManagement::Subscription"

// apiManagementSubscriptionsAPI is the armapimanagement surface used here. All
// synchronous, with ifMatch passed positionally on the PATCH and the delete.
//
// ListSecrets is deliberately NOT part of this interface: the two keys are
// write-only in the schema, so nothing reads them back.
type apiManagementSubscriptionsAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName string, serviceName string, sid string, parameters armapimanagement.SubscriptionCreateParameters, options *armapimanagement.SubscriptionClientCreateOrUpdateOptions) (armapimanagement.SubscriptionClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName string, serviceName string, sid string, options *armapimanagement.SubscriptionClientGetOptions) (armapimanagement.SubscriptionClientGetResponse, error)
	Update(ctx context.Context, resourceGroupName string, serviceName string, sid string, ifMatch string, parameters armapimanagement.SubscriptionUpdateParameters, options *armapimanagement.SubscriptionClientUpdateOptions) (armapimanagement.SubscriptionClientUpdateResponse, error)
	Delete(ctx context.Context, resourceGroupName string, serviceName string, sid string, ifMatch string, options *armapimanagement.SubscriptionClientDeleteOptions) (armapimanagement.SubscriptionClientDeleteResponse, error)
	NewListPager(resourceGroupName string, serviceName string, options *armapimanagement.SubscriptionClientListOptions) *runtime.Pager[armapimanagement.SubscriptionClientListResponse]
}

func init() {
	registry.Register(ResourceTypeApiManagementSubscription, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &ApiManagementSubscription{
			api:    c.ApiManagementSubscriptionClient,
			config: cfg,
		}
	})
}

// ApiManagementSubscription is the provisioner for subscriptions
// (Microsoft.ApiManagement/service/subscriptions) — the entity that issues the
// key pair a caller sends in Ocp-Apim-Subscription-Key.
//
// The Consumption tier has no subscription store, so this resource is only
// usable on a dedicated tier. See the schema for the doc reference.
type ApiManagementSubscription struct {
	api    apiManagementSubscriptionsAPI
	config *config.Config
}

// apiManagementSubscriptionProps mirrors
// schema/pkl/apimanagement/apimanagementsubscription.pkl.
type apiManagementSubscriptionProps struct {
	Name              string `json:"name"`
	ResourceGroupName string `json:"resourceGroupName"`
	ServiceName       string `json:"serviceName"`
	DisplayName       string `json:"displayName"`
	Scope             string `json:"scope"`
	OwnerID           string `json:"ownerId"`
	AllowTracing      *bool  `json:"allowTracing"`
	State             string `json:"state"`
	PrimaryKey        string `json:"primaryKey"`
	SecondaryKey      string `json:"secondaryKey"`
}

func apiManagementSubscriptionIDParts(resourceID string) (rgName, serviceName, sid string, err error) {
	rgName, names, err := armExactIDParts(resourceID, "service", "subscriptions")
	if err != nil {
		return "", "", "", err
	}
	return rgName, names[0], names[1], nil
}

func apiManagementSubscriptionState(state string) *armapimanagement.SubscriptionState {
	if state == "" {
		return nil
	}
	return to.Ptr(armapimanagement.SubscriptionState(state))
}

// apiManagementSubscriptionScope reports the scope the caller declared whenever
// it names the same thing ARM holds.
//
// ARM accepts a relative scope on the way in — "/apis", "/apis/{apiId}",
// "/products/{productId}" — and always answers with the absolute ARM id of the
// target. Passing that response straight through reports drift on every sync
// against a forma that used the relative form, so the declared value wins when
// ARM's absolute id ends with it. Anything else is a genuine repoint and ARM's
// own answer is reported.
func apiManagementSubscriptionScope(declared, actual string) string {
	if declared == "" {
		return actual
	}
	if declared == actual || strings.HasSuffix(actual, declared) {
		return declared
	}
	return actual
}

// apiManagementSubscriptionPriorScope digs the last-known scope out of
// ReadRequest.PriorProperties. Empty for a discovery read and for the read-back
// after a create, in which cases ARM's absolute id is all there is.
func apiManagementSubscriptionPriorScope(prior json.RawMessage) string {
	if len(prior) == 0 {
		return ""
	}
	var props apiManagementSubscriptionProps
	if err := json.Unmarshal(prior, &props); err != nil {
		return ""
	}
	return props.Scope
}

// buildPropertiesFromResult reports only what the schema declares.
//
// Dropped on purpose: primaryKey and secondaryKey, which ARM never fills on a
// Get and which are write-only here, and the five audit dates
// (createdDate, startDate, endDate, expirationDate, notificationDate), which
// the service maintains and which would read back as drift.
func (s *ApiManagementSubscription) buildPropertiesFromResult(sub *armapimanagement.SubscriptionContract, rgName, serviceName, declaredScope string) map[string]any {
	props := map[string]any{
		"resourceGroupName": rgName,
		"serviceName":       serviceName,
	}
	if sub.ID != nil {
		props["id"] = *sub.ID
	}
	if sub.Name != nil {
		props["name"] = *sub.Name
	}
	if sp := sub.Properties; sp != nil {
		if sp.DisplayName != nil {
			props["displayName"] = *sp.DisplayName
		}
		if sp.Scope != nil {
			props["scope"] = apiManagementSubscriptionScope(declaredScope, *sp.Scope)
		} else if declaredScope != "" {
			props["scope"] = declaredScope
		}
		if sp.OwnerID != nil {
			props["ownerId"] = *sp.OwnerID
		}
		if sp.AllowTracing != nil {
			props["allowTracing"] = *sp.AllowTracing
		}
		if sp.State != nil {
			props["state"] = canonicalizeEnum(string(*sp.State),
				"active", "suspended", "submitted", "rejected", "cancelled", "expired")
		}
	}
	return props
}

func (s *ApiManagementSubscription) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props apiManagementSubscriptionProps
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	if props.ServiceName == "" {
		return nil, fmt.Errorf("serviceName is required")
	}
	if props.DisplayName == "" {
		return nil, fmt.Errorf("displayName is required")
	}
	if props.Scope == "" {
		return nil, fmt.Errorf("scope is required")
	}
	name := props.Name
	if name == "" {
		name = request.Label
	}
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}

	createProps := &armapimanagement.SubscriptionCreateParameterProperties{
		DisplayName:  to.Ptr(props.DisplayName),
		Scope:        to.Ptr(props.Scope),
		AllowTracing: props.AllowTracing,
		State:        apiManagementSubscriptionState(props.State),
	}
	if props.OwnerID != "" {
		createProps.OwnerID = to.Ptr(props.OwnerID)
	}
	// Omitted keys are what makes ARM generate a random pair.
	if props.PrimaryKey != "" {
		createProps.PrimaryKey = to.Ptr(props.PrimaryKey)
	}
	if props.SecondaryKey != "" {
		createProps.SecondaryKey = to.Ptr(props.SecondaryKey)
	}

	// notify=false: a state change on an automatically declared subscription
	// should not email its owner.
	opts := &armapimanagement.SubscriptionClientCreateOrUpdateOptions{Notify: to.Ptr(false)}
	result, err := s.api.CreateOrUpdate(ctx, props.ResourceGroupName, props.ServiceName, name,
		armapimanagement.SubscriptionCreateParameters{Properties: createProps}, opts)
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
	propsJSON, err := json.Marshal(s.buildPropertiesFromResult(&result.SubscriptionContract,
		props.ResourceGroupName, props.ServiceName, props.Scope))
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

func (s *ApiManagementSubscription) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, serviceName, sid, err := apiManagementSubscriptionIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := s.api.Get(ctx, rgName, serviceName, sid, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(s.buildPropertiesFromResult(&result.SubscriptionContract,
		rgName, serviceName, apiManagementSubscriptionPriorScope(request.PriorProperties)))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeApiManagementSubscription,
		Properties:   string(propsJSON),
	}, nil
}

func (s *ApiManagementSubscription) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, serviceName, sid, err := apiManagementSubscriptionIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props apiManagementSubscriptionProps
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	updateProps := &armapimanagement.SubscriptionUpdateParameterProperties{
		AllowTracing: props.AllowTracing,
		State:        apiManagementSubscriptionState(props.State),
	}
	if props.DisplayName != "" {
		updateProps.DisplayName = to.Ptr(props.DisplayName)
	}
	if props.Scope != "" {
		updateProps.Scope = to.Ptr(props.Scope)
	}
	if props.OwnerID != "" {
		updateProps.OwnerID = to.Ptr(props.OwnerID)
	}
	if props.PrimaryKey != "" {
		updateProps.PrimaryKey = to.Ptr(props.PrimaryKey)
	}
	if props.SecondaryKey != "" {
		updateProps.SecondaryKey = to.Ptr(props.SecondaryKey)
	}

	result, err := s.api.Update(ctx, rgName, serviceName, sid, apimIfMatchAny,
		armapimanagement.SubscriptionUpdateParameters{Properties: updateProps}, nil)
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

	propsJSON, err := json.Marshal(s.buildPropertiesFromResult(&result.SubscriptionContract,
		rgName, serviceName, props.Scope))
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

func (s *ApiManagementSubscription) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, serviceName, sid, err := apiManagementSubscriptionIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	if _, err := s.api.Delete(ctx, rgName, serviceName, sid, apimIfMatchAny, nil); err != nil &&
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

// Status is never reached with real work to do: subscription writes are
// synchronous.
func (s *ApiManagementSubscription) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

// List needs both the resource group and the service name: ARM has no
// subscription-wide listing of API Management subscriptions.
func (s *ApiManagementSubscription) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	serviceName := request.AdditionalProperties["serviceName"]
	if rgName == "" || serviceName == "" {
		return &resource.ListResult{}, nil
	}

	var nativeIDs []string
	pager := s.api.NewListPager(rgName, serviceName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list api management subscriptions: %w", err)
		}
		for _, sub := range page.Value {
			if sub.ID != nil {
				nativeIDs = append(nativeIDs, *sub.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
