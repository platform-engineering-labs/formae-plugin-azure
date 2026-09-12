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

const ResourceTypeApiManagementService = "AZURE::ApiManagement::Service"

// apiManagementServicesAPI is the armapimanagement surface used here. Create,
// update and delete are all LROs — an API Management instance is a tenant, not
// a record — so all three go through Status.
type apiManagementServicesAPI interface {
	BeginCreateOrUpdate(ctx context.Context, resourceGroupName string, serviceName string, parameters armapimanagement.ServiceResource, options *armapimanagement.ServiceClientBeginCreateOrUpdateOptions) (*runtime.Poller[armapimanagement.ServiceClientCreateOrUpdateResponse], error)
	Get(ctx context.Context, resourceGroupName string, serviceName string, options *armapimanagement.ServiceClientGetOptions) (armapimanagement.ServiceClientGetResponse, error)
	BeginUpdate(ctx context.Context, resourceGroupName string, serviceName string, parameters armapimanagement.ServiceUpdateParameters, options *armapimanagement.ServiceClientBeginUpdateOptions) (*runtime.Poller[armapimanagement.ServiceClientUpdateResponse], error)
	BeginDelete(ctx context.Context, resourceGroupName string, serviceName string, options *armapimanagement.ServiceClientBeginDeleteOptions) (*runtime.Poller[armapimanagement.ServiceClientDeleteResponse], error)
	NewListPager(options *armapimanagement.ServiceClientListOptions) *runtime.Pager[armapimanagement.ServiceClientListResponse]
	NewListByResourceGroupPager(resourceGroupName string, options *armapimanagement.ServiceClientListByResourceGroupOptions) *runtime.Pager[armapimanagement.ServiceClientListByResourceGroupResponse]
}

func init() {
	registry.Register(ResourceTypeApiManagementService, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &ApiManagementService{
			api:      c.ApiManagementServiceClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// ApiManagementService is the provisioner for API Management instances
// (Microsoft.ApiManagement/service).
//
// It is the parent of every other resource in this namespace. Note that a
// delete only soft-deletes: the name stays reserved for 48 hours and is
// recoverable through the deleted-services API, which is deliberately not
// touched here because purging is irreversible.
type ApiManagementService struct {
	api      apiManagementServicesAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

// apiManagementServiceProps mirrors schema/pkl/apimanagement/apimanagementservice.pkl.
type apiManagementServiceProps struct {
	Name                    string  `json:"name"`
	Location                string  `json:"location"`
	ResourceGroupName       string  `json:"resourceGroupName"`
	PublisherEmail          string  `json:"publisherEmail"`
	PublisherName           string  `json:"publisherName"`
	SKUName                 string  `json:"skuName"`
	SKUCapacity             *int32  `json:"skuCapacity"`
	NotificationSenderEmail *string `json:"notificationSenderEmail"`
	PublicNetworkAccess     string  `json:"publicNetworkAccess"`
	VirtualNetworkType      string  `json:"virtualNetworkType"`
	IdentityType            string  `json:"identityType"`
}

func apiManagementServiceIDParts(resourceID string) (rgName, name string, err error) {
	rgName, names, err := armExactIDParts(resourceID, "service")
	if err != nil {
		return "", "", err
	}
	return rgName, names[0], nil
}

// apiManagementSKU builds the ARM sku block. Capacity is mandatory in the
// payload even for Consumption, where the only legal value is 0, so an omitted
// capacity is filled in from the tier rather than sent as null.
func apiManagementSKU(name string, capacity *int32) *armapimanagement.ServiceSKUProperties {
	if name == "" {
		return nil
	}
	units := int32(1)
	if name == string(armapimanagement.SKUTypeConsumption) {
		units = 0
	}
	if capacity != nil {
		units = *capacity
	}
	return &armapimanagement.ServiceSKUProperties{
		Name:     to.Ptr(armapimanagement.SKUType(name)),
		Capacity: to.Ptr(units),
	}
}

func apiManagementServiceIdentity(identityType string) *armapimanagement.ServiceIdentity {
	if identityType == "" {
		return nil
	}
	return &armapimanagement.ServiceIdentity{
		Type: to.Ptr(armapimanagement.ApimIdentityType(identityType)),
	}
}

func (s *ApiManagementService) buildPropertiesFromResult(svc *armapimanagement.ServiceResource, rgName string) map[string]any {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName

	if svc.ID != nil {
		props["id"] = *svc.ID
	}
	if svc.Name != nil {
		props["name"] = *svc.Name
	}
	if svc.Location != nil {
		props["location"] = normalizeAzureLocation(*svc.Location)
	}

	if sku := svc.SKU; sku != nil {
		if sku.Name != nil {
			props["skuName"] = canonicalizeEnum(string(*sku.Name),
				"Consumption", "Developer", "Basic", "Standard", "Premium")
		}
		if sku.Capacity != nil {
			props["skuCapacity"] = int(*sku.Capacity)
		}
	}

	if id := svc.Identity; id != nil {
		if id.Type != nil {
			props["identityType"] = string(*id.Type)
		}
		if id.PrincipalID != nil {
			props["principalId"] = *id.PrincipalID
		}
		if id.TenantID != nil {
			props["tenantId"] = *id.TenantID
		}
	}

	if p := svc.Properties; p != nil {
		if p.PublisherEmail != nil {
			props["publisherEmail"] = *p.PublisherEmail
		}
		if p.PublisherName != nil {
			props["publisherName"] = *p.PublisherName
		}
		if p.NotificationSenderEmail != nil {
			props["notificationSenderEmail"] = *p.NotificationSenderEmail
		}
		if p.PublicNetworkAccess != nil {
			props["publicNetworkAccess"] = canonicalizeEnum(string(*p.PublicNetworkAccess), "Enabled", "Disabled")
		}
		if p.VirtualNetworkType != nil {
			props["virtualNetworkType"] = canonicalizeEnum(string(*p.VirtualNetworkType), "None", "External", "Internal")
		}
		if p.GatewayURL != nil {
			props["gatewayUrl"] = *p.GatewayURL
		}
		if p.DeveloperPortalURL != nil {
			props["developerPortalUrl"] = *p.DeveloperPortalURL
		}
		if p.ManagementAPIURL != nil {
			props["managementApiUrl"] = *p.ManagementAPIURL
		}
		// provisioningState, targetProvisioningState, createdAtUtc,
		// platformVersion and the assigned IP addresses are deliberately
		// dropped: none of them is desired state, and the timestamps and
		// platform version move on their own.
		//
		// customProperties is dropped for a different reason — ARM
		// materializes the entire TLS/cipher set with defaults on any PATCH
		// that omits it, so reading it back would invite a partial
		// declaration that silently resets the rest.
	}

	if tags := azureTagsToFormaeTags(svc.Tags); tags != nil {
		props["Tags"] = tags
	}

	return props
}

func (s *ApiManagementService) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props apiManagementServiceProps
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	if props.Location == "" {
		return nil, fmt.Errorf("location is required")
	}
	if props.PublisherEmail == "" {
		return nil, fmt.Errorf("publisherEmail is required")
	}
	if props.PublisherName == "" {
		return nil, fmt.Errorf("publisherName is required")
	}
	if props.SKUName == "" {
		return nil, fmt.Errorf("skuName is required")
	}
	name := props.Name
	if name == "" {
		name = request.Label
	}
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}

	serviceProps := &armapimanagement.ServiceProperties{
		PublisherEmail:          to.Ptr(props.PublisherEmail),
		PublisherName:           to.Ptr(props.PublisherName),
		NotificationSenderEmail: props.NotificationSenderEmail,
	}
	if props.PublicNetworkAccess != "" {
		serviceProps.PublicNetworkAccess = to.Ptr(armapimanagement.PublicNetworkAccess(props.PublicNetworkAccess))
	}
	if props.VirtualNetworkType != "" {
		serviceProps.VirtualNetworkType = to.Ptr(armapimanagement.VirtualNetworkType(props.VirtualNetworkType))
	}

	params := armapimanagement.ServiceResource{
		Location:   to.Ptr(props.Location),
		SKU:        apiManagementSKU(props.SKUName, props.SKUCapacity),
		Identity:   apiManagementServiceIdentity(props.IdentityType),
		Properties: serviceProps,
	}
	if azureTags := formaeTagsToAzureTags(request.Properties); azureTags != nil {
		params.Tags = azureTags
	}

	poller, err := s.api.BeginCreateOrUpdate(ctx, props.ResourceGroupName, name, params, nil)
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

	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.ApiManagement/service/%s",
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
		nativeID, propsJSON, err := s.completeFromService(&result.ServiceResource)
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

func (s *ApiManagementService) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, name, err := apiManagementServiceIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := s.api.Get(ctx, rgName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(s.buildPropertiesFromResult(&result.ServiceResource, rgName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeApiManagementService,
		Properties:   string(propsJSON),
	}, nil
}

// Update is a PATCH, and an LRO like the create: changing the tier reprovisions
// the instance, so ARM answers 202 even for a retag.
func (s *ApiManagementService) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, name, err := apiManagementServiceIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props apiManagementServiceProps
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	updateProps := &armapimanagement.ServiceUpdateProperties{
		NotificationSenderEmail: props.NotificationSenderEmail,
	}
	if props.PublisherEmail != "" {
		updateProps.PublisherEmail = to.Ptr(props.PublisherEmail)
	}
	if props.PublisherName != "" {
		updateProps.PublisherName = to.Ptr(props.PublisherName)
	}
	if props.PublicNetworkAccess != "" {
		updateProps.PublicNetworkAccess = to.Ptr(armapimanagement.PublicNetworkAccess(props.PublicNetworkAccess))
	}

	params := armapimanagement.ServiceUpdateParameters{
		SKU:        apiManagementSKU(props.SKUName, props.SKUCapacity),
		Identity:   apiManagementServiceIdentity(props.IdentityType),
		Properties: updateProps,
	}
	if azureTags := formaeTagsToAzureTags(request.DesiredProperties); azureTags != nil {
		params.Tags = azureTags
	}

	poller, err := s.api.BeginUpdate(ctx, rgName, name, params, nil)
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
		propsJSON, err := json.Marshal(s.buildPropertiesFromResult(&result.ServiceResource, rgName))
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

// Delete soft-deletes the instance: the globally unique name stays reserved for
// 48 hours and the service is recoverable through the deleted-services API.
// Purging is not done here — it is irreversible.
func (s *ApiManagementService) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, name, err := apiManagementServiceIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, err := s.api.BeginDelete(ctx, rgName, name, nil)
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

func (s *ApiManagementService) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	reqID, err := decodeLROStatus(request.RequestID)
	if err != nil {
		return nil, err
	}

	switch reqID.OperationType {
	case lroOpCreate:
		return statusLRO(ctx, request, &reqID, resource.OperationCreate,
			func(token string) (*runtime.Poller[armapimanagement.ServiceClientCreateOrUpdateResponse], error) {
				return resumePoller[armapimanagement.ServiceClientCreateOrUpdateResponse](s.pipeline, token)
			},
			func(_ context.Context, result armapimanagement.ServiceClientCreateOrUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				return s.completeFromService(&result.ServiceResource)
			})
	case lroOpUpdate:
		return statusLRO(ctx, request, &reqID, resource.OperationUpdate,
			func(token string) (*runtime.Poller[armapimanagement.ServiceClientUpdateResponse], error) {
				return resumePoller[armapimanagement.ServiceClientUpdateResponse](s.pipeline, token)
			},
			func(_ context.Context, result armapimanagement.ServiceClientUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				return s.completeFromService(&result.ServiceResource)
			})
	case lroOpDelete:
		return statusDeleteLRO(ctx, request, &reqID,
			func(token string) (*runtime.Poller[armapimanagement.ServiceClientDeleteResponse], error) {
				return resumePoller[armapimanagement.ServiceClientDeleteResponse](s.pipeline, token)
			}, nil)
	default:
		return nil, fmt.Errorf("unknown operation type: %s", reqID.OperationType)
	}
}

func (s *ApiManagementService) completeFromService(svc *armapimanagement.ServiceResource) (string, json.RawMessage, error) {
	nativeID := ""
	rgName := ""
	if svc.ID != nil {
		nativeID = *svc.ID
		if rg, _, err := apiManagementServiceIDParts(*svc.ID); err == nil {
			rgName = rg
		}
	}
	propsJSON, err := json.Marshal(s.buildPropertiesFromResult(svc, rgName))
	if err != nil {
		return "", nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return nativeID, propsJSON, nil
}

func (s *ApiManagementService) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]

	var nativeIDs []string

	if rgName != "" {
		pager := s.api.NewListByResourceGroupPager(rgName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list api management services: %w", err)
			}
			for _, svc := range page.Value {
				if svc.ID != nil {
					nativeIDs = append(nativeIDs, *svc.ID)
				}
			}
		}
		return &resource.ListResult{NativeIDs: nativeIDs}, nil
	}

	pager := s.api.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list api management services: %w", err)
		}
		for _, svc := range page.Value {
			if svc.ID != nil {
				nativeIDs = append(nativeIDs, *svc.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
