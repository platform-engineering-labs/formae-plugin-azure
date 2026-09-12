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

const ResourceTypeApiManagementApi = "AZURE::ApiManagement::Api"

// apiManagementAPIsAPI is the armapimanagement surface used here. The create is
// an LRO (ARM has to materialize a revision), while update and delete are
// synchronous and take ifMatch positionally rather than as an option.
type apiManagementAPIsAPI interface {
	BeginCreateOrUpdate(ctx context.Context, resourceGroupName string, serviceName string, apiID string, parameters armapimanagement.APICreateOrUpdateParameter, options *armapimanagement.APIClientBeginCreateOrUpdateOptions) (*runtime.Poller[armapimanagement.APIClientCreateOrUpdateResponse], error)
	Get(ctx context.Context, resourceGroupName string, serviceName string, apiID string, options *armapimanagement.APIClientGetOptions) (armapimanagement.APIClientGetResponse, error)
	Update(ctx context.Context, resourceGroupName string, serviceName string, apiID string, ifMatch string, parameters armapimanagement.APIUpdateContract, options *armapimanagement.APIClientUpdateOptions) (armapimanagement.APIClientUpdateResponse, error)
	Delete(ctx context.Context, resourceGroupName string, serviceName string, apiID string, ifMatch string, options *armapimanagement.APIClientDeleteOptions) (armapimanagement.APIClientDeleteResponse, error)
	NewListByServicePager(resourceGroupName string, serviceName string, options *armapimanagement.APIClientListByServiceOptions) *runtime.Pager[armapimanagement.APIClientListByServiceResponse]
}

func init() {
	registry.Register(ResourceTypeApiManagementApi, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &ApiManagementApi{
			api:      c.ApiManagementAPIClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// ApiManagementApi is the provisioner for API Management APIs
// (Microsoft.ApiManagement/service/apis).
type ApiManagementApi struct {
	api      apiManagementAPIsAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

// apiManagementApiProps mirrors schema/pkl/apimanagement/apimanagementapi.pkl.
type apiManagementApiProps struct {
	Name                      string   `json:"name"`
	ResourceGroupName         string   `json:"resourceGroupName"`
	ServiceName               string   `json:"serviceName"`
	DisplayName               string   `json:"displayName"`
	Path                      string   `json:"path"`
	Protocols                 []string `json:"protocols"`
	ServiceURL                *string  `json:"serviceUrl"`
	Description               *string  `json:"description"`
	APIType                   string   `json:"apiType"`
	APIRevision               *string  `json:"apiRevision"`
	APIVersion                *string  `json:"apiVersion"`
	APIVersionSetID           *string  `json:"apiVersionSetId"`
	IsCurrent                 *bool    `json:"isCurrent"`
	SubscriptionRequired      *bool    `json:"subscriptionRequired"`
	SubscriptionKeyHeaderName *string  `json:"subscriptionKeyHeaderName"`
	SubscriptionKeyQueryName  *string  `json:"subscriptionKeyQueryName"`
}

func apiManagementApiIDParts(resourceID string) (rgName, serviceName, apiID string, err error) {
	rgName, names, err := armExactIDParts(resourceID, "service", "apis")
	if err != nil {
		return "", "", "", err
	}
	return rgName, names[0], names[1], nil
}

func apiManagementProtocols(values []string) []*armapimanagement.Protocol {
	if len(values) == 0 {
		return nil
	}
	out := make([]*armapimanagement.Protocol, 0, len(values))
	for _, v := range values {
		out = append(out, to.Ptr(armapimanagement.Protocol(v)))
	}
	return out
}

// apiManagementSubscriptionKeyNames builds the nested block only when the
// caller named at least one of the two parameters, so an omitted pair lets ARM
// apply its own defaults instead of being overwritten with empty strings.
func apiManagementSubscriptionKeyNames(header, query *string) *armapimanagement.SubscriptionKeyParameterNamesContract {
	if header == nil && query == nil {
		return nil
	}
	return &armapimanagement.SubscriptionKeyParameterNamesContract{
		Header: header,
		Query:  query,
	}
}

func (a *ApiManagementApi) buildPropertiesFromResult(api *armapimanagement.APIContract, rgName, serviceName string) map[string]any {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	props["serviceName"] = serviceName

	if api.ID != nil {
		props["id"] = *api.ID
	}
	if api.Name != nil {
		props["name"] = *api.Name
	}

	if p := api.Properties; p != nil {
		if p.DisplayName != nil {
			props["displayName"] = *p.DisplayName
		}
		if p.Path != nil {
			props["path"] = *p.Path
		}
		if len(p.Protocols) > 0 {
			protocols := make([]string, 0, len(p.Protocols))
			for _, proto := range p.Protocols {
				if proto != nil {
					protocols = append(protocols, string(*proto))
				}
			}
			props["protocols"] = protocols
		}
		if p.ServiceURL != nil {
			props["serviceUrl"] = *p.ServiceURL
		}
		if p.Description != nil {
			props["description"] = *p.Description
		}
		if p.APIType != nil {
			props["apiType"] = string(*p.APIType)
		}
		if p.APIRevision != nil {
			props["apiRevision"] = *p.APIRevision
		}
		if p.APIVersion != nil {
			props["apiVersion"] = *p.APIVersion
		}
		if p.APIVersionSetID != nil {
			props["apiVersionSetId"] = *p.APIVersionSetID
		}
		if p.IsCurrent != nil {
			props["isCurrent"] = *p.IsCurrent
		}
		if p.SubscriptionRequired != nil {
			props["subscriptionRequired"] = *p.SubscriptionRequired
		}
		if k := p.SubscriptionKeyParameterNames; k != nil {
			if k.Header != nil {
				props["subscriptionKeyHeaderName"] = *k.Header
			}
			if k.Query != nil {
				props["subscriptionKeyQueryName"] = *k.Query
			}
		}
		// apiVersionSet (the expanded copy of the version set that ARM echoes
		// alongside apiVersionSetId), sourceApiId, isOnline, contact, license
		// and the authentication settings are deliberately dropped: the
		// expanded copy duplicates a property already reported, and the rest
		// are either service state or not modelled by this resource.
	}

	return props
}

func (a *ApiManagementApi) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props apiManagementApiProps
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
	if props.Path == "" {
		return nil, fmt.Errorf("path is required")
	}
	if len(props.Protocols) == 0 {
		return nil, fmt.Errorf("protocols is required")
	}
	name := props.Name
	if name == "" {
		name = request.Label
	}
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}

	createProps := &armapimanagement.APICreateOrUpdateProperties{
		DisplayName:                   to.Ptr(props.DisplayName),
		Path:                          to.Ptr(props.Path),
		Protocols:                     apiManagementProtocols(props.Protocols),
		ServiceURL:                    props.ServiceURL,
		Description:                   props.Description,
		APIRevision:                   props.APIRevision,
		APIVersion:                    props.APIVersion,
		APIVersionSetID:               props.APIVersionSetID,
		IsCurrent:                     props.IsCurrent,
		SubscriptionRequired:          props.SubscriptionRequired,
		SubscriptionKeyParameterNames: apiManagementSubscriptionKeyNames(props.SubscriptionKeyHeaderName, props.SubscriptionKeyQueryName),
	}
	if props.APIType != "" {
		createProps.APIType = to.Ptr(armapimanagement.APIType(props.APIType))
	}

	poller, err := a.api.BeginCreateOrUpdate(ctx, props.ResourceGroupName, props.ServiceName, name,
		armapimanagement.APICreateOrUpdateParameter{Properties: createProps}, nil)
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

	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.ApiManagement/service/%s/apis/%s",
		a.config.SubscriptionId, props.ResourceGroupName, props.ServiceName, name)

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
		nativeID, propsJSON, err := a.completeFromAPI(&result.APIContract)
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

func (a *ApiManagementApi) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, serviceName, apiID, err := apiManagementApiIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := a.api.Get(ctx, rgName, serviceName, apiID, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(a.buildPropertiesFromResult(&result.APIContract, rgName, serviceName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeApiManagementApi,
		Properties:   string(propsJSON),
	}, nil
}

// Update is a synchronous PATCH, so Status is never reached for an update.
func (a *ApiManagementApi) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, serviceName, apiID, err := apiManagementApiIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props apiManagementApiProps
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	updateProps := &armapimanagement.APIContractUpdateProperties{
		ServiceURL:                    props.ServiceURL,
		Description:                   props.Description,
		APIVersion:                    props.APIVersion,
		APIVersionSetID:               props.APIVersionSetID,
		SubscriptionRequired:          props.SubscriptionRequired,
		SubscriptionKeyParameterNames: apiManagementSubscriptionKeyNames(props.SubscriptionKeyHeaderName, props.SubscriptionKeyQueryName),
	}
	if props.DisplayName != "" {
		updateProps.DisplayName = to.Ptr(props.DisplayName)
	}
	if props.Path != "" {
		updateProps.Path = to.Ptr(props.Path)
	}
	if len(props.Protocols) > 0 {
		updateProps.Protocols = apiManagementProtocols(props.Protocols)
	}

	result, err := a.api.Update(ctx, rgName, serviceName, apiID, apimIfMatchAny,
		armapimanagement.APIUpdateContract{Properties: updateProps}, nil)
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

	propsJSON, err := json.Marshal(a.buildPropertiesFromResult(&result.APIContract, rgName, serviceName))
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

func (a *ApiManagementApi) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, serviceName, apiID, err := apiManagementApiIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	if _, err := a.api.Delete(ctx, rgName, serviceName, apiID, apimIfMatchAny, nil); err != nil && !isDeleteSuccessError(err) {
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

// Status only ever handles the create: update and delete are synchronous.
func (a *ApiManagementApi) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	reqID, err := decodeLROStatus(request.RequestID)
	if err != nil {
		return nil, err
	}

	switch reqID.OperationType {
	case lroOpCreate:
		return statusLRO(ctx, request, &reqID, resource.OperationCreate,
			func(token string) (*runtime.Poller[armapimanagement.APIClientCreateOrUpdateResponse], error) {
				return resumePoller[armapimanagement.APIClientCreateOrUpdateResponse](a.pipeline, token)
			},
			func(_ context.Context, result armapimanagement.APIClientCreateOrUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				return a.completeFromAPI(&result.APIContract)
			})
	default:
		return nil, fmt.Errorf("unknown operation type: %s", reqID.OperationType)
	}
}

func (a *ApiManagementApi) completeFromAPI(api *armapimanagement.APIContract) (string, json.RawMessage, error) {
	nativeID, rgName, serviceName := "", "", ""
	if api.ID != nil {
		nativeID = *api.ID
		if rg, svc, _, err := apiManagementApiIDParts(*api.ID); err == nil {
			rgName, serviceName = rg, svc
		}
	}
	propsJSON, err := json.Marshal(a.buildPropertiesFromResult(api, rgName, serviceName))
	if err != nil {
		return "", nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return nativeID, propsJSON, nil
}

// List needs both the resource group and the service name: ARM has no
// subscription-wide listing of APIs.
func (a *ApiManagementApi) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	serviceName := request.AdditionalProperties["serviceName"]
	if rgName == "" || serviceName == "" {
		return &resource.ListResult{}, nil
	}

	var nativeIDs []string
	pager := a.api.NewListByServicePager(rgName, serviceName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list api management apis: %w", err)
		}
		for _, api := range page.Value {
			if api.ID != nil {
				nativeIDs = append(nativeIDs, *api.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
