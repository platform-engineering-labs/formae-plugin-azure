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

const ResourceTypeApiManagementApiRelease = "AZURE::ApiManagement::ApiRelease"

// apiManagementAPIReleasesAPI is the armapimanagement surface used here. All
// synchronous, with ifMatch passed positionally on the PATCH and the delete.
// Note that both the create and the update take the same APIReleaseContract.
type apiManagementAPIReleasesAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName string, serviceName string, apiID string, releaseID string, parameters armapimanagement.APIReleaseContract, options *armapimanagement.APIReleaseClientCreateOrUpdateOptions) (armapimanagement.APIReleaseClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName string, serviceName string, apiID string, releaseID string, options *armapimanagement.APIReleaseClientGetOptions) (armapimanagement.APIReleaseClientGetResponse, error)
	Update(ctx context.Context, resourceGroupName string, serviceName string, apiID string, releaseID string, ifMatch string, parameters armapimanagement.APIReleaseContract, options *armapimanagement.APIReleaseClientUpdateOptions) (armapimanagement.APIReleaseClientUpdateResponse, error)
	Delete(ctx context.Context, resourceGroupName string, serviceName string, apiID string, releaseID string, ifMatch string, options *armapimanagement.APIReleaseClientDeleteOptions) (armapimanagement.APIReleaseClientDeleteResponse, error)
	NewListByServicePager(resourceGroupName string, serviceName string, apiID string, options *armapimanagement.APIReleaseClientListByServiceOptions) *runtime.Pager[armapimanagement.APIReleaseClientListByServiceResponse]
}

func init() {
	registry.Register(ResourceTypeApiManagementApiRelease, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &ApiManagementApiRelease{
			api:    c.ApiManagementAPIReleaseClient,
			config: cfg,
		}
	})
}

// ApiManagementApiRelease is the provisioner for API releases
// (Microsoft.ApiManagement/service/apis/releases).
type ApiManagementApiRelease struct {
	api    apiManagementAPIReleasesAPI
	config *config.Config
}

// apiManagementApiReleaseProps mirrors
// schema/pkl/apimanagement/apimanagementapirelease.pkl.
type apiManagementApiReleaseProps struct {
	Name              string  `json:"name"`
	ResourceGroupName string  `json:"resourceGroupName"`
	ServiceName       string  `json:"serviceName"`
	APIName           string  `json:"apiName"`
	APIID             string  `json:"apiId"`
	Notes             *string `json:"notes"`
}

func apiManagementApiReleaseIDParts(resourceID string) (rgName, serviceName, apiID, releaseID string, err error) {
	rgName, names, err := armExactIDParts(resourceID, "service", "apis", "releases")
	if err != nil {
		return "", "", "", "", err
	}
	return rgName, names[0], names[1], names[2], nil
}

func (r *ApiManagementApiRelease) buildPropertiesFromResult(release *armapimanagement.APIReleaseContract, rgName, serviceName, apiID string) map[string]any {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	props["serviceName"] = serviceName
	props["apiName"] = apiID

	if release.ID != nil {
		props["id"] = *release.ID
	}
	if release.Name != nil {
		props["name"] = *release.Name
	}

	if p := release.Properties; p != nil {
		if p.APIID != nil {
			props["apiId"] = *p.APIID
		}
		if p.Notes != nil {
			props["notes"] = *p.Notes
		}
		// createdDateTime and updatedDateTime are deliberately dropped: they
		// move on their own and would read back as drift on every sync.
	}

	return props
}

func (r *ApiManagementApiRelease) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props apiManagementApiReleaseProps
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	if props.ServiceName == "" {
		return nil, fmt.Errorf("serviceName is required")
	}
	if props.APIName == "" {
		return nil, fmt.Errorf("apiName is required")
	}
	if props.APIID == "" {
		return nil, fmt.Errorf("apiId is required")
	}
	name := props.Name
	if name == "" {
		name = request.Label
	}
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}

	params := armapimanagement.APIReleaseContract{
		Properties: &armapimanagement.APIReleaseContractProperties{
			APIID: to.Ptr(props.APIID),
			Notes: props.Notes,
		},
	}

	result, err := r.api.CreateOrUpdate(ctx, props.ResourceGroupName, props.ServiceName, props.APIName, name, params, nil)
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
	propsJSON, err := json.Marshal(r.buildPropertiesFromResult(&result.APIReleaseContract,
		props.ResourceGroupName, props.ServiceName, props.APIName))
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

func (r *ApiManagementApiRelease) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, serviceName, apiID, releaseID, err := apiManagementApiReleaseIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := r.api.Get(ctx, rgName, serviceName, apiID, releaseID, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(r.buildPropertiesFromResult(&result.APIReleaseContract, rgName, serviceName, apiID))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeApiManagementApiRelease,
		Properties:   string(propsJSON),
	}, nil
}

func (r *ApiManagementApiRelease) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, serviceName, apiID, releaseID, err := apiManagementApiReleaseIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props apiManagementApiReleaseProps
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	updateProps := &armapimanagement.APIReleaseContractProperties{Notes: props.Notes}
	if props.APIID != "" {
		updateProps.APIID = to.Ptr(props.APIID)
	}

	result, err := r.api.Update(ctx, rgName, serviceName, apiID, releaseID, apimIfMatchAny,
		armapimanagement.APIReleaseContract{Properties: updateProps}, nil)
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

	propsJSON, err := json.Marshal(r.buildPropertiesFromResult(&result.APIReleaseContract, rgName, serviceName, apiID))
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

func (r *ApiManagementApiRelease) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, serviceName, apiID, releaseID, err := apiManagementApiReleaseIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	if _, err := r.api.Delete(ctx, rgName, serviceName, apiID, releaseID, apimIfMatchAny, nil); err != nil && !isDeleteSuccessError(err) {
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

// Status is never reached with real work to do: release writes are synchronous.
func (r *ApiManagementApiRelease) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

// List requires the resource group, the service and the API. The SDK calls the
// pager ListByService but it is scoped to a single API all the same.
func (r *ApiManagementApiRelease) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	serviceName := request.AdditionalProperties["serviceName"]
	apiName := request.AdditionalProperties["apiName"]
	if rgName == "" || serviceName == "" || apiName == "" {
		return &resource.ListResult{}, nil
	}

	var nativeIDs []string
	pager := r.api.NewListByServicePager(rgName, serviceName, apiName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list api management api releases: %w", err)
		}
		for _, release := range page.Value {
			if release.ID != nil {
				nativeIDs = append(nativeIDs, *release.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
