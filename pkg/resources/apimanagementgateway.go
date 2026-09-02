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

const ResourceTypeApiManagementGateway = "AZURE::ApiManagement::Gateway"

// apiManagementGatewaysAPI is the armapimanagement surface used here. All
// synchronous, with ifMatch passed positionally on the PATCH and the delete.
// ListKeys, RegenerateKey and GenerateToken are deliberately not part of this
// interface: the gateway keys are live credentials and never enter resource
// state.
type apiManagementGatewaysAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName string, serviceName string, gatewayID string, parameters armapimanagement.GatewayContract, options *armapimanagement.GatewayClientCreateOrUpdateOptions) (armapimanagement.GatewayClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName string, serviceName string, gatewayID string, options *armapimanagement.GatewayClientGetOptions) (armapimanagement.GatewayClientGetResponse, error)
	Update(ctx context.Context, resourceGroupName string, serviceName string, gatewayID string, ifMatch string, parameters armapimanagement.GatewayContract, options *armapimanagement.GatewayClientUpdateOptions) (armapimanagement.GatewayClientUpdateResponse, error)
	Delete(ctx context.Context, resourceGroupName string, serviceName string, gatewayID string, ifMatch string, options *armapimanagement.GatewayClientDeleteOptions) (armapimanagement.GatewayClientDeleteResponse, error)
	NewListByServicePager(resourceGroupName string, serviceName string, options *armapimanagement.GatewayClientListByServiceOptions) *runtime.Pager[armapimanagement.GatewayClientListByServiceResponse]
}

func init() {
	registry.Register(ResourceTypeApiManagementGateway, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &ApiManagementGateway{
			api:    c.ApiManagementGatewayClient,
			config: cfg,
		}
	})
}

// ApiManagementGateway is the provisioner for self-hosted gateway
// registrations (Microsoft.ApiManagement/service/gateways).
//
// Self-hosted gateways require the Developer or Premium tier. On Consumption —
// the tier the conformance fixtures use, because it is the only one that
// provisions inside a CI credential's lifetime — ARM rejects the create
// outright, so this type cannot be covered by a live conformance run against a
// Consumption instance.
//
// The gateway's keys are never serialized: ARM returns them only from a
// separate ListKeys call, so putting them in resource state would persist live
// credentials.
type ApiManagementGateway struct {
	api    apiManagementGatewaysAPI
	config *config.Config
}

// apiManagementGatewayProps mirrors
// schema/pkl/apimanagement/apimanagementgateway.pkl.
type apiManagementGatewayProps struct {
	Name                        string  `json:"name"`
	ResourceGroupName           string  `json:"resourceGroupName"`
	ServiceName                 string  `json:"serviceName"`
	LocationDataName            string  `json:"locationDataName"`
	LocationDataCity            *string `json:"locationDataCity"`
	LocationDataDistrict        *string `json:"locationDataDistrict"`
	LocationDataCountryOrRegion *string `json:"locationDataCountryOrRegion"`
	Description                 *string `json:"description"`
}

func apiManagementGatewayIDParts(resourceID string) (rgName, serviceName, gatewayID string, err error) {
	rgName, names, err := armExactIDParts(resourceID, "service", "gateways")
	if err != nil {
		return "", "", "", err
	}
	return rgName, names[0], names[1], nil
}

func (g *ApiManagementGateway) contract(props apiManagementGatewayProps) armapimanagement.GatewayContract {
	return armapimanagement.GatewayContract{
		Properties: &armapimanagement.GatewayContractProperties{
			Description: props.Description,
			LocationData: &armapimanagement.ResourceLocationDataContract{
				Name:            to.Ptr(props.LocationDataName),
				City:            props.LocationDataCity,
				District:        props.LocationDataDistrict,
				CountryOrRegion: props.LocationDataCountryOrRegion,
			},
		},
	}
}

func (g *ApiManagementGateway) buildPropertiesFromResult(gateway *armapimanagement.GatewayContract, rgName, serviceName string) map[string]any {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	props["serviceName"] = serviceName

	if gateway.ID != nil {
		props["id"] = *gateway.ID
	}
	if gateway.Name != nil {
		props["name"] = *gateway.Name
	}

	if p := gateway.Properties; p != nil {
		if p.Description != nil {
			props["description"] = *p.Description
		}
		if l := p.LocationData; l != nil {
			if l.Name != nil {
				props["locationDataName"] = *l.Name
			}
			if l.City != nil {
				props["locationDataCity"] = *l.City
			}
			if l.District != nil {
				props["locationDataDistrict"] = *l.District
			}
			if l.CountryOrRegion != nil {
				props["locationDataCountryOrRegion"] = *l.CountryOrRegion
			}
		}
	}

	return props
}

func (g *ApiManagementGateway) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props apiManagementGatewayProps
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	if props.ServiceName == "" {
		return nil, fmt.Errorf("serviceName is required")
	}
	if props.LocationDataName == "" {
		return nil, fmt.Errorf("locationDataName is required")
	}
	name := props.Name
	if name == "" {
		name = request.Label
	}
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}

	result, err := g.api.CreateOrUpdate(ctx, props.ResourceGroupName, props.ServiceName, name, g.contract(props), nil)
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
	propsJSON, err := json.Marshal(g.buildPropertiesFromResult(&result.GatewayContract,
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

func (g *ApiManagementGateway) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, serviceName, gatewayID, err := apiManagementGatewayIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := g.api.Get(ctx, rgName, serviceName, gatewayID, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(g.buildPropertiesFromResult(&result.GatewayContract, rgName, serviceName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeApiManagementGateway,
		Properties:   string(propsJSON),
	}, nil
}

func (g *ApiManagementGateway) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, serviceName, gatewayID, err := apiManagementGatewayIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props apiManagementGatewayProps
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.LocationDataName == "" {
		return nil, fmt.Errorf("locationDataName is required")
	}

	if _, err := g.api.Update(ctx, rgName, serviceName, gatewayID, apimIfMatchAny, g.contract(props), nil); err != nil {
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

	// The PATCH answers 204 with no body, so the current state has to be
	// re-read to report it.
	result, err := g.api.Get(ctx, rgName, serviceName, gatewayID, nil)
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

	propsJSON, err := json.Marshal(g.buildPropertiesFromResult(&result.GatewayContract, rgName, serviceName))
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

func (g *ApiManagementGateway) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, serviceName, gatewayID, err := apiManagementGatewayIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	if _, err := g.api.Delete(ctx, rgName, serviceName, gatewayID, apimIfMatchAny, nil); err != nil && !isDeleteSuccessError(err) {
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

// Status is never reached with real work to do: every write here is
// synchronous.
func (g *ApiManagementGateway) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

// List needs both the resource group and the service name: ARM has no
// subscription-wide listing of gateways.
func (g *ApiManagementGateway) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	serviceName := request.AdditionalProperties["serviceName"]
	if rgName == "" || serviceName == "" {
		return &resource.ListResult{}, nil
	}

	var nativeIDs []string
	pager := g.api.NewListByServicePager(rgName, serviceName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list api management gateways: %w", err)
		}
		for _, gateway := range page.Value {
			if gateway.ID != nil {
				nativeIDs = append(nativeIDs, *gateway.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
