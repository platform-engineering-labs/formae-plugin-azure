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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appservice/armappservice/v5"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeWebServicePlan = "AZURE::Web::ServicePlan"

// appServicePlansAPI is the subset of *armappservice.PlansClient used here.
//
// Create/update is a long-running operation; Delete is synchronous, which is why
// Status only ever sees a create or an update handle.
type appServicePlansAPI interface {
	BeginCreateOrUpdate(ctx context.Context, resourceGroupName string, name string, appServicePlan armappservice.Plan, options *armappservice.PlansClientBeginCreateOrUpdateOptions) (*runtime.Poller[armappservice.PlansClientCreateOrUpdateResponse], error)
	Get(ctx context.Context, resourceGroupName string, name string, options *armappservice.PlansClientGetOptions) (armappservice.PlansClientGetResponse, error)
	Delete(ctx context.Context, resourceGroupName string, name string, options *armappservice.PlansClientDeleteOptions) (armappservice.PlansClientDeleteResponse, error)
	NewListByResourceGroupPager(resourceGroupName string, options *armappservice.PlansClientListByResourceGroupOptions) *runtime.Pager[armappservice.PlansClientListByResourceGroupResponse]
	NewListPager(options *armappservice.PlansClientListOptions) *runtime.Pager[armappservice.PlansClientListResponse]
}

func init() {
	registry.Register(ResourceTypeWebServicePlan, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &ServicePlan{
			api:      c.AppServicePlansClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// ServicePlan is the provisioner for App Service plans
// (Microsoft.Web/serverfarms) — the compute every WebApp, FunctionApp and
// deployment slot hangs off.
type ServicePlan struct {
	api      appServicePlansAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

func servicePlanIDParts(resourceID string) (rgName, planName string, err error) {
	rgName, names, err := armIDParts(resourceID, "serverfarms")
	if err != nil {
		return "", "", err
	}
	return rgName, names["serverfarms"], nil
}

// webNumber coerces a JSON number (which arrives as float64 through
// map[string]any) into an int32. Shared by every Microsoft.Web resource in this
// plugin.
func webNumber(v any) (int32, bool) {
	f, ok := v.(float64)
	if !ok {
		return 0, false
	}
	return int32(f), true
}

// buildServicePlanParams converts the formae property map into an
// armappservice.Plan. Shared by Create and Update so the body shape stays
// identical across operations.
func buildServicePlanParams(props map[string]any, location string) (armappservice.Plan, error) {
	params := armappservice.Plan{
		Location:   stringPtr(location),
		Properties: &armappservice.PlanProperties{},
	}

	skuRaw, ok := props["sku"].(map[string]any)
	if !ok {
		return params, fmt.Errorf("sku is required")
	}
	skuName, _ := skuRaw["name"].(string)
	if skuName == "" {
		return params, fmt.Errorf("sku.name is required")
	}
	sku := &armappservice.SKUDescription{Name: stringPtr(skuName)}
	if tier, ok := skuRaw["tier"].(string); ok && tier != "" {
		sku.Tier = stringPtr(tier)
	}
	if capacity, ok := webNumber(skuRaw["capacity"]); ok {
		sku.Capacity = int32Ptr(capacity)
	}
	params.SKU = sku

	if kind, ok := props["kind"].(string); ok && kind != "" {
		params.Kind = stringPtr(kind)
	}
	if reserved, ok := props["reserved"].(bool); ok {
		params.Properties.Reserved = to.Ptr(reserved)
	}
	if zoneRedundant, ok := props["zoneRedundant"].(bool); ok {
		params.Properties.ZoneRedundant = to.Ptr(zoneRedundant)
	}
	if perSiteScaling, ok := props["perSiteScaling"].(bool); ok {
		params.Properties.PerSiteScaling = to.Ptr(perSiteScaling)
	}
	if elasticScaleEnabled, ok := props["elasticScaleEnabled"].(bool); ok {
		params.Properties.ElasticScaleEnabled = to.Ptr(elasticScaleEnabled)
	}
	if maxWorkers, ok := webNumber(props["maximumElasticWorkerCount"]); ok {
		params.Properties.MaximumElasticWorkerCount = int32Ptr(maxWorkers)
	}

	return params, nil
}

// serializeServicePlanProperties converts an Azure Plan into formae property
// format.
func serializeServicePlanProperties(result armappservice.Plan, rgName, planName string) (json.RawMessage, error) {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	if result.Name != nil {
		props["name"] = *result.Name
	} else {
		props["name"] = planName
	}
	if result.Location != nil {
		props["location"] = normalizeAzureLocation(*result.Location)
	}
	if result.ID != nil {
		props["id"] = *result.ID
	}
	if result.Kind != nil && *result.Kind != "" {
		props["kind"] = *result.Kind
	}

	if sku := result.SKU; sku != nil {
		skuMap := make(map[string]any)
		if sku.Name != nil {
			skuMap["name"] = *sku.Name
		}
		if sku.Tier != nil {
			skuMap["tier"] = *sku.Tier
		}
		if sku.Capacity != nil {
			skuMap["capacity"] = *sku.Capacity
		}
		if len(skuMap) > 0 {
			props["sku"] = skuMap
		}
	}

	if p := result.Properties; p != nil {
		if p.Reserved != nil {
			props["reserved"] = *p.Reserved
		}
		if p.ZoneRedundant != nil {
			props["zoneRedundant"] = *p.ZoneRedundant
		}
		if p.PerSiteScaling != nil {
			props["perSiteScaling"] = *p.PerSiteScaling
		}
		if p.ElasticScaleEnabled != nil {
			props["elasticScaleEnabled"] = *p.ElasticScaleEnabled
		}
		if p.MaximumElasticWorkerCount != nil {
			props["maximumElasticWorkerCount"] = *p.MaximumElasticWorkerCount
		}
	}

	if tags := azureTagsToFormaeTags(result.Tags); tags != nil {
		props["Tags"] = tags
	}

	return json.Marshal(props)
}

func (s *ServicePlan) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
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
	planName, ok := props["name"].(string)
	if !ok || planName == "" {
		planName = request.Label
	}
	if planName == "" {
		return nil, fmt.Errorf("name is required")
	}

	params, err := buildServicePlanParams(props, location)
	if err != nil {
		return nil, err
	}
	if azureTags := formaeTagsToAzureTags(request.Properties); azureTags != nil {
		params.Tags = azureTags
	}

	poller, err := s.api.BeginCreateOrUpdate(ctx, rgName, planName, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Web/serverfarms/%s",
		s.config.SubscriptionId, rgName, planName)

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
		propsJSON, err := serializeServicePlanProperties(result.Plan, rgName, planName)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize ServicePlan properties: %w", err)
		}
		nativeID := expectedNativeID
		if result.ID != nil {
			nativeID = *result.ID
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

func (s *ServicePlan) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, planName, err := servicePlanIDParts(request.NativeID)
	if err != nil {
		return nil, fmt.Errorf("invalid NativeID: cannot extract resourceGroup or serverfarm name from %s: %w", request.NativeID, err)
	}

	result, err := s.api.Get(ctx, rgName, planName, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}
	propsJSON, err := serializeServicePlanProperties(result.Plan, rgName, planName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize ServicePlan properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeWebServicePlan,
		Properties:   string(propsJSON),
	}, nil
}

func (s *ServicePlan) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, planName, err := servicePlanIDParts(request.NativeID)
	if err != nil {
		return nil, fmt.Errorf("invalid NativeID: cannot extract resourceGroup or serverfarm name from %s: %w", request.NativeID, err)
	}

	var props map[string]any
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	location, ok := props["location"].(string)
	if !ok || location == "" {
		return nil, fmt.Errorf("location is required")
	}

	params, err := buildServicePlanParams(props, location)
	if err != nil {
		return nil, err
	}
	if azureTags := formaeTagsToAzureTags(request.DesiredProperties); azureTags != nil {
		params.Tags = azureTags
	}

	poller, err := s.api.BeginCreateOrUpdate(ctx, rgName, planName, params, nil)
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
		propsJSON, err := serializeServicePlanProperties(result.Plan, rgName, planName)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize ServicePlan properties: %w", err)
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

// Delete is synchronous: ARM deletes a server farm inline. A 404 is success so
// the operation is idempotent.
func (s *ServicePlan) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, planName, err := servicePlanIDParts(request.NativeID)
	if err != nil {
		return nil, fmt.Errorf("invalid NativeID: cannot extract resourceGroup or serverfarm name from %s: %w", request.NativeID, err)
	}

	if _, err := s.api.Delete(ctx, rgName, planName, nil); err != nil && !isDeleteSuccessError(err) {
		return &resource.DeleteResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationDelete,
				OperationStatus: resource.OperationStatusFailure,
				NativeID:        request.NativeID,
				ErrorCode:       operationErrorCode(err),
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

// Status resumes a create or update poller. Delete is synchronous and never
// returns a request ID, so there is no delete branch.
func (s *ServicePlan) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
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
		operation := resource.OperationCreate
		if reqID.OperationType == lroOpUpdate {
			operation = resource.OperationUpdate
		}
		return statusLRO(ctx, request, &reqID, operation,
			func(token string) (*runtime.Poller[armappservice.PlansClientCreateOrUpdateResponse], error) {
				return resumePoller[armappservice.PlansClientCreateOrUpdateResponse](s.pipeline, token)
			},
			func(_ context.Context, result armappservice.PlansClientCreateOrUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				if result.ID == nil {
					return "", nil, fmt.Errorf("ServicePlan create/update returned no resource ID")
				}
				rgName, planName, err := servicePlanIDParts(*result.ID)
				if err != nil {
					return "", nil, err
				}
				propsJSON, err := serializeServicePlanProperties(result.Plan, rgName, planName)
				if err != nil {
					return "", nil, fmt.Errorf("failed to serialize ServicePlan properties: %w", err)
				}
				return *result.ID, propsJSON, nil
			})
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

func (s *ServicePlan) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]

	var nativeIDs []string
	if rgName != "" {
		pager := s.api.NewListByResourceGroupPager(rgName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list app service plans: %w", err)
			}
			for _, plan := range page.Value {
				if plan != nil && plan.ID != nil {
					nativeIDs = append(nativeIDs, *plan.ID)
				}
			}
		}
		return &resource.ListResult{NativeIDs: nativeIDs}, nil
	}

	pager := s.api.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list app service plans: %w", err)
		}
		for _, plan := range page.Value {
			if plan != nil && plan.ID != nil {
				nativeIDs = append(nativeIDs, *plan.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
