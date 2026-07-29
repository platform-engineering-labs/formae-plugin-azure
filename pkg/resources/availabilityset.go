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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v5"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeAvailabilitySet = "AZURE::Compute::AvailabilitySet"

// availabilitySetsAPI is the subset of *armcompute.AvailabilitySetsClient used
// here. Availability set operations are synchronous (no LRO/poller).
type availabilitySetsAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName string, availabilitySetName string, parameters armcompute.AvailabilitySet, options *armcompute.AvailabilitySetsClientCreateOrUpdateOptions) (armcompute.AvailabilitySetsClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName string, availabilitySetName string, options *armcompute.AvailabilitySetsClientGetOptions) (armcompute.AvailabilitySetsClientGetResponse, error)
	Update(ctx context.Context, resourceGroupName string, availabilitySetName string, parameters armcompute.AvailabilitySetUpdate, options *armcompute.AvailabilitySetsClientUpdateOptions) (armcompute.AvailabilitySetsClientUpdateResponse, error)
	Delete(ctx context.Context, resourceGroupName string, availabilitySetName string, options *armcompute.AvailabilitySetsClientDeleteOptions) (armcompute.AvailabilitySetsClientDeleteResponse, error)
	NewListPager(resourceGroupName string, options *armcompute.AvailabilitySetsClientListOptions) *runtime.Pager[armcompute.AvailabilitySetsClientListResponse]
	NewListBySubscriptionPager(options *armcompute.AvailabilitySetsClientListBySubscriptionOptions) *runtime.Pager[armcompute.AvailabilitySetsClientListBySubscriptionResponse]
}

func init() {
	registry.Register(ResourceTypeAvailabilitySet, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &AvailabilitySet{api: c.AvailabilitySetsClient, config: cfg}
	})
}

// AvailabilitySet is the provisioner for Azure availability sets
// (`Microsoft.Compute/availabilitySets/<name>`). All operations are synchronous.
type AvailabilitySet struct {
	api    availabilitySetsAPI
	config *config.Config
}

func serializeAvailabilitySetProperties(result armcompute.AvailabilitySet, rgName, name string) (json.RawMessage, error) {
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

	if result.SKU != nil && result.SKU.Name != nil {
		props["sku"] = map[string]any{"name": *result.SKU.Name}
	}

	if result.Properties != nil {
		if result.Properties.PlatformFaultDomainCount != nil {
			props["platformFaultDomainCount"] = int(*result.Properties.PlatformFaultDomainCount)
		}
		if result.Properties.PlatformUpdateDomainCount != nil {
			props["platformUpdateDomainCount"] = int(*result.Properties.PlatformUpdateDomainCount)
		}
		if ppg := result.Properties.ProximityPlacementGroup; ppg != nil && ppg.ID != nil {
			props["proximityPlacementGroupId"] = *ppg.ID
		}
	}

	if tags := azureTagsToFormaeTags(result.Tags); tags != nil {
		props["Tags"] = tags
	}

	if result.ID != nil {
		props["id"] = *result.ID
	}

	return json.Marshal(props)
}

func availabilitySetParamsFromProperties(props map[string]any) (armcompute.AvailabilitySet, error) {
	location, _ := props["location"].(string)
	if location == "" {
		return armcompute.AvailabilitySet{}, fmt.Errorf("location is required")
	}

	as := armcompute.AvailabilitySet{
		Location:   &location,
		Properties: &armcompute.AvailabilitySetProperties{},
	}

	if skuMap, ok := props["sku"].(map[string]any); ok {
		if skuName, ok := skuMap["name"].(string); ok && skuName != "" {
			as.SKU = &armcompute.SKU{Name: to.Ptr(skuName)}
		}
	}

	if v, ok := props["platformFaultDomainCount"].(float64); ok {
		as.Properties.PlatformFaultDomainCount = to.Ptr(int32(v))
	}
	if v, ok := props["platformUpdateDomainCount"].(float64); ok {
		as.Properties.PlatformUpdateDomainCount = to.Ptr(int32(v))
	}
	if v, ok := props["proximityPlacementGroupId"].(string); ok && v != "" {
		as.Properties.ProximityPlacementGroup = &armcompute.SubResource{ID: to.Ptr(v)}
	}

	if azureTags := formaeTagsToAzureTags(mustMarshalJSON(props)); azureTags != nil {
		as.Tags = azureTags
	}

	return as, nil
}

func (a *AvailabilitySet) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
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

	params, err := availabilitySetParamsFromProperties(props)
	if err != nil {
		return nil, err
	}

	// Synchronous: CreateOrUpdate is an idempotent upsert returning the final state.
	result, err := a.api.CreateOrUpdate(ctx, rgName, name, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	propsJSON, err := serializeAvailabilitySetProperties(result.AvailabilitySet, rgName, name)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize AvailabilitySet properties: %w", err)
	}

	nativeID := ""
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

func (a *AvailabilitySet) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, name, err := availabilitySetIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := a.api.Get(ctx, rgName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := serializeAvailabilitySetProperties(result.AvailabilitySet, rgName, name)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize AvailabilitySet properties: %w", err)
	}

	return &resource.ReadResult{
		ResourceType: ResourceTypeAvailabilitySet,
		Properties:   string(propsJSON),
	}, nil
}

func (a *AvailabilitySet) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, name, err := availabilitySetIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props map[string]any
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse desired properties: %w", err)
	}

	// platformFaultDomainCount / platformUpdateDomainCount are immutable
	// (createOnly in the schema) but ARM still *requires* them in the PATCH body:
	// omitting platformFaultDomainCount fails with
	// `InvalidParameter: Required parameter 'platformFaultDomainCount' is missing
	// (null)`. So echo the desired (== current) values back.
	update := armcompute.AvailabilitySetUpdate{
		Properties: &armcompute.AvailabilitySetProperties{},
	}
	if skuMap, ok := props["sku"].(map[string]any); ok {
		if skuName, ok := skuMap["name"].(string); ok && skuName != "" {
			update.SKU = &armcompute.SKU{Name: to.Ptr(skuName)}
		}
	}
	if v, ok := props["platformFaultDomainCount"].(float64); ok {
		update.Properties.PlatformFaultDomainCount = to.Ptr(int32(v))
	}
	if v, ok := props["platformUpdateDomainCount"].(float64); ok {
		update.Properties.PlatformUpdateDomainCount = to.Ptr(int32(v))
	}
	if v, ok := props["proximityPlacementGroupId"].(string); ok && v != "" {
		update.Properties.ProximityPlacementGroup = &armcompute.SubResource{ID: to.Ptr(v)}
	}
	if azureTags := formaeTagsToAzureTags(request.DesiredProperties); azureTags != nil {
		update.Tags = azureTags
	}

	result, err := a.api.Update(ctx, rgName, name, update, nil)
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

	propsJSON, err := serializeAvailabilitySetProperties(result.AvailabilitySet, rgName, name)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize AvailabilitySet properties: %w", err)
	}

	nativeID := request.NativeID
	if result.ID != nil {
		nativeID = *result.ID
	}

	return &resource.UpdateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:          resource.OperationUpdate,
			OperationStatus:    resource.OperationStatusSuccess,
			NativeID:           nativeID,
			ResourceProperties: propsJSON,
		},
	}, nil
}

func (a *AvailabilitySet) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, name, err := availabilitySetIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	// Synchronous delete. NotFound means the goal is already achieved.
	if _, err := a.api.Delete(ctx, rgName, name, nil); err != nil {
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

// Status is a no-op success passthrough: availability set operations are
// synchronous, so Create/Update/Delete never return InProgress. It exists only
// to satisfy the Provisioner interface.
func (a *AvailabilitySet) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

func (a *AvailabilitySet) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]

	var nativeIDs []string
	if rgName != "" {
		pager := a.api.NewListPager(rgName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list availability sets in resource group %s: %w", rgName, err)
			}
			for _, as := range page.Value {
				if as.ID != nil {
					nativeIDs = append(nativeIDs, *as.ID)
				}
			}
		}
		return &resource.ListResult{NativeIDs: nativeIDs}, nil
	}

	pager := a.api.NewListBySubscriptionPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list availability sets: %w", err)
		}
		for _, as := range page.Value {
			if as.ID != nil {
				nativeIDs = append(nativeIDs, *as.ID)
			}
		}
	}

	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
