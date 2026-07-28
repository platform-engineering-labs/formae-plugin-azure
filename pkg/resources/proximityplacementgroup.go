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

const ResourceTypeProximityPlacementGroup = "AZURE::Compute::ProximityPlacementGroup"

// proximityPlacementGroupsAPI is the subset of
// *armcompute.ProximityPlacementGroupsClient used here. All operations are
// synchronous (no LRO/poller).
type proximityPlacementGroupsAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName string, proximityPlacementGroupName string, parameters armcompute.ProximityPlacementGroup, options *armcompute.ProximityPlacementGroupsClientCreateOrUpdateOptions) (armcompute.ProximityPlacementGroupsClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName string, proximityPlacementGroupName string, options *armcompute.ProximityPlacementGroupsClientGetOptions) (armcompute.ProximityPlacementGroupsClientGetResponse, error)
	Update(ctx context.Context, resourceGroupName string, proximityPlacementGroupName string, parameters armcompute.ProximityPlacementGroupUpdate, options *armcompute.ProximityPlacementGroupsClientUpdateOptions) (armcompute.ProximityPlacementGroupsClientUpdateResponse, error)
	Delete(ctx context.Context, resourceGroupName string, proximityPlacementGroupName string, options *armcompute.ProximityPlacementGroupsClientDeleteOptions) (armcompute.ProximityPlacementGroupsClientDeleteResponse, error)
	NewListByResourceGroupPager(resourceGroupName string, options *armcompute.ProximityPlacementGroupsClientListByResourceGroupOptions) *runtime.Pager[armcompute.ProximityPlacementGroupsClientListByResourceGroupResponse]
	NewListBySubscriptionPager(options *armcompute.ProximityPlacementGroupsClientListBySubscriptionOptions) *runtime.Pager[armcompute.ProximityPlacementGroupsClientListBySubscriptionResponse]
}

func init() {
	registry.Register(ResourceTypeProximityPlacementGroup, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &ProximityPlacementGroup{api: c.ProximityPlacementGroupsClient, config: cfg}
	})
}

// ProximityPlacementGroup is the provisioner for Azure proximity placement
// groups (`Microsoft.Compute/proximityPlacementGroups/<name>`). All operations
// are synchronous.
type ProximityPlacementGroup struct {
	api    proximityPlacementGroupsAPI
	config *config.Config
}

func serializeProximityPlacementGroupProperties(result armcompute.ProximityPlacementGroup, rgName, name string) (json.RawMessage, error) {
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
	if result.ID != nil {
		props["id"] = *result.ID
	}

	if result.Properties != nil {
		if result.Properties.ProximityPlacementGroupType != nil {
			props["proximityPlacementGroupType"] = string(*result.Properties.ProximityPlacementGroupType)
		}
		if intent := result.Properties.Intent; intent != nil && len(intent.VMSizes) > 0 {
			sizes := make([]string, 0, len(intent.VMSizes))
			for _, s := range intent.VMSizes {
				if s != nil {
					sizes = append(sizes, *s)
				}
			}
			if len(sizes) > 0 {
				props["intent"] = map[string]any{"vmSizes": sizes}
			}
		}
	}

	if len(result.Zones) > 0 {
		zones := make([]string, 0, len(result.Zones))
		for _, z := range result.Zones {
			if z != nil {
				zones = append(zones, *z)
			}
		}
		props["zones"] = zones
	}

	if tags := azureTagsToFormaeTags(result.Tags); tags != nil {
		props["Tags"] = tags
	}

	return json.Marshal(props)
}

func proximityPlacementGroupParamsFromProperties(props map[string]any, rawProps json.RawMessage) (armcompute.ProximityPlacementGroup, error) {
	location, _ := props["location"].(string)
	if location == "" {
		return armcompute.ProximityPlacementGroup{}, fmt.Errorf("location is required")
	}

	ppg := armcompute.ProximityPlacementGroup{
		Location:   &location,
		Properties: &armcompute.ProximityPlacementGroupProperties{},
	}

	if v, ok := props["proximityPlacementGroupType"].(string); ok && v != "" {
		ppg.Properties.ProximityPlacementGroupType = to.Ptr(armcompute.ProximityPlacementGroupType(v))
	}

	if intentMap, ok := props["intent"].(map[string]any); ok {
		if rawSizes, ok := intentMap["vmSizes"].([]any); ok && len(rawSizes) > 0 {
			sizes := make([]*string, 0, len(rawSizes))
			for _, s := range rawSizes {
				if str, ok := s.(string); ok {
					sizes = append(sizes, stringPtr(str))
				}
			}
			ppg.Properties.Intent = &armcompute.ProximityPlacementGroupPropertiesIntent{VMSizes: sizes}
		}
	}

	if rawZones, ok := props["zones"].([]any); ok && len(rawZones) > 0 {
		zones := make([]*string, 0, len(rawZones))
		for _, z := range rawZones {
			if s, ok := z.(string); ok {
				zones = append(zones, stringPtr(s))
			}
		}
		ppg.Zones = zones
	}

	if azureTags := formaeTagsToAzureTags(rawProps); azureTags != nil {
		ppg.Tags = azureTags
	}

	return ppg, nil
}

func proximityPlacementGroupIDParts(resourceID string) (rgName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "proximityplacementgroups")
	if err != nil {
		return "", "", err
	}
	return rgName, names["proximityplacementgroups"], nil
}

func (p *ProximityPlacementGroup) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
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

	params, err := proximityPlacementGroupParamsFromProperties(props, request.Properties)
	if err != nil {
		return nil, err
	}

	// Synchronous: CreateOrUpdate is an idempotent upsert returning final state.
	result, err := p.api.CreateOrUpdate(ctx, rgName, name, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	propsJSON, err := serializeProximityPlacementGroupProperties(result.ProximityPlacementGroup, rgName, name)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize ProximityPlacementGroup properties: %w", err)
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

func (p *ProximityPlacementGroup) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, name, err := proximityPlacementGroupIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := p.api.Get(ctx, rgName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := serializeProximityPlacementGroupProperties(result.ProximityPlacementGroup, rgName, name)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize ProximityPlacementGroup properties: %w", err)
	}

	return &resource.ReadResult{
		ResourceType: ResourceTypeProximityPlacementGroup,
		Properties:   string(propsJSON),
	}, nil
}

func (p *ProximityPlacementGroup) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, name, err := proximityPlacementGroupIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	// ARM's PATCH body for a proximity placement group carries tags only —
	// ProximityPlacementGroupUpdate has no other fields, and type/intent/zones are
	// createOnly in the schema.
	update := armcompute.ProximityPlacementGroupUpdate{
		Tags: formaeTagsToAzureTags(request.DesiredProperties),
	}

	result, err := p.api.Update(ctx, rgName, name, update, nil)
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

	propsJSON, err := serializeProximityPlacementGroupProperties(result.ProximityPlacementGroup, rgName, name)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize ProximityPlacementGroup properties: %w", err)
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

func (p *ProximityPlacementGroup) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, name, err := proximityPlacementGroupIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	// Synchronous delete. NotFound means the goal is already achieved.
	if _, err := p.api.Delete(ctx, rgName, name, nil); err != nil {
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

// Status is a no-op success passthrough: proximity placement group operations
// are synchronous, so Create/Update/Delete never return InProgress. It exists
// only to satisfy the Provisioner interface.
func (p *ProximityPlacementGroup) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

func (p *ProximityPlacementGroup) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]

	var nativeIDs []string
	if rgName != "" {
		pager := p.api.NewListByResourceGroupPager(rgName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list proximity placement groups in resource group %s: %w", rgName, err)
			}
			for _, ppg := range page.Value {
				if ppg.ID != nil {
					nativeIDs = append(nativeIDs, *ppg.ID)
				}
			}
		}
		return &resource.ListResult{NativeIDs: nativeIDs}, nil
	}

	pager := p.api.NewListBySubscriptionPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list proximity placement groups: %w", err)
		}
		for _, ppg := range page.Value {
			if ppg.ID != nil {
				nativeIDs = append(nativeIDs, *ppg.ID)
			}
		}
	}

	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
