// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/dns/armdns"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeDnsZone = "AZURE::Network::DnsZone"

// dnsZonesAPI is the narrow slice of *armdns.ZonesClient used by the provisioner.
//
// Note: unlike PrivateDnsZones, the public DNS Zones API CreateOrUpdate is
// synchronous (returns the resource directly, no poller). Only Delete is a
// long-running operation, so LRO handling is limited to Delete/Status.
type dnsZonesAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName string, zoneName string, parameters armdns.Zone, options *armdns.ZonesClientCreateOrUpdateOptions) (armdns.ZonesClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName string, zoneName string, options *armdns.ZonesClientGetOptions) (armdns.ZonesClientGetResponse, error)
	BeginDelete(ctx context.Context, resourceGroupName string, zoneName string, options *armdns.ZonesClientBeginDeleteOptions) (*runtime.Poller[armdns.ZonesClientDeleteResponse], error)
	NewListByResourceGroupPager(resourceGroupName string, options *armdns.ZonesClientListByResourceGroupOptions) *runtime.Pager[armdns.ZonesClientListByResourceGroupResponse]
	NewListPager(options *armdns.ZonesClientListOptions) *runtime.Pager[armdns.ZonesClientListResponse]
}

func init() {
	registry.Register(ResourceTypeDnsZone, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &DnsZone{
			api:      c.DnsZonesClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// DnsZone is the provisioner for Azure public DNS Zones.
type DnsZone struct {
	api      dnsZonesAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

func serializeDnsZoneProperties(result armdns.Zone, rgName, zoneName string) (json.RawMessage, error) {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	if result.Name != nil {
		props["name"] = *result.Name
	} else {
		props["name"] = zoneName
	}
	if result.Location != nil {
		props["location"] = *result.Location
	}
	if result.ID != nil {
		props["id"] = *result.ID
	}
	if result.Properties != nil {
		if result.Properties.ZoneType != nil {
			props["zoneType"] = string(*result.Properties.ZoneType)
		}
		if len(result.Properties.NameServers) > 0 {
			nameServers := make([]string, 0, len(result.Properties.NameServers))
			for _, ns := range result.Properties.NameServers {
				if ns != nil {
					nameServers = append(nameServers, *ns)
				}
			}
			props["nameServers"] = nameServers
		}
	}
	if tags := azureTagsToFormaeTags(result.Tags); tags != nil {
		props["Tags"] = tags
	}

	return json.Marshal(props)
}

func dnsZoneParamsFromProperties(properties []byte, props map[string]any, location string) armdns.Zone {
	params := armdns.Zone{
		Location:   stringPtr(location),
		Properties: &armdns.ZoneProperties{},
	}
	zoneType := armdns.ZoneTypePublic
	if zt, ok := props["zoneType"].(string); ok && zt != "" {
		zoneType = armdns.ZoneType(zt)
	}
	params.Properties.ZoneType = &zoneType
	if azureTags := formaeTagsToAzureTags(properties); azureTags != nil {
		params.Tags = azureTags
	}
	return params
}

func (z *DnsZone) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
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
	zoneName, ok := props["name"].(string)
	if !ok || zoneName == "" {
		zoneName = request.Label
	}

	params := dnsZoneParamsFromProperties(request.Properties, props, location)

	result, err := z.api.CreateOrUpdate(ctx, rgName, zoneName, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	propsJSON, err := serializeDnsZoneProperties(result.Zone, rgName, zoneName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize DnsZone properties: %w", err)
	}
	return &resource.CreateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:          resource.OperationCreate,
			OperationStatus:    resource.OperationStatusSuccess,
			NativeID:           *result.ID,
			ResourceProperties: propsJSON,
		},
	}, nil
}

func (z *DnsZone) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, zoneName, err := dnsZoneIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}
	result, err := z.api.Get(ctx, rgName, zoneName, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}
	propsJSON, err := serializeDnsZoneProperties(result.Zone, rgName, zoneName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize DnsZone properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeDnsZone,
		Properties:   string(propsJSON),
	}, nil
}

func (z *DnsZone) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, zoneName, err := dnsZoneIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props map[string]any
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	location, ok := props["location"].(string)
	if !ok || location == "" {
		return nil, fmt.Errorf("location is required")
	}

	params := dnsZoneParamsFromProperties(request.DesiredProperties, props, location)

	result, err := z.api.CreateOrUpdate(ctx, rgName, zoneName, params, nil)
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

	propsJSON, err := serializeDnsZoneProperties(result.Zone, rgName, zoneName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize DnsZone properties: %w", err)
	}
	return &resource.UpdateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:          resource.OperationUpdate,
			OperationStatus:    resource.OperationStatusSuccess,
			NativeID:           *result.ID,
			ResourceProperties: propsJSON,
		},
	}, nil
}

func (z *DnsZone) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, zoneName, err := dnsZoneIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, err := z.api.BeginDelete(ctx, rgName, zoneName, nil)
	if err != nil {
		if operationErrorCode(err) == resource.OperationErrorCodeNotFound {
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
		}, fmt.Errorf("failed to start DnsZone deletion: %w", err)
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

func (z *DnsZone) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
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

	if reqID.OperationType != lroOpDelete {
		// Create/Update are synchronous for public DNS zones, so the only LRO
		// that can reach Status is Delete.
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
			},
		}, fmt.Errorf("unexpected operation type for DnsZone: %s", reqID.OperationType)
	}

	return statusDeleteLRO(ctx, request, &reqID,
		func(token string) (*runtime.Poller[armdns.ZonesClientDeleteResponse], error) {
			return resumePoller[armdns.ZonesClientDeleteResponse](z.pipeline, token)
		}, nil)
}

func (z *DnsZone) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	resourceGroupName := request.AdditionalProperties["resourceGroupName"]
	var nativeIDs []string
	if resourceGroupName != "" {
		pager := z.api.NewListByResourceGroupPager(resourceGroupName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list dns zones: %w", err)
			}
			for _, x := range page.Value {
				if x != nil && x.ID != nil {
					nativeIDs = append(nativeIDs, *x.ID)
				}
			}
		}
	} else {
		pager := z.api.NewListPager(nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list dns zones: %w", err)
			}
			for _, x := range page.Value {
				if x != nil && x.ID != nil {
					nativeIDs = append(nativeIDs, *x.ID)
				}
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}

func dnsZoneIDParts(nativeID string) (rgName, zoneName string, err error) {
	rgName, names, err := armIDParts(nativeID, "dnszones")
	if err != nil {
		return "", "", err
	}
	return rgName, names["dnszones"], nil
}
