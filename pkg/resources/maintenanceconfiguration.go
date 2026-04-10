// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerservice/armcontainerservice/v4"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeMaintenanceConfiguration = "Azure::ContainerService::MaintenanceConfiguration"

func init() {
	registry.Register(ResourceTypeMaintenanceConfiguration, func(client *client.Client, cfg *config.Config) prov.Provisioner {
		return &MaintenanceConfiguration{client, cfg}
	})
}

type MaintenanceConfiguration struct {
	Client *client.Client
	Config *config.Config
}

func serializeMaintenanceConfigurationProperties(result armcontainerservice.MaintenanceConfiguration, rgName, clusterName string) (json.RawMessage, error) {
	props := make(map[string]interface{})

	if result.ID != nil {
		props["id"] = *result.ID
	}
	if result.Name != nil {
		props["name"] = *result.Name
	}
	props["resourceGroupName"] = rgName
	props["clusterName"] = clusterName

	if result.Properties != nil {
		// TimeInWeek
		if result.Properties.TimeInWeek != nil {
			slots := make([]map[string]interface{}, 0, len(result.Properties.TimeInWeek))
			for _, tiw := range result.Properties.TimeInWeek {
				if tiw == nil {
					continue
				}
				slot := make(map[string]interface{})
				if tiw.Day != nil {
					slot["day"] = string(*tiw.Day)
				}
				if tiw.HourSlots != nil {
					hours := make([]int32, 0, len(tiw.HourSlots))
					for _, h := range tiw.HourSlots {
						if h != nil {
							hours = append(hours, *h)
						}
					}
					slot["hourSlots"] = hours
				}
				slots = append(slots, slot)
			}
			if len(slots) > 0 {
				props["timeInWeek"] = slots
			}
		}

		// NotAllowedTime
		if result.Properties.NotAllowedTime != nil {
			spans := make([]map[string]interface{}, 0, len(result.Properties.NotAllowedTime))
			for _, ts := range result.Properties.NotAllowedTime {
				if ts == nil {
					continue
				}
				span := make(map[string]interface{})
				if ts.Start != nil {
					span["start"] = ts.Start.UTC().Format("2006-01-02T15:04:05Z")
				}
				if ts.End != nil {
					span["end"] = ts.End.UTC().Format("2006-01-02T15:04:05Z")
				}
				spans = append(spans, span)
			}
			if len(spans) > 0 {
				props["notAllowedTime"] = spans
			}
		}
	}

	return json.Marshal(props)
}

func (mc *MaintenanceConfiguration) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props map[string]interface{}
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	rgName, ok := props["resourceGroupName"].(string)
	if !ok || rgName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}

	clusterName, ok := props["clusterName"].(string)
	if !ok || clusterName == "" {
		return nil, fmt.Errorf("clusterName is required")
	}

	configName, ok := props["name"].(string)
	if !ok || configName == "" {
		configName = request.Label
	}

	params := armcontainerservice.MaintenanceConfiguration{
		Properties: &armcontainerservice.MaintenanceConfigurationProperties{},
	}

	// Parse TimeInWeek
	if tiwRaw, ok := props["timeInWeek"].([]interface{}); ok {
		tiws := make([]*armcontainerservice.TimeInWeek, 0, len(tiwRaw))
		for _, raw := range tiwRaw {
			tiwMap, ok := raw.(map[string]interface{})
			if !ok {
				continue
			}
			tiw := &armcontainerservice.TimeInWeek{}
			if day, ok := tiwMap["day"].(string); ok {
				d := armcontainerservice.WeekDay(day)
				tiw.Day = &d
			}
			if hoursRaw, ok := tiwMap["hourSlots"].([]interface{}); ok {
				hours := make([]*int32, 0, len(hoursRaw))
				for _, h := range hoursRaw {
					if hf, ok := h.(float64); ok {
						hours = append(hours, to.Ptr(int32(hf)))
					}
				}
				tiw.HourSlots = hours
			}
			tiws = append(tiws, tiw)
		}
		params.Properties.TimeInWeek = tiws
	}

	// Parse NotAllowedTime
	if natRaw, ok := props["notAllowedTime"].([]interface{}); ok {
		spans := make([]*armcontainerservice.TimeSpan, 0, len(natRaw))
		for _, raw := range natRaw {
			spanMap, ok := raw.(map[string]interface{})
			if !ok {
				continue
			}
			span := &armcontainerservice.TimeSpan{}
			if start, ok := spanMap["start"].(string); ok {
				t, err := parseTime(start)
				if err == nil {
					span.Start = &t
				}
			}
			if end, ok := spanMap["end"].(string); ok {
				t, err := parseTime(end)
				if err == nil {
					span.End = &t
				}
			}
			spans = append(spans, span)
		}
		params.Properties.NotAllowedTime = spans
	}

	result, err := mc.Client.MaintenanceConfigurationsClient.CreateOrUpdate(ctx, rgName, clusterName, configName, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       mapAzureErrorToOperationErrorCode(err),
			},
		}, nil
	}

	propsJSON, err := serializeMaintenanceConfigurationProperties(result.MaintenanceConfiguration, rgName, clusterName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize maintenance configuration properties: %w", err)
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

func (mc *MaintenanceConfiguration) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	parts := splitResourceID(request.NativeID)

	rgName, ok := parts["resourcegroups"]
	if !ok || rgName == "" {
		return nil, fmt.Errorf("invalid NativeID: could not extract resource group name from %s", request.NativeID)
	}

	clusterName, ok := parts["managedclusters"]
	if !ok || clusterName == "" {
		return nil, fmt.Errorf("invalid NativeID: could not extract cluster name from %s", request.NativeID)
	}

	configName, ok := parts["maintenanceconfigurations"]
	if !ok || configName == "" {
		return nil, fmt.Errorf("invalid NativeID: could not extract maintenance configuration name from %s", request.NativeID)
	}

	result, err := mc.Client.MaintenanceConfigurationsClient.Get(ctx, rgName, clusterName, configName, nil)
	if err != nil {
		return &resource.ReadResult{
			ErrorCode: mapAzureErrorToOperationErrorCode(err),
		}, nil
	}

	propsJSON, err := serializeMaintenanceConfigurationProperties(result.MaintenanceConfiguration, rgName, clusterName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize maintenance configuration properties: %w", err)
	}

	return &resource.ReadResult{
		Properties: string(propsJSON),
	}, nil
}

func (mc *MaintenanceConfiguration) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	parts := splitResourceID(request.NativeID)

	rgName, ok := parts["resourcegroups"]
	if !ok || rgName == "" {
		return nil, fmt.Errorf("invalid NativeID: could not extract resource group name from %s", request.NativeID)
	}

	clusterName, ok := parts["managedclusters"]
	if !ok || clusterName == "" {
		return nil, fmt.Errorf("invalid NativeID: could not extract cluster name from %s", request.NativeID)
	}

	configName, ok := parts["maintenanceconfigurations"]
	if !ok || configName == "" {
		return nil, fmt.Errorf("invalid NativeID: could not extract maintenance configuration name from %s", request.NativeID)
	}

	var props map[string]interface{}
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	params := armcontainerservice.MaintenanceConfiguration{
		Properties: &armcontainerservice.MaintenanceConfigurationProperties{},
	}

	// Parse TimeInWeek
	if tiwRaw, ok := props["timeInWeek"].([]interface{}); ok {
		tiws := make([]*armcontainerservice.TimeInWeek, 0, len(tiwRaw))
		for _, raw := range tiwRaw {
			tiwMap, ok := raw.(map[string]interface{})
			if !ok {
				continue
			}
			tiw := &armcontainerservice.TimeInWeek{}
			if day, ok := tiwMap["day"].(string); ok {
				d := armcontainerservice.WeekDay(day)
				tiw.Day = &d
			}
			if hoursRaw, ok := tiwMap["hourSlots"].([]interface{}); ok {
				hours := make([]*int32, 0, len(hoursRaw))
				for _, h := range hoursRaw {
					if hf, ok := h.(float64); ok {
						hours = append(hours, to.Ptr(int32(hf)))
					}
				}
				tiw.HourSlots = hours
			}
			tiws = append(tiws, tiw)
		}
		params.Properties.TimeInWeek = tiws
	}

	// Parse NotAllowedTime
	if natRaw, ok := props["notAllowedTime"].([]interface{}); ok {
		spans := make([]*armcontainerservice.TimeSpan, 0, len(natRaw))
		for _, raw := range natRaw {
			spanMap, ok := raw.(map[string]interface{})
			if !ok {
				continue
			}
			span := &armcontainerservice.TimeSpan{}
			if start, ok := spanMap["start"].(string); ok {
				t, err := parseTime(start)
				if err == nil {
					span.Start = &t
				}
			}
			if end, ok := spanMap["end"].(string); ok {
				t, err := parseTime(end)
				if err == nil {
					span.End = &t
				}
			}
			spans = append(spans, span)
		}
		params.Properties.NotAllowedTime = spans
	}

	result, err := mc.Client.MaintenanceConfigurationsClient.CreateOrUpdate(ctx, rgName, clusterName, configName, params, nil)
	if err != nil {
		return &resource.UpdateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationUpdate,
				OperationStatus: resource.OperationStatusFailure,
				NativeID:        request.NativeID,
				ErrorCode:       mapAzureErrorToOperationErrorCode(err),
			},
		}, nil
	}

	propsJSON, err := serializeMaintenanceConfigurationProperties(result.MaintenanceConfiguration, rgName, clusterName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize maintenance configuration properties: %w", err)
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

func (mc *MaintenanceConfiguration) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	parts := splitResourceID(request.NativeID)

	rgName, ok := parts["resourcegroups"]
	if !ok || rgName == "" {
		return nil, fmt.Errorf("invalid NativeID: could not extract resource group name from %s", request.NativeID)
	}

	clusterName, ok := parts["managedclusters"]
	if !ok || clusterName == "" {
		return nil, fmt.Errorf("invalid NativeID: could not extract cluster name from %s", request.NativeID)
	}

	configName, ok := parts["maintenanceconfigurations"]
	if !ok || configName == "" {
		return nil, fmt.Errorf("invalid NativeID: could not extract maintenance configuration name from %s", request.NativeID)
	}

	_, err := mc.Client.MaintenanceConfigurationsClient.Delete(ctx, rgName, clusterName, configName, nil)
	if err != nil {
		if mapAzureErrorToOperationErrorCode(err) == resource.OperationErrorCodeNotFound {
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
				ErrorCode:       mapAzureErrorToOperationErrorCode(err),
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

func (mc *MaintenanceConfiguration) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	// MaintenanceConfiguration operations are synchronous — no LRO status polling needed
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

func (mc *MaintenanceConfiguration) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	resourceGroupName, ok := request.AdditionalProperties["resourceGroupName"]
	if !ok || resourceGroupName == "" {
		return nil, fmt.Errorf("resourceGroupName is required in AdditionalProperties for listing MaintenanceConfigurations")
	}

	clusterName, ok := request.AdditionalProperties["clusterName"]
	if !ok || clusterName == "" {
		return nil, fmt.Errorf("clusterName is required in AdditionalProperties for listing MaintenanceConfigurations")
	}

	pager := mc.Client.MaintenanceConfigurationsClient.NewListByManagedClusterPager(resourceGroupName, clusterName, nil)

	var nativeIDs []string

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list maintenance configurations: %w", err)
		}

		for _, config := range page.Value {
			if config.ID == nil {
				continue
			}
			nativeIDs = append(nativeIDs, *config.ID)
		}
	}

	return &resource.ListResult{
		NativeIDs: nativeIDs,
	}, nil
}
