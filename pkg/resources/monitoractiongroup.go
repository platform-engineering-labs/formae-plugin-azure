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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/monitor/armmonitor"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeMonitorActionGroup = "AZURE::Insights::ActionGroup"

// monitorActionGroupsAPI is the armmonitor surface used here; all operations are
// synchronous.
//
// Note: armmonitor is still a pre-1.0 module (v0.13.0), so a future major bump may
// change these signatures.
type monitorActionGroupsAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName string, actionGroupName string, actionGroup armmonitor.ActionGroupResource, options *armmonitor.ActionGroupsClientCreateOrUpdateOptions) (armmonitor.ActionGroupsClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName string, actionGroupName string, options *armmonitor.ActionGroupsClientGetOptions) (armmonitor.ActionGroupsClientGetResponse, error)
	Delete(ctx context.Context, resourceGroupName string, actionGroupName string, options *armmonitor.ActionGroupsClientDeleteOptions) (armmonitor.ActionGroupsClientDeleteResponse, error)
	NewListByResourceGroupPager(resourceGroupName string, options *armmonitor.ActionGroupsClientListByResourceGroupOptions) *runtime.Pager[armmonitor.ActionGroupsClientListByResourceGroupResponse]
	NewListBySubscriptionIDPager(options *armmonitor.ActionGroupsClientListBySubscriptionIDOptions) *runtime.Pager[armmonitor.ActionGroupsClientListBySubscriptionIDResponse]
}

func init() {
	registry.Register(ResourceTypeMonitorActionGroup, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &MonitorActionGroup{api: c.MonitorActionGroupsClient, config: cfg}
	})
}

// MonitorActionGroup is the provisioner for Azure Monitor action groups
// (Microsoft.Insights/actionGroups).
type MonitorActionGroup struct {
	api    monitorActionGroupsAPI
	config *config.Config
}

// monitorActionGroupProps mirrors schema/pkl/insights/actiongroup.pkl.
type monitorActionGroupProps struct {
	Name              string                      `json:"name"`
	ResourceGroupName string                      `json:"resourceGroupName"`
	Location          string                      `json:"location"`
	GroupShortName    string                      `json:"groupShortName"`
	Enabled           *bool                       `json:"enabled"`
	EmailReceivers    []monitorEmailReceiverProps `json:"emailReceivers"`
}

type monitorEmailReceiverProps struct {
	Name                 string `json:"name"`
	EmailAddress         string `json:"emailAddress"`
	UseCommonAlertSchema *bool  `json:"useCommonAlertSchema"`
}

func monitorActionGroupIDParts(resourceID string) (rgName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "actiongroups")
	if err != nil {
		return "", "", err
	}
	return rgName, names["actiongroups"], nil
}

func serializeMonitorActionGroup(ag armmonitor.ActionGroupResource, rgName, name string) (json.RawMessage, error) {
	props := map[string]any{
		"resourceGroupName": rgName,
		"name":              name,
	}
	if ag.ID != nil {
		props["id"] = *ag.ID
	}
	if ag.Name != nil {
		props["name"] = *ag.Name
	}
	// ARM echoes "Global" back capitalised as sent; normalise like other resources
	// so a read never disagrees with the schema default on case alone.
	if ag.Location != nil {
		loc := *ag.Location
		if strings.EqualFold(loc, "global") {
			loc = "Global"
		}
		props["location"] = loc
	}

	if ag.Properties != nil {
		if ag.Properties.GroupShortName != nil {
			props["groupShortName"] = *ag.Properties.GroupShortName
		}
		if ag.Properties.Enabled != nil {
			props["enabled"] = *ag.Properties.Enabled
		}
		receivers := make([]map[string]any, 0, len(ag.Properties.EmailReceivers))
		for _, r := range ag.Properties.EmailReceivers {
			if r == nil {
				continue
			}
			entry := map[string]any{}
			if r.Name != nil {
				entry["name"] = *r.Name
			}
			if r.EmailAddress != nil {
				entry["emailAddress"] = *r.EmailAddress
			}
			if r.UseCommonAlertSchema != nil {
				entry["useCommonAlertSchema"] = *r.UseCommonAlertSchema
			}
			receivers = append(receivers, entry)
		}
		if len(receivers) > 0 {
			props["emailReceivers"] = receivers
		}
	}

	if tags := azureTagsToFormaeTags(ag.Tags); tags != nil {
		props["Tags"] = tags
	}

	return json.Marshal(props)
}

func monitorActionGroupParams(props monitorActionGroupProps) armmonitor.ActionGroupResource {
	location := props.Location
	if location == "" {
		location = "Global"
	}
	enabled := true
	if props.Enabled != nil {
		enabled = *props.Enabled
	}

	receivers := make([]*armmonitor.EmailReceiver, 0, len(props.EmailReceivers))
	for _, r := range props.EmailReceivers {
		useCommon := true
		if r.UseCommonAlertSchema != nil {
			useCommon = *r.UseCommonAlertSchema
		}
		receivers = append(receivers, &armmonitor.EmailReceiver{
			Name:                 to.Ptr(r.Name),
			EmailAddress:         to.Ptr(r.EmailAddress),
			UseCommonAlertSchema: to.Ptr(useCommon),
		})
	}

	return armmonitor.ActionGroupResource{
		Location: to.Ptr(location),
		Properties: &armmonitor.ActionGroup{
			GroupShortName: to.Ptr(props.GroupShortName),
			Enabled:        to.Ptr(enabled),
			EmailReceivers: receivers,
		},
	}
}

// upsert backs both Create and Update. The narrow ARM PATCH (ActionGroupPatchBody)
// can only toggle `enabled` and tags — it cannot change receivers — so every write
// goes through CreateOrUpdate, which replaces the group wholesale.
func (m *MonitorActionGroup) upsert(ctx context.Context, payload json.RawMessage, label string) (armmonitor.ActionGroupResource, string, string, error) {
	var props monitorActionGroupProps
	if err := json.Unmarshal(payload, &props); err != nil {
		return armmonitor.ActionGroupResource{}, "", "", fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return armmonitor.ActionGroupResource{}, "", "", fmt.Errorf("resourceGroupName is required")
	}
	if props.GroupShortName == "" {
		return armmonitor.ActionGroupResource{}, "", "", fmt.Errorf("groupShortName is required")
	}
	name := props.Name
	if name == "" {
		name = label
	}
	if name == "" {
		return armmonitor.ActionGroupResource{}, "", "", fmt.Errorf("name is required")
	}

	params := monitorActionGroupParams(props)
	if azureTags := formaeTagsToAzureTags(payload); azureTags != nil {
		params.Tags = azureTags
	}

	result, err := m.api.CreateOrUpdate(ctx, props.ResourceGroupName, name, params, nil)
	if err != nil {
		return armmonitor.ActionGroupResource{}, props.ResourceGroupName, name, err
	}
	return result.ActionGroupResource, props.ResourceGroupName, name, nil
}

func (m *MonitorActionGroup) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	ag, rgName, name, err := m.upsert(ctx, request.Properties, request.Label)
	if err != nil {
		if rgName == "" || name == "" {
			return nil, err
		}
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	propsJSON, err := serializeMonitorActionGroup(ag, rgName, name)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize ActionGroup properties: %w", err)
	}

	nativeID := ""
	if ag.ID != nil {
		nativeID = *ag.ID
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

func (m *MonitorActionGroup) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, name, err := monitorActionGroupIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := m.api.Get(ctx, rgName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := serializeMonitorActionGroup(result.ActionGroupResource, rgName, name)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize ActionGroup properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeMonitorActionGroup,
		Properties:   string(propsJSON),
	}, nil
}

func (m *MonitorActionGroup) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	ag, rgName, name, err := m.upsert(ctx, request.DesiredProperties, "")
	if err != nil {
		if rgName == "" || name == "" {
			return nil, err
		}
		return &resource.UpdateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationUpdate,
				OperationStatus: resource.OperationStatusFailure,
				NativeID:        request.NativeID,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	propsJSON, err := serializeMonitorActionGroup(ag, rgName, name)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize ActionGroup properties after update: %w", err)
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

func (m *MonitorActionGroup) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, name, err := monitorActionGroupIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	if _, err := m.api.Delete(ctx, rgName, name, nil); err != nil {
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

// Action-group writes are synchronous, so Status just re-reads.
func (m *MonitorActionGroup) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	rgName, name, err := monitorActionGroupIDParts(request.NativeID)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
			},
		}, err
	}

	result, err := m.api.Get(ctx, rgName, name, nil)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       operationErrorCode(err),
			},
		}, fmt.Errorf("failed to get ActionGroup status: %w", err)
	}

	propsJSON, err := serializeMonitorActionGroup(result.ActionGroupResource, rgName, name)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize ActionGroup properties: %w", err)
	}
	nativeID := request.NativeID
	if result.ID != nil {
		nativeID = *result.ID
	}
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus:    resource.OperationStatusSuccess,
			RequestID:          request.RequestID,
			NativeID:           nativeID,
			ResourceProperties: propsJSON,
		},
	}, nil
}

func (m *MonitorActionGroup) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]

	var nativeIDs []string

	if rgName != "" {
		pager := m.api.NewListByResourceGroupPager(rgName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list action groups: %w", err)
			}
			for _, ag := range page.Value {
				if ag.ID != nil {
					nativeIDs = append(nativeIDs, *ag.ID)
				}
			}
		}
		return &resource.ListResult{NativeIDs: nativeIDs}, nil
	}

	pager := m.api.NewListBySubscriptionIDPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list action groups: %w", err)
		}
		for _, ag := range page.Value {
			if ag.ID != nil {
				nativeIDs = append(nativeIDs, *ag.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
