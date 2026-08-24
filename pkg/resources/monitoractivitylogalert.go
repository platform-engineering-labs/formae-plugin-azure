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

const ResourceTypeMonitorActivityLogAlert = "AZURE::Insights::ActivityLogAlert"

// monitorActivityLogAlertsAPI is the armmonitor surface used here; all operations are
// synchronous.
//
// Note: armmonitor is still a pre-1.0 module (v0.13.0), so a future major bump may
// change these signatures.
type monitorActivityLogAlertsAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName string, activityLogAlertName string, activityLogAlertRule armmonitor.ActivityLogAlertResource, options *armmonitor.ActivityLogAlertsClientCreateOrUpdateOptions) (armmonitor.ActivityLogAlertsClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName string, activityLogAlertName string, options *armmonitor.ActivityLogAlertsClientGetOptions) (armmonitor.ActivityLogAlertsClientGetResponse, error)
	Delete(ctx context.Context, resourceGroupName string, activityLogAlertName string, options *armmonitor.ActivityLogAlertsClientDeleteOptions) (armmonitor.ActivityLogAlertsClientDeleteResponse, error)
	NewListByResourceGroupPager(resourceGroupName string, options *armmonitor.ActivityLogAlertsClientListByResourceGroupOptions) *runtime.Pager[armmonitor.ActivityLogAlertsClientListByResourceGroupResponse]
	NewListBySubscriptionIDPager(options *armmonitor.ActivityLogAlertsClientListBySubscriptionIDOptions) *runtime.Pager[armmonitor.ActivityLogAlertsClientListBySubscriptionIDResponse]
}

func init() {
	registry.Register(ResourceTypeMonitorActivityLogAlert, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &MonitorActivityLogAlert{api: c.MonitorActivityLogAlertsClient, config: cfg}
	})
}

// MonitorActivityLogAlert is the provisioner for Azure Monitor action groups
// (Microsoft.Insights/actionGroups).
type MonitorActivityLogAlert struct {
	api    monitorActivityLogAlertsAPI
	config *config.Config
}

// monitorActivityLogAlertProps mirrors schema/pkl/insights/actiongroup.pkl.
type monitorActivityLogAlertProps struct {
	Name              string                       `json:"name"`
	ResourceGroupName string                       `json:"resourceGroupName"`
	Location          string                       `json:"location"`
	Scopes            []string                     `json:"scopes"`
	Conditions        []monitorAlertConditionProps `json:"conditions"`
	ActionGroupIDs    []string                     `json:"actionGroupIds"`
	Description       *string                      `json:"description"`
	Enabled           *bool                        `json:"enabled"`
}

type monitorAlertConditionProps struct {
	Field  string `json:"field"`
	Equals string `json:"equals"`
}

func monitorActivityLogAlertIDParts(resourceID string) (rgName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "activitylogalerts")
	if err != nil {
		return "", "", err
	}
	return rgName, names["activitylogalerts"], nil
}

func serializeMonitorActivityLogAlert(ag armmonitor.ActivityLogAlertResource, rgName, name string) (json.RawMessage, error) {
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

	if p := ag.Properties; p != nil {
		if p.Description != nil {
			props["description"] = *p.Description
		}
		if p.Enabled != nil {
			props["enabled"] = *p.Enabled
		}
		if len(p.Scopes) > 0 {
			scopes := make([]string, 0, len(p.Scopes))
			for _, scope := range p.Scopes {
				if scope == nil {
					continue
				}
				scopes = append(scopes, *scope)
			}
			props["scopes"] = scopes
		}
		if p.Condition != nil && len(p.Condition.AllOf) > 0 {
			conditions := make([]map[string]any, 0, len(p.Condition.AllOf))
			for _, c := range p.Condition.AllOf {
				// anyOf groups and containsAny lists are not modelled, so a condition
				// using either is skipped rather than half-read: surfacing something
				// the schema cannot express would read as drift forever.
				if c == nil || c.Field == nil || c.Equals == nil || len(c.AnyOf) > 0 || len(c.ContainsAny) > 0 {
					continue
				}
				conditions = append(conditions, map[string]any{
					"field":  *c.Field,
					"equals": *c.Equals,
				})
			}
			props["conditions"] = conditions
		}
		if p.Actions != nil && len(p.Actions.ActionGroups) > 0 {
			ids := make([]string, 0, len(p.Actions.ActionGroups))
			for _, action := range p.Actions.ActionGroups {
				if action == nil || action.ActionGroupID == nil {
					continue
				}
				ids = append(ids, *action.ActionGroupID)
			}
			props["actionGroupIds"] = ids
		}
	}

	if tags := azureTagsToFormaeTags(ag.Tags); tags != nil {
		props["Tags"] = tags
	}

	return json.Marshal(props)
}

func monitorActivityLogAlertParams(props monitorActivityLogAlertProps) armmonitor.ActivityLogAlertResource {
	location := props.Location
	if location == "" {
		location = "Global"
	}
	enabled := true
	if props.Enabled != nil {
		enabled = *props.Enabled
	}

	conditions := make([]*armmonitor.AlertRuleAnyOfOrLeafCondition, 0, len(props.Conditions))
	for _, c := range props.Conditions {
		conditions = append(conditions, &armmonitor.AlertRuleAnyOfOrLeafCondition{
			Field:  to.Ptr(c.Field),
			Equals: to.Ptr(c.Equals),
		})
	}

	scopes := make([]*string, 0, len(props.Scopes))
	for _, scope := range props.Scopes {
		scopes = append(scopes, to.Ptr(scope))
	}

	alertProps := &armmonitor.AlertRuleProperties{
		Enabled:     to.Ptr(enabled),
		Scopes:      scopes,
		Condition:   &armmonitor.AlertRuleAllOfCondition{AllOf: conditions},
		Description: props.Description,
	}

	if len(props.ActionGroupIDs) > 0 {
		actions := make([]*armmonitor.ActivityLogAlertActionGroup, 0, len(props.ActionGroupIDs))
		for _, id := range props.ActionGroupIDs {
			actions = append(actions, &armmonitor.ActivityLogAlertActionGroup{ActionGroupID: to.Ptr(id)})
		}
		alertProps.Actions = &armmonitor.ActionList{ActionGroups: actions}
	}

	return armmonitor.ActivityLogAlertResource{
		Location:   to.Ptr(location),
		Properties: alertProps,
	}
}

// upsert backs both Create and Update. The narrow ARM PATCH (AlertRulePatchObject)
// can only toggle `enabled` and tags — it cannot change scopes, conditions or
// action groups — so every write goes through CreateOrUpdate, which replaces the
// rule wholesale.
func (m *MonitorActivityLogAlert) upsert(ctx context.Context, payload json.RawMessage, label string) (armmonitor.ActivityLogAlertResource, string, string, error) {
	var props monitorActivityLogAlertProps
	if err := json.Unmarshal(payload, &props); err != nil {
		return armmonitor.ActivityLogAlertResource{}, "", "", fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return armmonitor.ActivityLogAlertResource{}, "", "", fmt.Errorf("resourceGroupName is required")
	}
	if len(props.Scopes) == 0 {
		return armmonitor.ActivityLogAlertResource{}, "", "", fmt.Errorf("scopes is required")
	}
	if len(props.Conditions) == 0 {
		return armmonitor.ActivityLogAlertResource{}, "", "", fmt.Errorf("conditions is required")
	}
	name := props.Name
	if name == "" {
		name = label
	}
	if name == "" {
		return armmonitor.ActivityLogAlertResource{}, "", "", fmt.Errorf("name is required")
	}

	params := monitorActivityLogAlertParams(props)
	if azureTags := formaeTagsToAzureTags(payload); azureTags != nil {
		params.Tags = azureTags
	}

	result, err := m.api.CreateOrUpdate(ctx, props.ResourceGroupName, name, params, nil)
	if err != nil {
		return armmonitor.ActivityLogAlertResource{}, props.ResourceGroupName, name, err
	}
	return result.ActivityLogAlertResource, props.ResourceGroupName, name, nil
}

func (m *MonitorActivityLogAlert) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
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

	propsJSON, err := serializeMonitorActivityLogAlert(ag, rgName, name)
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

func (m *MonitorActivityLogAlert) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, name, err := monitorActivityLogAlertIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := m.api.Get(ctx, rgName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := serializeMonitorActivityLogAlert(result.ActivityLogAlertResource, rgName, name)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize ActionGroup properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeMonitorActivityLogAlert,
		Properties:   string(propsJSON),
	}, nil
}

func (m *MonitorActivityLogAlert) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
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

	propsJSON, err := serializeMonitorActivityLogAlert(ag, rgName, name)
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

func (m *MonitorActivityLogAlert) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, name, err := monitorActivityLogAlertIDParts(request.NativeID)
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
func (m *MonitorActivityLogAlert) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	rgName, name, err := monitorActivityLogAlertIDParts(request.NativeID)
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

	propsJSON, err := serializeMonitorActivityLogAlert(result.ActivityLogAlertResource, rgName, name)
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

func (m *MonitorActivityLogAlert) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]

	var nativeIDs []string

	if rgName != "" {
		pager := m.api.NewListByResourceGroupPager(rgName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list activity log alerts: %w", err)
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
			return nil, fmt.Errorf("failed to list activity log alerts: %w", err)
		}
		for _, ag := range page.Value {
			if ag.ID != nil {
				nativeIDs = append(nativeIDs, *ag.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
