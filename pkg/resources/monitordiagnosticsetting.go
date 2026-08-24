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

const ResourceTypeMonitorDiagnosticSetting = "AZURE::Insights::DiagnosticSetting"

// diagnosticSettingSegment is the ARM path segment that separates a diagnostic
// setting's target resource from its own name. Matched case-insensitively: ARM
// echoes it back as "microsoft.insights" (lowercase) even when sent capitalised.
const diagnosticSettingSegment = "/providers/microsoft.insights/diagnosticsettings/"

// monitorDiagnosticSettingsAPI is the armmonitor surface used here. Every call is
// scope-based (resourceURI) rather than resource-group-based, and synchronous.
type monitorDiagnosticSettingsAPI interface {
	CreateOrUpdate(ctx context.Context, resourceURI string, name string, parameters armmonitor.DiagnosticSettingsResource, options *armmonitor.DiagnosticSettingsClientCreateOrUpdateOptions) (armmonitor.DiagnosticSettingsClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceURI string, name string, options *armmonitor.DiagnosticSettingsClientGetOptions) (armmonitor.DiagnosticSettingsClientGetResponse, error)
	Delete(ctx context.Context, resourceURI string, name string, options *armmonitor.DiagnosticSettingsClientDeleteOptions) (armmonitor.DiagnosticSettingsClientDeleteResponse, error)
	NewListPager(resourceURI string, options *armmonitor.DiagnosticSettingsClientListOptions) *runtime.Pager[armmonitor.DiagnosticSettingsClientListResponse]
}

func init() {
	registry.Register(ResourceTypeMonitorDiagnosticSetting, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &MonitorDiagnosticSetting{api: c.MonitorDiagnosticSettingsClient, config: cfg}
	})
}

// MonitorDiagnosticSetting is the provisioner for Azure Monitor diagnostic
// settings (Microsoft.Insights/diagnosticSettings).
//
// It is an ARM extension resource: it lives under whatever resource it monitors,
// so its NativeID is <targetResourceId>/providers/Microsoft.Insights/diagnosticSettings/<name>
// and it has no resource group of its own. That is why armIDParts is not used
// here — the target half of the id is an opaque resource id of any type.
type MonitorDiagnosticSetting struct {
	api    monitorDiagnosticSettingsAPI
	config *config.Config
}

// monitorDiagnosticSettingProps mirrors schema/pkl/insights/diagnosticsetting.pkl.
type monitorDiagnosticSettingProps struct {
	Name             string                    `json:"name"`
	TargetResourceID string                    `json:"targetResourceId"`
	WorkspaceID      string                    `json:"workspaceId"`
	StorageAccountID string                    `json:"storageAccountId"`
	Logs             []diagnosticLogSetting    `json:"logs"`
	Metrics          []diagnosticMetricSetting `json:"metrics"`
}

type diagnosticLogSetting struct {
	Category      string `json:"category"`
	CategoryGroup string `json:"categoryGroup"`
}

type diagnosticMetricSetting struct {
	Category string `json:"category"`
}

// diagnosticSettingNativeID composes the extension-resource id.
func diagnosticSettingNativeID(targetResourceID, name string) string {
	return strings.TrimRight(targetResourceID, "/") + "/providers/Microsoft.Insights/diagnosticSettings/" + name
}

// parseDiagnosticSettingID splits the extension-resource id back into the target
// resource id and the setting name.
func parseDiagnosticSettingID(nativeID string) (targetResourceID, name string, err error) {
	idx := strings.Index(strings.ToLower(nativeID), diagnosticSettingSegment)
	if idx < 0 {
		return "", "", fmt.Errorf("invalid diagnostic setting id %q: expected <targetResourceId>%s<name>", nativeID, diagnosticSettingSegment)
	}
	targetResourceID = nativeID[:idx]
	name = nativeID[idx+len(diagnosticSettingSegment):]
	if targetResourceID == "" || name == "" || strings.Contains(name, "/") {
		return "", "", fmt.Errorf("invalid diagnostic setting id %q", nativeID)
	}
	return targetResourceID, name, nil
}

func serializeMonitorDiagnosticSetting(ds armmonitor.DiagnosticSettingsResource, targetResourceID, name string) (json.RawMessage, error) {
	props := map[string]any{
		"targetResourceId": targetResourceID,
		"name":             name,
	}
	if ds.Name != nil {
		props["name"] = *ds.Name
	}
	if ds.ID != nil {
		props["id"] = *ds.ID
	}

	if ds.Properties != nil {
		if ds.Properties.WorkspaceID != nil {
			props["workspaceId"] = *ds.Properties.WorkspaceID
		}
		if ds.Properties.StorageAccountID != nil {
			props["storageAccountId"] = *ds.Properties.StorageAccountID
		}

		// ARM returns every category the target supports, disabling the ones that
		// were not requested. Only the enabled ones are real desired state; keeping
		// the disabled ones would drift against a subset declaration forever.
		logs := make([]map[string]any, 0, len(ds.Properties.Logs))
		for _, l := range ds.Properties.Logs {
			if l == nil || l.Enabled == nil || !*l.Enabled {
				continue
			}
			entry := map[string]any{}
			if l.Category != nil {
				entry["category"] = *l.Category
			}
			if l.CategoryGroup != nil {
				entry["categoryGroup"] = *l.CategoryGroup
			}
			logs = append(logs, entry)
		}
		if len(logs) > 0 {
			props["logs"] = logs
		}

		metrics := make([]map[string]any, 0, len(ds.Properties.Metrics))
		for _, m := range ds.Properties.Metrics {
			if m == nil || m.Enabled == nil || !*m.Enabled {
				continue
			}
			entry := map[string]any{}
			if m.Category != nil {
				entry["category"] = *m.Category
			}
			metrics = append(metrics, entry)
		}
		if len(metrics) > 0 {
			props["metrics"] = metrics
		}
	}

	return json.Marshal(props)
}

func monitorDiagnosticSettingParams(props monitorDiagnosticSettingProps) armmonitor.DiagnosticSettingsResource {
	settings := &armmonitor.DiagnosticSettings{}
	if props.WorkspaceID != "" {
		settings.WorkspaceID = to.Ptr(props.WorkspaceID)
	}
	if props.StorageAccountID != "" {
		settings.StorageAccountID = to.Ptr(props.StorageAccountID)
	}

	// Listing a category is the instruction to route it, so everything sent is
	// enabled; a category the caller dropped simply stops being sent.
	for _, l := range props.Logs {
		entry := &armmonitor.LogSettings{Enabled: to.Ptr(true)}
		// category and categoryGroup are mutually exclusive in ARM; send whichever
		// the caller set rather than both.
		if l.CategoryGroup != "" {
			entry.CategoryGroup = to.Ptr(l.CategoryGroup)
		} else if l.Category != "" {
			entry.Category = to.Ptr(l.Category)
		}
		settings.Logs = append(settings.Logs, entry)
	}

	for _, m := range props.Metrics {
		category := m.Category
		if category == "" {
			category = "AllMetrics"
		}
		settings.Metrics = append(settings.Metrics, &armmonitor.MetricSettings{
			Category: to.Ptr(category),
			Enabled:  to.Ptr(true),
		})
	}

	return armmonitor.DiagnosticSettingsResource{Properties: settings}
}

func (d *MonitorDiagnosticSetting) upsert(ctx context.Context, payload json.RawMessage, label string) (armmonitor.DiagnosticSettingsResource, string, string, error) {
	var props monitorDiagnosticSettingProps
	if err := json.Unmarshal(payload, &props); err != nil {
		return armmonitor.DiagnosticSettingsResource{}, "", "", fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.TargetResourceID == "" {
		return armmonitor.DiagnosticSettingsResource{}, "", "", fmt.Errorf("targetResourceId is required")
	}
	if props.WorkspaceID == "" && props.StorageAccountID == "" {
		return armmonitor.DiagnosticSettingsResource{}, "", "", fmt.Errorf("at least one destination is required: workspaceId or storageAccountId")
	}
	if len(props.Logs) == 0 && len(props.Metrics) == 0 {
		return armmonitor.DiagnosticSettingsResource{}, "", "", fmt.Errorf("at least one log or metric category is required")
	}
	name := props.Name
	if name == "" {
		name = label
	}
	if name == "" {
		return armmonitor.DiagnosticSettingsResource{}, "", "", fmt.Errorf("name is required")
	}

	result, err := d.api.CreateOrUpdate(ctx, props.TargetResourceID, name, monitorDiagnosticSettingParams(props), nil)
	if err != nil {
		return armmonitor.DiagnosticSettingsResource{}, props.TargetResourceID, name, err
	}
	return result.DiagnosticSettingsResource, props.TargetResourceID, name, nil
}

func (d *MonitorDiagnosticSetting) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	ds, targetResourceID, name, err := d.upsert(ctx, request.Properties, request.Label)
	if err != nil {
		if targetResourceID == "" || name == "" {
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

	propsJSON, err := serializeMonitorDiagnosticSetting(ds, targetResourceID, name)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize DiagnosticSetting properties: %w", err)
	}

	// Prefer ARM's own id; fall back to composing it when the response omits it.
	nativeID := diagnosticSettingNativeID(targetResourceID, name)
	if ds.ID != nil && *ds.ID != "" {
		nativeID = *ds.ID
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

func (d *MonitorDiagnosticSetting) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	targetResourceID, name, err := parseDiagnosticSettingID(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := d.api.Get(ctx, targetResourceID, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := serializeMonitorDiagnosticSetting(result.DiagnosticSettingsResource, targetResourceID, name)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize DiagnosticSetting properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeMonitorDiagnosticSetting,
		Properties:   string(propsJSON),
	}, nil
}

// Update is the same CreateOrUpdate call: ARM replaces the whole setting.
func (d *MonitorDiagnosticSetting) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	ds, targetResourceID, name, err := d.upsert(ctx, request.DesiredProperties, "")
	if err != nil {
		if targetResourceID == "" || name == "" {
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

	propsJSON, err := serializeMonitorDiagnosticSetting(ds, targetResourceID, name)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize DiagnosticSetting properties after update: %w", err)
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

func (d *MonitorDiagnosticSetting) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	targetResourceID, name, err := parseDiagnosticSettingID(request.NativeID)
	if err != nil {
		return nil, err
	}

	if _, err := d.api.Delete(ctx, targetResourceID, name, nil); err != nil {
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

// Diagnostic-setting writes are synchronous, so Status just re-reads.
func (d *MonitorDiagnosticSetting) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	targetResourceID, name, err := parseDiagnosticSettingID(request.NativeID)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
			},
		}, err
	}

	result, err := d.api.Get(ctx, targetResourceID, name, nil)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       operationErrorCode(err),
			},
		}, fmt.Errorf("failed to get DiagnosticSetting status: %w", err)
	}

	propsJSON, err := serializeMonitorDiagnosticSetting(result.DiagnosticSettingsResource, targetResourceID, name)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize DiagnosticSetting properties: %w", err)
	}
	nativeID := request.NativeID
	if result.ID != nil && *result.ID != "" {
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

// List needs a target to scope the lookup: ARM only lists diagnostic settings per
// resource, and there is no subscription-wide enumeration. Discovery therefore
// finds these only when a targetResourceId is supplied.
func (d *MonitorDiagnosticSetting) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	targetResourceID := request.AdditionalProperties["targetResourceId"]
	if targetResourceID == "" {
		return &resource.ListResult{}, nil
	}

	var nativeIDs []string
	pager := d.api.NewListPager(targetResourceID, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list diagnostic settings: %w", err)
		}
		for _, ds := range page.Value {
			if ds.ID != nil {
				nativeIDs = append(nativeIDs, *ds.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
