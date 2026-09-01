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

const ResourceTypeMonitorDataCollectionRuleAssociation = "AZURE::Insights::DataCollectionRuleAssociation"

// dataCollectionRuleAssociationSegment is the ARM path segment that separates an
// association's target resource from its own name. Matched case-insensitively: ARM
// echoes the provider back as "microsoft.insights" (lowercase) on some responses
// even when the request capitalised it.
const dataCollectionRuleAssociationSegment = "/providers/microsoft.insights/datacollectionruleassociations/"

// monitorDataCollectionRuleAssociationsAPI is the armmonitor surface used here.
// Every write is scope-based (resourceURI) rather than resource-group-based, and
// synchronous.
type monitorDataCollectionRuleAssociationsAPI interface {
	Create(ctx context.Context, resourceURI string, associationName string, body armmonitor.DataCollectionRuleAssociationProxyOnlyResource, options *armmonitor.DataCollectionRuleAssociationsClientCreateOptions) (armmonitor.DataCollectionRuleAssociationsClientCreateResponse, error)
	Get(ctx context.Context, resourceURI string, associationName string, options *armmonitor.DataCollectionRuleAssociationsClientGetOptions) (armmonitor.DataCollectionRuleAssociationsClientGetResponse, error)
	Delete(ctx context.Context, resourceURI string, associationName string, options *armmonitor.DataCollectionRuleAssociationsClientDeleteOptions) (armmonitor.DataCollectionRuleAssociationsClientDeleteResponse, error)
	NewListByRulePager(resourceGroupName string, dataCollectionRuleName string, options *armmonitor.DataCollectionRuleAssociationsClientListByRuleOptions) *runtime.Pager[armmonitor.DataCollectionRuleAssociationsClientListByRuleResponse]
}

func init() {
	registry.Register(ResourceTypeMonitorDataCollectionRuleAssociation, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &MonitorDataCollectionRuleAssociation{api: c.MonitorDataCollectionRuleAssociationsClient, config: cfg}
	})
}

// MonitorDataCollectionRuleAssociation is the provisioner for the resource that
// attaches a data collection rule (or endpoint) to a machine
// (Microsoft.Insights/dataCollectionRuleAssociations). A rule on its own collects
// nothing; this is what puts it to work.
//
// Like AZURE::Insights::DiagnosticSetting it is an ARM extension resource: it lives
// under whatever resource it is attached to, so its NativeID is
// <targetResourceId>/providers/Microsoft.Insights/dataCollectionRuleAssociations/<name>
// and it has no resource group of its own. That is why armIDParts is not used here —
// the target half of the id is an opaque resource id of any type.
type MonitorDataCollectionRuleAssociation struct {
	api    monitorDataCollectionRuleAssociationsAPI
	config *config.Config
}

// monitorDataCollectionRuleAssociationProps mirrors
// schema/pkl/insights/datacollectionruleassociation.pkl.
type monitorDataCollectionRuleAssociationProps struct {
	Name                     string `json:"name"`
	TargetResourceID         string `json:"targetResourceId"`
	DataCollectionRuleID     string `json:"dataCollectionRuleId"`
	DataCollectionEndpointID string `json:"dataCollectionEndpointId"`
	Description              string `json:"description"`
}

// dataCollectionRuleAssociationNativeID composes the extension-resource id.
func dataCollectionRuleAssociationNativeID(targetResourceID, name string) string {
	return strings.TrimRight(targetResourceID, "/") + "/providers/Microsoft.Insights/dataCollectionRuleAssociations/" + name
}

// parseDataCollectionRuleAssociationID splits the extension-resource id back into
// the target resource id and the association name.
func parseDataCollectionRuleAssociationID(nativeID string) (targetResourceID, name string, err error) {
	idx := strings.Index(strings.ToLower(nativeID), dataCollectionRuleAssociationSegment)
	if idx < 0 {
		return "", "", fmt.Errorf("invalid data collection rule association id %q: expected <targetResourceId>%s<name>",
			nativeID, dataCollectionRuleAssociationSegment)
	}
	targetResourceID = nativeID[:idx]
	name = nativeID[idx+len(dataCollectionRuleAssociationSegment):]
	if targetResourceID == "" || name == "" || strings.Contains(name, "/") {
		return "", "", fmt.Errorf("invalid data collection rule association id %q", nativeID)
	}
	return targetResourceID, name, nil
}

func serializeMonitorDataCollectionRuleAssociation(association armmonitor.DataCollectionRuleAssociationProxyOnlyResource, targetResourceID, name string) (json.RawMessage, error) {
	props := map[string]any{
		"targetResourceId": targetResourceID,
		"name":             name,
	}
	if association.Name != nil {
		props["name"] = *association.Name
	}
	if association.ID != nil {
		props["id"] = *association.ID
	}

	if p := association.Properties; p != nil {
		if p.DataCollectionRuleID != nil && *p.DataCollectionRuleID != "" {
			props["dataCollectionRuleId"] = *p.DataCollectionRuleID
		}
		if p.DataCollectionEndpointID != nil && *p.DataCollectionEndpointID != "" {
			props["dataCollectionEndpointId"] = *p.DataCollectionEndpointID
		}
		if p.Description != nil && *p.Description != "" {
			props["description"] = *p.Description
		}
		// metadata (which Azure offering provisioned the association) and
		// provisioningState are service state; etag and systemData never belong in
		// desired state.
	}

	return json.Marshal(props)
}

func monitorDataCollectionRuleAssociationParams(props monitorDataCollectionRuleAssociationProps) armmonitor.DataCollectionRuleAssociationProxyOnlyResource {
	properties := &armmonitor.DataCollectionRuleAssociationProxyOnlyResourceProperties{}
	if props.DataCollectionRuleID != "" {
		properties.DataCollectionRuleID = to.Ptr(props.DataCollectionRuleID)
	}
	if props.DataCollectionEndpointID != "" {
		properties.DataCollectionEndpointID = to.Ptr(props.DataCollectionEndpointID)
	}
	if props.Description != "" {
		properties.Description = to.Ptr(props.Description)
	}
	return armmonitor.DataCollectionRuleAssociationProxyOnlyResource{Properties: properties}
}

func (d *MonitorDataCollectionRuleAssociation) upsert(ctx context.Context, payload json.RawMessage, label string) (armmonitor.DataCollectionRuleAssociationProxyOnlyResource, string, string, error) {
	var empty armmonitor.DataCollectionRuleAssociationProxyOnlyResource

	var props monitorDataCollectionRuleAssociationProps
	if err := json.Unmarshal(payload, &props); err != nil {
		return empty, "", "", fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.TargetResourceID == "" {
		return empty, "", "", fmt.Errorf("targetResourceId is required")
	}
	// ARM stores exactly one of the two on an association; sending neither leaves it
	// pointing at nothing, and sending both is rejected.
	if props.DataCollectionRuleID == "" && props.DataCollectionEndpointID == "" {
		return empty, "", "", fmt.Errorf("one of dataCollectionRuleId or dataCollectionEndpointId is required")
	}
	if props.DataCollectionRuleID != "" && props.DataCollectionEndpointID != "" {
		return empty, "", "", fmt.Errorf("dataCollectionRuleId and dataCollectionEndpointId are mutually exclusive")
	}
	name := props.Name
	if name == "" {
		name = label
	}
	if name == "" {
		return empty, "", "", fmt.Errorf("name is required")
	}

	result, err := d.api.Create(ctx, props.TargetResourceID, name,
		monitorDataCollectionRuleAssociationParams(props), nil)
	if err != nil {
		return empty, props.TargetResourceID, name, err
	}
	return result.DataCollectionRuleAssociationProxyOnlyResource, props.TargetResourceID, name, nil
}

func (d *MonitorDataCollectionRuleAssociation) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	association, targetResourceID, name, err := d.upsert(ctx, request.Properties, request.Label)
	if err != nil {
		if targetResourceID == "" || name == "" {
			return nil, err
		}
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
				StatusMessage:   err.Error(),
			},
		}, nil
	}

	propsJSON, err := serializeMonitorDataCollectionRuleAssociation(association, targetResourceID, name)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize DataCollectionRuleAssociation properties: %w", err)
	}

	// Prefer ARM's own id; fall back to composing it when the response omits it.
	nativeID := dataCollectionRuleAssociationNativeID(targetResourceID, name)
	if association.ID != nil && *association.ID != "" {
		nativeID = *association.ID
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

func (d *MonitorDataCollectionRuleAssociation) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	targetResourceID, name, err := parseDataCollectionRuleAssociationID(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := d.api.Get(ctx, targetResourceID, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := serializeMonitorDataCollectionRuleAssociation(result.DataCollectionRuleAssociationProxyOnlyResource, targetResourceID, name)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize DataCollectionRuleAssociation properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeMonitorDataCollectionRuleAssociation,
		Properties:   string(propsJSON),
	}, nil
}

// Update is the same Create call: ARM replaces the whole association. There is no
// PATCH verb for the type.
func (d *MonitorDataCollectionRuleAssociation) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	association, targetResourceID, name, err := d.upsert(ctx, request.DesiredProperties, "")
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
				StatusMessage:   err.Error(),
			},
		}, nil
	}

	propsJSON, err := serializeMonitorDataCollectionRuleAssociation(association, targetResourceID, name)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize DataCollectionRuleAssociation properties after update: %w", err)
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

func (d *MonitorDataCollectionRuleAssociation) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	targetResourceID, name, err := parseDataCollectionRuleAssociationID(request.NativeID)
	if err != nil {
		return nil, err
	}

	if _, err := d.api.Delete(ctx, targetResourceID, name, nil); err != nil && !isDeleteSuccessError(err) {
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

// Status can only ever be asked about an operation that already finished: every
// write here is synchronous.
func (d *MonitorDataCollectionRuleAssociation) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

// List walks the associations of one data collection rule. That is the listing the
// declared parent can drive: discovery hands down the rule's resource group and
// name, and every AdditionalProperties key read here is supplied by the hint's
// listParam block.
//
// ARM offers two other listings, per data collection endpoint and per target
// resource, and neither is used. Nothing supplies their scope: the endpoint is not
// this type's parent, and the target resource is an arbitrary ARM id with no parent
// chain behind it (the same reason AZURE::Insights::DiagnosticSetting is invisible
// to discovery). An association pointing at an endpoint rather than a rule is
// therefore not discoverable, though its CRUD lifecycle works normally.
func (d *MonitorDataCollectionRuleAssociation) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	ruleName := request.AdditionalProperties["dataCollectionRuleName"]
	if rgName == "" || ruleName == "" {
		return &resource.ListResult{}, nil
	}

	var nativeIDs []string
	pager := d.api.NewListByRulePager(rgName, ruleName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list data collection rule associations: %w", err)
		}
		for _, association := range page.Value {
			if association != nil && association.ID != nil {
				nativeIDs = append(nativeIDs, *association.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
