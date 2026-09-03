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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/alertsmanagement/armalertsmanagement"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypePrometheusRuleGroup = "AZURE::AlertsManagement::PrometheusRuleGroup"

// prometheusRuleGroupsAPI is the armalertsmanagement surface used here. Every call
// is synchronous.
//
// The client is pinned to api-version 2023-03-01 in pkg/client: armalertsmanagement
// v0.10.0 otherwise defaults this type to the 2021-07-22-preview contract.
type prometheusRuleGroupsAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName, ruleGroupName string, parameters armalertsmanagement.PrometheusRuleGroupResource, options *armalertsmanagement.PrometheusRuleGroupsClientCreateOrUpdateOptions) (armalertsmanagement.PrometheusRuleGroupsClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName, ruleGroupName string, options *armalertsmanagement.PrometheusRuleGroupsClientGetOptions) (armalertsmanagement.PrometheusRuleGroupsClientGetResponse, error)
	Delete(ctx context.Context, resourceGroupName, ruleGroupName string, options *armalertsmanagement.PrometheusRuleGroupsClientDeleteOptions) (armalertsmanagement.PrometheusRuleGroupsClientDeleteResponse, error)
	NewListByResourceGroupPager(resourceGroupName string, options *armalertsmanagement.PrometheusRuleGroupsClientListByResourceGroupOptions) *runtime.Pager[armalertsmanagement.PrometheusRuleGroupsClientListByResourceGroupResponse]
	NewListBySubscriptionPager(options *armalertsmanagement.PrometheusRuleGroupsClientListBySubscriptionOptions) *runtime.Pager[armalertsmanagement.PrometheusRuleGroupsClientListBySubscriptionResponse]
}

func init() {
	registry.Register(ResourceTypePrometheusRuleGroup, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &PrometheusRuleGroup{api: c.PrometheusRuleGroupsClient, config: cfg}
	})
}

// PrometheusRuleGroup is the provisioner for managed Prometheus rule groups
// (Microsoft.AlertsManagement/prometheusRuleGroups).
type PrometheusRuleGroup struct {
	api    prometheusRuleGroupsAPI
	config *config.Config
}

// prometheusRuleGroupProps mirrors
// schema/pkl/alertsmanagement/prometheusrulegroup.pkl.
type prometheusRuleGroupProps struct {
	Name              string                `json:"name"`
	ResourceGroupName string                `json:"resourceGroupName"`
	Location          string                `json:"location"`
	Scopes            []string              `json:"scopes"`
	Rules             []prometheusRuleProps `json:"rules"`
	ClusterName       string                `json:"clusterName"`
	Description       *string               `json:"description"`
	Enabled           *bool                 `json:"enabled"`
	Interval          string                `json:"interval"`
}

type prometheusRuleProps struct {
	Record      string            `json:"record"`
	Alert       string            `json:"alert"`
	Expression  string            `json:"expression"`
	Enabled     *bool             `json:"enabled"`
	For         string            `json:"for"`
	Severity    *int32            `json:"severity"`
	Labels      map[string]string `json:"labels"`
	Annotations map[string]string `json:"annotations"`
}

func prometheusRuleGroupIDParts(resourceID string) (rgName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "prometheusrulegroups")
	if err != nil {
		return "", "", err
	}
	return rgName, names["prometheusrulegroups"], nil
}

// buildPropertiesFromResult reads a rule group back into desired-state shape.
//
// Inside rules[] only what the caller set is emitted, and `enabled` is required by
// the schema so it is always sent and always echoed. That matters because
// `hasProviderDefault` is honoured only on top-level resource properties: a value
// the service filled in inside rules[] would read as "not expected and not a
// provider default" on every sync. ARM's per-rule `actions` and
// `resolveConfiguration` are not modelled and so are not read back either.
func (p *PrometheusRuleGroup) buildPropertiesFromResult(group *armalertsmanagement.PrometheusRuleGroupResource, rgName string) map[string]any {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName

	if group.ID != nil {
		props["id"] = *group.ID
	}
	if group.Name != nil {
		props["name"] = *group.Name
	}
	if group.Location != nil {
		props["location"] = normalizeAzureLocation(*group.Location)
	}
	if tags := azureTagsToFormaeTags(group.Tags); len(tags) > 0 {
		props["Tags"] = tags
	}

	gp := group.Properties
	if gp == nil {
		return props
	}

	if scopes := stringsFromPointers(gp.Scopes); len(scopes) > 0 {
		props["scopes"] = scopes
	}
	if gp.ClusterName != nil && *gp.ClusterName != "" {
		props["clusterName"] = *gp.ClusterName
	}
	if gp.Description != nil && *gp.Description != "" {
		props["description"] = *gp.Description
	}
	if gp.Enabled != nil {
		props["enabled"] = *gp.Enabled
	}
	if gp.Interval != nil && *gp.Interval != "" {
		props["interval"] = *gp.Interval
	}

	rules := make([]map[string]any, 0, len(gp.Rules))
	for _, rule := range gp.Rules {
		if rule == nil {
			continue
		}
		entry := map[string]any{}
		if rule.Record != nil && *rule.Record != "" {
			entry["record"] = *rule.Record
		}
		if rule.Alert != nil && *rule.Alert != "" {
			entry["alert"] = *rule.Alert
		}
		if rule.Expression != nil {
			entry["expression"] = *rule.Expression
		}
		if rule.Enabled != nil {
			entry["enabled"] = *rule.Enabled
		}
		if rule.For != nil && *rule.For != "" {
			entry["for"] = *rule.For
		}
		if rule.Severity != nil {
			entry["severity"] = *rule.Severity
		}
		if labels := stringMapFromPointers(rule.Labels); len(labels) > 0 {
			entry["labels"] = labels
		}
		if annotations := stringMapFromPointers(rule.Annotations); len(annotations) > 0 {
			entry["annotations"] = annotations
		}
		rules = append(rules, entry)
	}
	if len(rules) > 0 {
		props["rules"] = rules
	}

	return props
}

// stringMapFromPointers flattens ARM's map[string]*string into the plain map the
// schema's Mapping fields carry. Nil values are skipped and an empty result comes
// back as nil, so a map ARM echoes back empty does not read as a declared-but-empty
// map.
func stringMapFromPointers(values map[string]*string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]string, len(values))
	for key, value := range values {
		if value == nil {
			continue
		}
		out[key] = *value
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// stringMapToPointers is the write-path inverse of stringMapFromPointers.
func stringMapToPointers(values map[string]string) map[string]*string {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]*string, len(values))
	for key, value := range values {
		out[key] = to.Ptr(value)
	}
	return out
}

// prometheusRuleGroupParams builds the request body shared by create and update.
func prometheusRuleGroupParams(props prometheusRuleGroupProps, payload json.RawMessage) armalertsmanagement.PrometheusRuleGroupResource {
	properties := &armalertsmanagement.PrometheusRuleGroupProperties{
		Scopes: stringPointers(props.Scopes),
	}
	if props.ClusterName != "" {
		properties.ClusterName = to.Ptr(props.ClusterName)
	}
	if props.Description != nil {
		properties.Description = props.Description
	}
	if props.Enabled != nil {
		properties.Enabled = props.Enabled
	}
	if props.Interval != "" {
		properties.Interval = to.Ptr(props.Interval)
	}

	for _, rule := range props.Rules {
		entry := &armalertsmanagement.PrometheusRule{
			Expression:  to.Ptr(rule.Expression),
			Labels:      stringMapToPointers(rule.Labels),
			Annotations: stringMapToPointers(rule.Annotations),
		}
		if rule.Record != "" {
			entry.Record = to.Ptr(rule.Record)
		}
		if rule.Alert != "" {
			entry.Alert = to.Ptr(rule.Alert)
		}
		if rule.Enabled != nil {
			entry.Enabled = rule.Enabled
		}
		if rule.For != "" {
			entry.For = to.Ptr(rule.For)
		}
		if rule.Severity != nil {
			entry.Severity = rule.Severity
		}
		properties.Rules = append(properties.Rules, entry)
	}

	params := armalertsmanagement.PrometheusRuleGroupResource{
		Location:   to.Ptr(props.Location),
		Properties: properties,
	}
	if tags := formaeTagsToAzureTags(payload); len(tags) > 0 {
		params.Tags = tags
	}
	return params
}

func (p *PrometheusRuleGroup) parseProps(payload json.RawMessage, label string) (prometheusRuleGroupProps, string, error) {
	var props prometheusRuleGroupProps
	if err := json.Unmarshal(payload, &props); err != nil {
		return props, "", fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return props, "", fmt.Errorf("resourceGroupName is required")
	}
	if props.Location == "" {
		return props, "", fmt.Errorf("location is required")
	}
	if len(props.Scopes) == 0 {
		return props, "", fmt.Errorf("at least one scope is required: an Azure Monitor workspace ARM id")
	}
	if len(props.Rules) == 0 {
		return props, "", fmt.Errorf("at least one rule is required")
	}
	for _, rule := range props.Rules {
		if rule.Expression == "" {
			return props, "", fmt.Errorf("every rule needs an expression")
		}
		// ARM rejects a rule that is neither a recording rule nor an alerting rule.
		if rule.Record == "" && rule.Alert == "" {
			return props, "", fmt.Errorf("every rule needs either record or alert")
		}
		if rule.Record != "" && rule.Alert != "" {
			return props, "", fmt.Errorf("a rule cannot set both record and alert")
		}
	}
	name := props.Name
	if name == "" {
		name = label
	}
	if name == "" {
		return props, "", fmt.Errorf("name is required")
	}
	return props, name, nil
}

func (p *PrometheusRuleGroup) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	props, name, err := p.parseProps(request.Properties, request.Label)
	if err != nil {
		return nil, err
	}

	result, err := p.api.CreateOrUpdate(ctx, props.ResourceGroupName, name,
		prometheusRuleGroupParams(props, request.Properties), nil)
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
	propsJSON, err := json.Marshal(p.buildPropertiesFromResult(&result.PrometheusRuleGroupResource, props.ResourceGroupName))
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

func (p *PrometheusRuleGroup) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, name, err := prometheusRuleGroupIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := p.api.Get(ctx, rgName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(p.buildPropertiesFromResult(&result.PrometheusRuleGroupResource, rgName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypePrometheusRuleGroup,
		Properties:   string(propsJSON),
	}, nil
}

// Update reissues CreateOrUpdate. The PATCH verb takes
// PrometheusRuleGroupResourcePatch, which reaches only tags and the enabled flag, so
// it cannot change the rules, the scopes or the interval. Location rides along
// because a PUT without it is rejected.
func (p *PrometheusRuleGroup) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, name, err := prometheusRuleGroupIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	props, _, err := p.parseProps(request.DesiredProperties, name)
	if err != nil {
		return nil, err
	}

	result, err := p.api.CreateOrUpdate(ctx, rgName, name,
		prometheusRuleGroupParams(props, request.DesiredProperties), nil)
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

	propsJSON, err := json.Marshal(p.buildPropertiesFromResult(&result.PrometheusRuleGroupResource, rgName))
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

func (p *PrometheusRuleGroup) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, name, err := prometheusRuleGroupIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	if _, err := p.api.Delete(ctx, rgName, name, nil); err != nil && !isDeleteSuccessError(err) {
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
func (p *PrometheusRuleGroup) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

// List narrows to a resource group when one is given, and otherwise walks the whole
// subscription.
func (p *PrometheusRuleGroup) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]

	var nativeIDs []string
	if rgName != "" {
		pager := p.api.NewListByResourceGroupPager(rgName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list Prometheus rule groups: %w", err)
			}
			for _, group := range page.Value {
				if group != nil && group.ID != nil {
					nativeIDs = append(nativeIDs, *group.ID)
				}
			}
		}
		return &resource.ListResult{NativeIDs: nativeIDs}, nil
	}

	pager := p.api.NewListBySubscriptionPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list Prometheus rule groups: %w", err)
		}
		for _, group := range page.Value {
			if group != nil && group.ID != nil {
				nativeIDs = append(nativeIDs, *group.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
