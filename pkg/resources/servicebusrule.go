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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/servicebus/armservicebus"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeServiceBusRule = "AZURE::ServiceBus::Rule"

// serviceBusRulesAPI is the armservicebus surface used here. Every call is
// synchronous, and every one takes the full four-level parent path: namespace,
// topic, subscription, then the rule itself. There is no PATCH verb, so an update
// is another CreateOrUpdate.
type serviceBusRulesAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName string, namespaceName string, topicName string, subscriptionName string, ruleName string, parameters armservicebus.Rule, options *armservicebus.RulesClientCreateOrUpdateOptions) (armservicebus.RulesClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName string, namespaceName string, topicName string, subscriptionName string, ruleName string, options *armservicebus.RulesClientGetOptions) (armservicebus.RulesClientGetResponse, error)
	Delete(ctx context.Context, resourceGroupName string, namespaceName string, topicName string, subscriptionName string, ruleName string, options *armservicebus.RulesClientDeleteOptions) (armservicebus.RulesClientDeleteResponse, error)
	NewListBySubscriptionsPager(resourceGroupName string, namespaceName string, topicName string, subscriptionName string, options *armservicebus.RulesClientListBySubscriptionsOptions) *runtime.Pager[armservicebus.RulesClientListBySubscriptionsResponse]
}

func init() {
	registry.Register(ResourceTypeServiceBusRule, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &ServiceBusRule{
			api:    c.ServiceBusRulesClient,
			config: cfg,
		}
	})
}

// ServiceBusRule is the provisioner for filter rules on a Service Bus topic
// subscription
// (Microsoft.ServiceBus/namespaces/topics/subscriptions/rules).
type ServiceBusRule struct {
	api    serviceBusRulesAPI
	config *config.Config
}

// serviceBusRuleProps mirrors schema/pkl/servicebus/rule.pkl.
type serviceBusRuleProps struct {
	Name              string                            `json:"name"`
	ResourceGroupName string                            `json:"resourceGroupName"`
	NamespaceName     string                            `json:"namespaceName"`
	TopicName         string                            `json:"topicName"`
	SubscriptionName  string                            `json:"subscriptionName"`
	FilterType        string                            `json:"filterType"`
	SQLFilter         *serviceBusSQLFilterProps         `json:"sqlFilter"`
	CorrelationFilter *serviceBusCorrelationFilterProps `json:"correlationFilter"`
	Action            *serviceBusRuleActionProps        `json:"action"`
}

type serviceBusSQLFilterProps struct {
	SQLExpression string `json:"sqlExpression"`
}

type serviceBusRuleActionProps struct {
	SQLExpression string `json:"sqlExpression"`
}

type serviceBusCorrelationFilterProps struct {
	CorrelationID *string `json:"correlationId"`
	Label         *string `json:"label"`
	ContentType   *string `json:"contentType"`
	MessageID     *string `json:"messageId"`
	ReplyTo       *string `json:"replyTo"`
	SessionID     *string `json:"sessionId"`
	To            *string `json:"to"`
}

func serviceBusRuleIDParts(resourceID string) (rgName, namespaceName, topicName, subscriptionName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "namespaces", "topics", "subscriptions", "rules")
	if err != nil {
		return "", "", "", "", "", err
	}
	return rgName, names["namespaces"], names["topics"], names["subscriptions"], names["rules"], nil
}

func (r *ServiceBusRule) buildPropertiesFromResult(rule *armservicebus.Rule, rgName, namespaceName, topicName, subscriptionName string) map[string]any {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	props["namespaceName"] = namespaceName
	props["topicName"] = topicName
	props["subscriptionName"] = subscriptionName

	if rule.ID != nil {
		props["id"] = *rule.ID
	}
	if rule.Name != nil {
		props["name"] = *rule.Name
	}

	if p := rule.Properties; p != nil {
		if p.FilterType != nil {
			props["filterType"] = canonicalizeEnum(string(*p.FilterType), "SqlFilter", "CorrelationFilter")
		}

		// Only sqlExpression is taken from the filter and action blocks. ARM also
		// echoes compatibilityLevel and requiresPreprocessing on both, and neither is
		// modelled: nested fields carrying provider defaults read back as drift.
		if f := p.SQLFilter; f != nil && f.SQLExpression != nil {
			props["sqlFilter"] = map[string]any{"sqlExpression": *f.SQLExpression}
		}
		if a := p.Action; a != nil && a.SQLExpression != nil {
			props["action"] = map[string]any{"sqlExpression": *a.SQLExpression}
		}

		if f := p.CorrelationFilter; f != nil {
			filter := make(map[string]any)
			for key, value := range map[string]*string{
				"correlationId": f.CorrelationID,
				"label":         f.Label,
				"contentType":   f.ContentType,
				"messageId":     f.MessageID,
				"replyTo":       f.ReplyTo,
				"sessionId":     f.SessionID,
				"to":            f.To,
			} {
				if value != nil && *value != "" {
					filter[key] = *value
				}
			}
			// f.Properties (user-defined property matches) is not modelled.
			if len(filter) > 0 {
				props["correlationFilter"] = filter
			}
		}
	}

	return props
}

// serviceBusRuleParams builds the request body shared by create and update. Only
// the filter block matching filterType is sent: ARM ignores the other, and sending
// both invites it to echo an empty one back.
func serviceBusRuleParams(props serviceBusRuleProps) armservicebus.Rule {
	ruleProps := &armservicebus.Ruleproperties{
		FilterType: to.Ptr(armservicebus.FilterType(props.FilterType)),
	}

	switch props.FilterType {
	case string(armservicebus.FilterTypeSQLFilter):
		if props.SQLFilter != nil {
			ruleProps.SQLFilter = &armservicebus.SQLFilter{
				SQLExpression: to.Ptr(props.SQLFilter.SQLExpression),
			}
		}
	case string(armservicebus.FilterTypeCorrelationFilter):
		if f := props.CorrelationFilter; f != nil {
			ruleProps.CorrelationFilter = &armservicebus.CorrelationFilter{
				CorrelationID: f.CorrelationID,
				Label:         f.Label,
				ContentType:   f.ContentType,
				MessageID:     f.MessageID,
				ReplyTo:       f.ReplyTo,
				SessionID:     f.SessionID,
				To:            f.To,
			}
		}
	}

	if props.Action != nil && props.Action.SQLExpression != "" {
		ruleProps.Action = &armservicebus.Action{SQLExpression: to.Ptr(props.Action.SQLExpression)}
	}

	return armservicebus.Rule{Properties: ruleProps}
}

// upsert backs both Create and Update: this API has no PATCH verb.
func (r *ServiceBusRule) upsert(ctx context.Context, payload json.RawMessage, label string) (armservicebus.Rule, serviceBusRuleProps, string, error) {
	var props serviceBusRuleProps
	if err := json.Unmarshal(payload, &props); err != nil {
		return armservicebus.Rule{}, props, "", fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return armservicebus.Rule{}, props, "", fmt.Errorf("resourceGroupName is required")
	}
	if props.NamespaceName == "" {
		return armservicebus.Rule{}, props, "", fmt.Errorf("namespaceName is required")
	}
	if props.TopicName == "" {
		return armservicebus.Rule{}, props, "", fmt.Errorf("topicName is required")
	}
	if props.SubscriptionName == "" {
		return armservicebus.Rule{}, props, "", fmt.Errorf("subscriptionName is required")
	}
	if props.FilterType == "" {
		return armservicebus.Rule{}, props, "", fmt.Errorf("filterType is required")
	}
	if props.FilterType == string(armservicebus.FilterTypeSQLFilter) && (props.SQLFilter == nil || props.SQLFilter.SQLExpression == "") {
		return armservicebus.Rule{}, props, "", fmt.Errorf("sqlFilter.sqlExpression is required when filterType is SqlFilter")
	}
	if props.FilterType == string(armservicebus.FilterTypeCorrelationFilter) && props.CorrelationFilter == nil {
		return armservicebus.Rule{}, props, "", fmt.Errorf("correlationFilter is required when filterType is CorrelationFilter")
	}
	name := props.Name
	if name == "" {
		name = label
	}
	if name == "" {
		return armservicebus.Rule{}, props, "", fmt.Errorf("name is required")
	}

	result, err := r.api.CreateOrUpdate(ctx, props.ResourceGroupName, props.NamespaceName,
		props.TopicName, props.SubscriptionName, name, serviceBusRuleParams(props), nil)
	if err != nil {
		return armservicebus.Rule{}, props, name, err
	}
	return result.Rule, props, name, nil
}

func (r *ServiceBusRule) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	created, props, name, err := r.upsert(ctx, request.Properties, request.Label)
	if err != nil {
		if name == "" {
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

	nativeID := ""
	if created.ID != nil {
		nativeID = *created.ID
	}
	propsJSON, err := json.Marshal(r.buildPropertiesFromResult(&created,
		props.ResourceGroupName, props.NamespaceName, props.TopicName, props.SubscriptionName))
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

func (r *ServiceBusRule) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, namespaceName, topicName, subscriptionName, name, err := serviceBusRuleIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := r.api.Get(ctx, rgName, namespaceName, topicName, subscriptionName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(r.buildPropertiesFromResult(&result.Rule,
		rgName, namespaceName, topicName, subscriptionName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeServiceBusRule,
		Properties:   string(propsJSON),
	}, nil
}

func (r *ServiceBusRule) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	updated, props, name, err := r.upsert(ctx, request.DesiredProperties, "")
	if err != nil {
		if name == "" {
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

	propsJSON, err := json.Marshal(r.buildPropertiesFromResult(&updated,
		props.ResourceGroupName, props.NamespaceName, props.TopicName, props.SubscriptionName))
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

func (r *ServiceBusRule) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, namespaceName, topicName, subscriptionName, name, err := serviceBusRuleIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	if _, err := r.api.Delete(ctx, rgName, namespaceName, topicName, subscriptionName, name, nil); err != nil && !isDeleteSuccessError(err) {
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

// Status is never reached with real work to do: every operation on a rule is
// synchronous, so it echoes success.
func (r *ServiceBusRule) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

// List needs all four parents: ARM has no listing above the subscription scope.
func (r *ServiceBusRule) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	namespaceName := request.AdditionalProperties["namespaceName"]
	topicName := request.AdditionalProperties["topicName"]
	subscriptionName := request.AdditionalProperties["subscriptionName"]
	if rgName == "" || namespaceName == "" || topicName == "" || subscriptionName == "" {
		return &resource.ListResult{}, nil
	}

	var nativeIDs []string
	pager := r.api.NewListBySubscriptionsPager(rgName, namespaceName, topicName, subscriptionName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list service bus rules: %w", err)
		}
		for _, rule := range page.Value {
			if rule.ID != nil {
				nativeIDs = append(nativeIDs, *rule.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
