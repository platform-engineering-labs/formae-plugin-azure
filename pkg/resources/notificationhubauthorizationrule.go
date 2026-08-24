// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/notificationhubs/armnotificationhubs"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeNotificationHubAuthorizationRule = "AZURE::NotificationHubs::NotificationHubAuthorizationRule"

// notificationHubAuthRulesAPI is the armnotificationhubs surface used here.
// Authorization rules hang off the notification hubs client (named simply Client
// in this SDK) rather than having one of their own, and every call is synchronous
// — there is no PATCH verb, so an update is another CreateOrUpdate.
type notificationHubAuthRulesAPI interface {
	CreateOrUpdateAuthorizationRule(ctx context.Context, resourceGroupName string, namespaceName string, notificationHubName string, authorizationRuleName string, parameters armnotificationhubs.SharedAccessAuthorizationRuleCreateOrUpdateParameters, options *armnotificationhubs.ClientCreateOrUpdateAuthorizationRuleOptions) (armnotificationhubs.ClientCreateOrUpdateAuthorizationRuleResponse, error)
	GetAuthorizationRule(ctx context.Context, resourceGroupName string, namespaceName string, notificationHubName string, authorizationRuleName string, options *armnotificationhubs.ClientGetAuthorizationRuleOptions) (armnotificationhubs.ClientGetAuthorizationRuleResponse, error)
	DeleteAuthorizationRule(ctx context.Context, resourceGroupName string, namespaceName string, notificationHubName string, authorizationRuleName string, options *armnotificationhubs.ClientDeleteAuthorizationRuleOptions) (armnotificationhubs.ClientDeleteAuthorizationRuleResponse, error)
	NewListAuthorizationRulesPager(resourceGroupName string, namespaceName string, notificationHubName string, options *armnotificationhubs.ClientListAuthorizationRulesOptions) *runtime.Pager[armnotificationhubs.ClientListAuthorizationRulesResponse]
}

func init() {
	registry.Register(ResourceTypeNotificationHubAuthorizationRule, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &NotificationHubAuthorizationRule{
			api:    c.NotificationHubsClient,
			config: cfg,
		}
	})
}

// NotificationHubAuthorizationRule is the provisioner for SAS rules scoped to a
// single notification hub
// (Microsoft.NotificationHubs/namespaces/notificationHubs/authorizationRules).
//
// The rule's keys are never serialized: ARM returns them only from a separate
// ListKeys call, so putting them in resource state would persist live credentials.
type NotificationHubAuthorizationRule struct {
	api    notificationHubAuthRulesAPI
	config *config.Config
}

// notificationHubAuthRuleProps mirrors
// schema/pkl/notificationhubs/notificationhubauthorizationrule.pkl.
type notificationHubAuthRuleProps struct {
	Name                string   `json:"name"`
	ResourceGroupName   string   `json:"resourceGroupName"`
	NamespaceName       string   `json:"namespaceName"`
	NotificationHubName string   `json:"notificationHubName"`
	Rights              []string `json:"rights"`
}

// notificationHubAccessRights converts the schema's rights into the ARM shape.
// Order is echoed as sent: ARM treats the rights as a set, and sorting them here
// would only make a desired list written in another order look like drift.
func notificationHubAccessRights(rights []string) []*armnotificationhubs.AccessRights {
	if len(rights) == 0 {
		return nil
	}
	out := make([]*armnotificationhubs.AccessRights, 0, len(rights))
	for _, right := range rights {
		if right == "" {
			continue
		}
		out = append(out, to.Ptr(armnotificationhubs.AccessRights(right)))
	}
	return out
}

func notificationHubAuthRuleIDParts(resourceID string) (rgName, namespaceName, hubName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "namespaces", "notificationhubs", "authorizationrules")
	if err != nil {
		return "", "", "", "", err
	}
	return rgName, names["namespaces"], names["notificationhubs"], names["authorizationrules"], nil
}

func (a *NotificationHubAuthorizationRule) buildPropertiesFromResult(rule *armnotificationhubs.SharedAccessAuthorizationRuleResource, rgName, namespaceName, hubName string) map[string]any {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	props["namespaceName"] = namespaceName
	props["notificationHubName"] = hubName

	if rule.ID != nil {
		props["id"] = *rule.ID
	}
	if rule.Name != nil {
		props["name"] = *rule.Name
	}

	// Unlike the Relay rules, this ARM type returns primaryKey and secondaryKey
	// INLINE from Get. They are live credentials, so only rights is taken from the
	// response — keyName, claimType, claimValue, revision, createdTime and
	// modifiedTime are dropped as well, being service bookkeeping rather than
	// desired state.
	if p := rule.Properties; p != nil && len(p.Rights) > 0 {
		rights := make([]string, 0, len(p.Rights))
		for _, right := range p.Rights {
			if right == nil {
				continue
			}
			rights = append(rights, canonicalizeEnum(string(*right), "Listen", "Send", "Manage"))
		}
		props["rights"] = rights
	}

	return props
}

func (a *NotificationHubAuthorizationRule) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props notificationHubAuthRuleProps
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	if props.NamespaceName == "" {
		return nil, fmt.Errorf("namespaceName is required")
	}
	if props.NotificationHubName == "" {
		return nil, fmt.Errorf("notificationHubName is required")
	}
	if len(props.Rights) == 0 {
		return nil, fmt.Errorf("rights is required")
	}
	name := props.Name
	if name == "" {
		name = request.Label
	}
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}

	result, err := a.api.CreateOrUpdateAuthorizationRule(ctx, props.ResourceGroupName, props.NamespaceName,
		props.NotificationHubName, name,
		armnotificationhubs.SharedAccessAuthorizationRuleCreateOrUpdateParameters{
			Properties: &armnotificationhubs.SharedAccessAuthorizationRuleProperties{Rights: notificationHubAccessRights(props.Rights)},
		}, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	nativeID := ""
	if result.ID != nil {
		nativeID = *result.ID
	}
	propsJSON, err := json.Marshal(a.buildPropertiesFromResult(&result.SharedAccessAuthorizationRuleResource,
		props.ResourceGroupName, props.NamespaceName, props.NotificationHubName))
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

func (a *NotificationHubAuthorizationRule) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, namespaceName, hubName, name, err := notificationHubAuthRuleIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := a.api.GetAuthorizationRule(ctx, rgName, namespaceName, hubName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(a.buildPropertiesFromResult(&result.SharedAccessAuthorizationRuleResource, rgName, namespaceName, hubName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeNotificationHubAuthorizationRule,
		Properties:   string(propsJSON),
	}, nil
}

// Update re-PUTs through CreateOrUpdateAuthorizationRule: this API has no PATCH
// verb. rights is the only mutable property, so it is the only thing an update can
// carry.
func (a *NotificationHubAuthorizationRule) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, namespaceName, hubName, name, err := notificationHubAuthRuleIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props notificationHubAuthRuleProps
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	result, err := a.api.CreateOrUpdateAuthorizationRule(ctx, rgName, namespaceName, hubName, name,
		armnotificationhubs.SharedAccessAuthorizationRuleCreateOrUpdateParameters{
			Properties: &armnotificationhubs.SharedAccessAuthorizationRuleProperties{Rights: notificationHubAccessRights(props.Rights)},
		}, nil)
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

	propsJSON, err := json.Marshal(a.buildPropertiesFromResult(&result.SharedAccessAuthorizationRuleResource, rgName, namespaceName, hubName))
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

func (a *NotificationHubAuthorizationRule) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, namespaceName, hubName, name, err := notificationHubAuthRuleIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	if _, err := a.api.DeleteAuthorizationRule(ctx, rgName, namespaceName, hubName, name, nil); err != nil && !isDeleteSuccessError(err) {
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

// Status is never reached with real work to do: every operation on an
// authorization rule is synchronous, so it echoes success.
func (a *NotificationHubAuthorizationRule) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

// List requires the resource group, the namespace and the hub: ARM has no listing
// above the hub scope.
func (a *NotificationHubAuthorizationRule) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	namespaceName := request.AdditionalProperties["namespaceName"]
	hubName := request.AdditionalProperties["notificationHubName"]
	if rgName == "" || namespaceName == "" || hubName == "" {
		return &resource.ListResult{}, nil
	}

	var nativeIDs []string
	pager := a.api.NewListAuthorizationRulesPager(rgName, namespaceName, hubName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list notification hub authorization rules: %w", err)
		}
		for _, rule := range page.Value {
			if rule.ID != nil {
				nativeIDs = append(nativeIDs, *rule.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
