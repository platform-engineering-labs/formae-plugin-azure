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

const ResourceTypeNotificationHub = "AZURE::NotificationHubs::NotificationHub"

// notificationHubsAPI is the armnotificationhubs surface used here. Every call is
// synchronous, including delete — so Status never does real work. Note the client
// is simply named Client in this SDK, not NotificationHubsClient.
type notificationHubsAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName string, namespaceName string, notificationHubName string, parameters armnotificationhubs.NotificationHubCreateOrUpdateParameters, options *armnotificationhubs.ClientCreateOrUpdateOptions) (armnotificationhubs.ClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName string, namespaceName string, notificationHubName string, options *armnotificationhubs.ClientGetOptions) (armnotificationhubs.ClientGetResponse, error)
	Delete(ctx context.Context, resourceGroupName string, namespaceName string, notificationHubName string, options *armnotificationhubs.ClientDeleteOptions) (armnotificationhubs.ClientDeleteResponse, error)
	NewListPager(resourceGroupName string, namespaceName string, options *armnotificationhubs.ClientListOptions) *runtime.Pager[armnotificationhubs.ClientListResponse]
}

func init() {
	registry.Register(ResourceTypeNotificationHub, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &NotificationHub{
			api:    c.NotificationHubsClient,
			config: cfg,
		}
	})
}

// DNSForwardingRule is the provisioner for rules inside a DNS forwarding ruleset
// (Microsoft.Network/dnsForwardingRulesets/forwardingRules).
type NotificationHub struct {
	api    notificationHubsAPI
	config *config.Config
}

// notificationHubProps mirrors schema/pkl/network/dnsforwardingrule.pkl.
type notificationHubProps struct {
	Name              string  `json:"name"`
	Location          string  `json:"location"`
	ResourceGroupName string  `json:"resourceGroupName"`
	NamespaceName     string  `json:"namespaceName"`
	RegistrationTTL   *string `json:"registrationTtl"`
}

// notificationHubParams builds the request body shared by create and update.
// Location is required on every write, even an update: ARM rejects a body without
// it. The PNS credential fields are left nil so an out-of-band credential stays
// untouched — sending an empty block would clear it.
func notificationHubParams(props notificationHubProps, rawProps json.RawMessage) armnotificationhubs.NotificationHubCreateOrUpdateParameters {
	params := armnotificationhubs.NotificationHubCreateOrUpdateParameters{
		Location:   to.Ptr(props.Location),
		Properties: &armnotificationhubs.NotificationHubProperties{RegistrationTTL: props.RegistrationTTL},
	}
	if azureTags := formaeTagsToAzureTags(rawProps); azureTags != nil {
		params.Tags = azureTags
	}
	return params
}

func notificationHubIDParts(resourceID string) (rgName, namespaceName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "namespaces", "notificationhubs")
	if err != nil {
		return "", "", "", err
	}
	return rgName, names["namespaces"], names["notificationhubs"], nil
}

func (n *NotificationHub) buildPropertiesFromResult(hub *armnotificationhubs.NotificationHubResource, rgName, namespaceName string) map[string]any {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	props["namespaceName"] = namespaceName

	if hub.ID != nil {
		props["id"] = *hub.ID
	}
	if hub.Name != nil {
		props["name"] = *hub.Name
	}

	if hub.Location != nil {
		props["location"] = normalizeAzureLocation(*hub.Location)
	}

	if p := hub.Properties; p != nil {
		if p.RegistrationTTL != nil {
			props["registrationTtl"] = *p.RegistrationTTL
		}
		// The six PNS credential blocks are never surfaced: they are live secrets,
		// ARM keeps them behind GetPnsCredentials, and echoing them into state would
		// persist them. The nested authorizationRules list is skipped too — those
		// are their own resource. properties.name duplicates the resource name.
	}

	if tags := azureTagsToFormaeTags(hub.Tags); tags != nil {
		props["Tags"] = tags
	}

	return props
}

func (n *NotificationHub) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props notificationHubProps
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	if props.NamespaceName == "" {
		return nil, fmt.Errorf("namespaceName is required")
	}
	if props.Location == "" {
		return nil, fmt.Errorf("location is required")
	}

	name := props.Name
	if name == "" {
		name = request.Label
	}
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}

	result, err := n.api.CreateOrUpdate(ctx, props.ResourceGroupName, props.NamespaceName, name,
		notificationHubParams(props, request.Properties), nil)
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
	propsJSON, err := json.Marshal(n.buildPropertiesFromResult(&result.NotificationHubResource,
		props.ResourceGroupName, props.NamespaceName))
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

func (n *NotificationHub) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, namespaceName, name, err := notificationHubIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := n.api.Get(ctx, rgName, namespaceName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(n.buildPropertiesFromResult(&result.NotificationHubResource, rgName, namespaceName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeNotificationHub,
		Properties:   string(propsJSON),
	}, nil
}

// Update re-PUTs through CreateOrUpdate. The API does expose a Patch verb, but it
// takes the same full body, so there is nothing to be gained by using it.
func (n *NotificationHub) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, namespaceName, name, err := notificationHubIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props notificationHubProps
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	result, err := n.api.CreateOrUpdate(ctx, rgName, namespaceName, name,
		notificationHubParams(props, request.DesiredProperties), nil)
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

	propsJSON, err := json.Marshal(n.buildPropertiesFromResult(&result.NotificationHubResource, rgName, namespaceName))
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

func (n *NotificationHub) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, namespaceName, name, err := notificationHubIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	if _, err := n.api.Delete(ctx, rgName, namespaceName, name, nil); err != nil && !isDeleteSuccessError(err) {
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

// Status is never reached with real work to do: every operation on a forwarding
// hub is synchronous, so it echoes success.
func (n *NotificationHub) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

// List requires both the resource group and the ruleset name: ARM has no
// subscription-wide listing for forwarding rules.
func (n *NotificationHub) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	namespaceName := request.AdditionalProperties["namespaceName"]
	if rgName == "" || namespaceName == "" {
		return &resource.ListResult{}, nil
	}

	var nativeIDs []string
	pager := n.api.NewListPager(rgName, namespaceName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list notification hubs: %w", err)
		}
		for _, hub := range page.Value {
			if hub.ID != nil {
				nativeIDs = append(nativeIDs, *hub.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
