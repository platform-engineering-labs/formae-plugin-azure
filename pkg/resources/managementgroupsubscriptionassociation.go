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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/managementgroups/armmanagementgroups"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeManagementGroupSubscriptionAssociation = "AZURE::Management::ManagementGroupSubscriptionAssociation"

// managementGroupSubscriptionsAPI is the subset of
// *armmanagementgroups.ManagementGroupSubscriptionsClient used here. Every verb is
// synchronous, and there is no update verb at all — the association IS the pair of
// its two ids.
//
// TENANT-SCOPED: like armmanagementgroups.Client, this client is built without a
// subscription id. The subscription this associates is an argument, not the
// client's own binding, so a target bound to subscription A can perfectly well
// place subscription B under a group.
type managementGroupSubscriptionsAPI interface {
	Create(ctx context.Context, groupID string, subscriptionID string, options *armmanagementgroups.ManagementGroupSubscriptionsClientCreateOptions) (armmanagementgroups.ManagementGroupSubscriptionsClientCreateResponse, error)
	GetSubscription(ctx context.Context, groupID string, subscriptionID string, options *armmanagementgroups.ManagementGroupSubscriptionsClientGetSubscriptionOptions) (armmanagementgroups.ManagementGroupSubscriptionsClientGetSubscriptionResponse, error)
	Delete(ctx context.Context, groupID string, subscriptionID string, options *armmanagementgroups.ManagementGroupSubscriptionsClientDeleteOptions) (armmanagementgroups.ManagementGroupSubscriptionsClientDeleteResponse, error)
	NewGetSubscriptionsUnderManagementGroupPager(groupID string, options *armmanagementgroups.ManagementGroupSubscriptionsClientGetSubscriptionsUnderManagementGroupOptions) *runtime.Pager[armmanagementgroups.ManagementGroupSubscriptionsClientGetSubscriptionsUnderManagementGroupResponse]
}

func init() {
	registry.Register(ResourceTypeManagementGroupSubscriptionAssociation, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &ManagementGroupSubscriptionAssociation{api: c.ManagementGroupSubscriptionsClient, config: cfg}
	})
}

// ManagementGroupSubscriptionAssociation is the provisioner for the placement of a
// subscription under a management group
// (Microsoft.Management/managementGroups/subscriptions).
type ManagementGroupSubscriptionAssociation struct {
	api    managementGroupSubscriptionsAPI
	config *config.Config
}

// managementGroupSubscriptionAssociationProps mirrors
// schema/pkl/management/managementgroupsubscriptionassociation.pkl.
type managementGroupSubscriptionAssociationProps struct {
	ManagementGroupID string `json:"managementGroupId"`
	SubscriptionID    string `json:"subscriptionId"`
}

const managementGroupSubscriptionSegment = "/subscriptions/"

// managementGroupSubscriptionAssociationNativeID composes the association's ARM ID,
// which is the group's ID with the subscription appended:
// /providers/Microsoft.Management/managementGroups/{group}/subscriptions/{sub}
func managementGroupSubscriptionAssociationNativeID(managementGroupID, subscriptionID string) string {
	return managementGroupID + "/subscriptions/" + subscriptionID
}

// managementGroupSubscriptionAssociationIDParts splits the association ID back into
// the management group's fully qualified ID and the subscription's GUID.
func managementGroupSubscriptionAssociationIDParts(resourceID string) (managementGroupID, subscriptionID string, err error) {
	lower := strings.ToLower(resourceID)
	idx := strings.LastIndex(lower, managementGroupSubscriptionSegment)
	if idx < 0 {
		return "", "", fmt.Errorf("not a management group subscription association resource ID: %s", resourceID)
	}
	managementGroupID = resourceID[:idx]
	subscriptionID = resourceID[idx+len(managementGroupSubscriptionSegment):]
	if subscriptionID == "" || strings.Contains(subscriptionID, "/") {
		return "", "", fmt.Errorf("not a management group subscription association resource ID: %s", resourceID)
	}
	if _, err := managementGroupIDParts(managementGroupID); err != nil {
		return "", "", fmt.Errorf("not a management group subscription association resource ID: %s", resourceID)
	}
	return managementGroupID, subscriptionID, nil
}

// normalizeSubscriptionID accepts either a bare GUID or a `/subscriptions/{guid}`
// scope and returns the bare GUID the API takes. Both spellings are common in
// desired state — the scope form is what a resolvable reference to a subscription
// yields — and sending the scope form would produce a doubled path segment.
func normalizeSubscriptionID(value string) string {
	trimmed := strings.Trim(value, "/")
	if idx := strings.LastIndex(strings.ToLower(trimmed), "subscriptions/"); idx >= 0 {
		trimmed = trimmed[idx+len("subscriptions/"):]
	}
	return trimmed
}

func managementGroupSubscriptionAssociationProperties(subscription *armmanagementgroups.SubscriptionUnderManagementGroup, managementGroupID, subscriptionID string) map[string]any {
	props := map[string]any{
		"managementGroupId": managementGroupID,
		"subscriptionId":    subscriptionID,
		"id":                managementGroupSubscriptionAssociationNativeID(managementGroupID, subscriptionID),
	}
	if subscription == nil || subscription.Properties == nil {
		return props
	}
	if subscription.Properties.DisplayName != nil && *subscription.Properties.DisplayName != "" {
		props["displayName"] = *subscription.Properties.DisplayName
	}
	// state, tenant and the parent echo are the service's own view; the parent is
	// already the managementGroupId this resource is addressed by. None is read back.
	return props
}

func (a *ManagementGroupSubscriptionAssociation) parseProps(payload json.RawMessage) (managementGroupSubscriptionAssociationProps, error) {
	var props managementGroupSubscriptionAssociationProps
	if err := json.Unmarshal(payload, &props); err != nil {
		return props, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ManagementGroupID == "" {
		return props, fmt.Errorf("managementGroupId is required")
	}
	if props.SubscriptionID == "" {
		return props, fmt.Errorf("subscriptionId is required")
	}
	if _, err := managementGroupIDParts(props.ManagementGroupID); err != nil {
		return props, fmt.Errorf("managementGroupId must be a fully qualified management group ID: %s", props.ManagementGroupID)
	}
	props.SubscriptionID = normalizeSubscriptionID(props.SubscriptionID)
	if props.SubscriptionID == "" {
		return props, fmt.Errorf("subscriptionId is required")
	}
	return props, nil
}

func (a *ManagementGroupSubscriptionAssociation) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	props, err := a.parseProps(request.Properties)
	if err != nil {
		return nil, err
	}
	groupName, err := managementGroupIDParts(props.ManagementGroupID)
	if err != nil {
		return nil, err
	}

	result, err := a.api.Create(ctx, groupName, props.SubscriptionID, nil)
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

	propsJSON, err := json.Marshal(managementGroupSubscriptionAssociationProperties(
		&result.SubscriptionUnderManagementGroup, props.ManagementGroupID, props.SubscriptionID))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.CreateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:          resource.OperationCreate,
			OperationStatus:    resource.OperationStatusSuccess,
			NativeID:           managementGroupSubscriptionAssociationNativeID(props.ManagementGroupID, props.SubscriptionID),
			ResourceProperties: propsJSON,
		},
	}, nil
}

func (a *ManagementGroupSubscriptionAssociation) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	managementGroupID, subscriptionID, err := managementGroupSubscriptionAssociationIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}
	groupName, err := managementGroupIDParts(managementGroupID)
	if err != nil {
		return nil, err
	}

	result, err := a.api.GetSubscription(ctx, groupName, subscriptionID, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(managementGroupSubscriptionAssociationProperties(
		&result.SubscriptionUnderManagementGroup, managementGroupID, subscriptionID))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeManagementGroupSubscriptionAssociation,
		Properties:   string(propsJSON),
	}, nil
}

// Update is impossible: the association has no mutable field and no PATCH verb.
// Moving a subscription to a different group is a delete and a create, which is
// what marking both fields createOnly makes the planner do.
func (a *ManagementGroupSubscriptionAssociation) Update(_ context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	return &resource.UpdateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationUpdate,
			OperationStatus: resource.OperationStatusFailure,
			NativeID:        request.NativeID,
			ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
			StatusMessage:   "ManagementGroupSubscriptionAssociations are immutable and cannot be updated. Delete and recreate instead.",
		},
	}, fmt.Errorf("ManagementGroupSubscriptionAssociations are immutable and cannot be updated")
}

// Delete moves the subscription back to the TENANT ROOT group. A subscription is
// never unparented, so this does not detach it — it re-parents it to the root.
func (a *ManagementGroupSubscriptionAssociation) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	managementGroupID, subscriptionID, err := managementGroupSubscriptionAssociationIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}
	groupName, err := managementGroupIDParts(managementGroupID)
	if err != nil {
		return nil, err
	}

	if _, err := a.api.Delete(ctx, groupName, subscriptionID, nil); err != nil && !isDeleteSuccessError(err) {
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
func (a *ManagementGroupSubscriptionAssociation) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

// List enumerates the subscriptions under one management group. There is no
// tenant-wide listing of associations, so without a management group to look under
// there is nothing to enumerate — hence the listParam on the schema.
func (a *ManagementGroupSubscriptionAssociation) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	managementGroupID := request.AdditionalProperties["managementGroupId"]
	if managementGroupID == "" {
		return &resource.ListResult{}, nil
	}
	groupName, err := managementGroupIDParts(managementGroupID)
	if err != nil {
		return nil, err
	}

	var nativeIDs []string
	pager := a.api.NewGetSubscriptionsUnderManagementGroupPager(groupName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list subscriptions under management group %s: %w", groupName, err)
		}
		for _, subscription := range page.Value {
			if subscription != nil && subscription.ID != nil {
				nativeIDs = append(nativeIDs, *subscription.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
