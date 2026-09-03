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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/managementgroups/armmanagementgroups"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeManagementGroup = "AZURE::Management::ManagementGroup"

// managementGroupsAPI is the subset of *armmanagementgroups.Client used here.
//
// Create and delete are LROs; update is a synchronous PATCH that reaches the only
// two mutable fields a group has.
//
// TENANT-SCOPED. Unlike every other client in this plugin, armmanagementgroups.Client
// is constructed WITHOUT a subscription id — its URLs start at
// /providers/Microsoft.Management — so nothing here consults config.SubscriptionId.
type managementGroupsAPI interface {
	BeginCreateOrUpdate(ctx context.Context, groupID string, createManagementGroupRequest armmanagementgroups.CreateManagementGroupRequest, options *armmanagementgroups.ClientBeginCreateOrUpdateOptions) (*runtime.Poller[armmanagementgroups.ClientCreateOrUpdateResponse], error)
	Get(ctx context.Context, groupID string, options *armmanagementgroups.ClientGetOptions) (armmanagementgroups.ClientGetResponse, error)
	Update(ctx context.Context, groupID string, patchGroupRequest armmanagementgroups.PatchManagementGroupRequest, options *armmanagementgroups.ClientUpdateOptions) (armmanagementgroups.ClientUpdateResponse, error)
	BeginDelete(ctx context.Context, groupID string, options *armmanagementgroups.ClientBeginDeleteOptions) (*runtime.Poller[armmanagementgroups.ClientDeleteResponse], error)
	NewListPager(options *armmanagementgroups.ClientListOptions) *runtime.Pager[armmanagementgroups.ClientListResponse]
}

func init() {
	registry.Register(ResourceTypeManagementGroup, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &ManagementGroup{
			api:      c.ManagementGroupsClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// ManagementGroup is the provisioner for management groups
// (Microsoft.Management/managementGroups).
type ManagementGroup struct {
	api      managementGroupsAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

// managementGroupProps mirrors schema/pkl/management/managementgroup.pkl.
type managementGroupProps struct {
	Name        string  `json:"name"`
	DisplayName *string `json:"displayName"`
	ParentID    *string `json:"parentId"`
}

const managementGroupPrefix = "/providers/microsoft.management/managementgroups/"

// managementGroupNativeID composes a group's ARM ID from its group ID.
func managementGroupNativeID(name string) string {
	return "/providers/Microsoft.Management/managementGroups/" + name
}

// managementGroupIDParts recovers the group ID from a management group ARM ID.
// The ID is tenant-rooted rather than subscription-rooted, so armIDParts does not
// apply.
func managementGroupIDParts(resourceID string) (name string, err error) {
	lower := strings.ToLower(resourceID)
	if !strings.HasPrefix(lower, managementGroupPrefix) {
		return "", fmt.Errorf("not a management group resource ID: %s", resourceID)
	}
	name = resourceID[len(managementGroupPrefix):]
	if name == "" || strings.Contains(name, "/") {
		return "", fmt.Errorf("not a management group resource ID: %s", resourceID)
	}
	return name, nil
}

func managementGroupProperties(group *armmanagementgroups.ManagementGroup, name string) map[string]any {
	props := map[string]any{
		"name": name,
		"id":   managementGroupNativeID(name),
	}
	if group == nil {
		return props
	}
	if group.Name != nil && *group.Name != "" {
		props["name"] = *group.Name
	}
	if group.ID != nil && *group.ID != "" {
		props["id"] = *group.ID
	}

	g := group.Properties
	if g == nil {
		return props
	}
	if g.DisplayName != nil && *g.DisplayName != "" {
		props["displayName"] = *g.DisplayName
	}
	if g.TenantID != nil && *g.TenantID != "" {
		props["tenantId"] = *g.TenantID
	}
	if g.Details != nil && g.Details.Parent != nil && g.Details.Parent.ID != nil && *g.Details.Parent.ID != "" {
		props["parentId"] = *g.Details.Parent.ID
	}

	// children is the service's own view of what sits under the group — membership
	// is declared by the child, not here — and updatedBy/updatedTime/version are
	// audit fields. None is read back.
	return props
}

func managementGroupParams(props managementGroupProps, name string) armmanagementgroups.CreateManagementGroupRequest {
	request := armmanagementgroups.CreateManagementGroupRequest{
		Name:       to.Ptr(name),
		Properties: &armmanagementgroups.CreateManagementGroupProperties{},
	}
	if props.DisplayName != nil && *props.DisplayName != "" {
		request.Properties.DisplayName = props.DisplayName
	}
	if props.ParentID != nil && *props.ParentID != "" {
		request.Properties.Details = &armmanagementgroups.CreateManagementGroupDetails{
			Parent: &armmanagementgroups.CreateParentGroupInfo{ID: props.ParentID},
		}
	}
	return request
}

func (m *ManagementGroup) parseProps(payload json.RawMessage, label string) (managementGroupProps, string, error) {
	var props managementGroupProps
	if err := json.Unmarshal(payload, &props); err != nil {
		return props, "", fmt.Errorf("failed to parse resource properties: %w", err)
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

func (m *ManagementGroup) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	props, name, err := m.parseProps(request.Properties, request.Label)
	if err != nil {
		return nil, err
	}

	poller, err := m.api.BeginCreateOrUpdate(ctx, name, managementGroupParams(props, name), nil)
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

	nativeID := managementGroupNativeID(name)

	if poller.Done() {
		result, err := poller.Result(ctx)
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
		propsJSON, err := json.Marshal(managementGroupProperties(&result.ManagementGroup, name))
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

	token, err := poller.ResumeToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get resume token: %w", err)
	}
	reqID, err := encodeLROStart(lroOpCreate, token, nativeID)
	if err != nil {
		return nil, err
	}

	return &resource.CreateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationCreate,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       reqID,
			NativeID:        nativeID,
		},
	}, nil
}

func (m *ManagementGroup) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	name, err := managementGroupIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := m.api.Get(ctx, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(managementGroupProperties(&result.ManagementGroup, name))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeManagementGroup,
		Properties:   string(propsJSON),
	}, nil
}

// Update is a synchronous PATCH. Only displayName and the parent can move; the
// group ID is part of every descendant's resource ID and is createOnly.
//
// Re-parenting takes the whole subtree with it, and ARM performs it as one atomic
// move rather than as a delete and a create.
func (m *ManagementGroup) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	name, err := managementGroupIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	props, _, err := m.parseProps(request.DesiredProperties, name)
	if err != nil {
		return nil, err
	}

	patch := armmanagementgroups.PatchManagementGroupRequest{}
	if props.DisplayName != nil && *props.DisplayName != "" {
		patch.DisplayName = props.DisplayName
	}
	if props.ParentID != nil && *props.ParentID != "" {
		patch.ParentGroupID = props.ParentID
	}

	result, err := m.api.Update(ctx, name, patch, nil)
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

	propsJSON, err := json.Marshal(managementGroupProperties(&result.ManagementGroup, name))
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

// Delete removes the group. ARM refuses while the group still has children, so a
// subscription association or a child group under it must be destroyed first —
// which is what the parent/child edges in the schema express.
func (m *ManagementGroup) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	name, err := managementGroupIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, err := m.api.BeginDelete(ctx, name, nil)
	if err != nil {
		if isDeleteSuccessError(err) {
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
				StatusMessage:   err.Error(),
			},
		}, nil
	}

	if poller.Done() {
		if _, err := poller.Result(ctx); err != nil && !isDeleteSuccessError(err) {
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

	token, err := poller.ResumeToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get resume token: %w", err)
	}
	reqID, err := encodeLROStart(lroOpDelete, token, request.NativeID)
	if err != nil {
		return nil, err
	}

	return &resource.DeleteResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationDelete,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       reqID,
			NativeID:        request.NativeID,
		},
	}, nil
}

func (m *ManagementGroup) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	reqID, err := decodeLROStatus(request.RequestID)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
				StatusMessage:   err.Error(),
			},
		}, err
	}

	switch reqID.OperationType {
	case lroOpCreate:
		return statusLRO(ctx, request, &reqID, resource.OperationCreate,
			func(token string) (*runtime.Poller[armmanagementgroups.ClientCreateOrUpdateResponse], error) {
				return resumePoller[armmanagementgroups.ClientCreateOrUpdateResponse](m.pipeline, token)
			},
			func(_ context.Context, result armmanagementgroups.ClientCreateOrUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				name, err := managementGroupIDParts(reqID.NativeID)
				if err != nil {
					return "", nil, err
				}
				propsJSON, err := json.Marshal(managementGroupProperties(&result.ManagementGroup, name))
				if err != nil {
					return "", nil, fmt.Errorf("failed to marshal response properties: %w", err)
				}
				return reqID.NativeID, propsJSON, nil
			})
	case lroOpDelete:
		return statusDeleteLRO(ctx, request, &reqID,
			func(token string) (*runtime.Poller[armmanagementgroups.ClientDeleteResponse], error) {
				return resumePoller[armmanagementgroups.ClientDeleteResponse](m.pipeline, token)
			}, nil)
	default:
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
				StatusMessage:   fmt.Sprintf("unknown LRO operation type: %s", reqID.OperationType),
			},
		}, fmt.Errorf("unknown LRO operation type: %s", reqID.OperationType)
	}
}

// List enumerates every management group in the tenant the caller can see. There is
// no per-parent listing verb; the hierarchy is read from each group's own parent.
func (m *ManagementGroup) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	var nativeIDs []string
	pager := m.api.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list management groups: %w", err)
		}
		for _, group := range page.Value {
			if group != nil && group.ID != nil {
				nativeIDs = append(nativeIDs, *group.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
