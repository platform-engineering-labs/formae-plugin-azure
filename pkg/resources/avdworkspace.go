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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/desktopvirtualization/armdesktopvirtualization"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeAvdWorkspace = "AZURE::DesktopVirtualization::Workspace"

// avdWorkspacesAPI is the armdesktopvirtualization surface used here; all
// operations are synchronous.
type avdWorkspacesAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName string, workspaceName string, workspace armdesktopvirtualization.Workspace, options *armdesktopvirtualization.WorkspacesClientCreateOrUpdateOptions) (armdesktopvirtualization.WorkspacesClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName string, workspaceName string, options *armdesktopvirtualization.WorkspacesClientGetOptions) (armdesktopvirtualization.WorkspacesClientGetResponse, error)
	Update(ctx context.Context, resourceGroupName string, workspaceName string, options *armdesktopvirtualization.WorkspacesClientUpdateOptions) (armdesktopvirtualization.WorkspacesClientUpdateResponse, error)
	Delete(ctx context.Context, resourceGroupName string, workspaceName string, options *armdesktopvirtualization.WorkspacesClientDeleteOptions) (armdesktopvirtualization.WorkspacesClientDeleteResponse, error)
	NewListByResourceGroupPager(resourceGroupName string, options *armdesktopvirtualization.WorkspacesClientListByResourceGroupOptions) *runtime.Pager[armdesktopvirtualization.WorkspacesClientListByResourceGroupResponse]
	NewListBySubscriptionPager(options *armdesktopvirtualization.WorkspacesClientListBySubscriptionOptions) *runtime.Pager[armdesktopvirtualization.WorkspacesClientListBySubscriptionResponse]
}

func init() {
	registry.Register(ResourceTypeAvdWorkspace, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &AvdWorkspace{api: c.AvdWorkspacesClient, config: cfg}
	})
}

// AvdWorkspace is the provisioner for Azure Virtual Desktop workspaces
// (Microsoft.DesktopVirtualization/workspaces).
//
// Which application groups appear in the feed is a field,
// applicationGroupReferences, not an association resource: ARM stores the list
// on the workspace and writes the reverse pointer on the group itself.
type AvdWorkspace struct {
	api    avdWorkspacesAPI
	config *config.Config
}

// avdWorkspaceProps mirrors schema/pkl/desktopvirtualization/avdworkspace.pkl.
type avdWorkspaceProps struct {
	Name                       string   `json:"name"`
	Location                   string   `json:"location"`
	ResourceGroupName          string   `json:"resourceGroupName"`
	ApplicationGroupReferences []string `json:"applicationGroupReferences"`
	Description                string   `json:"description"`
	FriendlyName               string   `json:"friendlyName"`
}

func avdWorkspaceIDParts(resourceID string) (rgName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "workspaces")
	if err != nil {
		return "", "", err
	}
	return rgName, names["workspaces"], nil
}

func (a *AvdWorkspace) buildPropertiesFromResult(ws *armdesktopvirtualization.Workspace, rgName string) map[string]any {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName

	if ws.ID != nil {
		props["id"] = *ws.ID
	}
	if ws.Name != nil {
		props["name"] = *ws.Name
	}
	if ws.Location != nil {
		props["location"] = normalizeAzureLocation(*ws.Location)
	}

	if p := ws.Properties; p != nil {
		// An empty list comes back as nil rather than [] so a workspace with no
		// application groups does not read as a declared-but-empty list.
		if refs := stringsFromPointers(p.ApplicationGroupReferences); len(refs) > 0 {
			props["applicationGroupReferences"] = refs
		}
		// ARM answers Get with "" for a description or friendly name that was
		// never set, and desired state carries the field absent — emitting the
		// empty string would report drift on every sync.
		if p.Description != nil && *p.Description != "" {
			props["description"] = *p.Description
		}
		if p.FriendlyName != nil && *p.FriendlyName != "" {
			props["friendlyName"] = *p.FriendlyName
		}
		// objectId and cloudPcResource are deliberately dropped: neither is
		// desired state.
	}

	if tags := azureTagsToFormaeTags(ws.Tags); tags != nil {
		props["Tags"] = tags
	}

	return props
}

func (a *AvdWorkspace) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props avdWorkspaceProps
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
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

	params := armdesktopvirtualization.Workspace{
		Location: to.Ptr(props.Location),
		Properties: &armdesktopvirtualization.WorkspaceProperties{
			ApplicationGroupReferences: stringPointers(props.ApplicationGroupReferences),
		},
	}
	if props.Description != "" {
		params.Properties.Description = to.Ptr(props.Description)
	}
	if props.FriendlyName != "" {
		params.Properties.FriendlyName = to.Ptr(props.FriendlyName)
	}
	if azureTags := formaeTagsToAzureTags(request.Properties); azureTags != nil {
		params.Tags = azureTags
	}

	result, err := a.api.CreateOrUpdate(ctx, props.ResourceGroupName, name, params, nil)
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
	propsJSON, err := json.Marshal(a.buildPropertiesFromResult(&result.Workspace, props.ResourceGroupName))
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

func (a *AvdWorkspace) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, name, err := avdWorkspaceIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := a.api.Get(ctx, rgName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(a.buildPropertiesFromResult(&result.Workspace, rgName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeAvdWorkspace,
		Properties:   string(propsJSON),
	}, nil
}

// Update is a synchronous PATCH.
//
// applicationGroupReferences is sent as the whole list every time, including
// when it is empty: it is a set the caller owns outright, and PATCHing only
// non-empty lists would make removing the last application group impossible.
func (a *AvdWorkspace) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, name, err := avdWorkspaceIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props avdWorkspaceProps
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	patchProps := &armdesktopvirtualization.WorkspacePatchProperties{
		ApplicationGroupReferences: make([]*string, 0, len(props.ApplicationGroupReferences)),
	}
	for _, ref := range props.ApplicationGroupReferences {
		patchProps.ApplicationGroupReferences = append(patchProps.ApplicationGroupReferences, to.Ptr(ref))
	}
	if props.Description != "" {
		patchProps.Description = to.Ptr(props.Description)
	}
	if props.FriendlyName != "" {
		patchProps.FriendlyName = to.Ptr(props.FriendlyName)
	}

	patch := &armdesktopvirtualization.WorkspacePatch{Properties: patchProps}
	if azureTags := formaeTagsToAzureTags(request.DesiredProperties); azureTags != nil {
		patch.Tags = azureTags
	}

	result, err := a.api.Update(ctx, rgName, name,
		&armdesktopvirtualization.WorkspacesClientUpdateOptions{Workspace: patch})
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

	propsJSON, err := json.Marshal(a.buildPropertiesFromResult(&result.Workspace, rgName))
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

func (a *AvdWorkspace) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, name, err := avdWorkspaceIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	if _, err := a.api.Delete(ctx, rgName, name, nil); err != nil && !isDeleteSuccessError(err) {
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

// Status is never reached with real work to do: armdesktopvirtualization exposes
// no LRO at all.
func (a *AvdWorkspace) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

func (a *AvdWorkspace) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]

	var nativeIDs []string

	if rgName != "" {
		pager := a.api.NewListByResourceGroupPager(rgName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list AVD workspaces: %w", err)
			}
			for _, ws := range page.Value {
				if ws.ID != nil {
					nativeIDs = append(nativeIDs, *ws.ID)
				}
			}
		}
		return &resource.ListResult{NativeIDs: nativeIDs}, nil
	}

	pager := a.api.NewListBySubscriptionPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list AVD workspaces: %w", err)
		}
		for _, ws := range page.Value {
			if ws.ID != nil {
				nativeIDs = append(nativeIDs, *ws.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
