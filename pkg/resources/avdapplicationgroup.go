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

const ResourceTypeAvdApplicationGroup = "AZURE::DesktopVirtualization::ApplicationGroup"

// avdApplicationGroupsAPI is the armdesktopvirtualization surface used here; all
// operations are synchronous.
type avdApplicationGroupsAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName string, applicationGroupName string, applicationGroup armdesktopvirtualization.ApplicationGroup, options *armdesktopvirtualization.ApplicationGroupsClientCreateOrUpdateOptions) (armdesktopvirtualization.ApplicationGroupsClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName string, applicationGroupName string, options *armdesktopvirtualization.ApplicationGroupsClientGetOptions) (armdesktopvirtualization.ApplicationGroupsClientGetResponse, error)
	Update(ctx context.Context, resourceGroupName string, applicationGroupName string, options *armdesktopvirtualization.ApplicationGroupsClientUpdateOptions) (armdesktopvirtualization.ApplicationGroupsClientUpdateResponse, error)
	Delete(ctx context.Context, resourceGroupName string, applicationGroupName string, options *armdesktopvirtualization.ApplicationGroupsClientDeleteOptions) (armdesktopvirtualization.ApplicationGroupsClientDeleteResponse, error)
	NewListByResourceGroupPager(resourceGroupName string, options *armdesktopvirtualization.ApplicationGroupsClientListByResourceGroupOptions) *runtime.Pager[armdesktopvirtualization.ApplicationGroupsClientListByResourceGroupResponse]
	NewListBySubscriptionPager(options *armdesktopvirtualization.ApplicationGroupsClientListBySubscriptionOptions) *runtime.Pager[armdesktopvirtualization.ApplicationGroupsClientListBySubscriptionResponse]
}

func init() {
	registry.Register(ResourceTypeAvdApplicationGroup, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &AvdApplicationGroup{api: c.AvdApplicationGroupsClient, config: cfg}
	})
}

// AvdApplicationGroup is the provisioner for Azure Virtual Desktop application
// groups (Microsoft.DesktopVirtualization/applicationGroups).
//
// The link to the host pool is a field, hostPoolArmPath, not an association
// resource: ARM stores exactly one host pool per group, so there is no
// many-to-many to break out.
type AvdApplicationGroup struct {
	api    avdApplicationGroupsAPI
	config *config.Config
}

// avdApplicationGroupProps mirrors
// schema/pkl/desktopvirtualization/avdapplicationgroup.pkl.
type avdApplicationGroupProps struct {
	Name                 string `json:"name"`
	Location             string `json:"location"`
	ResourceGroupName    string `json:"resourceGroupName"`
	HostPoolArmPath      string `json:"hostPoolArmPath"`
	ApplicationGroupType string `json:"applicationGroupType"`
	Description          string `json:"description"`
	FriendlyName         string `json:"friendlyName"`
}

func avdApplicationGroupIDParts(resourceID string) (rgName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "applicationgroups")
	if err != nil {
		return "", "", err
	}
	return rgName, names["applicationgroups"], nil
}

func (a *AvdApplicationGroup) buildPropertiesFromResult(group *armdesktopvirtualization.ApplicationGroup, rgName string) map[string]any {
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

	if p := group.Properties; p != nil {
		if p.HostPoolArmPath != nil {
			props["hostPoolArmPath"] = *p.HostPoolArmPath
		}
		if p.ApplicationGroupType != nil {
			props["applicationGroupType"] = canonicalizeEnum(string(*p.ApplicationGroupType),
				"RemoteApp", "Desktop")
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
		// workspaceArmPath, objectId and cloudPcResource are deliberately
		// dropped: the first is written by the service the moment a workspace
		// lists this group, so surfacing it would report drift as soon as the
		// workspace exists, and neither of the others is desired state.
	}

	if tags := azureTagsToFormaeTags(group.Tags); tags != nil {
		props["Tags"] = tags
	}

	return props
}

func (a *AvdApplicationGroup) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props avdApplicationGroupProps
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	if props.Location == "" {
		return nil, fmt.Errorf("location is required")
	}
	if props.HostPoolArmPath == "" {
		return nil, fmt.Errorf("hostPoolArmPath is required")
	}
	if props.ApplicationGroupType == "" {
		return nil, fmt.Errorf("applicationGroupType is required")
	}
	name := props.Name
	if name == "" {
		name = request.Label
	}
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}

	params := armdesktopvirtualization.ApplicationGroup{
		Location: to.Ptr(props.Location),
		Properties: &armdesktopvirtualization.ApplicationGroupProperties{
			HostPoolArmPath: to.Ptr(props.HostPoolArmPath),
			ApplicationGroupType: to.Ptr(
				armdesktopvirtualization.ApplicationGroupType(props.ApplicationGroupType)),
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
	propsJSON, err := json.Marshal(a.buildPropertiesFromResult(&result.ApplicationGroup, props.ResourceGroupName))
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

func (a *AvdApplicationGroup) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, name, err := avdApplicationGroupIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := a.api.Get(ctx, rgName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(a.buildPropertiesFromResult(&result.ApplicationGroup, rgName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeAvdApplicationGroup,
		Properties:   string(propsJSON),
	}, nil
}

// Update is a synchronous PATCH. ARM's ApplicationGroupPatchProperties carries
// only description and friendlyName, which is exactly why the schema declares
// hostPoolArmPath and applicationGroupType createOnly: there is no in-place
// change for either.
func (a *AvdApplicationGroup) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, name, err := avdApplicationGroupIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props avdApplicationGroupProps
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	patchProps := &armdesktopvirtualization.ApplicationGroupPatchProperties{}
	if props.Description != "" {
		patchProps.Description = to.Ptr(props.Description)
	}
	if props.FriendlyName != "" {
		patchProps.FriendlyName = to.Ptr(props.FriendlyName)
	}

	patch := &armdesktopvirtualization.ApplicationGroupPatch{Properties: patchProps}
	if azureTags := formaeTagsToAzureTags(request.DesiredProperties); azureTags != nil {
		patch.Tags = azureTags
	}

	result, err := a.api.Update(ctx, rgName, name,
		&armdesktopvirtualization.ApplicationGroupsClientUpdateOptions{ApplicationGroup: patch})
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

	propsJSON, err := json.Marshal(a.buildPropertiesFromResult(&result.ApplicationGroup, rgName))
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

func (a *AvdApplicationGroup) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, name, err := avdApplicationGroupIDParts(request.NativeID)
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
func (a *AvdApplicationGroup) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

func (a *AvdApplicationGroup) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]

	var nativeIDs []string

	if rgName != "" {
		pager := a.api.NewListByResourceGroupPager(rgName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list AVD application groups: %w", err)
			}
			for _, group := range page.Value {
				if group.ID != nil {
					nativeIDs = append(nativeIDs, *group.ID)
				}
			}
		}
		return &resource.ListResult{NativeIDs: nativeIDs}, nil
	}

	pager := a.api.NewListBySubscriptionPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list AVD application groups: %w", err)
		}
		for _, group := range page.Value {
			if group.ID != nil {
				nativeIDs = append(nativeIDs, *group.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
