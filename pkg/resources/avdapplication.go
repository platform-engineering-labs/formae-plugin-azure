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

const ResourceTypeAvdApplication = "AZURE::DesktopVirtualization::Application"

// avdApplicationsAPI is the armdesktopvirtualization surface used here; all
// operations are synchronous. There is no subscription-wide pager for
// applications: ARM only lists them under one application group, which is
// exactly what the schema's two-level listParam supplies.
type avdApplicationsAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName string, applicationGroupName string, applicationName string, application armdesktopvirtualization.Application, options *armdesktopvirtualization.ApplicationsClientCreateOrUpdateOptions) (armdesktopvirtualization.ApplicationsClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName string, applicationGroupName string, applicationName string, options *armdesktopvirtualization.ApplicationsClientGetOptions) (armdesktopvirtualization.ApplicationsClientGetResponse, error)
	Update(ctx context.Context, resourceGroupName string, applicationGroupName string, applicationName string, options *armdesktopvirtualization.ApplicationsClientUpdateOptions) (armdesktopvirtualization.ApplicationsClientUpdateResponse, error)
	Delete(ctx context.Context, resourceGroupName string, applicationGroupName string, applicationName string, options *armdesktopvirtualization.ApplicationsClientDeleteOptions) (armdesktopvirtualization.ApplicationsClientDeleteResponse, error)
	NewListPager(resourceGroupName string, applicationGroupName string, options *armdesktopvirtualization.ApplicationsClientListOptions) *runtime.Pager[armdesktopvirtualization.ApplicationsClientListResponse]
}

func init() {
	registry.Register(ResourceTypeAvdApplication, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &AvdApplication{api: c.AvdApplicationsClient, config: cfg}
	})
}

// AvdApplication is the provisioner for a single published application inside a
// RemoteApp application group
// (Microsoft.DesktopVirtualization/applicationGroups/applications).
//
// The resource carries no location and no tags: ARM's Application model has
// neither. It is a proxy-only child of the application group.
type AvdApplication struct {
	api    avdApplicationsAPI
	config *config.Config
}

// avdApplicationProps mirrors
// schema/pkl/desktopvirtualization/avdapplication.pkl.
type avdApplicationProps struct {
	Name                 string `json:"name"`
	ResourceGroupName    string `json:"resourceGroupName"`
	ApplicationGroupName string `json:"applicationGroupName"`
	CommandLineSetting   string `json:"commandLineSetting"`
	FilePath             string `json:"filePath"`
	CommandLineArguments string `json:"commandLineArguments"`
	Description          string `json:"description"`
	FriendlyName         string `json:"friendlyName"`
	ShowInPortal         *bool  `json:"showInPortal"`
}

func avdApplicationIDParts(resourceID string) (rgName, groupName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "applicationgroups", "applications")
	if err != nil {
		return "", "", "", err
	}
	return rgName, names["applicationgroups"], names["applications"], nil
}

func (a *AvdApplication) buildPropertiesFromResult(app *armdesktopvirtualization.Application, rgName, groupName string) map[string]any {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	props["applicationGroupName"] = groupName

	if app.ID != nil {
		props["id"] = *app.ID
	}
	if app.Name != nil {
		// ARM answers with the child's name qualified by its parent
		// ("group/app"); desired state carries the bare leaf.
		props["name"] = avdApplicationLeafName(*app.Name)
	}

	if p := app.Properties; p != nil {
		if p.CommandLineSetting != nil {
			props["commandLineSetting"] = canonicalizeEnum(string(*p.CommandLineSetting),
				"Allow", "DoNotAllow", "Require")
		}
		if p.FilePath != nil {
			props["filePath"] = *p.FilePath
		}
		// ARM answers Get with "" for the free-text optionals that were never
		// set, and desired state carries them absent — emitting the empty string
		// would report drift on every sync.
		if p.CommandLineArguments != nil && *p.CommandLineArguments != "" {
			props["commandLineArguments"] = *p.CommandLineArguments
		}
		if p.Description != nil && *p.Description != "" {
			props["description"] = *p.Description
		}
		if p.FriendlyName != nil && *p.FriendlyName != "" {
			props["friendlyName"] = *p.FriendlyName
		}
		if p.ShowInPortal != nil {
			props["showInPortal"] = *p.ShowInPortal
		}
		// applicationType, the two msixPackage* fields, iconPath, iconIndex,
		// iconHash, iconContent and objectId are deliberately dropped: the icon
		// fields are service-computed, MSIX app attach is not modelled, and
		// objectId is internal bookkeeping.
	}

	return props
}

// avdApplicationLeafName strips the parent qualifier ARM prefixes onto a child's
// name. ARM answers "group/app" for a nested proxy resource, but desired state
// and the ARM ID both carry the bare leaf, so echoing the qualified form back
// would report drift on every sync.
func avdApplicationLeafName(name string) string {
	for i := len(name) - 1; i >= 0; i-- {
		if name[i] == '/' {
			return name[i+1:]
		}
	}
	return name
}

func (a *AvdApplication) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props avdApplicationProps
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	if props.ApplicationGroupName == "" {
		return nil, fmt.Errorf("applicationGroupName is required")
	}
	if props.CommandLineSetting == "" {
		return nil, fmt.Errorf("commandLineSetting is required")
	}
	if props.FilePath == "" {
		return nil, fmt.Errorf("filePath is required")
	}
	name := props.Name
	if name == "" {
		name = request.Label
	}
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}

	params := armdesktopvirtualization.Application{
		Properties: &armdesktopvirtualization.ApplicationProperties{
			CommandLineSetting: to.Ptr(
				armdesktopvirtualization.CommandLineSetting(props.CommandLineSetting)),
			FilePath:     to.Ptr(props.FilePath),
			ShowInPortal: props.ShowInPortal,
		},
	}
	if props.CommandLineArguments != "" {
		params.Properties.CommandLineArguments = to.Ptr(props.CommandLineArguments)
	}
	if props.Description != "" {
		params.Properties.Description = to.Ptr(props.Description)
	}
	if props.FriendlyName != "" {
		params.Properties.FriendlyName = to.Ptr(props.FriendlyName)
	}

	result, err := a.api.CreateOrUpdate(ctx, props.ResourceGroupName, props.ApplicationGroupName, name, params, nil)
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
	propsJSON, err := json.Marshal(a.buildPropertiesFromResult(
		&result.Application, props.ResourceGroupName, props.ApplicationGroupName))
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

func (a *AvdApplication) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, groupName, name, err := avdApplicationIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := a.api.Get(ctx, rgName, groupName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(a.buildPropertiesFromResult(&result.Application, rgName, groupName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeAvdApplication,
		Properties:   string(propsJSON),
	}, nil
}

// Update is a synchronous PATCH. Every mutable field the schema declares is
// present in ApplicationPatchProperties, so nothing needs a replace.
func (a *AvdApplication) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, groupName, name, err := avdApplicationIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props avdApplicationProps
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	patchProps := &armdesktopvirtualization.ApplicationPatchProperties{
		ShowInPortal: props.ShowInPortal,
	}
	if props.CommandLineSetting != "" {
		patchProps.CommandLineSetting = to.Ptr(
			armdesktopvirtualization.CommandLineSetting(props.CommandLineSetting))
	}
	if props.FilePath != "" {
		patchProps.FilePath = to.Ptr(props.FilePath)
	}
	if props.CommandLineArguments != "" {
		patchProps.CommandLineArguments = to.Ptr(props.CommandLineArguments)
	}
	if props.Description != "" {
		patchProps.Description = to.Ptr(props.Description)
	}
	if props.FriendlyName != "" {
		patchProps.FriendlyName = to.Ptr(props.FriendlyName)
	}

	result, err := a.api.Update(ctx, rgName, groupName, name,
		&armdesktopvirtualization.ApplicationsClientUpdateOptions{
			Application: &armdesktopvirtualization.ApplicationPatch{Properties: patchProps},
		})
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

	propsJSON, err := json.Marshal(a.buildPropertiesFromResult(&result.Application, rgName, groupName))
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

func (a *AvdApplication) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, groupName, name, err := avdApplicationIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	if _, err := a.api.Delete(ctx, rgName, groupName, name, nil); err != nil && !isDeleteSuccessError(err) {
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
func (a *AvdApplication) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

// List enumerates the applications of one application group. Both scope keys are
// supplied by the schema's listParam block, so there is no subscription-wide
// fallback to build — ARM has no pager for one.
func (a *AvdApplication) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	groupName := request.AdditionalProperties["applicationGroupName"]
	if rgName == "" || groupName == "" {
		return &resource.ListResult{}, nil
	}

	var nativeIDs []string
	pager := a.api.NewListPager(rgName, groupName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list AVD applications: %w", err)
		}
		for _, app := range page.Value {
			if app.ID != nil {
				nativeIDs = append(nativeIDs, *app.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
