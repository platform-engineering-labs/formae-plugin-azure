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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/automation/armautomation"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeAutomationModule = "AZURE::Automation::Module"

// automationModuleAPI is the armautomation surface used here. Singular client
// name (ModuleClient). Every verb answers synchronously even though the import
// itself is not: see the type doc.
type automationModuleAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName string, automationAccountName string, moduleName string, parameters armautomation.ModuleCreateOrUpdateParameters, options *armautomation.ModuleClientCreateOrUpdateOptions) (armautomation.ModuleClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName string, automationAccountName string, moduleName string, options *armautomation.ModuleClientGetOptions) (armautomation.ModuleClientGetResponse, error)
	Update(ctx context.Context, resourceGroupName string, automationAccountName string, moduleName string, parameters armautomation.ModuleUpdateParameters, options *armautomation.ModuleClientUpdateOptions) (armautomation.ModuleClientUpdateResponse, error)
	Delete(ctx context.Context, resourceGroupName string, automationAccountName string, moduleName string, options *armautomation.ModuleClientDeleteOptions) (armautomation.ModuleClientDeleteResponse, error)
	NewListByAutomationAccountPager(resourceGroupName string, automationAccountName string, options *armautomation.ModuleClientListByAutomationAccountOptions) *runtime.Pager[armautomation.ModuleClientListByAutomationAccountResponse]
}

func init() {
	registry.Register(ResourceTypeAutomationModule, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &AutomationModule{
			api:    c.AutomationModuleClient,
			config: cfg,
		}
	})
}

// AutomationModule is the provisioner for PowerShell modules imported into an
// Automation account (Microsoft.Automation/automationAccounts/modules).
//
// The PUT hands ARM a contentLink URI to a .nupkg or .zip and returns
// immediately; ARM then downloads and validates the package out of band, walking
// provisioningState through ContentRetrieved / ContentDownloaded /
// ContentValidated to Succeeded, or to Failed if the URI is unreachable. That
// state is service-managed and is NOT modelled: it is neither settable nor
// stable, so emitting it would report drift on every sync while an import is
// still walking, and the client exposes no poller to wait on it either.
//
// contentLink is write-only: ARM's Get does not return it (only the derived
// version, size and activity count), so drift in the URI cannot be detected and
// a changed URI in a forma is simply re-pushed, which is what re-importing a
// module means.
type AutomationModule struct {
	api    automationModuleAPI
	config *config.Config
}

// automationModuleProps mirrors schema/pkl/automation/automationmodule.pkl.
type automationModuleProps struct {
	Name                  string `json:"name"`
	ResourceGroupName     string `json:"resourceGroupName"`
	AutomationAccountName string `json:"automationAccountName"`
	ContentLinkURI        any    `json:"contentLinkUri"`
	ContentLinkVersion    string `json:"contentLinkVersion"`
}

func automationModuleIDParts(resourceID string) (rgName, accountName, name string, err error) {
	return automationChildIDParts(resourceID, "modules")
}

func (m *AutomationModule) buildPropertiesFromResult(mod *armautomation.Module, rgName, accountName string) map[string]any {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	props["automationAccountName"] = accountName

	if mod.ID != nil {
		props["id"] = *mod.ID
	}
	if mod.Name != nil {
		props["name"] = *mod.Name
	}

	if tags := azureTagsToFormaeTags(mod.Tags); tags != nil {
		props["Tags"] = tags
	}

	// provisioningState, version, sizeInBytes, activityCount, isComposite,
	// isGlobal, error, creationTime and lastModifiedTime are deliberately
	// dropped: every one of them is derived from the package ARM downloaded, and
	// several move while an import is still in flight. contentLink is write-only
	// (see the type doc) and ARM does not return it anyway.

	return props
}

func (m *AutomationModule) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props automationModuleProps
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	if props.AutomationAccountName == "" {
		return nil, fmt.Errorf("automationAccountName is required")
	}
	contentLinkURI, ok := opaqueString(props.ContentLinkURI)
	if !ok {
		return nil, fmt.Errorf("contentLinkUri is required")
	}
	name := props.Name
	if name == "" {
		name = request.Label
	}
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}

	params := armautomation.ModuleCreateOrUpdateParameters{
		Name: to.Ptr(name),
		Properties: &armautomation.ModuleCreateOrUpdateProperties{
			ContentLink: automationContentLink(contentLinkURI, props.ContentLinkVersion),
		},
	}
	if azureTags := formaeTagsToAzureTags(request.Properties); azureTags != nil {
		params.Tags = azureTags
	}

	result, err := m.api.CreateOrUpdate(ctx, props.ResourceGroupName, props.AutomationAccountName, name, params, nil)
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
	if nativeID == "" {
		nativeID = automationChildNativeID(m.config.SubscriptionId, props.ResourceGroupName,
			props.AutomationAccountName, "modules", name)
	}
	propsJSON, err := json.Marshal(m.buildPropertiesFromResult(&result.Module,
		props.ResourceGroupName, props.AutomationAccountName))
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

func (m *AutomationModule) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, accountName, name, err := automationModuleIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := m.api.Get(ctx, rgName, accountName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(m.buildPropertiesFromResult(&result.Module, rgName, accountName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeAutomationModule,
		Properties:   string(propsJSON),
	}, nil
}

// Update is a synchronous PATCH that re-imports from a contentLink. ARM starts
// another out-of-band download, exactly as create does.
func (m *AutomationModule) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, accountName, name, err := automationModuleIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props automationModuleProps
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	params := armautomation.ModuleUpdateParameters{
		Properties: &armautomation.ModuleUpdateProperties{},
	}
	if contentLinkURI, ok := opaqueString(props.ContentLinkURI); ok {
		params.Properties.ContentLink = automationContentLink(contentLinkURI, props.ContentLinkVersion)
	}
	if azureTags := formaeTagsToAzureTags(request.DesiredProperties); azureTags != nil {
		params.Tags = azureTags
	}

	result, err := m.api.Update(ctx, rgName, accountName, name, params, nil)
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

	propsJSON, err := json.Marshal(m.buildPropertiesFromResult(&result.Module, rgName, accountName))
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

func (m *AutomationModule) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, accountName, name, err := automationModuleIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	if _, err := m.api.Delete(ctx, rgName, accountName, name, nil); err != nil && !isDeleteSuccessError(err) {
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

// Status is never reached with real work to do: the ARM calls are synchronous,
// and the out-of-band import that follows a PUT has no poller to resume.
func (m *AutomationModule) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

// List needs both the resource group and the automation account: ARM has no
// subscription-wide listing for modules.
func (m *AutomationModule) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	accountName := request.AdditionalProperties["automationAccountName"]
	if rgName == "" || accountName == "" {
		return &resource.ListResult{}, nil
	}

	var nativeIDs []string
	pager := m.api.NewListByAutomationAccountPager(rgName, accountName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list automation modules: %w", err)
		}
		for _, mod := range page.Value {
			if mod.ID != nil {
				nativeIDs = append(nativeIDs, *mod.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
