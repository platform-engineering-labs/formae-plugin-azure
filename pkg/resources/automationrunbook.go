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

const ResourceTypeAutomationRunbook = "AZURE::Automation::Runbook"

// automationRunbookAPI is the armautomation surface used here. Singular client
// name (RunbookClient), and every verb used is synchronous — BeginPublish is the
// only LRO on the client and this resource deliberately does not drive it.
type automationRunbookAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName string, automationAccountName string, runbookName string, parameters armautomation.RunbookCreateOrUpdateParameters, options *armautomation.RunbookClientCreateOrUpdateOptions) (armautomation.RunbookClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName string, automationAccountName string, runbookName string, options *armautomation.RunbookClientGetOptions) (armautomation.RunbookClientGetResponse, error)
	Update(ctx context.Context, resourceGroupName string, automationAccountName string, runbookName string, parameters armautomation.RunbookUpdateParameters, options *armautomation.RunbookClientUpdateOptions) (armautomation.RunbookClientUpdateResponse, error)
	Delete(ctx context.Context, resourceGroupName string, automationAccountName string, runbookName string, options *armautomation.RunbookClientDeleteOptions) (armautomation.RunbookClientDeleteResponse, error)
	NewListByAutomationAccountPager(resourceGroupName string, automationAccountName string, options *armautomation.RunbookClientListByAutomationAccountOptions) *runtime.Pager[armautomation.RunbookClientListByAutomationAccountResponse]
}

func init() {
	registry.Register(ResourceTypeAutomationRunbook, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &AutomationRunbook{
			api:    c.AutomationRunbookClient,
			config: cfg,
		}
	})
}

// AutomationRunbook is the provisioner for runbooks inside an Automation account
// (Microsoft.Automation/automationAccounts/runbooks).
//
// This is the runbook RECORD, not the script body. ARM models the body as a
// separate draft/publish flow (RunbookDraftClient plus RunbookClient.BeginPublish)
// and the draft is not modelled here: a runbook created without a
// publishContentLink is created with an empty draft, and a runbook created with
// one is published from that URI by ARM at create time.
//
// Because publishing is a create-time act, publishContentLinkUri is both
// createOnly and write-only: ARM's Get does not return it, so drift in it cannot
// be detected.
type AutomationRunbook struct {
	api    automationRunbookAPI
	config *config.Config
}

// automationRunbookProps mirrors schema/pkl/automation/automationrunbook.pkl.
type automationRunbookProps struct {
	Name                      string `json:"name"`
	ResourceGroupName         string `json:"resourceGroupName"`
	AutomationAccountName     string `json:"automationAccountName"`
	Location                  string `json:"location"`
	RunbookType               string `json:"runbookType"`
	LogVerbose                *bool  `json:"logVerbose"`
	LogProgress               *bool  `json:"logProgress"`
	Description               string `json:"description"`
	PublishContentLinkURI     any    `json:"publishContentLinkUri"`
	PublishContentLinkVersion string `json:"publishContentLinkVersion"`
}

func automationRunbookIDParts(resourceID string) (rgName, accountName, name string, err error) {
	return automationChildIDParts(resourceID, "runbooks")
}

func (r *AutomationRunbook) buildPropertiesFromResult(rb *armautomation.Runbook, rgName, accountName string) map[string]any {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	props["automationAccountName"] = accountName

	if rb.ID != nil {
		props["id"] = *rb.ID
	}
	if rb.Name != nil {
		props["name"] = *rb.Name
	}
	if rb.Location != nil {
		props["location"] = normalizeAzureLocation(*rb.Location)
	}

	if p := rb.Properties; p != nil {
		if p.RunbookType != nil {
			props["runbookType"] = canonicalizeEnum(string(*p.RunbookType),
				"Graph", "GraphPowerShell", "GraphPowerShellWorkflow", "PowerShell",
				"PowerShell72", "PowerShellWorkflow", "Python", "Python2", "Python3", "Script")
		}
		if p.LogVerbose != nil {
			props["logVerbose"] = *p.LogVerbose
		}
		if p.LogProgress != nil {
			props["logProgress"] = *p.LogProgress
		}
		// An unset description comes back as an empty string from some API
		// versions and as null from others; emitting "" would read as drift
		// against a forma that never declared one.
		if p.Description != nil && *p.Description != "" {
			props["description"] = *p.Description
		}
		// state, provisioningState, jobCount, outputTypes, parameters,
		// runtimeEnvironment, logActivityTrace, draft, publishContentLink,
		// lastModifiedBy, creationTime and lastModifiedTime are deliberately
		// dropped: none is desired state, the counters and timestamps move on
		// their own, and publishContentLink is write-only (see the type doc).
	}

	if tags := azureTagsToFormaeTags(rb.Tags); tags != nil {
		props["Tags"] = tags
	}

	return props
}

// automationContentLink builds the ARM contentLink block from a URI and an
// optional version. Returns nil when there is no URI, so the field is omitted
// from the request body rather than sent empty.
//
// The contentHash is not modelled: ARM only verifies it, and a schema that
// carried it would make every content change a two-field edit.
func automationContentLink(uri, version string) *armautomation.ContentLink {
	if uri == "" {
		return nil
	}
	link := &armautomation.ContentLink{URI: to.Ptr(uri)}
	if version != "" {
		link.Version = to.Ptr(version)
	}
	return link
}

func (r *AutomationRunbook) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props automationRunbookProps
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	if props.AutomationAccountName == "" {
		return nil, fmt.Errorf("automationAccountName is required")
	}
	if props.Location == "" {
		return nil, fmt.Errorf("location is required")
	}
	if props.RunbookType == "" {
		return nil, fmt.Errorf("runbookType is required")
	}
	name := props.Name
	if name == "" {
		name = request.Label
	}
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}

	createProps := &armautomation.RunbookCreateOrUpdateProperties{
		RunbookType: to.Ptr(armautomation.RunbookTypeEnum(props.RunbookType)),
		LogVerbose:  props.LogVerbose,
		LogProgress: props.LogProgress,
	}
	if props.Description != "" {
		createProps.Description = to.Ptr(props.Description)
	}
	if uri, ok := opaqueString(props.PublishContentLinkURI); ok {
		createProps.PublishContentLink = automationContentLink(uri, props.PublishContentLinkVersion)
	} else {
		// ARM rejects a runbook that carries neither a publishContentLink nor a
		// draft, so an empty draft is the "record only, no script yet" form.
		createProps.Draft = &armautomation.RunbookDraft{}
	}

	params := armautomation.RunbookCreateOrUpdateParameters{
		Name:       to.Ptr(name),
		Location:   to.Ptr(props.Location),
		Properties: createProps,
	}
	if azureTags := formaeTagsToAzureTags(request.Properties); azureTags != nil {
		params.Tags = azureTags
	}

	result, err := r.api.CreateOrUpdate(ctx, props.ResourceGroupName, props.AutomationAccountName, name, params, nil)
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
		nativeID = automationChildNativeID(r.config.SubscriptionId, props.ResourceGroupName,
			props.AutomationAccountName, "runbooks", name)
	}
	propsJSON, err := json.Marshal(r.buildPropertiesFromResult(&result.Runbook,
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

func (r *AutomationRunbook) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, accountName, name, err := automationRunbookIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := r.api.Get(ctx, rgName, accountName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(r.buildPropertiesFromResult(&result.Runbook, rgName, accountName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeAutomationRunbook,
		Properties:   string(propsJSON),
	}, nil
}

// Update is a synchronous PATCH over RunbookUpdateParameters, which reaches only
// description, the two log flags and the tags. runbookType and the content link
// are createOnly: ARM has no verb that changes either in place.
func (r *AutomationRunbook) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, accountName, name, err := automationRunbookIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props automationRunbookProps
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	updateProps := &armautomation.RunbookUpdateProperties{
		LogVerbose:  props.LogVerbose,
		LogProgress: props.LogProgress,
	}
	if props.Description != "" {
		updateProps.Description = to.Ptr(props.Description)
	}

	params := armautomation.RunbookUpdateParameters{
		Name:       to.Ptr(name),
		Properties: updateProps,
	}
	if azureTags := formaeTagsToAzureTags(request.DesiredProperties); azureTags != nil {
		params.Tags = azureTags
	}

	result, err := r.api.Update(ctx, rgName, accountName, name, params, nil)
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

	propsJSON, err := json.Marshal(r.buildPropertiesFromResult(&result.Runbook, rgName, accountName))
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

func (r *AutomationRunbook) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, accountName, name, err := automationRunbookIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	if _, err := r.api.Delete(ctx, rgName, accountName, name, nil); err != nil && !isDeleteSuccessError(err) {
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

// Status is never reached with real work to do: create, update and delete are
// all synchronous here.
func (r *AutomationRunbook) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

// List needs both the resource group and the automation account: ARM has no
// subscription-wide listing for runbooks.
func (r *AutomationRunbook) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	accountName := request.AdditionalProperties["automationAccountName"]
	if rgName == "" || accountName == "" {
		return &resource.ListResult{}, nil
	}

	var nativeIDs []string
	pager := r.api.NewListByAutomationAccountPager(rgName, accountName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list automation runbooks: %w", err)
		}
		for _, rb := range page.Value {
			if rb.ID != nil {
				nativeIDs = append(nativeIDs, *rb.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
