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

const ResourceTypeAutomationVariable = "AZURE::Automation::Variable"

// automationVariableAPI is the armautomation surface used here. Singular client
// name (VariableClient); all four verbs are synchronous.
type automationVariableAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName string, automationAccountName string, variableName string, parameters armautomation.VariableCreateOrUpdateParameters, options *armautomation.VariableClientCreateOrUpdateOptions) (armautomation.VariableClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName string, automationAccountName string, variableName string, options *armautomation.VariableClientGetOptions) (armautomation.VariableClientGetResponse, error)
	Update(ctx context.Context, resourceGroupName string, automationAccountName string, variableName string, parameters armautomation.VariableUpdateParameters, options *armautomation.VariableClientUpdateOptions) (armautomation.VariableClientUpdateResponse, error)
	Delete(ctx context.Context, resourceGroupName string, automationAccountName string, variableName string, options *armautomation.VariableClientDeleteOptions) (armautomation.VariableClientDeleteResponse, error)
	NewListByAutomationAccountPager(resourceGroupName string, automationAccountName string, options *armautomation.VariableClientListByAutomationAccountOptions) *runtime.Pager[armautomation.VariableClientListByAutomationAccountResponse]
}

func init() {
	registry.Register(ResourceTypeAutomationVariable, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &AutomationVariable{
			api:    c.AutomationVariableClient,
			config: cfg,
		}
	})
}

// AutomationVariable is the provisioner for variables inside an Automation
// account (Microsoft.Automation/automationAccounts/variables).
//
// The value is write-only, for both halves of the encryption switch. When
// isEncrypted is true ARM never returns the value at all, so a read that
// expected it would report drift on every sync — the same asymmetry a connection
// string has. When isEncrypted is false ARM does echo it back, but treating one
// of the two cases as comparable and the other as not would make the schema's
// meaning depend on a sibling field, so the value is never read back either way
// and a changed value in a forma is simply pushed.
//
// isEncrypted itself is createOnly: ARM will not flip an existing variable
// between encrypted and plain.
type AutomationVariable struct {
	api    automationVariableAPI
	config *config.Config
}

// automationVariableProps mirrors schema/pkl/automation/automationvariable.pkl.
type automationVariableProps struct {
	Name                  string `json:"name"`
	ResourceGroupName     string `json:"resourceGroupName"`
	AutomationAccountName string `json:"automationAccountName"`
	IsEncrypted           *bool  `json:"isEncrypted"`
	Value                 any    `json:"value"`
	Description           string `json:"description"`
}

func automationVariableIDParts(resourceID string) (rgName, accountName, name string, err error) {
	return automationChildIDParts(resourceID, "variables")
}

func (v *AutomationVariable) buildPropertiesFromResult(variable *armautomation.Variable, rgName, accountName string) map[string]any {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	props["automationAccountName"] = accountName

	if variable.ID != nil {
		props["id"] = *variable.ID
	}
	if variable.Name != nil {
		props["name"] = *variable.Name
	}

	if p := variable.Properties; p != nil {
		if p.IsEncrypted != nil {
			props["isEncrypted"] = *p.IsEncrypted
		}
		if p.Description != nil && *p.Description != "" {
			props["description"] = *p.Description
		}
		// value is deliberately never emitted: it is write-only (see the type
		// doc). creationTime and lastModifiedTime move on their own.
	}

	return props
}

func (v *AutomationVariable) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props automationVariableProps
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	if props.AutomationAccountName == "" {
		return nil, fmt.Errorf("automationAccountName is required")
	}
	name := props.Name
	if name == "" {
		name = request.Label
	}
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}

	createProps := &armautomation.VariableCreateOrUpdateProperties{
		IsEncrypted: props.IsEncrypted,
	}
	if value, ok := opaqueString(props.Value); ok {
		createProps.Value = to.Ptr(value)
	}
	if props.Description != "" {
		createProps.Description = to.Ptr(props.Description)
	}

	result, err := v.api.CreateOrUpdate(ctx, props.ResourceGroupName, props.AutomationAccountName, name,
		armautomation.VariableCreateOrUpdateParameters{
			Name:       to.Ptr(name),
			Properties: createProps,
		}, nil)
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
		nativeID = automationChildNativeID(v.config.SubscriptionId, props.ResourceGroupName,
			props.AutomationAccountName, "variables", name)
	}
	propsJSON, err := json.Marshal(v.buildPropertiesFromResult(&result.Variable,
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

func (v *AutomationVariable) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, accountName, name, err := automationVariableIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := v.api.Get(ctx, rgName, accountName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(v.buildPropertiesFromResult(&result.Variable, rgName, accountName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeAutomationVariable,
		Properties:   string(propsJSON),
	}, nil
}

// Update is a synchronous PATCH reaching the value and the description.
// isEncrypted is createOnly, so a change to it replaces the variable.
func (v *AutomationVariable) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, accountName, name, err := automationVariableIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props automationVariableProps
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	updateProps := &armautomation.VariableUpdateProperties{}
	if value, ok := opaqueString(props.Value); ok {
		updateProps.Value = to.Ptr(value)
	}
	if props.Description != "" {
		updateProps.Description = to.Ptr(props.Description)
	}

	result, err := v.api.Update(ctx, rgName, accountName, name,
		armautomation.VariableUpdateParameters{
			Name:       to.Ptr(name),
			Properties: updateProps,
		}, nil)
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

	propsJSON, err := json.Marshal(v.buildPropertiesFromResult(&result.Variable, rgName, accountName))
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

func (v *AutomationVariable) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, accountName, name, err := automationVariableIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	if _, err := v.api.Delete(ctx, rgName, accountName, name, nil); err != nil && !isDeleteSuccessError(err) {
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

// Status is never reached with real work to do: every variable operation is
// synchronous.
func (v *AutomationVariable) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

// List needs both the resource group and the automation account: ARM has no
// subscription-wide listing for variables.
func (v *AutomationVariable) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	accountName := request.AdditionalProperties["automationAccountName"]
	if rgName == "" || accountName == "" {
		return &resource.ListResult{}, nil
	}

	var nativeIDs []string
	pager := v.api.NewListByAutomationAccountPager(rgName, accountName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list automation variables: %w", err)
		}
		for _, variable := range page.Value {
			if variable.ID != nil {
				nativeIDs = append(nativeIDs, *variable.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
