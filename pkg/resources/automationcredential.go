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

const ResourceTypeAutomationCredential = "AZURE::Automation::Credential"

// automationCredentialAPI is the armautomation surface used here. Singular
// client name (CredentialClient); all four verbs are synchronous.
type automationCredentialAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName string, automationAccountName string, credentialName string, parameters armautomation.CredentialCreateOrUpdateParameters, options *armautomation.CredentialClientCreateOrUpdateOptions) (armautomation.CredentialClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName string, automationAccountName string, credentialName string, options *armautomation.CredentialClientGetOptions) (armautomation.CredentialClientGetResponse, error)
	Update(ctx context.Context, resourceGroupName string, automationAccountName string, credentialName string, parameters armautomation.CredentialUpdateParameters, options *armautomation.CredentialClientUpdateOptions) (armautomation.CredentialClientUpdateResponse, error)
	Delete(ctx context.Context, resourceGroupName string, automationAccountName string, credentialName string, options *armautomation.CredentialClientDeleteOptions) (armautomation.CredentialClientDeleteResponse, error)
	NewListByAutomationAccountPager(resourceGroupName string, automationAccountName string, options *armautomation.CredentialClientListByAutomationAccountOptions) *runtime.Pager[armautomation.CredentialClientListByAutomationAccountResponse]
}

func init() {
	registry.Register(ResourceTypeAutomationCredential, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &AutomationCredential{
			api:    c.AutomationCredentialClient,
			config: cfg,
		}
	})
}

// AutomationCredential is the provisioner for credential assets inside an
// Automation account (Microsoft.Automation/automationAccounts/credentials).
//
// A credential is a username/password pair a runbook retrieves at execution
// time. ARM's own model marks the password as write-only: CredentialProperties
// has no password field at all, so Get can never return it. The password is
// therefore declared write-only in the schema and never read back — drift in it
// cannot be detected, and a changed password in a forma is simply pushed.
//
// The username is returned and is fully comparable.
type AutomationCredential struct {
	api    automationCredentialAPI
	config *config.Config
}

// automationCredentialProps mirrors
// schema/pkl/automation/automationcredential.pkl.
type automationCredentialProps struct {
	Name                  string `json:"name"`
	ResourceGroupName     string `json:"resourceGroupName"`
	AutomationAccountName string `json:"automationAccountName"`
	UserName              string `json:"userName"`
	Password              any    `json:"password"`
	Description           string `json:"description"`
}

func automationCredentialIDParts(resourceID string) (rgName, accountName, name string, err error) {
	return automationChildIDParts(resourceID, "credentials")
}

func (c *AutomationCredential) buildPropertiesFromResult(cred *armautomation.Credential, rgName, accountName string) map[string]any {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	props["automationAccountName"] = accountName

	if cred.ID != nil {
		props["id"] = *cred.ID
	}
	if cred.Name != nil {
		props["name"] = *cred.Name
	}

	if p := cred.Properties; p != nil {
		if p.UserName != nil {
			props["userName"] = *p.UserName
		}
		if p.Description != nil && *p.Description != "" {
			props["description"] = *p.Description
		}
		// creationTime and lastModifiedTime move on their own. There is no
		// password to drop: ARM's response model does not carry one.
	}

	return props
}

func (c *AutomationCredential) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props automationCredentialProps
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	if props.AutomationAccountName == "" {
		return nil, fmt.Errorf("automationAccountName is required")
	}
	if props.UserName == "" {
		return nil, fmt.Errorf("userName is required")
	}
	password, ok := opaqueString(props.Password)
	if !ok {
		return nil, fmt.Errorf("password is required")
	}
	name := props.Name
	if name == "" {
		name = request.Label
	}
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}

	createProps := &armautomation.CredentialCreateOrUpdateProperties{
		UserName: to.Ptr(props.UserName),
		Password: to.Ptr(password),
	}
	if props.Description != "" {
		createProps.Description = to.Ptr(props.Description)
	}

	result, err := c.api.CreateOrUpdate(ctx, props.ResourceGroupName, props.AutomationAccountName, name,
		armautomation.CredentialCreateOrUpdateParameters{
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
		nativeID = automationChildNativeID(c.config.SubscriptionId, props.ResourceGroupName,
			props.AutomationAccountName, "credentials", name)
	}
	propsJSON, err := json.Marshal(c.buildPropertiesFromResult(&result.Credential,
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

func (c *AutomationCredential) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, accountName, name, err := automationCredentialIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := c.api.Get(ctx, rgName, accountName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(c.buildPropertiesFromResult(&result.Credential, rgName, accountName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeAutomationCredential,
		Properties:   string(propsJSON),
	}, nil
}

// Update is a synchronous PATCH. ARM's CredentialUpdateProperties carries the
// username, the password and the description, so all three are mutable; a
// password that arrives redacted rather than as plaintext is left out of the
// body, which means "keep the one the service already holds".
func (c *AutomationCredential) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, accountName, name, err := automationCredentialIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props automationCredentialProps
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	updateProps := &armautomation.CredentialUpdateProperties{}
	if props.UserName != "" {
		updateProps.UserName = to.Ptr(props.UserName)
	}
	if password, ok := opaqueString(props.Password); ok {
		updateProps.Password = to.Ptr(password)
	}
	if props.Description != "" {
		updateProps.Description = to.Ptr(props.Description)
	}

	result, err := c.api.Update(ctx, rgName, accountName, name,
		armautomation.CredentialUpdateParameters{
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

	propsJSON, err := json.Marshal(c.buildPropertiesFromResult(&result.Credential, rgName, accountName))
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

func (c *AutomationCredential) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, accountName, name, err := automationCredentialIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	if _, err := c.api.Delete(ctx, rgName, accountName, name, nil); err != nil && !isDeleteSuccessError(err) {
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

// Status is never reached with real work to do: every credential operation is
// synchronous.
func (c *AutomationCredential) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

// List needs both the resource group and the automation account: ARM has no
// subscription-wide listing for credentials.
func (c *AutomationCredential) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	accountName := request.AdditionalProperties["automationAccountName"]
	if rgName == "" || accountName == "" {
		return &resource.ListResult{}, nil
	}

	var nativeIDs []string
	pager := c.api.NewListByAutomationAccountPager(rgName, accountName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list automation credentials: %w", err)
		}
		for _, cred := range page.Value {
			if cred.ID != nil {
				nativeIDs = append(nativeIDs, *cred.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
