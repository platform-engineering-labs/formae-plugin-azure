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

const ResourceTypeAutomationAccount = "AZURE::Automation::Account"

// automationAccountAPI is the armautomation surface used here. Note the singular
// client name: the generated client is AccountClient, not AccountsClient, and
// every verb on it is synchronous — there is no BeginX anywhere in
// armautomation, so Status never has real work to do for any Automation type.
type automationAccountAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName string, automationAccountName string, parameters armautomation.AccountCreateOrUpdateParameters, options *armautomation.AccountClientCreateOrUpdateOptions) (armautomation.AccountClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName string, automationAccountName string, options *armautomation.AccountClientGetOptions) (armautomation.AccountClientGetResponse, error)
	Update(ctx context.Context, resourceGroupName string, automationAccountName string, parameters armautomation.AccountUpdateParameters, options *armautomation.AccountClientUpdateOptions) (armautomation.AccountClientUpdateResponse, error)
	Delete(ctx context.Context, resourceGroupName string, automationAccountName string, options *armautomation.AccountClientDeleteOptions) (armautomation.AccountClientDeleteResponse, error)
	NewListPager(options *armautomation.AccountClientListOptions) *runtime.Pager[armautomation.AccountClientListResponse]
	NewListByResourceGroupPager(resourceGroupName string, options *armautomation.AccountClientListByResourceGroupOptions) *runtime.Pager[armautomation.AccountClientListByResourceGroupResponse]
}

func init() {
	registry.Register(ResourceTypeAutomationAccount, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &AutomationAccount{
			api:    c.AutomationAccountClient,
			config: cfg,
		}
	})
}

// AutomationAccount is the provisioner for Azure Automation accounts
// (Microsoft.Automation/automationAccounts).
//
// The account is the parent of every other Automation resource: runbooks,
// schedules, job schedules, variables, credentials and modules all hang off it.
//
// The account's registration keys are not surfaced as properties: ARM returns
// them only from a separate Keys/ListByAutomationAccount call, so putting them in
// resource state would persist live credentials.
type AutomationAccount struct {
	api    automationAccountAPI
	config *config.Config
}

// automationAccountProps mirrors schema/pkl/automation/automationaccount.pkl.
type automationAccountProps struct {
	Name              string `json:"name"`
	Location          string `json:"location"`
	ResourceGroupName string `json:"resourceGroupName"`
	SKUName           string `json:"skuName"`
}

func automationAccountIDParts(resourceID string) (rgName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "automationaccounts")
	if err != nil {
		return "", "", err
	}
	return rgName, names["automationaccounts"], nil
}

// automationChildIDParts pulls the resource group, the parent automation account
// and the child's own name out of a child resource's ARM ID. childType is the
// leaf ARM type segment ("runbooks", "schedules", ...); matching is
// case-insensitive, so the lowercase form is enough for ARM's mixed-case
// "jobSchedules".
//
// Shared by all six child provisioners rather than repeated six times.
func automationChildIDParts(resourceID, childType string) (rgName, accountName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "automationaccounts", childType)
	if err != nil {
		return "", "", "", err
	}
	return rgName, names["automationaccounts"], names[childType], nil
}

// automationChildNativeID builds the ARM ID a child resource will have. ARM
// echoes the ID back on every create in this namespace, so this is only used to
// cross-check and for the mocked tests; nothing depends on it at runtime.
func automationChildNativeID(subscriptionID, rgName, accountName, childType, name string) string {
	return fmt.Sprintf(
		"/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Automation/automationAccounts/%s/%s/%s",
		subscriptionID, rgName, accountName, childType, name)
}

func (a *AutomationAccount) buildPropertiesFromResult(acct *armautomation.Account, rgName string) map[string]any {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName

	if acct.ID != nil {
		props["id"] = *acct.ID
	}
	if acct.Name != nil {
		props["name"] = *acct.Name
	}
	if acct.Location != nil {
		props["location"] = normalizeAzureLocation(*acct.Location)
	}

	if p := acct.Properties; p != nil {
		if p.SKU != nil && p.SKU.Name != nil {
			props["skuName"] = canonicalizeEnum(string(*p.SKU.Name), "Free", "Basic")
		}
		// creationTime, lastModifiedTime, lastModifiedBy, state,
		// automationHybridServiceUrl and privateEndpointConnections are
		// deliberately dropped: the timestamps and the state move on their own
		// and would read back as drift on every sync, and none of them is
		// desired state.
	}

	if tags := azureTagsToFormaeTags(acct.Tags); tags != nil {
		props["Tags"] = tags
	}

	return props
}

func (a *AutomationAccount) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props automationAccountProps
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	if props.Location == "" {
		return nil, fmt.Errorf("location is required")
	}
	if props.SKUName == "" {
		return nil, fmt.Errorf("skuName is required")
	}
	name := props.Name
	if name == "" {
		name = request.Label
	}
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}

	params := armautomation.AccountCreateOrUpdateParameters{
		Name:     to.Ptr(name),
		Location: to.Ptr(props.Location),
		Properties: &armautomation.AccountCreateOrUpdateProperties{
			SKU: &armautomation.SKU{Name: to.Ptr(armautomation.SKUNameEnum(props.SKUName))},
		},
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
	propsJSON, err := json.Marshal(a.buildPropertiesFromResult(&result.Account, props.ResourceGroupName))
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

func (a *AutomationAccount) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, name, err := automationAccountIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := a.api.Get(ctx, rgName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(a.buildPropertiesFromResult(&result.Account, rgName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeAutomationAccount,
		Properties:   string(propsJSON),
	}, nil
}

// Update is a synchronous PATCH. Only the SKU and the tags are mutable; name,
// location and resource group are createOnly. Location is deliberately left out
// of the body: ARM accepts it but a PATCH that restates the region has no effect
// and would let a schema mistake read as an accepted move.
func (a *AutomationAccount) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, name, err := automationAccountIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props automationAccountProps
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	params := armautomation.AccountUpdateParameters{
		Name:       to.Ptr(name),
		Properties: &armautomation.AccountUpdateProperties{},
	}
	if props.SKUName != "" {
		params.Properties.SKU = &armautomation.SKU{
			Name: to.Ptr(armautomation.SKUNameEnum(props.SKUName)),
		}
	}
	if azureTags := formaeTagsToAzureTags(request.DesiredProperties); azureTags != nil {
		params.Tags = azureTags
	}

	result, err := a.api.Update(ctx, rgName, name, params, nil)
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

	propsJSON, err := json.Marshal(a.buildPropertiesFromResult(&result.Account, rgName))
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

func (a *AutomationAccount) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, name, err := automationAccountIDParts(request.NativeID)
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

// Status is never reached with real work to do: armautomation exposes no LRO for
// automation accounts, so every operation finishes inside its own call.
func (a *AutomationAccount) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

func (a *AutomationAccount) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]

	var nativeIDs []string

	if rgName != "" {
		pager := a.api.NewListByResourceGroupPager(rgName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list automation accounts: %w", err)
			}
			for _, acct := range page.Value {
				if acct.ID != nil {
					nativeIDs = append(nativeIDs, *acct.ID)
				}
			}
		}
		return &resource.ListResult{NativeIDs: nativeIDs}, nil
	}

	pager := a.api.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list automation accounts: %w", err)
		}
		for _, acct := range page.Value {
			if acct.ID != nil {
				nativeIDs = append(nativeIDs, *acct.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
