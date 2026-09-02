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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/logic/armlogic"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeLogicIntegrationAccount = "AZURE::Logic::IntegrationAccount"

// logicIntegrationAccountsAPI is the armlogic surface used here. Every verb is
// synchronous — IntegrationAccountsClient has no BeginX at all — and Update is a
// full-body PUT-shaped PATCH, so create and update send the same document.
//
// ListCallbackURL, RegenerateAccessKey, LogTrackingEvents and
// NewListKeyVaultKeysPager are deliberately absent: the first two return live
// credentials that must not reach resource state, and the last two are
// data-plane operations, not desired state.
type logicIntegrationAccountsAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName string, integrationAccountName string, integrationAccount armlogic.IntegrationAccount, options *armlogic.IntegrationAccountsClientCreateOrUpdateOptions) (armlogic.IntegrationAccountsClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName string, integrationAccountName string, options *armlogic.IntegrationAccountsClientGetOptions) (armlogic.IntegrationAccountsClientGetResponse, error)
	Delete(ctx context.Context, resourceGroupName string, integrationAccountName string, options *armlogic.IntegrationAccountsClientDeleteOptions) (armlogic.IntegrationAccountsClientDeleteResponse, error)
	NewListByResourceGroupPager(resourceGroupName string, options *armlogic.IntegrationAccountsClientListByResourceGroupOptions) *runtime.Pager[armlogic.IntegrationAccountsClientListByResourceGroupResponse]
	NewListBySubscriptionPager(options *armlogic.IntegrationAccountsClientListBySubscriptionOptions) *runtime.Pager[armlogic.IntegrationAccountsClientListBySubscriptionResponse]
}

func init() {
	registry.Register(ResourceTypeLogicIntegrationAccount, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &LogicIntegrationAccount{
			api:    c.LogicIntegrationAccountsClient,
			config: cfg,
		}
	})
}

// LogicIntegrationAccount is the provisioner for integration accounts
// (Microsoft.Logic/integrationAccounts) — the container for the B2B artifacts a
// Logic Apps workflow uses.
//
// The account's shared access keys are never serialized: ARM returns them only
// from ListCallbackURL and RegenerateAccessKey, so putting them in resource
// state would persist live credentials.
type LogicIntegrationAccount struct {
	api    logicIntegrationAccountsAPI
	config *config.Config
}

// logicIntegrationAccountProps mirrors
// schema/pkl/logic/logicintegrationaccount.pkl.
type logicIntegrationAccountProps struct {
	Name              string `json:"name"`
	Location          string `json:"location"`
	ResourceGroupName string `json:"resourceGroupName"`
	SKUName           string `json:"skuName"`
}

func (p *logicIntegrationAccountProps) parse(payload json.RawMessage, fallbackName string) error {
	if err := json.Unmarshal(payload, p); err != nil {
		return fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if p.ResourceGroupName == "" {
		return fmt.Errorf("resourceGroupName is required")
	}
	if p.Location == "" {
		return fmt.Errorf("location is required")
	}
	if p.Name == "" {
		p.Name = fallbackName
	}
	if p.Name == "" {
		return fmt.Errorf("name is required")
	}
	if p.SKUName == "" {
		return fmt.Errorf("skuName is required")
	}
	return nil
}

func logicIntegrationAccountIDParts(resourceID string) (rgName, name string, err error) {
	rgName, names, err := armExactIDParts(resourceID, "integrationAccounts")
	if err != nil {
		return "", "", err
	}
	return rgName, names[0], nil
}

// params builds the request body shared by create and update.
//
// skuName is required by the schema rather than provider-defaulted: ARM's own
// default is NotSpecified, which produces an account no workflow can use, and
// the two paid tiers bill per hour from the moment they exist.
func (a *LogicIntegrationAccount) params(props logicIntegrationAccountProps, tagsSource json.RawMessage) armlogic.IntegrationAccount {
	account := armlogic.IntegrationAccount{
		Location: to.Ptr(props.Location),
		SKU: &armlogic.IntegrationAccountSKU{
			Name: to.Ptr(armlogic.IntegrationAccountSKUName(props.SKUName)),
		},
		// An empty properties block is sent deliberately: ARM rejects an
		// integration account PUT whose body has no properties member at all.
		Properties: &armlogic.IntegrationAccountProperties{},
	}
	if azureTags := formaeTagsToAzureTags(tagsSource); azureTags != nil {
		account.Tags = azureTags
	}
	return account
}

func (a *LogicIntegrationAccount) buildPropertiesFromResult(account *armlogic.IntegrationAccount, rgName string) map[string]any {
	props := map[string]any{"resourceGroupName": rgName}

	if account.ID != nil {
		props["id"] = *account.ID
	}
	if account.Name != nil {
		props["name"] = *account.Name
	}
	if account.Location != nil {
		props["location"] = normalizeAzureLocation(*account.Location)
	}
	if account.SKU != nil && account.SKU.Name != nil {
		props["skuName"] = canonicalizeEnum(string(*account.SKU.Name),
			"Free", "Basic", "Standard", "NotSpecified")
	}

	// properties.state and properties.integrationServiceEnvironment are not
	// modelled and are not read back: the state is service state rather than
	// desired state, and integration service environments are retired.

	if tags := azureTagsToFormaeTags(account.Tags); tags != nil {
		props["Tags"] = tags
	}

	return props
}

func (a *LogicIntegrationAccount) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props logicIntegrationAccountProps
	if err := props.parse(request.Properties, request.Label); err != nil {
		return nil, err
	}

	result, err := a.api.CreateOrUpdate(ctx, props.ResourceGroupName, props.Name,
		a.params(props, request.Properties), nil)
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
	propsJSON, err := json.Marshal(a.buildPropertiesFromResult(&result.IntegrationAccount, props.ResourceGroupName))
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

func (a *LogicIntegrationAccount) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, name, err := logicIntegrationAccountIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := a.api.Get(ctx, rgName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(a.buildPropertiesFromResult(&result.IntegrationAccount, rgName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeLogicIntegrationAccount,
		Properties:   string(propsJSON),
	}, nil
}

// Update reissues CreateOrUpdate rather than calling Update: the SDK's Update is
// a whole-document PATCH taking the same IntegrationAccount body, so the two are
// equivalent, and reusing the create path keeps one code path for the SKU block.
func (a *LogicIntegrationAccount) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, name, err := logicIntegrationAccountIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props logicIntegrationAccountProps
	if err := props.parse(request.DesiredProperties, name); err != nil {
		return nil, err
	}

	result, err := a.api.CreateOrUpdate(ctx, rgName, name, a.params(props, request.DesiredProperties), nil)
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

	propsJSON, err := json.Marshal(a.buildPropertiesFromResult(&result.IntegrationAccount, rgName))
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

func (a *LogicIntegrationAccount) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, name, err := logicIntegrationAccountIDParts(request.NativeID)
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

// Status echoes success: every verb this provisioner uses is synchronous.
func (a *LogicIntegrationAccount) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

// List pages the resource group when discovery supplies one, and falls back to
// the subscription-wide pager otherwise. resourceGroupName IS supplied by the
// hint's listParam, so the fallback is only reached by a caller that asked for
// everything — it needs no subscriptionWideList entry.
func (a *LogicIntegrationAccount) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]

	var nativeIDs []string

	if rgName != "" {
		pager := a.api.NewListByResourceGroupPager(rgName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list logic integration accounts: %w", err)
			}
			for _, account := range page.Value {
				if account != nil && account.ID != nil {
					nativeIDs = append(nativeIDs, *account.ID)
				}
			}
		}
		return &resource.ListResult{NativeIDs: nativeIDs}, nil
	}

	pager := a.api.NewListBySubscriptionPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list logic integration accounts: %w", err)
		}
		for _, account := range page.Value {
			if account != nil && account.ID != nil {
				nativeIDs = append(nativeIDs, *account.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
