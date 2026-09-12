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

const ResourceTypeLogicIntegrationAccountPartner = "AZURE::Logic::IntegrationAccountPartner"

// logicIntegrationAccountPartnersAPI is the armlogic surface used here. Every
// verb is synchronous and there is no PATCH: an update is another
// CreateOrUpdate.
type logicIntegrationAccountPartnersAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName string, integrationAccountName string, partnerName string, partner armlogic.IntegrationAccountPartner, options *armlogic.IntegrationAccountPartnersClientCreateOrUpdateOptions) (armlogic.IntegrationAccountPartnersClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName string, integrationAccountName string, partnerName string, options *armlogic.IntegrationAccountPartnersClientGetOptions) (armlogic.IntegrationAccountPartnersClientGetResponse, error)
	Delete(ctx context.Context, resourceGroupName string, integrationAccountName string, partnerName string, options *armlogic.IntegrationAccountPartnersClientDeleteOptions) (armlogic.IntegrationAccountPartnersClientDeleteResponse, error)
	NewListPager(resourceGroupName string, integrationAccountName string, options *armlogic.IntegrationAccountPartnersClientListOptions) *runtime.Pager[armlogic.IntegrationAccountPartnersClientListResponse]
}

func init() {
	registry.Register(ResourceTypeLogicIntegrationAccountPartner, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &LogicIntegrationAccountPartner{
			api:    c.LogicIntegrationAccountPartnersClient,
			config: cfg,
		}
	})
}

// LogicIntegrationAccountPartner is the provisioner for trading partners held in
// an integration account
// (Microsoft.Logic/integrationAccounts/partners).
//
// A partner on its own does nothing. It becomes meaningful when an
// AZURE::Logic::IntegrationAccountAgreement names two of them, and that
// agreement will not create until both partners exist AND carry the exact
// qualifier/value pair the agreement declares.
type LogicIntegrationAccountPartner struct {
	api    logicIntegrationAccountPartnersAPI
	config *config.Config
}

// logicIntegrationAccountPartnerProps mirrors
// schema/pkl/logic/logicintegrationaccountpartner.pkl.
type logicIntegrationAccountPartnerProps struct {
	logicChildProps
	PartnerType        string                  `json:"partnerType"`
	BusinessIdentities []logicBusinessIdentity `json:"businessIdentities"`
}

func (p *logicIntegrationAccountPartnerProps) parse(payload json.RawMessage, fallbackName string) error {
	if err := json.Unmarshal(payload, p); err != nil {
		return fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if err := p.validate(fallbackName); err != nil {
		return err
	}
	if p.PartnerType == "" {
		return fmt.Errorf("partnerType is required")
	}
	if len(p.BusinessIdentities) == 0 {
		return fmt.Errorf("businessIdentities is required and must carry at least one identity")
	}
	for i, identity := range p.BusinessIdentities {
		if identity.Qualifier == "" {
			return fmt.Errorf("businessIdentities[%d].qualifier is required", i)
		}
		if identity.Value == "" {
			return fmt.Errorf("businessIdentities[%d].value is required", i)
		}
	}
	return nil
}

// params builds the request body shared by create and update.
func (p *LogicIntegrationAccountPartner) params(props logicIntegrationAccountPartnerProps) armlogic.IntegrationAccountPartner {
	return armlogic.IntegrationAccountPartner{
		Properties: &armlogic.IntegrationAccountPartnerProperties{
			PartnerType: to.Ptr(armlogic.PartnerType(props.PartnerType)),
			Content: &armlogic.PartnerContent{
				B2B: &armlogic.B2BPartnerContent{
					BusinessIdentities: logicBusinessIdentitiesToARM(props.BusinessIdentities),
				},
			},
		},
	}
}

func (p *LogicIntegrationAccountPartner) buildPropertiesFromResult(partner *armlogic.IntegrationAccountPartner, rgName, accountName string) map[string]any {
	props := logicChildBaseProps(rgName, accountName, partner.ID, partner.Name)

	if pp := partner.Properties; pp != nil {
		if pp.PartnerType != nil {
			props["partnerType"] = canonicalizeEnum(string(*pp.PartnerType), "B2B", "NotSpecified")
		}
		// The schema flattens ARM's content.b2b.businessIdentities wrapper to a
		// single list: PartnerContent has exactly one member and B2BPartnerContent
		// exactly one after that, so the two intermediate objects carry no
		// information a caller could set.
		if pp.Content != nil && pp.Content.B2B != nil {
			if identities := logicBusinessIdentitiesProps(pp.Content.B2B.BusinessIdentities); identities != nil {
				props["businessIdentities"] = identities
			}
		}
		// metadata is arbitrary JSON the schema cannot express, and the timestamps
		// move on their own; neither is read back.
	}

	return props
}

func (p *LogicIntegrationAccountPartner) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props logicIntegrationAccountPartnerProps
	if err := props.parse(request.Properties, request.Label); err != nil {
		return nil, err
	}

	result, err := p.api.CreateOrUpdate(ctx, props.ResourceGroupName, props.IntegrationAccountName,
		props.Name, p.params(props), nil)
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
	propsJSON, err := json.Marshal(p.buildPropertiesFromResult(&result.IntegrationAccountPartner,
		props.ResourceGroupName, props.IntegrationAccountName))
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

func (p *LogicIntegrationAccountPartner) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, accountName, name, err := logicChildIDParts(request.NativeID, "partners")
	if err != nil {
		return nil, err
	}

	result, err := p.api.Get(ctx, rgName, accountName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(p.buildPropertiesFromResult(&result.IntegrationAccountPartner, rgName, accountName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeLogicIntegrationAccountPartner,
		Properties:   string(propsJSON),
	}, nil
}

// Update reissues CreateOrUpdate: this API has no PATCH verb for partners.
func (p *LogicIntegrationAccountPartner) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, accountName, name, err := logicChildIDParts(request.NativeID, "partners")
	if err != nil {
		return nil, err
	}

	var props logicIntegrationAccountPartnerProps
	if err := props.parse(request.DesiredProperties, name); err != nil {
		return nil, err
	}

	result, err := p.api.CreateOrUpdate(ctx, rgName, accountName, name, p.params(props), nil)
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

	propsJSON, err := json.Marshal(p.buildPropertiesFromResult(&result.IntegrationAccountPartner, rgName, accountName))
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

func (p *LogicIntegrationAccountPartner) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, accountName, name, err := logicChildIDParts(request.NativeID, "partners")
	if err != nil {
		return nil, err
	}

	if _, err := p.api.Delete(ctx, rgName, accountName, name, nil); err != nil && !isDeleteSuccessError(err) {
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
func (p *LogicIntegrationAccountPartner) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

// List needs both the resource group and the integration account: ARM has no
// subscription-wide listing of integration account partners.
func (p *LogicIntegrationAccountPartner) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	accountName := request.AdditionalProperties["integrationAccountName"]
	if rgName == "" || accountName == "" {
		return &resource.ListResult{}, nil
	}

	var nativeIDs []string
	pager := p.api.NewListPager(rgName, accountName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list logic integration account partners: %w", err)
		}
		for _, partner := range page.Value {
			if partner != nil && partner.ID != nil {
				nativeIDs = append(nativeIDs, *partner.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
