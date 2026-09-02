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

const ResourceTypeLogicIntegrationAccountAgreement = "AZURE::Logic::IntegrationAccountAgreement"

// logicIntegrationAccountAgreementsAPI is the armlogic surface used here. Every
// verb is synchronous and there is no PATCH: an update is another
// CreateOrUpdate.
//
// ListContentCallbackURL is deliberately absent: it mints a SAS URL that is a
// bearer credential.
type logicIntegrationAccountAgreementsAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName string, integrationAccountName string, agreementName string, agreement armlogic.IntegrationAccountAgreement, options *armlogic.IntegrationAccountAgreementsClientCreateOrUpdateOptions) (armlogic.IntegrationAccountAgreementsClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName string, integrationAccountName string, agreementName string, options *armlogic.IntegrationAccountAgreementsClientGetOptions) (armlogic.IntegrationAccountAgreementsClientGetResponse, error)
	Delete(ctx context.Context, resourceGroupName string, integrationAccountName string, agreementName string, options *armlogic.IntegrationAccountAgreementsClientDeleteOptions) (armlogic.IntegrationAccountAgreementsClientDeleteResponse, error)
	NewListPager(resourceGroupName string, integrationAccountName string, options *armlogic.IntegrationAccountAgreementsClientListOptions) *runtime.Pager[armlogic.IntegrationAccountAgreementsClientListResponse]
}

func init() {
	registry.Register(ResourceTypeLogicIntegrationAccountAgreement, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &LogicIntegrationAccountAgreement{
			api:    c.LogicIntegrationAccountAgreementsClient,
			config: cfg,
		}
	})
}

// LogicIntegrationAccountAgreement is the provisioner for trading-partner
// agreements held in an integration account
// (Microsoft.Logic/integrationAccounts/agreements).
//
// ORDER MATTERS. Both partners must already exist as
// AZURE::Logic::IntegrationAccountPartner resources, and each must carry the
// exact qualifier/value pair given in hostIdentity / guestIdentity. ARM rejects
// the create otherwise with a message that names neither the partner nor the
// field, which is why the fixture chain is account -> partners -> agreement.
type LogicIntegrationAccountAgreement struct {
	api    logicIntegrationAccountAgreementsAPI
	config *config.Config
}

// logicIntegrationAccountAgreementProps mirrors
// schema/pkl/logic/logicintegrationaccountagreement.pkl.
type logicIntegrationAccountAgreementProps struct {
	logicChildProps
	AgreementType string                `json:"agreementType"`
	HostPartner   string                `json:"hostPartner"`
	GuestPartner  string                `json:"guestPartner"`
	HostIdentity  logicBusinessIdentity `json:"hostIdentity"`
	GuestIdentity logicBusinessIdentity `json:"guestIdentity"`
	Content       string                `json:"content"`
}

func (p *logicIntegrationAccountAgreementProps) parse(payload json.RawMessage, fallbackName string) error {
	if err := json.Unmarshal(payload, p); err != nil {
		return fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if err := p.validate(fallbackName); err != nil {
		return err
	}
	if p.AgreementType == "" {
		return fmt.Errorf("agreementType is required")
	}
	if p.HostPartner == "" {
		return fmt.Errorf("hostPartner is required")
	}
	if p.GuestPartner == "" {
		return fmt.Errorf("guestPartner is required")
	}
	if p.HostIdentity.Qualifier == "" || p.HostIdentity.Value == "" {
		return fmt.Errorf("hostIdentity.qualifier and hostIdentity.value are required")
	}
	if p.GuestIdentity.Qualifier == "" || p.GuestIdentity.Value == "" {
		return fmt.Errorf("guestIdentity.qualifier and guestIdentity.value are required")
	}
	if p.Content == "" {
		return fmt.Errorf("content is required")
	}
	return nil
}

// logicAgreementContent decodes the caller's JSON settings block into the
// protocol-specific member named by agreementType.
//
// The schema carries only the INNER block — for AS2, the object with
// receiveAgreement and sendAgreement — rather than ARM's one-member
// AgreementContent wrapper. Two reasons: agreementType already says which
// protocol is in play, so repeating it inside the document is redundant and
// invites the two disagreeing; and the SDK marshals AgreementContent's AS2
// member under the key `aS2`, which no hand-written document would guess and
// whose UnmarshalJSON matches case-sensitively.
//
// Decoding into the SDK's own typed models means a document that is valid JSON
// but the wrong shape fails here rather than as an opaque ARM 400.
func logicAgreementContent(agreementType, document string) (*armlogic.AgreementContent, error) {
	content := &armlogic.AgreementContent{}
	switch armlogic.AgreementType(agreementType) {
	case armlogic.AgreementTypeAS2:
		var as2 armlogic.AS2AgreementContent
		if err := logicJSONDocument("content", document, &as2); err != nil {
			return nil, err
		}
		if as2.ReceiveAgreement == nil || as2.SendAgreement == nil {
			return nil, fmt.Errorf("content for an AS2 agreement must carry both receiveAgreement and sendAgreement")
		}
		content.AS2 = &as2
	case armlogic.AgreementTypeX12:
		var x12 armlogic.X12AgreementContent
		if err := logicJSONDocument("content", document, &x12); err != nil {
			return nil, err
		}
		if x12.ReceiveAgreement == nil || x12.SendAgreement == nil {
			return nil, fmt.Errorf("content for an X12 agreement must carry both receiveAgreement and sendAgreement")
		}
		content.X12 = &x12
	case armlogic.AgreementTypeEdifact:
		var edifact armlogic.EdifactAgreementContent
		if err := logicJSONDocument("content", document, &edifact); err != nil {
			return nil, err
		}
		if edifact.ReceiveAgreement == nil || edifact.SendAgreement == nil {
			return nil, fmt.Errorf("content for an EDIFACT agreement must carry both receiveAgreement and sendAgreement")
		}
		content.Edifact = &edifact
	default:
		return nil, fmt.Errorf("unsupported agreementType %q: expected AS2, X12 or Edifact", agreementType)
	}
	return content, nil
}

// params builds the request body shared by create and update.
func (g *LogicIntegrationAccountAgreement) params(props logicIntegrationAccountAgreementProps) (armlogic.IntegrationAccountAgreement, error) {
	content, err := logicAgreementContent(props.AgreementType, props.Content)
	if err != nil {
		return armlogic.IntegrationAccountAgreement{}, err
	}

	return armlogic.IntegrationAccountAgreement{
		Properties: &armlogic.IntegrationAccountAgreementProperties{
			AgreementType: to.Ptr(armlogic.AgreementType(props.AgreementType)),
			HostPartner:   to.Ptr(props.HostPartner),
			GuestPartner:  to.Ptr(props.GuestPartner),
			HostIdentity:  logicBusinessIdentityToARM(&props.HostIdentity),
			GuestIdentity: logicBusinessIdentityToARM(&props.GuestIdentity),
			Content:       content,
		},
	}, nil
}

func (g *LogicIntegrationAccountAgreement) buildPropertiesFromResult(agreement *armlogic.IntegrationAccountAgreement, rgName, accountName string) map[string]any {
	props := logicChildBaseProps(rgName, accountName, agreement.ID, agreement.Name)

	if p := agreement.Properties; p != nil {
		if p.AgreementType != nil {
			props["agreementType"] = canonicalizeEnum(string(*p.AgreementType),
				"AS2", "X12", "Edifact", "NotSpecified")
		}
		if p.HostPartner != nil {
			props["hostPartner"] = *p.HostPartner
		}
		if p.GuestPartner != nil {
			props["guestPartner"] = *p.GuestPartner
		}
		if identity := logicBusinessIdentityProps(p.HostIdentity); identity != nil {
			props["hostIdentity"] = identity
		}
		if identity := logicBusinessIdentityProps(p.GuestIdentity); identity != nil {
			props["guestIdentity"] = identity
		}
		// content is declared writeOnly in the schema and is deliberately NOT read
		// back: ARM fills in every optional leaf of the protocol settings tree it
		// did not receive — around seventy of them for AS2 — and reorders the
		// object, so comparing its echo against what was authored would report
		// drift on an agreement nobody touched.
		//
		// metadata is arbitrary JSON the schema cannot express, and the timestamps
		// move on their own; neither is read back.
	}

	return props
}

func (g *LogicIntegrationAccountAgreement) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props logicIntegrationAccountAgreementProps
	if err := props.parse(request.Properties, request.Label); err != nil {
		return nil, err
	}
	params, err := g.params(props)
	if err != nil {
		return nil, err
	}

	result, err := g.api.CreateOrUpdate(ctx, props.ResourceGroupName, props.IntegrationAccountName,
		props.Name, params, nil)
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
	propsJSON, err := json.Marshal(g.buildPropertiesFromResult(&result.IntegrationAccountAgreement,
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

func (g *LogicIntegrationAccountAgreement) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, accountName, name, err := logicChildIDParts(request.NativeID, "agreements")
	if err != nil {
		return nil, err
	}

	result, err := g.api.Get(ctx, rgName, accountName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(g.buildPropertiesFromResult(&result.IntegrationAccountAgreement, rgName, accountName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeLogicIntegrationAccountAgreement,
		Properties:   string(propsJSON),
	}, nil
}

// Update reissues CreateOrUpdate: this API has no PATCH verb for agreements.
func (g *LogicIntegrationAccountAgreement) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, accountName, name, err := logicChildIDParts(request.NativeID, "agreements")
	if err != nil {
		return nil, err
	}

	var props logicIntegrationAccountAgreementProps
	if err := props.parse(request.DesiredProperties, name); err != nil {
		return nil, err
	}
	params, err := g.params(props)
	if err != nil {
		return nil, err
	}

	result, err := g.api.CreateOrUpdate(ctx, rgName, accountName, name, params, nil)
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

	propsJSON, err := json.Marshal(g.buildPropertiesFromResult(&result.IntegrationAccountAgreement, rgName, accountName))
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

func (g *LogicIntegrationAccountAgreement) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, accountName, name, err := logicChildIDParts(request.NativeID, "agreements")
	if err != nil {
		return nil, err
	}

	if _, err := g.api.Delete(ctx, rgName, accountName, name, nil); err != nil && !isDeleteSuccessError(err) {
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
func (g *LogicIntegrationAccountAgreement) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

// List needs both the resource group and the integration account: ARM has no
// subscription-wide listing of integration account agreements.
func (g *LogicIntegrationAccountAgreement) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	accountName := request.AdditionalProperties["integrationAccountName"]
	if rgName == "" || accountName == "" {
		return &resource.ListResult{}, nil
	}

	var nativeIDs []string
	pager := g.api.NewListPager(rgName, accountName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list logic integration account agreements: %w", err)
		}
		for _, agreement := range page.Value {
			if agreement != nil && agreement.ID != nil {
				nativeIDs = append(nativeIDs, *agreement.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
