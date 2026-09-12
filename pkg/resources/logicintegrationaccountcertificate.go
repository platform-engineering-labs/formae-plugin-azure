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

const ResourceTypeLogicIntegrationAccountCertificate = "AZURE::Logic::IntegrationAccountCertificate"

// logicIntegrationAccountCertificatesAPI is the armlogic surface used here.
// Every verb is synchronous and there is no PATCH: an update is another
// CreateOrUpdate. This client has no ListContentCallbackURL at all, unlike the
// other integration-account children.
type logicIntegrationAccountCertificatesAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName string, integrationAccountName string, certificateName string, certificate armlogic.IntegrationAccountCertificate, options *armlogic.IntegrationAccountCertificatesClientCreateOrUpdateOptions) (armlogic.IntegrationAccountCertificatesClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName string, integrationAccountName string, certificateName string, options *armlogic.IntegrationAccountCertificatesClientGetOptions) (armlogic.IntegrationAccountCertificatesClientGetResponse, error)
	Delete(ctx context.Context, resourceGroupName string, integrationAccountName string, certificateName string, options *armlogic.IntegrationAccountCertificatesClientDeleteOptions) (armlogic.IntegrationAccountCertificatesClientDeleteResponse, error)
	NewListPager(resourceGroupName string, integrationAccountName string, options *armlogic.IntegrationAccountCertificatesClientListOptions) *runtime.Pager[armlogic.IntegrationAccountCertificatesClientListResponse]
}

func init() {
	registry.Register(ResourceTypeLogicIntegrationAccountCertificate, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &LogicIntegrationAccountCertificate{
			api:    c.LogicIntegrationAccountCertificatesClient,
			config: cfg,
		}
	})
}

// LogicIntegrationAccountCertificate is the provisioner for certificates held in
// an integration account
// (Microsoft.Logic/integrationAccounts/certificates).
//
// PUBLIC HALF ONLY. ARM's certificate model has a second form — a
// KeyVaultKeyReference naming a private key — which is deliberately not
// implemented: it needs a data-plane grant on the vault plus an access policy
// for the integration account's managed identity, neither of which this resource
// type can express, and getting either wrong fails as an opaque ARM 400.
type LogicIntegrationAccountCertificate struct {
	api    logicIntegrationAccountCertificatesAPI
	config *config.Config
}

// logicIntegrationAccountCertificateProps mirrors
// schema/pkl/logic/logicintegrationaccountcertificate.pkl.
type logicIntegrationAccountCertificateProps struct {
	logicChildProps
	PublicCertificate string `json:"publicCertificate"`
}

func (p *logicIntegrationAccountCertificateProps) parse(payload json.RawMessage, fallbackName string) error {
	if err := json.Unmarshal(payload, p); err != nil {
		return fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if err := p.validate(fallbackName); err != nil {
		return err
	}
	if p.PublicCertificate == "" {
		return fmt.Errorf("publicCertificate is required")
	}
	return nil
}

// params builds the request body shared by create and update. The key member is
// never set: only the public form is supported.
func (c *LogicIntegrationAccountCertificate) params(props logicIntegrationAccountCertificateProps) armlogic.IntegrationAccountCertificate {
	return armlogic.IntegrationAccountCertificate{
		Properties: &armlogic.IntegrationAccountCertificateProperties{
			PublicCertificate: to.Ptr(props.PublicCertificate),
		},
	}
}

func (c *LogicIntegrationAccountCertificate) buildPropertiesFromResult(certificate *armlogic.IntegrationAccountCertificate, rgName, accountName string) map[string]any {
	props := logicChildBaseProps(rgName, accountName, certificate.ID, certificate.Name)

	if p := certificate.Properties; p != nil {
		// publicCertificate IS read back — unlike the other artifact bodies in
		// this namespace, ARM echoes the blob rather than replacing it with a
		// contentLink — but it is declared writeOnly in the schema, because ARM is
		// free to re-encode what it echoes and a difference in encoding is not a
		// change anybody made.
		if p.PublicCertificate != nil && *p.PublicCertificate != "" {
			props["publicCertificate"] = *p.PublicCertificate
		}
		// key is not modelled: the Key Vault form needs a data-plane grant this
		// resource cannot express. metadata is arbitrary JSON the schema cannot
		// express, and the timestamps move on their own.
	}

	return props
}

func (c *LogicIntegrationAccountCertificate) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props logicIntegrationAccountCertificateProps
	if err := props.parse(request.Properties, request.Label); err != nil {
		return nil, err
	}

	result, err := c.api.CreateOrUpdate(ctx, props.ResourceGroupName, props.IntegrationAccountName,
		props.Name, c.params(props), nil)
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
	propsJSON, err := json.Marshal(c.buildPropertiesFromResult(&result.IntegrationAccountCertificate,
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

func (c *LogicIntegrationAccountCertificate) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, accountName, name, err := logicChildIDParts(request.NativeID, "certificates")
	if err != nil {
		return nil, err
	}

	result, err := c.api.Get(ctx, rgName, accountName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(c.buildPropertiesFromResult(&result.IntegrationAccountCertificate, rgName, accountName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeLogicIntegrationAccountCertificate,
		Properties:   string(propsJSON),
	}, nil
}

// Update reissues CreateOrUpdate: this API has no PATCH verb for certificates.
func (c *LogicIntegrationAccountCertificate) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, accountName, name, err := logicChildIDParts(request.NativeID, "certificates")
	if err != nil {
		return nil, err
	}

	var props logicIntegrationAccountCertificateProps
	if err := props.parse(request.DesiredProperties, name); err != nil {
		return nil, err
	}

	result, err := c.api.CreateOrUpdate(ctx, rgName, accountName, name, c.params(props), nil)
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

	propsJSON, err := json.Marshal(c.buildPropertiesFromResult(&result.IntegrationAccountCertificate, rgName, accountName))
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

func (c *LogicIntegrationAccountCertificate) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, accountName, name, err := logicChildIDParts(request.NativeID, "certificates")
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

// Status echoes success: every verb this provisioner uses is synchronous.
func (c *LogicIntegrationAccountCertificate) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

// List needs both the resource group and the integration account: ARM has no
// subscription-wide listing of integration account certificates.
func (c *LogicIntegrationAccountCertificate) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	accountName := request.AdditionalProperties["integrationAccountName"]
	if rgName == "" || accountName == "" {
		return &resource.ListResult{}, nil
	}

	var nativeIDs []string
	pager := c.api.NewListPager(rgName, accountName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list logic integration account certificates: %w", err)
		}
		for _, certificate := range page.Value {
			if certificate != nil && certificate.ID != nil {
				nativeIDs = append(nativeIDs, *certificate.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
