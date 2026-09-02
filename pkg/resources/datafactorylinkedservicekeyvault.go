// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/datafactory/armdatafactory"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
)

const ResourceTypeDataFactoryLinkedServiceKeyVault = "AZURE::DataFactory::LinkedServiceKeyVault"

// dataFactoryLinkedServiceKeyVaultProps mirrors the connector-specific half of
// schema/pkl/datafactory/datafactorylinkedservicekeyvault.pkl. The shared half
// lives in dataFactoryLinkedServiceCommon.
type dataFactoryLinkedServiceKeyVaultProps struct {
	BaseURL string `json:"baseUrl"`
}

// dataFactoryLinkedServiceKeyVaultKind is the AzureKeyVault connector: the
// indirection every other linked service uses to fetch a secret instead of
// embedding it. It carries no credential of its own — the factory's managed
// identity authenticates to the vault — so nothing here is write-only.
var dataFactoryLinkedServiceKeyVaultKind = linkedServiceKind{
	resourceType: ResourceTypeDataFactoryLinkedServiceKeyVault,
	armType:      "AzureKeyVault",

	build: func(common *dataFactoryLinkedServiceCommon, payload json.RawMessage) (armdatafactory.LinkedServiceClassification, error) {
		var props dataFactoryLinkedServiceKeyVaultProps
		if err := json.Unmarshal(payload, &props); err != nil {
			return nil, fmt.Errorf("failed to parse resource properties: %w", err)
		}
		if props.BaseURL == "" {
			return nil, fmt.Errorf("baseUrl is required")
		}
		return &armdatafactory.AzureKeyVaultLinkedService{
			Description: common.Description,
			ConnectVia:  common.connectVia(),
			Annotations: common.annotationList(),
			TypeProperties: &armdatafactory.AzureKeyVaultLinkedServiceTypeProperties{
				BaseURL: props.BaseURL,
			},
		}, nil
	},

	readTypeProperties: func(properties armdatafactory.LinkedServiceClassification, props map[string]any) {
		ls, ok := properties.(*armdatafactory.AzureKeyVaultLinkedService)
		if !ok || ls.TypeProperties == nil {
			return
		}
		if v, ok := dataFactoryExpressionString(ls.TypeProperties.BaseURL); ok {
			props["baseUrl"] = v
		}
		// credential (a CredentialReference to a user-assigned identity
		// credential) is not modelled and is not read back.
	},
}

func init() {
	registry.Register(ResourceTypeDataFactoryLinkedServiceKeyVault, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &DataFactoryLinkedService{
			api:    c.DataFactoryLinkedServicesClient,
			kind:   &dataFactoryLinkedServiceKeyVaultKind,
			config: cfg,
		}
	})
}
