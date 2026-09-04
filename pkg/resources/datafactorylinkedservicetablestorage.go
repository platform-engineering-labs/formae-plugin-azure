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

const ResourceTypeDataFactoryLinkedServiceAzureTableStorage = "AZURE::DataFactory::LinkedServiceAzureTableStorage"

// dataFactoryLinkedServiceTableStorageProps mirrors the connector-specific half of
// schema/pkl/datafactory/datafactorylinkedservicetablestorage.pkl. The shared half
// lives in dataFactoryLinkedServiceCommon.
type dataFactoryLinkedServiceTableStorageProps struct {
	ConnectionString *string `json:"connectionString"`
}

// dataFactoryLinkedServiceTableStorageKind is the AzureTableStorage connector.
//
// Unlike the blob connector there is no managed-identity endpoint form: table
// storage authenticates through a connection string only, which is always sent as
// a SecureString so the service stores it encrypted and returns only a mask.
var dataFactoryLinkedServiceTableStorageKind = linkedServiceKind{
	resourceType: ResourceTypeDataFactoryLinkedServiceAzureTableStorage,
	armType:      "AzureTableStorage",

	build: func(common *dataFactoryLinkedServiceCommon, payload json.RawMessage) (armdatafactory.LinkedServiceClassification, error) {
		var props dataFactoryLinkedServiceTableStorageProps
		if err := json.Unmarshal(payload, &props); err != nil {
			return nil, fmt.Errorf("failed to parse resource properties: %w", err)
		}
		secret := dataFactorySecureString(props.ConnectionString)
		if secret == nil {
			return nil, fmt.Errorf("connectionString is required")
		}

		return &armdatafactory.AzureTableStorageLinkedService{
			Description: common.Description,
			ConnectVia:  common.connectVia(),
			Annotations: common.annotationList(),
			TypeProperties: &armdatafactory.AzureStorageLinkedServiceTypeProperties{
				ConnectionString: secret,
			},
		}, nil
	},

	readTypeProperties: func(_ armdatafactory.LinkedServiceClassification, _ map[string]any) {
		// Nothing to read: connectionString is declared writeOnly and was sent as
		// a SecureString, so ARM returns only a mask and comparing it would
		// report drift forever. accountKey, sasToken, sasUri and
		// encryptedCredential are not modelled at all.
	},
}

func init() {
	registry.Register(ResourceTypeDataFactoryLinkedServiceAzureTableStorage, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &DataFactoryLinkedService{
			api:    c.DataFactoryLinkedServicesClient,
			kind:   &dataFactoryLinkedServiceTableStorageKind,
			config: cfg,
		}
	})
}
