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

const ResourceTypeDataFactoryLinkedServiceAzureBlobStorage = "AZURE::DataFactory::LinkedServiceAzureBlobStorage"

// dataFactoryLinkedServiceBlobStorageProps mirrors the connector-specific half of
// schema/pkl/datafactory/datafactorylinkedserviceblobstorage.pkl. The shared half
// lives in dataFactoryLinkedServiceCommon.
type dataFactoryLinkedServiceBlobStorageProps struct {
	ServiceEndpoint  *string `json:"serviceEndpoint"`
	ConnectionString *string `json:"connectionString"`
	AccountKind      *string `json:"accountKind"`
}

// dataFactoryLinkedServiceBlobStorageKind is the AzureBlobStorage connector.
//
// serviceEndpoint and connectionString are mutually exclusive: the first
// authenticates with the factory's managed identity, the second embeds an account
// key or SAS. ARM rejects both together, and that check is made here so the
// mistake fails before any ARM call rather than as an opaque 400.
var dataFactoryLinkedServiceBlobStorageKind = linkedServiceKind{
	resourceType: ResourceTypeDataFactoryLinkedServiceAzureBlobStorage,
	armType:      "AzureBlobStorage",

	build: func(common *dataFactoryLinkedServiceCommon, payload json.RawMessage) (armdatafactory.LinkedServiceClassification, error) {
		var props dataFactoryLinkedServiceBlobStorageProps
		if err := json.Unmarshal(payload, &props); err != nil {
			return nil, fmt.Errorf("failed to parse resource properties: %w", err)
		}

		hasEndpoint := props.ServiceEndpoint != nil && *props.ServiceEndpoint != ""
		hasConnectionString := props.ConnectionString != nil && *props.ConnectionString != ""
		if hasEndpoint && hasConnectionString {
			return nil, fmt.Errorf("serviceEndpoint and connectionString are mutually exclusive")
		}
		if !hasEndpoint && !hasConnectionString {
			return nil, fmt.Errorf("one of serviceEndpoint or connectionString is required")
		}

		typeProps := &armdatafactory.AzureBlobStorageLinkedServiceTypeProperties{
			AccountKind: props.AccountKind,
		}
		if hasEndpoint {
			typeProps.ServiceEndpoint = props.ServiceEndpoint
		}
		if secret := dataFactorySecureString(props.ConnectionString); secret != nil {
			typeProps.ConnectionString = secret
		}

		return &armdatafactory.AzureBlobStorageLinkedService{
			Description:    common.Description,
			ConnectVia:     common.connectVia(),
			Annotations:    common.annotationList(),
			TypeProperties: typeProps,
		}, nil
	},

	readTypeProperties: func(properties armdatafactory.LinkedServiceClassification, props map[string]any) {
		ls, ok := properties.(*armdatafactory.AzureBlobStorageLinkedService)
		if !ok || ls.TypeProperties == nil {
			return
		}
		if ls.TypeProperties.ServiceEndpoint != nil && *ls.TypeProperties.ServiceEndpoint != "" {
			props["serviceEndpoint"] = *ls.TypeProperties.ServiceEndpoint
		}
		if ls.TypeProperties.AccountKind != nil && *ls.TypeProperties.AccountKind != "" {
			props["accountKind"] = canonicalizeEnum(*ls.TypeProperties.AccountKind,
				"Storage", "StorageV2", "BlobStorage", "BlockBlobStorage")
		}
		// connectionString is declared writeOnly and is never read back: it was
		// sent as a SecureString, so ARM returns only a mask and comparing it
		// would report drift forever. The service-principal, SAS-token,
		// credential and encryptedCredential shapes are not modelled at all.
	},
}

func init() {
	registry.Register(ResourceTypeDataFactoryLinkedServiceAzureBlobStorage, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &DataFactoryLinkedService{
			api:    c.DataFactoryLinkedServicesClient,
			kind:   &dataFactoryLinkedServiceBlobStorageKind,
			config: cfg,
		}
	})
}
