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

const ResourceTypeDataFactoryLinkedServiceAzureSqlDatabase = "AZURE::DataFactory::LinkedServiceAzureSqlDatabase"

// dataFactoryLinkedServiceSQLDatabaseProps mirrors the connector-specific half of
// schema/pkl/datafactory/datafactorylinkedservicesqldatabase.pkl. The shared half
// lives in dataFactoryLinkedServiceCommon.
type dataFactoryLinkedServiceSQLDatabaseProps struct {
	ConnectionString   *string `json:"connectionString"`
	ServicePrincipalID *string `json:"servicePrincipalId"`
	Tenant             *string `json:"tenant"`
}

// dataFactoryLinkedServiceSQLDatabaseKind is the AzureSqlDatabase connector.
//
// The connection string is the whole configuration and is always sent as a
// SecureString, so the service stores it encrypted and returns only a mask. A
// string with no credentials in it means the factory's managed identity
// authenticates.
var dataFactoryLinkedServiceSQLDatabaseKind = linkedServiceKind{
	resourceType: ResourceTypeDataFactoryLinkedServiceAzureSqlDatabase,
	armType:      "AzureSqlDatabase",

	build: func(common *dataFactoryLinkedServiceCommon, payload json.RawMessage) (armdatafactory.LinkedServiceClassification, error) {
		var props dataFactoryLinkedServiceSQLDatabaseProps
		if err := json.Unmarshal(payload, &props); err != nil {
			return nil, fmt.Errorf("failed to parse resource properties: %w", err)
		}
		secret := dataFactorySecureString(props.ConnectionString)
		if secret == nil {
			return nil, fmt.Errorf("connectionString is required")
		}

		typeProps := &armdatafactory.AzureSQLDatabaseLinkedServiceTypeProperties{
			ConnectionString: secret,
		}
		if props.ServicePrincipalID != nil && *props.ServicePrincipalID != "" {
			typeProps.ServicePrincipalID = *props.ServicePrincipalID
		}
		if props.Tenant != nil && *props.Tenant != "" {
			typeProps.Tenant = *props.Tenant
		}

		return &armdatafactory.AzureSQLDatabaseLinkedService{
			Description:    common.Description,
			ConnectVia:     common.connectVia(),
			Annotations:    common.annotationList(),
			TypeProperties: typeProps,
		}, nil
	},

	readTypeProperties: func(properties armdatafactory.LinkedServiceClassification, props map[string]any) {
		ls, ok := properties.(*armdatafactory.AzureSQLDatabaseLinkedService)
		if !ok || ls.TypeProperties == nil {
			return
		}
		if v, ok := dataFactoryExpressionString(ls.TypeProperties.ServicePrincipalID); ok {
			props["servicePrincipalId"] = v
		}
		if v, ok := dataFactoryExpressionString(ls.TypeProperties.Tenant); ok {
			props["tenant"] = v
		}
		// connectionString is declared writeOnly and is never read back: it was
		// sent as a SecureString, so ARM returns only a mask and comparing it
		// would report drift forever. servicePrincipalKey, password,
		// alwaysEncryptedSettings, credential and encryptedCredential are not
		// modelled at all.
	},
}

func init() {
	registry.Register(ResourceTypeDataFactoryLinkedServiceAzureSqlDatabase, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &DataFactoryLinkedService{
			api:    c.DataFactoryLinkedServicesClient,
			kind:   &dataFactoryLinkedServiceSQLDatabaseKind,
			config: cfg,
		}
	})
}
