// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/datafactory/armdatafactory"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
)

const ResourceTypeDataFactoryLinkedServiceWeb = "AZURE::DataFactory::LinkedServiceWeb"

// dataFactoryLinkedServiceWebProps mirrors the connector-specific half of
// schema/pkl/datafactory/datafactorylinkedserviceweb.pkl. The shared half lives in
// dataFactoryLinkedServiceCommon.
type dataFactoryLinkedServiceWebProps struct {
	URL                string  `json:"url"`
	AuthenticationType string  `json:"authenticationType"`
	Username           *string `json:"username"`
	Password           *string `json:"password"`
}

// dataFactoryLinkedServiceWebKind is the Web connector.
//
// Its typeProperties block is itself discriminated, on authenticationType. Only
// Anonymous and Basic are expressible: ClientCertificate needs a base64 PFX and its
// password, neither of which ARM ever returns, so such a linked service could be
// created but never verified.
var dataFactoryLinkedServiceWebKind = linkedServiceKind{
	resourceType: ResourceTypeDataFactoryLinkedServiceWeb,
	armType:      "Web",

	build: func(common *dataFactoryLinkedServiceCommon, payload json.RawMessage) (armdatafactory.LinkedServiceClassification, error) {
		var props dataFactoryLinkedServiceWebProps
		if err := json.Unmarshal(payload, &props); err != nil {
			return nil, fmt.Errorf("failed to parse resource properties: %w", err)
		}
		if props.URL == "" {
			return nil, fmt.Errorf("url is required")
		}

		var typeProps armdatafactory.WebLinkedServiceTypePropertiesClassification
		switch props.AuthenticationType {
		case string(armdatafactory.WebAuthenticationTypeAnonymous):
			typeProps = &armdatafactory.WebAnonymousAuthentication{
				AuthenticationType: to.Ptr(armdatafactory.WebAuthenticationTypeAnonymous),
				URL:                props.URL,
			}
		case string(armdatafactory.WebAuthenticationTypeBasic):
			if props.Username == nil || *props.Username == "" {
				return nil, fmt.Errorf("username is required for Basic authentication")
			}
			password := dataFactorySecureString(props.Password)
			if password == nil {
				return nil, fmt.Errorf("password is required for Basic authentication")
			}
			typeProps = &armdatafactory.WebBasicAuthentication{
				AuthenticationType: to.Ptr(armdatafactory.WebAuthenticationTypeBasic),
				URL:                props.URL,
				Username:           *props.Username,
				Password:           password,
			}
		case "":
			return nil, fmt.Errorf("authenticationType is required")
		default:
			return nil, fmt.Errorf("authenticationType must be Anonymous or Basic, got %q", props.AuthenticationType)
		}

		return &armdatafactory.WebLinkedService{
			Description:    common.Description,
			ConnectVia:     common.connectVia(),
			Annotations:    common.annotationList(),
			TypeProperties: typeProps,
		}, nil
	},

	readTypeProperties: func(properties armdatafactory.LinkedServiceClassification, props map[string]any) {
		ls, ok := properties.(*armdatafactory.WebLinkedService)
		if !ok || ls.TypeProperties == nil {
			return
		}
		if base := ls.TypeProperties.GetWebLinkedServiceTypeProperties(); base != nil {
			if v, ok := dataFactoryExpressionString(base.URL); ok {
				props["url"] = v
			}
			if base.AuthenticationType != nil {
				props["authenticationType"] = canonicalizeEnum(string(*base.AuthenticationType),
					"Anonymous", "Basic", "ClientCertificate")
			}
		}
		if basic, ok := ls.TypeProperties.(*armdatafactory.WebBasicAuthentication); ok {
			if v, ok := dataFactoryExpressionString(basic.Username); ok {
				props["username"] = v
			}
		}
		// password is declared writeOnly and is never read back: it was sent as a
		// SecureString, so ARM returns only a mask and comparing it would report
		// drift forever.
	},
}

func init() {
	registry.Register(ResourceTypeDataFactoryLinkedServiceWeb, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &DataFactoryLinkedService{
			api:    c.DataFactoryLinkedServicesClient,
			kind:   &dataFactoryLinkedServiceWebKind,
			config: cfg,
		}
	})
}
