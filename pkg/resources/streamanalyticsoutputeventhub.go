// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/streamanalytics/armstreamanalytics"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
)

const ResourceTypeStreamAnalyticsOutputEventHub = "AZURE::StreamAnalytics::OutputEventHub"

func init() {
	registry.Register(ResourceTypeStreamAnalyticsOutputEventHub, func(c *client.Client, _ *config.Config) prov.Provisioner {
		return &StreamAnalyticsOutput{
			api:  c.StreamAnalyticsOutputsClient,
			kind: streamAnalyticsOutputEventHubKind,
		}
	})
}

// streamAnalyticsOutputEventHubKind is the Event Hub half of
// AZURE::StreamAnalytics::OutputEventHub. The envelope lives in
// streamanalyticsio.go.
var streamAnalyticsOutputEventHubKind = streamAnalyticsOutputKind{
	resourceType:   ResourceTypeStreamAnalyticsOutputEventHub,
	datasourceType: streamAnalyticsEventHubDatasourceType,
	serialization:  true,

	build: func(props map[string]any) (armstreamanalytics.OutputDataSourceClassification, error) {
		namespace, err := saRequiredString(props, "serviceBusNamespace")
		if err != nil {
			return nil, err
		}
		hubName, err := saRequiredString(props, "eventHubName")
		if err != nil {
			return nil, err
		}
		policyName, err := saRequiredString(props, "sharedAccessPolicyName")
		if err != nil {
			return nil, err
		}
		policyKey, err := saRequiredString(props, "sharedAccessPolicyKey")
		if err != nil {
			return nil, err
		}

		return &armstreamanalytics.EventHubOutputDataSource{
			Type: to.Ptr(streamAnalyticsEventHubDatasourceType),
			Properties: &armstreamanalytics.EventHubOutputDataSourceProperties{
				ServiceBusNamespace:    to.Ptr(namespace),
				EventHubName:           to.Ptr(hubName),
				SharedAccessPolicyName: to.Ptr(policyName),
				SharedAccessPolicyKey:  to.Ptr(policyKey),
				PartitionKey:           saStringPtr(props, "partitionKey"),
				PropertyColumns:        stringPointers(saStringList(props, "propertyColumns")),
			},
		}, nil
	},

	serialize: func(ds armstreamanalytics.OutputDataSourceClassification, props map[string]any) {
		hub, ok := ds.(*armstreamanalytics.EventHubOutputDataSource)
		if !ok || hub == nil || hub.Properties == nil {
			return
		}
		body := hub.Properties
		if body.ServiceBusNamespace != nil {
			props["serviceBusNamespace"] = *body.ServiceBusNamespace
		}
		if body.EventHubName != nil {
			props["eventHubName"] = *body.EventHubName
		}
		if body.SharedAccessPolicyName != nil {
			props["sharedAccessPolicyName"] = *body.SharedAccessPolicyName
		}
		if body.PartitionKey != nil {
			props["partitionKey"] = *body.PartitionKey
		}
		if columns := stringsFromPointers(body.PropertyColumns); columns != nil {
			props["propertyColumns"] = columns
		}
		// sharedAccessPolicyKey is never echoed: ARM strips it from every response.
	},
}
