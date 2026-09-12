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

const ResourceTypeStreamAnalyticsOutputServiceBusQueue = "AZURE::StreamAnalytics::OutputServiceBusQueue"

// streamAnalyticsServiceBusQueueDatasourceType is the ARM discriminator for the
// Service Bus queue output datasource.
const streamAnalyticsServiceBusQueueDatasourceType = "Microsoft.ServiceBus/Queue"

func init() {
	registry.Register(ResourceTypeStreamAnalyticsOutputServiceBusQueue, func(c *client.Client, _ *config.Config) prov.Provisioner {
		return &StreamAnalyticsOutput{
			api:  c.StreamAnalyticsOutputsClient,
			kind: streamAnalyticsOutputServiceBusQueueKind,
		}
	})
}

// streamAnalyticsOutputServiceBusQueueKind is the Service Bus queue half of
// AZURE::StreamAnalytics::OutputServiceBusQueue. The envelope lives in
// streamanalyticsio.go.
//
// `systemPropertyColumns` is not modelled: the SDK types it as a bare `any`
// (it is a free-form map of Service Bus system property to output column, and
// older API versions typed it as a string array), so there is no stable PKL shape
// for it and no way to verify what ARM echoes back.
var streamAnalyticsOutputServiceBusQueueKind = streamAnalyticsOutputKind{
	resourceType:   ResourceTypeStreamAnalyticsOutputServiceBusQueue,
	datasourceType: streamAnalyticsServiceBusQueueDatasourceType,
	serialization:  true,

	build: func(props map[string]any) (armstreamanalytics.OutputDataSourceClassification, error) {
		namespace, err := saRequiredString(props, "serviceBusNamespace")
		if err != nil {
			return nil, err
		}
		queueName, err := saRequiredString(props, "queueName")
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

		return &armstreamanalytics.ServiceBusQueueOutputDataSource{
			Type: to.Ptr(streamAnalyticsServiceBusQueueDatasourceType),
			Properties: &armstreamanalytics.ServiceBusQueueOutputDataSourceProperties{
				ServiceBusNamespace:    to.Ptr(namespace),
				QueueName:              to.Ptr(queueName),
				SharedAccessPolicyName: to.Ptr(policyName),
				SharedAccessPolicyKey:  to.Ptr(policyKey),
				PropertyColumns:        stringPointers(saStringList(props, "propertyColumns")),
			},
		}, nil
	},

	serialize: func(ds armstreamanalytics.OutputDataSourceClassification, props map[string]any) {
		queue, ok := ds.(*armstreamanalytics.ServiceBusQueueOutputDataSource)
		if !ok || queue == nil || queue.Properties == nil {
			return
		}
		body := queue.Properties
		if body.ServiceBusNamespace != nil {
			props["serviceBusNamespace"] = *body.ServiceBusNamespace
		}
		if body.QueueName != nil {
			props["queueName"] = *body.QueueName
		}
		if body.SharedAccessPolicyName != nil {
			props["sharedAccessPolicyName"] = *body.SharedAccessPolicyName
		}
		if columns := stringsFromPointers(body.PropertyColumns); columns != nil {
			props["propertyColumns"] = columns
		}
		// sharedAccessPolicyKey is never echoed: ARM strips it from every response.
	},
}
