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

const ResourceTypeStreamAnalyticsInputEventHub = "AZURE::StreamAnalytics::InputEventHub"

// streamAnalyticsEventHubDatasourceType is the ARM discriminator for the v1 Event
// Hub datasource, shared by the Event Hub input and the Event Hub output.
//
// Note the namespace: "Microsoft.ServiceBus/EventHub", not
// "Microsoft.EventHub/EventHub". The latter is the newer EventHubV2 datasource,
// which authenticates with a managed identity instead of a shared access policy
// key. Sending the ServiceBus form is what makes sharedAccessPolicyName/Key the
// credential pair.
const streamAnalyticsEventHubDatasourceType = "Microsoft.ServiceBus/EventHub"

func init() {
	registry.Register(ResourceTypeStreamAnalyticsInputEventHub, func(c *client.Client, _ *config.Config) prov.Provisioner {
		return &StreamAnalyticsInput{
			api:  c.StreamAnalyticsInputsClient,
			kind: streamAnalyticsInputEventHubKind,
		}
	})
}

// streamAnalyticsInputEventHubKind is the Event Hub half of
// AZURE::StreamAnalytics::InputEventHub. The envelope lives in
// streamanalyticsio.go.
var streamAnalyticsInputEventHubKind = streamAnalyticsInputKind{
	resourceType:   ResourceTypeStreamAnalyticsInputEventHub,
	datasourceType: streamAnalyticsEventHubDatasourceType,

	build: func(props map[string]any) (armstreamanalytics.StreamInputDataSourceClassification, error) {
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

		return &armstreamanalytics.EventHubStreamInputDataSource{
			Type: to.Ptr(streamAnalyticsEventHubDatasourceType),
			Properties: &armstreamanalytics.EventHubStreamInputDataSourceProperties{
				ServiceBusNamespace:    to.Ptr(namespace),
				EventHubName:           to.Ptr(hubName),
				SharedAccessPolicyName: to.Ptr(policyName),
				SharedAccessPolicyKey:  to.Ptr(policyKey),
				ConsumerGroupName:      saStringPtr(props, "consumerGroupName"),
			},
		}, nil
	},

	serialize: func(ds armstreamanalytics.StreamInputDataSourceClassification, props map[string]any) {
		hub, ok := ds.(*armstreamanalytics.EventHubStreamInputDataSource)
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
		if body.ConsumerGroupName != nil {
			props["consumerGroupName"] = *body.ConsumerGroupName
		}
		// sharedAccessPolicyKey is never echoed: ARM strips it from every response.
	},
}
