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

const ResourceTypeStreamAnalyticsInputIotHub = "AZURE::StreamAnalytics::InputIotHub"

// streamAnalyticsIotHubDatasourceType is the ARM discriminator for the IoT Hub
// stream input datasource.
const streamAnalyticsIotHubDatasourceType = "Microsoft.Devices/IotHubs"

func init() {
	registry.Register(ResourceTypeStreamAnalyticsInputIotHub, func(c *client.Client, _ *config.Config) prov.Provisioner {
		return &StreamAnalyticsInput{
			api:  c.StreamAnalyticsInputsClient,
			kind: streamAnalyticsInputIotHubKind,
		}
	})
}

// streamAnalyticsInputIotHubKind is the IoT Hub half of
// AZURE::StreamAnalytics::InputIotHub. The envelope lives in streamanalyticsio.go.
//
// `iotHubNamespace` is ARM's own name for what is really the IoT hub's own name
// (or its hostname); it is not a separate namespace resource the way an Event Hubs
// namespace is. The shared access policy must carry at least "service connect",
// which is why the default `iothubowner` policy is the usual choice.
var streamAnalyticsInputIotHubKind = streamAnalyticsInputKind{
	resourceType:   ResourceTypeStreamAnalyticsInputIotHub,
	datasourceType: streamAnalyticsIotHubDatasourceType,

	build: func(props map[string]any) (armstreamanalytics.StreamInputDataSourceClassification, error) {
		hubNamespace, err := saRequiredString(props, "iotHubNamespace")
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

		return &armstreamanalytics.IoTHubStreamInputDataSource{
			Type: to.Ptr(streamAnalyticsIotHubDatasourceType),
			Properties: &armstreamanalytics.IoTHubStreamInputDataSourceProperties{
				IotHubNamespace:        to.Ptr(hubNamespace),
				SharedAccessPolicyName: to.Ptr(policyName),
				SharedAccessPolicyKey:  to.Ptr(policyKey),
				Endpoint:               saStringPtr(props, "endpoint"),
				ConsumerGroupName:      saStringPtr(props, "consumerGroupName"),
			},
		}, nil
	},

	serialize: func(ds armstreamanalytics.StreamInputDataSourceClassification, props map[string]any) {
		hub, ok := ds.(*armstreamanalytics.IoTHubStreamInputDataSource)
		if !ok || hub == nil || hub.Properties == nil {
			return
		}
		body := hub.Properties
		if body.IotHubNamespace != nil {
			props["iotHubNamespace"] = *body.IotHubNamespace
		}
		if body.SharedAccessPolicyName != nil {
			props["sharedAccessPolicyName"] = *body.SharedAccessPolicyName
		}
		if body.Endpoint != nil {
			props["endpoint"] = *body.Endpoint
		}
		if body.ConsumerGroupName != nil {
			props["consumerGroupName"] = *body.ConsumerGroupName
		}
		// sharedAccessPolicyKey is never echoed: ARM strips it from every response.
	},
}
