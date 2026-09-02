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

const ResourceTypeStreamAnalyticsOutputBlob = "AZURE::StreamAnalytics::OutputBlob"

func init() {
	registry.Register(ResourceTypeStreamAnalyticsOutputBlob, func(c *client.Client, _ *config.Config) prov.Provisioner {
		return &StreamAnalyticsOutput{
			api:  c.StreamAnalyticsOutputsClient,
			kind: streamAnalyticsOutputBlobKind,
		}
	})
}

// streamAnalyticsOutputBlobKind is the blob half of
// AZURE::StreamAnalytics::OutputBlob. The envelope lives in streamanalyticsio.go.
//
// Same flattening as the blob input: ARM's single-element `storageAccounts` array
// becomes storageAccountName + a write-only storageAccountKey.
var streamAnalyticsOutputBlobKind = streamAnalyticsOutputKind{
	resourceType:   ResourceTypeStreamAnalyticsOutputBlob,
	datasourceType: streamAnalyticsBlobDatasourceType,
	serialization:  true,

	build: func(props map[string]any) (armstreamanalytics.OutputDataSourceClassification, error) {
		accountName, err := saRequiredString(props, "storageAccountName")
		if err != nil {
			return nil, err
		}
		accountKey, err := saRequiredString(props, "storageAccountKey")
		if err != nil {
			return nil, err
		}
		container, err := saRequiredString(props, "container")
		if err != nil {
			return nil, err
		}
		pathPattern, err := saRequiredString(props, "pathPattern")
		if err != nil {
			return nil, err
		}

		return &armstreamanalytics.BlobOutputDataSource{
			Type: to.Ptr(streamAnalyticsBlobDatasourceType),
			Properties: &armstreamanalytics.BlobOutputDataSourceProperties{
				Container:   to.Ptr(container),
				PathPattern: to.Ptr(pathPattern),
				StorageAccounts: []*armstreamanalytics.StorageAccount{{
					AccountName: to.Ptr(accountName),
					AccountKey:  to.Ptr(accountKey),
				}},
				DateFormat: saStringPtr(props, "dateFormat"),
				TimeFormat: saStringPtr(props, "timeFormat"),
			},
		}, nil
	},

	serialize: func(ds armstreamanalytics.OutputDataSourceClassification, props map[string]any) {
		blob, ok := ds.(*armstreamanalytics.BlobOutputDataSource)
		if !ok || blob == nil || blob.Properties == nil {
			return
		}
		body := blob.Properties
		if body.Container != nil {
			props["container"] = *body.Container
		}
		if body.PathPattern != nil {
			props["pathPattern"] = *body.PathPattern
		}
		if body.DateFormat != nil {
			props["dateFormat"] = *body.DateFormat
		}
		if body.TimeFormat != nil {
			props["timeFormat"] = *body.TimeFormat
		}
		// storageAccountKey is never echoed: ARM strips AccountKey from responses.
		for _, account := range body.StorageAccounts {
			if account != nil && account.AccountName != nil {
				props["storageAccountName"] = *account.AccountName
				break
			}
		}
	},
}
