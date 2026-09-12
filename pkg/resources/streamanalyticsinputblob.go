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

const ResourceTypeStreamAnalyticsInputBlob = "AZURE::StreamAnalytics::InputBlob"

// streamAnalyticsBlobDatasourceType is the ARM discriminator shared by the blob
// input and the blob output.
const streamAnalyticsBlobDatasourceType = "Microsoft.Storage/Blob"

func init() {
	registry.Register(ResourceTypeStreamAnalyticsInputBlob, func(c *client.Client, _ *config.Config) prov.Provisioner {
		return &StreamAnalyticsInput{
			api:  c.StreamAnalyticsInputsClient,
			kind: streamAnalyticsInputBlobKind,
		}
	})
}

// streamAnalyticsInputBlobKind is the blob half of AZURE::StreamAnalytics::InputBlob.
// The envelope (CRUD, List, ID parsing) lives in streamanalyticsio.go.
//
// ARM models the storage account as a one-element `storageAccounts` array. The
// schema flattens it to storageAccountName + storageAccountKey because the array
// is single-valued in practice and a nested list would put the credential inside a
// nested class, where writeOnly buys nothing.
var streamAnalyticsInputBlobKind = streamAnalyticsInputKind{
	resourceType:   ResourceTypeStreamAnalyticsInputBlob,
	datasourceType: streamAnalyticsBlobDatasourceType,

	build: func(props map[string]any) (armstreamanalytics.StreamInputDataSourceClassification, error) {
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

		body := &armstreamanalytics.BlobStreamInputDataSourceProperties{
			Container:   to.Ptr(container),
			PathPattern: to.Ptr(pathPattern),
			StorageAccounts: []*armstreamanalytics.StorageAccount{{
				AccountName: to.Ptr(accountName),
				AccountKey:  to.Ptr(accountKey),
			}},
			DateFormat:           saStringPtr(props, "dateFormat"),
			TimeFormat:           saStringPtr(props, "timeFormat"),
			SourcePartitionCount: saInt32Ptr(props, "sourcePartitionCount"),
		}

		return &armstreamanalytics.BlobStreamInputDataSource{
			Type:       to.Ptr(streamAnalyticsBlobDatasourceType),
			Properties: body,
		}, nil
	},

	serialize: func(ds armstreamanalytics.StreamInputDataSourceClassification, props map[string]any) {
		blob, ok := ds.(*armstreamanalytics.BlobStreamInputDataSource)
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
		if body.SourcePartitionCount != nil {
			props["sourcePartitionCount"] = *body.SourcePartitionCount
		}
		// storageAccountKey is deliberately absent: ARM strips AccountKey from
		// every response, so echoing it would report drift on every sync.
		for _, account := range body.StorageAccounts {
			if account != nil && account.AccountName != nil {
				props["storageAccountName"] = *account.AccountName
				break
			}
		}
	},
}
