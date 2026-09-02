// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/datafactory/armdatafactory"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

// This file carries everything the five AZURE::DataFactory::Dataset* types share.
// All five POST the same DatasetResource envelope to the same four verbs and differ
// only in the discriminated Properties block, so the envelope, the read-back mapping
// and the CRUD live here once and each type file contributes only its discriminator.
// It is deliberately the same shape as datafactorylinkedservice.go, which does this
// for the five linked-service types. Precedent: cosmoschild.go, servicebusprops.go.

// dataFactoryDatasetsAPI is the armdatafactory surface all five types use. Every
// verb is synchronous — DatasetsClient has no BeginX at all — so no poller is ever
// created and Status never has real work to do.
type dataFactoryDatasetsAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName string, factoryName string, datasetName string, dataset armdatafactory.DatasetResource, options *armdatafactory.DatasetsClientCreateOrUpdateOptions) (armdatafactory.DatasetsClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName string, factoryName string, datasetName string, options *armdatafactory.DatasetsClientGetOptions) (armdatafactory.DatasetsClientGetResponse, error)
	Delete(ctx context.Context, resourceGroupName string, factoryName string, datasetName string, options *armdatafactory.DatasetsClientDeleteOptions) (armdatafactory.DatasetsClientDeleteResponse, error)
	NewListByFactoryPager(resourceGroupName string, factoryName string, options *armdatafactory.DatasetsClientListByFactoryOptions) *runtime.Pager[armdatafactory.DatasetsClientListByFactoryResponse]
}

// dataFactoryDatasetCommon is the part of every dataset schema that does not depend
// on the storage format.
type dataFactoryDatasetCommon struct {
	Name              string   `json:"name"`
	ResourceGroupName string   `json:"resourceGroupName"`
	FactoryName       string   `json:"factoryName"`
	LinkedServiceName string   `json:"linkedServiceName"`
	Description       *string  `json:"description"`
	FolderName        *string  `json:"folderName"`
	Annotations       []string `json:"annotations"`
}

func (c *dataFactoryDatasetCommon) parse(payload json.RawMessage, fallbackName string) error {
	if err := json.Unmarshal(payload, c); err != nil {
		return fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if c.ResourceGroupName == "" {
		return fmt.Errorf("resourceGroupName is required")
	}
	if c.FactoryName == "" {
		return fmt.Errorf("factoryName is required")
	}
	if c.LinkedServiceName == "" {
		return fmt.Errorf("linkedServiceName is required")
	}
	if c.Name == "" {
		c.Name = fallbackName
	}
	if c.Name == "" {
		return fmt.Errorf("name is required")
	}
	return nil
}

// linkedServiceRef builds the linked-service reference. Unlike the integration
// runtime on a linked service this is not optional: ARM rejects a dataset without
// one, which is why parse refuses an empty name before any ARM call is made.
func (c *dataFactoryDatasetCommon) linkedServiceRef() *armdatafactory.LinkedServiceReference {
	return &armdatafactory.LinkedServiceReference{
		Type:          to.Ptr(armdatafactory.LinkedServiceReferenceTypeLinkedServiceReference),
		ReferenceName: to.Ptr(c.LinkedServiceName),
	}
}

// folder builds the authoring-UI folder block. Returning nil leaves it out so the
// dataset appears at the root, which is what an undeclared folder must mean.
func (c *dataFactoryDatasetCommon) folder() *armdatafactory.DatasetFolder {
	if c.FolderName == nil || *c.FolderName == "" {
		return nil
	}
	return &armdatafactory.DatasetFolder{Name: c.FolderName}
}

// annotationList widens the schema's Listing<String> to the free-form JSON list
// ARM models annotations as.
func (c *dataFactoryDatasetCommon) annotationList() []any {
	if len(c.Annotations) == 0 {
		return nil
	}
	out := make([]any, 0, len(c.Annotations))
	for _, annotation := range c.Annotations {
		out = append(out, annotation)
	}
	return out
}

// dataFactoryBlobLocationProps is the location block the DelimitedText, Json and
// Parquet datasets share.
//
// ARM models a dataset location as a discriminated union with a dozen members
// (AzureBlobFSLocation, AmazonS3Location, HTTPServerLocation, ...). Only
// AzureBlobStorageLocation is modelled here, because that is the one a
// LinkedServiceAzureBlobStorage — the only object-store linked service this plugin
// has — can address. A dataset pointing anywhere else is not expressible and is not
// read back either.
type dataFactoryBlobLocationProps struct {
	Container  string  `json:"container"`
	FolderPath *string `json:"folderPath"`
	FileName   *string `json:"fileName"`
}

// blobLocation builds the AzureBlobStorageLocation block. The container is
// required: ARM refuses a DelimitedText, Json or Parquet dataset without a
// location, and a location without a container addresses nothing.
func (p dataFactoryBlobLocationProps) blobLocation() (*armdatafactory.AzureBlobStorageLocation, error) {
	if p.Container == "" {
		return nil, fmt.Errorf("container is required")
	}
	location := &armdatafactory.AzureBlobStorageLocation{
		Type:      to.Ptr("AzureBlobStorageLocation"),
		Container: p.Container,
	}
	if p.FolderPath != nil && *p.FolderPath != "" {
		location.FolderPath = *p.FolderPath
	}
	if p.FileName != nil && *p.FileName != "" {
		location.FileName = *p.FileName
	}
	return location, nil
}

// dataFactoryReadBlobLocation adds an AzureBlobStorageLocation back to the property
// set. A location of any other kind is skipped rather than half-read: surfacing
// something the schema cannot express would show as drift forever.
func dataFactoryReadBlobLocation(location armdatafactory.DatasetLocationClassification, props map[string]any) {
	blob, ok := location.(*armdatafactory.AzureBlobStorageLocation)
	if !ok || blob == nil {
		return
	}
	if v, ok := dataFactoryExpressionString(blob.Container); ok {
		props["container"] = v
	}
	if v, ok := dataFactoryExpressionString(blob.FolderPath); ok {
		props["folderPath"] = v
	}
	if v, ok := dataFactoryExpressionString(blob.FileName); ok {
		props["fileName"] = v
	}
}

// datasetKind is what a concrete dataset type contributes: its Formae resource
// type, and the two halves of the discriminated Properties block.
type datasetKind struct {
	// resourceType is the AZURE::DataFactory::Dataset* name.
	resourceType string

	// armType is the ARM discriminator, e.g. "AzureBlob". Used only in List, to
	// keep a factory's other datasets out of this type's results.
	armType string

	// build turns parsed properties into the concrete SDK model, base fields and
	// all. It is given the already-validated common block plus the raw payload so
	// it can pick out its own format fields.
	build func(common *dataFactoryDatasetCommon, payload json.RawMessage) (armdatafactory.DatasetClassification, error)

	// readTypeProperties adds the format-specific properties of an ARM response to
	// the property set.
	readTypeProperties func(properties armdatafactory.DatasetClassification, props map[string]any)
}

// DataFactoryDataset is the provisioner shared by all five dataset types
// (Microsoft.DataFactory/factories/datasets). The kind field decides which storage
// format it speaks for.
//
// Creating a dataset is a metadata write: it costs nothing, the service does not
// touch the storage it describes, and a dataset naming a container that does not
// exist still creates cleanly — it only fails when an activity reads it.
type DataFactoryDataset struct {
	api    dataFactoryDatasetsAPI
	kind   *datasetKind
	config *config.Config
}

func (d *DataFactoryDataset) buildPropertiesFromResult(res *armdatafactory.DatasetResource, rgName, factoryName string) map[string]any {
	props := map[string]any{
		"resourceGroupName": rgName,
		"factoryName":       factoryName,
	}
	if res.ID != nil {
		props["id"] = *res.ID
	}
	if res.Name != nil {
		props["name"] = *res.Name
	}

	if res.Properties == nil {
		return props
	}
	if base := res.Properties.GetDataset(); base != nil {
		if base.LinkedServiceName != nil && base.LinkedServiceName.ReferenceName != nil &&
			*base.LinkedServiceName.ReferenceName != "" {
			props["linkedServiceName"] = *base.LinkedServiceName.ReferenceName
		}
		if base.Description != nil && *base.Description != "" {
			props["description"] = *base.Description
		}
		if base.Folder != nil && base.Folder.Name != nil && *base.Folder.Name != "" {
			props["folderName"] = *base.Folder.Name
		}
		if annotations := dataFactoryAnnotationStrings(base.Annotations); len(annotations) > 0 {
			props["annotations"] = annotations
		}
		// parameters, structure and schema are not modelled and are not read
		// back: a dataset authored in the Data Factory UI reads without them.
	}
	d.kind.readTypeProperties(res.Properties, props)
	return props
}

func (d *DataFactoryDataset) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var common dataFactoryDatasetCommon
	if err := common.parse(request.Properties, request.Label); err != nil {
		return nil, err
	}
	properties, err := d.kind.build(&common, request.Properties)
	if err != nil {
		return nil, err
	}

	result, err := d.api.CreateOrUpdate(ctx, common.ResourceGroupName, common.FactoryName, common.Name,
		armdatafactory.DatasetResource{Properties: properties}, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
				StatusMessage:   err.Error(),
			},
		}, nil
	}

	nativeID := ""
	if result.ID != nil {
		nativeID = *result.ID
	}
	propsJSON, err := json.Marshal(d.buildPropertiesFromResult(&result.DatasetResource,
		common.ResourceGroupName, common.FactoryName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}

	return &resource.CreateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:          resource.OperationCreate,
			OperationStatus:    resource.OperationStatusSuccess,
			NativeID:           nativeID,
			ResourceProperties: propsJSON,
		},
	}, nil
}

func (d *DataFactoryDataset) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, factoryName, name, err := dataFactoryChildIDParts(request.NativeID, "datasets")
	if err != nil {
		return nil, err
	}

	result, err := d.api.Get(ctx, rgName, factoryName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(d.buildPropertiesFromResult(&result.DatasetResource, rgName, factoryName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: d.kind.resourceType,
		Properties:   string(propsJSON),
	}, nil
}

// Update reissues CreateOrUpdate: this API has no PATCH verb for datasets.
func (d *DataFactoryDataset) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, factoryName, name, err := dataFactoryChildIDParts(request.NativeID, "datasets")
	if err != nil {
		return nil, err
	}

	var common dataFactoryDatasetCommon
	if err := common.parse(request.DesiredProperties, name); err != nil {
		return nil, err
	}
	properties, err := d.kind.build(&common, request.DesiredProperties)
	if err != nil {
		return nil, err
	}

	result, err := d.api.CreateOrUpdate(ctx, rgName, factoryName, name,
		armdatafactory.DatasetResource{Properties: properties}, nil)
	if err != nil {
		return &resource.UpdateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationUpdate,
				OperationStatus: resource.OperationStatusFailure,
				NativeID:        request.NativeID,
				ErrorCode:       operationErrorCode(err),
				StatusMessage:   err.Error(),
			},
		}, nil
	}

	propsJSON, err := json.Marshal(d.buildPropertiesFromResult(&result.DatasetResource, rgName, factoryName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.UpdateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:          resource.OperationUpdate,
			OperationStatus:    resource.OperationStatusSuccess,
			NativeID:           request.NativeID,
			ResourceProperties: propsJSON,
		},
	}, nil
}

// Delete is refused by the service while a pipeline activity or a data flow still
// references the dataset; that arrives as a 400 and is surfaced as a failure with
// the provider's own reason.
func (d *DataFactoryDataset) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, factoryName, name, err := dataFactoryChildIDParts(request.NativeID, "datasets")
	if err != nil {
		return nil, err
	}

	if _, err := d.api.Delete(ctx, rgName, factoryName, name, nil); err != nil && !isDeleteSuccessError(err) {
		return &resource.DeleteResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationDelete,
				OperationStatus: resource.OperationStatusFailure,
				NativeID:        request.NativeID,
				ErrorCode:       operationErrorCode(err),
				StatusMessage:   err.Error(),
			},
		}, nil
	}

	return &resource.DeleteResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationDelete,
			OperationStatus: resource.OperationStatusSuccess,
			NativeID:        request.NativeID,
		},
	}, nil
}

// Status echoes success: every DatasetsClient verb is synchronous.
func (d *DataFactoryDataset) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

// List requires both the resource group and the factory name: ARM has no
// subscription-wide listing for datasets.
//
// A factory's pager returns every format at once, so the results are filtered by
// discriminator: handing a Parquet dataset's ID to the DelimitedText provisioner
// would read it with the wrong shape.
func (d *DataFactoryDataset) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	factoryName := request.AdditionalProperties["factoryName"]
	if rgName == "" || factoryName == "" {
		return &resource.ListResult{}, nil
	}

	var nativeIDs []string
	pager := d.api.NewListByFactoryPager(rgName, factoryName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list data factory datasets: %w", err)
		}
		for _, dataset := range page.Value {
			if dataset == nil || dataset.ID == nil || dataset.Properties == nil {
				continue
			}
			base := dataset.Properties.GetDataset()
			if base == nil || base.Type == nil || *base.Type != d.kind.armType {
				continue
			}
			nativeIDs = append(nativeIDs, *dataset.ID)
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
