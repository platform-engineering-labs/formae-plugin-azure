// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/datafactory/armdatafactory"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeDataFactoryIntegrationRuntimeAzure = "AZURE::DataFactory::IntegrationRuntimeAzure"

// dataFactoryComputeLocationAutoResolve is the sentinel that lets the service pick
// the activity region, and is what it fills in when computeProperties.location is
// omitted.
const dataFactoryComputeLocationAutoResolve = "AutoResolve"

func init() {
	registry.Register(ResourceTypeDataFactoryIntegrationRuntimeAzure, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &DataFactoryIntegrationRuntimeAzure{
			api:    c.DataFactoryIntegrationRuntimesClient,
			config: cfg,
		}
	})
}

// DataFactoryIntegrationRuntimeAzure is the provisioner for Azure
// (service-managed) integration runtimes
// (Microsoft.DataFactory/factories/integrationRuntimes with type Managed).
//
// ARM calls the type "Managed" and uses the same shape for Azure-SSIS, which is
// deliberately not expressible here: nodeSize and numberOfNodes turn the runtime
// into a dedicated SSIS cluster that must be started explicitly and bills per
// node-hour. This provisioner only ever sends the on-demand shape, so creating one
// allocates nothing and takes no VM quota.
type DataFactoryIntegrationRuntimeAzure struct {
	api    dataFactoryIntegrationRuntimesAPI
	config *config.Config
}

// dataFactoryNormalizeComputeLocation folds the compute location to the form
// desired state uses.
//
// It is either the AutoResolve sentinel, which the service echoes verbatim, or a
// region name, which ARM may hand back spaced and capitalized ("East US") after
// accepting the compact form. Passing either through untouched reports drift on
// every sync, and folding both would turn AutoResolve into "autoresolve".
func dataFactoryNormalizeComputeLocation(location string) string {
	if strings.EqualFold(location, dataFactoryComputeLocationAutoResolve) {
		return dataFactoryComputeLocationAutoResolve
	}
	return normalizeAzureLocation(location)
}

func (a *DataFactoryIntegrationRuntimeAzure) params(props dataFactoryIntegrationRuntimeProps) armdatafactory.IntegrationRuntimeResource {
	compute := &armdatafactory.IntegrationRuntimeComputeProperties{}
	if props.ComputeLocation != nil && *props.ComputeLocation != "" {
		compute.Location = props.ComputeLocation
	}

	dataFlow := &armdatafactory.IntegrationRuntimeDataFlowProperties{}
	if props.DataFlowComputeType != nil && *props.DataFlowComputeType != "" {
		dataFlow.ComputeType = to.Ptr(armdatafactory.DataFlowComputeType(*props.DataFlowComputeType))
	}
	dataFlow.CoreCount = props.DataFlowCoreCount
	dataFlow.TimeToLive = props.DataFlowTimeToLive
	if dataFlow.ComputeType != nil || dataFlow.CoreCount != nil || dataFlow.TimeToLive != nil {
		compute.DataFlowProperties = dataFlow
	}

	typeProps := &armdatafactory.ManagedIntegrationRuntimeTypeProperties{}
	if compute.Location != nil || compute.DataFlowProperties != nil {
		typeProps.ComputeProperties = compute
	}

	return armdatafactory.IntegrationRuntimeResource{
		Properties: &armdatafactory.ManagedIntegrationRuntime{
			Type:           to.Ptr(armdatafactory.IntegrationRuntimeTypeManaged),
			Description:    props.Description,
			TypeProperties: typeProps,
		},
	}
}

func (a *DataFactoryIntegrationRuntimeAzure) buildPropertiesFromResult(res *armdatafactory.IntegrationRuntimeResource, rgName, factoryName string) map[string]any {
	name := ""
	if res.Name != nil {
		name = *res.Name
	}
	props := dataFactoryIntegrationRuntimeBaseProps(res.Properties, rgName, factoryName, name)
	if res.ID != nil {
		props["id"] = *res.ID
	}

	managed, ok := res.Properties.(*armdatafactory.ManagedIntegrationRuntime)
	if !ok || managed.TypeProperties == nil {
		return props
	}
	// managed.State is service state (Started / Stopped / Online), not desired
	// state, and moves on its own — it is deliberately dropped.
	compute := managed.TypeProperties.ComputeProperties
	if compute == nil {
		return props
	}
	if compute.Location != nil && *compute.Location != "" {
		props["computeLocation"] = dataFactoryNormalizeComputeLocation(*compute.Location)
	}
	if df := compute.DataFlowProperties; df != nil {
		if df.ComputeType != nil {
			props["dataFlowComputeType"] = canonicalizeEnum(string(*df.ComputeType),
				"General", "MemoryOptimized", "ComputeOptimized")
		}
		if df.CoreCount != nil {
			props["dataFlowCoreCount"] = *df.CoreCount
		}
		if df.TimeToLive != nil {
			props["dataFlowTimeToLive"] = *df.TimeToLive
		}
	}
	// nodeSize, numberOfNodes, maxParallelExecutionsPerNode and vNetProperties are
	// the Azure-SSIS half of this model. They are not modelled and not read back:
	// a runtime carrying them was not created by this provider.
	return props
}

func (a *DataFactoryIntegrationRuntimeAzure) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props dataFactoryIntegrationRuntimeProps
	if err := props.parse(request.Properties, request.Label); err != nil {
		return nil, err
	}

	result, err := a.api.CreateOrUpdate(ctx, props.ResourceGroupName, props.FactoryName, props.Name, a.params(props), nil)
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
	propsJSON, err := json.Marshal(a.buildPropertiesFromResult(&result.IntegrationRuntimeResource, props.ResourceGroupName, props.FactoryName))
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

func (a *DataFactoryIntegrationRuntimeAzure) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, factoryName, name, err := dataFactoryChildIDParts(request.NativeID, "integrationruntimes")
	if err != nil {
		return nil, err
	}

	result, err := a.api.Get(ctx, rgName, factoryName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(a.buildPropertiesFromResult(&result.IntegrationRuntimeResource, rgName, factoryName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeDataFactoryIntegrationRuntimeAzure,
		Properties:   string(propsJSON),
	}, nil
}

// Update reissues CreateOrUpdate: the narrower Update verb only accepts autoUpdate
// and updateDelayOffset, which apply to self-hosted runtimes.
func (a *DataFactoryIntegrationRuntimeAzure) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, factoryName, name, err := dataFactoryChildIDParts(request.NativeID, "integrationruntimes")
	if err != nil {
		return nil, err
	}

	var props dataFactoryIntegrationRuntimeProps
	if err := props.parse(request.DesiredProperties, name); err != nil {
		return nil, err
	}

	result, err := a.api.CreateOrUpdate(ctx, rgName, factoryName, name, a.params(props), nil)
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

	propsJSON, err := json.Marshal(a.buildPropertiesFromResult(&result.IntegrationRuntimeResource, rgName, factoryName))
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

func (a *DataFactoryIntegrationRuntimeAzure) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, factoryName, name, err := dataFactoryChildIDParts(request.NativeID, "integrationruntimes")
	if err != nil {
		return nil, err
	}

	if _, err := a.api.Delete(ctx, rgName, factoryName, name, nil); err != nil && !isDeleteSuccessError(err) {
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

// Status echoes success: every verb this provisioner uses is synchronous.
func (a *DataFactoryIntegrationRuntimeAzure) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

// List enumerates a factory's runtimes and keeps only the managed ones: ARM returns
// both kinds from the same pager, and handing a self-hosted runtime's ID to this
// provisioner would read it with the wrong shape.
func (a *DataFactoryIntegrationRuntimeAzure) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	factoryName := request.AdditionalProperties["factoryName"]
	if rgName == "" || factoryName == "" {
		return &resource.ListResult{}, nil
	}

	nativeIDs, err := dataFactoryListIntegrationRuntimes(ctx, a.api, rgName, factoryName,
		armdatafactory.IntegrationRuntimeTypeManaged)
	if err != nil {
		return nil, err
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
