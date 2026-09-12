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
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeDataFactoryIntegrationRuntimeSelfHosted = "AZURE::DataFactory::IntegrationRuntimeSelfHosted"

// dataFactoryIntegrationRuntimesAPI is the armdatafactory surface both integration
// runtime types use. CreateOrUpdate, Get and Delete are all synchronous: the only
// pollers on IntegrationRuntimesClient are BeginStart and BeginStop, which apply to
// Azure-SSIS runtimes this provider does not manage.
type dataFactoryIntegrationRuntimesAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName string, factoryName string, integrationRuntimeName string, integrationRuntime armdatafactory.IntegrationRuntimeResource, options *armdatafactory.IntegrationRuntimesClientCreateOrUpdateOptions) (armdatafactory.IntegrationRuntimesClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName string, factoryName string, integrationRuntimeName string, options *armdatafactory.IntegrationRuntimesClientGetOptions) (armdatafactory.IntegrationRuntimesClientGetResponse, error)
	Delete(ctx context.Context, resourceGroupName string, factoryName string, integrationRuntimeName string, options *armdatafactory.IntegrationRuntimesClientDeleteOptions) (armdatafactory.IntegrationRuntimesClientDeleteResponse, error)
	NewListByFactoryPager(resourceGroupName string, factoryName string, options *armdatafactory.IntegrationRuntimesClientListByFactoryOptions) *runtime.Pager[armdatafactory.IntegrationRuntimesClientListByFactoryResponse]
}

func init() {
	registry.Register(ResourceTypeDataFactoryIntegrationRuntimeSelfHosted, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &DataFactoryIntegrationRuntimeSelfHosted{
			api:    c.DataFactoryIntegrationRuntimesClient,
			config: cfg,
		}
	})
}

// DataFactoryIntegrationRuntimeSelfHosted is the provisioner for self-hosted
// integration runtimes (Microsoft.DataFactory/factories/integrationRuntimes with
// type SelfHosted).
//
// Creating one provisions no compute: it is a registration record that hands back a
// pair of auth keys, and nothing runs until an operator installs the agent on a
// machine of their own. The auth keys are never serialized — ARM returns them only
// from a separate ListAuthKeys call, so putting them in resource state would
// persist live credentials.
type DataFactoryIntegrationRuntimeSelfHosted struct {
	api    dataFactoryIntegrationRuntimesAPI
	config *config.Config
}

// dataFactoryIntegrationRuntimeProps mirrors the shared part of
// schema/pkl/datafactory/datafactoryintegrationruntimeselfhosted.pkl and
// schema/pkl/datafactory/datafactoryintegrationruntimeazure.pkl.
type dataFactoryIntegrationRuntimeProps struct {
	Name              string  `json:"name"`
	ResourceGroupName string  `json:"resourceGroupName"`
	FactoryName       string  `json:"factoryName"`
	Description       *string `json:"description"`
	// Azure (managed) runtimes only.
	ComputeLocation     *string `json:"computeLocation"`
	DataFlowComputeType *string `json:"dataFlowComputeType"`
	DataFlowCoreCount   *int32  `json:"dataFlowCoreCount"`
	DataFlowTimeToLive  *int32  `json:"dataFlowTimeToLive"`
}

// parse validates the parent coordinates every integration runtime needs and
// resolves the runtime name, falling back to the resource label.
func (p *dataFactoryIntegrationRuntimeProps) parse(payload json.RawMessage, fallbackName string) error {
	if err := json.Unmarshal(payload, p); err != nil {
		return fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if p.ResourceGroupName == "" {
		return fmt.Errorf("resourceGroupName is required")
	}
	if p.FactoryName == "" {
		return fmt.Errorf("factoryName is required")
	}
	if p.Name == "" {
		p.Name = fallbackName
	}
	if p.Name == "" {
		return fmt.Errorf("name is required")
	}
	return nil
}

// dataFactoryIntegrationRuntimeBaseProps maps the fields shared by both runtime
// types out of an ARM response.
func dataFactoryIntegrationRuntimeBaseProps(ir armdatafactory.IntegrationRuntimeClassification, rgName, factoryName, name string) map[string]any {
	props := map[string]any{
		"resourceGroupName": rgName,
		"factoryName":       factoryName,
	}
	if name != "" {
		props["name"] = name
	}
	if ir == nil {
		return props
	}
	if base := ir.GetIntegrationRuntime(); base != nil && base.Description != nil && *base.Description != "" {
		props["description"] = *base.Description
	}
	return props
}

func (s *DataFactoryIntegrationRuntimeSelfHosted) buildPropertiesFromResult(res *armdatafactory.IntegrationRuntimeResource, rgName, factoryName string) map[string]any {
	name := ""
	if res.Name != nil {
		name = *res.Name
	}
	props := dataFactoryIntegrationRuntimeBaseProps(res.Properties, rgName, factoryName, name)
	if res.ID != nil {
		props["id"] = *res.ID
	}
	// typeProperties.linkedInfo is not modelled and is not read back: a linked
	// runtime is created through a different verb and is keyed by a sharing
	// credential ARM never returns.
	return props
}

func (s *DataFactoryIntegrationRuntimeSelfHosted) params(props dataFactoryIntegrationRuntimeProps) armdatafactory.IntegrationRuntimeResource {
	return armdatafactory.IntegrationRuntimeResource{
		Properties: &armdatafactory.SelfHostedIntegrationRuntime{
			Type:        to.Ptr(armdatafactory.IntegrationRuntimeTypeSelfHosted),
			Description: props.Description,
		},
	}
}

func (s *DataFactoryIntegrationRuntimeSelfHosted) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props dataFactoryIntegrationRuntimeProps
	if err := props.parse(request.Properties, request.Label); err != nil {
		return nil, err
	}

	result, err := s.api.CreateOrUpdate(ctx, props.ResourceGroupName, props.FactoryName, props.Name, s.params(props), nil)
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
	propsJSON, err := json.Marshal(s.buildPropertiesFromResult(&result.IntegrationRuntimeResource, props.ResourceGroupName, props.FactoryName))
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

func (s *DataFactoryIntegrationRuntimeSelfHosted) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, factoryName, name, err := dataFactoryChildIDParts(request.NativeID, "integrationruntimes")
	if err != nil {
		return nil, err
	}

	result, err := s.api.Get(ctx, rgName, factoryName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(s.buildPropertiesFromResult(&result.IntegrationRuntimeResource, rgName, factoryName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeDataFactoryIntegrationRuntimeSelfHosted,
		Properties:   string(propsJSON),
	}, nil
}

// Update reissues CreateOrUpdate. The narrower Update verb takes only autoUpdate
// and updateDelayOffset, neither of which this type models.
func (s *DataFactoryIntegrationRuntimeSelfHosted) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, factoryName, name, err := dataFactoryChildIDParts(request.NativeID, "integrationruntimes")
	if err != nil {
		return nil, err
	}

	var props dataFactoryIntegrationRuntimeProps
	if err := props.parse(request.DesiredProperties, name); err != nil {
		return nil, err
	}

	result, err := s.api.CreateOrUpdate(ctx, rgName, factoryName, name, s.params(props), nil)
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

	propsJSON, err := json.Marshal(s.buildPropertiesFromResult(&result.IntegrationRuntimeResource, rgName, factoryName))
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

func (s *DataFactoryIntegrationRuntimeSelfHosted) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, factoryName, name, err := dataFactoryChildIDParts(request.NativeID, "integrationruntimes")
	if err != nil {
		return nil, err
	}

	if _, err := s.api.Delete(ctx, rgName, factoryName, name, nil); err != nil && !isDeleteSuccessError(err) {
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
func (s *DataFactoryIntegrationRuntimeSelfHosted) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

// List enumerates a factory's runtimes and keeps only the self-hosted ones: ARM
// returns both kinds from the same pager, and handing an Azure runtime's ID to this
// provisioner would read it with the wrong shape.
func (s *DataFactoryIntegrationRuntimeSelfHosted) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	factoryName := request.AdditionalProperties["factoryName"]
	if rgName == "" || factoryName == "" {
		return &resource.ListResult{}, nil
	}

	nativeIDs, err := dataFactoryListIntegrationRuntimes(ctx, s.api, rgName, factoryName,
		armdatafactory.IntegrationRuntimeTypeSelfHosted)
	if err != nil {
		return nil, err
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}

// dataFactoryListIntegrationRuntimes pages a factory's integration runtimes and
// returns the IDs of those of the wanted type. Shared by both runtime provisioners.
func dataFactoryListIntegrationRuntimes(
	ctx context.Context,
	api dataFactoryIntegrationRuntimesAPI,
	rgName, factoryName string,
	want armdatafactory.IntegrationRuntimeType,
) ([]string, error) {
	var nativeIDs []string
	pager := api.NewListByFactoryPager(rgName, factoryName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list data factory integration runtimes: %w", err)
		}
		for _, ir := range page.Value {
			if ir == nil || ir.ID == nil || ir.Properties == nil {
				continue
			}
			base := ir.Properties.GetIntegrationRuntime()
			if base == nil || base.Type == nil || *base.Type != want {
				continue
			}
			nativeIDs = append(nativeIDs, *ir.ID)
		}
	}
	return nativeIDs, nil
}
