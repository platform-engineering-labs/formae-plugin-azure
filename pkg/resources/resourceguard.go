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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/dataprotection/armdataprotection/v3"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeResourceGuard = "AZURE::DataProtection::ResourceGuard"

// resourceGuardsAPI is the armdataprotection surface used here.
//
// Unlike its BackupVault sibling in the same SDK module, every resourceGuards
// operation is synchronous — the ARM contract is PUT/GET/PATCH/DELETE with no
// Azure-AsyncOperation header — so there is no poller and no resume token
// anywhere in this file.
type resourceGuardsAPI interface {
	Put(ctx context.Context, resourceGroupName string, resourceGuardsName string, parameters armdataprotection.ResourceGuardResource, options *armdataprotection.ResourceGuardsClientPutOptions) (armdataprotection.ResourceGuardsClientPutResponse, error)
	Get(ctx context.Context, resourceGroupName string, resourceGuardsName string, options *armdataprotection.ResourceGuardsClientGetOptions) (armdataprotection.ResourceGuardsClientGetResponse, error)
	Delete(ctx context.Context, resourceGroupName string, resourceGuardsName string, options *armdataprotection.ResourceGuardsClientDeleteOptions) (armdataprotection.ResourceGuardsClientDeleteResponse, error)
	NewGetResourcesInSubscriptionPager(options *armdataprotection.ResourceGuardsClientGetResourcesInSubscriptionOptions) *runtime.Pager[armdataprotection.ResourceGuardsClientGetResourcesInSubscriptionResponse]
	NewGetResourcesInResourceGroupPager(resourceGroupName string, options *armdataprotection.ResourceGuardsClientGetResourcesInResourceGroupOptions) *runtime.Pager[armdataprotection.ResourceGuardsClientGetResourcesInResourceGroupResponse]
}

func init() {
	registry.Register(ResourceTypeResourceGuard, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &ResourceGuard{
			api:    c.ResourceGuardsClient,
			config: cfg,
		}
	})
}

// ResourceGuard is the provisioner for Resource Guards
// (Microsoft.DataProtection/resourceGuards).
type ResourceGuard struct {
	api    resourceGuardsAPI
	config *config.Config
}

// resourceGuardProps mirrors schema/pkl/dataprotection/resourceguard.pkl.
type resourceGuardProps struct {
	Name                                string   `json:"name"`
	Location                            string   `json:"location"`
	ResourceGroupName                   string   `json:"resourceGroupName"`
	VaultCriticalOperationExclusionList []string `json:"vaultCriticalOperationExclusionList"`
}

func resourceGuardIDParts(resourceID string) (rgName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "resourceguards")
	if err != nil {
		return "", "", err
	}
	return rgName, names["resourceguards"], nil
}

func (r *ResourceGuard) buildPropertiesFromResult(guard *armdataprotection.ResourceGuardResource, rgName string) map[string]any {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName

	if guard.ID != nil {
		props["id"] = *guard.ID
	}
	if guard.Name != nil {
		props["name"] = *guard.Name
	}
	if guard.Location != nil {
		props["location"] = normalizeAzureLocation(*guard.Location)
	}

	if p := guard.Properties; p != nil {
		if ops := stringsFromPointers(p.VaultCriticalOperationExclusionList); ops != nil {
			props["vaultCriticalOperationExclusionList"] = ops
		}
		if p.ProvisioningState != nil {
			props["provisioningState"] = string(*p.ProvisioningState)
		}
	}

	if tags := azureTagsToFormaeTags(guard.Tags); tags != nil {
		props["Tags"] = tags
	}

	return props
}

// putParams builds the PUT body. ARM's PATCH for a Resource Guard carries tags
// and nothing else (PatchResourceGuardInput has a single Tags field), so an
// exclusion-list change has to go back through PUT — which is why Update calls
// Put too rather than Patch.
func resourceGuardPutParams(props resourceGuardProps, rawProperties []byte) armdataprotection.ResourceGuardResource {
	params := armdataprotection.ResourceGuardResource{
		Location: to.Ptr(props.Location),
		Properties: &armdataprotection.ResourceGuard{
			VaultCriticalOperationExclusionList: stringPointers(props.VaultCriticalOperationExclusionList),
		},
	}
	if azureTags := formaeTagsToAzureTags(rawProperties); azureTags != nil {
		params.Tags = azureTags
	}
	return params
}

func (r *ResourceGuard) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props resourceGuardProps
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	if props.Location == "" {
		return nil, fmt.Errorf("location is required")
	}
	name := props.Name
	if name == "" {
		name = request.Label
	}
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}

	result, err := r.api.Put(ctx, props.ResourceGroupName, name, resourceGuardPutParams(props, request.Properties), nil)
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

	propsJSON, err := json.Marshal(r.buildPropertiesFromResult(&result.ResourceGuardResource, props.ResourceGroupName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}

	nativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.DataProtection/resourceGuards/%s",
		r.config.SubscriptionId, props.ResourceGroupName, name)
	if result.ID != nil {
		nativeID = *result.ID
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

func (r *ResourceGuard) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, name, err := resourceGuardIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := r.api.Get(ctx, rgName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(r.buildPropertiesFromResult(&result.ResourceGuardResource, rgName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeResourceGuard,
		Properties:   string(propsJSON),
	}, nil
}

func (r *ResourceGuard) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, name, err := resourceGuardIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props resourceGuardProps
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.Location == "" {
		return nil, fmt.Errorf("location is required")
	}

	result, err := r.api.Put(ctx, rgName, name, resourceGuardPutParams(props, request.DesiredProperties), nil)
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

	propsJSON, err := json.Marshal(r.buildPropertiesFromResult(&result.ResourceGuardResource, rgName))
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

func (r *ResourceGuard) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, name, err := resourceGuardIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	if _, err := r.api.Delete(ctx, rgName, name, nil); err != nil && !isDeleteSuccessError(err) {
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

// Status re-reads the guard. Every operation on this type is synchronous, so
// Status is only ever reached if the agent retries a request it already has a
// terminal answer for.
func (r *ResourceGuard) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	rgName, name, err := resourceGuardIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := r.api.Get(ctx, rgName, name, nil)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				NativeID:        request.NativeID,
				ErrorCode:       operationErrorCode(err),
				StatusMessage:   err.Error(),
			},
		}, nil
	}

	propsJSON, err := json.Marshal(r.buildPropertiesFromResult(&result.ResourceGuardResource, rgName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus:    resource.OperationStatusSuccess,
			RequestID:          request.RequestID,
			NativeID:           request.NativeID,
			ResourceProperties: propsJSON,
		},
	}, nil
}

func (r *ResourceGuard) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]

	var nativeIDs []string

	if rgName != "" {
		pager := r.api.NewGetResourcesInResourceGroupPager(rgName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list resource guards: %w", err)
			}
			for _, guard := range page.Value {
				if guard.ID != nil {
					nativeIDs = append(nativeIDs, *guard.ID)
				}
			}
		}
		return &resource.ListResult{NativeIDs: nativeIDs}, nil
	}

	pager := r.api.NewGetResourcesInSubscriptionPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list resource guards: %w", err)
		}
		for _, guard := range page.Value {
			if guard.ID != nil {
				nativeIDs = append(nativeIDs, *guard.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
