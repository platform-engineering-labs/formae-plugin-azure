// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeResourceGroup = "Azure::Resources::ResourceGroup"

// azureTagsToFormaeTags, formaeTagsToAzureTags, mapAzureErrorToOperationErrorCode,
// splitResourceID are defined in common.go

func init() {
	registry.Register(ResourceTypeResourceGroup, func(client *client.Client, cfg *config.Config) prov.Provisioner {
		return &ResourceGroup{client, cfg}
	})
}

type ResourceGroup struct {
	Client *client.Client
	Config *config.Config
}

// serializeResourceGroupProperties converts an Azure ResourceGroup to Formae property format
func serializeResourceGroupProperties(result armresources.ResourceGroup, rgName string) (json.RawMessage, error) {
	props := make(map[string]interface{})

	// Add name (required field in schema)
	props["name"] = rgName

	// Add location (normalized to "name" format: lowercase, no spaces)
	// Azure returns inconsistent formats - ResourceGroup uses "westus2", others use "West US 2"
	if result.Location != nil {
		props["location"] = strings.ToLower(strings.ReplaceAll(*result.Location, " ", ""))
	}

	// Add tags in Formae's Tag format
	if tags := azureTagsToFormaeTags(result.Tags); tags != nil {
		props["Tags"] = tags
	}

	// Add managedBy if present
	if result.ManagedBy != nil {
		props["managedBy"] = *result.ManagedBy
	}

	// Include id for resolvable references
	if result.ID != nil {
		props["id"] = *result.ID
	}

	// Marshal properties to JSON
	return json.Marshal(props)
}

func (rg *ResourceGroup) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	// Parse properties JSON
	var props map[string]interface{}
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	// Extract location (required)
	location, ok := props["location"].(string)
	if !ok || location == "" {
		return nil, fmt.Errorf("location is required")
	}

	// Extract resource group name from properties, fall back to label
	rgName, ok := props["name"].(string)
	if !ok || rgName == "" {
		rgName = request.Label
	}

	// Build ResourceGroup parameters
	params := armresources.ResourceGroup{
		Location: &location,
	}

	// Add tags if present
	if azureTags := formaeTagsToAzureTags(request.Properties); azureTags != nil {
		params.Tags = azureTags
	}

	// Add managedBy if present
	if managedBy, ok := props["managedBy"].(string); ok && managedBy != "" {
		params.ManagedBy = &managedBy
	}

	// Call Azure API to create resource group
	// Note: Resource Groups are synchronous operations (no LRO polling needed)
	result, err := rg.Client.ResourceGroupsClient.CreateOrUpdate(
		ctx,
		rgName, // Resource group name from properties or label
		params,
		nil,
	)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,

				ErrorCode: mapAzureErrorToOperationErrorCode(err),
			},
		}, fmt.Errorf("failed to create resource group: %w", err)
	}

	// Serialize properties using shared serialization logic
	propsJSON, err := serializeResourceGroupProperties(result.ResourceGroup, rgName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize resource group properties: %w", err)
	}

	// Return CreateResult with properties for synchronous operation
	return &resource.CreateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationCreate,
			OperationStatus: resource.OperationStatusSuccess,
			NativeID:        *result.ID,

			ResourceProperties: propsJSON,
		},
	}, nil
}

func (rg *ResourceGroup) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	// Extract resource group name from NativeID
	parts := splitResourceID(request.NativeID)
	rgName, ok := parts["resourcegroups"]
	if !ok || rgName == "" {
		return nil, fmt.Errorf("invalid NativeID: could not extract resource group name from %s", request.NativeID)
	}

	// Parse properties JSON
	var props map[string]interface{}
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	// Extract location (required for Azure API even though it's CreateOnly)
	location, ok := props["location"].(string)
	if !ok || location == "" {
		return nil, fmt.Errorf("location is required")
	}

	// Build ResourceGroup parameters
	params := armresources.ResourceGroup{
		Location: &location,
	}

	// Add tags if present
	if azureTags := formaeTagsToAzureTags(request.DesiredProperties); azureTags != nil {
		params.Tags = azureTags
	}

	// Note: managedBy is a CreateOnly field, so we don't update it

	// Call Azure API to update resource group
	// Note: CreateOrUpdate handles both create and update operations
	// Resource Groups are synchronous operations (no LRO polling needed)
	result, err := rg.Client.ResourceGroupsClient.CreateOrUpdate(
		ctx,
		rgName,
		params,
		nil,
	)
	if err != nil {
		return &resource.UpdateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationUpdate,
				OperationStatus: resource.OperationStatusFailure,
				NativeID:        request.NativeID,

				ErrorCode: mapAzureErrorToOperationErrorCode(err),
			},
		}, fmt.Errorf("failed to update resource group: %w", err)
	}

	// Serialize properties using shared serialization logic
	propsJSON, err := serializeResourceGroupProperties(result.ResourceGroup, rgName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize resource group properties: %w", err)
	}

	// Return UpdateResult with properties for synchronous operation
	return &resource.UpdateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationUpdate,
			OperationStatus: resource.OperationStatusSuccess,
			NativeID:        *result.ID,

			ResourceProperties: propsJSON,
		},
	}, nil
}

func (rg *ResourceGroup) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	// Extract resource group name from NativeID
	parts := splitResourceID(request.NativeID)
	rgName, ok := parts["resourcegroups"]
	if !ok || rgName == "" {
		return nil, fmt.Errorf("invalid NativeID: could not extract resource group name from %s", request.NativeID)
	}

	// Start async deletion
	poller, err := rg.Client.ResourceGroupsClient.BeginDelete(ctx, rgName, nil)
	if err != nil {
		// If the resource is already gone (NotFound), treat as success
		if mapAzureErrorToOperationErrorCode(err) == resource.OperationErrorCodeNotFound {
			return &resource.DeleteResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationDelete,
					OperationStatus: resource.OperationStatusSuccess,
					NativeID:        request.NativeID,
				},
			}, nil
		}
		return &resource.DeleteResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationDelete,
				OperationStatus: resource.OperationStatusFailure,
				NativeID:        request.NativeID,

				ErrorCode: mapAzureErrorToOperationErrorCode(err),
			},
		}, fmt.Errorf("failed to start resource group deletion: %w", err)
	}

	// Check if the operation completed synchronously
	if poller.Done() {
		_, err := poller.Result(ctx)
		if err != nil {
			// For delete operations, NotFound means the resource is gone (success)
			if mapAzureErrorToOperationErrorCode(err) == resource.OperationErrorCodeNotFound {
				return &resource.DeleteResult{
					ProgressResult: &resource.ProgressResult{
						Operation:       resource.OperationDelete,
						OperationStatus: resource.OperationStatusSuccess,
						NativeID:        request.NativeID,
					},
				}, nil
			}
			return &resource.DeleteResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationDelete,
					OperationStatus: resource.OperationStatusFailure,
					NativeID:        request.NativeID,
					ErrorCode:       mapAzureErrorToOperationErrorCode(err),
				},
			}, fmt.Errorf("failed to get resource group delete result: %w", err)
		}

		return &resource.DeleteResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationDelete,
				OperationStatus: resource.OperationStatusSuccess,
				NativeID:        request.NativeID,
			},
		}, nil
	}

	// Get the ResumeToken - this is a serializable representation of the poller state
	// that allows us to track the operation across process restarts
	resumeToken, err := poller.ResumeToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get resume token: %w", err)
	}

	// Return InProgress with ResumeToken as RequestID
	// The RequestID will be used by Status to poll for completion
	return &resource.DeleteResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationDelete,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       resumeToken, // ResumeToken contains operation tracking info
			NativeID:        request.NativeID,
		},
	}, nil
}

func (rg *ResourceGroup) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	// RequestID is the ResumeToken (serialized poller state) from the Delete operation
	resumeToken := request.RequestID

	// Reconstruct the poller from the resume token
	poller, err := rg.Client.ResumeDeleteResourceGroupPoller(resumeToken)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationDelete,
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,

				ErrorCode: resource.OperationErrorCodeGeneralServiceException,
			},
		}, fmt.Errorf("failed to resume poller from token: %w", err)
	}

	// Check if the operation is already done
	if poller.Done() {
		// Operation completed - get the result
		_, err := poller.Result(ctx)
		if err != nil {
			// For delete operations, NotFound means the resource is gone (success)
			if mapAzureErrorToOperationErrorCode(err) == resource.OperationErrorCodeNotFound {
				return &resource.StatusResult{
					ProgressResult: &resource.ProgressResult{
						Operation:       resource.OperationDelete,
						OperationStatus: resource.OperationStatusSuccess,
						RequestID:       request.RequestID,
					},
				}, nil
			}
			// Operation failed
			return &resource.StatusResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationDelete,
					OperationStatus: resource.OperationStatusFailure,
					RequestID:       request.RequestID,

					ErrorCode: mapAzureErrorToOperationErrorCode(err),
				},
			}, nil
		}
		// Operation succeeded - resource was deleted
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationDelete,
				OperationStatus: resource.OperationStatusSuccess,
				RequestID:       request.RequestID,
			},
		}, nil
	}

	// Operation still in progress - poll for updated status
	_, err = poller.Poll(ctx)
	if err != nil {
		// For delete operations, NotFound means the resource is gone (success)
		if mapAzureErrorToOperationErrorCode(err) == resource.OperationErrorCodeNotFound {
			return &resource.StatusResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationDelete,
					OperationStatus: resource.OperationStatusSuccess,
					RequestID:       request.RequestID,
				},
			}, nil
		}
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationDelete,
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,

				ErrorCode: mapAzureErrorToOperationErrorCode(err),
			},
		}, nil
	}

	// Check if Poll() updated the state to done
	if poller.Done() {
		_, err := poller.Result(ctx)
		if err != nil {
			if mapAzureErrorToOperationErrorCode(err) == resource.OperationErrorCodeNotFound {
				return &resource.StatusResult{
					ProgressResult: &resource.ProgressResult{
						Operation:       resource.OperationDelete,
						OperationStatus: resource.OperationStatusSuccess,
						RequestID:       request.RequestID,
					},
				}, nil
			}
			return &resource.StatusResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationDelete,
					OperationStatus: resource.OperationStatusFailure,
					RequestID:       request.RequestID,
					ErrorCode:       mapAzureErrorToOperationErrorCode(err),
				},
			}, nil
		}
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationDelete,
				OperationStatus: resource.OperationStatusSuccess,
				RequestID:       request.RequestID,
			},
		}, nil
	}

	// Still in progress
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationDelete,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       request.RequestID,
		},
	}, nil
}

func (rg *ResourceGroup) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	// Extract resource group name from NativeID
	// NativeID format: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}
	parts := splitResourceID(request.NativeID)
	rgName, ok := parts["resourcegroups"]
	if !ok || rgName == "" {
		return nil, fmt.Errorf("invalid NativeID: could not extract resource group name from %s", request.NativeID)
	}

	// Get resource group from Azure
	result, err := rg.Client.ResourceGroupsClient.Get(ctx, rgName, nil)
	if err != nil {
		return &resource.ReadResult{

			ErrorCode: mapAzureErrorToOperationErrorCode(err),
		}, fmt.Errorf("failed to read resource group: %w", err)
	}

	// Serialize properties using shared serialization logic
	propsJSON, err := serializeResourceGroupProperties(result.ResourceGroup, rgName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize resource group properties: %w", err)
	}

	return &resource.ReadResult{

		Properties: string(propsJSON),
	}, nil
}

func (rg *ResourceGroup) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	log := plugin.LoggerFromContext(ctx)
	log.Debug("ResourceGroup.List starting")

	pager := rg.Client.ResourceGroupsClient.NewListPager(nil)

	var nativeIDs []string
	pageNum := 0

	for pager.More() {
		pageNum++
		page, err := pager.NextPage(ctx)
		if err != nil {
			log.Error("ResourceGroup.List failed", "page", pageNum, "error", err)
			return nil, fmt.Errorf("failed to list resource groups: %w", err)
		}

		pageCount := len(page.Value)
		log.Debug("ResourceGroup.List page received", "page", pageNum, "itemsInPage", pageCount)

		for _, rg := range page.Value {
			if rg.ID == nil {
				continue
			}
			nativeIDs = append(nativeIDs, *rg.ID)
		}
	}

	log.Debug("ResourceGroup.List completed", "totalPages", pageNum, "totalItems", len(nativeIDs))

	return &resource.ListResult{
		NativeIDs: nativeIDs,
	}, nil
}
