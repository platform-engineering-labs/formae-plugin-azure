// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/msi/armmsi"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeUserAssignedIdentity = "Azure::ManagedIdentity::UserAssignedIdentity"

func init() {
	registry.Register(ResourceTypeUserAssignedIdentity, func(client *client.Client, cfg *config.Config) prov.Provisioner {
		return &UserAssignedIdentity{client, cfg}
	})
}

// UserAssignedIdentity is the provisioner for Azure User Assigned Managed Identities.
type UserAssignedIdentity struct {
	Client *client.Client
	Config *config.Config
}

// serializeUserAssignedIdentityProperties converts an Azure UserAssignedIdentity to Formae property format
func serializeUserAssignedIdentityProperties(result armmsi.Identity, rgName, identityName string) (json.RawMessage, error) {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	if result.Name != nil {
		props["name"] = *result.Name
	} else {
		props["name"] = identityName
	}

	if result.Location != nil {
		props["location"] = *result.Location
	}

	// Properties contains output-only fields
	if result.Properties != nil {
		if result.Properties.PrincipalID != nil {
			props["principalId"] = *result.Properties.PrincipalID
		}
		if result.Properties.ClientID != nil {
			props["clientId"] = *result.Properties.ClientID
		}
		if result.Properties.TenantID != nil {
			props["tenantId"] = *result.Properties.TenantID
		}
	}

	// Add tags
	if tags := azureTagsToFormaeTags(result.Tags); tags != nil {
		props["Tags"] = tags
	}

	// Include id for resolvable references
	if result.ID != nil {
		props["id"] = *result.ID
	}

	return json.Marshal(props)
}

func (u *UserAssignedIdentity) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props map[string]any
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	rgName, ok := props["resourceGroupName"].(string)
	if !ok || rgName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}

	location, ok := props["location"].(string)
	if !ok || location == "" {
		return nil, fmt.Errorf("location is required")
	}

	identityName, ok := props["name"].(string)
	if !ok || identityName == "" {
		identityName = request.Label
	}

	params := armmsi.Identity{
		Location: stringPtr(location),
	}

	if azureTags := formaeTagsToAzureTags(request.Properties); azureTags != nil {
		params.Tags = azureTags
	}

	// User assigned identity creation is synchronous
	result, err := u.Client.UserAssignedIdentitiesClient.CreateOrUpdate(ctx, rgName, identityName, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       mapAzureErrorToOperationErrorCode(err),
			},
		}, fmt.Errorf("failed to create UserAssignedIdentity: %w", err)
	}

	// Return success without ResourceProperties per Lesson 1
	// Properties will be populated by framework via Status→Read flow
	return &resource.CreateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationCreate,
			OperationStatus: resource.OperationStatusSuccess,
			NativeID:        *result.ID,
		},
	}, nil
}

func (u *UserAssignedIdentity) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	parts := splitResourceID(request.NativeID)

	rgName, ok := parts["resourcegroups"]
	if !ok || rgName == "" {
		return nil, fmt.Errorf("invalid NativeID: could not extract resource group name from %s", request.NativeID)
	}

	identityName, ok := parts["userassignedidentities"]
	if !ok || identityName == "" {
		return nil, fmt.Errorf("invalid NativeID: could not extract UserAssignedIdentity name from %s", request.NativeID)
	}

	result, err := u.Client.UserAssignedIdentitiesClient.Get(ctx, rgName, identityName, nil)
	if err != nil {
		return &resource.ReadResult{
			ErrorCode: mapAzureErrorToOperationErrorCode(err),
		}, fmt.Errorf("failed to read UserAssignedIdentity: %w", err)
	}

	propsJSON, err := serializeUserAssignedIdentityProperties(result.Identity, rgName, identityName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize UserAssignedIdentity properties: %w", err)
	}

	return &resource.ReadResult{
		Properties: string(propsJSON),
	}, nil
}

func (u *UserAssignedIdentity) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	parts := splitResourceID(request.NativeID)

	rgName, ok := parts["resourcegroups"]
	if !ok || rgName == "" {
		return nil, fmt.Errorf("invalid NativeID: could not extract resource group name from %s", request.NativeID)
	}

	identityName, ok := parts["userassignedidentities"]
	if !ok || identityName == "" {
		return nil, fmt.Errorf("invalid NativeID: could not extract UserAssignedIdentity name from %s", request.NativeID)
	}

	// Only tags can be updated for user assigned identities
	params := armmsi.IdentityUpdate{}

	if azureTags := formaeTagsToAzureTags(request.DesiredProperties); azureTags != nil {
		params.Tags = azureTags
	}

	// User assigned identity update is synchronous
	result, err := u.Client.UserAssignedIdentitiesClient.Update(ctx, rgName, identityName, params, nil)
	if err != nil {
		return &resource.UpdateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationUpdate,
				OperationStatus: resource.OperationStatusFailure,
				NativeID:        request.NativeID,
				ErrorCode:       mapAzureErrorToOperationErrorCode(err),
			},
		}, fmt.Errorf("failed to update UserAssignedIdentity: %w", err)
	}

	// Return success without ResourceProperties per Lesson 1
	return &resource.UpdateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationUpdate,
			OperationStatus: resource.OperationStatusSuccess,
			NativeID:        *result.ID,
		},
	}, nil
}

func (u *UserAssignedIdentity) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	parts := splitResourceID(request.NativeID)

	rgName, ok := parts["resourcegroups"]
	if !ok || rgName == "" {
		return nil, fmt.Errorf("invalid NativeID: could not extract resource group name from %s", request.NativeID)
	}

	identityName, ok := parts["userassignedidentities"]
	if !ok || identityName == "" {
		return nil, fmt.Errorf("invalid NativeID: could not extract UserAssignedIdentity name from %s", request.NativeID)
	}

	// User assigned identity deletion is synchronous
	_, err := u.Client.UserAssignedIdentitiesClient.Delete(ctx, rgName, identityName, nil)
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
				ErrorCode:       mapAzureErrorToOperationErrorCode(err),
			},
		}, fmt.Errorf("failed to delete UserAssignedIdentity: %w", err)
	}

	return &resource.DeleteResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationDelete,
			OperationStatus: resource.OperationStatusSuccess,
			NativeID:        request.NativeID,
		},
	}, nil
}

func (u *UserAssignedIdentity) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	// User assigned identity operations are synchronous, so Status should not be called
	// If it is called, do a Read to get current state
	parts := splitResourceID(request.NativeID)

	rgName := parts["resourcegroups"]
	identityName := parts["userassignedidentities"]

	if rgName == "" || identityName == "" {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
			},
		}, fmt.Errorf("invalid NativeID: could not extract resource group or identity name")
	}

	result, err := u.Client.UserAssignedIdentitiesClient.Get(ctx, rgName, identityName, nil)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       mapAzureErrorToOperationErrorCode(err),
			},
		}, fmt.Errorf("failed to get UserAssignedIdentity status: %w", err)
	}

	propsJSON, err := serializeUserAssignedIdentityProperties(result.Identity, rgName, identityName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize UserAssignedIdentity properties: %w", err)
	}

	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus:    resource.OperationStatusSuccess,
			RequestID:          request.RequestID,
			NativeID:           *result.ID,
			ResourceProperties: propsJSON,
		},
	}, nil
}

func (u *UserAssignedIdentity) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	resourceGroupName, ok := request.AdditionalProperties["resourceGroupName"]
	if !ok || resourceGroupName == "" {
		return nil, fmt.Errorf("resourceGroupName is required in AdditionalProperties for listing UserAssignedIdentities")
	}

	pager := u.Client.UserAssignedIdentitiesClient.NewListByResourceGroupPager(resourceGroupName, nil)

	var nativeIDs []string

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list user assigned identities in resource group %s: %w", resourceGroupName, err)
		}

		for _, identity := range page.Value {
			if identity.ID == nil {
				continue
			}

			nativeIDs = append(nativeIDs, *identity.ID)
		}
	}

	return &resource.ListResult{
		NativeIDs: nativeIDs,
	}, nil
}
