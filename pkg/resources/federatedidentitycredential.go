// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/msi/armmsi"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeFederatedIdentityCredential = "Azure::ManagedIdentity::FederatedIdentityCredential"

type federatedIdentityCredentialsAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName, resourceName, federatedIdentityCredentialResourceName string, parameters armmsi.FederatedIdentityCredential, options *armmsi.FederatedIdentityCredentialsClientCreateOrUpdateOptions) (armmsi.FederatedIdentityCredentialsClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName, resourceName, federatedIdentityCredentialResourceName string, options *armmsi.FederatedIdentityCredentialsClientGetOptions) (armmsi.FederatedIdentityCredentialsClientGetResponse, error)
	Delete(ctx context.Context, resourceGroupName, resourceName, federatedIdentityCredentialResourceName string, options *armmsi.FederatedIdentityCredentialsClientDeleteOptions) (armmsi.FederatedIdentityCredentialsClientDeleteResponse, error)
	NewListPager(resourceGroupName, resourceName string, options *armmsi.FederatedIdentityCredentialsClientListOptions) *runtime.Pager[armmsi.FederatedIdentityCredentialsClientListResponse]
}

func init() {
	registry.Register(ResourceTypeFederatedIdentityCredential, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &FederatedIdentityCredential{api: c.FederatedIdentityCredentialsClient, config: cfg}
	})
}

// FederatedIdentityCredential is the provisioner for federated identity credentials
// attached to a user-assigned managed identity (e.g., AKS workload identity, GitHub OIDC).
type FederatedIdentityCredential struct {
	api    federatedIdentityCredentialsAPI
	config *config.Config
}

func serializeFederatedIdentityCredentialProperties(result armmsi.FederatedIdentityCredential, rgName, uaiName, ficName string) (json.RawMessage, error) {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	props["userAssignedIdentityName"] = uaiName
	if result.Name != nil {
		props["name"] = *result.Name
	} else {
		props["name"] = ficName
	}

	if result.Properties != nil {
		if result.Properties.Issuer != nil {
			props["issuer"] = *result.Properties.Issuer
		}
		if result.Properties.Subject != nil {
			props["subject"] = *result.Properties.Subject
		}
		if len(result.Properties.Audiences) > 0 {
			audiences := make([]string, 0, len(result.Properties.Audiences))
			for _, a := range result.Properties.Audiences {
				if a != nil {
					audiences = append(audiences, *a)
				}
			}
			props["audiences"] = audiences
		}
	}

	if result.ID != nil {
		props["id"] = *result.ID
	}

	return json.Marshal(props)
}

func ficParamsFromProperties(props map[string]any) (armmsi.FederatedIdentityCredential, error) {
	issuer, _ := props["issuer"].(string)
	if issuer == "" {
		return armmsi.FederatedIdentityCredential{}, fmt.Errorf("issuer is required")
	}
	subject, _ := props["subject"].(string)
	if subject == "" {
		return armmsi.FederatedIdentityCredential{}, fmt.Errorf("subject is required")
	}

	rawAudiences, ok := props["audiences"].([]any)
	if !ok || len(rawAudiences) == 0 {
		return armmsi.FederatedIdentityCredential{}, fmt.Errorf("audiences is required")
	}
	audiences := make([]*string, 0, len(rawAudiences))
	for _, raw := range rawAudiences {
		s, ok := raw.(string)
		if !ok {
			return armmsi.FederatedIdentityCredential{}, fmt.Errorf("audiences must be a list of strings")
		}
		v := s
		audiences = append(audiences, &v)
	}

	return armmsi.FederatedIdentityCredential{
		Properties: &armmsi.FederatedIdentityCredentialProperties{
			Issuer:    &issuer,
			Subject:   &subject,
			Audiences: audiences,
		},
	}, nil
}

func (f *FederatedIdentityCredential) parseNativeID(nativeID string) (rgName, uaiName, ficName string, err error) {
	parts := splitResourceID(nativeID)
	rgName = parts["resourcegroups"]
	uaiName = parts["userassignedidentities"]
	ficName = parts["federatedidentitycredentials"]
	if rgName == "" || uaiName == "" || ficName == "" {
		return "", "", "", fmt.Errorf("invalid NativeID: %s", nativeID)
	}
	return rgName, uaiName, ficName, nil
}

func (f *FederatedIdentityCredential) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props map[string]any
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	rgName, _ := props["resourceGroupName"].(string)
	if rgName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	uaiName, _ := props["userAssignedIdentityName"].(string)
	if uaiName == "" {
		return nil, fmt.Errorf("userAssignedIdentityName is required")
	}
	ficName, _ := props["name"].(string)
	if ficName == "" {
		ficName = request.Label
	}
	if ficName == "" {
		return nil, fmt.Errorf("name is required")
	}

	params, err := ficParamsFromProperties(props)
	if err != nil {
		return nil, err
	}

	result, err := f.api.CreateOrUpdate(ctx, rgName, uaiName, ficName, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       mapAzureErrorToOperationErrorCode(err),
			},
		}, nil
	}

	propsJSON, err := serializeFederatedIdentityCredentialProperties(result.FederatedIdentityCredential, rgName, uaiName, ficName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize FederatedIdentityCredential properties: %w", err)
	}

	return &resource.CreateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:          resource.OperationCreate,
			OperationStatus:    resource.OperationStatusSuccess,
			NativeID:           *result.ID,
			ResourceProperties: propsJSON,
		},
	}, nil
}

func (f *FederatedIdentityCredential) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, uaiName, ficName, err := f.parseNativeID(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := f.api.Get(ctx, rgName, uaiName, ficName, nil)
	if err != nil {
		return &resource.ReadResult{
			ErrorCode: mapAzureErrorToOperationErrorCode(err),
		}, nil
	}

	propsJSON, err := serializeFederatedIdentityCredentialProperties(result.FederatedIdentityCredential, rgName, uaiName, ficName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize FederatedIdentityCredential properties: %w", err)
	}

	return &resource.ReadResult{
		ResourceType: ResourceTypeFederatedIdentityCredential,
		Properties:   string(propsJSON),
	}, nil
}

func (f *FederatedIdentityCredential) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, uaiName, ficName, err := f.parseNativeID(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props map[string]any
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse desired properties: %w", err)
	}

	params, err := ficParamsFromProperties(props)
	if err != nil {
		return nil, err
	}

	result, err := f.api.CreateOrUpdate(ctx, rgName, uaiName, ficName, params, nil)
	if err != nil {
		return &resource.UpdateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationUpdate,
				OperationStatus: resource.OperationStatusFailure,
				NativeID:        request.NativeID,
				ErrorCode:       mapAzureErrorToOperationErrorCode(err),
			},
		}, nil
	}

	propsJSON, err := serializeFederatedIdentityCredentialProperties(result.FederatedIdentityCredential, rgName, uaiName, ficName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize FederatedIdentityCredential properties: %w", err)
	}

	return &resource.UpdateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:          resource.OperationUpdate,
			OperationStatus:    resource.OperationStatusSuccess,
			NativeID:           *result.ID,
			ResourceProperties: propsJSON,
		},
	}, nil
}

func (f *FederatedIdentityCredential) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, uaiName, ficName, err := f.parseNativeID(request.NativeID)
	if err != nil {
		return nil, err
	}

	if _, err := f.api.Delete(ctx, rgName, uaiName, ficName, nil); err != nil {
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
		}, fmt.Errorf("failed to delete FederatedIdentityCredential: %w", err)
	}

	return &resource.DeleteResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationDelete,
			OperationStatus: resource.OperationStatusSuccess,
			NativeID:        request.NativeID,
		},
	}, nil
}

func (f *FederatedIdentityCredential) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	// FIC operations are synchronous; if Status is called, do a Read.
	rgName, uaiName, ficName, err := f.parseNativeID(request.NativeID)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
			},
		}, err
	}

	result, err := f.api.Get(ctx, rgName, uaiName, ficName, nil)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       mapAzureErrorToOperationErrorCode(err),
			},
		}, fmt.Errorf("failed to get FederatedIdentityCredential status: %w", err)
	}

	propsJSON, err := serializeFederatedIdentityCredentialProperties(result.FederatedIdentityCredential, rgName, uaiName, ficName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize FederatedIdentityCredential properties: %w", err)
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

func (f *FederatedIdentityCredential) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	uaiName := request.AdditionalProperties["userAssignedIdentityName"]
	if rgName == "" || uaiName == "" {
		return &resource.ListResult{}, nil
	}

	var nativeIDs []string
	pager := f.api.NewListPager(rgName, uaiName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list FederatedIdentityCredentials: %w", err)
		}
		for _, fic := range page.Value {
			if fic.ID != nil {
				nativeIDs = append(nativeIDs, *fic.ID)
			}
		}
	}

	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
