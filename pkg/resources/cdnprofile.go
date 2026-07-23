// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/cdn/armcdn/v2"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeCdnProfile = "AZURE::Cdn::Profile"

// cdnProfilesAPI is the narrow slice of *armcdn.ProfilesClient used by the
// provisioner. Create/Update/Delete are all long-running operations (LRO); Get
// is synchronous. Update is handled through BeginCreate (PUT create-or-update)
// so the request body stays a full armcdn.Profile for both operations.
type cdnProfilesAPI interface {
	BeginCreate(ctx context.Context, resourceGroupName string, profileName string, profile armcdn.Profile, options *armcdn.ProfilesClientBeginCreateOptions) (*runtime.Poller[armcdn.ProfilesClientCreateResponse], error)
	Get(ctx context.Context, resourceGroupName string, profileName string, options *armcdn.ProfilesClientGetOptions) (armcdn.ProfilesClientGetResponse, error)
	BeginDelete(ctx context.Context, resourceGroupName string, profileName string, options *armcdn.ProfilesClientBeginDeleteOptions) (*runtime.Poller[armcdn.ProfilesClientDeleteResponse], error)
	NewListPager(options *armcdn.ProfilesClientListOptions) *runtime.Pager[armcdn.ProfilesClientListResponse]
	NewListByResourceGroupPager(resourceGroupName string, options *armcdn.ProfilesClientListByResourceGroupOptions) *runtime.Pager[armcdn.ProfilesClientListByResourceGroupResponse]
}

func init() {
	registry.Register(ResourceTypeCdnProfile, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &CdnProfile{
			api:      c.CdnProfilesClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// CdnProfile is the provisioner for an Azure Front Door Standard profile
// (Microsoft.Cdn/profiles with SKU Standard_AzureFrontDoor).
type CdnProfile struct {
	api      cdnProfilesAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

func cdnProfileIDParts(resourceID string) (rgName, profileName string, err error) {
	rgName, names, err := armIDParts(resourceID, "profiles")
	if err != nil {
		return "", "", err
	}
	return rgName, names["profiles"], nil
}

// buildCdnProfileParams converts the formae property map into an armcdn.Profile
// body suitable for BeginCreate. Shared by Create and Update.
func buildCdnProfileParams(props map[string]any, location string) armcdn.Profile {
	params := armcdn.Profile{
		Location:   stringPtr(location),
		SKU:        &armcdn.SKU{},
		Properties: &armcdn.ProfileProperties{},
	}
	skuName := armcdn.SKUNameStandardAzureFrontDoor
	if skuRaw, ok := props["sku"].(map[string]any); ok {
		if name, ok := skuRaw["name"].(string); ok && name != "" {
			skuName = armcdn.SKUName(name)
		}
	}
	params.SKU.Name = &skuName

	if v, ok := props["originResponseTimeoutSeconds"].(float64); ok {
		params.Properties.OriginResponseTimeoutSeconds = int32Ptr(int32(v))
	}
	return params
}

func serializeCdnProfileProperties(result armcdn.Profile, rgName, profileName string) (json.RawMessage, error) {
	props := make(map[string]any)
	props["resourceGroupName"] = rgName
	if result.Name != nil {
		props["name"] = *result.Name
	} else {
		props["name"] = profileName
	}
	if result.Location != nil {
		props["location"] = *result.Location
	}
	if result.ID != nil {
		props["id"] = *result.ID
	}
	if result.SKU != nil && result.SKU.Name != nil {
		props["sku"] = map[string]any{"name": string(*result.SKU.Name)}
	}
	if result.Properties != nil && result.Properties.OriginResponseTimeoutSeconds != nil {
		props["originResponseTimeoutSeconds"] = *result.Properties.OriginResponseTimeoutSeconds
	}
	if tags := azureTagsToFormaeTags(result.Tags); tags != nil {
		props["Tags"] = tags
	}
	return json.Marshal(props)
}

func (p *CdnProfile) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
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
	profileName, ok := props["name"].(string)
	if !ok || profileName == "" {
		profileName = request.Label
	}

	params := buildCdnProfileParams(props, location)
	if azureTags := formaeTagsToAzureTags(request.Properties); azureTags != nil {
		params.Tags = azureTags
	}

	poller, err := p.api.BeginCreate(ctx, rgName, profileName, params, nil)
	if err != nil {
		return &resource.CreateResult{ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationCreate,
			OperationStatus: resource.OperationStatusFailure,
			ErrorCode:       operationErrorCode(err),
		}}, nil
	}

	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Cdn/profiles/%s",
		p.config.SubscriptionId, rgName, profileName)

	if poller.Done() {
		result, err := poller.Result(ctx)
		if err != nil {
			return &resource.CreateResult{ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			}}, nil
		}
		propsJSON, err := serializeCdnProfileProperties(result.Profile, rgName, profileName)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize CdnProfile properties: %w", err)
		}
		return &resource.CreateResult{ProgressResult: &resource.ProgressResult{
			Operation:          resource.OperationCreate,
			OperationStatus:    resource.OperationStatusSuccess,
			NativeID:           *result.ID,
			ResourceProperties: propsJSON,
		}}, nil
	}

	resumeToken, err := poller.ResumeToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get resume token: %w", err)
	}
	reqIDJSON, err := encodeLROStart(lroOpCreate, resumeToken, expectedNativeID)
	if err != nil {
		return nil, err
	}
	return &resource.CreateResult{ProgressResult: &resource.ProgressResult{
		Operation:       resource.OperationCreate,
		OperationStatus: resource.OperationStatusInProgress,
		RequestID:       reqIDJSON,
		NativeID:        expectedNativeID,
	}}, nil
}

func (p *CdnProfile) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, profileName, err := cdnProfileIDParts(request.NativeID)
	if err != nil {
		return nil, fmt.Errorf("invalid NativeID %s: %w", request.NativeID, err)
	}
	result, err := p.api.Get(ctx, rgName, profileName, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}
	propsJSON, err := serializeCdnProfileProperties(result.Profile, rgName, profileName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize CdnProfile properties: %w", err)
	}
	return &resource.ReadResult{ResourceType: ResourceTypeCdnProfile, Properties: string(propsJSON)}, nil
}

func (p *CdnProfile) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, profileName, err := cdnProfileIDParts(request.NativeID)
	if err != nil {
		return nil, fmt.Errorf("invalid NativeID %s: %w", request.NativeID, err)
	}
	var props map[string]any
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	location, ok := props["location"].(string)
	if !ok || location == "" {
		return nil, fmt.Errorf("location is required")
	}

	params := buildCdnProfileParams(props, location)
	if azureTags := formaeTagsToAzureTags(request.DesiredProperties); azureTags != nil {
		params.Tags = azureTags
	}

	poller, err := p.api.BeginCreate(ctx, rgName, profileName, params, nil)
	if err != nil {
		return &resource.UpdateResult{ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationUpdate,
			OperationStatus: resource.OperationStatusFailure,
			NativeID:        request.NativeID,
			ErrorCode:       operationErrorCode(err),
		}}, nil
	}

	if poller.Done() {
		result, err := poller.Result(ctx)
		if err != nil {
			return &resource.UpdateResult{ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationUpdate,
				OperationStatus: resource.OperationStatusFailure,
				NativeID:        request.NativeID,
				ErrorCode:       operationErrorCode(err),
			}}, nil
		}
		propsJSON, err := serializeCdnProfileProperties(result.Profile, rgName, profileName)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize CdnProfile properties: %w", err)
		}
		return &resource.UpdateResult{ProgressResult: &resource.ProgressResult{
			Operation:          resource.OperationUpdate,
			OperationStatus:    resource.OperationStatusSuccess,
			NativeID:           *result.ID,
			ResourceProperties: propsJSON,
		}}, nil
	}

	resumeToken, err := poller.ResumeToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get resume token: %w", err)
	}
	reqIDJSON, err := encodeLROStart(lroOpUpdate, resumeToken, request.NativeID)
	if err != nil {
		return nil, err
	}
	return &resource.UpdateResult{ProgressResult: &resource.ProgressResult{
		Operation:       resource.OperationUpdate,
		OperationStatus: resource.OperationStatusInProgress,
		RequestID:       reqIDJSON,
		NativeID:        request.NativeID,
	}}, nil
}

func (p *CdnProfile) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, profileName, err := cdnProfileIDParts(request.NativeID)
	if err != nil {
		return nil, fmt.Errorf("invalid NativeID %s: %w", request.NativeID, err)
	}
	poller, err := p.api.BeginDelete(ctx, rgName, profileName, nil)
	if err != nil {
		if operationErrorCode(err) == resource.OperationErrorCodeNotFound {
			return &resource.DeleteResult{ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationDelete,
				OperationStatus: resource.OperationStatusSuccess,
				NativeID:        request.NativeID,
			}}, nil
		}
		return &resource.DeleteResult{ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationDelete,
			OperationStatus: resource.OperationStatusFailure,
			NativeID:        request.NativeID,
			ErrorCode:       operationErrorCode(err),
		}}, fmt.Errorf("failed to start CdnProfile deletion: %w", err)
	}
	resumeToken, err := poller.ResumeToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get resume token: %w", err)
	}
	reqIDJSON, err := encodeLROStart(lroOpDelete, resumeToken, request.NativeID)
	if err != nil {
		return nil, err
	}
	return &resource.DeleteResult{ProgressResult: &resource.ProgressResult{
		Operation:       resource.OperationDelete,
		OperationStatus: resource.OperationStatusInProgress,
		RequestID:       reqIDJSON,
		NativeID:        request.NativeID,
	}}, nil
}

func (p *CdnProfile) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	reqID, err := decodeLROStatus(request.RequestID)
	if err != nil {
		return &resource.StatusResult{ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusFailure,
			RequestID:       request.RequestID,
			ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
		}}, err
	}

	switch reqID.OperationType {
	case lroOpCreate, lroOpUpdate:
		operation := resource.OperationCreate
		if reqID.OperationType == lroOpUpdate {
			operation = resource.OperationUpdate
		}
		return statusLRO(ctx, request, &reqID, operation,
			func(token string) (*runtime.Poller[armcdn.ProfilesClientCreateResponse], error) {
				return resumePoller[armcdn.ProfilesClientCreateResponse](p.pipeline, token)
			},
			func(_ context.Context, result armcdn.ProfilesClientCreateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				rgName, profileName, err := cdnProfileIDParts(*result.ID)
				if err != nil {
					return "", nil, err
				}
				propsJSON, err := serializeCdnProfileProperties(result.Profile, rgName, profileName)
				if err != nil {
					return "", nil, fmt.Errorf("failed to serialize CdnProfile properties: %w", err)
				}
				return *result.ID, propsJSON, nil
			})
	case lroOpDelete:
		return statusDeleteLRO(ctx, request, &reqID,
			func(token string) (*runtime.Poller[armcdn.ProfilesClientDeleteResponse], error) {
				return resumePoller[armcdn.ProfilesClientDeleteResponse](p.pipeline, token)
			}, nil)
	default:
		return &resource.StatusResult{ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusFailure,
			RequestID:       request.RequestID,
			ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
		}}, fmt.Errorf("unknown operation type: %s", reqID.OperationType)
	}
}

func (p *CdnProfile) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	var nativeIDs []string
	if rgName != "" {
		pager := p.api.NewListByResourceGroupPager(rgName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list cdn profiles: %w", err)
			}
			for _, x := range page.Value {
				if x != nil && x.ID != nil {
					nativeIDs = append(nativeIDs, *x.ID)
				}
			}
		}
	} else {
		pager := p.api.NewListPager(nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list cdn profiles: %w", err)
			}
			for _, x := range page.Value {
				if x != nil && x.ID != nil {
					nativeIDs = append(nativeIDs, *x.ID)
				}
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
