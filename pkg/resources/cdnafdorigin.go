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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/cdn/armcdn/v2"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeCdnAFDOrigin = "AZURE::Cdn::AFDOrigin"

// cdnAFDOriginsAPI is the narrow slice of *armcdn.AFDOriginsClient used by the
// provisioner. Create/Delete are LRO; Get is synchronous. Update goes through
// BeginCreate (PUT create-or-update).
type cdnAFDOriginsAPI interface {
	BeginCreate(ctx context.Context, resourceGroupName string, profileName string, originGroupName string, originName string, origin armcdn.AFDOrigin, options *armcdn.AFDOriginsClientBeginCreateOptions) (*runtime.Poller[armcdn.AFDOriginsClientCreateResponse], error)
	Get(ctx context.Context, resourceGroupName string, profileName string, originGroupName string, originName string, options *armcdn.AFDOriginsClientGetOptions) (armcdn.AFDOriginsClientGetResponse, error)
	BeginDelete(ctx context.Context, resourceGroupName string, profileName string, originGroupName string, originName string, options *armcdn.AFDOriginsClientBeginDeleteOptions) (*runtime.Poller[armcdn.AFDOriginsClientDeleteResponse], error)
	NewListByOriginGroupPager(resourceGroupName string, profileName string, originGroupName string, options *armcdn.AFDOriginsClientListByOriginGroupOptions) *runtime.Pager[armcdn.AFDOriginsClientListByOriginGroupResponse]
}

func init() {
	registry.Register(ResourceTypeCdnAFDOrigin, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &CdnAFDOrigin{
			api:      c.CdnAFDOriginsClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// CdnAFDOrigin is the provisioner for a Front Door origin
// (Microsoft.Cdn/profiles/originGroups/origins).
type CdnAFDOrigin struct {
	api      cdnAFDOriginsAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

func cdnAFDOriginIDParts(resourceID string) (rgName, profileName, originGroupName, originName string, err error) {
	rgName, names, err := armIDParts(resourceID, "profiles", "originGroups", "origins")
	if err != nil {
		return "", "", "", "", err
	}
	return rgName, names["profiles"], names["originGroups"], names["origins"], nil
}

func buildCdnAFDOriginParams(props map[string]any) armcdn.AFDOrigin {
	op := &armcdn.AFDOriginProperties{}
	if v, ok := props["hostName"].(string); ok && v != "" {
		op.HostName = stringPtr(v)
	}
	if v, ok := props["httpPort"].(float64); ok {
		op.HTTPPort = int32Ptr(int32(v))
	}
	if v, ok := props["httpsPort"].(float64); ok {
		op.HTTPSPort = int32Ptr(int32(v))
	}
	if v, ok := props["originHostHeader"].(string); ok && v != "" {
		op.OriginHostHeader = stringPtr(v)
	}
	if v, ok := props["priority"].(float64); ok {
		op.Priority = int32Ptr(int32(v))
	}
	if v, ok := props["weight"].(float64); ok {
		op.Weight = int32Ptr(int32(v))
	}
	if v, ok := props["enabledState"].(string); ok && v != "" {
		op.EnabledState = to.Ptr(armcdn.EnabledState(v))
	}
	if v, ok := props["enforceCertificateNameCheck"].(bool); ok {
		op.EnforceCertificateNameCheck = to.Ptr(v)
	}
	return armcdn.AFDOrigin{Properties: op}
}

func serializeCdnAFDOriginProperties(result armcdn.AFDOrigin, rgName, profileName, originGroupName, originName string) (json.RawMessage, error) {
	props := make(map[string]any)
	props["resourceGroupName"] = rgName
	props["profileName"] = profileName
	props["originGroupName"] = originGroupName
	if result.Name != nil {
		props["name"] = *result.Name
	} else {
		props["name"] = originName
	}
	if result.ID != nil {
		props["id"] = *result.ID
	}
	if p := result.Properties; p != nil {
		if p.HostName != nil {
			props["hostName"] = *p.HostName
		}
		if p.HTTPPort != nil {
			props["httpPort"] = *p.HTTPPort
		}
		if p.HTTPSPort != nil {
			props["httpsPort"] = *p.HTTPSPort
		}
		if p.OriginHostHeader != nil {
			props["originHostHeader"] = *p.OriginHostHeader
		}
		if p.Priority != nil {
			props["priority"] = *p.Priority
		}
		if p.Weight != nil {
			props["weight"] = *p.Weight
		}
		if p.EnabledState != nil {
			props["enabledState"] = string(*p.EnabledState)
		}
		if p.EnforceCertificateNameCheck != nil {
			props["enforceCertificateNameCheck"] = *p.EnforceCertificateNameCheck
		}
	}
	return json.Marshal(props)
}

func (o *CdnAFDOrigin) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props map[string]any
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	rgName, ok := props["resourceGroupName"].(string)
	if !ok || rgName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	profileName, ok := props["profileName"].(string)
	if !ok || profileName == "" {
		return nil, fmt.Errorf("profileName is required")
	}
	originGroupName, ok := props["originGroupName"].(string)
	if !ok || originGroupName == "" {
		return nil, fmt.Errorf("originGroupName is required")
	}
	originName, ok := props["name"].(string)
	if !ok || originName == "" {
		originName = request.Label
	}

	params := buildCdnAFDOriginParams(props)

	poller, err := o.api.BeginCreate(ctx, rgName, profileName, originGroupName, originName, params, nil)
	if err != nil {
		return &resource.CreateResult{ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationCreate,
			OperationStatus: resource.OperationStatusFailure,
			ErrorCode:       operationErrorCode(err),
		}}, nil
	}

	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Cdn/profiles/%s/originGroups/%s/origins/%s",
		o.config.SubscriptionId, rgName, profileName, originGroupName, originName)

	if poller.Done() {
		result, err := poller.Result(ctx)
		if err != nil {
			return &resource.CreateResult{ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			}}, nil
		}
		propsJSON, err := serializeCdnAFDOriginProperties(result.AFDOrigin, rgName, profileName, originGroupName, originName)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize AFDOrigin properties: %w", err)
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

func (o *CdnAFDOrigin) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, profileName, originGroupName, originName, err := cdnAFDOriginIDParts(request.NativeID)
	if err != nil {
		return nil, fmt.Errorf("invalid NativeID %s: %w", request.NativeID, err)
	}
	result, err := o.api.Get(ctx, rgName, profileName, originGroupName, originName, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}
	propsJSON, err := serializeCdnAFDOriginProperties(result.AFDOrigin, rgName, profileName, originGroupName, originName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize AFDOrigin properties: %w", err)
	}
	return &resource.ReadResult{ResourceType: ResourceTypeCdnAFDOrigin, Properties: string(propsJSON)}, nil
}

func (o *CdnAFDOrigin) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, profileName, originGroupName, originName, err := cdnAFDOriginIDParts(request.NativeID)
	if err != nil {
		return nil, fmt.Errorf("invalid NativeID %s: %w", request.NativeID, err)
	}
	var props map[string]any
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	params := buildCdnAFDOriginParams(props)

	poller, err := o.api.BeginCreate(ctx, rgName, profileName, originGroupName, originName, params, nil)
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
		propsJSON, err := serializeCdnAFDOriginProperties(result.AFDOrigin, rgName, profileName, originGroupName, originName)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize AFDOrigin properties: %w", err)
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

func (o *CdnAFDOrigin) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, profileName, originGroupName, originName, err := cdnAFDOriginIDParts(request.NativeID)
	if err != nil {
		return nil, fmt.Errorf("invalid NativeID %s: %w", request.NativeID, err)
	}
	poller, err := o.api.BeginDelete(ctx, rgName, profileName, originGroupName, originName, nil)
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
		}}, fmt.Errorf("failed to start AFDOrigin deletion: %w", err)
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

func (o *CdnAFDOrigin) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
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
			func(token string) (*runtime.Poller[armcdn.AFDOriginsClientCreateResponse], error) {
				return resumePoller[armcdn.AFDOriginsClientCreateResponse](o.pipeline, token)
			},
			func(_ context.Context, result armcdn.AFDOriginsClientCreateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				rgName, profileName, originGroupName, originName, err := cdnAFDOriginIDParts(*result.ID)
				if err != nil {
					return "", nil, err
				}
				propsJSON, err := serializeCdnAFDOriginProperties(result.AFDOrigin, rgName, profileName, originGroupName, originName)
				if err != nil {
					return "", nil, fmt.Errorf("failed to serialize AFDOrigin properties: %w", err)
				}
				return *result.ID, propsJSON, nil
			})
	case lroOpDelete:
		return statusDeleteLRO(ctx, request, &reqID,
			func(token string) (*runtime.Poller[armcdn.AFDOriginsClientDeleteResponse], error) {
				return resumePoller[armcdn.AFDOriginsClientDeleteResponse](o.pipeline, token)
			}, nil)
	default:
		return &resource.StatusResult{ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusFailure,
			RequestID:       request.RequestID,
			ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
		}}, fmt.Errorf("unknown operation type: %s", reqID.OperationType)
	}
}

func (o *CdnAFDOrigin) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	profileName := request.AdditionalProperties["profileName"]
	originGroupName := request.AdditionalProperties["originGroupName"]
	if rgName == "" || profileName == "" || originGroupName == "" {
		return &resource.ListResult{}, nil
	}
	var nativeIDs []string
	pager := o.api.NewListByOriginGroupPager(rgName, profileName, originGroupName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list afd origins: %w", err)
		}
		for _, x := range page.Value {
			if x != nil && x.ID != nil {
				nativeIDs = append(nativeIDs, *x.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
