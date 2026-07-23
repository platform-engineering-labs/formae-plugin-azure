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

const ResourceTypeCdnAFDOriginGroup = "AZURE::Cdn::AFDOriginGroup"

// cdnAFDOriginGroupsAPI is the narrow slice of *armcdn.AFDOriginGroupsClient
// used by the provisioner. Create/Delete are LRO; Get is synchronous. Update
// goes through BeginCreate (PUT create-or-update) so the body stays a full
// armcdn.AFDOriginGroup for both operations.
type cdnAFDOriginGroupsAPI interface {
	BeginCreate(ctx context.Context, resourceGroupName string, profileName string, originGroupName string, originGroup armcdn.AFDOriginGroup, options *armcdn.AFDOriginGroupsClientBeginCreateOptions) (*runtime.Poller[armcdn.AFDOriginGroupsClientCreateResponse], error)
	Get(ctx context.Context, resourceGroupName string, profileName string, originGroupName string, options *armcdn.AFDOriginGroupsClientGetOptions) (armcdn.AFDOriginGroupsClientGetResponse, error)
	BeginDelete(ctx context.Context, resourceGroupName string, profileName string, originGroupName string, options *armcdn.AFDOriginGroupsClientBeginDeleteOptions) (*runtime.Poller[armcdn.AFDOriginGroupsClientDeleteResponse], error)
	NewListByProfilePager(resourceGroupName string, profileName string, options *armcdn.AFDOriginGroupsClientListByProfileOptions) *runtime.Pager[armcdn.AFDOriginGroupsClientListByProfileResponse]
}

func init() {
	registry.Register(ResourceTypeCdnAFDOriginGroup, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &CdnAFDOriginGroup{
			api:      c.CdnAFDOriginGroupsClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// CdnAFDOriginGroup is the provisioner for a Front Door origin group
// (Microsoft.Cdn/profiles/originGroups).
type CdnAFDOriginGroup struct {
	api      cdnAFDOriginGroupsAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

func cdnAFDOriginGroupIDParts(resourceID string) (rgName, profileName, originGroupName string, err error) {
	rgName, names, err := armIDParts(resourceID, "profiles", "originGroups")
	if err != nil {
		return "", "", "", err
	}
	return rgName, names["profiles"], names["originGroups"], nil
}

func buildCdnAFDOriginGroupParams(props map[string]any) armcdn.AFDOriginGroup {
	gp := &armcdn.AFDOriginGroupProperties{}
	if lbRaw, ok := props["loadBalancingSettings"].(map[string]any); ok {
		lb := &armcdn.LoadBalancingSettingsParameters{}
		if v, ok := lbRaw["sampleSize"].(float64); ok {
			lb.SampleSize = int32Ptr(int32(v))
		}
		if v, ok := lbRaw["successfulSamplesRequired"].(float64); ok {
			lb.SuccessfulSamplesRequired = int32Ptr(int32(v))
		}
		if v, ok := lbRaw["additionalLatencyInMilliseconds"].(float64); ok {
			lb.AdditionalLatencyInMilliseconds = int32Ptr(int32(v))
		}
		gp.LoadBalancingSettings = lb
	}
	if hpRaw, ok := props["healthProbeSettings"].(map[string]any); ok {
		hp := &armcdn.HealthProbeParameters{}
		if v, ok := hpRaw["probePath"].(string); ok && v != "" {
			hp.ProbePath = stringPtr(v)
		}
		if v, ok := hpRaw["probeRequestType"].(string); ok && v != "" {
			hp.ProbeRequestType = to.Ptr(armcdn.HealthProbeRequestType(v))
		}
		if v, ok := hpRaw["probeProtocol"].(string); ok && v != "" {
			hp.ProbeProtocol = to.Ptr(armcdn.ProbeProtocol(v))
		}
		if v, ok := hpRaw["probeIntervalInSeconds"].(float64); ok {
			hp.ProbeIntervalInSeconds = int32Ptr(int32(v))
		}
		gp.HealthProbeSettings = hp
	}
	if v, ok := props["sessionAffinityState"].(string); ok && v != "" {
		gp.SessionAffinityState = to.Ptr(armcdn.EnabledState(v))
	}
	return armcdn.AFDOriginGroup{Properties: gp}
}

func serializeCdnAFDOriginGroupProperties(result armcdn.AFDOriginGroup, rgName, profileName, originGroupName string) (json.RawMessage, error) {
	props := make(map[string]any)
	props["resourceGroupName"] = rgName
	props["profileName"] = profileName
	if result.Name != nil {
		props["name"] = *result.Name
	} else {
		props["name"] = originGroupName
	}
	if result.ID != nil {
		props["id"] = *result.ID
	}
	if p := result.Properties; p != nil {
		if lb := p.LoadBalancingSettings; lb != nil {
			m := make(map[string]any)
			if lb.SampleSize != nil {
				m["sampleSize"] = *lb.SampleSize
			}
			if lb.SuccessfulSamplesRequired != nil {
				m["successfulSamplesRequired"] = *lb.SuccessfulSamplesRequired
			}
			if lb.AdditionalLatencyInMilliseconds != nil {
				m["additionalLatencyInMilliseconds"] = *lb.AdditionalLatencyInMilliseconds
			}
			props["loadBalancingSettings"] = m
		}
		if hp := p.HealthProbeSettings; hp != nil {
			m := make(map[string]any)
			if hp.ProbePath != nil {
				m["probePath"] = *hp.ProbePath
			}
			if hp.ProbeRequestType != nil {
				m["probeRequestType"] = string(*hp.ProbeRequestType)
			}
			if hp.ProbeProtocol != nil {
				m["probeProtocol"] = string(*hp.ProbeProtocol)
			}
			if hp.ProbeIntervalInSeconds != nil {
				m["probeIntervalInSeconds"] = *hp.ProbeIntervalInSeconds
			}
			props["healthProbeSettings"] = m
		}
		if p.SessionAffinityState != nil {
			props["sessionAffinityState"] = string(*p.SessionAffinityState)
		}
	}
	return json.Marshal(props)
}

func (g *CdnAFDOriginGroup) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
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
	originGroupName, ok := props["name"].(string)
	if !ok || originGroupName == "" {
		originGroupName = request.Label
	}

	params := buildCdnAFDOriginGroupParams(props)

	poller, err := g.api.BeginCreate(ctx, rgName, profileName, originGroupName, params, nil)
	if err != nil {
		return &resource.CreateResult{ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationCreate,
			OperationStatus: resource.OperationStatusFailure,
			ErrorCode:       operationErrorCode(err),
		}}, nil
	}

	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Cdn/profiles/%s/originGroups/%s",
		g.config.SubscriptionId, rgName, profileName, originGroupName)

	if poller.Done() {
		result, err := poller.Result(ctx)
		if err != nil {
			return &resource.CreateResult{ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			}}, nil
		}
		propsJSON, err := serializeCdnAFDOriginGroupProperties(result.AFDOriginGroup, rgName, profileName, originGroupName)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize AFDOriginGroup properties: %w", err)
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

func (g *CdnAFDOriginGroup) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, profileName, originGroupName, err := cdnAFDOriginGroupIDParts(request.NativeID)
	if err != nil {
		return nil, fmt.Errorf("invalid NativeID %s: %w", request.NativeID, err)
	}
	result, err := g.api.Get(ctx, rgName, profileName, originGroupName, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}
	propsJSON, err := serializeCdnAFDOriginGroupProperties(result.AFDOriginGroup, rgName, profileName, originGroupName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize AFDOriginGroup properties: %w", err)
	}
	return &resource.ReadResult{ResourceType: ResourceTypeCdnAFDOriginGroup, Properties: string(propsJSON)}, nil
}

func (g *CdnAFDOriginGroup) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, profileName, originGroupName, err := cdnAFDOriginGroupIDParts(request.NativeID)
	if err != nil {
		return nil, fmt.Errorf("invalid NativeID %s: %w", request.NativeID, err)
	}
	var props map[string]any
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	params := buildCdnAFDOriginGroupParams(props)

	poller, err := g.api.BeginCreate(ctx, rgName, profileName, originGroupName, params, nil)
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
		propsJSON, err := serializeCdnAFDOriginGroupProperties(result.AFDOriginGroup, rgName, profileName, originGroupName)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize AFDOriginGroup properties: %w", err)
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

func (g *CdnAFDOriginGroup) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, profileName, originGroupName, err := cdnAFDOriginGroupIDParts(request.NativeID)
	if err != nil {
		return nil, fmt.Errorf("invalid NativeID %s: %w", request.NativeID, err)
	}
	poller, err := g.api.BeginDelete(ctx, rgName, profileName, originGroupName, nil)
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
		}}, fmt.Errorf("failed to start AFDOriginGroup deletion: %w", err)
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

func (g *CdnAFDOriginGroup) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
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
			func(token string) (*runtime.Poller[armcdn.AFDOriginGroupsClientCreateResponse], error) {
				return resumePoller[armcdn.AFDOriginGroupsClientCreateResponse](g.pipeline, token)
			},
			func(_ context.Context, result armcdn.AFDOriginGroupsClientCreateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				rgName, profileName, originGroupName, err := cdnAFDOriginGroupIDParts(*result.ID)
				if err != nil {
					return "", nil, err
				}
				propsJSON, err := serializeCdnAFDOriginGroupProperties(result.AFDOriginGroup, rgName, profileName, originGroupName)
				if err != nil {
					return "", nil, fmt.Errorf("failed to serialize AFDOriginGroup properties: %w", err)
				}
				return *result.ID, propsJSON, nil
			})
	case lroOpDelete:
		return statusDeleteLRO(ctx, request, &reqID,
			func(token string) (*runtime.Poller[armcdn.AFDOriginGroupsClientDeleteResponse], error) {
				return resumePoller[armcdn.AFDOriginGroupsClientDeleteResponse](g.pipeline, token)
			}, nil)
	default:
		return &resource.StatusResult{ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusFailure,
			RequestID:       request.RequestID,
			ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
		}}, fmt.Errorf("unknown operation type: %s", reqID.OperationType)
	}
}

func (g *CdnAFDOriginGroup) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	profileName := request.AdditionalProperties["profileName"]
	if rgName == "" || profileName == "" {
		return &resource.ListResult{}, nil
	}
	var nativeIDs []string
	pager := g.api.NewListByProfilePager(rgName, profileName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list afd origin groups: %w", err)
		}
		for _, x := range page.Value {
			if x != nil && x.ID != nil {
				nativeIDs = append(nativeIDs, *x.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
