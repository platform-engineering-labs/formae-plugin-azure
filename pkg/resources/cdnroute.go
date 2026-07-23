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

const ResourceTypeCdnRoute = "AZURE::Cdn::Route"

// cdnRoutesAPI is the narrow slice of *armcdn.RoutesClient used by the
// provisioner. Create/Delete are LRO; Get is synchronous. Update goes through
// BeginCreate (PUT create-or-update).
type cdnRoutesAPI interface {
	BeginCreate(ctx context.Context, resourceGroupName string, profileName string, endpointName string, routeName string, route armcdn.Route, options *armcdn.RoutesClientBeginCreateOptions) (*runtime.Poller[armcdn.RoutesClientCreateResponse], error)
	Get(ctx context.Context, resourceGroupName string, profileName string, endpointName string, routeName string, options *armcdn.RoutesClientGetOptions) (armcdn.RoutesClientGetResponse, error)
	BeginDelete(ctx context.Context, resourceGroupName string, profileName string, endpointName string, routeName string, options *armcdn.RoutesClientBeginDeleteOptions) (*runtime.Poller[armcdn.RoutesClientDeleteResponse], error)
	NewListByEndpointPager(resourceGroupName string, profileName string, endpointName string, options *armcdn.RoutesClientListByEndpointOptions) *runtime.Pager[armcdn.RoutesClientListByEndpointResponse]
}

func init() {
	registry.Register(ResourceTypeCdnRoute, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &CdnRoute{
			api:      c.CdnRoutesClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// CdnRoute is the provisioner for a Front Door route
// (Microsoft.Cdn/profiles/afdEndpoints/routes).
type CdnRoute struct {
	api      cdnRoutesAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

func cdnRouteIDParts(resourceID string) (rgName, profileName, endpointName, routeName string, err error) {
	rgName, names, err := armIDParts(resourceID, "profiles", "afdEndpoints", "routes")
	if err != nil {
		return "", "", "", "", err
	}
	return rgName, names["profiles"], names["afdEndpoints"], names["routes"], nil
}

func stringListFromProperties(raw any) []*string {
	list, ok := raw.([]any)
	if !ok {
		return nil
	}
	out := make([]*string, 0, len(list))
	for _, v := range list {
		if s, ok := v.(string); ok && s != "" {
			out = append(out, stringPtr(s))
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func buildCdnRouteParams(props map[string]any) armcdn.Route {
	rp := &armcdn.RouteProperties{}

	// Route links to an OriginGroup by full ARM id (SubResource reference). The
	// forma supplies originGroup.res.id, so it round-trips as a full ARM id.
	if id, ok := resolvableString(props["originGroupId"]); ok {
		rp.OriginGroup = &armcdn.ResourceReference{ID: stringPtr(id)}
	}
	rp.PatternsToMatch = stringListFromProperties(props["patternsToMatch"])
	if protos := stringListFromProperties(props["supportedProtocols"]); protos != nil {
		sp := make([]*armcdn.AFDEndpointProtocols, 0, len(protos))
		for _, p := range protos {
			sp = append(sp, to.Ptr(armcdn.AFDEndpointProtocols(*p)))
		}
		rp.SupportedProtocols = sp
	}
	if v, ok := props["forwardingProtocol"].(string); ok && v != "" {
		rp.ForwardingProtocol = to.Ptr(armcdn.ForwardingProtocol(v))
	}
	if v, ok := props["linkToDefaultDomain"].(string); ok && v != "" {
		rp.LinkToDefaultDomain = to.Ptr(armcdn.LinkToDefaultDomain(v))
	}
	if v, ok := props["httpsRedirect"].(string); ok && v != "" {
		rp.HTTPSRedirect = to.Ptr(armcdn.HTTPSRedirect(v))
	}
	if v, ok := props["enabledState"].(string); ok && v != "" {
		rp.EnabledState = to.Ptr(armcdn.EnabledState(v))
	}
	if v, ok := props["originPath"].(string); ok && v != "" {
		rp.OriginPath = stringPtr(v)
	}
	return armcdn.Route{Properties: rp}
}

func serializeCdnRouteProperties(result armcdn.Route, rgName, profileName, endpointName, routeName string) (json.RawMessage, error) {
	props := make(map[string]any)
	props["resourceGroupName"] = rgName
	props["profileName"] = profileName
	props["endpointName"] = endpointName
	if result.Name != nil {
		props["name"] = *result.Name
	} else {
		props["name"] = routeName
	}
	if result.ID != nil {
		props["id"] = *result.ID
	}
	if p := result.Properties; p != nil {
		if p.OriginGroup != nil && p.OriginGroup.ID != nil {
			props["originGroupId"] = *p.OriginGroup.ID
		}
		if len(p.PatternsToMatch) > 0 {
			patterns := make([]string, 0, len(p.PatternsToMatch))
			for _, s := range p.PatternsToMatch {
				if s != nil {
					patterns = append(patterns, *s)
				}
			}
			props["patternsToMatch"] = patterns
		}
		if len(p.SupportedProtocols) > 0 {
			protos := make([]string, 0, len(p.SupportedProtocols))
			for _, s := range p.SupportedProtocols {
				if s != nil {
					protos = append(protos, string(*s))
				}
			}
			props["supportedProtocols"] = protos
		}
		if p.ForwardingProtocol != nil {
			props["forwardingProtocol"] = string(*p.ForwardingProtocol)
		}
		if p.LinkToDefaultDomain != nil {
			props["linkToDefaultDomain"] = string(*p.LinkToDefaultDomain)
		}
		if p.HTTPSRedirect != nil {
			props["httpsRedirect"] = string(*p.HTTPSRedirect)
		}
		if p.EnabledState != nil {
			props["enabledState"] = string(*p.EnabledState)
		}
		if p.OriginPath != nil {
			props["originPath"] = *p.OriginPath
		}
	}
	return json.Marshal(props)
}

func (r *CdnRoute) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
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
	endpointName, ok := props["endpointName"].(string)
	if !ok || endpointName == "" {
		return nil, fmt.Errorf("endpointName is required")
	}
	routeName, ok := props["name"].(string)
	if !ok || routeName == "" {
		routeName = request.Label
	}

	params := buildCdnRouteParams(props)

	poller, err := r.api.BeginCreate(ctx, rgName, profileName, endpointName, routeName, params, nil)
	if err != nil {
		return &resource.CreateResult{ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationCreate,
			OperationStatus: resource.OperationStatusFailure,
			ErrorCode:       operationErrorCode(err),
		}}, nil
	}

	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Cdn/profiles/%s/afdEndpoints/%s/routes/%s",
		r.config.SubscriptionId, rgName, profileName, endpointName, routeName)

	if poller.Done() {
		result, err := poller.Result(ctx)
		if err != nil {
			return &resource.CreateResult{ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			}}, nil
		}
		propsJSON, err := serializeCdnRouteProperties(result.Route, rgName, profileName, endpointName, routeName)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize Route properties: %w", err)
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

func (r *CdnRoute) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, profileName, endpointName, routeName, err := cdnRouteIDParts(request.NativeID)
	if err != nil {
		return nil, fmt.Errorf("invalid NativeID %s: %w", request.NativeID, err)
	}
	result, err := r.api.Get(ctx, rgName, profileName, endpointName, routeName, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}
	propsJSON, err := serializeCdnRouteProperties(result.Route, rgName, profileName, endpointName, routeName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize Route properties: %w", err)
	}
	return &resource.ReadResult{ResourceType: ResourceTypeCdnRoute, Properties: string(propsJSON)}, nil
}

func (r *CdnRoute) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, profileName, endpointName, routeName, err := cdnRouteIDParts(request.NativeID)
	if err != nil {
		return nil, fmt.Errorf("invalid NativeID %s: %w", request.NativeID, err)
	}
	var props map[string]any
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	params := buildCdnRouteParams(props)

	poller, err := r.api.BeginCreate(ctx, rgName, profileName, endpointName, routeName, params, nil)
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
		propsJSON, err := serializeCdnRouteProperties(result.Route, rgName, profileName, endpointName, routeName)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize Route properties: %w", err)
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

func (r *CdnRoute) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, profileName, endpointName, routeName, err := cdnRouteIDParts(request.NativeID)
	if err != nil {
		return nil, fmt.Errorf("invalid NativeID %s: %w", request.NativeID, err)
	}
	poller, err := r.api.BeginDelete(ctx, rgName, profileName, endpointName, routeName, nil)
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
		}}, fmt.Errorf("failed to start Route deletion: %w", err)
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

func (r *CdnRoute) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
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
			func(token string) (*runtime.Poller[armcdn.RoutesClientCreateResponse], error) {
				return resumePoller[armcdn.RoutesClientCreateResponse](r.pipeline, token)
			},
			func(_ context.Context, result armcdn.RoutesClientCreateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				rgName, profileName, endpointName, routeName, err := cdnRouteIDParts(*result.ID)
				if err != nil {
					return "", nil, err
				}
				propsJSON, err := serializeCdnRouteProperties(result.Route, rgName, profileName, endpointName, routeName)
				if err != nil {
					return "", nil, fmt.Errorf("failed to serialize Route properties: %w", err)
				}
				return *result.ID, propsJSON, nil
			})
	case lroOpDelete:
		return statusDeleteLRO(ctx, request, &reqID,
			func(token string) (*runtime.Poller[armcdn.RoutesClientDeleteResponse], error) {
				return resumePoller[armcdn.RoutesClientDeleteResponse](r.pipeline, token)
			}, nil)
	default:
		return &resource.StatusResult{ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusFailure,
			RequestID:       request.RequestID,
			ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
		}}, fmt.Errorf("unknown operation type: %s", reqID.OperationType)
	}
}

func (r *CdnRoute) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	profileName := request.AdditionalProperties["profileName"]
	endpointName := request.AdditionalProperties["endpointName"]
	if rgName == "" || profileName == "" || endpointName == "" {
		return &resource.ListResult{}, nil
	}
	var nativeIDs []string
	pager := r.api.NewListByEndpointPager(rgName, profileName, endpointName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list afd routes: %w", err)
		}
		for _, x := range page.Value {
			if x != nil && x.ID != nil {
				nativeIDs = append(nativeIDs, *x.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
