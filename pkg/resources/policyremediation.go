// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/policyinsights/armpolicyinsights"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypePolicyRemediation = "AZURE::PolicyInsights::PolicyRemediation"

// policyRemediationsAPI is the subset of *armpolicyinsights.RemediationsClient used
// here. Everything is synchronous and CreateOrUpdate is also the update verb.
//
// The `AtResource` family is used for every scope, not only for resource scopes:
// its URL template is `/{resourceId}/providers/Microsoft.PolicyInsights/...` with
// the scope interpolated raw, so passing a subscription, a resource group or a
// management group scope produces exactly the URL the AtSubscription /
// AtResourceGroup / AtManagementGroup variants would have built. One triple
// therefore covers every scope, the same way policy assignments use their
// scope-taking verbs.
type policyRemediationsAPI interface {
	CreateOrUpdateAtResource(ctx context.Context, resourceID, remediationName string, parameters armpolicyinsights.Remediation, options *armpolicyinsights.RemediationsClientCreateOrUpdateAtResourceOptions) (armpolicyinsights.RemediationsClientCreateOrUpdateAtResourceResponse, error)
	GetAtResource(ctx context.Context, resourceID, remediationName string, options *armpolicyinsights.RemediationsClientGetAtResourceOptions) (armpolicyinsights.RemediationsClientGetAtResourceResponse, error)
	DeleteAtResource(ctx context.Context, resourceID, remediationName string, options *armpolicyinsights.RemediationsClientDeleteAtResourceOptions) (armpolicyinsights.RemediationsClientDeleteAtResourceResponse, error)
	CancelAtResource(ctx context.Context, resourceID, remediationName string, options *armpolicyinsights.RemediationsClientCancelAtResourceOptions) (armpolicyinsights.RemediationsClientCancelAtResourceResponse, error)
	NewListForResourcePager(resourceID string, options *armpolicyinsights.RemediationsClientListForResourceOptions) *runtime.Pager[armpolicyinsights.RemediationsClientListForResourceResponse]
	NewListForSubscriptionPager(options *armpolicyinsights.RemediationsClientListForSubscriptionOptions) *runtime.Pager[armpolicyinsights.RemediationsClientListForSubscriptionResponse]
}

func init() {
	registry.Register(ResourceTypePolicyRemediation, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &PolicyRemediation{api: c.PolicyRemediationsClient, config: cfg}
	})
}

// PolicyRemediation is the provisioner for policy remediation tasks
// (Microsoft.PolicyInsights/remediations).
type PolicyRemediation struct {
	api    policyRemediationsAPI
	config *config.Config
}

// policyRemediationProps mirrors
// schema/pkl/policyinsights/policyremediation.pkl.
//
// ARM's `filters` and `failureThreshold` objects are flattened: a nested PKL class
// silently ignores hasProviderDefault, and both objects carry a single field.
type policyRemediationProps struct {
	Name                        string   `json:"name"`
	Scope                       string   `json:"scope"`
	PolicyAssignmentID          string   `json:"policyAssignmentId"`
	PolicyDefinitionReferenceID *string  `json:"policyDefinitionReferenceId"`
	ResourceDiscoveryMode       *string  `json:"resourceDiscoveryMode"`
	ParallelDeployments         *int32   `json:"parallelDeployments"`
	ResourceCount               *int32   `json:"resourceCount"`
	FailureThresholdPercentage  *float32 `json:"failureThresholdPercentage"`
	FilterLocations             []string `json:"filterLocations"`
	FilterResourceIDs           []string `json:"filterResourceIds"`
}

const policyRemediationSegment = "/providers/microsoft.policyinsights/remediations/"

// policyRemediationIDParts splits a remediation ID into the scope it runs over and
// its name. The scope may be a subscription, a resource group, a single resource or
// a management group, so armIDParts does not apply.
func policyRemediationIDParts(resourceID string) (scope, name string, err error) {
	idx := strings.Index(strings.ToLower(resourceID), policyRemediationSegment)
	if idx < 0 {
		return "", "", fmt.Errorf("not a policy remediation resource ID: %s", resourceID)
	}
	scope = resourceID[:idx]
	name = resourceID[idx+len(policyRemediationSegment):]
	if scope == "" || name == "" {
		return "", "", fmt.Errorf("not a policy remediation resource ID: %s", resourceID)
	}
	return scope, name, nil
}

func (p *PolicyRemediation) buildPropertiesFromResult(remediation *armpolicyinsights.Remediation, scope string) map[string]any {
	props := make(map[string]any)

	props["scope"] = scope

	if remediation.ID != nil {
		props["id"] = *remediation.ID
	}
	if remediation.Name != nil {
		props["name"] = *remediation.Name
	}

	r := remediation.Properties
	if r == nil {
		return props
	}

	if r.PolicyAssignmentID != nil {
		props["policyAssignmentId"] = *r.PolicyAssignmentID
	}
	if r.PolicyDefinitionReferenceID != nil && *r.PolicyDefinitionReferenceID != "" {
		props["policyDefinitionReferenceId"] = *r.PolicyDefinitionReferenceID
	}
	if r.ResourceDiscoveryMode != nil {
		props["resourceDiscoveryMode"] = canonicalizeEnum(string(*r.ResourceDiscoveryMode), "ExistingNonCompliant", "ReEvaluateCompliance")
	}
	if r.ParallelDeployments != nil {
		props["parallelDeployments"] = *r.ParallelDeployments
	}
	if r.ResourceCount != nil {
		props["resourceCount"] = *r.ResourceCount
	}
	if r.FailureThreshold != nil && r.FailureThreshold.Percentage != nil {
		props["failureThresholdPercentage"] = *r.FailureThreshold.Percentage
	}
	if r.Filters != nil {
		if locations := stringsFromPointers(r.Filters.Locations); locations != nil {
			props["filterLocations"] = locations
		}
		if resourceIDs := stringsFromPointers(r.Filters.ResourceIDs); resourceIDs != nil {
			props["filterResourceIds"] = resourceIDs
		}
	}

	// correlationId, createdOn, lastUpdatedOn, deploymentStatus, provisioningState
	// and statusMessage are the running task's own state, not configuration, and
	// change under the resource without anyone asking. None is read back.
	return props
}

// policyRemediationParams builds the request body shared by create and update.
func policyRemediationParams(props policyRemediationProps) armpolicyinsights.Remediation {
	remediation := armpolicyinsights.Remediation{
		Properties: &armpolicyinsights.RemediationProperties{
			PolicyAssignmentID:          to.Ptr(props.PolicyAssignmentID),
			PolicyDefinitionReferenceID: props.PolicyDefinitionReferenceID,
			ParallelDeployments:         props.ParallelDeployments,
			ResourceCount:               props.ResourceCount,
		},
	}

	if props.ResourceDiscoveryMode != nil && *props.ResourceDiscoveryMode != "" {
		remediation.Properties.ResourceDiscoveryMode = to.Ptr(armpolicyinsights.ResourceDiscoveryMode(*props.ResourceDiscoveryMode))
	}
	if props.FailureThresholdPercentage != nil {
		remediation.Properties.FailureThreshold = &armpolicyinsights.RemediationPropertiesFailureThreshold{
			Percentage: props.FailureThresholdPercentage,
		}
	}
	if len(props.FilterLocations) > 0 || len(props.FilterResourceIDs) > 0 {
		remediation.Properties.Filters = &armpolicyinsights.RemediationFilters{
			Locations:   stringPointers(props.FilterLocations),
			ResourceIDs: stringPointers(props.FilterResourceIDs),
		}
	}

	return remediation
}

func (p *PolicyRemediation) parseProps(payload json.RawMessage, label string) (policyRemediationProps, string, error) {
	var props policyRemediationProps
	if err := json.Unmarshal(payload, &props); err != nil {
		return props, "", fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.Scope == "" {
		return props, "", fmt.Errorf("scope is required")
	}
	if props.PolicyAssignmentID == "" {
		return props, "", fmt.Errorf("policyAssignmentId is required")
	}
	// ARM rejects the combination at PUT time with a message that does not name the
	// discovery mode, so it is caught here where the reason is obvious.
	if props.ResourceDiscoveryMode != nil &&
		*props.ResourceDiscoveryMode == string(armpolicyinsights.ResourceDiscoveryModeReEvaluateCompliance) &&
		len(props.FilterResourceIDs) > 0 {
		return props, "", fmt.Errorf("filterResourceIds cannot be used with resourceDiscoveryMode ReEvaluateCompliance")
	}

	name := props.Name
	if name == "" {
		name = label
	}
	if name == "" {
		return props, "", fmt.Errorf("name is required")
	}
	return props, name, nil
}

func (p *PolicyRemediation) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	props, name, err := p.parseProps(request.Properties, request.Label)
	if err != nil {
		return nil, err
	}

	result, err := p.api.CreateOrUpdateAtResource(ctx, props.Scope, name, policyRemediationParams(props), nil)
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
	propsJSON, err := json.Marshal(p.buildPropertiesFromResult(&result.Remediation, props.Scope))
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

func (p *PolicyRemediation) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	scope, name, err := policyRemediationIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := p.api.GetAtResource(ctx, scope, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(p.buildPropertiesFromResult(&result.Remediation, scope))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypePolicyRemediation,
		Properties:   string(propsJSON),
	}, nil
}

// Update reissues CreateOrUpdate, which RE-RUNS the task over whatever is
// non-compliant at that moment. That is what the API offers — a remediation has no
// PATCH — and it is the documented way to re-trigger one.
func (p *PolicyRemediation) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	scope, name, err := policyRemediationIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	props, _, err := p.parseProps(request.DesiredProperties, name)
	if err != nil {
		return nil, err
	}

	result, err := p.api.CreateOrUpdateAtResource(ctx, scope, name, policyRemediationParams(props), nil)
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

	propsJSON, err := json.Marshal(p.buildPropertiesFromResult(&result.Remediation, scope))
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

// policyRemediationActiveStates are the provisioning states in which ARM refuses to
// delete a remediation. Everything else — Canceled, Failed, Complete, Succeeded —
// is terminal.
var policyRemediationActiveStates = map[string]struct{}{
	"accepted":   {},
	"evaluating": {},
}

const (
	policyRemediationDeleteAttempts = 6
	policyRemediationDeleteDelay    = 5 * time.Second
)

// Delete cancels a still-running task before removing it.
//
// ARM refuses to delete a remediation that is still evaluating, which a task in
// `ReEvaluateCompliance` mode can be for minutes. Cancelling first is what makes the
// delete land; a task that is already terminal is deleted straight away.
func (p *PolicyRemediation) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	scope, name, err := policyRemediationIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	failure := func(err error) *resource.DeleteResult {
		return &resource.DeleteResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationDelete,
				OperationStatus: resource.OperationStatusFailure,
				NativeID:        request.NativeID,
				ErrorCode:       operationErrorCode(err),
				StatusMessage:   err.Error(),
			},
		}
	}
	success := &resource.DeleteResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationDelete,
			OperationStatus: resource.OperationStatusSuccess,
			NativeID:        request.NativeID,
		},
	}

	current, err := p.api.GetAtResource(ctx, scope, name, nil)
	if err != nil {
		if isDeleteSuccessError(err) {
			return success, nil
		}
		return failure(err), nil
	}

	if policyRemediationIsActive(&current.Remediation) {
		// Best effort: a cancel that races the task reaching a terminal state is not
		// fatal, because the delete below still has to succeed for this to report
		// success.
		_, _ = p.api.CancelAtResource(ctx, scope, name, nil)
	}

	var lastErr error
	for attempt := 0; attempt < policyRemediationDeleteAttempts; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return failure(ctx.Err()), nil
			case <-time.After(policyRemediationDeleteDelay):
			}
		}
		_, err := p.api.DeleteAtResource(ctx, scope, name, nil)
		if err == nil || isDeleteSuccessError(err) {
			return success, nil
		}
		lastErr = err
		if operationErrorCode(err) != resource.OperationErrorCodeResourceConflict &&
			operationErrorCode(err) != resource.OperationErrorCodeInvalidRequest {
			break
		}
	}

	return failure(lastErr), nil
}

func policyRemediationIsActive(remediation *armpolicyinsights.Remediation) bool {
	if remediation == nil || remediation.Properties == nil || remediation.Properties.ProvisioningState == nil {
		return false
	}
	_, active := policyRemediationActiveStates[strings.ToLower(*remediation.Properties.ProvisioningState)]
	return active
}

// Status can only ever be asked about an operation that already finished: every
// write here is synchronous. The remediation task itself runs on after the write
// returns, but its progress is compliance state rather than resource state.
func (p *PolicyRemediation) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

// List enumerates remediations at the scope it is given, and across the
// subscription when it is given none.
func (p *PolicyRemediation) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	scope := request.AdditionalProperties["scope"]

	var nativeIDs []string
	if scope != "" {
		pager := p.api.NewListForResourcePager(scope, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list policy remediations: %w", err)
			}
			for _, remediation := range page.Value {
				if remediation != nil && remediation.ID != nil {
					nativeIDs = append(nativeIDs, *remediation.ID)
				}
			}
		}
		return &resource.ListResult{NativeIDs: nativeIDs}, nil
	}

	pager := p.api.NewListForSubscriptionPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list policy remediations: %w", err)
		}
		for _, remediation := range page.Value {
			if remediation != nil && remediation.ID != nil {
				nativeIDs = append(nativeIDs, *remediation.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
