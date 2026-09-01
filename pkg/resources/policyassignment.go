// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypePolicyAssignment = "AZURE::Authorization::PolicyAssignment"

// policyAssignmentsAPI is the subset of *armpolicy.AssignmentsClient used here.
// Everything is synchronous and Create is also the update verb.
//
// The scope-taking verbs are used rather than the ByID ones so that a single
// implementation covers subscription, resource-group and resource scopes alike.
type policyAssignmentsAPI interface {
	Create(ctx context.Context, scope, policyAssignmentName string, parameters armpolicy.Assignment, options *armpolicy.AssignmentsClientCreateOptions) (armpolicy.AssignmentsClientCreateResponse, error)
	Get(ctx context.Context, scope, policyAssignmentName string, options *armpolicy.AssignmentsClientGetOptions) (armpolicy.AssignmentsClientGetResponse, error)
	Delete(ctx context.Context, scope, policyAssignmentName string, options *armpolicy.AssignmentsClientDeleteOptions) (armpolicy.AssignmentsClientDeleteResponse, error)
	NewListPager(options *armpolicy.AssignmentsClientListOptions) *runtime.Pager[armpolicy.AssignmentsClientListResponse]
	NewListForResourceGroupPager(resourceGroupName string, options *armpolicy.AssignmentsClientListForResourceGroupOptions) *runtime.Pager[armpolicy.AssignmentsClientListForResourceGroupResponse]
}

func init() {
	registry.Register(ResourceTypePolicyAssignment, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &PolicyAssignment{api: c.PolicyAssignmentsClient, config: cfg}
	})
}

// PolicyAssignment is the provisioner for policy assignments
// (Microsoft.Authorization/policyAssignments).
type PolicyAssignment struct {
	api    policyAssignmentsAPI
	config *config.Config
}

// policyAssignmentProps mirrors
// schema/pkl/authorization/policyassignment.pkl.
type policyAssignmentProps struct {
	Name                  string                               `json:"name"`
	Scope                 string                               `json:"scope"`
	PolicyDefinitionID    string                               `json:"policyDefinitionId"`
	DisplayName           *string                              `json:"displayName"`
	Description           *string                              `json:"description"`
	EnforcementMode       *string                              `json:"enforcementMode"`
	NotScopes             []string                             `json:"notScopes"`
	NonComplianceMessages []policyAssignmentNonComplianceProps `json:"nonComplianceMessages"`
}

type policyAssignmentNonComplianceProps struct {
	Message                     string  `json:"message"`
	PolicyDefinitionReferenceID *string `json:"policyDefinitionReferenceId"`
}

const policyAssignmentSegment = "/providers/microsoft.authorization/policyassignments/"

// policyAssignmentIDParts splits an assignment ID into the scope it applies to and
// its name. As with role definitions the scope may be a subscription, a resource
// group, a single resource or a management group, so armIDParts does not apply.
func policyAssignmentIDParts(resourceID string) (scope, name string, err error) {
	idx := strings.Index(strings.ToLower(resourceID), policyAssignmentSegment)
	if idx < 0 {
		return "", "", fmt.Errorf("not a policy assignment resource ID: %s", resourceID)
	}
	scope = resourceID[:idx]
	name = resourceID[idx+len(policyAssignmentSegment):]
	if scope == "" || name == "" {
		return "", "", fmt.Errorf("not a policy assignment resource ID: %s", resourceID)
	}
	return scope, name, nil
}

func (p *PolicyAssignment) buildPropertiesFromResult(assignment *armpolicy.Assignment, scope string) map[string]any {
	props := make(map[string]any)

	props["scope"] = scope

	if assignment.ID != nil {
		props["id"] = *assignment.ID
	}
	if assignment.Name != nil {
		props["name"] = *assignment.Name
	}

	a := assignment.Properties
	if a == nil {
		return props
	}

	if a.PolicyDefinitionID != nil {
		props["policyDefinitionId"] = *a.PolicyDefinitionID
	}
	if a.DisplayName != nil && *a.DisplayName != "" {
		props["displayName"] = *a.DisplayName
	}
	if a.Description != nil && *a.Description != "" {
		props["description"] = *a.Description
	}
	if a.EnforcementMode != nil {
		props["enforcementMode"] = canonicalizeEnum(string(*a.EnforcementMode), "Default", "DoNotEnforce")
	}
	if notScopes := stringsFromPointers(a.NotScopes); notScopes != nil {
		props["notScopes"] = notScopes
	}

	messages := make([]map[string]any, 0, len(a.NonComplianceMessages))
	for _, message := range a.NonComplianceMessages {
		if message == nil || message.Message == nil {
			continue
		}
		entry := map[string]any{"message": *message.Message}
		if message.PolicyDefinitionReferenceID != nil && *message.PolicyDefinitionReferenceID != "" {
			entry["policyDefinitionReferenceId"] = *message.PolicyDefinitionReferenceID
		}
		messages = append(messages, entry)
	}
	if len(messages) > 0 {
		props["nonComplianceMessages"] = messages
	}

	// parameters, metadata, overrides and resourceSelectors are unmodelled; scope,
	// assignmentType, instanceId and the three definition-version fields are the
	// service's own view. Identity and location are only meaningful for effects this
	// schema does not cover. None is read back.
	return props
}

// policyAssignmentParams builds the request body shared by create and update.
func policyAssignmentParams(props policyAssignmentProps) armpolicy.Assignment {
	assignment := armpolicy.Assignment{
		Properties: &armpolicy.AssignmentProperties{
			PolicyDefinitionID: to.Ptr(props.PolicyDefinitionID),
			DisplayName:        props.DisplayName,
			Description:        props.Description,
			NotScopes:          stringPointers(props.NotScopes),
		},
	}

	if props.EnforcementMode != nil && *props.EnforcementMode != "" {
		assignment.Properties.EnforcementMode = to.Ptr(armpolicy.EnforcementMode(*props.EnforcementMode))
	}

	if len(props.NonComplianceMessages) > 0 {
		messages := make([]*armpolicy.NonComplianceMessage, 0, len(props.NonComplianceMessages))
		for _, message := range props.NonComplianceMessages {
			messages = append(messages, &armpolicy.NonComplianceMessage{
				Message:                     to.Ptr(message.Message),
				PolicyDefinitionReferenceID: message.PolicyDefinitionReferenceID,
			})
		}
		assignment.Properties.NonComplianceMessages = messages
	}

	return assignment
}

func (p *PolicyAssignment) parseProps(payload json.RawMessage, label string) (policyAssignmentProps, string, error) {
	var props policyAssignmentProps
	if err := json.Unmarshal(payload, &props); err != nil {
		return props, "", fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.Scope == "" {
		return props, "", fmt.Errorf("scope is required")
	}
	if props.PolicyDefinitionID == "" {
		return props, "", fmt.Errorf("policyDefinitionId is required")
	}
	// ARM: "Only one non-compliance message may be provided when assigning a policy
	// definition." Several are allowed only for an initiative, where each message
	// names the definition inside it that it belongs to. Caught here because ARM
	// only reports it at PUT time, and its wording does not say what to do about it.
	if len(props.NonComplianceMessages) > 1 {
		for _, message := range props.NonComplianceMessages {
			if message.PolicyDefinitionReferenceID == nil || *message.PolicyDefinitionReferenceID == "" {
				return props, "", fmt.Errorf("only one nonComplianceMessage is allowed when assigning a single policy definition; several require a policyDefinitionReferenceId on each (initiatives only)")
			}
		}
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

func (p *PolicyAssignment) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	props, name, err := p.parseProps(request.Properties, request.Label)
	if err != nil {
		return nil, err
	}

	result, err := p.api.Create(ctx, props.Scope, name, policyAssignmentParams(props), nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	nativeID := ""
	if result.ID != nil {
		nativeID = *result.ID
	}
	propsJSON, err := json.Marshal(p.buildPropertiesFromResult(&result.Assignment, props.Scope))
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

func (p *PolicyAssignment) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	scope, name, err := policyAssignmentIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := p.api.Get(ctx, scope, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(p.buildPropertiesFromResult(&result.Assignment, scope))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypePolicyAssignment,
		Properties:   string(propsJSON),
	}, nil
}

// Update reissues Create: it is the API's only write verb.
func (p *PolicyAssignment) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	scope, name, err := policyAssignmentIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	props, _, err := p.parseProps(request.DesiredProperties, name)
	if err != nil {
		return nil, err
	}

	result, err := p.api.Create(ctx, scope, name, policyAssignmentParams(props), nil)
	if err != nil {
		return &resource.UpdateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationUpdate,
				OperationStatus: resource.OperationStatusFailure,
				NativeID:        request.NativeID,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	propsJSON, err := json.Marshal(p.buildPropertiesFromResult(&result.Assignment, scope))
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

func (p *PolicyAssignment) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	scope, name, err := policyAssignmentIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	if _, err := p.api.Delete(ctx, scope, name, nil); err != nil && !isDeleteSuccessError(err) {
		return &resource.DeleteResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationDelete,
				OperationStatus: resource.OperationStatusFailure,
				NativeID:        request.NativeID,
				ErrorCode:       operationErrorCode(err),
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

// Status can only ever be asked about an operation that already finished: every
// write here is synchronous.
func (p *PolicyAssignment) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

// List enumerates assignments at a resource group when the scope names one, and
// otherwise across the subscription.
func (p *PolicyAssignment) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	scope := request.AdditionalProperties["scope"]

	if rgName := policyAssignmentResourceGroupFromScope(scope); rgName != "" {
		var nativeIDs []string
		pager := p.api.NewListForResourceGroupPager(rgName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list policy assignments: %w", err)
			}
			for _, assignment := range page.Value {
				if assignment == nil || assignment.ID == nil {
					continue
				}
				if !policyAssignmentIsWithinSubscription(*assignment.ID, p.config.SubscriptionId) {
					continue
				}
				nativeIDs = append(nativeIDs, *assignment.ID)
			}
		}
		return &resource.ListResult{NativeIDs: nativeIDs}, nil
	}

	var nativeIDs []string
	pager := p.api.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list policy assignments: %w", err)
		}
		for _, assignment := range page.Value {
			if assignment == nil || assignment.ID == nil {
				continue
			}
			if !policyAssignmentIsWithinSubscription(*assignment.ID, p.config.SubscriptionId) {
				continue
			}
			nativeIDs = append(nativeIDs, *assignment.ID)
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}

// policyAssignmentResourceGroupFromScope returns the resource group a scope names,
// or "" when the scope is broader than one. A scope that reaches further than a
// group — down to an individual resource — has no group-level pager of its own, so
// it falls back to the subscription listing.
// policyAssignmentIsWithinSubscription reports whether an assignment id names
// something at or below the given subscription.
//
// ARM's subscription-scoped list returns every assignment that APPLIES to the
// subscription, which includes ones assigned on a management group above it.
// Those are visible but not ours: the target grants formae rights on the
// subscription, so reading an assignment above it is refused, and a resource
// imported from there fails on every sync forever rather than once.
//
// Both list branches need this, not just the subscription-wide one. The SDK is
// explicit that an unfiltered resource-group list "includes all policy
// assignments associated with the resource group, including those that apply
// directly or apply from containing scopes" - and a containing scope can be a
// management group, so that pager returns inherited assignments too.
//
// Casing is normalised because ARM is inconsistent about it in resource ids, and
// a casing difference must not drop an assignment that really is ours.
func policyAssignmentIsWithinSubscription(nativeID, subscriptionID string) bool {
	if nativeID == "" || subscriptionID == "" {
		return false
	}
	prefix := "/subscriptions/" + strings.ToLower(subscriptionID) + "/"
	return strings.HasPrefix(strings.ToLower(nativeID), prefix)
}

func policyAssignmentResourceGroupFromScope(scope string) string {
	const marker = "/resourcegroups/"
	idx := strings.Index(strings.ToLower(scope), marker)
	if idx < 0 {
		return ""
	}
	rest := scope[idx+len(marker):]
	if rest == "" || strings.Contains(rest, "/") {
		return ""
	}
	return rest
}
