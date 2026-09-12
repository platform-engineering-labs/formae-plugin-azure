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
	armpolicyv2 "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy/v2"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypePolicyExemption = "AZURE::Authorization::PolicyExemption"

// policyExemptionsAPI is the subset of *armpolicyv2.ExemptionsClient used here.
// Everything is synchronous and CreateOrUpdate is also the update verb — the PATCH
// verb (Update) reaches only assignmentScopeValidation and resourceSelectors, so a
// full PUT is what the update path needs.
//
// THIS IS THE ONLY FILE THAT IMPORTS armpolicy/v2. The three older policy resources
// import armpolicy v1.0.0, which REMOVED ExemptionsClient; v2.0.0-beta.1 is the
// only published module that still has it. The alias keeps the two apart, and the
// other three must not be moved onto it as a side effect of this file existing.
//
// As with policy assignments, the scope-taking verbs are used so that one
// implementation covers subscription, resource-group, resource and management-group
// scopes alike.
type policyExemptionsAPI interface {
	CreateOrUpdate(ctx context.Context, scope, policyExemptionName string, parameters armpolicyv2.Exemption, options *armpolicyv2.ExemptionsClientCreateOrUpdateOptions) (armpolicyv2.ExemptionsClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, scope, policyExemptionName string, options *armpolicyv2.ExemptionsClientGetOptions) (armpolicyv2.ExemptionsClientGetResponse, error)
	Delete(ctx context.Context, scope, policyExemptionName string, options *armpolicyv2.ExemptionsClientDeleteOptions) (armpolicyv2.ExemptionsClientDeleteResponse, error)
	NewListPager(options *armpolicyv2.ExemptionsClientListOptions) *runtime.Pager[armpolicyv2.ExemptionsClientListResponse]
	NewListForResourceGroupPager(resourceGroupName string, options *armpolicyv2.ExemptionsClientListForResourceGroupOptions) *runtime.Pager[armpolicyv2.ExemptionsClientListForResourceGroupResponse]
}

func init() {
	registry.Register(ResourceTypePolicyExemption, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &PolicyExemption{api: c.PolicyExemptionsClient, config: cfg}
	})
}

// PolicyExemption is the provisioner for policy exemptions
// (Microsoft.Authorization/policyExemptions).
type PolicyExemption struct {
	api    policyExemptionsAPI
	config *config.Config
}

// policyExemptionProps mirrors schema/pkl/authorization/policyexemption.pkl.
type policyExemptionProps struct {
	Name                         string   `json:"name"`
	Scope                        string   `json:"scope"`
	PolicyAssignmentID           string   `json:"policyAssignmentId"`
	ExemptionCategory            string   `json:"exemptionCategory"`
	DisplayName                  *string  `json:"displayName"`
	Description                  *string  `json:"description"`
	ExpiresOn                    *string  `json:"expiresOn"`
	PolicyDefinitionReferenceIDs []string `json:"policyDefinitionReferenceIds"`
	AssignmentScopeValidation    *string  `json:"assignmentScopeValidation"`
}

const policyExemptionSegment = "/providers/microsoft.authorization/policyexemptions/"

// policyExemptionIDParts splits an exemption ID into the scope it exempts and its
// name. The scope may be a subscription, a resource group, a single resource or a
// management group, so armIDParts does not apply.
func policyExemptionIDParts(resourceID string) (scope, name string, err error) {
	idx := strings.Index(strings.ToLower(resourceID), policyExemptionSegment)
	if idx < 0 {
		return "", "", fmt.Errorf("not a policy exemption resource ID: %s", resourceID)
	}
	scope = resourceID[:idx]
	name = resourceID[idx+len(policyExemptionSegment):]
	if scope == "" || name == "" {
		return "", "", fmt.Errorf("not a policy exemption resource ID: %s", resourceID)
	}
	return scope, name, nil
}

func (p *PolicyExemption) buildPropertiesFromResult(exemption *armpolicyv2.Exemption, scope string) map[string]any {
	props := make(map[string]any)

	props["scope"] = scope

	if exemption.ID != nil {
		props["id"] = *exemption.ID
	}
	if exemption.Name != nil {
		props["name"] = *exemption.Name
	}

	e := exemption.Properties
	if e == nil {
		return props
	}

	if e.PolicyAssignmentID != nil {
		props["policyAssignmentId"] = *e.PolicyAssignmentID
	}
	if e.ExemptionCategory != nil {
		props["exemptionCategory"] = canonicalizeEnum(string(*e.ExemptionCategory), "Waiver", "Mitigated")
	}
	if e.DisplayName != nil && *e.DisplayName != "" {
		props["displayName"] = *e.DisplayName
	}
	if e.Description != nil && *e.Description != "" {
		props["description"] = *e.Description
	}
	if e.ExpiresOn != nil {
		// Written and compared as UTC RFC 3339 so that a value ARM hands back in a
		// different offset does not read as drift against desired state.
		props["expiresOn"] = e.ExpiresOn.UTC().Format(time.RFC3339)
	}
	if refs := stringsFromPointers(e.PolicyDefinitionReferenceIDs); refs != nil {
		props["policyDefinitionReferenceIds"] = refs
	}
	if e.AssignmentScopeValidation != nil {
		props["assignmentScopeValidation"] = canonicalizeEnum(string(*e.AssignmentScopeValidation), "Default", "DoNotValidate")
	}

	// metadata and resourceSelectors are unmodelled; systemData is the service's own
	// view. None is read back.
	return props
}

// policyExemptionParams builds the request body shared by create and update.
func policyExemptionParams(props policyExemptionProps) (armpolicyv2.Exemption, error) {
	exemption := armpolicyv2.Exemption{
		Properties: &armpolicyv2.ExemptionProperties{
			PolicyAssignmentID:           to.Ptr(props.PolicyAssignmentID),
			ExemptionCategory:            to.Ptr(armpolicyv2.ExemptionCategory(props.ExemptionCategory)),
			DisplayName:                  props.DisplayName,
			Description:                  props.Description,
			PolicyDefinitionReferenceIDs: stringPointers(props.PolicyDefinitionReferenceIDs),
		},
	}

	if props.ExpiresOn != nil && *props.ExpiresOn != "" {
		expiresOn, err := parseTime(*props.ExpiresOn)
		if err != nil {
			return armpolicyv2.Exemption{}, fmt.Errorf("expiresOn is not a valid ISO 8601 timestamp: %w", err)
		}
		exemption.Properties.ExpiresOn = to.Ptr(expiresOn.UTC())
	}

	if props.AssignmentScopeValidation != nil && *props.AssignmentScopeValidation != "" {
		exemption.Properties.AssignmentScopeValidation = to.Ptr(armpolicyv2.AssignmentScopeValidation(*props.AssignmentScopeValidation))
	}

	return exemption, nil
}

func (p *PolicyExemption) parseProps(payload json.RawMessage, label string) (policyExemptionProps, string, error) {
	var props policyExemptionProps
	if err := json.Unmarshal(payload, &props); err != nil {
		return props, "", fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.Scope == "" {
		return props, "", fmt.Errorf("scope is required")
	}
	if props.PolicyAssignmentID == "" {
		return props, "", fmt.Errorf("policyAssignmentId is required")
	}
	if props.ExemptionCategory == "" {
		return props, "", fmt.Errorf("exemptionCategory is required")
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

func (p *PolicyExemption) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	props, name, err := p.parseProps(request.Properties, request.Label)
	if err != nil {
		return nil, err
	}
	params, err := policyExemptionParams(props)
	if err != nil {
		return nil, err
	}

	result, err := p.api.CreateOrUpdate(ctx, props.Scope, name, params, nil)
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
	propsJSON, err := json.Marshal(p.buildPropertiesFromResult(&result.Exemption, props.Scope))
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

func (p *PolicyExemption) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	scope, name, err := policyExemptionIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := p.api.Get(ctx, scope, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(p.buildPropertiesFromResult(&result.Exemption, scope))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypePolicyExemption,
		Properties:   string(propsJSON),
	}, nil
}

// Update reissues CreateOrUpdate. The PATCH verb this API also offers reaches only
// assignmentScopeValidation and resourceSelectors, so it cannot carry an update to
// the category, the expiry or the assignment.
func (p *PolicyExemption) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	scope, name, err := policyExemptionIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	props, _, err := p.parseProps(request.DesiredProperties, name)
	if err != nil {
		return nil, err
	}
	params, err := policyExemptionParams(props)
	if err != nil {
		return nil, err
	}

	result, err := p.api.CreateOrUpdate(ctx, scope, name, params, nil)
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

	propsJSON, err := json.Marshal(p.buildPropertiesFromResult(&result.Exemption, scope))
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

func (p *PolicyExemption) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	scope, name, err := policyExemptionIDParts(request.NativeID)
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

// Status can only ever be asked about an operation that already finished: every
// write here is synchronous.
func (p *PolicyExemption) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

// List enumerates exemptions at a resource group when the scope names one, and
// otherwise across the subscription.
func (p *PolicyExemption) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	scope := request.AdditionalProperties["scope"]

	var nativeIDs []string
	if rgName := policyAssignmentResourceGroupFromScope(scope); rgName != "" {
		pager := p.api.NewListForResourceGroupPager(rgName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list policy exemptions: %w", err)
			}
			for _, exemption := range page.Value {
				if exemption != nil && exemption.ID != nil {
					nativeIDs = append(nativeIDs, *exemption.ID)
				}
			}
		}
		return &resource.ListResult{NativeIDs: nativeIDs}, nil
	}

	pager := p.api.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list policy exemptions: %w", err)
		}
		for _, exemption := range page.Value {
			if exemption != nil && exemption.ID != nil {
				nativeIDs = append(nativeIDs, *exemption.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
