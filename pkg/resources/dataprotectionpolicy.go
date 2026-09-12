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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/dataprotection/armdataprotection/v3"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

// All four AZURE::DataProtection::BackupPolicy* types are the SAME ARM resource
// (`Microsoft.DataProtection/backupVaults/backupPolicies`, modelled by the SDK as
// BaseBackupPolicyResource). They differ only in the fixed `datasourceTypes` value
// ARM validates the rule tree against. Splitting them into four formae types keeps
// the datasource an immutable property of the type rather than a field a user can
// change into an invalid combination, and mirrors what the portal and
// `az dataprotection backup-policy get-default-policy-template` present.
//
// This file carries the whole implementation; the four <type>.go files are just a
// ResourceType constant plus an init() that binds the datasource string.
//
// The client is entirely SYNCHRONOUS — BackupPoliciesClient has no BeginX verb, so
// there is no poller, no resume token and no LRO Status path (trap 8).

// dataProtectionBackupPoliciesAPI is the armdataprotection surface used here.
type dataProtectionBackupPoliciesAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName string, vaultName string, backupPolicyName string, parameters armdataprotection.BaseBackupPolicyResource, options *armdataprotection.BackupPoliciesClientCreateOrUpdateOptions) (armdataprotection.BackupPoliciesClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName string, vaultName string, backupPolicyName string, options *armdataprotection.BackupPoliciesClientGetOptions) (armdataprotection.BackupPoliciesClientGetResponse, error)
	Delete(ctx context.Context, resourceGroupName string, vaultName string, backupPolicyName string, options *armdataprotection.BackupPoliciesClientDeleteOptions) (armdataprotection.BackupPoliciesClientDeleteResponse, error)
	NewListPager(resourceGroupName string, vaultName string, options *armdataprotection.BackupPoliciesClientListOptions) *runtime.Pager[armdataprotection.BackupPoliciesClientListResponse]
}

// dpPolicyTaggingCriterion mirrors the TaggingCriterion nested class in every
// dataprotectionbackuppolicy*.pkl.
type dpPolicyTaggingCriterion struct {
	TagName          string   `json:"tagName"`
	IsDefault        *bool    `json:"isDefault"`
	TaggingPriority  *int64   `json:"taggingPriority"`
	AbsoluteCriteria []string `json:"absoluteCriteria"`
}

// dpPolicyBackupRule mirrors the BackupRule nested class. ARM nests the schedule
// one level deeper (trigger.schedule.repeatingTimeIntervals); the schema flattens
// it because a ScheduleBasedTriggerContext is the only trigger shape a policy
// authored through this plugin can have.
type dpPolicyBackupRule struct {
	Name                   string                     `json:"name"`
	BackupType             string                     `json:"backupType"`
	DatastoreType          string                     `json:"datastoreType"`
	RepeatingTimeIntervals []string                   `json:"repeatingTimeIntervals"`
	TimeZone               string                     `json:"timeZone"`
	TaggingCriteria        []dpPolicyTaggingCriterion `json:"taggingCriteria"`
}

// dpPolicyCopySetting mirrors the RetentionCopySetting nested class.
type dpPolicyCopySetting struct {
	DatastoreType     string `json:"datastoreType"`
	CopyAfterDuration string `json:"copyAfterDuration"`
}

// dpPolicyLifecycle mirrors the RetentionLifecycle nested class.
type dpPolicyLifecycle struct {
	SourceDatastoreType string                `json:"sourceDatastoreType"`
	DeleteAfterDuration string                `json:"deleteAfterDuration"`
	TargetCopySettings  []dpPolicyCopySetting `json:"targetCopySettings"`
}

// dpPolicyRetentionRule mirrors the RetentionRule nested class.
type dpPolicyRetentionRule struct {
	Name       string              `json:"name"`
	IsDefault  *bool               `json:"isDefault"`
	Lifecycles []dpPolicyLifecycle `json:"lifecycles"`
}

// dpPolicyProps mirrors the top-level properties of every
// dataprotectionbackuppolicy*.pkl.
type dpPolicyProps struct {
	Name              string                  `json:"name"`
	ResourceGroupName string                  `json:"resourceGroupName"`
	VaultName         string                  `json:"vaultName"`
	BackupRules       []dpPolicyBackupRule    `json:"backupRules"`
	RetentionRules    []dpPolicyRetentionRule `json:"retentionRules"`
}

// dataProtectionBackupPolicy provisions one backup policy flavour. resourceType and
// datasourceType are bound per formae type by the four thin registration files.
type dataProtectionBackupPolicy struct {
	api            dataProtectionBackupPoliciesAPI
	config         *config.Config
	resourceType   string
	datasourceType string
}

func dataProtectionBackupPolicyIDParts(resourceID string) (rgName, vaultName, policyName string, err error) {
	rgName, names, err := armIDParts(resourceID, "backupvaults", "backuppolicies")
	if err != nil {
		return "", "", "", err
	}
	return rgName, names["backupvaults"], names["backuppolicies"], nil
}

func dpDataStoreInfo(datastoreType string) *armdataprotection.DataStoreInfoBase {
	return &armdataprotection.DataStoreInfoBase{
		ObjectType:    to.Ptr("DataStoreInfoBase"),
		DataStoreType: to.Ptr(armdataprotection.DataStoreTypes(datastoreType)),
	}
}

func dpTaggingCriteria(criteria []dpPolicyTaggingCriterion) []*armdataprotection.TaggingCriteria {
	if len(criteria) == 0 {
		return nil
	}
	out := make([]*armdataprotection.TaggingCriteria, 0, len(criteria))
	for _, c := range criteria {
		entry := &armdataprotection.TaggingCriteria{
			IsDefault:       c.IsDefault,
			TaggingPriority: c.TaggingPriority,
			TagInfo:         &armdataprotection.RetentionTag{TagName: to.Ptr(c.TagName)},
		}
		if len(c.AbsoluteCriteria) > 0 {
			markers := make([]*armdataprotection.AbsoluteMarker, 0, len(c.AbsoluteCriteria))
			for _, marker := range c.AbsoluteCriteria {
				markers = append(markers, to.Ptr(armdataprotection.AbsoluteMarker(marker)))
			}
			entry.Criteria = []armdataprotection.BackupCriteriaClassification{
				&armdataprotection.ScheduleBasedBackupCriteria{
					ObjectType:       to.Ptr("ScheduleBasedBackupCriteria"),
					AbsoluteCriteria: markers,
				},
			}
		}
		out = append(out, entry)
	}
	return out
}

func dpCopySettings(settings []dpPolicyCopySetting) []*armdataprotection.TargetCopySetting {
	if len(settings) == 0 {
		return nil
	}
	out := make([]*armdataprotection.TargetCopySetting, 0, len(settings))
	for _, s := range settings {
		entry := &armdataprotection.TargetCopySetting{
			DataStore: dpDataStoreInfo(s.DatastoreType),
		}
		// An absent duration is ARM's ImmediateCopyOption: copy as soon as the
		// source backup lands. A duration switches to CustomCopyOption.
		if s.CopyAfterDuration == "" {
			entry.CopyAfter = &armdataprotection.ImmediateCopyOption{
				ObjectType: to.Ptr("ImmediateCopyOption"),
			}
		} else {
			entry.CopyAfter = &armdataprotection.CustomCopyOption{
				ObjectType: to.Ptr("CustomCopyOption"),
				Duration:   to.Ptr(s.CopyAfterDuration),
			}
		}
		out = append(out, entry)
	}
	return out
}

// buildPolicy renders the declared rule lists into ARM's polymorphic policyRules
// array. Backup rules come first and retention rules second — the order ARM's own
// disk and PostgreSQL templates use — but ARM does not depend on it, and the read
// path re-splits by objectType rather than by position.
func (d *dataProtectionBackupPolicy) buildPolicy(props dpPolicyProps) (*armdataprotection.BackupPolicy, error) {
	rules := make([]armdataprotection.BasePolicyRuleClassification, 0, len(props.BackupRules)+len(props.RetentionRules))

	for _, br := range props.BackupRules {
		if br.Name == "" {
			return nil, fmt.Errorf("every backupRule needs a name")
		}
		if len(br.RepeatingTimeIntervals) == 0 {
			return nil, fmt.Errorf("backupRule %q needs at least one repeatingTimeInterval", br.Name)
		}
		schedule := &armdataprotection.BackupSchedule{
			RepeatingTimeIntervals: stringPointers(br.RepeatingTimeIntervals),
		}
		if br.TimeZone != "" {
			schedule.TimeZone = to.Ptr(br.TimeZone)
		}
		rules = append(rules, &armdataprotection.AzureBackupRule{
			ObjectType: to.Ptr("AzureBackupRule"),
			Name:       to.Ptr(br.Name),
			DataStore:  dpDataStoreInfo(br.DatastoreType),
			BackupParameters: &armdataprotection.AzureBackupParams{
				ObjectType: to.Ptr("AzureBackupParams"),
				BackupType: to.Ptr(br.BackupType),
			},
			Trigger: &armdataprotection.ScheduleBasedTriggerContext{
				ObjectType:      to.Ptr("ScheduleBasedTriggerContext"),
				Schedule:        schedule,
				TaggingCriteria: dpTaggingCriteria(br.TaggingCriteria),
			},
		})
	}

	for _, rr := range props.RetentionRules {
		if rr.Name == "" {
			return nil, fmt.Errorf("every retentionRule needs a name")
		}
		if len(rr.Lifecycles) == 0 {
			return nil, fmt.Errorf("retentionRule %q needs at least one lifecycle", rr.Name)
		}
		lifecycles := make([]*armdataprotection.SourceLifeCycle, 0, len(rr.Lifecycles))
		for _, l := range rr.Lifecycles {
			if l.DeleteAfterDuration == "" {
				return nil, fmt.Errorf("retentionRule %q needs a deleteAfterDuration on every lifecycle", rr.Name)
			}
			lifecycles = append(lifecycles, &armdataprotection.SourceLifeCycle{
				SourceDataStore: dpDataStoreInfo(l.SourceDatastoreType),
				DeleteAfter: &armdataprotection.AbsoluteDeleteOption{
					ObjectType: to.Ptr("AbsoluteDeleteOption"),
					Duration:   to.Ptr(l.DeleteAfterDuration),
				},
				TargetDataStoreCopySettings: dpCopySettings(l.TargetCopySettings),
			})
		}
		rules = append(rules, &armdataprotection.AzureRetentionRule{
			ObjectType: to.Ptr("AzureRetentionRule"),
			Name:       to.Ptr(rr.Name),
			IsDefault:  rr.IsDefault,
			Lifecycles: lifecycles,
		})
	}

	if len(rules) == 0 {
		return nil, fmt.Errorf("a backup policy needs at least one retentionRule")
	}

	return &armdataprotection.BackupPolicy{
		ObjectType:      to.Ptr("BackupPolicy"),
		DatasourceTypes: []*string{to.Ptr(d.datasourceType)},
		PolicyRules:     rules,
	}, nil
}

func dpReadTaggingCriteria(criteria []*armdataprotection.TaggingCriteria) []map[string]any {
	out := make([]map[string]any, 0, len(criteria))
	for _, c := range criteria {
		if c == nil {
			continue
		}
		entry := map[string]any{}
		if c.TagInfo != nil && c.TagInfo.TagName != nil {
			entry["tagName"] = *c.TagInfo.TagName
		}
		if c.IsDefault != nil {
			entry["isDefault"] = *c.IsDefault
		}
		if c.TaggingPriority != nil {
			entry["taggingPriority"] = *c.TaggingPriority
		}
		markers := make([]string, 0)
		for _, raw := range c.Criteria {
			sched, ok := raw.(*armdataprotection.ScheduleBasedBackupCriteria)
			if !ok {
				continue
			}
			for _, m := range sched.AbsoluteCriteria {
				if m != nil {
					markers = append(markers, string(*m))
				}
			}
		}
		if len(markers) > 0 {
			entry["absoluteCriteria"] = markers
		}
		if len(entry) > 0 {
			out = append(out, entry)
		}
	}
	return out
}

func dpReadCopySettings(settings []*armdataprotection.TargetCopySetting) []map[string]any {
	out := make([]map[string]any, 0, len(settings))
	for _, s := range settings {
		if s == nil {
			continue
		}
		entry := map[string]any{}
		if s.DataStore != nil && s.DataStore.DataStoreType != nil {
			entry["datastoreType"] = canonicalizeEnum(string(*s.DataStore.DataStoreType),
				"OperationalStore", "VaultStore", "ArchiveStore")
		}
		if custom, ok := s.CopyAfter.(*armdataprotection.CustomCopyOption); ok && custom.Duration != nil {
			entry["copyAfterDuration"] = *custom.Duration
		}
		if len(entry) > 0 {
			out = append(out, entry)
		}
	}
	return out
}

// buildPropertiesFromResult reads a policy back into the schema's shape. Only
// modelled fields are emitted: ARM also echoes a service-assigned `tagInfo.id`
// ("Default_") and, on some datasource types, an empty
// `targetDataStoreCopySettings: []`, neither of which the schema declares.
func (d *dataProtectionBackupPolicy) buildPropertiesFromResult(res *armdataprotection.BaseBackupPolicyResource, rgName, vaultName string) map[string]any {
	props := map[string]any{
		"resourceGroupName": rgName,
		"vaultName":         vaultName,
	}
	if res.ID != nil {
		props["id"] = *res.ID
	}
	if res.Name != nil {
		props["name"] = *res.Name
	}

	policy, ok := res.Properties.(*armdataprotection.BackupPolicy)
	if !ok || policy == nil {
		return props
	}

	backupRules := make([]map[string]any, 0)
	retentionRules := make([]map[string]any, 0)

	for _, raw := range policy.PolicyRules {
		switch rule := raw.(type) {
		case *armdataprotection.AzureBackupRule:
			entry := map[string]any{}
			if rule.Name != nil {
				entry["name"] = *rule.Name
			}
			if params, ok := rule.BackupParameters.(*armdataprotection.AzureBackupParams); ok && params.BackupType != nil {
				entry["backupType"] = *params.BackupType
			}
			if rule.DataStore != nil && rule.DataStore.DataStoreType != nil {
				entry["datastoreType"] = canonicalizeEnum(string(*rule.DataStore.DataStoreType),
					"OperationalStore", "VaultStore", "ArchiveStore")
			}
			if trigger, ok := rule.Trigger.(*armdataprotection.ScheduleBasedTriggerContext); ok {
				if trigger.Schedule != nil {
					if intervals := stringsFromPointers(trigger.Schedule.RepeatingTimeIntervals); len(intervals) > 0 {
						entry["repeatingTimeIntervals"] = intervals
					}
					if trigger.Schedule.TimeZone != nil {
						entry["timeZone"] = *trigger.Schedule.TimeZone
					}
				}
				if criteria := dpReadTaggingCriteria(trigger.TaggingCriteria); len(criteria) > 0 {
					entry["taggingCriteria"] = criteria
				}
			}
			backupRules = append(backupRules, entry)
		case *armdataprotection.AzureRetentionRule:
			entry := map[string]any{}
			if rule.Name != nil {
				entry["name"] = *rule.Name
			}
			if rule.IsDefault != nil {
				entry["isDefault"] = *rule.IsDefault
			}
			lifecycles := make([]map[string]any, 0, len(rule.Lifecycles))
			for _, l := range rule.Lifecycles {
				if l == nil {
					continue
				}
				lc := map[string]any{}
				if l.SourceDataStore != nil && l.SourceDataStore.DataStoreType != nil {
					lc["sourceDatastoreType"] = canonicalizeEnum(string(*l.SourceDataStore.DataStoreType),
						"OperationalStore", "VaultStore", "ArchiveStore")
				}
				if del, ok := l.DeleteAfter.(*armdataprotection.AbsoluteDeleteOption); ok && del.Duration != nil {
					lc["deleteAfterDuration"] = *del.Duration
				}
				if copies := dpReadCopySettings(l.TargetDataStoreCopySettings); len(copies) > 0 {
					lc["targetCopySettings"] = copies
				}
				if len(lc) > 0 {
					lifecycles = append(lifecycles, lc)
				}
			}
			if len(lifecycles) > 0 {
				entry["lifecycles"] = lifecycles
			}
			retentionRules = append(retentionRules, entry)
		}
	}

	if len(backupRules) > 0 {
		props["backupRules"] = backupRules
	}
	if len(retentionRules) > 0 {
		props["retentionRules"] = retentionRules
	}

	return props
}

func (d *dataProtectionBackupPolicy) expectedNativeID(rgName, vaultName, name string) string {
	return fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.DataProtection/backupVaults/%s/backupPolicies/%s",
		d.config.SubscriptionId, rgName, vaultName, name)
}

func (d *dataProtectionBackupPolicy) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props dpPolicyProps
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	if props.VaultName == "" {
		return nil, fmt.Errorf("vaultName is required")
	}
	name := props.Name
	if name == "" {
		name = request.Label
	}
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}

	policy, err := d.buildPolicy(props)
	if err != nil {
		return nil, err
	}

	response, err := d.api.CreateOrUpdate(ctx, props.ResourceGroupName, props.VaultName, name,
		armdataprotection.BaseBackupPolicyResource{Properties: policy}, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				NativeID:        d.expectedNativeID(props.ResourceGroupName, props.VaultName, name),
				ErrorCode:       operationErrorCode(err),
				StatusMessage:   err.Error(),
			},
		}, nil
	}
	result := &response.BaseBackupPolicyResource

	propsJSON, err := json.Marshal(d.buildPropertiesFromResult(result, props.ResourceGroupName, props.VaultName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}

	nativeID := d.expectedNativeID(props.ResourceGroupName, props.VaultName, name)
	if result.ID != nil {
		nativeID = *result.ID
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

func (d *dataProtectionBackupPolicy) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, vaultName, name, err := dataProtectionBackupPolicyIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := d.api.Get(ctx, rgName, vaultName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(d.buildPropertiesFromResult(&result.BaseBackupPolicyResource, rgName, vaultName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}

	return &resource.ReadResult{
		ResourceType: d.resourceType,
		Properties:   string(propsJSON),
	}, nil
}

// Update is a full PUT: BackupPoliciesClient has no PATCH verb, so the rule tree is
// replaced wholesale. name, resourceGroupName and vaultName are createOnly in the
// schema because a change to any of them addresses a different policy.
func (d *dataProtectionBackupPolicy) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, vaultName, name, err := dataProtectionBackupPolicyIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props dpPolicyProps
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse desired properties: %w", err)
	}

	policy, err := d.buildPolicy(props)
	if err != nil {
		return nil, err
	}

	result, err := d.api.CreateOrUpdate(ctx, rgName, vaultName, name,
		armdataprotection.BaseBackupPolicyResource{Properties: policy}, nil)
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

	propsJSON, err := json.Marshal(d.buildPropertiesFromResult(&result.BaseBackupPolicyResource, rgName, vaultName))
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

func (d *dataProtectionBackupPolicy) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, vaultName, name, err := dataProtectionBackupPolicyIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	if _, err := d.api.Delete(ctx, rgName, vaultName, name, nil); err != nil {
		if isDeleteSuccessError(err) {
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

// Status re-reads the policy. Every verb on this client is synchronous, so a
// caller only lands here after a restart lost the in-memory result.
func (d *dataProtectionBackupPolicy) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	rgName, vaultName, name, err := dataProtectionBackupPolicyIDParts(request.NativeID)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
				StatusMessage:   err.Error(),
			},
		}, err
	}

	result, err := d.api.Get(ctx, rgName, vaultName, name, nil)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       operationErrorCode(err),
				StatusMessage:   err.Error(),
			},
		}, nil
	}

	propsJSON, err := json.Marshal(d.buildPropertiesFromResult(&result.BaseBackupPolicyResource, rgName, vaultName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}

	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus:    resource.OperationStatusSuccess,
			RequestID:          request.RequestID,
			NativeID:           request.NativeID,
			ResourceProperties: propsJSON,
		},
	}, nil
}

// List enumerates the policies of one vault. ARM has no cross-vault policy pager,
// so an empty scope yields nothing rather than falling back subscription-wide —
// which is why none of the four types needs a subscriptionWideList entry.
//
// The pager returns every policy in the vault regardless of datasource, so filter
// to the flavour this provisioner owns; otherwise all four formae types would each
// claim every policy in the vault.
func (d *dataProtectionBackupPolicy) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	vaultName := request.AdditionalProperties["vaultName"]
	if rgName == "" || vaultName == "" {
		return &resource.ListResult{}, nil
	}

	var nativeIDs []string
	pager := d.api.NewListPager(rgName, vaultName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list backup policies: %w", err)
		}
		for _, item := range page.Value {
			if item == nil || item.ID == nil {
				continue
			}
			if !d.ownsPolicy(item) {
				continue
			}
			nativeIDs = append(nativeIDs, *item.ID)
		}
	}

	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}

func (d *dataProtectionBackupPolicy) ownsPolicy(item *armdataprotection.BaseBackupPolicyResource) bool {
	base := item.Properties
	if base == nil {
		return false
	}
	policy := base.GetBaseBackupPolicy()
	if policy == nil {
		return false
	}
	for _, dst := range policy.DatasourceTypes {
		if dst != nil && *dst == d.datasourceType {
			return true
		}
	}
	return false
}
