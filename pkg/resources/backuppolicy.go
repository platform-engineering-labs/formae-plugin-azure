// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/recoveryservices/armrecoveryservicesbackup/v4"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

// Shared plumbing for the two AZURE::RecoveryServices::BackupPolicy* types.
//
// Both are the same ARM resource (Microsoft.RecoveryServices/vaults/backupPolicies)
// with a different polymorphic `properties` discriminator, so schedule and
// retention conversion, ID parsing, the LRO handling and discovery are identical
// between them. This file is the shared half, in the spirit of cosmoschild.go;
// backuppolicyvm.go and backuppolicyfileshare.go carry only what actually differs.

// backupPolicyScheduleAnchorDate is the date half of every schedule/retention
// timestamp sent to ARM.
//
// ARM models a backup schedule time as a full RFC3339 timestamp but only ever
// honours its time-of-day; the date is ignored on the way in and echoed back
// unpredictably (the service rewrites it to the policy's own creation date on
// some paths). Reading the date back would therefore report drift on every sync,
// so the schema models times as bare "HH:MM" and this constant supplies the date
// half in both directions. Terraform's azurerm provider pins a constant date for
// exactly the same reason.
const backupPolicyScheduleAnchorDate = "2024-01-01"

// backupPolicyTimeOfDay matches the "HH:MM" form the schema accepts. ARM only
// allows backups on the hour or the half hour.
var backupPolicyTimeOfDay = regexp.MustCompile(`^([01][0-9]|2[0-3]):(00|30)$`)

// backupPolicySchedule mirrors the `backupSchedule` nested class in both policy
// schemas.
type backupPolicySchedule struct {
	Frequency  string   `json:"frequency"`
	Times      []string `json:"times"`
	DaysOfWeek []string `json:"daysOfWeek"`
}

type backupRetentionDaily struct {
	Count int32 `json:"count"`
}

type backupRetentionWeekly struct {
	Count      int32    `json:"count"`
	DaysOfWeek []string `json:"daysOfWeek"`
}

type backupRetentionMonthly struct {
	Count        int32    `json:"count"`
	DaysOfWeek   []string `json:"daysOfWeek"`
	WeeksOfMonth []string `json:"weeksOfMonth"`
}

type backupRetentionYearly struct {
	Count        int32    `json:"count"`
	MonthsOfYear []string `json:"monthsOfYear"`
	DaysOfWeek   []string `json:"daysOfWeek"`
	WeeksOfMonth []string `json:"weeksOfMonth"`
}

// backupPolicyRetention is the retention half shared by both policy schemas.
type backupPolicyRetention struct {
	DailyRetention   *backupRetentionDaily   `json:"dailyRetention"`
	WeeklyRetention  *backupRetentionWeekly  `json:"weeklyRetention"`
	MonthlyRetention *backupRetentionMonthly `json:"monthlyRetention"`
	YearlyRetention  *backupRetentionYearly  `json:"yearlyRetention"`
}

func backupPolicyIDParts(resourceID string) (rgName, vaultName, policyName string, err error) {
	rgName, names, err := armIDParts(resourceID, "vaults", "backuppolicies")
	if err != nil {
		return "", "", "", err
	}
	return rgName, names["vaults"], names["backuppolicies"], nil
}

// backupPolicyTimes converts the schema's "HH:MM" strings into the timestamps ARM
// wants, all on backupPolicyScheduleAnchorDate.
func backupPolicyTimes(times []string) ([]*time.Time, error) {
	if len(times) == 0 {
		return nil, fmt.Errorf("at least one schedule time is required")
	}
	out := make([]*time.Time, 0, len(times))
	for _, value := range times {
		if !backupPolicyTimeOfDay.MatchString(value) {
			return nil, fmt.Errorf("schedule time %q must be HH:MM on the hour or half hour", value)
		}
		parsed, err := time.Parse(time.RFC3339, backupPolicyScheduleAnchorDate+"T"+value+":00Z")
		if err != nil {
			return nil, fmt.Errorf("cannot parse schedule time %q: %w", value, err)
		}
		t := parsed
		out = append(out, &t)
	}
	return out, nil
}

// backupPolicyTimeStrings is the read-path inverse: it keeps only the time of day,
// which is the only half of an ARM schedule timestamp that carries meaning.
func backupPolicyTimeStrings(times []*time.Time) []string {
	if len(times) == 0 {
		return nil
	}
	out := make([]string, 0, len(times))
	for _, t := range times {
		if t == nil {
			continue
		}
		out = append(out, t.UTC().Format("15:04"))
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func backupDaysOfWeek(values []string) []*armrecoveryservicesbackup.DayOfWeek {
	if len(values) == 0 {
		return nil
	}
	out := make([]*armrecoveryservicesbackup.DayOfWeek, 0, len(values))
	for _, value := range values {
		out = append(out, to.Ptr(armrecoveryservicesbackup.DayOfWeek(value)))
	}
	return out
}

func backupDayOfWeekStrings(values []*armrecoveryservicesbackup.DayOfWeek) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value == nil {
			continue
		}
		out = append(out, string(*value))
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func backupWeeksOfMonth(values []string) []*armrecoveryservicesbackup.WeekOfMonth {
	if len(values) == 0 {
		return nil
	}
	out := make([]*armrecoveryservicesbackup.WeekOfMonth, 0, len(values))
	for _, value := range values {
		out = append(out, to.Ptr(armrecoveryservicesbackup.WeekOfMonth(value)))
	}
	return out
}

func backupWeekOfMonthStrings(values []*armrecoveryservicesbackup.WeekOfMonth) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value == nil {
			continue
		}
		out = append(out, string(*value))
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func backupMonthsOfYear(values []string) []*armrecoveryservicesbackup.MonthOfYear {
	if len(values) == 0 {
		return nil
	}
	out := make([]*armrecoveryservicesbackup.MonthOfYear, 0, len(values))
	for _, value := range values {
		out = append(out, to.Ptr(armrecoveryservicesbackup.MonthOfYear(value)))
	}
	return out
}

func backupMonthOfYearStrings(values []*armrecoveryservicesbackup.MonthOfYear) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value == nil {
			continue
		}
		out = append(out, string(*value))
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// backupPolicySimpleSchedule builds the V1 SimpleSchedulePolicy both policy types
// use.
func backupPolicySimpleSchedule(schedule backupPolicySchedule) (*armrecoveryservicesbackup.SimpleSchedulePolicy, error) {
	if schedule.Frequency == "" {
		return nil, fmt.Errorf("backupSchedule.frequency is required")
	}
	times, err := backupPolicyTimes(schedule.Times)
	if err != nil {
		return nil, err
	}
	if schedule.Frequency == "Weekly" && len(schedule.DaysOfWeek) == 0 {
		return nil, fmt.Errorf("backupSchedule.daysOfWeek is required when frequency is Weekly")
	}

	return &armrecoveryservicesbackup.SimpleSchedulePolicy{
		SchedulePolicyType:   to.Ptr("SimpleSchedulePolicy"),
		ScheduleRunFrequency: to.Ptr(armrecoveryservicesbackup.ScheduleRunType(schedule.Frequency)),
		ScheduleRunTimes:     times,
		ScheduleRunDays:      backupDaysOfWeek(schedule.DaysOfWeek),
	}, nil
}

// backupPolicyLongTermRetention builds the retention half.
//
// Every retention schedule carries `retentionTimes`, and ARM rejects a policy
// whose retention times differ from its schedule times — the two are one setting
// split across the wire format. The schema therefore models the times once, on the
// schedule, and this derives the retention copies from them.
func backupPolicyLongTermRetention(retention backupPolicyRetention, times []*time.Time) (*armrecoveryservicesbackup.LongTermRetentionPolicy, error) {
	policy := &armrecoveryservicesbackup.LongTermRetentionPolicy{
		RetentionPolicyType: to.Ptr("LongTermRetentionPolicy"),
	}
	configured := false

	if r := retention.DailyRetention; r != nil {
		policy.DailySchedule = &armrecoveryservicesbackup.DailyRetentionSchedule{
			RetentionTimes: times,
			RetentionDuration: &armrecoveryservicesbackup.RetentionDuration{
				Count:        to.Ptr(r.Count),
				DurationType: to.Ptr(armrecoveryservicesbackup.RetentionDurationTypeDays),
			},
		}
		configured = true
	}
	if r := retention.WeeklyRetention; r != nil {
		if len(r.DaysOfWeek) == 0 {
			return nil, fmt.Errorf("weeklyRetention.daysOfWeek is required")
		}
		policy.WeeklySchedule = &armrecoveryservicesbackup.WeeklyRetentionSchedule{
			RetentionTimes: times,
			DaysOfTheWeek:  backupDaysOfWeek(r.DaysOfWeek),
			RetentionDuration: &armrecoveryservicesbackup.RetentionDuration{
				Count:        to.Ptr(r.Count),
				DurationType: to.Ptr(armrecoveryservicesbackup.RetentionDurationTypeWeeks),
			},
		}
		configured = true
	}
	if r := retention.MonthlyRetention; r != nil {
		if len(r.DaysOfWeek) == 0 || len(r.WeeksOfMonth) == 0 {
			return nil, fmt.Errorf("monthlyRetention needs both daysOfWeek and weeksOfMonth")
		}
		policy.MonthlySchedule = &armrecoveryservicesbackup.MonthlyRetentionSchedule{
			RetentionTimes:              times,
			RetentionScheduleFormatType: to.Ptr(armrecoveryservicesbackup.RetentionScheduleFormatWeekly),
			RetentionScheduleWeekly: &armrecoveryservicesbackup.WeeklyRetentionFormat{
				DaysOfTheWeek:   backupDaysOfWeek(r.DaysOfWeek),
				WeeksOfTheMonth: backupWeeksOfMonth(r.WeeksOfMonth),
			},
			RetentionDuration: &armrecoveryservicesbackup.RetentionDuration{
				Count:        to.Ptr(r.Count),
				DurationType: to.Ptr(armrecoveryservicesbackup.RetentionDurationTypeMonths),
			},
		}
		configured = true
	}
	if r := retention.YearlyRetention; r != nil {
		if len(r.DaysOfWeek) == 0 || len(r.WeeksOfMonth) == 0 || len(r.MonthsOfYear) == 0 {
			return nil, fmt.Errorf("yearlyRetention needs monthsOfYear, daysOfWeek and weeksOfMonth")
		}
		policy.YearlySchedule = &armrecoveryservicesbackup.YearlyRetentionSchedule{
			RetentionTimes:              times,
			MonthsOfYear:                backupMonthsOfYear(r.MonthsOfYear),
			RetentionScheduleFormatType: to.Ptr(armrecoveryservicesbackup.RetentionScheduleFormatWeekly),
			RetentionScheduleWeekly: &armrecoveryservicesbackup.WeeklyRetentionFormat{
				DaysOfTheWeek:   backupDaysOfWeek(r.DaysOfWeek),
				WeeksOfTheMonth: backupWeeksOfMonth(r.WeeksOfMonth),
			},
			RetentionDuration: &armrecoveryservicesbackup.RetentionDuration{
				Count:        to.Ptr(r.Count),
				DurationType: to.Ptr(armrecoveryservicesbackup.RetentionDurationTypeYears),
			},
		}
		configured = true
	}

	if !configured {
		return nil, fmt.Errorf("at least one retention schedule is required")
	}
	return policy, nil
}

// backupPolicyScheduleProps renders a SimpleSchedulePolicy back into the schema
// shape.
//
// Only keys the schema actually declares are emitted, and `daysOfWeek` only when
// ARM reports one. hasProviderDefault is a no-op inside a nested class — the SDK
// only recurses into classes extending formae.SubResource — so a key the caller
// never supplied would come back as "not expected and not a provider default" in
// every conformance phase at once.
func backupPolicyScheduleProps(schedule armrecoveryservicesbackup.SchedulePolicyClassification) map[string]any {
	simple, ok := schedule.(*armrecoveryservicesbackup.SimpleSchedulePolicy)
	if !ok || simple == nil {
		return nil
	}
	out := map[string]any{}
	if simple.ScheduleRunFrequency != nil {
		out["frequency"] = canonicalizeEnum(string(*simple.ScheduleRunFrequency), "Daily", "Weekly", "Hourly")
	}
	if times := backupPolicyTimeStrings(simple.ScheduleRunTimes); times != nil {
		out["times"] = times
	}
	if days := backupDayOfWeekStrings(simple.ScheduleRunDays); days != nil {
		out["daysOfWeek"] = days
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// backupPolicyRetentionProps renders a LongTermRetentionPolicy back into the
// schema shape, writing each present schedule under its own top-level key.
func backupPolicyRetentionProps(retention armrecoveryservicesbackup.RetentionPolicyClassification, props map[string]any) {
	longTerm, ok := retention.(*armrecoveryservicesbackup.LongTermRetentionPolicy)
	if !ok || longTerm == nil {
		return
	}

	if s := longTerm.DailySchedule; s != nil && s.RetentionDuration != nil && s.RetentionDuration.Count != nil {
		props["dailyRetention"] = map[string]any{"count": *s.RetentionDuration.Count}
	}
	if s := longTerm.WeeklySchedule; s != nil && s.RetentionDuration != nil && s.RetentionDuration.Count != nil {
		entry := map[string]any{"count": *s.RetentionDuration.Count}
		if days := backupDayOfWeekStrings(s.DaysOfTheWeek); days != nil {
			entry["daysOfWeek"] = days
		}
		props["weeklyRetention"] = entry
	}
	if s := longTerm.MonthlySchedule; s != nil && s.RetentionDuration != nil && s.RetentionDuration.Count != nil {
		entry := map[string]any{"count": *s.RetentionDuration.Count}
		if w := s.RetentionScheduleWeekly; w != nil {
			if days := backupDayOfWeekStrings(w.DaysOfTheWeek); days != nil {
				entry["daysOfWeek"] = days
			}
			if weeks := backupWeekOfMonthStrings(w.WeeksOfTheMonth); weeks != nil {
				entry["weeksOfMonth"] = weeks
			}
		}
		props["monthlyRetention"] = entry
	}
	if s := longTerm.YearlySchedule; s != nil && s.RetentionDuration != nil && s.RetentionDuration.Count != nil {
		entry := map[string]any{"count": *s.RetentionDuration.Count}
		if months := backupMonthOfYearStrings(s.MonthsOfYear); months != nil {
			entry["monthsOfYear"] = months
		}
		if w := s.RetentionScheduleWeekly; w != nil {
			if days := backupDayOfWeekStrings(w.DaysOfTheWeek); days != nil {
				entry["daysOfWeek"] = days
			}
			if weeks := backupWeekOfMonthStrings(w.WeeksOfTheMonth); weeks != nil {
				entry["weeksOfMonth"] = weeks
			}
		}
		props["yearlyRetention"] = entry
	}
}

// backupProtectionPoliciesAPI is the CRUD surface. Delete is the only long-running
// operation; CreateOrUpdate answers 200-with-body on the happy path and 202 with an
// EMPTY body when ARM decides to run the write asynchronously.
type backupProtectionPoliciesAPI interface {
	CreateOrUpdate(ctx context.Context, vaultName string, resourceGroupName string, policyName string, parameters armrecoveryservicesbackup.ProtectionPolicyResource, options *armrecoveryservicesbackup.ProtectionPoliciesClientCreateOrUpdateOptions) (armrecoveryservicesbackup.ProtectionPoliciesClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, vaultName string, resourceGroupName string, policyName string, options *armrecoveryservicesbackup.ProtectionPoliciesClientGetOptions) (armrecoveryservicesbackup.ProtectionPoliciesClientGetResponse, error)
	BeginDelete(ctx context.Context, vaultName string, resourceGroupName string, policyName string, options *armrecoveryservicesbackup.ProtectionPoliciesClientBeginDeleteOptions) (*runtime.Poller[armrecoveryservicesbackup.ProtectionPoliciesClientDeleteResponse], error)
}

// backupPoliciesListAPI is the discovery surface. It lives on a different SDK
// client from CRUD (BackupPoliciesClient, not ProtectionPoliciesClient) because
// ARM splits the collection GET onto its own operation group.
type backupPoliciesListAPI interface {
	NewListPager(vaultName string, resourceGroupName string, options *armrecoveryservicesbackup.BackupPoliciesClientListOptions) *runtime.Pager[armrecoveryservicesbackup.BackupPoliciesClientListResponse]
}

// backupPolicyCore holds everything the two policy provisioners share.
type backupPolicyCore struct {
	api      backupProtectionPoliciesAPI
	listAPI  backupPoliciesListAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

// backupPolicyPropsBuilder renders a policy resource into schema properties.
type backupPolicyPropsBuilder func(policy *armrecoveryservicesbackup.ProtectionPolicyResource, rgName, vaultName string) map[string]any

func (c *backupPolicyCore) nativeID(rgName, vaultName, policyName string) string {
	return fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.RecoveryServices/vaults/%s/backupPolicies/%s",
		c.config.SubscriptionId, rgName, vaultName, policyName)
}

// write drives CreateOrUpdate for both Create and Update.
//
// When ARM answers 202 the response body is empty, so there is nothing to build
// properties from and no resume token either (the SDK does not model this call as
// an LRO). The operation is reported in progress with an empty resume token, which
// statusPolicy below reads as "poll by GET".
func (c *backupPolicyCore) write(ctx context.Context, operation resource.Operation, rgName, vaultName, policyName string,
	params armrecoveryservicesbackup.ProtectionPolicyResource, build backupPolicyPropsBuilder) (*resource.ProgressResult, error) {

	expectedNativeID := c.nativeID(rgName, vaultName, policyName)

	result, err := c.api.CreateOrUpdate(ctx, vaultName, rgName, policyName, params, nil)
	if err != nil {
		// No NativeID on a failed create: the policy may never have existed.
		// Update overwrites this with the id it already had.
		return &resource.ProgressResult{
			Operation:       operation,
			OperationStatus: resource.OperationStatusFailure,
			ErrorCode:       operationErrorCode(err),
			StatusMessage:   err.Error(),
		}, nil
	}

	if result.ID == nil {
		lroOp := lroOpCreate
		if operation == resource.OperationUpdate {
			lroOp = lroOpUpdate
		}
		reqIDJSON, err := encodeLROStart(lroOp, "", expectedNativeID)
		if err != nil {
			return nil, err
		}
		return &resource.ProgressResult{
			Operation:       operation,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       reqIDJSON,
			NativeID:        expectedNativeID,
		}, nil
	}

	propsJSON, err := json.Marshal(build(&result.ProtectionPolicyResource, rgName, vaultName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ProgressResult{
		Operation:          operation,
		OperationStatus:    resource.OperationStatusSuccess,
		NativeID:           *result.ID,
		ResourceProperties: propsJSON,
	}, nil
}

func (c *backupPolicyCore) read(ctx context.Context, resourceType, nativeID string, build backupPolicyPropsBuilder) (*resource.ReadResult, error) {
	rgName, vaultName, policyName, err := backupPolicyIDParts(nativeID)
	if err != nil {
		return nil, err
	}

	result, err := c.api.Get(ctx, vaultName, rgName, policyName, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(build(&result.ProtectionPolicyResource, rgName, vaultName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: resourceType,
		Properties:   string(propsJSON),
	}, nil
}

func (c *backupPolicyCore) delete(ctx context.Context, nativeID string) (*resource.DeleteResult, error) {
	rgName, vaultName, policyName, err := backupPolicyIDParts(nativeID)
	if err != nil {
		return nil, err
	}

	failure := func(err error) *resource.DeleteResult {
		return &resource.DeleteResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationDelete,
				OperationStatus: resource.OperationStatusFailure,
				NativeID:        nativeID,
				ErrorCode:       operationErrorCode(err),
				StatusMessage:   err.Error(),
			},
		}
	}
	success := &resource.DeleteResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationDelete,
			OperationStatus: resource.OperationStatusSuccess,
			NativeID:        nativeID,
		},
	}

	poller, err := c.api.BeginDelete(ctx, vaultName, rgName, policyName, nil)
	if err != nil {
		if isDeleteSuccessError(err) {
			return success, nil
		}
		return failure(err), nil
	}

	if poller.Done() {
		if _, err := poller.Result(ctx); err != nil && !isDeleteSuccessError(err) {
			return failure(err), nil
		}
		return success, nil
	}

	resumeToken, err := poller.ResumeToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get resume token: %w", err)
	}
	reqIDJSON, err := encodeLROStart(lroOpDelete, resumeToken, nativeID)
	if err != nil {
		return nil, err
	}
	return &resource.DeleteResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationDelete,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       reqIDJSON,
			NativeID:        nativeID,
		},
	}, nil
}

func (c *backupPolicyCore) status(ctx context.Context, request *resource.StatusRequest, build backupPolicyPropsBuilder) (*resource.StatusResult, error) {
	reqID, err := decodeLROStatus(request.RequestID)
	if err != nil {
		return nil, err
	}

	switch reqID.OperationType {
	case lroOpCreate, lroOpUpdate:
		operation := resource.OperationCreate
		if reqID.OperationType == lroOpUpdate {
			operation = resource.OperationUpdate
		}
		return c.pollByGet(ctx, request, &reqID, operation, build)
	case lroOpDelete:
		return statusDeleteLRO(ctx, request, &reqID,
			func(token string) (*runtime.Poller[armrecoveryservicesbackup.ProtectionPoliciesClientDeleteResponse], error) {
				return resumePoller[armrecoveryservicesbackup.ProtectionPoliciesClientDeleteResponse](c.pipeline, token)
			}, nil)
	default:
		return nil, fmt.Errorf("unknown operation type: %s", reqID.OperationType)
	}
}

// pollByGet completes an asynchronous CreateOrUpdate by reading the policy back.
// A 404 means ARM has not committed it yet, which is still in progress.
func (c *backupPolicyCore) pollByGet(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID,
	operation resource.Operation, build backupPolicyPropsBuilder) (*resource.StatusResult, error) {

	rgName, vaultName, policyName, err := backupPolicyIDParts(reqID.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := c.api.Get(ctx, vaultName, rgName, policyName, nil)
	if err != nil {
		if operationErrorCode(err) == resource.OperationErrorCodeNotFound {
			return lroInProgress(operation, request.RequestID, reqID.NativeID), nil
		}
		return lroFailure(operation, request.RequestID, operationErrorCode(err), err.Error()), nil
	}

	propsJSON, err := json.Marshal(build(&result.ProtectionPolicyResource, rgName, vaultName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return lroSuccess(operation, request.RequestID, reqID.NativeID, propsJSON), nil
}

// list enumerates the vault's policies and keeps only those whose polymorphic
// properties match this resource type.
//
// The server-side OData filter narrows to a backup management type, but a
// management type still covers several policy shapes (an AzureStorage vault also
// carries the built-in hourly log policy), so `matches` does the final cut.
func (c *backupPolicyCore) list(ctx context.Context, request *resource.ListRequest, backupManagementType string,
	matches func(armrecoveryservicesbackup.ProtectionPolicyClassification) bool) (*resource.ListResult, error) {

	vaultName := request.AdditionalProperties["vaultName"]
	rgName := request.AdditionalProperties["resourceGroupName"]
	if vaultName == "" || rgName == "" {
		return nil, fmt.Errorf("vaultName and resourceGroupName are required to list backup policies")
	}

	filter := "backupManagementType eq '" + backupManagementType + "'"
	pager := c.listAPI.NewListPager(vaultName, rgName, &armrecoveryservicesbackup.BackupPoliciesClientListOptions{
		Filter: &filter,
	})

	var nativeIDs []string
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list backup policies: %w", err)
		}
		for _, policy := range page.Value {
			if policy == nil || policy.ID == nil {
				continue
			}
			if !matches(policy.Properties) {
				continue
			}
			nativeIDs = append(nativeIDs, *policy.ID)
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
