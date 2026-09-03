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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armlocks"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeManagementLock = "AZURE::Authorization::ManagementLock"

// managementLocksAPI is the subset of *armlocks.ManagementLocksClient used here.
// Everything is synchronous and CreateOrUpdate is also the update verb.
//
// The `*ByScope` verbs would collapse all three of these triples into one, and that
// is what every other scope-addressed resource in this plugin uses. They are
// UNUSABLE here: armlocks v1.2.0 builds their URL with
// `url.PathEscape(scope)` — unlike armpolicy and armpolicyinsights, which
// interpolate the scope raw — so every slash in the scope is sent as %2F and ARM
// gets `/%2Fsubscriptions%2F.../providers/Microsoft.Authorization/locks/x`, which
// routes nowhere. Verified against the generated request:
//
//	https://management.azure.com/%2Fsubscriptions%2Fsub-1%2FresourceGroups%2Frg-1/providers/Microsoft.Authorization/locks/lock1
//
// The level-specific verbs below interpolate parentResourcePath and resourceType
// raw and escape only single path segments, so their URLs are correct. Hence the
// scope is parsed apart here and dispatched to the matching triple.
type managementLocksAPI interface {
	CreateOrUpdateAtSubscriptionLevel(ctx context.Context, lockName string, parameters armlocks.ManagementLockObject, options *armlocks.ManagementLocksClientCreateOrUpdateAtSubscriptionLevelOptions) (armlocks.ManagementLocksClientCreateOrUpdateAtSubscriptionLevelResponse, error)
	CreateOrUpdateAtResourceGroupLevel(ctx context.Context, resourceGroupName string, lockName string, parameters armlocks.ManagementLockObject, options *armlocks.ManagementLocksClientCreateOrUpdateAtResourceGroupLevelOptions) (armlocks.ManagementLocksClientCreateOrUpdateAtResourceGroupLevelResponse, error)
	CreateOrUpdateAtResourceLevel(ctx context.Context, resourceGroupName, resourceProviderNamespace, parentResourcePath, resourceType, resourceName, lockName string, parameters armlocks.ManagementLockObject, options *armlocks.ManagementLocksClientCreateOrUpdateAtResourceLevelOptions) (armlocks.ManagementLocksClientCreateOrUpdateAtResourceLevelResponse, error)

	GetAtSubscriptionLevel(ctx context.Context, lockName string, options *armlocks.ManagementLocksClientGetAtSubscriptionLevelOptions) (armlocks.ManagementLocksClientGetAtSubscriptionLevelResponse, error)
	GetAtResourceGroupLevel(ctx context.Context, resourceGroupName string, lockName string, options *armlocks.ManagementLocksClientGetAtResourceGroupLevelOptions) (armlocks.ManagementLocksClientGetAtResourceGroupLevelResponse, error)
	GetAtResourceLevel(ctx context.Context, resourceGroupName, resourceProviderNamespace, parentResourcePath, resourceType, resourceName, lockName string, options *armlocks.ManagementLocksClientGetAtResourceLevelOptions) (armlocks.ManagementLocksClientGetAtResourceLevelResponse, error)

	DeleteAtSubscriptionLevel(ctx context.Context, lockName string, options *armlocks.ManagementLocksClientDeleteAtSubscriptionLevelOptions) (armlocks.ManagementLocksClientDeleteAtSubscriptionLevelResponse, error)
	DeleteAtResourceGroupLevel(ctx context.Context, resourceGroupName string, lockName string, options *armlocks.ManagementLocksClientDeleteAtResourceGroupLevelOptions) (armlocks.ManagementLocksClientDeleteAtResourceGroupLevelResponse, error)
	DeleteAtResourceLevel(ctx context.Context, resourceGroupName, resourceProviderNamespace, parentResourcePath, resourceType, resourceName, lockName string, options *armlocks.ManagementLocksClientDeleteAtResourceLevelOptions) (armlocks.ManagementLocksClientDeleteAtResourceLevelResponse, error)

	NewListAtSubscriptionLevelPager(options *armlocks.ManagementLocksClientListAtSubscriptionLevelOptions) *runtime.Pager[armlocks.ManagementLocksClientListAtSubscriptionLevelResponse]
	NewListAtResourceGroupLevelPager(resourceGroupName string, options *armlocks.ManagementLocksClientListAtResourceGroupLevelOptions) *runtime.Pager[armlocks.ManagementLocksClientListAtResourceGroupLevelResponse]
	NewListAtResourceLevelPager(resourceGroupName, resourceProviderNamespace, parentResourcePath, resourceType, resourceName string, options *armlocks.ManagementLocksClientListAtResourceLevelOptions) *runtime.Pager[armlocks.ManagementLocksClientListAtResourceLevelResponse]
}

func init() {
	registry.Register(ResourceTypeManagementLock, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &ManagementLock{api: c.ManagementLocksClient, config: cfg}
	})
}

// ManagementLock is the provisioner for management locks
// (Microsoft.Authorization/locks).
type ManagementLock struct {
	api    managementLocksAPI
	config *config.Config
}

// managementLockProps mirrors schema/pkl/authorization/managementlock.pkl.
type managementLockProps struct {
	Name  string  `json:"name"`
	Scope string  `json:"scope"`
	Level string  `json:"level"`
	Notes *string `json:"notes"`
}

const managementLockSegment = "/providers/microsoft.authorization/locks/"

// managementLockIDParts splits a lock ID into the scope it protects and its name.
// The scope may be a subscription, a resource group or a single resource, so
// armIDParts does not apply.
func managementLockIDParts(resourceID string) (scope, name string, err error) {
	idx := strings.Index(strings.ToLower(resourceID), managementLockSegment)
	if idx < 0 {
		return "", "", fmt.Errorf("not a management lock resource ID: %s", resourceID)
	}
	scope = resourceID[:idx]
	name = resourceID[idx+len(managementLockSegment):]
	if scope == "" || name == "" || strings.Contains(name, "/") {
		return "", "", fmt.Errorf("not a management lock resource ID: %s", resourceID)
	}
	return scope, name, nil
}

// managementLockNativeID composes the lock's ARM ID from the scope the caller
// supplied rather than echoing the one ARM returns.
//
// ARM answers a resource-group-level lock PUT with an id spelled
// `/subscriptions/{id}/resourcegroups/{rg}/...` — lower-case `resourcegroups` —
// while every ID this plugin hands out elsewhere, and everything a user writes,
// spells it `resourceGroups`. Read derives `scope` back out of the native ID, so
// echoing ARM's casing would make the scope property differ from desired state on
// the very first sync. Composing it keeps the round trip exact.
func managementLockNativeID(scope, name string) string {
	return scope + "/providers/Microsoft.Authorization/locks/" + name
}

// lockScope is a lock scope decomposed into the arguments the level-specific SDK
// verbs take. See managementLocksAPI for why the ByScope verbs are not used.
type lockScope struct {
	// level is one of "subscription", "resourceGroup" or "resource".
	level              string
	subscriptionID     string
	resourceGroupName  string
	providerNamespace  string
	parentResourcePath string
	resourceType       string
	resourceName       string
}

const (
	lockLevelSubscription  = "subscription"
	lockLevelResourceGroup = "resourceGroup"
	lockLevelResource      = "resource"
)

// parseLockScope decomposes a lock scope.
//
// The client is bound to one subscription, so a scope naming a different one is
// rejected rather than silently written to the bound subscription — the
// level-specific verbs take the subscription from the client, not from the scope,
// which makes that mistake invisible otherwise.
func (m *ManagementLock) parseLockScope(scope string) (lockScope, error) {
	segments := strings.Split(strings.Trim(scope, "/"), "/")
	if len(segments) < 2 || !strings.EqualFold(segments[0], "subscriptions") {
		return lockScope{}, fmt.Errorf("scope must name a subscription, a resource group or a resource: %s", scope)
	}

	parsed := lockScope{subscriptionID: segments[1]}
	if m.config != nil && m.config.SubscriptionId != "" && !strings.EqualFold(parsed.subscriptionID, m.config.SubscriptionId) {
		return lockScope{}, fmt.Errorf("scope names subscription %s but this target is bound to %s", parsed.subscriptionID, m.config.SubscriptionId)
	}

	switch {
	case len(segments) == 2:
		parsed.level = lockLevelSubscription
		return parsed, nil
	case len(segments) == 4 && strings.EqualFold(segments[2], "resourceGroups"):
		parsed.level = lockLevelResourceGroup
		parsed.resourceGroupName = segments[3]
		return parsed, nil
	}

	if len(segments) < 8 || !strings.EqualFold(segments[2], "resourceGroups") || !strings.EqualFold(segments[4], "providers") {
		return lockScope{}, fmt.Errorf("scope must name a subscription, a resource group or a resource: %s", scope)
	}

	parsed.level = lockLevelResource
	parsed.resourceGroupName = segments[3]
	parsed.providerNamespace = segments[5]

	// Everything after the provider namespace is type/name pairs. The leaf pair is
	// resourceType/resourceName; anything before it is the parentResourcePath, which
	// ARM takes as a raw path segment (e.g. "servers/my-server" for a SQL database).
	rest := segments[6:]
	if len(rest)%2 != 0 {
		return lockScope{}, fmt.Errorf("scope is not a well-formed resource ID: %s", scope)
	}
	parsed.resourceType = rest[len(rest)-2]
	parsed.resourceName = rest[len(rest)-1]
	parsed.parentResourcePath = strings.Join(rest[:len(rest)-2], "/")
	return parsed, nil
}

func managementLockParams(props managementLockProps) armlocks.ManagementLockObject {
	lock := armlocks.ManagementLockObject{
		Properties: &armlocks.ManagementLockProperties{
			Level: to.Ptr(armlocks.LockLevel(props.Level)),
		},
	}
	if props.Notes != nil && *props.Notes != "" {
		lock.Properties.Notes = props.Notes
	}
	return lock
}

func managementLockProperties(lock *armlocks.ManagementLockObject, scope, name string) map[string]any {
	props := map[string]any{
		"scope": scope,
		"name":  name,
		"id":    managementLockNativeID(scope, name),
	}
	if lock == nil || lock.Properties == nil {
		return props
	}
	if lock.Properties.Level != nil {
		props["level"] = canonicalizeEnum(string(*lock.Properties.Level), "CanNotDelete", "ReadOnly", "NotSpecified")
	}
	if lock.Properties.Notes != nil && *lock.Properties.Notes != "" {
		props["notes"] = *lock.Properties.Notes
	}
	// owners is unmodelled: ARM accepts it and never acts on it. systemData is the
	// service's own view. Neither is read back.
	return props
}

func (m *ManagementLock) parseProps(payload json.RawMessage, label string) (managementLockProps, string, error) {
	var props managementLockProps
	if err := json.Unmarshal(payload, &props); err != nil {
		return props, "", fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.Scope == "" {
		return props, "", fmt.Errorf("scope is required")
	}
	if props.Level == "" {
		return props, "", fmt.Errorf("level is required")
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

// put issues the CreateOrUpdate matching the scope's level.
func (m *ManagementLock) put(ctx context.Context, scope lockScope, name string, params armlocks.ManagementLockObject) (*armlocks.ManagementLockObject, error) {
	switch scope.level {
	case lockLevelSubscription:
		result, err := m.api.CreateOrUpdateAtSubscriptionLevel(ctx, name, params, nil)
		if err != nil {
			return nil, err
		}
		return &result.ManagementLockObject, nil
	case lockLevelResourceGroup:
		result, err := m.api.CreateOrUpdateAtResourceGroupLevel(ctx, scope.resourceGroupName, name, params, nil)
		if err != nil {
			return nil, err
		}
		return &result.ManagementLockObject, nil
	default:
		result, err := m.api.CreateOrUpdateAtResourceLevel(ctx, scope.resourceGroupName, scope.providerNamespace,
			scope.parentResourcePath, scope.resourceType, scope.resourceName, name, params, nil)
		if err != nil {
			return nil, err
		}
		return &result.ManagementLockObject, nil
	}
}

// get issues the Get matching the scope's level.
func (m *ManagementLock) get(ctx context.Context, scope lockScope, name string) (*armlocks.ManagementLockObject, error) {
	switch scope.level {
	case lockLevelSubscription:
		result, err := m.api.GetAtSubscriptionLevel(ctx, name, nil)
		if err != nil {
			return nil, err
		}
		return &result.ManagementLockObject, nil
	case lockLevelResourceGroup:
		result, err := m.api.GetAtResourceGroupLevel(ctx, scope.resourceGroupName, name, nil)
		if err != nil {
			return nil, err
		}
		return &result.ManagementLockObject, nil
	default:
		result, err := m.api.GetAtResourceLevel(ctx, scope.resourceGroupName, scope.providerNamespace,
			scope.parentResourcePath, scope.resourceType, scope.resourceName, name, nil)
		if err != nil {
			return nil, err
		}
		return &result.ManagementLockObject, nil
	}
}

// remove issues the Delete matching the scope's level.
func (m *ManagementLock) remove(ctx context.Context, scope lockScope, name string) error {
	switch scope.level {
	case lockLevelSubscription:
		_, err := m.api.DeleteAtSubscriptionLevel(ctx, name, nil)
		return err
	case lockLevelResourceGroup:
		_, err := m.api.DeleteAtResourceGroupLevel(ctx, scope.resourceGroupName, name, nil)
		return err
	default:
		_, err := m.api.DeleteAtResourceLevel(ctx, scope.resourceGroupName, scope.providerNamespace,
			scope.parentResourcePath, scope.resourceType, scope.resourceName, name, nil)
		return err
	}
}

func (m *ManagementLock) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	props, name, err := m.parseProps(request.Properties, request.Label)
	if err != nil {
		return nil, err
	}
	scope, err := m.parseLockScope(props.Scope)
	if err != nil {
		return nil, err
	}

	lock, err := m.put(ctx, scope, name, managementLockParams(props))
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

	propsJSON, err := json.Marshal(managementLockProperties(lock, props.Scope, name))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.CreateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:          resource.OperationCreate,
			OperationStatus:    resource.OperationStatusSuccess,
			NativeID:           managementLockNativeID(props.Scope, name),
			ResourceProperties: propsJSON,
		},
	}, nil
}

func (m *ManagementLock) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	scopeStr, name, err := managementLockIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}
	scope, err := m.parseLockScope(scopeStr)
	if err != nil {
		return nil, err
	}

	lock, err := m.get(ctx, scope, name)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(managementLockProperties(lock, scopeStr, name))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeManagementLock,
		Properties:   string(propsJSON),
	}, nil
}

// Update reissues CreateOrUpdate: it is the API's only write verb. Scope and name
// are createOnly, so only level and notes can move.
func (m *ManagementLock) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	scopeStr, name, err := managementLockIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}
	scope, err := m.parseLockScope(scopeStr)
	if err != nil {
		return nil, err
	}

	props, _, err := m.parseProps(request.DesiredProperties, name)
	if err != nil {
		return nil, err
	}

	lock, err := m.put(ctx, scope, name, managementLockParams(props))
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

	propsJSON, err := json.Marshal(managementLockProperties(lock, scopeStr, name))
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

// managementLockDeleteVerifyAttempts and managementLockDeleteVerifyDelay bound the
// read-back that confirms the lock is really gone. ARM's DELETE is synchronous, so
// one confirming GET is normally enough; the retries only cover the seconds of
// read-after-write lag the locks endpoint occasionally shows.
const (
	managementLockDeleteVerifyAttempts = 6
	managementLockDeleteVerifyDelay    = 2 * time.Second
)

// Delete removes the lock and then CONFIRMS it is gone before reporting success.
//
// A lock that outlives its formae resource is the worst failure mode this type has:
// a CanNotDelete lock left behind makes the enclosing resource group undeletable
// for everyone, and formae would never retry a delete it was told succeeded. So a
// successful DELETE is not taken at its word — the lock is read back until it is
// NotFound, and anything else is reported as a failure with the reason attached.
func (m *ManagementLock) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	scopeStr, name, err := managementLockIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}
	scope, err := m.parseLockScope(scopeStr)
	if err != nil {
		return nil, err
	}

	failure := func(code resource.OperationErrorCode, message string) *resource.DeleteResult {
		return &resource.DeleteResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationDelete,
				OperationStatus: resource.OperationStatusFailure,
				NativeID:        request.NativeID,
				ErrorCode:       code,
				StatusMessage:   message,
			},
		}
	}

	if err := m.remove(ctx, scope, name); err != nil && !isDeleteSuccessError(err) {
		return failure(operationErrorCode(err), err.Error()), nil
	}

	var lastErr error
	for attempt := 0; attempt < managementLockDeleteVerifyAttempts; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				if lastErr != nil {
					return failure(resource.OperationErrorCodeGeneralServiceException,
						fmt.Sprintf("%v (gave up waiting: %v)", lastErr, ctx.Err())), nil
				}
				return failure(resource.OperationErrorCodeGeneralServiceException, ctx.Err().Error()), nil
			case <-time.After(managementLockDeleteVerifyDelay):
			}
		}
		_, err := m.get(ctx, scope, name)
		if err == nil {
			lastErr = fmt.Errorf("lock %s still exists at %s after delete", name, scopeStr)
			continue
		}
		if operationErrorCode(err) == resource.OperationErrorCodeNotFound {
			return &resource.DeleteResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationDelete,
					OperationStatus: resource.OperationStatusSuccess,
					NativeID:        request.NativeID,
				},
			}, nil
		}
		// The delete itself was accepted; a read-back that fails for any other reason
		// leaves the lock's fate unknown, which must not be reported as success.
		lastErr = fmt.Errorf("could not confirm lock %s was deleted: %w", name, err)
	}

	return failure(resource.OperationErrorCodeGeneralServiceException, lastErr.Error()), nil
}

// Status can only ever be asked about an operation that already finished: every
// write here is synchronous.
func (m *ManagementLock) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

// List enumerates locks at the scope it is given, and across the subscription when
// it is given none. The subscription-level pager returns locks at every scope
// beneath it too, so discovery without a scope still sees resource-level locks.
func (m *ManagementLock) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	if scopeStr := request.AdditionalProperties["scope"]; scopeStr != "" {
		scope, err := m.parseLockScope(scopeStr)
		if err != nil {
			return nil, err
		}
		switch scope.level {
		case lockLevelResourceGroup:
			return drainLockPager(ctx, m.api.NewListAtResourceGroupLevelPager(scope.resourceGroupName, nil),
				func(page armlocks.ManagementLocksClientListAtResourceGroupLevelResponse) []*armlocks.ManagementLockObject {
					return page.Value
				})
		case lockLevelResource:
			return drainLockPager(ctx, m.api.NewListAtResourceLevelPager(scope.resourceGroupName, scope.providerNamespace,
				scope.parentResourcePath, scope.resourceType, scope.resourceName, nil),
				func(page armlocks.ManagementLocksClientListAtResourceLevelResponse) []*armlocks.ManagementLockObject {
					return page.Value
				})
		}
	}

	return drainLockPager(ctx, m.api.NewListAtSubscriptionLevelPager(nil),
		func(page armlocks.ManagementLocksClientListAtSubscriptionLevelResponse) []*armlocks.ManagementLockObject {
			return page.Value
		})
}

// drainLockPager collects the IDs from any of the level-specific lock pagers. They
// differ only in the response type wrapping the same list, so one generic drain
// with a per-pager accessor covers all three.
func drainLockPager[T any](ctx context.Context, pager *runtime.Pager[T], values func(T) []*armlocks.ManagementLockObject) (*resource.ListResult, error) {
	var nativeIDs []string
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list management locks: %w", err)
		}
		for _, lock := range values(page) {
			if lock != nil && lock.ID != nil {
				nativeIDs = append(nativeIDs, *lock.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
