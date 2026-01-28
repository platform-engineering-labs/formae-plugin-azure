// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"strings"

	"github.com/platform-engineering-labs/formae/pkg/model"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

// azureTagsToFormaeTags converts Azure SDK tags map to Formae Tag format.
// Returns nil if the input map is empty.
func azureTagsToFormaeTags(azureTags map[string]*string) []map[string]string {
	if len(azureTags) == 0 {
		return nil
	}
	tags := make([]map[string]string, 0, len(azureTags))
	for k, v := range azureTags {
		if v != nil {
			tags = append(tags, map[string]string{
				"Key":   k,
				"Value": *v,
			})
		}
	}
	return tags
}

// formaeTagsToAzureTags converts Formae tags from resource properties to Azure SDK format.
// Extracts tags using model.GetTagsFromProperties and converts to map[string]*string.
// Returns nil if no tags are present.
func formaeTagsToAzureTags(properties []byte) map[string]*string {
	tags := model.GetTagsFromProperties(properties)
	if len(tags) == 0 {
		return nil
	}
	azureTags := make(map[string]*string)
	for _, tag := range tags {
		val := tag.Value
		azureTags[tag.Key] = &val
	}
	return azureTags
}

// splitResourceID splits an Azure resource ID into its component parts.
// Example: /subscriptions/xxx/resourceGroups/yyy returns map["subscriptions"]="xxx", map["resourcegroups"]="yyy"
// For nested resources: /subscriptions/xxx/resourceGroups/yyy/providers/Microsoft.Network/virtualNetworks/zzz
// returns map["subscriptions"]="xxx", map["resourcegroups"]="yyy", map["virtualnetworks"]="zzz"
// Note: Keys are lowercased for case-insensitive matching since Azure returns inconsistent casing.
func splitResourceID(resourceID string) map[string]string {
	parts := make(map[string]string)

	// Split by / and filter out empty strings
	segments := []string{}
	for _, seg := range strings.Split(resourceID, "/") {
		if seg != "" {
			segments = append(segments, seg)
		}
	}

	// Pair up key-value segments, lowercase the keys for consistent matching
	for i := 0; i < len(segments)-1; i += 2 {
		parts[strings.ToLower(segments[i])] = segments[i+1]
	}

	return parts
}

// mapAzureErrorToOperationErrorCode maps Azure SDK errors to OperationErrorCode.
// This allows the PluginOperator to handle errors in an operation-aware context.
func mapAzureErrorToOperationErrorCode(err error) resource.OperationErrorCode {
	if err == nil {
		return ""
	}

	errStr := err.Error()

	// Map common Azure error patterns to operation error codes
	switch {
	// 404 Not Found errors
	case strings.Contains(errStr, "ResourceGroupNotFound"),
		strings.Contains(errStr, "ResourceNotFound"),
		strings.Contains(errStr, "NotFound"),
		strings.Contains(errStr, "404"):
		return resource.OperationErrorCodeNotFound

	// 403 Forbidden / Access Denied
	case strings.Contains(errStr, "AuthorizationFailed"),
		strings.Contains(errStr, "Forbidden"),
		strings.Contains(errStr, "403"):
		return resource.OperationErrorCodeAccessDenied

	// 401 Unauthorized / Invalid Credentials
	case strings.Contains(errStr, "Unauthorized"),
		strings.Contains(errStr, "AuthenticationFailed"),
		strings.Contains(errStr, "InvalidAuthenticationToken"),
		strings.Contains(errStr, "401"):
		return resource.OperationErrorCodeInvalidCredentials

	// 409 Conflict
	case strings.Contains(errStr, "Conflict"),
		strings.Contains(errStr, "ResourceExists"),
		strings.Contains(errStr, "409"):
		return resource.OperationErrorCodeResourceConflict

	// 429 Throttling
	case strings.Contains(errStr, "TooManyRequests"),
		strings.Contains(errStr, "Throttling"),
		strings.Contains(errStr, "429"):
		return resource.OperationErrorCodeThrottling

	// 500 Internal Server Error
	case strings.Contains(errStr, "InternalServerError"),
		strings.Contains(errStr, "500"):
		return resource.OperationErrorCodeServiceInternalError

	// Timeout errors
	case strings.Contains(errStr, "Timeout"),
		strings.Contains(errStr, "RequestTimeout"),
		strings.Contains(errStr, "GatewayTimeout"):
		return resource.OperationErrorCodeServiceTimeout

	// Service limit/quota exceeded
	case strings.Contains(errStr, "QuotaExceeded"),
		strings.Contains(errStr, "LimitExceeded"):
		return resource.OperationErrorCodeServiceLimitExceeded

	// Invalid request
	case strings.Contains(errStr, "InvalidParameter"),
		strings.Contains(errStr, "InvalidRequest"),
		strings.Contains(errStr, "BadRequest"),
		strings.Contains(errStr, "400"):
		return resource.OperationErrorCodeInvalidRequest

	// Network failures
	case strings.Contains(errStr, "connection refused"),
		strings.Contains(errStr, "network"),
		strings.Contains(errStr, "dial"):
		return resource.OperationErrorCodeNetworkFailure

	// Default to general service exception for unknown errors
	default:
		return resource.OperationErrorCodeGeneralServiceException
	}
}

// stringPtr returns a pointer to a string. Useful for Azure SDK calls.
func stringPtr(s string) *string {
	return &s
}

// isDeleteSuccessError returns true if the error indicates the resource is already deleted.
// For delete operations, NotFound means the goal is achieved (resource doesn't exist).
// This ensures delete operations are idempotent.
func isDeleteSuccessError(err error) bool {
	if err == nil {
		return false
	}
	return mapAzureErrorToOperationErrorCode(err) == resource.OperationErrorCodeNotFound
}
