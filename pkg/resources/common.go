// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
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

// tag represents a key-value pair used for resource tagging.
type tag struct {
	Key   string
	Value string
}

// flexibleTags handles both slice and map JSON formats for tags.
type flexibleTags []tag

func (t *flexibleTags) UnmarshalJSON(data []byte) error {
	var tagsAsSlice []tag
	if err := json.Unmarshal(data, &tagsAsSlice); err == nil {
		*t = tagsAsSlice
		return nil
	}

	var tagsAsMap map[string]string
	if err := json.Unmarshal(data, &tagsAsMap); err == nil {
		var tags []tag
		for key, value := range tagsAsMap {
			tags = append(tags, tag{Key: key, Value: value})
		}
		*t = tags
		return nil
	}

	return fmt.Errorf("tags field is neither a slice of objects nor a map")
}

// getTagsFromProperties extracts tags from resource properties JSON.
// Handles both top-level Tags and nested Properties.Tags formats.
func getTagsFromProperties(payload json.RawMessage) []tag {
	if len(payload) == 0 {
		return nil
	}

	var topLevel struct {
		Tags flexibleTags `json:"Tags"`
	}
	if err := json.Unmarshal(payload, &topLevel); err == nil && len(topLevel.Tags) > 0 {
		return topLevel.Tags
	}

	var nested struct {
		Properties struct {
			Tags flexibleTags `json:"Tags"`
		} `json:"Properties"`
	}
	if err := json.Unmarshal(payload, &nested); err == nil && len(nested.Properties.Tags) > 0 {
		return nested.Properties.Tags
	}

	return nil
}

// formaeTagsToAzureTags converts Formae tags from resource properties to Azure SDK format.
// Returns nil if no tags are present.
func formaeTagsToAzureTags(properties []byte) map[string]*string {
	tags := getTagsFromProperties(properties)
	if len(tags) == 0 {
		return nil
	}
	azureTags := make(map[string]*string)
	for _, t := range tags {
		val := t.Value
		azureTags[t.Key] = &val
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
//
// It first checks for *azcore.ResponseError (the typed error from the Azure SDK)
// which reliably provides the HTTP status code. Falls back to string matching
// for non-HTTP errors (network failures, timeouts, etc.).
func mapAzureErrorToOperationErrorCode(err error) resource.OperationErrorCode {
	if err == nil {
		return ""
	}

	// Prefer typed error from Azure SDK — this is the most reliable way to
	// map HTTP responses since err.Error() may truncate the status code.
	var respErr *azcore.ResponseError
	if errors.As(err, &respErr) {
		switch respErr.StatusCode {
		case 400:
			return resource.OperationErrorCodeInvalidRequest
		case 401:
			return resource.OperationErrorCodeInvalidCredentials
		case 403:
			return resource.OperationErrorCodeAccessDenied
		case 404:
			return resource.OperationErrorCodeNotFound
		case 409:
			return resource.OperationErrorCodeResourceConflict
		case 429:
			return resource.OperationErrorCodeThrottling
		case 500:
			return resource.OperationErrorCodeServiceInternalError
		case 502, 503, 504:
			return resource.OperationErrorCodeServiceTimeout
		}
	}

	// Fall back to string matching for non-HTTP errors
	errStr := err.Error()

	switch {
	case strings.Contains(errStr, "Timeout"),
		strings.Contains(errStr, "RequestTimeout"),
		strings.Contains(errStr, "GatewayTimeout"):
		return resource.OperationErrorCodeServiceTimeout

	case strings.Contains(errStr, "QuotaExceeded"),
		strings.Contains(errStr, "LimitExceeded"):
		return resource.OperationErrorCodeServiceLimitExceeded

	case strings.Contains(errStr, "connection refused"),
		strings.Contains(errStr, "network"),
		strings.Contains(errStr, "dial"):
		return resource.OperationErrorCodeNetworkFailure

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

// parseTime tries common ISO 8601 formats for time strings from Pkl/JSON.
func parseTime(s string) (time.Time, error) {
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05Z", "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("cannot parse time: %s", s)
}
