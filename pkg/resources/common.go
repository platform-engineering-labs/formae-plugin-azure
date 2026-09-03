// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"

	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
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

// operationErrorCode maps provider errors to Formae operation error codes.
func operationErrorCode(err error) resource.OperationErrorCode {
	return prov.OperationErrorCode(err)
}

// stringPtr returns a pointer to a string. Useful for Azure SDK calls.
func stringPtr(s string) *string {
	return &s
}

// isDeleteSuccessError returns true if the error indicates the resource is already deleted.
// For delete operations, NotFound means the goal is achieved (resource doesn't exist).
// This ensures delete operations are idempotent.
func isDeleteSuccessError(err error) bool {
	return prov.IsDeleteSuccessError(err)
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

// metadataFromProperties reads the entity-set shaped `metadata` list
// (`[{Key,Value}, ...]`) used by storage child resources back into the flat
// map[string]*string that ARM expects. Returns nil when there is nothing to send.
//
// Shared by AZURE::Storage::Queue and AZURE::Storage::FileShare; kept here rather
// than duplicated per resource.
func metadataFromProperties(props map[string]any) map[string]*string {
	raw, ok := props["metadata"].([]any)
	if !ok || len(raw) == 0 {
		return nil
	}
	out := make(map[string]*string, len(raw))
	for _, entry := range raw {
		m, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		key, _ := m["Key"].(string)
		value, _ := m["Value"].(string)
		if key == "" {
			continue
		}
		v := value
		out[key] = &v
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// stringPointers converts a slice of strings into the pointer slice the Azure SDK
// models use. Returns nil for an empty input, so an unset list is omitted from the
// request body rather than sent as an empty array.
func stringPointers(values []string) []*string {
	if len(values) == 0 {
		return nil
	}
	out := make([]*string, 0, len(values))
	for _, value := range values {
		out = append(out, to.Ptr(value))
	}
	return out
}

// stringsFromPointers is the read-path inverse of stringPointers. Nil entries are
// skipped, and an empty result comes back as nil so a list ARM echoes back empty does
// not read as a declared-but-empty list.
func stringsFromPointers(values []*string) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value == nil {
			continue
		}
		out = append(out, *value)
	}
	return out
}

// canonicalizeEnum maps a service-returned enum value onto the casing the SDK and
// PKL schema use.
//
// Services are inconsistent here: some return capitalized values ("Enabled",
// "Default") where the SDK constants and the ARM request body use lowercase, and
// some return a lower-cased path segment where desired state carries the enum's own
// casing. Echoing the service casing straight through breaks two things: conformance
// [Verify] compares desired "enabled" against actual "Enabled", and `formae extract`
// fails to render the PKL union at all. A blanket strings.ToLower is wrong because
// some values are mixed-case ("highDensity", "storage_optimized_l1"), so match
// case-insensitively against the known set and emit its canonical form. An
// unrecognised value passes through untouched rather than being mangled.
func canonicalizeEnum(value string, allowed ...string) string {
	for _, a := range allowed {
		if strings.EqualFold(value, a) {
			return a
		}
	}
	return value
}

// normalizeAzureLocation folds a region name to the form desired state uses.
//
// ARM accepts "eastus" on the way in and hands back "East US" on the way out, so a
// read that passes the response through verbatim reports drift on every sync against
// a fixture that wrote the compact form. Regions are the one enum-ish field where
// case and spacing vary per response rather than per service, which is why this is
// not folded into canonicalizeEnum.
func normalizeAzureLocation(loc string) string {
	return strings.ToLower(strings.ReplaceAll(loc, " ", ""))
}
