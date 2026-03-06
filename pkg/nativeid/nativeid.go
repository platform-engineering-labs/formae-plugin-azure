// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package nativeid

import (
	"fmt"
	"strings"

	"github.com/segmentio/ksuid"
)

// NativeID is an encoded Azure resource identifier.
// Format: azure:v1:{ksuid}:{armID}
//
// New resources no longer use KSUID encoding — the plugin returns raw ARM IDs
// directly. Formae's datastore handles resource reincarnations through its
// versioning system, and raw ARM IDs are required for discovery deduplication
// (List returns raw ARM IDs that must match NativeIDs in the datastore).
//
// This type and ArmID() are retained for backwards compatibility: existing
// datastores may contain KSUID-wrapped NativeIDs from before this change.
// ArmID() safely extracts the raw ARM ID from both wrapped and unwrapped forms.
type NativeID string

// Encode wraps a raw ARM ID with a unique KSUID.
// No longer used in plugin.go but retained for tests.
// Returns empty NativeID for empty input.
func Encode(armID string) NativeID {
	if armID == "" {
		return ""
	}
	return NativeID(fmt.Sprintf("azure:v1:%s:%s", ksuid.New().String(), armID))
}

// ReEncode replaces the ARM ID portion of an existing encoded NativeID,
// preserving the original KSUID. Use this for Update/Delete/Status where the
// resource identity must remain stable. Falls back to Encode if the original
// is not in the expected format.
func ReEncode(original string, armID string) NativeID {
	if armID == "" {
		return ""
	}
	if strings.HasPrefix(original, "azure:v1:") {
		if parts := strings.SplitN(original, ":", 4); len(parts) == 4 {
			return NativeID(fmt.Sprintf("azure:v1:%s:%s", parts[2], armID))
		}
	}
	return Encode(armID)
}

// ArmID extracts the raw Azure ARM ID.
// Returns the original string if not encoded (backwards compat).
func (n NativeID) ArmID() string {
	s := string(n)
	if strings.HasPrefix(s, "azure:v1:") {
		if parts := strings.SplitN(s, ":", 4); len(parts) == 4 {
			return parts[3]
		}
	}
	return s
}

// String returns the encoded NativeID string.
func (n NativeID) String() string {
	return string(n)
}
