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
// Azure ARM IDs are stable and can be reused after a resource is destroyed and
// recreated. Formae needs each resource instance to be unique across its
// lifetime, so we wrap the ARM ID with a KSUID to guarantee uniqueness even
// when the same ARM ID appears again after a destroy/recreate cycle.
//
// This package is the single source of truth for encoding and decoding;
// plugin.go encodes outbound results and decodes inbound requests at the
// boundary so that provisioners only ever see raw ARM IDs.
type NativeID string

// Encode wraps a raw ARM ID with a unique KSUID.
// Returns empty NativeID for empty input.
func Encode(armID string) NativeID {
	if armID == "" {
		return ""
	}
	return NativeID(fmt.Sprintf("azure:v1:%s:%s", ksuid.New().String(), armID))
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
