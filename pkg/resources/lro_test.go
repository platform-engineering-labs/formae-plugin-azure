// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build unit

package resources

import (
	"encoding/json"
	"testing"
)

// TestLRORequestIDJSONShape locks the wire shape of lroRequestID. The encoded
// JSON is persisted in the formae datastore — any drift here orphans in-flight
// LRO operations across an upgrade.
func TestLRORequestIDJSONShape(t *testing.T) {
	cases := []struct {
		name string
		in   lroRequestID
		want string
	}{
		{
			name: "all fields populated",
			in:   lroRequestID{OperationType: "create", ResumeToken: "tok-abc", NativeID: "/subscriptions/x/resourceGroups/y/providers/Microsoft.Network/virtualNetworks/z"},
			want: `{"operationType":"create","resumeToken":"tok-abc","nativeID":"/subscriptions/x/resourceGroups/y/providers/Microsoft.Network/virtualNetworks/z"}`,
		},
		{
			name: "nativeID omitted when empty",
			in:   lroRequestID{OperationType: "delete", ResumeToken: "tok-xyz"},
			want: `{"operationType":"delete","resumeToken":"tok-xyz"}`,
		},
		{
			name: "update with nativeID",
			in:   lroRequestID{OperationType: "update", ResumeToken: "tok-123", NativeID: "/sub/foo"},
			want: `{"operationType":"update","resumeToken":"tok-123","nativeID":"/sub/foo"}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := json.Marshal(tc.in)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if string(got) != tc.want {
				t.Errorf("JSON shape drift\n  got:  %s\n  want: %s", got, tc.want)
			}
		})
	}
}

func TestEncodeDecodeLRORoundTrip(t *testing.T) {
	cases := []lroRequestID{
		{OperationType: "create", ResumeToken: "abc", NativeID: "/sub/x"},
		{OperationType: "update", ResumeToken: "def", NativeID: "/sub/y"},
		{OperationType: "delete", ResumeToken: "ghi", NativeID: ""},
	}
	for _, want := range cases {
		t.Run(want.OperationType, func(t *testing.T) {
			encoded, err := encodeLROStart(want.OperationType, want.ResumeToken, want.NativeID)
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			got, err := decodeLROStatus(encoded)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if got != want {
				t.Errorf("round-trip mismatch\n  got:  %+v\n  want: %+v", got, want)
			}
		})
	}
}

// TestDecodeLROStatusBackwardCompat verifies decoder still accepts JSON
// produced by the pre-Wave-0 inline marshaling in virtualnetwork.go etc.
func TestDecodeLROStatusBackwardCompat(t *testing.T) {
	// This is the exact shape produced by `json.Marshal(lroRequestID{...})`
	// in virtualnetwork.go before the Wave 0 extraction. In-flight LROs
	// persisted under the old code must decode under the new code.
	legacy := `{"operationType":"create","resumeToken":"legacy-token","nativeID":"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet"}`
	got, err := decodeLROStatus(legacy)
	if err != nil {
		t.Fatalf("decode legacy: %v", err)
	}
	if got.OperationType != "create" || got.ResumeToken != "legacy-token" || got.NativeID == "" {
		t.Errorf("legacy decode mismatch: %+v", got)
	}
}
