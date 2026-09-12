// © 2026 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build integration

package resources

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/apimanagement/armapimanagement"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

// Exercise the real SDK request serialization and response decoding. The endpoint
// models PATCH retaining omitted properties, and replacing a supplied tags array.
func TestNamedValueTagsClearWireAndReadback(t *testing.T) {
	for _, tc := range []struct {
		name, desired, patch string
		want                 []string
		send                 bool
	}{
		{"last_member", `{"tags":[]}`, `[{"op":"remove","path":"/tags/0"}]`, []string{}, true},
		{"whole_field", `{}`, `[{"op":"remove","path":"/tags"}]`, []string{}, true},
		{"replace_empty", `{"tags":[]}`, `[{"op":"replace","path":"/tags","value":[]}]`, []string{}, true},
		{"partial_remove", `{"tags":["keep"]}`, `[{"op":"remove","path":"/tags/0"}]`, []string{"keep"}, true},
		{"unrelated", `{}`, `[{"op":"replace","path":"/displayName","value":"new"}]`, []string{"old", "keep"}, false},
		{"implicit_empty", `{"tags":[]}`, ``, []string{"old", "keep"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state := []string{"old", "keep"}
			if tc.name == "last_member" {
				state = []string{"old"}
			}
			patchCount, getCount := 0, 0
			transport := metadataTransport(func(r *http.Request) (*http.Response, error) {
				switch r.Method {
				case http.MethodPatch:
					patchCount++
					require.Equal(t, "*", r.Header.Get("If-Match"))
					var payload struct {
						Properties map[string]json.RawMessage `json:"properties"`
					}
					require.NoError(t, json.NewDecoder(r.Body).Decode(&payload))
					raw, present := payload.Properties["tags"]
					require.Equal(t, tc.send, present, "explicit clear must reach SDK wire body")
					if present {
						require.NotEqual(t, "null", string(raw))
						require.NoError(t, json.Unmarshal(raw, &state))
					}
				case http.MethodGet:
					getCount++
				default:
					t.Fatalf("unexpected request %s", r.Method)
				}
				body, err := json.Marshal(map[string]any{"id": testApimNamedValueNativeID, "name": "backend-url", "properties": map[string]any{"displayName": "backend-url", "tags": state, "provisioningState": "Succeeded"}})
				require.NoError(t, err)
				return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(string(body))), Request: r}, nil
			})
			client, err := armapimanagement.NewNamedValueClient("sub-1", metadataCredential{}, &arm.ClientOptions{ClientOptions: policy.ClientOptions{Transport: transport}, DisableRPRegistration: true})
			require.NoError(t, err)
			prov := newTestApiManagementNamedValue(client)
			req := &resource.UpdateRequest{NativeID: testApimNamedValueNativeID, DesiredProperties: json.RawMessage(tc.desired)}
			if tc.patch != "" {
				req.PatchDocument = to.Ptr(tc.patch)
			}
			result, err := prov.Update(context.Background(), req)
			require.NoError(t, err)
			require.Equal(t, resource.OperationStatusSuccess, result.ProgressResult.OperationStatus)
			got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testApimNamedValueNativeID})
			require.NoError(t, err)
			var props struct {
				Tags []string `json:"tags"`
			}
			require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
			require.ElementsMatch(t, tc.want, props.Tags)
			require.Equal(t, 1, patchCount)
			require.GreaterOrEqual(t, getCount, 1)
		})
	}
}
