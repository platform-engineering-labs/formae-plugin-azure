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
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

type metadataCredential struct{}

func (metadataCredential) GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{Token: "test", ExpiresOn: time.Now().Add(time.Hour)}, nil
}

type metadataTransport func(*http.Request) (*http.Response, error)

func (f metadataTransport) Do(r *http.Request) (*http.Response, error) { return f(r) }

type metadataProvisioner interface {
	Update(context.Context, *resource.UpdateRequest) (*resource.UpdateResult, error)
	Read(context.Context, *resource.ReadRequest) (*resource.ReadResult, error)
}

// Real SDK serialization and response decoding against an in-memory ARM endpoint.
// Omitted properties retain state; present metadata replaces the metadata map.
// This models the service contract; it is not a live Azure conformance test.
func TestStorageMetadataUpdateWireAndReadback(t *testing.T) {
	for _, kind := range []string{"blob", "share", "queue", "account-tags"} {
		t.Run(kind, func(t *testing.T) {
			for _, tc := range []struct {
				name, desired, patch string
				prior, want          map[string]string
				send                 bool
			}{
				{"root_replace", `{}`, `[{"op":"replace","path":"","value":{}}]`, map[string]string{"old": "value"}, map[string]string{}, true},
				{"null_with_remove", `{"metadata":null}`, `[{"op":"remove","path":"/metadata"}]`, map[string]string{"old": "value"}, map[string]string{}, true},
				{"read_only_patch", `{"metadata":[]}`, `[{"op":"test","path":"/metadata","value":[]}]`, map[string]string{"old": "value"}, map[string]string{"old": "value"}, false},
				{"absent_patch", `{}`, ``, map[string]string{"old": "value"}, map[string]string{"old": "value"}, false},
				{"last_member", `{"metadata":[]}`, `[{"op":"remove","path":"/metadata/0"}]`, map[string]string{"old": "value"}, map[string]string{}, true},
				{"remove_field", `{}`, `[{"op":"remove","path":"/metadata"}]`, map[string]string{"old": "value"}, map[string]string{}, true},
				{"replace_empty", `{"metadata":[]}`, `[{"op":"replace","path":"/metadata","value":[]}]`, map[string]string{"old": "value"}, map[string]string{}, true},
				{"partial_remove", `{"metadata":[{"Key":"keep","Value":"yes"}]}`, `[{"op":"remove","path":"/metadata/0"}]`, map[string]string{"old": "value", "keep": "yes"}, map[string]string{"keep": "yes"}, true},
				{"retained_desired_authoritative", `{"metadata":[{"Key":"keep","Value":"yes"}]}`, `[{"op":"remove","path":"/metadata"}]`, map[string]string{"old": "value", "keep": "yes"}, map[string]string{"keep": "yes"}, true},
				{"unrelated_omission", `{}`, `[{"op":"replace","path":"/publicAccess","value":"None"}]`, map[string]string{"old": "value"}, map[string]string{"old": "value"}, false},
				{"implicit_empty", `{"metadata":[]}`, ``, map[string]string{"old": "value"}, map[string]string{"old": "value"}, false},
				{"unrelated_empty", `{"metadata":[]}`, `[{"op":"replace","path":"/metadataOther","value":[]}]`, map[string]string{"old": "value"}, map[string]string{"old": "value"}, false},
			} {
				t.Run(tc.name, func(t *testing.T) {
					state := tc.prior
					field := "metadata"
					if kind == "account-tags" {
						field = "tags"
						tc.desired = strings.ReplaceAll(tc.desired, "metadata", "Tags")
						tc.patch = strings.ReplaceAll(tc.patch, "metadata", "Tags")
					}
					nativeID := ""
					patchCount, getCount := 0, 0
					transport := metadataTransport(func(r *http.Request) (*http.Response, error) {
						switch r.Method {
						case http.MethodPatch:
							patchCount++
							var payload struct {
								Properties map[string]json.RawMessage `json:"properties"`
								Tags       json.RawMessage            `json:"tags"`
							}
							require.NoError(t, json.NewDecoder(r.Body).Decode(&payload))
							raw, present := payload.Properties[field]
							if kind == "account-tags" {
								raw = payload.Tags
								present = raw != nil
							}
							require.Equal(t, tc.send, present, "metadata presence in actual SDK PATCH body")
							if present {
								require.NotEqual(t, "null", string(raw))
								state = map[string]string{}
								require.NoError(t, json.Unmarshal(raw, &state))
							}
						case http.MethodGet:
							getCount++
						default:
							t.Fatalf("unexpected request %s", r.Method)
						}
						response := map[string]any{"id": nativeID, "properties": map[string]any{"metadata": state}}
						if kind == "account-tags" {
							response = map[string]any{"id": nativeID, "tags": state, "properties": map[string]any{}}
						}
						body, err := json.Marshal(response)
						require.NoError(t, err)
						return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(string(body))), Request: r}, nil
					})
					opts := &arm.ClientOptions{ClientOptions: policy.ClientOptions{Transport: transport}, DisableRPRegistration: true}
					var prov metadataProvisioner
					switch kind {
					case "account-tags":
						client, err := armstorage.NewAccountsClient("sub-1", metadataCredential{}, opts)
						require.NoError(t, err)
						prov = newTestStorageAccount(client)
						nativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Storage/storageAccounts/acct1"
					case "blob":
						client, err := armstorage.NewBlobContainersClient("sub-1", metadataCredential{}, opts)
						require.NoError(t, err)
						prov = newTestBlobContainer(client)
						nativeID = testBlobContainerNativeID
					case "share":
						client, err := armstorage.NewFileSharesClient("sub-1", metadataCredential{}, opts)
						require.NoError(t, err)
						prov = newTestFileShare(client)
						nativeID = testFileShareNativeID
					case "queue":
						client, err := armstorage.NewQueueClient("sub-1", metadataCredential{}, opts)
						require.NoError(t, err)
						prov = newTestStorageQueue(client)
						nativeID = testStorageQueueNativeID
					}
					priorEntries := []map[string]string{}
					for k, v := range tc.prior {
						priorEntries = append(priorEntries, map[string]string{"Key": k, "Value": v})
					}
					priorKey := "metadata"
					if kind == "account-tags" {
						priorKey = "Tags"
					}
					priorJSON, err := json.Marshal(map[string]any{priorKey: priorEntries})
					require.NoError(t, err)
					request := &resource.UpdateRequest{NativeID: nativeID, PriorProperties: priorJSON, DesiredProperties: json.RawMessage(tc.desired)}
					if tc.patch != "" {
						request.PatchDocument = to.Ptr(tc.patch)
					}
					result, err := prov.Update(context.Background(), request)
					require.NoError(t, err)
					require.Equal(t, resource.OperationStatusSuccess, result.ProgressResult.OperationStatus)
					got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: nativeID})
					require.NoError(t, err)
					var props map[string]any
					require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
					if kind == "account-tags" {
						props["metadata"] = props["Tags"]
					}
					actual := map[string]string{}
					for k, v := range metadataFromProperties(props) {
						actual[k] = *v
					}
					require.Equal(t, tc.want, actual, "provider state after Update then Read")
					require.Equal(t, 1, patchCount)
					require.Equal(t, 1, getCount)
				})
			}
		})
	}
}
