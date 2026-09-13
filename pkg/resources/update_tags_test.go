// © 2026 Platform Engineering Labs Inc.
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"encoding/json"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

func TestUpdateTagsIntent(t *testing.T) {
	for _, tc := range []struct {
		name, desired, patch string
		want                 map[string]*string
	}{
		{"absent without patch", `{}`, ``, nil},
		{"unrelated patch", `{}`, `[{"op":"remove","path":"/other"}]`, nil},
		{"similar prefix", `{}`, `[{"op":"remove","path":"/TagsExtra"}]`, nil},
		{"remove field", `{}`, `[{"op":"remove","path":"/Tags"}]`, map[string]*string{}},
		{"remove last element", `{}`, `[{"op":"remove","path":"/Tags/0"}]`, map[string]*string{}},
		{"empty list without patch", `{"Tags":[]}`, ``, nil},
		{"empty map without patch", `{"Tags":{}}`, ``, nil},
		{"nested empty", `{"Properties":{"Tags":[]}}`, ``, nil},
		{"nested remove", `{}`, `[{"op":"remove","path":"/Properties/Tags"}]`, map[string]*string{}},
		{"retained values win", `{"Tags":[{"Key":"keep","Value":"yes"}]}`, `[{"op":"remove","path":"/Tags/0"}]`, map[string]*string{"keep": to.Ptr("yes")}},
		{"nested retained values", `{"Properties":{"Tags":{"keep":"yes"}}}`, ``, map[string]*string{"keep": to.Ptr("yes")}},
		{"legacy empty tags unrelated patch", `{"Tags":[]}`, `[{"op":"replace","path":"/minimumTlsVersion","value":"TLS1_2"}]`, nil},
		{"null with replace", `{"Tags":null}`, `[{"op":"replace","path":"/Tags","value":null}]`, map[string]*string{}},
		{"whole document replacement", `{}`, `[{"op":"replace","path":"","value":{}}]`, map[string]*string{}},
		{"null without patch", `{"Tags":null}`, ``, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := &resource.UpdateRequest{DesiredProperties: json.RawMessage(tc.desired)}
			if tc.patch != "" {
				request.PatchDocument = to.Ptr(tc.patch)
			}
			require.Equal(t, tc.want, formaeUpdateTagsToAzureTags(request))
		})
	}
}

func TestUpdateNestedTagsAncestor(t *testing.T) {
	request := &resource.UpdateRequest{PriorProperties: json.RawMessage(`{"Properties":{"Tags":[{"Key":"old","Value":"yes"}]}}`), DesiredProperties: json.RawMessage(`{"Properties":{}}`), PatchDocument: to.Ptr(`[{"op":"replace","path":"/Properties","value":{}}]`)}
	require.Equal(t, map[string]*string{}, formaeUpdateTagsToAzureTags(request))
	request.PriorProperties = json.RawMessage(`{"Tags":[{"Key":"old","Value":"yes"}]}`)
	require.Nil(t, formaeUpdateTagsToAzureTags(request))
}

func TestClearTagsKeyVaultWireBody(t *testing.T) {
	tags := formaeUpdateTagsToAzureTags(&resource.UpdateRequest{DesiredProperties: json.RawMessage(`{}`), PatchDocument: to.Ptr(`[{"op":"remove","path":"/Tags"}]`)})
	for name, params := range map[string]any{
		"certificate": azcertificates.UpdateCertificateParameters{Tags: tags},
		"secret":      azsecrets.UpdateSecretPropertiesParameters{Tags: tags},
	} {
		t.Run(name, func(t *testing.T) {
			body, err := json.Marshal(params)
			require.NoError(t, err)
			require.JSONEq(t, `{"tags":{}}`, string(body))
		})
	}
}
