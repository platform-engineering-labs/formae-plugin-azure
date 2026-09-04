// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"encoding/json"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/apimanagement/armapimanagement"
	"github.com/stretchr/testify/require"
)

// The document a fixture would declare: indented, self-closing tags spaced,
// attributes in author order.
const testApimPolicyDeclared = `<policies>
  <inbound>
    <base />
    <set-header name="x-formae" exists-action="override">
      <value>conformance</value>
    </set-header>
  </inbound>
  <backend>
    <base />
  </backend>
  <outbound>
    <base />
  </outbound>
  <on-error>
    <base />
  </on-error>
</policies>`

// The same document as ARM hands it back: CRLF line endings, different
// indentation, unspaced self-closing tags, attributes reordered.
const testApimPolicyReserialized = "<policies>\r\n\t<inbound>\r\n\t\t<base/>\r\n\t\t" +
	"<set-header exists-action=\"override\" name=\"x-formae\">\r\n\t\t\t<value>conformance</value>\r\n\t\t" +
	"</set-header>\r\n\t</inbound>\r\n\t<backend>\r\n\t\t<base/>\r\n\t</backend>\r\n\t" +
	"<outbound>\r\n\t\t<base/>\r\n\t</outbound>\r\n\t<on-error>\r\n\t\t<base/>\r\n\t</on-error>\r\n</policies>"

func TestApimXMLEquivalent(t *testing.T) {
	// This is the whole reason the helper exists: ARM's rendering of the
	// caller's document differs textually in four separate ways at once.
	t.Run("reserialized_document_is_equivalent", func(t *testing.T) {
		require.NotEqual(t, testApimPolicyDeclared, testApimPolicyReserialized)
		require.True(t, apimXMLEquivalent(testApimPolicyDeclared, testApimPolicyReserialized))
	})

	t.Run("attribute_order_alone_is_equivalent", func(t *testing.T) {
		require.True(t, apimXMLEquivalent(
			`<set-header name="a" exists-action="override" />`,
			`<set-header exists-action="override" name="a" />`))
	})

	t.Run("a_real_change_is_not_equivalent", func(t *testing.T) {
		require.False(t, apimXMLEquivalent(testApimPolicyDeclared,
			`<policies><inbound><base /></inbound></policies>`))
	})

	t.Run("a_changed_attribute_value_is_not_equivalent", func(t *testing.T) {
		require.False(t, apimXMLEquivalent(
			`<set-header name="a" />`,
			`<set-header name="b" />`))
	})

	// A rawxml body can carry an unescaped policy expression, which is not
	// well-formed XML. The tokenizer fails on both sides and the textual
	// fallback has to take over rather than declaring them different.
	t.Run("malformed_documents_fall_back_to_text", func(t *testing.T) {
		raw := `<inbound><set-variable value="@(a && b)" /></inbound>`
		require.True(t, apimXMLEquivalent(raw, raw))
		require.True(t, apimXMLEquivalent(
			"<inbound>\n  <set-variable value=\"@(a && b)\" />\n</inbound>",
			"<inbound><set-variable value=\"@(a && b)\"/></inbound>"))
	})

	t.Run("both_empty_is_equivalent", func(t *testing.T) {
		require.True(t, apimXMLEquivalent("", ""))
	})
}

func TestApimJSONEquivalent(t *testing.T) {
	t.Run("key_order_and_whitespace_are_ignored", func(t *testing.T) {
		require.True(t, apimJSONEquivalent(
			`{"a": 1, "b": {"c": [1, 2]}}`,
			"{\"b\":{\"c\":[1,2]},\n \"a\":1}"))
	})

	t.Run("a_real_change_is_not_equivalent", func(t *testing.T) {
		require.False(t, apimJSONEquivalent(`{"a":1}`, `{"a":2}`))
	})

	// Array order is meaningful in JSON Schema, so it must not be normalized
	// away.
	t.Run("array_order_is_significant", func(t *testing.T) {
		require.False(t, apimJSONEquivalent(`[1,2]`, `[2,1]`))
	})

	t.Run("unparseable_input_is_not_equivalent", func(t *testing.T) {
		require.False(t, apimJSONEquivalent(`{`, `{}`))
	})
}

func TestApimPolicyReadProps(t *testing.T) {
	armState := &armapimanagement.PolicyContractProperties{
		Value:  to.Ptr(testApimPolicyReserialized),
		Format: to.Ptr(armapimanagement.PolicyContentFormatXML),
	}

	// The core case: the caller's document is reported verbatim, so a sync
	// against an unchanged policy shows no drift.
	t.Run("echoes_the_declared_document_when_equivalent", func(t *testing.T) {
		prior, _ := json.Marshal(map[string]any{"value": testApimPolicyDeclared, "format": "xml"})
		props := map[string]any{}
		apimPolicyReadProps(props, armState, prior)
		require.Equal(t, testApimPolicyDeclared, props["value"])
		require.Equal(t, "xml", props["format"])
	})

	// ARM answers a Get with format "xml" whatever was submitted, so a
	// rawxml declaration has to keep reporting rawxml or the format itself
	// becomes permanent drift.
	t.Run("keeps_a_rawxml_declaration_when_arm_reports_xml", func(t *testing.T) {
		prior, _ := json.Marshal(map[string]any{"value": testApimPolicyDeclared, "format": "rawxml"})
		props := map[string]any{}
		apimPolicyReadProps(props, armState, prior)
		require.Equal(t, "rawxml", props["format"])
	})

	// An omitted format stays omitted: the schema marks it as having a
	// provider default, and reporting ARM's "xml" would contradict that.
	t.Run("leaves_an_omitted_format_omitted", func(t *testing.T) {
		prior, _ := json.Marshal(map[string]any{"value": testApimPolicyDeclared})
		props := map[string]any{}
		apimPolicyReadProps(props, armState, prior)
		require.Equal(t, testApimPolicyDeclared, props["value"])
		require.NotContains(t, props, "format")
	})

	// Someone edited the policy in the portal. That is real drift and ARM's
	// document is what must be reported.
	t.Run("reports_arm_when_the_documents_differ", func(t *testing.T) {
		prior, _ := json.Marshal(map[string]any{
			"value":  `<policies><inbound><base /></inbound></policies>`,
			"format": "xml",
		})
		props := map[string]any{}
		apimPolicyReadProps(props, armState, prior)
		require.Equal(t, testApimPolicyReserialized, props["value"])
		require.Equal(t, "xml", props["format"])
	})

	// A discovery read has no prior state, so ARM's rendering is all there is.
	t.Run("reports_arm_with_no_prior_state", func(t *testing.T) {
		props := map[string]any{}
		apimPolicyReadProps(props, armState, nil)
		require.Equal(t, testApimPolicyReserialized, props["value"])
		require.Equal(t, "xml", props["format"])
	})

	t.Run("tolerates_unparseable_prior_state", func(t *testing.T) {
		props := map[string]any{}
		apimPolicyReadProps(props, armState, json.RawMessage(`not json`))
		require.Equal(t, testApimPolicyReserialized, props["value"])
	})

	t.Run("omits_both_when_arm_has_nothing", func(t *testing.T) {
		props := map[string]any{}
		apimPolicyReadProps(props, nil, nil)
		require.NotContains(t, props, "value")
		require.NotContains(t, props, "format")
	})
}

func TestApimPolicyContract(t *testing.T) {
	t.Run("omits_format_when_not_declared", func(t *testing.T) {
		got := apimPolicyContract(apimPolicyBodyProps{Value: "<policies />"})
		require.Equal(t, "<policies />", *got.Properties.Value)
		// Nil rather than an empty string, so ARM applies its own default.
		require.Nil(t, got.Properties.Format)
	})

	t.Run("passes_a_declared_format_through", func(t *testing.T) {
		got := apimPolicyContract(apimPolicyBodyProps{Value: "<policies />", Format: "rawxml"})
		require.Equal(t, armapimanagement.PolicyContentFormatRawxml, *got.Properties.Format)
	})
}

func TestApimSchemaDocumentRoundTrip(t *testing.T) {
	t.Run("json_document_becomes_a_structured_value", func(t *testing.T) {
		got, err := apimJSONToAny(`{"schemas":{"Status":{"type":"object"}}}`)
		require.NoError(t, err)
		require.IsType(t, map[string]any{}, got)
		require.True(t, apimJSONEquivalent(apimAnyToJSON(got), `{"schemas":{"Status":{"type":"object"}}}`))
	})

	t.Run("invalid_json_is_rejected_with_a_reason", func(t *testing.T) {
		_, err := apimJSONToAny(`{`)
		require.ErrorContains(t, err, "value is not valid JSON")
	})

	t.Run("a_string_document_passes_through_unchanged", func(t *testing.T) {
		require.Equal(t, "<xsd:schema />", apimAnyToJSON("<xsd:schema />"))
	})

	t.Run("a_nil_document_renders_empty", func(t *testing.T) {
		require.Equal(t, "", apimAnyToJSON(nil))
	})
}

func TestApimEchoSuppliedDocument(t *testing.T) {
	t.Run("echoes_the_supplied_document_when_equivalent", func(t *testing.T) {
		got := apimEchoSuppliedDocument(`{"a": 1}`, `{"a":1}`, apimJSONEquivalent)
		require.Equal(t, `{"a": 1}`, got)
	})

	t.Run("reports_the_actual_document_when_it_differs", func(t *testing.T) {
		got := apimEchoSuppliedDocument(`{"a": 1}`, `{"a":2}`, apimJSONEquivalent)
		require.Equal(t, `{"a":2}`, got)
	})

	t.Run("reports_the_actual_document_with_nothing_supplied", func(t *testing.T) {
		got := apimEchoSuppliedDocument("", `{"a":2}`, apimJSONEquivalent)
		require.Equal(t, `{"a":2}`, got)
	})
}
