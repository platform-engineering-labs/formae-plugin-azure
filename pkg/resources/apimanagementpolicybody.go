// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"sort"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/apimanagement/armapimanagement"
)

// Shared helpers for the API Management resources whose body is a document ARM
// is free to reformat: the four policy singletons (service, api, api-operation
// and — in the product group — product policy) plus the two schema resources.
//
// ARM does not store a policy document verbatim. It reparses the XML and
// re-serializes it, so what comes back out of a Get differs from what went in:
// indentation and line endings are rewritten, attributes come back in the
// order the parser emitted them, `<base />` and `<base/>` are interchangeable,
// and a document submitted as `rawxml` is returned as `xml`. Reporting ARM's
// rendering as the resource's current state therefore shows drift on every
// single sync even though nothing changed.
//
// The fix used throughout this namespace: report the caller's own document back
// whenever it is SEMANTICALLY the same as what ARM holds, and report ARM's
// document only when it genuinely differs (someone edited the policy in the
// portal). Equivalence is decided by canonicalizing both sides — never by
// canonicalizing what is stored, which would lose the author's formatting.
//
// The caller's document reaches Read through resource.ReadRequest.PriorProperties,
// which carries the last-known model for the resource. It is empty for a
// discovery read and for the read-back after a create, and in both of those
// cases ARM's own rendering is the only thing available and is what gets
// reported.

// apimIfMatchAny is the ETag wildcard. Every APIM child delete and PATCH takes
// ifMatch as a positional argument rather than an option, and formae has no
// optimistic-concurrency model for these, so the wildcard is always sent.
const apimIfMatchAny = "*"

// apimPolicyName is the only legal policy id: ARM models a policy as a
// singleton child named "policy", which is why the policy resources carry no
// name property of their own.
const apimPolicyName = "policy"

// apimPolicyBodyProps is the caller-supplied half of every policy resource.
// Each policy resource embeds it so the four of them cannot drift apart.
type apimPolicyBodyProps struct {
	Value  string `json:"value"`
	Format string `json:"format"`
}

// apimPolicyFormat maps the schema's optional format onto the ARM enum. Nil
// when the caller omitted it, so ARM applies its own default of "xml" instead
// of receiving an empty string.
func apimPolicyFormat(format string) *armapimanagement.PolicyContentFormat {
	if format == "" {
		return nil
	}
	return to.Ptr(armapimanagement.PolicyContentFormat(format))
}

// apimPolicyContract builds the request body for a policy PUT.
func apimPolicyContract(body apimPolicyBodyProps) armapimanagement.PolicyContract {
	return armapimanagement.PolicyContract{
		Properties: &armapimanagement.PolicyContractProperties{
			Value:  to.Ptr(body.Value),
			Format: apimPolicyFormat(body.Format),
		},
	}
}

// apimPolicyReadProps fills value and format on a policy read.
//
// prior is resource.ReadRequest.PriorProperties: when it carries a document
// equivalent to the one ARM holds, the caller's exact text and format are
// reported so ARM's reformatting is not mistaken for drift. Otherwise ARM's
// document is reported, which is what a real out-of-band edit looks like.
func apimPolicyReadProps(props map[string]any, p *armapimanagement.PolicyContractProperties, prior json.RawMessage) {
	armValue, armFormat := "", ""
	if p != nil {
		if p.Value != nil {
			armValue = *p.Value
		}
		if p.Format != nil {
			armFormat = string(*p.Format)
		}
	}

	if priorBody, ok := apimPriorPolicyBody(prior); ok && apimXMLEquivalent(priorBody.Value, armValue) {
		props["value"] = priorBody.Value
		if priorBody.Format != "" {
			props["format"] = priorBody.Format
		}
		return
	}

	if armValue != "" {
		props["value"] = armValue
	}
	if armFormat != "" {
		props["format"] = armFormat
	}
}

// apimPolicyWriteBackProps fills value and format from what the caller just
// sent, for the read-back on a create or update. The response body carries
// ARM's rendering, but the caller's text is what the caller asked for and is
// still authoritative at that moment.
func apimPolicyWriteBackProps(props map[string]any, body apimPolicyBodyProps) {
	props["value"] = body.Value
	if body.Format != "" {
		props["format"] = body.Format
	}
}

func apimPriorPolicyBody(prior json.RawMessage) (apimPolicyBodyProps, bool) {
	if len(prior) == 0 {
		return apimPolicyBodyProps{}, false
	}
	var body apimPolicyBodyProps
	if err := json.Unmarshal(prior, &body); err != nil {
		return apimPolicyBodyProps{}, false
	}
	if body.Value == "" {
		return apimPolicyBodyProps{}, false
	}
	return body, true
}

var apimInterTagWhitespace = regexp.MustCompile(`>\s+<`)
var apimWhitespaceRun = regexp.MustCompile(`\s+`)

// apimXMLEquivalent reports whether two policy documents mean the same thing.
//
// The primary comparison canonicalizes both documents through an XML tokenizer:
// attributes are sorted, insignificant whitespace between elements is dropped,
// and character data has its whitespace runs collapsed. That covers everything
// ARM is known to change. A `rawxml` document need not be well-formed XML —
// policy expressions can carry bare `&` and `<` — so a parse failure on either
// side falls back to a textual normalization rather than declaring the two
// different.
func apimXMLEquivalent(a, b string) bool {
	if a == b {
		return true
	}
	ca, errA := apimCanonicalXML(a)
	cb, errB := apimCanonicalXML(b)
	if errA == nil && errB == nil {
		return ca == cb
	}
	return apimFlattenXML(a) == apimFlattenXML(b)
}

func apimFlattenXML(s string) string {
	out := apimInterTagWhitespace.ReplaceAllString(s, "><")
	out = strings.ReplaceAll(out, " />", "/>")
	out = apimWhitespaceRun.ReplaceAllString(out, " ")
	return strings.TrimSpace(out)
}

func apimCanonicalXML(s string) (string, error) {
	if strings.TrimSpace(s) == "" {
		return "", nil
	}
	dec := xml.NewDecoder(strings.NewReader(s))
	var out strings.Builder
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			attrs := make([]xml.Attr, len(t.Attr))
			copy(attrs, t.Attr)
			sort.Slice(attrs, func(i, j int) bool {
				if attrs[i].Name.Space != attrs[j].Name.Space {
					return attrs[i].Name.Space < attrs[j].Name.Space
				}
				return attrs[i].Name.Local < attrs[j].Name.Local
			})
			out.WriteString("<" + t.Name.Space + ":" + t.Name.Local)
			for _, a := range attrs {
				out.WriteString(" " + a.Name.Space + ":" + a.Name.Local + "=" +
					apimWhitespaceRun.ReplaceAllString(strings.TrimSpace(a.Value), " "))
			}
			out.WriteString(">")
		case xml.EndElement:
			out.WriteString("</" + t.Name.Space + ":" + t.Name.Local + ">")
		case xml.CharData:
			text := apimWhitespaceRun.ReplaceAllString(strings.TrimSpace(string(t)), " ")
			if text != "" {
				out.WriteString(text)
			}
		}
	}
	return out.String(), nil
}

// apimJSONEquivalent reports whether two JSON documents carry the same data,
// ignoring key order and insignificant whitespace. Used by the two schema
// resources, whose JSON content types travel as structured documents and come
// back re-serialized by ARM.
func apimJSONEquivalent(a, b string) bool {
	if a == b {
		return true
	}
	var va, vb any
	if json.Unmarshal([]byte(a), &va) != nil || json.Unmarshal([]byte(b), &vb) != nil {
		return false
	}
	return reflect.DeepEqual(va, vb)
}

// apimJSONToAny parses a caller-supplied JSON document into the untyped value
// the SDK's schema-document fields take.
func apimJSONToAny(s string) (any, error) {
	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		return nil, fmt.Errorf("value is not valid JSON: %w", err)
	}
	return v, nil
}

// apimAnyToJSON renders an ARM-returned schema document back into the string
// form the schema declares. Returns "" when there is nothing to render, so
// callers can leave the property out entirely.
func apimAnyToJSON(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	out, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(out)
}

// apimEchoSuppliedDocument reports supplied when it is equivalent to actual,
// and actual otherwise. Shared by the schema resources, which have the same
// ARM-reformats-the-body problem as the policies but compare as JSON.
func apimEchoSuppliedDocument(supplied, actual string, equivalent func(string, string) bool) string {
	if supplied != "" && equivalent(supplied, actual) {
		return supplied
	}
	return actual
}
