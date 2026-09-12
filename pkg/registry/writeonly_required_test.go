// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build unit

package registry

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// fieldHintRE captures one @azure.FieldHint block together with the property it
// annotates: group 1 is the hint body, group 2 the property name.
var fieldHintRE = regexp.MustCompile(`(?s)@azure\.FieldHint\s*\{(.*?)\}\s*(?:@formae\.\w+[^\n]*\n\s*)*(\w+)\s*:`)

// TestNoFieldIsBothWriteOnlyAndRequired guards a combination that renders a
// resource permanently undiscoverable.
//
// `writeOnly` says the provider never returns the value. `required` makes core
// reject any resource that lacks it. Put both on one field and discovery finds
// the resource, then throws it away:
//
//	Discovery finished. The following resources have been discovered:
//	  AZURE::OperationalInsights::StorageInsightConfig  1
//	Validation of required fields failed error="resource fpsdt-lasic-... is
//	missing required fields: [storageAccountKey]"
//
// The conformance harness reports that as a plain `[Discover]` timeout with no
// hint of the cause, which is what made this expensive to find the first time.
//
// A write-only field is therefore always optional in this plugin. Presence is
// ARM's to enforce on the write; there is nothing for core to check on the read.
func TestNoFieldIsBothWriteOnlyAndRequired(t *testing.T) {
	var offenders []string

	root, err := filepath.Abs(filepath.Join("..", "..", "schema", "pkl"))
	if err != nil {
		t.Fatalf("resolve schema/pkl path: %v", err)
	}

	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".pkl") {
			return err
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			rel = path
		}
		for _, m := range fieldHintRE.FindAllStringSubmatch(string(src), -1) {
			body, field := m[1], m[2]
			if strings.Contains(body, "writeOnly = true") && strings.Contains(body, "required = true") {
				offenders = append(offenders, filepath.Join("schema", "pkl", rel)+": "+field)
			}
		}
		return nil
	})
	require.NoError(t, err)

	require.Empty(t, offenders,
		"these fields are both writeOnly and required, so discovery will drop the resource; "+
			"drop `required` and make the property nullable")
}
