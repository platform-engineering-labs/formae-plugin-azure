// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build unit

package resources

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Discovery drives a resource's List() by handing it the AdditionalProperties
// named in its PKL @azure.ResourceHint listParam block. A key that List() reads
// but the hint never supplies always arrives empty, so the pager is built with a
// blank scope: the SDK call errors, discovery logs nothing for the type, and the
// conformance discovery gate fails with "resource did not appear in inventory"
// — with no "Received N resources" line to explain why. That mismatch is
// invisible to the compiler and to every mocked test, because both sides are
// correct in isolation.
//
// This test enforces the contract statically: every AdditionalProperties key a
// List() reads must be supplied by that resource's hint, unless the resource is
// listed in subscriptionWideList below.
var subscriptionWideList = map[string]string{
	"AZURE::Authorization::PolicyAssignment": "falls back to NewListPager over the whole subscription when scope is empty",
	"AZURE::Authorization::RoleAssignment":   "defaults scope to /subscriptions/<id> when empty",
	"AZURE::Authorization::RoleDefinition":   "defaults scope to /subscriptions/<id> when empty",
	"AZURE::DBforPostgreSQL::Configuration":  "enumerates all flexible servers in the subscription when the server scope is empty",
	"AZURE::DBforPostgreSQL::Database":       "enumerates all servers in the subscription when the server scope is empty",
	"AZURE::DBforPostgreSQL::FirewallRule":   "enumerates all flexible servers in the subscription when the server scope is empty",
	"AZURE::EventGrid::EventSubscription":    "enumerates subscription-wide when the target resource scope is empty",
	"AZURE::Insights::DiagnosticSetting":     "hangs off an arbitrary target resource; no parent chain to drive it",
	"AZURE::Network::PrivateDnsZoneGroup":    "enumerates all private endpoints in the subscription when the endpoint scope is empty",
	"AZURE::Network::PrivateEndpoint":        "falls back to NewListBySubscriptionPager when the resource group is empty",
	"AZURE::Sql::Database":                   "enumerates all servers in the subscription when the server scope is empty",
	"AZURE::Sql::ElasticPool":                "enumerates all servers in the subscription when the server scope is empty",
}

var (
	reResourceType = regexp.MustCompile(`ResourceType\w*\s*=\s*"(AZURE::[^"]+)"`)
	reListFunc     = regexp.MustCompile(`(?s)func \([^)]*\) List\(ctx context\.Context.*?\n\}\n`)
	reAdditional   = regexp.MustCompile(`AdditionalProperties\["([^"]+)"\]`)
	rePklType      = regexp.MustCompile(`(?m)^const type = "([^"]+)"`)
	reHint         = regexp.MustCompile(`(?s)@azure\.ResourceHint\s*\{(.*?)\n\}`)
	reListParam    = regexp.MustCompile(`listParameter\s*=\s*"([^"]+)"`)
)

func TestListParamsCoverEveryAdditionalPropertyRead(t *testing.T) {
	root := repoRoot(t)

	// type -> listParameter names the hint supplies
	supplied := map[string]map[string]bool{}
	pkls, err := filepath.Glob(filepath.Join(root, "schema", "pkl", "*", "*.pkl"))
	require.NoError(t, err)
	for _, p := range pkls {
		src, err := os.ReadFile(p)
		require.NoError(t, err)
		m := rePklType.FindSubmatch(src)
		if m == nil {
			continue
		}
		params := map[string]bool{}
		if h := reHint.FindSubmatch(src); h != nil {
			for _, lp := range reListParam.FindAllSubmatch(h[1], -1) {
				params[string(lp[1])] = true
			}
		}
		supplied[string(m[1])] = params
	}
	require.NotEmpty(t, supplied, "no PKL schemas parsed - is schema/pkl present?")

	gos, err := filepath.Glob(filepath.Join(root, "pkg", "resources", "*.go"))
	require.NoError(t, err)

	checked := 0
	for _, p := range gos {
		if strings.HasSuffix(p, "_test.go") {
			continue
		}
		src, err := os.ReadFile(p)
		require.NoError(t, err)
		typeMatch := reResourceType.FindSubmatch(src)
		if typeMatch == nil {
			continue
		}
		resourceType := string(typeMatch[1])
		params, ok := supplied[resourceType]
		if !ok {
			continue
		}
		listBody := reListFunc.Find(src)
		if listBody == nil {
			continue
		}
		checked++

		var missing []string
		for _, k := range reAdditional.FindAllSubmatch(listBody, -1) {
			if key := string(k[1]); !params[key] {
				missing = append(missing, key)
			}
		}
		if len(missing) == 0 {
			continue
		}
		if why, exempt := subscriptionWideList[resourceType]; exempt {
			t.Logf("%s reads %v without a listParam: allowed, %s", resourceType, missing, why)
			continue
		}
		sort.Strings(missing)
		t.Errorf("%s: List() reads AdditionalProperties %v that its @azure.ResourceHint listParam never supplies "+
			"(%s). Discovery will call List() with those keys empty and the type will never be enumerated. "+
			"Add a formae.ListProperty for each, or - if List() enumerates subscription-wide when they are empty - "+
			"add the type to subscriptionWideList with the reason.",
			resourceType, missing, filepath.Base(p))
	}

	require.Greater(t, checked, 100, "expected to check well over 100 resources; the parser probably broke")
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	require.NoError(t, err)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		require.NotEqual(t, parent, dir, "walked past the filesystem root without finding go.mod")
		dir = parent
	}
}
