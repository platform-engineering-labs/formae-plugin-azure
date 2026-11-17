// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build conformance

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"testing"

	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/resources"
	"github.com/platform-engineering-labs/formae/pkg/model"
	"github.com/platform-engineering-labs/formae/pkg/plugin"
	conformance "github.com/platform-engineering-labs/formae/pkg/plugin-conformance-tests"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

// TestAPIMUnsupportedTierListsLive is an on-demand acceptance test selected by
// the Debug workflow's exact api-management-service discovery filter. It creates
// only the supported Consumption service fixture, then lists its unavailable
// collections through the candidate plugin's real Azure clients.
func TestAPIMUnsupportedTierListsLive(t *testing.T) {
	if os.Getenv("FORMAE_TEST_TYPE") != "discovery" || os.Getenv("FORMAE_TEST_FILTER") != "api-management-service" {
		t.Skip("requires the api-management-service discovery filter")
	}

	var created []conformance.CreatedResourceInfo
	var target model.Target
	h := conformance.NewTestHarness(t)
	defer func() {
		// Registered SDK cleanups provide an idempotent fallback, including when
		// setup only partially succeeds. Explicit deletes make cleanup errors
		// fail this test while still attempting every resource in reverse order.
		defer h.Cleanup()
		for i := len(created) - 1; i >= 0; i-- {
			res := created[i]
			if err := h.DeleteUnmanagedResource(res.ResourceType, res.NativeID, &target); err != nil {
				t.Errorf("cleanup %s (%s): %v", res.Label, res.ResourceType, err)
			}
		}
	}()

	evaluated, err := h.Eval("testdata/api-management-service.pkl")
	require.NoError(t, err)
	var forma model.Forma
	require.NoError(t, json.Unmarshal([]byte(evaluated), &forma))
	require.Len(t, forma.Targets, 1)
	target = forma.Targets[0]
	require.Equal(t, "AZURE", target.Namespace)
	require.NotEmpty(t, target.Config)

	created, err = h.CreateAllUnmanagedResources(evaluated)
	require.NoError(t, err)
	var services []conformance.CreatedResourceInfo
	for _, res := range created {
		if res.ResourceType == resources.ResourceTypeApiManagementService {
			services = append(services, res)
		}
	}
	require.Len(t, services, 1)
	var service struct {
		ResourceGroupName string `json:"resourceGroupName"`
		Name              string `json:"name"`
		SKUName           string `json:"skuName"`
	}
	require.NoError(t, json.Unmarshal(services[0].Properties, &service))
	require.NotEmpty(t, service.ResourceGroupName)
	require.NotEmpty(t, service.Name)
	require.Equal(t, "Consumption", service.SKUName)

	p := &Plugin{}
	for _, resourceType := range []string{
		resources.ResourceTypeApiManagementUser,
		resources.ResourceTypeApiManagementGroup,
		resources.ResourceTypeApiManagementGateway,
	} {
		t.Run(resourceType, func(t *testing.T) {
			var logs bytes.Buffer
			logger := plugin.NewPluginLogger(slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
			ctx := plugin.WithLogger(context.Background(), logger)
			got, err := p.List(ctx, &resource.ListRequest{
				ResourceType: resourceType,
				TargetConfig: target.Config,
				AdditionalProperties: map[string]string{
					"resourceGroupName": service.ResourceGroupName,
					"serviceName":       service.Name,
				},
			})
			t.Logf("Plugin.List events:\n%s", logs.String())
			require.NoError(t, err)
			require.NotNil(t, got)
			require.Empty(t, got.NativeIDs)
			require.Nil(t, got.NextPageToken)

			// Empty success alone could come from authorization suppression or a
			// successful empty provider page. Require the exact typed-error branch.
			witnesses := 0
			scanner := bufio.NewScanner(&logs)
			for scanner.Scan() {
				var event map[string]any
				require.NoError(t, json.Unmarshal(scanner.Bytes(), &event))
				require.NotEqual(t, "ERROR", event["level"], "List must not log a failure")
				require.NotEqual(t, "WARN", event["level"], "List must not suppress access denial")
				if event["msg"] != "List skipped: API Management collection unavailable in pricing tier" {
					continue
				}
				witnesses++
				delete(event, "time")
				require.Equal(t, map[string]any{
					"level":             "DEBUG",
					"msg":               "List skipped: API Management collection unavailable in pricing tier",
					"resourceType":      resourceType,
					"resourceGroupName": service.ResourceGroupName,
					"serviceName":       service.Name,
					"statusCode":        float64(400),
					"errorCode":         "MethodNotAllowedInPricingTier",
					"successfulPages":   float64(0),
				}, event)
			}
			require.NoError(t, scanner.Err())
			require.Equal(t, 1, witnesses, "expected one typed tier-skip DEBUG event")
		})
	}
}
