// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"errors"
	"net/http"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/platform-engineering-labs/formae/pkg/plugin"
)

// skipUnsupportedApiManagementTier is used only by User, Group, and Gateway
// discovery before any successful page. Other operations retain provider errors.
// An unsupported collection must not discard a previously successful page.
func skipUnsupportedApiManagementTier(ctx context.Context, err error, resourceType, resourceGroupName, serviceName string) bool {
	var responseErr *azcore.ResponseError
	if !errors.As(err, &responseErr) || responseErr.StatusCode != http.StatusBadRequest || responseErr.ErrorCode != "MethodNotAllowedInPricingTier" {
		return false
	}

	plugin.LoggerFromContext(ctx).Debug("List skipped: API Management collection unavailable in pricing tier",
		"resourceType", resourceType,
		"resourceGroupName", resourceGroupName,
		"serviceName", serviceName,
		"statusCode", responseErr.StatusCode,
		"errorCode", responseErr.ErrorCode,
		"successfulPages", 0,
	)
	return true
}
