// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package prov

import (
	"errors"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

// AzureErrorCode maps known Azure SDK and transport errors to Formae operation
// error codes. The second return value is false when the error is not a
// provider/runtime failure and should remain a returned error.
func AzureErrorCode(err error) (resource.OperationErrorCode, bool) {
	if err == nil {
		return "", false
	}

	var respErr *azcore.ResponseError
	if errors.As(err, &respErr) {
		switch respErr.StatusCode {
		case 400:
			return resource.OperationErrorCodeInvalidRequest, true
		case 401:
			return resource.OperationErrorCodeInvalidCredentials, true
		case 403:
			return resource.OperationErrorCodeAccessDenied, true
		case 404:
			return resource.OperationErrorCodeNotFound, true
		case 409:
			return resource.OperationErrorCodeResourceConflict, true
		case 429:
			return resource.OperationErrorCodeThrottling, true
		case 500:
			return resource.OperationErrorCodeServiceInternalError, true
		case 502, 503, 504:
			return resource.OperationErrorCodeServiceTimeout, true
		default:
			return resource.OperationErrorCodeGeneralServiceException, true
		}
	}

	errStr := err.Error()
	switch {
	case strings.Contains(errStr, "Timeout"),
		strings.Contains(errStr, "RequestTimeout"),
		strings.Contains(errStr, "GatewayTimeout"):
		return resource.OperationErrorCodeServiceTimeout, true
	case strings.Contains(errStr, "QuotaExceeded"),
		strings.Contains(errStr, "LimitExceeded"):
		return resource.OperationErrorCodeServiceLimitExceeded, true
	case strings.Contains(errStr, "connection refused"),
		strings.Contains(errStr, "network"),
		strings.Contains(errStr, "dial"):
		return resource.OperationErrorCodeNetworkFailure, true
	default:
		return "", false
	}
}

// OperationErrorCode maps an error to a Formae operation error code, using a
// general service exception for unclassified errors.
func OperationErrorCode(err error) resource.OperationErrorCode {
	if err == nil {
		return ""
	}
	if code, ok := AzureErrorCode(err); ok {
		return code
	}
	return resource.OperationErrorCodeGeneralServiceException
}

// IsDeleteSuccessError returns true if the error means the resource is already absent.
func IsDeleteSuccessError(err error) bool {
	code, ok := AzureErrorCode(err)
	return ok && code == resource.OperationErrorCodeNotFound
}
