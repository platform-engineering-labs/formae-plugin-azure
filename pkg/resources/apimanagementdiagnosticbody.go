// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/apimanagement/armapimanagement"
)

// Shared body for the two API Management diagnostics.
//
// AZURE::ApiManagement::Diagnostic (service-wide) and
// AZURE::ApiManagement::ApiDiagnostic (per API) are the same entity at two
// scopes: ARM's request and response body is armapimanagement.DiagnosticContract
// for both, and the only difference between the two resources is that the
// per-API one carries an extra name in its path. Both embed apimDiagnosticProps
// and route their bodies through the three functions here, so the pair cannot
// drift apart the way a copied handler would.
//
// Two ARM shapes are deliberately flattened or dropped, and the reasons live in
// schema/pkl/apimanagement/apimanagementdiagnostic.pkl:
//
//   - body.bytes is flattened to bodyBytes, saving a fourth level of nesting for
//     a block with exactly one field.
//   - dataMasking is not modelled. The service populates it with its own
//     entries — it masks the subscription-key and Authorization headers by
//     default — with no ordering guaranteed on the way back, so any declaration
//     of it reads as drift.

// apimDiagnosticHTTPMessageProps mirrors the DiagnosticHttpMessage class.
type apimDiagnosticHTTPMessageProps struct {
	Headers   []string `json:"headers"`
	BodyBytes *int32   `json:"bodyBytes"`
}

// apimDiagnosticPipelineProps mirrors the DiagnosticPipeline class.
type apimDiagnosticPipelineProps struct {
	Request  *apimDiagnosticHTTPMessageProps `json:"request"`
	Response *apimDiagnosticHTTPMessageProps `json:"response"`
}

// apimDiagnosticSamplingProps mirrors the DiagnosticSampling class.
type apimDiagnosticSamplingProps struct {
	SamplingType string   `json:"samplingType"`
	Percentage   *float64 `json:"percentage"`
}

// apimDiagnosticProps is the half both diagnostic resources share. Each embeds
// it alongside its own scope fields.
type apimDiagnosticProps struct {
	Name                    string                       `json:"name"`
	ResourceGroupName       string                       `json:"resourceGroupName"`
	ServiceName             string                       `json:"serviceName"`
	LoggerID                string                       `json:"loggerId"`
	AlwaysLog               string                       `json:"alwaysLog"`
	HTTPCorrelationProtocol string                       `json:"httpCorrelationProtocol"`
	LogClientIP             *bool                        `json:"logClientIp"`
	OperationNameFormat     string                       `json:"operationNameFormat"`
	Verbosity               string                       `json:"verbosity"`
	Sampling                *apimDiagnosticSamplingProps `json:"sampling"`
	Frontend                *apimDiagnosticPipelineProps `json:"frontend"`
	Backend                 *apimDiagnosticPipelineProps `json:"backend"`
}

func apimDiagnosticHTTPMessage(msg *apimDiagnosticHTTPMessageProps) *armapimanagement.HTTPMessageDiagnostic {
	if msg == nil {
		return nil
	}
	out := &armapimanagement.HTTPMessageDiagnostic{
		Headers: stringPointers(msg.Headers),
	}
	if msg.BodyBytes != nil {
		out.Body = &armapimanagement.BodyDiagnosticSettings{Bytes: msg.BodyBytes}
	}
	return out
}

func apimDiagnosticPipeline(pipeline *apimDiagnosticPipelineProps) *armapimanagement.PipelineDiagnosticSettings {
	if pipeline == nil {
		return nil
	}
	return &armapimanagement.PipelineDiagnosticSettings{
		Request:  apimDiagnosticHTTPMessage(pipeline.Request),
		Response: apimDiagnosticHTTPMessage(pipeline.Response),
	}
}

func apimDiagnosticSampling(sampling *apimDiagnosticSamplingProps) *armapimanagement.SamplingSettings {
	if sampling == nil {
		return nil
	}
	out := &armapimanagement.SamplingSettings{Percentage: sampling.Percentage}
	if sampling.SamplingType != "" {
		out.SamplingType = to.Ptr(armapimanagement.SamplingType(sampling.SamplingType))
	}
	return out
}

// apimDiagnosticContract builds the request body for a diagnostic PUT or PATCH.
// Both verbs take the same DiagnosticContract.
//
// Every optional enum is left nil when unset rather than sent as an empty
// string, so ARM applies its own default instead of rejecting the value.
func apimDiagnosticContract(body apimDiagnosticProps) armapimanagement.DiagnosticContract {
	props := &armapimanagement.DiagnosticContractProperties{
		LoggerID:    to.Ptr(body.LoggerID),
		LogClientIP: body.LogClientIP,
		Sampling:    apimDiagnosticSampling(body.Sampling),
		Frontend:    apimDiagnosticPipeline(body.Frontend),
		Backend:     apimDiagnosticPipeline(body.Backend),
	}
	if body.AlwaysLog != "" {
		props.AlwaysLog = to.Ptr(armapimanagement.AlwaysLog(body.AlwaysLog))
	}
	if body.HTTPCorrelationProtocol != "" {
		props.HTTPCorrelationProtocol = to.Ptr(armapimanagement.HTTPCorrelationProtocol(body.HTTPCorrelationProtocol))
	}
	if body.OperationNameFormat != "" {
		props.OperationNameFormat = to.Ptr(armapimanagement.OperationNameFormat(body.OperationNameFormat))
	}
	if body.Verbosity != "" {
		props.Verbosity = to.Ptr(armapimanagement.Verbosity(body.Verbosity))
	}
	return armapimanagement.DiagnosticContract{Properties: props}
}

func apimDiagnosticHTTPMessageReadProps(msg *armapimanagement.HTTPMessageDiagnostic) map[string]any {
	if msg == nil {
		return nil
	}
	out := map[string]any{}
	if headers := stringsFromPointers(msg.Headers); len(headers) > 0 {
		out["headers"] = headers
	}
	if msg.Body != nil && msg.Body.Bytes != nil {
		out["bodyBytes"] = *msg.Body.Bytes
	}
	// dataMasking is deliberately not read back: see the note at the top.
	if len(out) == 0 {
		return nil
	}
	return out
}

func apimDiagnosticPipelineReadProps(pipeline *armapimanagement.PipelineDiagnosticSettings) map[string]any {
	if pipeline == nil {
		return nil
	}
	out := map[string]any{}
	if request := apimDiagnosticHTTPMessageReadProps(pipeline.Request); request != nil {
		out["request"] = request
	}
	if response := apimDiagnosticHTTPMessageReadProps(pipeline.Response); response != nil {
		out["response"] = response
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// apimDiagnosticReadProps fills the shared half of a diagnostic read.
//
// Enum values are canonicalized because ARM is inconsistent about the casing it
// echoes: desired "W3C" compared against actual "w3c" is a false drift, and
// `formae extract` cannot render the PKL union at all from an unrecognised
// casing.
func apimDiagnosticReadProps(props map[string]any, p *armapimanagement.DiagnosticContractProperties) {
	if p == nil {
		return
	}
	if p.LoggerID != nil {
		props["loggerId"] = *p.LoggerID
	}
	if p.AlwaysLog != nil {
		props["alwaysLog"] = canonicalizeEnum(string(*p.AlwaysLog), "allErrors")
	}
	if p.HTTPCorrelationProtocol != nil {
		props["httpCorrelationProtocol"] = canonicalizeEnum(string(*p.HTTPCorrelationProtocol),
			"None", "Legacy", "W3C")
	}
	if p.LogClientIP != nil {
		props["logClientIp"] = *p.LogClientIP
	}
	if p.OperationNameFormat != nil {
		props["operationNameFormat"] = canonicalizeEnum(string(*p.OperationNameFormat), "Name", "Url")
	}
	if p.Verbosity != nil {
		props["verbosity"] = canonicalizeEnum(string(*p.Verbosity), "verbose", "information", "error")
	}
	if p.Sampling != nil {
		sampling := map[string]any{}
		if p.Sampling.SamplingType != nil {
			sampling["samplingType"] = canonicalizeEnum(string(*p.Sampling.SamplingType), "fixed")
		}
		if p.Sampling.Percentage != nil {
			sampling["percentage"] = *p.Sampling.Percentage
		}
		if len(sampling) > 0 {
			props["sampling"] = sampling
		}
	}
	if frontend := apimDiagnosticPipelineReadProps(p.Frontend); frontend != nil {
		props["frontend"] = frontend
	}
	if backend := apimDiagnosticPipelineReadProps(p.Backend); backend != nil {
		props["backend"] = backend
	}
}
