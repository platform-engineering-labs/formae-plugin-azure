// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package prov

import (
	"context"
	"fmt"

	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/nativeid"
	"github.com/platform-engineering-labs/formae/pkg/plugin"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

// Wrap adds provider-wide operation handling around a resource provisioner.
func Wrap(p Provisioner) Provisioner {
	return &azureProvisioner{inner: p}
}

type azureProvisioner struct {
	inner Provisioner
}

var _ Provisioner = &azureProvisioner{}

func (p *azureProvisioner) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	result, err := p.inner.Create(ctx, request)
	if err != nil {
		return createFailure(err)
	}
	if result == nil || result.ProgressResult == nil {
		return nil, fmt.Errorf("create returned nil progress result")
	}
	logFailure(ctx, "create", "", result.ProgressResult)
	return result, nil
}

func (p *azureProvisioner) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	request.NativeID = nativeid.NativeID(request.NativeID).ArmID()
	result, err := p.inner.Read(ctx, request)
	if err != nil {
		if code, ok := AzureErrorCode(err); ok {
			return &resource.ReadResult{ResourceType: request.ResourceType, ErrorCode: code}, nil
		}
		return nil, err
	}
	if result == nil {
		return nil, fmt.Errorf("read returned nil result")
	}
	return result, nil
}

func (p *azureProvisioner) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	request.NativeID = nativeid.NativeID(request.NativeID).ArmID()
	result, err := p.inner.Update(ctx, request)
	if err != nil {
		return updateFailure(request.NativeID, err)
	}
	if result == nil || result.ProgressResult == nil {
		return nil, fmt.Errorf("update returned nil progress result")
	}
	logFailure(ctx, "update", request.NativeID, result.ProgressResult)
	return result, nil
}

func (p *azureProvisioner) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	request.NativeID = nativeid.NativeID(request.NativeID).ArmID()
	result, err := p.inner.Delete(ctx, request)
	if err != nil {
		if IsDeleteSuccessError(err) {
			return &resource.DeleteResult{ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationDelete,
				OperationStatus: resource.OperationStatusSuccess,
				NativeID:        request.NativeID,
			}}, nil
		}
		return deleteFailure(request.NativeID, err)
	}
	if result == nil || result.ProgressResult == nil {
		return nil, fmt.Errorf("delete returned nil progress result")
	}
	logFailure(ctx, "delete", request.NativeID, result.ProgressResult)
	return result, nil
}

func (p *azureProvisioner) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	request.NativeID = nativeid.NativeID(request.NativeID).ArmID()
	result, err := p.inner.Status(ctx, request)
	if err != nil {
		return statusFailure(request.RequestID, err)
	}
	if result == nil || result.ProgressResult == nil {
		return nil, fmt.Errorf("status returned nil progress result")
	}
	logFailure(ctx, "status", "", result.ProgressResult)
	return result, nil
}

func (p *azureProvisioner) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	return p.inner.List(ctx, request)
}

// logFailure records why an operation failed, at Error level, in the plugin's own
// log.
//
// Without this a failed operation is close to undiagnosable from CI. The
// conformance harness prints only
//
//	[Create] Apply command should complete successfully: command reached terminal
//	state: Failed
//
// and the agent log shows the state transition to Failed but not the reason. The
// reason IS carried - every provisioner sets ProgressResult.StatusMessage, and the
// mocked "Azure error maps to failure with a reason" tests assert it - it simply
// had nowhere visible to go. During wave 3 that cost roughly fifteen live failures
// their diagnosis: the only way to see an ARM error was to reproduce the fixture
// by hand.
//
// Logging here rather than in each provisioner is deliberate: every resource is
// wrapped, so one call site covers all of them and cannot be forgotten by the next
// resource added.
func logFailure(ctx context.Context, op string, nativeID string, pr *resource.ProgressResult) {
	if pr == nil || pr.OperationStatus != resource.OperationStatusFailure {
		return
	}
	id := nativeID
	if id == "" {
		id = pr.NativeID
	}
	plugin.LoggerFromContext(ctx).Error("azure operation failed",
		"operation", op,
		"nativeID", id,
		"errorCode", pr.ErrorCode,
		"reason", pr.StatusMessage)
}

// The four *Failure helpers all set StatusMessage from the error.
//
// They previously set only ErrorCode and discarded err.Error(), which is trap 6
// living in the shared wrapper: an ARM refusal reached core as a bare code with no
// text, so a failed operation logged a transition to Failed with nothing to say
// why. Every resource routes its Go-error path through here, so dropping the
// message here dropped it for all of them at once.
func createFailure(err error) (*resource.CreateResult, error) {
	code, ok := AzureErrorCode(err)
	if !ok {
		return nil, err
	}
	return &resource.CreateResult{ProgressResult: &resource.ProgressResult{
		Operation:       resource.OperationCreate,
		OperationStatus: resource.OperationStatusFailure,
		ErrorCode:       code,
		StatusMessage:   err.Error(),
	}}, nil
}

func updateFailure(nativeID string, err error) (*resource.UpdateResult, error) {
	code, ok := AzureErrorCode(err)
	if !ok {
		return nil, err
	}
	return &resource.UpdateResult{ProgressResult: &resource.ProgressResult{
		Operation:       resource.OperationUpdate,
		OperationStatus: resource.OperationStatusFailure,
		NativeID:        nativeID,
		ErrorCode:       code,
		StatusMessage:   err.Error(),
	}}, nil
}

func deleteFailure(nativeID string, err error) (*resource.DeleteResult, error) {
	code, ok := AzureErrorCode(err)
	if !ok {
		return nil, err
	}
	return &resource.DeleteResult{ProgressResult: &resource.ProgressResult{
		Operation:       resource.OperationDelete,
		OperationStatus: resource.OperationStatusFailure,
		NativeID:        nativeID,
		ErrorCode:       code,
		StatusMessage:   err.Error(),
	}}, nil
}

func statusFailure(requestID string, err error) (*resource.StatusResult, error) {
	code, ok := AzureErrorCode(err)
	if !ok {
		return nil, err
	}
	return &resource.StatusResult{ProgressResult: &resource.ProgressResult{
		OperationStatus: resource.OperationStatusFailure,
		RequestID:       requestID,
		StatusMessage:   err.Error(),
		ErrorCode:       code,
	}}, nil
}
